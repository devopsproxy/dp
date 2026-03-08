// Package render provides presentation-layer helpers for DevOps-Proxy CLI output.
// graph.go implements the Phase 10 attack-path graph export feature.
// It is a pure rendering module — no correlation logic, no scoring changes.
package render

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// ── Graph model ───────────────────────────────────────────────────────────────

// Graph is the in-memory representation of an attack path graph.
// Nodes represent security entities; Edges represent attacker movement between them.
type Graph struct {
	Nodes []GraphNode
	Edges []GraphEdge
}

// GraphNode represents a security entity in the attack path graph.
// Type is one of: Internet, LoadBalancer, Deployment, StatefulSet, DaemonSet,
// Job, CronJob, ReplicaSet, Pod (fallback), ServiceAccount, IAMRole, Cluster, CloudResource.
type GraphNode struct {
	ID    string
	Label string
	Type  string
}

// GraphEdge represents a directional attacker-movement link between two nodes.
type GraphEdge struct {
	From string
	To   string
}

// ── Mapping table ─────────────────────────────────────────────────────────────

// ruleNodeType maps rule IDs to graph node types.
// Only rule IDs that produce typed nodes are listed; unknown rule IDs are skipped.
// Pod-type rules are resolved to workload nodes by workloadNodeInfo at render time.
var ruleNodeType = map[string]string{
	// Network exposure
	"K8S_SERVICE_PUBLIC_LOADBALANCER": "LoadBalancer",

	// Pod privilege rules — resolved to Workload nodes via workload_kind metadata.
	"K8S_POD_RUN_AS_ROOT":          "Pod",
	"K8S_POD_CAP_SYS_ADMIN":        "Pod",
	"K8S_POD_PRIVILEGED_CONTAINER": "Pod",

	// Service account / identity rules
	"K8S_DEFAULT_SERVICEACCOUNT_USED":    "ServiceAccount",
	"K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT": "ServiceAccount",
	"EKS_SERVICEACCOUNT_NO_IRSA":         "ServiceAccount",

	// IAM / cloud identity rules
	"EKS_NODE_ROLE_OVERPERMISSIVE": "IAMRole",
	"EKS_IAM_ROLE_WILDCARD":        "IAMRole",

	// Cloud resource (OIDC)
	"EKS_OIDC_PROVIDER_NOT_ASSOCIATED": "CloudResource",

	// Cluster-level rules
	"EKS_ENCRYPTION_DISABLED":            "Cluster",
	"EKS_CONTROL_PLANE_LOGGING_DISABLED": "Cluster",
	"EKS_PUBLIC_ENDPOINT_ENABLED":        "Cluster",
	"K8S_CLUSTER_SINGLE_NODE":            "Cluster",
}

// ── Builder ───────────────────────────────────────────────────────────────────

// BuildAttackGraph constructs a Graph from the attack paths in summary using
// real Kubernetes structural relationships and workload-collapsed nodes.
//
// Node hierarchy (Phase 10.4):
//
//	Internet → LoadBalancer → Workload (Deployment/StatefulSet/…) → ServiceAccount
//
// Edge rules:
//
//	Internet → LoadBalancer   always; every LB finding gets this edge.
//	LoadBalancer → Workload   only when the Service's selector matches the pod's labels
//	                          (Metadata["service_selector"] vs Metadata["pod_labels"]).
//	Workload → ServiceAccount only when the pod's declared SA name matches the SA
//	                          finding's ResourceID in the same namespace
//	                          (Metadata["pod_service_account"] == sa.ResourceID).
//
// Workload collapsing (Phase 10.4): multiple pod findings that belong to the
// same workload (same workload_kind + workload_name) produce a single graph node.
// The workload kind/name are resolved at the engine layer via ownerReferences.
//
// Nodes that have no matching structural partner are still added to the graph
// but receive no edges from the unpaired layer. IAMRole, Cluster, and CloudResource
// nodes are added as context nodes without structural edges.
//
// Node deduplication: if the same resource appears across multiple paths only
// one GraphNode is created. Edge deduplication: identical edges are collapsed.
func BuildAttackGraph(summary models.AuditSummary, findings []models.Finding) Graph {
	var graph Graph

	if len(summary.AttackPaths) == 0 {
		return graph
	}

	// Index findings for fast lookup.
	findingByID := make(map[string]*models.Finding, len(findings))
	for i := range findings {
		findingByID[findings[i].ID] = &findings[i]
	}

	nodeSet := make(map[string]bool)
	edgeSet := make(map[string]bool)

	addNode := func(id, label, typ string) {
		if nodeSet[id] {
			return
		}
		nodeSet[id] = true
		graph.Nodes = append(graph.Nodes, GraphNode{ID: id, Label: label, Type: typ})
	}

	addEdge := func(from, to string) {
		key := from + "→" + to
		if edgeSet[key] {
			return
		}
		edgeSet[key] = true
		graph.Edges = append(graph.Edges, GraphEdge{From: from, To: to})
	}

	for _, path := range summary.AttackPaths {
		// Collect and categorize findings for this path.
		var lbFindings, podFindings, saFindings, otherFindings []*models.Finding
		for _, fid := range path.FindingIDs {
			f, ok := findingByID[fid]
			if !ok {
				continue
			}
			switch ruleNodeType[f.RuleID] {
			case "LoadBalancer":
				lbFindings = append(lbFindings, f)
			case "Pod":
				podFindings = append(podFindings, f)
			case "ServiceAccount":
				saFindings = append(saFindings, f)
			default:
				if ruleNodeType[f.RuleID] != "" {
					otherFindings = append(otherFindings, f)
				}
			}
		}

		if len(lbFindings)+len(podFindings)+len(saFindings)+len(otherFindings) == 0 {
			continue
		}

		// Internet is the shared conceptual attacker entry point.
		addNode("Internet", "Internet", "Internet")

		// ── LoadBalancer nodes: always connect from Internet ──────────────────
		for _, f := range lbFindings {
			nid := sanitizeNodeID("LoadBalancer_" + f.ResourceID)
			addNode(nid, findingNodeLabel(f), "LoadBalancer")
			addEdge("Internet", nid)
		}

		// ── Workload nodes: connect to each LB whose selector matches ─────────
		// Phase 10.4: pod findings collapse into their parent workload node.
		// Multiple pods of the same workload produce one node (via nodeSet dedup).
		for _, f := range podFindings {
			wid, wLabel, wType := workloadNodeInfo(f)
			addNode(wid, wLabel, wType)

			podLabels, _ := f.Metadata["pod_labels"].(map[string]string)
			for _, lbf := range lbFindings {
				lbID := sanitizeNodeID("LoadBalancer_" + lbf.ResourceID)
				selector, _ := lbf.Metadata["service_selector"].(map[string]string)
				if selectorMatchesPodLabels(selector, podLabels) {
					addEdge(lbID, wid)
				}
			}
		}

		// ── ServiceAccount nodes: connect from workload that declares this SA ──
		for _, f := range saFindings {
			nid := sanitizeNodeID("ServiceAccount_" + f.ResourceID)
			addNode(nid, findingNodeLabel(f), "ServiceAccount")

			saNS, _ := f.Metadata["namespace"].(string)
			for _, pf := range podFindings {
				podSA, _ := pf.Metadata["pod_service_account"].(string)
				podNS, _ := pf.Metadata["namespace"].(string)
				if podSA == f.ResourceID && podNS == saNS {
					wid, _, _ := workloadNodeInfo(pf)
					addEdge(wid, nid)
				}
			}
		}

		// ── Other nodes (IAMRole, Cluster, CloudResource): context only ───────
		for _, f := range otherFindings {
			nt := ruleNodeType[f.RuleID]
			nid := sanitizeNodeID(nt + "_" + f.ResourceID)
			addNode(nid, findingNodeLabel(f), nt)
		}
	}

	return graph
}

// workloadNodeInfo returns the graph node ID, label, and type for a pod finding.
// When the finding carries workload_kind and workload_name metadata (stamped by
// annotateStructuralTopology at the engine layer), it returns a workload-collapsed
// node. When metadata is absent it falls back to a Pod node keyed by the
// finding's ResourceID so that graphs remain honest in the absence of structural data.
func workloadNodeInfo(f *models.Finding) (id, label, nodeType string) {
	wKind, _ := f.Metadata["workload_kind"].(string)
	wName, _ := f.Metadata["workload_name"].(string)
	if wKind != "" && wName != "" {
		ns, _ := f.Metadata["namespace"].(string)
		labelStr := wName
		if ns != "" {
			labelStr = wName + " (" + ns + ")"
		}
		return sanitizeNodeID(wKind + "_" + wName), labelStr, wKind
	}
	// Fallback: no workload metadata — use pod resource ID directly.
	return sanitizeNodeID("Pod_" + f.ResourceID), findingNodeLabel(f), "Pod"
}

// selectorMatchesPodLabels reports whether every key-value pair in selector
// is present and equal in podLabels. An empty or nil selector returns false
// so that services without selectors never produce spurious edges.
func selectorMatchesPodLabels(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

// findingNodeLabel returns a human-readable label for a finding node.
// When the finding has a namespace in its metadata the label includes it as a suffix.
func findingNodeLabel(f *models.Finding) string {
	if f.Metadata != nil {
		if ns, ok := f.Metadata["namespace"].(string); ok && ns != "" {
			return f.ResourceID + " (" + ns + ")"
		}
	}
	return f.ResourceID
}

// sanitizeNodeID replaces characters that are not alphanumeric or underscore
// with an underscore so that node IDs are valid in both Mermaid and Graphviz.
func sanitizeNodeID(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			buf.WriteRune(r)
		} else {
			buf.WriteRune('_')
		}
	}
	return buf.String()
}

// ── Mermaid renderer ──────────────────────────────────────────────────────────

// RenderMermaidGraph renders graph as a Mermaid flowchart (TD direction).
// Node labels are included in quoted brackets so that labels with spaces and
// parentheses render correctly. Output is valid Mermaid 10+ syntax.
func RenderMermaidGraph(graph Graph) string {
	var sb strings.Builder

	sb.WriteString("graph TD\n\n")

	// Declare nodes with labels.
	for _, n := range graph.Nodes {
		// Escape double-quotes inside labels.
		label := strings.ReplaceAll(n.Label, `"`, `'`)
		fmt.Fprintf(&sb, "    %s[\"%s\"]\n", n.ID, label)
	}

	if len(graph.Nodes) > 0 && len(graph.Edges) > 0 {
		sb.WriteRune('\n')
	}

	// Declare edges.
	for _, e := range graph.Edges {
		fmt.Fprintf(&sb, "    %s --> %s\n", e.From, e.To)
	}

	return sb.String()
}

// ── Graphviz renderer ─────────────────────────────────────────────────────────

// RenderGraphvizGraph renders graph as a Graphviz DOT digraph.
// Node labels are double-quoted so that labels with spaces render correctly.
// Output is valid DOT syntax compatible with Graphviz 2.x+.
func RenderGraphvizGraph(graph Graph) string {
	var sb strings.Builder

	sb.WriteString("digraph AttackPath {\n\n")

	// Declare nodes with labels.
	for _, n := range graph.Nodes {
		// Escape double-quotes inside labels.
		label := strings.ReplaceAll(n.Label, `"`, `'`)
		fmt.Fprintf(&sb, "    %s [label=\"%s\"]\n", n.ID, label)
	}

	if len(graph.Nodes) > 0 && len(graph.Edges) > 0 {
		sb.WriteRune('\n')
	}

	// Declare edges.
	for _, e := range graph.Edges {
		fmt.Fprintf(&sb, "    %s -> %s\n", e.From, e.To)
	}

	sb.WriteString("}\n")

	return sb.String()
}
