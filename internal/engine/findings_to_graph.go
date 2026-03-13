// Package engine — findings_to_graph.go
//
// Phase 18: Misconfiguration to Attack Path Bridging.
// EnrichWithFindings converts security rule findings into Misconfiguration
// graph nodes and attaches them to existing asset graph nodes via AMPLIFIES
// edges. This allows the graph traversal engine to surface misconfigurations
// as amplifiers in attack path detection without modifying rule detection logic.
package engine

import (
	"fmt"
	"strings"

	"github.com/devopsproxy/dp/internal/graph"
	"github.com/devopsproxy/dp/internal/models"
)

// EnrichWithFindings converts security rule findings into Misconfiguration
// nodes in the asset graph and links them to the assets they affect via
// AMPLIFIES edges.
//
// Supported rule mappings:
//
//   - K8S_SERVICE_PUBLIC_LOADBALANCER → Misconfiguration(PublicLoadBalancer)
//     attached to the matching LoadBalancer node (matched by service name from
//     finding ResourceID) via LoadBalancer → Misconfiguration AMPLIFIES edge.
//     Also adds Internet → Misconfiguration EXPOSES edge so the node is
//     reachable from attacker entry points.
//
//   - EKS_NODE_ROLE_OVERPERMISSIVE → Misconfiguration(WildcardIAMRole)
//     attached to every IAMRole node in the graph via IAMRole → Misconfiguration
//     AMPLIFIES edge.
//
//   - K8S_POD_RUN_AS_ROOT / K8S_PRIVILEGED_CONTAINER / K8S_POD_CAP_SYS_ADMIN →
//     Misconfiguration(PrivilegedContainer) attached to the matching Workload
//     node (matched by workload_name metadata or ResourceID) via Workload →
//     Misconfiguration AMPLIFIES edge.
//
// Nodes are added idempotently (first-write-wins in graph.AddNode). Edges are
// added idempotently (graph.AddEdge is a no-op for duplicate edges).
// Findings for unrecognised rule IDs are silently ignored.
// The function is a no-op when g is nil.
func EnrichWithFindings(g *graph.Graph, findings []models.Finding) {
	if g == nil {
		return
	}

	// Ensure the Internet node exists — it is the canonical attacker entry
	// point and must be present before we add EXPOSES edges from it.
	const internetID = "Internet"
	if g.GetNode(internetID) == nil {
		g.AddNode(&graph.Node{
			ID:       internetID,
			Type:     graph.NodeTypeInternet,
			Name:     "Internet",
			Metadata: map[string]string{},
		})
	}

	for _, f := range findings {
		switch f.RuleID {
		case "K8S_SERVICE_PUBLIC_LOADBALANCER":
			enrichPublicLoadBalancer(g, f)
		case "EKS_NODE_ROLE_OVERPERMISSIVE":
			enrichWildcardIAMRole(g, f)
		case "K8S_POD_RUN_AS_ROOT", "K8S_PRIVILEGED_CONTAINER", "K8S_POD_CAP_SYS_ADMIN":
			enrichPrivilegedContainer(g, f)
		}
	}
}

// enrichPublicLoadBalancer creates a PublicLoadBalancer Misconfiguration node
// for a K8S_SERVICE_PUBLIC_LOADBALANCER finding and wires it into the graph:
//
//	Internet → MisconfigNode   (EXPOSES)
//	LBNode   → MisconfigNode   (AMPLIFIES)  when matching LoadBalancer exists
func enrichPublicLoadBalancer(g *graph.Graph, f models.Finding) {
	// Derive a stable service name from the finding's ResourceID.
	svcName := f.ResourceID
	if svcName == "" {
		return
	}

	miscID := fmt.Sprintf("Misconfiguration_PublicLoadBalancer_%s", sanitiseNodeName(svcName))
	g.AddNode(&graph.Node{
		ID:   miscID,
		Type: graph.NodeTypeMisconfiguration,
		Name: fmt.Sprintf("PublicLoadBalancer (%s)", svcName),
		Metadata: map[string]string{
			"misconfig_type": "PublicLoadBalancer",
			"service":        svcName,
		},
	})

	// Internet → Misconfiguration (EXPOSES) so the node is reachable from
	// attacker entry points during traversal.
	g.AddEdge("Internet", miscID, graph.EdgeTypeExposes)

	// Find the matching LoadBalancer node and add an AMPLIFIES edge.
	lbID := matchingLoadBalancerID(g, svcName)
	if lbID != "" {
		g.AddEdge(lbID, miscID, graph.EdgeTypeAmplifies)
	}
}

// enrichWildcardIAMRole creates a WildcardIAMRole Misconfiguration node for an
// EKS_NODE_ROLE_OVERPERMISSIVE finding and adds IAMRole → Misconfiguration
// AMPLIFIES edges for every IAMRole node currently in the graph.
func enrichWildcardIAMRole(g *graph.Graph, _ models.Finding) {
	miscID := "Misconfiguration_WildcardIAMRole"
	g.AddNode(&graph.Node{
		ID:   miscID,
		Type: graph.NodeTypeMisconfiguration,
		Name: "WildcardIAMRole",
		Metadata: map[string]string{
			"misconfig_type": "WildcardIAMRole",
		},
	})

	for _, node := range g.Nodes {
		if node.Type == graph.NodeTypeIAMRole {
			g.AddEdge(node.ID, miscID, graph.EdgeTypeAmplifies)
		}
	}
}

// enrichPrivilegedContainer creates a PrivilegedContainer Misconfiguration node
// for a pod-privilege finding and wires it to the matching Workload node:
//
//	WorkloadNode → MisconfigNode   (AMPLIFIES)  when matching Workload exists
func enrichPrivilegedContainer(g *graph.Graph, f models.Finding) {
	// Resolve workload name from metadata (set by annotateStructuralTopology)
	// or fall back to ResourceID.
	workloadName := ""
	if wn, ok := f.Metadata["workload_name"].(string); ok && wn != "" {
		workloadName = wn
	}
	if workloadName == "" {
		workloadName = f.ResourceID
	}
	if workloadName == "" {
		return
	}

	miscID := fmt.Sprintf("Misconfiguration_PrivilegedContainer_%s", sanitiseNodeName(workloadName))
	g.AddNode(&graph.Node{
		ID:   miscID,
		Type: graph.NodeTypeMisconfiguration,
		Name: fmt.Sprintf("PrivilegedContainer (%s)", workloadName),
		Metadata: map[string]string{
			"misconfig_type": "PrivilegedContainer",
			"workload":       workloadName,
		},
	})

	// Find the Workload node that owns this pod and add an AMPLIFIES edge.
	workloadID := matchingWorkloadID(g, workloadName)
	if workloadID != "" {
		g.AddEdge(workloadID, miscID, graph.EdgeTypeAmplifies)
	}
}

// matchingLoadBalancerID scans the graph for a NodeTypeLoadBalancer node whose
// Name matches svcName (case-insensitive). Returns the node ID on success, ""
// when not found.
func matchingLoadBalancerID(g *graph.Graph, svcName string) string {
	lower := strings.ToLower(svcName)
	for _, node := range g.Nodes {
		if node.Type == graph.NodeTypeLoadBalancer &&
			strings.ToLower(node.Name) == lower {
			return node.ID
		}
	}
	return ""
}

// matchingWorkloadID scans the graph for a NodeTypeWorkload node whose Name
// matches workloadName (case-insensitive). Returns the node ID on success, ""
// when not found.
func matchingWorkloadID(g *graph.Graph, workloadName string) string {
	lower := strings.ToLower(workloadName)
	for _, node := range g.Nodes {
		if node.Type == graph.NodeTypeWorkload &&
			strings.ToLower(node.Name) == lower {
			return node.ID
		}
	}
	return ""
}

// sanitiseNodeName converts a resource name to a safe graph node ID segment by
// replacing non-alphanumeric characters with underscores.
func sanitiseNodeName(name string) string {
	var b strings.Builder
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '-' {
			b.WriteRune(ch)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
