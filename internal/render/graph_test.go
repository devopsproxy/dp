package render

import (
	"strings"
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeSummaryWithPath(paths []models.AttackPath) models.AuditSummary {
	return models.AuditSummary{AttackPaths: paths}
}

// makeFindingWithNS creates a Finding with a namespace in Metadata.
// makeFinding (4-arg: id, ruleID, resourceID, meta) is defined in explain_test.go.
func makeFindingWithNS(id, ruleID, resourceID, ns string) models.Finding {
	return makeFinding(id, ruleID, resourceID, map[string]any{"namespace": ns})
}

// makeLBFinding creates a LoadBalancer finding with a service selector and namespace.
func makeLBFinding(id, resourceID, ns string, selector map[string]string) models.Finding {
	return makeFinding(id, "K8S_SERVICE_PUBLIC_LOADBALANCER", resourceID, map[string]any{
		"namespace":        ns,
		"service_selector": selector,
	})
}

// makeWorkloadPodFinding creates a Pod finding with full workload metadata so
// the graph builder produces a Workload node (Deployment/StatefulSet/…) instead
// of a Pod fallback node.
func makeWorkloadPodFinding(id, resourceID, ns, serviceAccountName string, labels map[string]string, workloadKind, workloadName string) models.Finding {
	return makeFinding(id, "K8S_POD_RUN_AS_ROOT", resourceID, map[string]any{
		"namespace":           ns,
		"pod_labels":          labels,
		"pod_service_account": serviceAccountName,
		"workload_kind":       workloadKind,
		"workload_name":       workloadName,
	})
}

// makeSAFinding creates a ServiceAccount finding with a namespace.
func makeSAFinding(id, ruleID, resourceID, ns string) models.Finding {
	return makeFinding(id, ruleID, resourceID, map[string]any{"namespace": ns})
}

// ── TestBuildAttackGraph_HappyPath ────────────────────────────────────────────

// TestBuildAttackGraph_HappyPath verifies that a single well-formed path with
// structural and workload metadata produces the correct nodes and edges.
// Phase 10.4: the pod finding collapses into a Deployment node.
func TestBuildAttackGraph_HappyPath(t *testing.T) {
	findings := []models.Finding{
		makeLBFinding("f1", "web-svc", "prod", map[string]string{"app": "web"}),
		makeWorkloadPodFinding("f2", "app-pod", "prod", "default",
			map[string]string{"app": "web"}, "Deployment", "app"),
		makeSAFinding("f3", "K8S_DEFAULT_SERVICEACCOUNT_USED", "default", "prod"),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs: []string{"f1", "f2", "f3"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)

	// Internet node must be present.
	if !hasNodeType(g, "Internet") {
		t.Error("expected Internet node; not found")
	}
	// Workload layer: Deployment node, not Pod.
	if !hasNodeType(g, "Deployment") {
		t.Error("expected Deployment node; not found")
	}
	if hasNodeType(g, "Pod") {
		t.Error("unexpected Pod node — should be collapsed into Deployment")
	}
	// LoadBalancer and ServiceAccount must still be present.
	for _, typ := range []string{"LoadBalancer", "ServiceAccount"} {
		if !hasNodeType(g, typ) {
			t.Errorf("expected node of type %q; not found", typ)
		}
	}
	// Structural edges: Internet→LB, LB→Deployment, Deployment→SA.
	lbID := sanitizeNodeID("LoadBalancer_web-svc")
	wID := sanitizeNodeID("Deployment_app")
	saID := sanitizeNodeID("ServiceAccount_default")
	if !hasEdge(g, "Internet", lbID) {
		t.Errorf("expected Internet → %s", lbID)
	}
	if !hasEdge(g, lbID, wID) {
		t.Errorf("expected %s → %s (selector match)", lbID, wID)
	}
	if !hasEdge(g, wID, saID) {
		t.Errorf("expected %s → %s (serviceAccountName match)", wID, saID)
	}
	// First edge must originate from Internet.
	if len(g.Edges) > 0 && g.Edges[0].From != "Internet" {
		t.Errorf("first edge From must be 'Internet'; got %q", g.Edges[0].From)
	}
}

// ── TestBuildAttackGraph_EmptyPaths ──────────────────────────────────────────

// TestBuildAttackGraph_EmptyPaths verifies that an empty summary produces an
// empty graph (no nodes, no edges, no panic).
func TestBuildAttackGraph_EmptyPaths(t *testing.T) {
	g := BuildAttackGraph(models.AuditSummary{}, nil, nil)

	if len(g.Nodes) != 0 {
		t.Errorf("expected 0 nodes; got %d", len(g.Nodes))
	}
	if len(g.Edges) != 0 {
		t.Errorf("expected 0 edges; got %d", len(g.Edges))
	}
}

// ── TestGraphNodeDeduplication ────────────────────────────────────────────────

// TestGraphNodeDeduplication verifies that when the same resource appears in
// two different attack paths only one GraphNode is created for it.
func TestGraphNodeDeduplication(t *testing.T) {
	findings := []models.Finding{
		makeLBFinding("f1", "shared-svc", "prod", map[string]string{"app": "shared"}),
		makeWorkloadPodFinding("f2", "pod-a", "prod", "default",
			map[string]string{"app": "shared"}, "Deployment", "shared-app"),
		makeFinding("f3", "EKS_NODE_ROLE_OVERPERMISSIVE", "node-role", nil),
	}

	// Two paths both reference the same LoadBalancer finding.
	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege"},
			FindingIDs: []string{"f1", "f2"},
		},
		{
			Score:      90,
			Layers:     []string{"Network Exposure", "IAM Over-Permission"},
			FindingIDs: []string{"f1", "f3"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)

	// Count nodes by ID — no duplicate IDs allowed.
	seen := make(map[string]int)
	for _, n := range g.Nodes {
		seen[n.ID]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("node %q appears %d times; want exactly 1", id, count)
		}
	}

	// The shared LB node must appear exactly once.
	lbID := sanitizeNodeID("LoadBalancer_shared-svc")
	if seen[lbID] != 1 {
		t.Errorf("expected node %q to appear once; got count %d", lbID, seen[lbID])
	}
}

// ── TestMermaidOutputValid ────────────────────────────────────────────────────

// TestMermaidOutputValid verifies that RenderMermaidGraph produces output that:
// - starts with "graph TD"
// - contains node IDs and labels
func TestMermaidOutputValid(t *testing.T) {
	findings := []models.Finding{
		makeFindingWithNS("f1", "K8S_SERVICE_PUBLIC_LOADBALANCER", "kafka-ui", "prod"),
		makeFinding("f2", "K8S_POD_RUN_AS_ROOT", "platform-api", nil),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege"},
			FindingIDs: []string{"f1", "f2"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)
	out := RenderMermaidGraph(g)

	if !strings.HasPrefix(out, "graph TD") {
		t.Errorf("Mermaid output must start with 'graph TD'; got: %.40s", out)
	}
	if !strings.Contains(out, "Internet") {
		t.Error("Mermaid output must contain 'Internet' node")
	}
	if !strings.Contains(out, "kafka-ui") {
		t.Error("Mermaid output must contain resource label 'kafka-ui'")
	}
}

// ── TestGraphvizOutputValid ───────────────────────────────────────────────────

// TestGraphvizOutputValid verifies that RenderGraphvizGraph produces valid DOT:
// - starts with "digraph AttackPath {"
// - contains "->" for edges
// - is properly terminated with "}"
func TestGraphvizOutputValid(t *testing.T) {
	findings := []models.Finding{
		makeLBFinding("f1", "my-lb", "default", map[string]string{"app": "my-lb"}),
		makeFinding("f2", "EKS_NODE_ROLE_OVERPERMISSIVE", "node-role", nil),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      94,
			Layers:     []string{"Network Exposure", "IAM Over-Permission"},
			FindingIDs: []string{"f1", "f2"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)
	out := RenderGraphvizGraph(g)

	if !strings.HasPrefix(out, "digraph AttackPath {") {
		t.Errorf("Graphviz output must start with 'digraph AttackPath {'; got: %.60s", out)
	}
	if !strings.Contains(out, "->") {
		t.Error("Graphviz output must contain '->' for edges")
	}
	trimmed := strings.TrimRight(out, "\n")
	if !strings.HasSuffix(trimmed, "}") {
		t.Errorf("Graphviz output must end with '}'; got suffix: %.40s", trimmed[maxInt(0, len(trimmed)-40):])
	}
}

// ── TestNodeSanitization ──────────────────────────────────────────────────────

// TestNodeSanitization verifies that sanitizeNodeID replaces all characters
// that are invalid for Mermaid/Graphviz node IDs with underscores.
func TestNodeSanitization(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"LoadBalancer_web-svc", "LoadBalancer_web_svc"},
		{"Pod_my.pod/namespace", "Pod_my_pod_namespace"},
		{"ServiceAccount_prod:sa", "ServiceAccount_prod_sa"},
		{"IAMRole_arn:aws:iam::123456789012:role/node", "IAMRole_arn_aws_iam__123456789012_role_node"},
		{"Cluster_my cluster", "Cluster_my_cluster"},
		{"already_valid", "already_valid"},
		{"Deployment_platform-api", "Deployment_platform_api"},
	}

	for _, tc := range cases {
		got := sanitizeNodeID(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeNodeID(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}

// ── TestSelectorMatchesPodLabels ──────────────────────────────────────────────

// TestSelectorMatchesPodLabels verifies the core selector-matching predicate.
func TestSelectorMatchesPodLabels(t *testing.T) {
	cases := []struct {
		name      string
		selector  map[string]string
		podLabels map[string]string
		want      bool
	}{
		{"exact match", map[string]string{"app": "web"}, map[string]string{"app": "web"}, true},
		{"subset match", map[string]string{"app": "web"}, map[string]string{"app": "web", "env": "prod"}, true},
		{"value mismatch", map[string]string{"app": "web"}, map[string]string{"app": "api"}, false},
		{"missing key", map[string]string{"app": "web"}, map[string]string{"env": "prod"}, false},
		{"empty selector", map[string]string{}, map[string]string{"app": "web"}, false},
		{"nil selector", nil, map[string]string{"app": "web"}, false},
		{"nil labels", map[string]string{"app": "web"}, nil, false},
		{"multi-key all match", map[string]string{"app": "web", "env": "prod"}, map[string]string{"app": "web", "env": "prod"}, true},
		{"multi-key partial fail", map[string]string{"app": "web", "env": "prod"}, map[string]string{"app": "web", "env": "dev"}, false},
	}

	for _, tc := range cases {
		got := selectorMatchesPodLabels(tc.selector, tc.podLabels)
		if got != tc.want {
			t.Errorf("%s: selectorMatchesPodLabels(%v, %v) = %v; want %v",
				tc.name, tc.selector, tc.podLabels, got, tc.want)
		}
	}
}

// ── TestGraphBuilder_ServiceSelectorMatching ──────────────────────────────────

// TestGraphBuilder_ServiceSelectorMatching verifies that a Service only
// connects to workloads whose pod labels satisfy the Service's selector.
// Phase 10.4: pod findings collapse into Workload nodes; selector matching
// still operates on pod labels, and edges are drawn to the Workload node.
func TestGraphBuilder_ServiceSelectorMatching(t *testing.T) {
	findings := []models.Finding{
		// portainer LB selects pods with app=portainer.
		makeLBFinding("f1", "portainer", "infra", map[string]string{"app": "portainer"}),
		// portainer-pod matches the selector; belongs to Deployment "portainer".
		makeWorkloadPodFinding("f2", "portainer-pod", "infra", "portainer-sa",
			map[string]string{"app": "portainer"}, "Deployment", "portainer"),
		// api-pod does NOT match — different label value; belongs to Deployment "api".
		makeWorkloadPodFinding("f3", "api-pod", "infra", "api-sa",
			map[string]string{"app": "api"}, "Deployment", "api"),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege"},
			FindingIDs: []string{"f1", "f2", "f3"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)

	lbID := sanitizeNodeID("LoadBalancer_portainer")
	matchedWID := sanitizeNodeID("Deployment_portainer")
	unmatchedWID := sanitizeNodeID("Deployment_api")

	// portainer LB must connect only to Deployment_portainer.
	if !hasEdge(g, lbID, matchedWID) {
		t.Errorf("expected edge %s → %s (selector match app=portainer)", lbID, matchedWID)
	}
	// Deployment_api must NOT receive an edge from portainer LB.
	if hasEdge(g, lbID, unmatchedWID) {
		t.Errorf("unexpected edge %s → %s (selector mismatch: app=portainer vs app=api)", lbID, unmatchedWID)
	}
	// Both workload nodes must still exist in the graph.
	seen := make(map[string]bool)
	for _, n := range g.Nodes {
		seen[n.ID] = true
	}
	if !seen[matchedWID] {
		t.Errorf("expected node %s to be present", matchedWID)
	}
	if !seen[unmatchedWID] {
		t.Errorf("expected node %s to be present even without an edge", unmatchedWID)
	}
	// No raw Pod nodes must appear (all collapsed into Deployment).
	if hasNodeType(g, "Pod") {
		t.Error("unexpected Pod node — all pods should be collapsed into Deployment nodes")
	}
}

// ── TestGraphBuilder_PodServiceAccountEdge ────────────────────────────────────

// TestGraphBuilder_PodServiceAccountEdge verifies that a Workload node connects
// to its ServiceAccount finding only when the pod's declared serviceAccountName
// matches the SA finding's ResourceID in the same namespace.
func TestGraphBuilder_PodServiceAccountEdge(t *testing.T) {
	findings := []models.Finding{
		makeLBFinding("f1", "portainer-svc", "infra", map[string]string{"app": "portainer"}),
		// portainer-pod declares SA portainer-sa-clusteradmin; Deployment "portainer".
		makeWorkloadPodFinding("f2", "portainer-pod", "infra", "portainer-sa-clusteradmin",
			map[string]string{"app": "portainer"}, "Deployment", "portainer"),
		// portainer-sa-clusteradmin SA finding — same namespace, name matches pod's SA.
		makeSAFinding("f3", "K8S_DEFAULT_SERVICEACCOUNT_USED", "portainer-sa-clusteradmin", "infra"),
		// unrelated-sa in the same namespace — must NOT connect to the portainer workload.
		makeSAFinding("f4", "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", "unrelated-sa", "infra"),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs: []string{"f1", "f2", "f3", "f4"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)

	wID := sanitizeNodeID("Deployment_portainer")
	matchedSAID := sanitizeNodeID("ServiceAccount_portainer-sa-clusteradmin")
	unmatchedSAID := sanitizeNodeID("ServiceAccount_unrelated-sa")

	// Deployment_portainer must connect to its declared SA.
	if !hasEdge(g, wID, matchedSAID) {
		t.Errorf("expected edge %s → %s (serviceAccountName match)", wID, matchedSAID)
	}
	// Deployment_portainer must NOT connect to unrelated-sa.
	if hasEdge(g, wID, unmatchedSAID) {
		t.Errorf("unexpected edge %s → %s (no serviceAccountName relationship)", wID, unmatchedSAID)
	}
	// Both SA nodes must still exist in the graph.
	seen := make(map[string]bool)
	for _, n := range g.Nodes {
		seen[n.ID] = true
	}
	if !seen[matchedSAID] {
		t.Errorf("expected node %s to be present", matchedSAID)
	}
	if !seen[unmatchedSAID] {
		t.Errorf("expected node %s to be present even without an edge", unmatchedSAID)
	}
}

// ── TestGraphBuilder_NoSpuriousEdgesWithoutMetadata ───────────────────────────

// TestGraphBuilder_NoSpuriousEdgesWithoutMetadata verifies that when findings
// carry no structural metadata the graph adds all nodes but creates NO
// cross-layer edges — only Internet→LB. Without workload metadata the pod
// finding falls back to a Pod node keyed by ResourceID.
func TestGraphBuilder_NoSpuriousEdgesWithoutMetadata(t *testing.T) {
	findings := []models.Finding{
		makeFinding("f1", "K8S_SERVICE_PUBLIC_LOADBALANCER", "web-svc", nil),
		makeFinding("f2", "K8S_POD_RUN_AS_ROOT", "app-pod", nil),
		makeFinding("f3", "K8S_DEFAULT_SERVICEACCOUNT_USED", "default", nil),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs: []string{"f1", "f2", "f3"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)

	lbID := sanitizeNodeID("LoadBalancer_web-svc")
	podID := sanitizeNodeID("Pod_app-pod") // fallback: no workload metadata
	saID := sanitizeNodeID("ServiceAccount_default")

	// All nodes must exist.
	seen := make(map[string]bool)
	for _, n := range g.Nodes {
		seen[n.ID] = true
	}
	for _, id := range []string{"Internet", lbID, podID, saID} {
		if !seen[id] {
			t.Errorf("expected node %s; not found", id)
		}
	}
	// Only Internet→LB — no heuristic cross-layer edges.
	if !hasEdge(g, "Internet", lbID) {
		t.Errorf("expected Internet → %s", lbID)
	}
	if hasEdge(g, lbID, podID) {
		t.Errorf("unexpected edge %s → %s (no selector metadata)", lbID, podID)
	}
	if hasEdge(g, podID, saID) {
		t.Errorf("unexpected edge %s → %s (no serviceAccountName metadata)", podID, saID)
	}
	if len(g.Edges) != 1 {
		t.Errorf("expected exactly 1 edge (Internet→LB only); got %d", len(g.Edges))
	}
}

// ── TestGraphBuilder_WorkloadCollapse ─────────────────────────────────────────

// TestGraphBuilder_WorkloadCollapse verifies that multiple pod findings belonging
// to the same Deployment collapse into a single Workload node.
// 3 pods of Deployment "api" must produce exactly one Deployment_api node.
func TestGraphBuilder_WorkloadCollapse(t *testing.T) {
	findings := []models.Finding{
		makeLBFinding("f1", "api-svc", "prod", map[string]string{"app": "api"}),
		// Three pods of the same Deployment "api".
		makeWorkloadPodFinding("f2", "api-pod-1", "prod", "api-sa",
			map[string]string{"app": "api"}, "Deployment", "api"),
		makeWorkloadPodFinding("f3", "api-pod-2", "prod", "api-sa",
			map[string]string{"app": "api"}, "Deployment", "api"),
		makeWorkloadPodFinding("f4", "api-pod-3", "prod", "api-sa",
			map[string]string{"app": "api"}, "Deployment", "api"),
		makeSAFinding("f5", "K8S_DEFAULT_SERVICEACCOUNT_USED", "api-sa", "prod"),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs: []string{"f1", "f2", "f3", "f4", "f5"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)

	// Count Deployment nodes — must be exactly one despite 3 pod findings.
	deploymentCount := 0
	podCount := 0
	for _, n := range g.Nodes {
		if n.Type == "Deployment" {
			deploymentCount++
		}
		if n.Type == "Pod" {
			podCount++
		}
	}
	if deploymentCount != 1 {
		t.Errorf("expected 1 Deployment node from 3 pod findings; got %d", deploymentCount)
	}
	if podCount != 0 {
		t.Errorf("expected 0 Pod nodes (all collapsed into Deployment); got %d", podCount)
	}

	// The single Deployment_api node must exist.
	wID := sanitizeNodeID("Deployment_api")
	seen := make(map[string]bool)
	for _, n := range g.Nodes {
		seen[n.ID] = true
	}
	if !seen[wID] {
		t.Errorf("expected node %s; not found", wID)
	}

	// LB must connect to the single Deployment node (not 3 separate pods).
	lbID := sanitizeNodeID("LoadBalancer_api-svc")
	if !hasEdge(g, lbID, wID) {
		t.Errorf("expected edge %s → %s", lbID, wID)
	}

	// Deployment must connect to its SA.
	saID := sanitizeNodeID("ServiceAccount_api-sa")
	if !hasEdge(g, wID, saID) {
		t.Errorf("expected edge %s → %s", wID, saID)
	}

	// Total edge count: Internet→LB, LB→Deployment, Deployment→SA = 3.
	if len(g.Edges) != 3 {
		t.Errorf("expected 3 edges (Internet→LB, LB→Workload, Workload→SA); got %d", len(g.Edges))
	}
}

// ── TestGraphBuilder_WorkloadServiceAccountEdge ───────────────────────────────

// TestGraphBuilder_WorkloadServiceAccountEdge verifies that a Deployment workload
// node connects to its ServiceAccount when the pod's serviceAccountName matches.
func TestGraphBuilder_WorkloadServiceAccountEdge(t *testing.T) {
	findings := []models.Finding{
		makeLBFinding("f1", "api-svc", "prod", map[string]string{"app": "api"}),
		makeWorkloadPodFinding("f2", "api-pod", "prod", "api-sa",
			map[string]string{"app": "api"}, "Deployment", "api"),
		makeSAFinding("f3", "K8S_DEFAULT_SERVICEACCOUNT_USED", "api-sa", "prod"),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs: []string{"f1", "f2", "f3"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)

	wID := sanitizeNodeID("Deployment_api")
	saID := sanitizeNodeID("ServiceAccount_api-sa")

	if !hasEdge(g, wID, saID) {
		t.Errorf("expected edge %s → %s (Deployment → ServiceAccount)", wID, saID)
	}

	// The Deployment node label should include the namespace.
	for _, n := range g.Nodes {
		if n.ID == wID {
			if !strings.Contains(n.Label, "prod") {
				t.Errorf("Deployment node label %q should contain namespace 'prod'", n.Label)
			}
			if n.Type != "Deployment" {
				t.Errorf("expected node type 'Deployment'; got %q", n.Type)
			}
			break
		}
	}
}

// ── TestGraphBuilder_ServiceAccountToIAMRole ──────────────────────────────────

// TestGraphBuilder_ServiceAccountToIAMRole verifies that when a ServiceAccount
// finding carries iam_role_arn metadata an IAMRole node is created and a
// ServiceAccount → IAMRole edge is added.
func TestGraphBuilder_ServiceAccountToIAMRole(t *testing.T) {
	const arn = "arn:aws:iam::123456789012:role/app-role"

	findings := []models.Finding{
		makeLBFinding("f1", "api-svc", "prod", map[string]string{"app": "api"}),
		makeWorkloadPodFinding("f2", "api-pod", "prod", "api-sa",
			map[string]string{"app": "api"}, "Deployment", "api"),
		makeFinding("f3", "EKS_SERVICEACCOUNT_NO_IRSA", "api-sa", map[string]any{
			"namespace":    "prod",
			"iam_role_arn": arn,
		}),
	}

	summary := makeSummaryWithPath([]models.AttackPath{
		{
			Score:      98,
			Layers:     []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs: []string{"f1", "f2", "f3"},
		},
	})

	g := BuildAttackGraph(summary, findings, nil)

	saID := sanitizeNodeID("ServiceAccount_api-sa")
	roleID := sanitizeNodeID("IAMRole_app-role")

	// IAMRole node must exist with correct label and type.
	var roleNode *GraphNode
	for i := range g.Nodes {
		if g.Nodes[i].ID == roleID {
			roleNode = &g.Nodes[i]
			break
		}
	}
	if roleNode == nil {
		t.Fatalf("expected IAMRole node %q; not found in graph", roleID)
	}
	if roleNode.Type != "IAMRole" {
		t.Errorf("expected node type 'IAMRole'; got %q", roleNode.Type)
	}
	if !strings.Contains(roleNode.Label, "app-role") {
		t.Errorf("IAMRole node label %q should contain role name 'app-role'", roleNode.Label)
	}
	if !strings.Contains(roleNode.Label, "AWS IAM") {
		t.Errorf("IAMRole node label %q should contain 'AWS IAM'", roleNode.Label)
	}

	// ServiceAccount → IAMRole edge must exist.
	if !hasEdge(g, saID, roleID) {
		t.Errorf("expected edge %s → %s (ServiceAccount → IAMRole)", saID, roleID)
	}
}

// TestExtractRoleName verifies ARN parsing for various formats.
func TestExtractRoleName(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:iam::123456789012:role/app-role", "app-role"},
		{"arn:aws:iam::123456789012:role/path/nested-role", "nested-role"},
		{"not-an-arn", "not-an-arn"},
		{"", ""},
	}
	for _, tc := range cases {
		got := extractRoleName(tc.arn)
		if got != tc.want {
			t.Errorf("extractRoleName(%q) = %q; want %q", tc.arn, got, tc.want)
		}
	}
}

// ── graph test helpers ────────────────────────────────────────────────────────

func hasNodeType(g Graph, typ string) bool {
	for _, n := range g.Nodes {
		if n.Type == typ {
			return true
		}
	}
	return false
}

func hasEdge(g Graph, from, to string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
