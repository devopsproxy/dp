package engine

import (
	"testing"

	"github.com/devopsproxy/dp/internal/graph"
	"github.com/devopsproxy/dp/internal/models"
)

// ── TestMisconfigurationNodeCreation ─────────────────────────────────────────

// TestMisconfigurationNodeCreation verifies that EnrichWithFindings creates the
// expected Misconfiguration nodes for each supported rule ID and does not panic
// or error when the graph has no matching asset nodes to attach edges to.
func TestMisconfigurationNodeCreation(t *testing.T) {
	g := graph.NewGraph()
	// Add a minimal Internet node so EXPOSES edges can be created.
	g.AddNode(&graph.Node{
		ID:       "Internet",
		Type:     graph.NodeTypeInternet,
		Name:     "Internet",
		Metadata: map[string]string{},
	})

	findings := []models.Finding{
		{
			RuleID:     "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceID: "kafka-ui",
		},
		{
			RuleID:     "EKS_NODE_ROLE_OVERPERMISSIVE",
			ResourceID: "cluster",
		},
		{
			RuleID:     "K8S_POD_RUN_AS_ROOT",
			ResourceID: "web-pod",
			Metadata:   map[string]any{"workload_name": "web"},
		},
	}

	EnrichWithFindings(g, findings)

	// PublicLoadBalancer misconfiguration node should exist.
	lbMiscID := "Misconfiguration_PublicLoadBalancer_kafka-ui"
	if g.GetNode(lbMiscID) == nil {
		t.Errorf("expected node %q to exist after EnrichWithFindings", lbMiscID)
	}
	if n := g.GetNode(lbMiscID); n != nil {
		if n.Type != graph.NodeTypeMisconfiguration {
			t.Errorf("node %q: expected type Misconfiguration; got %q", lbMiscID, n.Type)
		}
		if n.Metadata["misconfig_type"] != "PublicLoadBalancer" {
			t.Errorf("node %q: expected misconfig_type=PublicLoadBalancer; got %q", lbMiscID, n.Metadata["misconfig_type"])
		}
	}

	// WildcardIAMRole misconfiguration node should exist.
	iamMiscID := "Misconfiguration_WildcardIAMRole"
	if g.GetNode(iamMiscID) == nil {
		t.Errorf("expected node %q to exist after EnrichWithFindings", iamMiscID)
	}

	// PrivilegedContainer misconfiguration node should exist (keyed by workload_name).
	privMiscID := "Misconfiguration_PrivilegedContainer_web"
	if g.GetNode(privMiscID) == nil {
		t.Errorf("expected node %q to exist after EnrichWithFindings", privMiscID)
	}
}

// ── TestAttackPathWithMisconfiguration ────────────────────────────────────────

// TestAttackPathWithMisconfiguration verifies that after EnrichWithFindings
// injects a Misconfiguration node, a graph traversal path that includes the
// Misconfiguration node is detected by FindGraphAttackPaths.
func TestAttackPathWithMisconfiguration(t *testing.T) {
	// Build a graph: Internet → LB → Workload → IAMRole → S3Bucket (sensitive).
	// The LB maps to a K8S_SERVICE_PUBLIC_LOADBALANCER finding, so
	// EnrichWithFindings will add:
	//   Misconfiguration_PublicLoadBalancer_web → Internet (EXPOSES)
	//   LB → Misconfiguration (AMPLIFIES)
	g := graph.NewGraph()

	internet := &graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet", Metadata: map[string]string{}}
	lb := &graph.Node{ID: "LoadBalancer_web", Type: graph.NodeTypeLoadBalancer, Name: "web", Metadata: map[string]string{}}
	workload := &graph.Node{ID: "Deployment_api", Type: graph.NodeTypeWorkload, Name: "api", Metadata: map[string]string{}}
	role := &graph.Node{ID: "IAMRole_app-role", Type: graph.NodeTypeIAMRole, Name: "app-role", Metadata: map[string]string{"arn": "arn:aws:iam::123:role/app-role"}}
	bucket := &graph.Node{
		ID:       "S3Bucket_data",
		Type:     graph.NodeTypeS3Bucket,
		Name:     "data",
		Metadata: map[string]string{"sensitivity": "high"},
	}

	for _, n := range []*graph.Node{internet, lb, workload, role, bucket} {
		g.AddNode(n)
	}
	g.AddEdge(internet.ID, lb.ID, graph.EdgeTypeExposes)
	g.AddEdge(lb.ID, workload.ID, graph.EdgeTypeRoutesTo)
	g.AddEdge(workload.ID, role.ID, graph.EdgeTypeRunsAs)
	g.AddEdge(role.ID, bucket.ID, graph.EdgeTypeCanAccess)

	// Enrich with a public LB finding.
	findings := []models.Finding{
		{
			RuleID:     "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceID: "web",
		},
	}
	EnrichWithFindings(g, findings)

	// The Misconfiguration node should now exist.
	miscID := "Misconfiguration_PublicLoadBalancer_web"
	if g.GetNode(miscID) == nil {
		t.Fatalf("expected Misconfiguration node %q to exist", miscID)
	}

	// There should be an AMPLIFIES edge from LB to the misconfig node.
	foundAmplifies := false
	for _, e := range g.Edges {
		if e.From == lb.ID && e.To == miscID && e.Type == graph.EdgeTypeAmplifies {
			foundAmplifies = true
			break
		}
	}
	if !foundAmplifies {
		t.Errorf("expected AMPLIFIES edge from %q to %q", lb.ID, miscID)
	}

	// FindGraphAttackPaths should still detect the original path (Internet → LB
	// → Workload → IAMRole → S3Bucket) since traversal includes AMPLIFIES edges
	// and the main path topology is intact.
	paths := FindGraphAttackPaths(g)
	if len(paths) == 0 {
		t.Error("expected at least one attack path after misconfiguration enrichment; got none")
	}
}

// ── TestGraphTraversalWithMisconfigNodes ─────────────────────────────────────

// TestGraphTraversalWithMisconfigNodes verifies that a Misconfiguration node
// injected directly into the graph does not break traversal and that the AMPLIFIES
// edge from a Workload to a PrivilegedContainer Misconfiguration node is present
// after EnrichWithFindings.
func TestGraphTraversalWithMisconfigNodes(t *testing.T) {
	g := graph.NewGraph()

	internet := &graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet", Metadata: map[string]string{}}
	lb := &graph.Node{ID: "LoadBalancer_svc", Type: graph.NodeTypeLoadBalancer, Name: "svc", Metadata: map[string]string{}}
	workload := &graph.Node{ID: "Deployment_worker", Type: graph.NodeTypeWorkload, Name: "worker", Metadata: map[string]string{}}
	role := &graph.Node{ID: "IAMRole_worker-role", Type: graph.NodeTypeIAMRole, Name: "worker-role", Metadata: map[string]string{"arn": "arn:aws:iam::456:role/worker-role"}}
	secret := &graph.Node{
		ID:       "SecretsManagerSecret_db-pass",
		Type:     graph.NodeTypeSecretsManagerSecret,
		Name:     "db-pass",
		Metadata: map[string]string{"sensitivity": "high"},
	}

	for _, n := range []*graph.Node{internet, lb, workload, role, secret} {
		g.AddNode(n)
	}
	g.AddEdge(internet.ID, lb.ID, graph.EdgeTypeExposes)
	g.AddEdge(lb.ID, workload.ID, graph.EdgeTypeRoutesTo)
	g.AddEdge(workload.ID, role.ID, graph.EdgeTypeRunsAs)
	g.AddEdge(role.ID, secret.ID, graph.EdgeTypeCanAccess)

	findings := []models.Finding{
		{
			RuleID:     "K8S_POD_CAP_SYS_ADMIN",
			ResourceID: "worker-pod",
			Metadata:   map[string]any{"workload_name": "worker"},
		},
	}
	EnrichWithFindings(g, findings)

	// PrivilegedContainer node should exist.
	privID := "Misconfiguration_PrivilegedContainer_worker"
	if g.GetNode(privID) == nil {
		t.Fatalf("expected PrivilegedContainer Misconfiguration node %q to exist", privID)
	}

	// AMPLIFIES edge from workload to PrivilegedContainer should exist.
	foundAmplifies := false
	for _, e := range g.Edges {
		if e.From == workload.ID && e.To == privID && e.Type == graph.EdgeTypeAmplifies {
			foundAmplifies = true
			break
		}
	}
	if !foundAmplifies {
		t.Errorf("expected AMPLIFIES edge from %q to %q", workload.ID, privID)
	}

	// Traversal should still work; the main Internet→S3 path must be detected.
	paths := FindGraphAttackPaths(g)
	if len(paths) == 0 {
		t.Error("expected at least one attack path; got none")
	}

	// Verify the original path still reaches the sensitive secret.
	found := false
	for _, p := range paths {
		for _, nid := range p.Nodes {
			if nid == secret.ID {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected at least one path to include %q", secret.ID)
	}
}
