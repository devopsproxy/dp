package traversal

import (
	"testing"

	"github.com/devopsproxy/dp/internal/graph"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func buildGraph(nodes []graph.Node, edges []struct {
	from, to string
	t        graph.EdgeType
}) *graph.Graph {
	g := graph.NewGraph()
	for i := range nodes {
		n := nodes[i]
		g.AddNode(&n)
	}
	for _, e := range edges {
		g.AddEdge(e.from, e.to, e.t)
	}
	return g
}

func nodeIDs(paths []TraversalResult) [][]string {
	out := make([][]string, len(paths))
	for i, p := range paths {
		out[i] = p.Nodes
	}
	return out
}

func pathContains(paths []TraversalResult, nodeID string) bool {
	for _, p := range paths {
		for _, n := range p.Nodes {
			if n == nodeID {
				return true
			}
		}
	}
	return false
}

// ── TestGraphTraversal_Basic ──────────────────────────────────────────────────

// TestGraphTraversal_Basic verifies that a simple 3-node linear chain produces
// exactly one path containing all three nodes in order.
func TestGraphTraversal_Basic(t *testing.T) {
	g := buildGraph(
		[]graph.Node{
			{ID: "A", Type: graph.NodeTypeInternet, Name: "A"},
			{ID: "B", Type: graph.NodeTypeLoadBalancer, Name: "B"},
			{ID: "C", Type: graph.NodeTypeIAMRole, Name: "C"},
		},
		[]struct {
			from, to string
			t        graph.EdgeType
		}{
			{"A", "B", graph.EdgeTypeExposes},
			{"B", "C", graph.EdgeTypeRoutesTo},
		},
	)

	paths := TraverseFromNode(g, "A", TraversalOptions{})

	if len(paths) != 1 {
		t.Fatalf("expected 1 path; got %d: %v", len(paths), nodeIDs(paths))
	}
	p := paths[0]
	want := []string{"A", "B", "C"}
	if len(p.Nodes) != len(want) {
		t.Fatalf("path nodes = %v; want %v", p.Nodes, want)
	}
	for i, n := range want {
		if p.Nodes[i] != n {
			t.Errorf("path[%d] = %q; want %q", i, p.Nodes[i], n)
		}
	}
	if len(p.Edges) != 2 {
		t.Errorf("expected 2 edges; got %v", p.Edges)
	}
}

// ── TestGraphTraversal_CycleProtection ───────────────────────────────────────

// TestGraphTraversal_CycleProtection verifies that a graph with a cycle does
// not produce an infinite loop and that cycle-closing edges are silently skipped.
func TestGraphTraversal_CycleProtection(t *testing.T) {
	// A → B → A  (cycle)
	g := buildGraph(
		[]graph.Node{
			{ID: "A", Type: graph.NodeTypeWorkload, Name: "A"},
			{ID: "B", Type: graph.NodeTypeServiceAccount, Name: "B"},
		},
		[]struct {
			from, to string
			t        graph.EdgeType
		}{
			{"A", "B", graph.EdgeTypeRunsAs},
			{"B", "A", graph.EdgeTypeRunsAs}, // back-edge
		},
	)

	paths := TraverseFromNode(g, "A", TraversalOptions{})

	// Should produce exactly one path: [A, B].
	// When visiting B, going back to A is blocked (A is already in path).
	if len(paths) != 1 {
		t.Fatalf("expected 1 path; got %d: %v", len(paths), nodeIDs(paths))
	}
	p := paths[0]
	if len(p.Nodes) != 2 || p.Nodes[0] != "A" || p.Nodes[1] != "B" {
		t.Errorf("unexpected path: %v", p.Nodes)
	}
}

// ── TestGraphTraversal_ReachableSensitiveData ─────────────────────────────────

// TestGraphTraversal_ReachableSensitiveData verifies that FindSensitiveResources
// discovers cloud resource nodes marked as "high" sensitivity reachable via
// identity/access edges, and excludes nodes with other sensitivity levels.
func TestGraphTraversal_ReachableSensitiveData(t *testing.T) {
	g := graph.NewGraph()

	// Workload → SA → IAMRole → S3 (high) → (leaf)
	//                          → DynamoDB (medium) → (leaf)
	g.AddNode(&graph.Node{ID: "wl", Type: graph.NodeTypeWorkload, Name: "api"})
	g.AddNode(&graph.Node{ID: "sa", Type: graph.NodeTypeServiceAccount, Name: "api-sa"})
	g.AddNode(&graph.Node{ID: "role", Type: graph.NodeTypeIAMRole, Name: "api-role"})
	g.AddNode(&graph.Node{
		ID: "bucket", Type: graph.NodeTypeS3Bucket, Name: "customer-data",
		Metadata: map[string]string{"sensitivity": "high"},
	})
	g.AddNode(&graph.Node{
		ID: "table", Type: graph.NodeTypeDynamoDBTable, Name: "orders",
		Metadata: map[string]string{"sensitivity": "medium"},
	})

	g.AddEdge("wl", "sa", graph.EdgeTypeRunsAs)
	g.AddEdge("sa", "role", graph.EdgeTypeAssumesRole)
	g.AddEdge("role", "bucket", graph.EdgeTypeCanAccess)
	g.AddEdge("role", "table", graph.EdgeTypeCanAccess)

	sensitive := FindSensitiveResources(g, "wl")

	if len(sensitive) != 1 {
		t.Fatalf("expected 1 sensitive resource; got %d: %v", len(sensitive), sensitive)
	}
	if sensitive[0].Name != "customer-data" {
		t.Errorf("expected customer-data; got %s", sensitive[0].Name)
	}

	// Verify DynamoDB (medium) is NOT returned.
	for _, n := range sensitive {
		if n.Name == "orders" {
			t.Errorf("medium-sensitivity resource 'orders' should not be in sensitive list")
		}
	}
}

// ── TestBlastRadius_Traversal ─────────────────────────────────────────────────

// TestBlastRadius_Traversal verifies that FindSensitiveResources produces the
// same set of HIGH-sensitivity resources as the BFS-based ComputeBlastRadius
// would identify, using the graph traversal engine as the implementation.
func TestBlastRadius_Traversal(t *testing.T) {
	g := graph.NewGraph()

	// Full chain: Deployment → Node → IAMRole → S3(high) + Secret(high) + KMS(medium)
	g.AddNode(&graph.Node{ID: "dep", Type: graph.NodeTypeWorkload, Name: "platform-api"})
	g.AddNode(&graph.Node{ID: "node1", Type: graph.NodeTypeNode, Name: "ip-10-0-1-1"})
	g.AddNode(&graph.Node{ID: "role1", Type: graph.NodeTypeIAMRole, Name: "node-role"})
	g.AddNode(&graph.Node{
		ID: "bucket1", Type: graph.NodeTypeS3Bucket, Name: "customer-data",
		Metadata: map[string]string{"sensitivity": "high"},
	})
	g.AddNode(&graph.Node{
		ID: "secret1", Type: graph.NodeTypeSecretsManagerSecret, Name: "prod-db-password",
		Metadata: map[string]string{"sensitivity": "high"},
	})
	g.AddNode(&graph.Node{
		ID: "kms1", Type: graph.NodeTypeKMSKey, Name: "alias/my-key",
		Metadata: map[string]string{"sensitivity": "medium"},
	})

	g.AddEdge("dep", "node1", graph.EdgeTypeRunsOn)
	g.AddEdge("node1", "role1", graph.EdgeTypeAssumesRole)
	g.AddEdge("role1", "bucket1", graph.EdgeTypeCanAccess)
	g.AddEdge("role1", "secret1", graph.EdgeTypeCanAccess)
	g.AddEdge("role1", "kms1", graph.EdgeTypeCanAccess)

	sensitive := FindSensitiveResources(g, "dep")

	if len(sensitive) != 2 {
		t.Fatalf("expected 2 sensitive resources; got %d", len(sensitive))
	}
	names := make(map[string]bool)
	for _, n := range sensitive {
		names[n.Name] = true
	}
	if !names["customer-data"] {
		t.Errorf("expected customer-data in sensitive resources")
	}
	if !names["prod-db-password"] {
		t.Errorf("expected prod-db-password in sensitive resources")
	}
	if names["alias/my-key"] {
		t.Errorf("kms key (medium) should not be in sensitive list")
	}
}

// ── TestGetNeighbors ──────────────────────────────────────────────────────────

func TestGetNeighbors(t *testing.T) {
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "A", Type: graph.NodeTypeWorkload, Name: "A"})
	g.AddNode(&graph.Node{ID: "B", Type: graph.NodeTypeServiceAccount, Name: "B"})
	g.AddNode(&graph.Node{ID: "C", Type: graph.NodeTypeIAMRole, Name: "C"})
	g.AddEdge("A", "B", graph.EdgeTypeRunsAs)
	g.AddEdge("A", "C", graph.EdgeTypeRunsOn)

	neighbors := GetNeighbors(g, "A")
	if len(neighbors) != 2 {
		t.Fatalf("expected 2 neighbors; got %d", len(neighbors))
	}
	set := map[string]bool{"B": true, "C": true}
	for _, n := range neighbors {
		if !set[n] {
			t.Errorf("unexpected neighbor %q", n)
		}
	}

	// Non-existent node returns empty.
	if n := GetNeighbors(g, "missing"); len(n) != 0 {
		t.Errorf("expected empty for missing node; got %v", n)
	}
}

// ── TestNodeType ──────────────────────────────────────────────────────────────

func TestNodeTypeHelper(t *testing.T) {
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "wl", Type: graph.NodeTypeWorkload, Name: "api"})

	if got := NodeType(g, "wl"); got != "Workload" {
		t.Errorf("NodeType = %q; want %q", got, "Workload")
	}
	if got := NodeType(g, "missing"); got != "" {
		t.Errorf("expected empty for missing; got %q", got)
	}
}

// ── TestTraverseFromNode_EdgeFilter ───────────────────────────────────────────

// TestTraverseFromNode_EdgeFilter verifies that AllowedEdgeTypes correctly
// limits which edges are followed — edges of other types are not traversed.
func TestTraverseFromNode_EdgeFilter(t *testing.T) {
	g := buildGraph(
		[]graph.Node{
			{ID: "start", Type: graph.NodeTypeWorkload, Name: "start"},
			{ID: "sa", Type: graph.NodeTypeServiceAccount, Name: "sa"},
			{ID: "ns", Type: graph.NodeTypeNamespace, Name: "ns"},
		},
		[]struct {
			from, to string
			t        graph.EdgeType
		}{
			{"start", "sa", graph.EdgeTypeRunsAs},   // allowed
			{"start", "ns", graph.EdgeTypeContains}, // blocked by filter
		},
	)

	paths := TraverseFromNode(g, "start", TraversalOptions{
		AllowedEdgeTypes: []graph.EdgeType{graph.EdgeTypeRunsAs},
	})

	if len(paths) != 1 {
		t.Fatalf("expected 1 path; got %d: %v", len(paths), nodeIDs(paths))
	}
	if pathContains(paths, "ns") {
		t.Errorf("namespace node should not appear when CONTAINS edge is filtered out")
	}
}

// ── TestTraverseFromNode_MissingStart ─────────────────────────────────────────

func TestTraverseFromNode_MissingStart(t *testing.T) {
	g := graph.NewGraph()
	if p := TraverseFromNode(g, "does-not-exist", TraversalOptions{}); p != nil {
		t.Errorf("expected nil for missing start node; got %v", p)
	}
}
