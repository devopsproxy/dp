package engine

import (
	"testing"

	"github.com/devopsproxy/dp/internal/graph"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// buildCloudGraph constructs a small asset graph for cloud attack path tests.
// It wires: Internet → (EXPOSES) → LB → (ROUTES_TO) → Workload
//
//	→ (RUNS_AS) → SA → (ASSUMES_ROLE) → IAMRole → (CAN_ACCESS) → cloudNode
//	→ (RUNS_ON) → Node → (ASSUMES_ROLE) → IAMRole2 → (CAN_ACCESS) → cloudNode2
func buildCloudGraph(cloudSensitivity, cloudSensitivity2 string) *graph.Graph {
	g := graph.NewGraph()

	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LB_web", Type: graph.NodeTypeLoadBalancer, Name: "web-svc"})
	g.AddNode(&graph.Node{ID: "Workload_api", Type: graph.NodeTypeWorkload, Name: "platform-api"})
	g.AddNode(&graph.Node{ID: "SA_api", Type: graph.NodeTypeServiceAccount, Name: "api-sa"})
	g.AddNode(&graph.Node{ID: "Role_irsa", Type: graph.NodeTypeIAMRole, Name: "irsa-role"})
	g.AddNode(&graph.Node{ID: "Node_1", Type: graph.NodeTypeNode, Name: "ip-10-0-1-1"})
	g.AddNode(&graph.Node{ID: "Role_node", Type: graph.NodeTypeIAMRole, Name: "node-role"})

	if cloudSensitivity != "" {
		g.AddNode(&graph.Node{
			ID:       "S3_customer",
			Type:     graph.NodeTypeS3Bucket,
			Name:     "customer-data",
			Metadata: map[string]string{"sensitivity": cloudSensitivity},
		})
	}
	if cloudSensitivity2 != "" {
		g.AddNode(&graph.Node{
			ID:       "Secret_db",
			Type:     graph.NodeTypeSecretsManagerSecret,
			Name:     "prod-db-password",
			Metadata: map[string]string{"sensitivity": cloudSensitivity2},
		})
	}

	g.AddEdge("Internet", "LB_web", graph.EdgeTypeExposes)
	g.AddEdge("LB_web", "Workload_api", graph.EdgeTypeRoutesTo)
	g.AddEdge("Workload_api", "SA_api", graph.EdgeTypeRunsAs)
	g.AddEdge("SA_api", "Role_irsa", graph.EdgeTypeAssumesRole)
	g.AddEdge("Workload_api", "Node_1", graph.EdgeTypeRunsOn)
	g.AddEdge("Node_1", "Role_node", graph.EdgeTypeAssumesRole)

	if cloudSensitivity != "" {
		g.AddEdge("Role_irsa", "S3_customer", graph.EdgeTypeCanAccess)
	}
	if cloudSensitivity2 != "" {
		g.AddEdge("Role_node", "Secret_db", graph.EdgeTypeCanAccess)
	}

	return g
}

// ── TestCloudAttackPathDetection ──────────────────────────────────────────────

// TestCloudAttackPathDetection verifies that a full Internet→LB→Workload→SA→
// IAMRole→S3(high) chain produces at least one CloudAttackPath with the correct
// source, target, and a score > 0.
func TestCloudAttackPathDetection(t *testing.T) {
	g := buildCloudGraph("high", "")

	paths := DetectCloudAttackPaths(g)

	if len(paths) == 0 {
		t.Fatal("expected at least one cloud attack path; got none")
	}
	found := false
	for _, p := range paths {
		if p.Source == "Internet" && p.Target == "S3_customer" {
			found = true
			if p.Score == 0 {
				t.Errorf("expected non-zero score; got 0")
			}
			if len(p.Nodes) < 2 {
				t.Errorf("expected at least 2 nodes in path; got %d", len(p.Nodes))
			}
			if p.Nodes[0] != "Internet" {
				t.Errorf("first node = %q; want Internet", p.Nodes[0])
			}
			break
		}
	}
	if !found {
		t.Errorf("no path found with Source=Internet, Target=S3_customer; got %+v", paths)
	}
}

// ── TestCloudAttackPath_NoSensitiveData ───────────────────────────────────────

// TestCloudAttackPath_NoSensitiveData verifies that when no cloud resource nodes
// exist at all, DetectCloudAttackPaths returns nil.
func TestCloudAttackPath_NoSensitiveData(t *testing.T) {
	// Graph has Internet + workload + IAM role but no cloud resource leaf nodes.
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LB", Type: graph.NodeTypeLoadBalancer, Name: "svc"})
	g.AddNode(&graph.Node{ID: "WL", Type: graph.NodeTypeWorkload, Name: "api"})
	g.AddNode(&graph.Node{ID: "Role", Type: graph.NodeTypeIAMRole, Name: "role"})
	g.AddEdge("Internet", "LB", graph.EdgeTypeExposes)
	g.AddEdge("LB", "WL", graph.EdgeTypeRoutesTo)
	g.AddEdge("WL", "Role", graph.EdgeTypeRunsAs)
	// No CAN_ACCESS → cloud resource edges; traversal ends at IAMRole (not cloud leaf).

	paths := DetectCloudAttackPaths(g)
	if paths != nil {
		t.Errorf("expected nil when no cloud resource nodes; got %+v", paths)
	}
}

// ── TestCloudAttackPath_S3Sensitive ───────────────────────────────────────────

// TestCloudAttackPath_S3Sensitive verifies that a path ending at a high-sensitivity
// S3 bucket receives a score of 100 (all four criteria met: Internet + Workload +
// IAMRole + sensitive data).
func TestCloudAttackPath_S3Sensitive(t *testing.T) {
	g := buildCloudGraph("high", "")

	paths := DetectCloudAttackPaths(g)

	maxScore := 0
	for _, p := range paths {
		if p.Score > maxScore {
			maxScore = p.Score
		}
	}
	if maxScore != 100 {
		t.Errorf("expected max score 100 for full Internet→Workload→IAMRole→S3(high) chain; got %d", maxScore)
	}
}

// ── TestCloudAttackPath_SecretsManager ────────────────────────────────────────

// TestCloudAttackPath_SecretsManager verifies that a path reaching a high-sensitivity
// Secrets Manager secret via the node instance-profile chain is detected and
// that the path's Nodes slice contains the intermediate Node node.
func TestCloudAttackPath_SecretsManager(t *testing.T) {
	// Instance-profile chain only: Internet → LB → Workload → Node → IAMRole → Secret(high)
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LB", Type: graph.NodeTypeLoadBalancer, Name: "svc"})
	g.AddNode(&graph.Node{ID: "WL", Type: graph.NodeTypeWorkload, Name: "api"})
	g.AddNode(&graph.Node{ID: "Node1", Type: graph.NodeTypeNode, Name: "ip-10-0-1-1"})
	g.AddNode(&graph.Node{ID: "Role1", Type: graph.NodeTypeIAMRole, Name: "node-role"})
	g.AddNode(&graph.Node{
		ID:       "SM_secret",
		Type:     graph.NodeTypeSecretsManagerSecret,
		Name:     "prod-db-password",
		Metadata: map[string]string{"sensitivity": "high"},
	})

	g.AddEdge("Internet", "LB", graph.EdgeTypeExposes)
	g.AddEdge("LB", "WL", graph.EdgeTypeRoutesTo)
	g.AddEdge("WL", "Node1", graph.EdgeTypeRunsOn)
	g.AddEdge("Node1", "Role1", graph.EdgeTypeAssumesRole)
	g.AddEdge("Role1", "SM_secret", graph.EdgeTypeCanAccess)

	paths := DetectCloudAttackPaths(g)

	if len(paths) == 0 {
		t.Fatal("expected at least one cloud attack path; got none")
	}

	found := false
	for _, p := range paths {
		if p.Source == "Internet" && p.Target == "SM_secret" {
			found = true
			// Must include the Node node in the path.
			hasNode := false
			for _, n := range p.Nodes {
				if n == "Node1" {
					hasNode = true
				}
			}
			if !hasNode {
				t.Errorf("expected Node1 in path nodes; got %v", p.Nodes)
			}
			break
		}
	}
	if !found {
		t.Errorf("no path with Source=Internet, Target=SM_secret; got %+v", paths)
	}
}

// ── TestDetectCloudAttackPaths_NilGraph ───────────────────────────────────────

// TestDetectCloudAttackPaths_NilGraph verifies that nil graph input returns nil
// without panicking.
func TestDetectCloudAttackPaths_NilGraph(t *testing.T) {
	if paths := DetectCloudAttackPaths(nil); paths != nil {
		t.Errorf("expected nil for nil graph; got %+v", paths)
	}
}
