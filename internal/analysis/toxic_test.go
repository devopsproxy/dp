package analysis

import (
	"testing"

	"github.com/devopsproxy/dp/internal/graph"
)

// buildInternetToS3Graph builds a minimal graph matching Pattern 1:
// Internet → LoadBalancer → Workload → Node → IAMRole → S3Bucket
func buildInternetToS3Graph() *graph.Graph {
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LoadBalancer_kafka-ui", Type: graph.NodeTypeLoadBalancer, Name: "kafka-ui"})
	g.AddNode(&graph.Node{ID: "Workload_platform-api", Type: graph.NodeTypeWorkload, Name: "platform-api"})
	g.AddNode(&graph.Node{ID: "Node_ip-10-0-1-5", Type: graph.NodeTypeNode, Name: "ip-10-0-1-5"})
	g.AddNode(&graph.Node{ID: "IAMRole_eks-node-role", Type: graph.NodeTypeIAMRole, Name: "eks-node-role"})
	g.AddNode(&graph.Node{ID: "S3Bucket_customer-data", Type: graph.NodeTypeS3Bucket, Name: "customer-data"})
	g.AddEdge("Internet", "LoadBalancer_kafka-ui", graph.EdgeTypeExposes)
	g.AddEdge("LoadBalancer_kafka-ui", "Workload_platform-api", graph.EdgeTypeRoutesTo)
	g.AddEdge("Workload_platform-api", "Node_ip-10-0-1-5", graph.EdgeTypeRunsOn)
	g.AddEdge("Node_ip-10-0-1-5", "IAMRole_eks-node-role", graph.EdgeTypeAssumesRole)
	g.AddEdge("IAMRole_eks-node-role", "S3Bucket_customer-data", graph.EdgeTypeCanAccess)
	return g
}

// buildInternetToSecretsManagerGraph builds a minimal graph matching Pattern 2:
// Internet → LoadBalancer → Workload → Node → IAMRole → SecretsManagerSecret
func buildInternetToSecretsManagerGraph() *graph.Graph {
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LoadBalancer_web", Type: graph.NodeTypeLoadBalancer, Name: "web"})
	g.AddNode(&graph.Node{ID: "Workload_api", Type: graph.NodeTypeWorkload, Name: "api"})
	g.AddNode(&graph.Node{ID: "Node_worker-1", Type: graph.NodeTypeNode, Name: "worker-1"})
	g.AddNode(&graph.Node{ID: "IAMRole_node-role", Type: graph.NodeTypeIAMRole, Name: "node-role"})
	g.AddNode(&graph.Node{ID: "SecretsManagerSecret_db-creds", Type: graph.NodeTypeSecretsManagerSecret, Name: "db-creds"})
	g.AddEdge("Internet", "LoadBalancer_web", graph.EdgeTypeExposes)
	g.AddEdge("LoadBalancer_web", "Workload_api", graph.EdgeTypeRoutesTo)
	g.AddEdge("Workload_api", "Node_worker-1", graph.EdgeTypeRunsOn)
	g.AddEdge("Node_worker-1", "IAMRole_node-role", graph.EdgeTypeAssumesRole)
	g.AddEdge("IAMRole_node-role", "SecretsManagerSecret_db-creds", graph.EdgeTypeCanAccess)
	return g
}

// TestDetectInternetToS3ToxicPath verifies that a graph containing the
// Internet → LoadBalancer → Workload → Node → IAMRole → S3Bucket topology
// produces a CRITICAL ToxicRisk entry.
func TestDetectInternetToS3ToxicPath(t *testing.T) {
	g := buildInternetToS3Graph()
	results := DetectToxicCombinations(g)

	if len(results) == 0 {
		t.Fatal("expected at least one toxic combination; got none")
	}

	found := false
	for _, r := range results {
		if r.Severity == "CRITICAL" && len(r.Path) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a CRITICAL ToxicRisk; got %+v", results)
	}

	// Verify the path contains the expected node names in order.
	r := results[0]
	wantNames := []string{"Internet", "kafka-ui", "platform-api", "ip-10-0-1-5", "eks-node-role", "customer-data"}
	if len(r.Path) != len(wantNames) {
		t.Fatalf("expected path length %d; got %d (%v)", len(wantNames), len(r.Path), r.Path)
	}
	for i, name := range wantNames {
		if r.Path[i] != name {
			t.Errorf("path[%d]: expected %q; got %q", i, name, r.Path[i])
		}
	}
}

// TestDetectSecretsManagerToxicPath verifies that a graph containing the
// Internet → LB → Workload → Node → IAMRole → SecretsManagerSecret topology
// produces a CRITICAL ToxicRisk entry.
func TestDetectSecretsManagerToxicPath(t *testing.T) {
	g := buildInternetToSecretsManagerGraph()
	results := DetectToxicCombinations(g)

	if len(results) == 0 {
		t.Fatal("expected at least one toxic combination; got none")
	}
	found := false
	for _, r := range results {
		if r.Severity == "CRITICAL" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a CRITICAL ToxicRisk for Secrets Manager path; got %+v", results)
	}
}

// TestNoFalsePositives verifies that a graph which does NOT match any toxic
// pattern produces no results.
func TestNoFalsePositives(t *testing.T) {
	// Graph: Internet → LoadBalancer → Workload → ServiceAccount → IAMRole
	// (no Node hop — Pattern 1 and 2 require Node in the path;
	//  Pattern 3 requires SecretsManagerSecret at the end, which is absent)
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LoadBalancer_web", Type: graph.NodeTypeLoadBalancer, Name: "web"})
	g.AddNode(&graph.Node{ID: "Workload_api", Type: graph.NodeTypeWorkload, Name: "api"})
	g.AddNode(&graph.Node{ID: "ServiceAccount_app-sa", Type: graph.NodeTypeServiceAccount, Name: "app-sa"})
	g.AddNode(&graph.Node{ID: "IAMRole_app-role", Type: graph.NodeTypeIAMRole, Name: "app-role"})
	g.AddEdge("Internet", "LoadBalancer_web", graph.EdgeTypeExposes)
	g.AddEdge("LoadBalancer_web", "Workload_api", graph.EdgeTypeRoutesTo)
	g.AddEdge("Workload_api", "ServiceAccount_app-sa", graph.EdgeTypeRunsAs)
	g.AddEdge("ServiceAccount_app-sa", "IAMRole_app-role", graph.EdgeTypeAssumesRole)

	results := DetectToxicCombinations(g)
	if len(results) != 0 {
		t.Errorf("expected no toxic combinations; got %+v", results)
	}
}

// TestNilGraphReturnsNil verifies that passing a nil graph is safe.
func TestNilGraphReturnsNil(t *testing.T) {
	results := DetectToxicCombinations(nil)
	if results != nil {
		t.Errorf("expected nil for nil graph; got %+v", results)
	}
}

// TestPattern3_WorkloadToSecretsManager verifies Pattern 3 (HIGH):
// Workload → ServiceAccount → IAMRole → SecretsManagerSecret
func TestPattern3_WorkloadToSecretsManager(t *testing.T) {
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Workload_billing", Type: graph.NodeTypeWorkload, Name: "billing"})
	g.AddNode(&graph.Node{ID: "ServiceAccount_billing-sa", Type: graph.NodeTypeServiceAccount, Name: "billing-sa"})
	g.AddNode(&graph.Node{ID: "IAMRole_billing-role", Type: graph.NodeTypeIAMRole, Name: "billing-role"})
	g.AddNode(&graph.Node{ID: "SecretsManagerSecret_api-key", Type: graph.NodeTypeSecretsManagerSecret, Name: "api-key"})
	g.AddEdge("Workload_billing", "ServiceAccount_billing-sa", graph.EdgeTypeRunsAs)
	g.AddEdge("ServiceAccount_billing-sa", "IAMRole_billing-role", graph.EdgeTypeAssumesRole)
	g.AddEdge("IAMRole_billing-role", "SecretsManagerSecret_api-key", graph.EdgeTypeCanAccess)

	results := DetectToxicCombinations(g)
	if len(results) == 0 {
		t.Fatal("expected Pattern 3 (HIGH) to fire; got no results")
	}
	found := false
	for _, r := range results {
		if r.Severity == "HIGH" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected HIGH ToxicRisk; got %+v", results)
	}
}

// TestSortOrder verifies that CRITICAL entries appear before HIGH entries.
func TestSortOrder(t *testing.T) {
	// Build a graph matching both Pattern 1 (CRITICAL) and Pattern 3 (HIGH).
	g := buildInternetToS3Graph()
	// Add Pattern 3 topology to the same graph.
	g.AddNode(&graph.Node{ID: "Workload_billing", Type: graph.NodeTypeWorkload, Name: "billing"})
	g.AddNode(&graph.Node{ID: "ServiceAccount_billing-sa", Type: graph.NodeTypeServiceAccount, Name: "billing-sa"})
	g.AddNode(&graph.Node{ID: "IAMRole_billing-role", Type: graph.NodeTypeIAMRole, Name: "billing-role"})
	g.AddNode(&graph.Node{ID: "SecretsManagerSecret_api-key", Type: graph.NodeTypeSecretsManagerSecret, Name: "api-key"})
	g.AddEdge("Workload_billing", "ServiceAccount_billing-sa", graph.EdgeTypeRunsAs)
	g.AddEdge("ServiceAccount_billing-sa", "IAMRole_billing-role", graph.EdgeTypeAssumesRole)
	g.AddEdge("IAMRole_billing-role", "SecretsManagerSecret_api-key", graph.EdgeTypeCanAccess)

	results := DetectToxicCombinations(g)
	if len(results) < 2 {
		t.Fatalf("expected at least 2 results; got %d", len(results))
	}
	if results[0].Severity != "CRITICAL" {
		t.Errorf("expected first result to be CRITICAL; got %q", results[0].Severity)
	}
}
