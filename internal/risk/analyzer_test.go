package risk

import (
	"testing"

	"github.com/devopsproxy/dp/internal/graph"
)

// addNode is a test helper to reduce boilerplate.
func addNode(g *graph.Graph, id string, nt graph.NodeType, name string) {
	g.AddNode(&graph.Node{ID: id, Type: nt, Name: name})
}

// buildBase builds a minimal graph with:
//
//	Internet → LoadBalancer_web → Deployment_api
//	Deployment_api → Node_worker-1 (RUNS_ON)
func buildBase() *graph.Graph {
	g := graph.NewGraph()
	addNode(g, "Internet", graph.NodeTypeInternet, "Internet")
	addNode(g, "LoadBalancer_web", graph.NodeTypeLoadBalancer, "web")
	addNode(g, "Deployment_api", graph.NodeTypeWorkload, "api")
	addNode(g, "Node_worker-1", graph.NodeTypeNode, "worker-1")
	g.AddEdge("Internet", "LoadBalancer_web", graph.EdgeTypeExposes)
	g.AddEdge("LoadBalancer_web", "Deployment_api", graph.EdgeTypeRoutesTo)
	g.AddEdge("Deployment_api", "Node_worker-1", graph.EdgeTypeRunsOn)
	return g
}

// TestInternetWorkloadNode verifies P1 (Internet → Workload → Node) is detected.
func TestInternetWorkloadNode(t *testing.T) {
	g := buildBase()
	results := AnalyzeTopRisks(g)

	if len(results) == 0 {
		t.Fatal("expected at least one RiskFinding; got none")
	}

	found := false
	for _, r := range results {
		// P1: path should contain Internet, LB, Workload, Node.
		if len(r.Path) == 4 && r.Path[0] == "Internet" && r.Path[3] == "worker-1" {
			found = true
			wantScore := scoreInternet + scoreNode // 40+30=70
			if r.Score != wantScore {
				t.Errorf("P1 score: want %d; got %d", wantScore, r.Score)
			}
			if r.Severity != "HIGH" {
				t.Errorf("P1 severity: want HIGH; got %q", r.Severity)
			}
		}
	}
	if !found {
		t.Errorf("P1 (Internet→Workload→Node) not found in results: %+v", results)
	}
}

// TestInternetWorkloadIAMRole verifies P2 (Internet → Workload → IAMRole) is detected.
func TestInternetWorkloadIAMRole(t *testing.T) {
	g := graph.NewGraph()
	addNode(g, "Internet", graph.NodeTypeInternet, "Internet")
	addNode(g, "LoadBalancer_lb", graph.NodeTypeLoadBalancer, "lb")
	addNode(g, "Deployment_svc", graph.NodeTypeWorkload, "svc")
	addNode(g, "ServiceAccount_sa", graph.NodeTypeServiceAccount, "sa")
	addNode(g, "IAMRole_app-role", graph.NodeTypeIAMRole, "app-role")
	g.AddEdge("Internet", "LoadBalancer_lb", graph.EdgeTypeExposes)
	g.AddEdge("LoadBalancer_lb", "Deployment_svc", graph.EdgeTypeRoutesTo)
	g.AddEdge("Deployment_svc", "ServiceAccount_sa", graph.EdgeTypeRunsAs)
	g.AddEdge("ServiceAccount_sa", "IAMRole_app-role", graph.EdgeTypeAssumesRole)

	results := AnalyzeTopRisks(g)
	if len(results) == 0 {
		t.Fatal("expected at least one RiskFinding; got none")
	}

	found := false
	for _, r := range results {
		if r.Score == scoreInternet+scoreIAMRole {
			found = true
			if r.Severity != "HIGH" {
				t.Errorf("P2 severity: want HIGH; got %q", r.Severity)
			}
		}
	}
	if !found {
		t.Errorf("P2 (Internet→Workload→IAMRole) not found; results: %+v", results)
	}
}

// TestRiskScoreCalculation verifies that P3 produces score=130 and CRITICAL severity.
func TestRiskScoreCalculation(t *testing.T) {
	g := graph.NewGraph()
	addNode(g, "Internet", graph.NodeTypeInternet, "Internet")
	addNode(g, "LoadBalancer_lb", graph.NodeTypeLoadBalancer, "lb")
	addNode(g, "Deployment_api", graph.NodeTypeWorkload, "api")
	addNode(g, "ServiceAccount_sa", graph.NodeTypeServiceAccount, "sa")
	addNode(g, "IAMRole_role", graph.NodeTypeIAMRole, "role")
	addNode(g, "S3Bucket_data", graph.NodeTypeS3Bucket, "data")
	g.AddEdge("Internet", "LoadBalancer_lb", graph.EdgeTypeExposes)
	g.AddEdge("LoadBalancer_lb", "Deployment_api", graph.EdgeTypeRoutesTo)
	g.AddEdge("Deployment_api", "ServiceAccount_sa", graph.EdgeTypeRunsAs)
	g.AddEdge("ServiceAccount_sa", "IAMRole_role", graph.EdgeTypeAssumesRole)
	g.AddEdge("IAMRole_role", "S3Bucket_data", graph.EdgeTypeCanAccess)

	results := AnalyzeTopRisks(g)

	found := false
	for _, r := range results {
		wantScore := scoreInternet + scoreIAMRole + scoreCloudResource // 130
		if r.Score == wantScore {
			found = true
			if r.Severity != "CRITICAL" {
				t.Errorf("P3 severity: want CRITICAL; got %q", r.Severity)
			}
		}
	}
	if !found {
		t.Errorf("P3 (score=130) not found; results: %+v", results)
	}
}

// TestSeverityAssignment verifies the three severity thresholds.
func TestSeverityAssignment(t *testing.T) {
	cases := []struct {
		score    int
		wantSev  string
	}{
		{130, "CRITICAL"},
		{100, "CRITICAL"},
		{99, "HIGH"},
		{70, "HIGH"},
		{69, "MEDIUM"},
		{40, "MEDIUM"},
		{39, "LOW"},
	}
	for _, tc := range cases {
		got := severityFromScore(tc.score)
		if got != tc.wantSev {
			t.Errorf("severityFromScore(%d) = %q; want %q", tc.score, got, tc.wantSev)
		}
	}
}

// TestWorkloadNodeIAMRole verifies P4 (Workload → Node → IAMRole) is detected
// even when there is no Internet exposure.
func TestWorkloadNodeIAMRole(t *testing.T) {
	g := graph.NewGraph()
	addNode(g, "Deployment_batch", graph.NodeTypeWorkload, "batch")
	addNode(g, "Node_worker-2", graph.NodeTypeNode, "worker-2")
	addNode(g, "IAMRole_node-role", graph.NodeTypeIAMRole, "node-role")
	g.AddEdge("Deployment_batch", "Node_worker-2", graph.EdgeTypeRunsOn)
	g.AddEdge("Node_worker-2", "IAMRole_node-role", graph.EdgeTypeAssumesRole)

	results := AnalyzeTopRisks(g)

	if len(results) == 0 {
		t.Fatal("expected at least one RiskFinding for P4; got none")
	}
	found := false
	for _, r := range results {
		if r.Score == scoreNode+scoreIAMRole { // 70
			found = true
			if r.Severity != "HIGH" {
				t.Errorf("P4 severity: want HIGH; got %q", r.Severity)
			}
		}
	}
	if !found {
		t.Errorf("P4 (Workload→Node→IAMRole) not found; results: %+v", results)
	}
}

// TestSortedByScoreDescending verifies results are ordered highest-score first.
func TestSortedByScoreDescending(t *testing.T) {
	// Build graph with both P1 (70) and P3 (130).
	g := graph.NewGraph()
	addNode(g, "Internet", graph.NodeTypeInternet, "Internet")
	addNode(g, "LoadBalancer_lb", graph.NodeTypeLoadBalancer, "lb")
	addNode(g, "Deployment_api", graph.NodeTypeWorkload, "api")
	addNode(g, "Node_worker-1", graph.NodeTypeNode, "worker-1")
	addNode(g, "ServiceAccount_sa", graph.NodeTypeServiceAccount, "sa")
	addNode(g, "IAMRole_role", graph.NodeTypeIAMRole, "role")
	addNode(g, "S3Bucket_data", graph.NodeTypeS3Bucket, "data")
	g.AddEdge("Internet", "LoadBalancer_lb", graph.EdgeTypeExposes)
	g.AddEdge("LoadBalancer_lb", "Deployment_api", graph.EdgeTypeRoutesTo)
	g.AddEdge("Deployment_api", "Node_worker-1", graph.EdgeTypeRunsOn)
	g.AddEdge("Deployment_api", "ServiceAccount_sa", graph.EdgeTypeRunsAs)
	g.AddEdge("ServiceAccount_sa", "IAMRole_role", graph.EdgeTypeAssumesRole)
	g.AddEdge("IAMRole_role", "S3Bucket_data", graph.EdgeTypeCanAccess)

	results := AnalyzeTopRisks(g)
	if len(results) < 2 {
		t.Fatalf("expected at least 2 results; got %d: %+v", len(results), results)
	}
	for i := 1; i < len(results); i++ {
		if results[i].Score > results[i-1].Score {
			t.Errorf("results not sorted by score desc: results[%d].Score=%d > results[%d].Score=%d",
				i, results[i].Score, i-1, results[i-1].Score)
		}
	}
}

// TestNilGraphReturnsNil verifies a nil graph is handled safely.
func TestNilGraphReturnsNil(t *testing.T) {
	if got := AnalyzeTopRisks(nil); got != nil {
		t.Errorf("expected nil; got %+v", got)
	}
}
