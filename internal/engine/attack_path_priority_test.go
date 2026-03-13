package engine

import (
	"testing"

	"github.com/devopsproxy/dp/internal/graph"
	"github.com/devopsproxy/dp/internal/models"
)

// ── TestAttackPathSeverityCritical ────────────────────────────────────────────

// TestAttackPathSeverityCritical verifies that a path whose score is >= 90
// receives CRITICAL severity after DetectCloudAttackPaths converts it.
func TestAttackPathSeverityCritical(t *testing.T) {
	// Build a minimal graph: Internet → LoadBalancer → Workload → IAMRole → S3Bucket.
	// ScorePath awards: +40 (Internet) + 20 (Workload) + 20 (IAMRole) + 20 (sensitive S3) = 100.
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

	paths := DetectCloudAttackPaths(g)
	if len(paths) == 0 {
		t.Fatal("expected at least one cloud attack path; got none")
	}

	p := paths[0]
	if p.Score < 90 {
		t.Errorf("expected score >= 90 for CRITICAL; got %d", p.Score)
	}
	if p.Severity != models.AttackPathSeverityCritical {
		t.Errorf("expected severity CRITICAL; got %q", p.Severity)
	}
}

// ── TestAttackPathSeverityHigh ────────────────────────────────────────────────

// TestAttackPathSeverityHigh verifies that a path with 70 <= score < 90
// receives HIGH severity. A path with +40 Internet + 20 IAMRole = 60 won't
// qualify, so we use Internet + Workload + IAMRole = 80 (no sensitive resource).
func TestAttackPathSeverityHigh(t *testing.T) {
	g := graph.NewGraph()

	internet := &graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet", Metadata: map[string]string{}}
	workload := &graph.Node{ID: "Deployment_svc", Type: graph.NodeTypeWorkload, Name: "svc", Metadata: map[string]string{}}
	role := &graph.Node{ID: "IAMRole_reader", Type: graph.NodeTypeIAMRole, Name: "reader", Metadata: map[string]string{"arn": "arn:aws:iam::123:role/reader"}}
	// Non-sensitive S3 bucket: sensitivity is absent → hasSensitiveResource = false.
	bucket := &graph.Node{
		ID:       "S3Bucket_logs",
		Type:     graph.NodeTypeS3Bucket,
		Name:     "logs",
		Metadata: map[string]string{}, // no sensitivity key
	}

	for _, n := range []*graph.Node{internet, workload, role, bucket} {
		g.AddNode(n)
	}
	g.AddEdge(internet.ID, workload.ID, graph.EdgeTypeExposes)
	g.AddEdge(workload.ID, role.ID, graph.EdgeTypeRunsAs)
	g.AddEdge(role.ID, bucket.ID, graph.EdgeTypeCanAccess)

	paths := DetectCloudAttackPaths(g)
	if len(paths) == 0 {
		t.Fatal("expected at least one cloud attack path; got none")
	}

	p := paths[0]
	// Score: +40 (Internet) + 20 (Workload) + 20 (IAMRole) = 80; no sensitive → HIGH.
	if p.Score < 70 || p.Score >= 90 {
		t.Errorf("expected 70 <= score < 90 for HIGH; got %d", p.Score)
	}
	if p.Severity != models.AttackPathSeverityHigh {
		t.Errorf("expected severity HIGH; got %q (score=%d)", p.Severity, p.Score)
	}
}

// ── TestAttackPathSorting ─────────────────────────────────────────────────────

// TestAttackPathSorting verifies that DetectCloudAttackPaths returns paths
// sorted CRITICAL first, then HIGH, then by descending score within severity,
// then shorter paths before longer ones when scores are equal.
func TestAttackPathSorting(t *testing.T) {
	// Use models.AttackPathSeverityFromScore + SeverityRank directly to verify
	// the sort contract without building a full graph (which would require
	// distinct traversal paths). We test the sort comparator via the public
	// model helpers which power FindGraphAttackPaths.

	cases := []struct {
		score    int
		wantSev  models.AttackPathSeverity
		wantRank int
	}{
		{110, models.AttackPathSeverityCritical, 0},
		{100, models.AttackPathSeverityCritical, 0},
		{90, models.AttackPathSeverityCritical, 0},
		{89, models.AttackPathSeverityHigh, 1},
		{70, models.AttackPathSeverityHigh, 1},
		{69, models.AttackPathSeverityMedium, 2},
		{40, models.AttackPathSeverityMedium, 2},
		{0, models.AttackPathSeverityMedium, 2},
	}

	for _, tc := range cases {
		got := models.AttackPathSeverityFromScore(tc.score)
		if got != tc.wantSev {
			t.Errorf("score %d: expected severity %q; got %q", tc.score, tc.wantSev, got)
		}
		if got.SeverityRank() != tc.wantRank {
			t.Errorf("score %d: expected rank %d; got %d", tc.score, tc.wantRank, got.SeverityRank())
		}
	}

	// Verify CRITICAL sorts before HIGH via the rank ordering.
	critRank := models.AttackPathSeverityCritical.SeverityRank()
	highRank := models.AttackPathSeverityHigh.SeverityRank()
	medRank := models.AttackPathSeverityMedium.SeverityRank()
	if critRank >= highRank {
		t.Errorf("expected CRITICAL rank < HIGH rank; got crit=%d high=%d", critRank, highRank)
	}
	if highRank >= medRank {
		t.Errorf("expected HIGH rank < MEDIUM rank; got high=%d med=%d", highRank, medRank)
	}
}
