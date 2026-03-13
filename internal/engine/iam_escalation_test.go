package engine

import (
	"testing"

	"github.com/devopsproxy/dp/internal/graph"
	"github.com/devopsproxy/dp/internal/graph/traversal"
)

// ── TestAttackPath_PrivilegeEscalation ────────────────────────────────────────

// TestAttackPath_PrivilegeEscalation verifies that a path containing two or more
// IAMRole nodes receives the +10 privilege-escalation bonus in ScorePath, raising
// the maximum achievable score from 100 to 110.
func TestAttackPath_PrivilegeEscalation(t *testing.T) {
	// Path: Internet → LB → Workload → SA → IAMRole_A (ASSUMES_ROLE) →
	//        IAMRole_B (ASSUME_ROLE) → S3(high)
	//
	// Expected criteria met:
	//   +40 Internet
	//   +20 Workload
	//   +20 IAMRole (at least one IAMRole present)
	//   +20 sensitive cloud resource
	//   +10 IAMRole → IAMRole escalation (≥2 IAMRole nodes)
	//   = 110

	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LB", Type: graph.NodeTypeLoadBalancer, Name: "svc"})
	g.AddNode(&graph.Node{ID: "WL", Type: graph.NodeTypeWorkload, Name: "api"})
	g.AddNode(&graph.Node{ID: "SA", Type: graph.NodeTypeServiceAccount, Name: "api-sa"})
	g.AddNode(&graph.Node{ID: "RoleA", Type: graph.NodeTypeIAMRole, Name: "app-role",
		Metadata: map[string]string{"arn": "arn:aws:iam::123:role/app-role"}})
	g.AddNode(&graph.Node{ID: "RoleB", Type: graph.NodeTypeIAMRole, Name: "admin-role",
		Metadata: map[string]string{"arn": "arn:aws:iam::123:role/admin-role"}})
	g.AddNode(&graph.Node{
		ID:   "S3_sensitive",
		Type: graph.NodeTypeS3Bucket,
		Name: "prod-data",
		Metadata: map[string]string{"sensitivity": "high"},
	})

	g.AddEdge("Internet", "LB", graph.EdgeTypeExposes)
	g.AddEdge("LB", "WL", graph.EdgeTypeRoutesTo)
	g.AddEdge("WL", "SA", graph.EdgeTypeRunsAs)
	g.AddEdge("SA", "RoleA", graph.EdgeTypeAssumesRole)
	g.AddEdge("RoleA", "RoleB", graph.EdgeTypeAssumeRole) // cross-role escalation
	g.AddEdge("RoleB", "S3_sensitive", graph.EdgeTypeCanAccess)

	// Build traversal path from the graph topology.
	paths := traversal.TraverseFromNode(g, "Internet", traversal.TraversalOptions{
		AllowedEdgeTypes: attackPathEdges,
	})

	if len(paths) == 0 {
		t.Fatal("expected at least one traversal path; got none")
	}

	// Find the path ending at S3_sensitive.
	var escalationPath *traversal.TraversalResult
	for i := range paths {
		p := &paths[i]
		if len(p.Nodes) > 0 && p.Nodes[len(p.Nodes)-1] == "S3_sensitive" {
			escalationPath = p
			break
		}
	}
	if escalationPath == nil {
		t.Fatal("expected path ending at S3_sensitive; not found")
	}

	score := ScorePath(g, *escalationPath)
	if score != 110 {
		t.Errorf("expected score 110 for full chain with IAMRole escalation; got %d", score)
	}
}

// TestAttackPath_NoEscalation verifies that a path with only one IAMRole node
// does NOT receive the +10 escalation bonus — max score stays at 100.
func TestAttackPath_NoEscalation(t *testing.T) {
	// Path: Internet → LB → Workload → SA → IAMRole → S3(high)
	// Only one IAMRole — no escalation bonus.
	// Expected: +40 +20 +20 +20 = 100

	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LB", Type: graph.NodeTypeLoadBalancer, Name: "svc"})
	g.AddNode(&graph.Node{ID: "WL", Type: graph.NodeTypeWorkload, Name: "api"})
	g.AddNode(&graph.Node{ID: "SA", Type: graph.NodeTypeServiceAccount, Name: "sa"})
	g.AddNode(&graph.Node{ID: "Role", Type: graph.NodeTypeIAMRole, Name: "app-role"})
	g.AddNode(&graph.Node{
		ID:   "S3_data",
		Type: graph.NodeTypeS3Bucket,
		Name: "data",
		Metadata: map[string]string{"sensitivity": "high"},
	})

	g.AddEdge("Internet", "LB", graph.EdgeTypeExposes)
	g.AddEdge("LB", "WL", graph.EdgeTypeRoutesTo)
	g.AddEdge("WL", "SA", graph.EdgeTypeRunsAs)
	g.AddEdge("SA", "Role", graph.EdgeTypeAssumesRole)
	g.AddEdge("Role", "S3_data", graph.EdgeTypeCanAccess)

	paths := traversal.TraverseFromNode(g, "Internet", traversal.TraversalOptions{
		AllowedEdgeTypes: attackPathEdges,
	})

	var s3Path *traversal.TraversalResult
	for i := range paths {
		p := &paths[i]
		if len(p.Nodes) > 0 && p.Nodes[len(p.Nodes)-1] == "S3_data" {
			s3Path = p
			break
		}
	}
	if s3Path == nil {
		t.Fatal("expected path ending at S3_data; not found")
	}

	score := ScorePath(g, *s3Path)
	if score != 100 {
		t.Errorf("expected score 100 for single-IAMRole path; got %d", score)
	}
}

// TestAttackPath_EscalationInFindGraphAttackPaths verifies that
// FindGraphAttackPaths produces a path with score 110 when cross-role escalation
// is present, and that the path's Nodes slice contains both IAMRole nodes.
func TestAttackPath_EscalationInFindGraphAttackPaths(t *testing.T) {
	g := graph.NewGraph()
	g.AddNode(&graph.Node{ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet"})
	g.AddNode(&graph.Node{ID: "LB", Type: graph.NodeTypeLoadBalancer, Name: "svc"})
	g.AddNode(&graph.Node{ID: "WL", Type: graph.NodeTypeWorkload, Name: "api"})
	g.AddNode(&graph.Node{ID: "SA", Type: graph.NodeTypeServiceAccount, Name: "sa"})
	g.AddNode(&graph.Node{ID: "RoleA", Type: graph.NodeTypeIAMRole, Name: "app-role"})
	g.AddNode(&graph.Node{ID: "RoleB", Type: graph.NodeTypeIAMRole, Name: "admin-role"})
	g.AddNode(&graph.Node{
		ID:   "Secret_prod",
		Type: graph.NodeTypeSecretsManagerSecret,
		Name: "db-password",
		Metadata: map[string]string{"sensitivity": "high"},
	})

	g.AddEdge("Internet", "LB", graph.EdgeTypeExposes)
	g.AddEdge("LB", "WL", graph.EdgeTypeRoutesTo)
	g.AddEdge("WL", "SA", graph.EdgeTypeRunsAs)
	g.AddEdge("SA", "RoleA", graph.EdgeTypeAssumesRole)
	g.AddEdge("RoleA", "RoleB", graph.EdgeTypeAssumeRole)
	g.AddEdge("RoleB", "Secret_prod", graph.EdgeTypeCanAccess)

	found := FindGraphAttackPaths(g)
	if len(found) == 0 {
		t.Fatal("expected at least one attack path; got none")
	}

	// Top path should score 110.
	top := found[0]
	if top.Score != 110 {
		t.Errorf("expected top score 110; got %d", top.Score)
	}

	// Verify both IAMRole nodes appear in the winning path.
	hasRoleA, hasRoleB := false, false
	for _, n := range top.Nodes {
		if n == "RoleA" {
			hasRoleA = true
		}
		if n == "RoleB" {
			hasRoleB = true
		}
	}
	if !hasRoleA {
		t.Errorf("expected RoleA in path nodes %v", top.Nodes)
	}
	if !hasRoleB {
		t.Errorf("expected RoleB in path nodes %v", top.Nodes)
	}
}
