package graph

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// ── TestGraphBuilder_NodeRolePath ─────────────────────────────────────────────

// TestGraphBuilder_NodeRolePath verifies that a workload's blast radius
// includes an IAM role reachable via the node instance-profile path:
//
//	Deployment → Node → IAMRole
//
// This covers clusters that do not use IRSA — pods inherit cloud permissions
// from the node's EC2 instance profile.
func TestGraphBuilder_NodeRolePath(t *testing.T) {
	const (
		nodeProviderID = "aws:///us-east-1a/i-0abc123def456"
		roleARN        = "arn:aws:iam::123456789012:role/eks-node-role"
	)

	cluster := &models.KubernetesClusterData{
		ContextName: "test",
		Nodes: []models.KubernetesNodeData{
			{Name: "ip-10-0-1-1.ec2.internal", ProviderID: nodeProviderID},
		},
		Pods: []models.KubernetesPodData{
			{
				Name:         "api-pod",
				Namespace:    "prod",
				WorkloadKind: "Deployment",
				WorkloadName: "api",
				NodeName:     "ip-10-0-1-1.ec2.internal",
			},
		},
	}

	g, err := BuildAssetGraph(cluster)
	if err != nil {
		t.Fatalf("BuildAssetGraph: %v", err)
	}

	// Enrich with node IAM roles.
	EnrichWithNodeRoles(g, map[string]string{
		"ip-10-0-1-1.ec2.internal": roleARN,
	})

	// Verify Workload node exists.
	wID := sanitizeID("Deployment_api")
	if g.GetNode(wID) == nil {
		t.Fatalf("expected Workload node %q", wID)
	}

	// Verify Node node exists.
	nodeID := sanitizeID("Node_ip-10-0-1-1.ec2.internal")
	nodeNode := g.GetNode(nodeID)
	if nodeNode == nil {
		t.Fatalf("expected Node node %q", nodeID)
	}
	if nodeNode.Type != NodeTypeNode {
		t.Errorf("expected NodeTypeNode; got %q", nodeNode.Type)
	}

	// Verify IAMRole node exists.
	roleID := sanitizeID("IAMRole_eks-node-role")
	roleNode := g.GetNode(roleID)
	if roleNode == nil {
		t.Fatalf("expected IAMRole node %q", roleID)
	}
	if roleNode.Type != NodeTypeIAMRole {
		t.Errorf("expected NodeTypeIAMRole; got %q", roleNode.Type)
	}

	// Verify RUNS_ON edge: Workload → Node.
	if !g.HasEdge(wID, nodeID) {
		t.Errorf("expected RUNS_ON edge %s → %s", wID, nodeID)
	}

	// Verify ASSUMES_ROLE edge: Node → IAMRole.
	if !g.HasEdge(nodeID, roleID) {
		t.Errorf("expected ASSUMES_ROLE edge %s → %s", nodeID, roleID)
	}

	// Verify blast radius resolves the IAM role via the node path.
	result, err := ComputeBlastRadius(g, wID)
	if err != nil {
		t.Fatalf("ComputeBlastRadius: %v", err)
	}
	if len(result.Identities) != 1 || result.Identities[0].Name != "eks-node-role" {
		t.Errorf("expected 1 identity eks-node-role via node path; got %v", result.Identities)
	}
}

// ── TestGraphBuilder_NodeIAMRoleEdge ─────────────────────────────────────────

// TestGraphBuilder_NodeIAMRoleEdge verifies that EnrichWithNodeRoles correctly
// adds a Node → IAMRole ASSUMES_ROLE edge and that the IAMRole node is created
// with the correct metadata (arn). It also verifies that:
//   - A missing Node node is silently skipped (no dangling edges).
//   - An empty role ARN is skipped.
//   - The node's ProviderID is stored in its Metadata.
func TestGraphBuilder_NodeIAMRoleEdge(t *testing.T) {
	const roleARN = "arn:aws:iam::999888777666:role/worker-node-role"

	cluster := &models.KubernetesClusterData{
		ContextName: "test",
		Nodes: []models.KubernetesNodeData{
			{Name: "node-a", ProviderID: "aws:///us-west-2a/i-0aaa111"},
			{Name: "node-b", ProviderID: "aws:///us-west-2b/i-0bbb222"},
		},
	}

	g, err := BuildAssetGraph(cluster)
	if err != nil {
		t.Fatalf("BuildAssetGraph: %v", err)
	}

	// Verify ProviderID is stored in Node metadata.
	nodeAID := sanitizeID("Node_node-a")
	nodeA := g.GetNode(nodeAID)
	if nodeA == nil {
		t.Fatalf("expected Node node %q after BuildAssetGraph", nodeAID)
	}
	if nodeA.Metadata["provider_id"] != "aws:///us-west-2a/i-0aaa111" {
		t.Errorf("expected provider_id metadata; got %q", nodeA.Metadata["provider_id"])
	}

	// Enrich node-a with a role; skip node-b (empty ARN) and a phantom node.
	EnrichWithNodeRoles(g, map[string]string{
		"node-a":       roleARN,
		"node-b":       "",                                          // empty — must be skipped
		"node-missing": "arn:aws:iam::123:role/should-not-appear", // no Node node in graph
	})

	// IAMRole node for node-a must exist.
	roleID := sanitizeID("IAMRole_worker-node-role")
	roleNode := g.GetNode(roleID)
	if roleNode == nil {
		t.Fatalf("expected IAMRole node %q after EnrichWithNodeRoles", roleID)
	}
	if roleNode.Type != NodeTypeIAMRole {
		t.Errorf("expected NodeTypeIAMRole; got %q", roleNode.Type)
	}
	if roleNode.Metadata["arn"] != roleARN {
		t.Errorf("expected arn %q; got %q", roleARN, roleNode.Metadata["arn"])
	}

	// ASSUMES_ROLE edge: node-a → role.
	if !g.HasEdge(nodeAID, roleID) {
		t.Errorf("expected ASSUMES_ROLE edge %s → %s", nodeAID, roleID)
	}

	// No edge from node-b (empty ARN).
	nodeBID := sanitizeID("Node_node-b")
	if g.HasEdge(nodeBID, roleID) {
		t.Errorf("unexpected edge from node-b with empty ARN")
	}

	// The "should-not-appear" role must not exist (node-missing has no graph node).
	phantomRoleID := sanitizeID("IAMRole_should-not-appear")
	if g.GetNode(phantomRoleID) != nil {
		t.Errorf("unexpected IAMRole node for missing node")
	}
}

// ── TestBuildAssetGraph_NodeNodeType ─────────────────────────────────────────

// TestBuildAssetGraph_NodeNodeType verifies that BuildAssetGraph creates
// NodeTypeNode nodes for every cluster node with a non-empty name.
func TestBuildAssetGraph_NodeNodeType(t *testing.T) {
	cluster := &models.KubernetesClusterData{
		ContextName: "ctx",
		Nodes: []models.KubernetesNodeData{
			{Name: "worker-1", ProviderID: "aws:///eu-west-1a/i-0111"},
			{Name: "worker-2", ProviderID: "aws:///eu-west-1b/i-0222"},
			{Name: ""},  // empty name — must be skipped
		},
	}

	g, err := BuildAssetGraph(cluster)
	if err != nil {
		t.Fatalf("BuildAssetGraph: %v", err)
	}

	for _, name := range []string{"worker-1", "worker-2"} {
		nodeID := sanitizeID("Node_" + name)
		n := g.GetNode(nodeID)
		if n == nil {
			t.Errorf("expected Node node %q; not found", nodeID)
			continue
		}
		if n.Type != NodeTypeNode {
			t.Errorf("node %q: expected NodeTypeNode; got %q", nodeID, n.Type)
		}
		if n.Name != name {
			t.Errorf("node %q: expected Name=%q; got %q", nodeID, name, n.Name)
		}
	}

	// Empty-name node must not produce a graph node.
	emptyID := sanitizeID("Node_")
	if g.GetNode(emptyID) != nil {
		t.Errorf("unexpected node for empty-name entry")
	}
}

// ── TestGraphBuilder_WorkloadRunsOnEdge ───────────────────────────────────────

// TestGraphBuilder_WorkloadRunsOnEdge verifies that a RUNS_ON edge is added
// from the workload node to the node it is scheduled on.
func TestGraphBuilder_WorkloadRunsOnEdge(t *testing.T) {
	cluster := &models.KubernetesClusterData{
		ContextName: "ctx",
		Nodes: []models.KubernetesNodeData{
			{Name: "node-1"},
		},
		Pods: []models.KubernetesPodData{
			{
				Name:         "pod-a",
				Namespace:    "default",
				WorkloadKind: "Deployment",
				WorkloadName: "frontend",
				NodeName:     "node-1",
			},
			{
				Name:         "pod-b",
				Namespace:    "default",
				WorkloadKind: "Deployment",
				WorkloadName: "frontend", // same workload, same node → deduplicated
				NodeName:     "node-1",
			},
		},
	}

	g, err := BuildAssetGraph(cluster)
	if err != nil {
		t.Fatalf("BuildAssetGraph: %v", err)
	}

	wID := sanitizeID("Deployment_frontend")
	nodeID := sanitizeID("Node_node-1")

	if !g.HasEdge(wID, nodeID) {
		t.Errorf("expected RUNS_ON edge %s → %s", wID, nodeID)
	}

	// Count RUNS_ON edges — must be exactly one (deduplicated).
	count := 0
	for _, e := range g.EdgesFrom(wID) {
		if e.Type == EdgeTypeRunsOn && e.To == nodeID {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 RUNS_ON edge; got %d", count)
	}
}

// Ensure the existing cloud-access tests still compile in this file's package.
// (They live in graph_test.go; this is just a compile-time cross-reference check.)
var _ = models.CloudResourceTypeS3Bucket
