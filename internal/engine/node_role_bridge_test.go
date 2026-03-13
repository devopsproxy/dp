package engine

import (
	"testing"

	"github.com/devopsproxy/dp/internal/graph"
)

// ── TestAttackPathViaNodeRole ─────────────────────────────────────────────────

// TestAttackPathViaNodeRole verifies that FindGraphAttackPaths detects the
// Internet → LoadBalancer → Deployment → Node → IAMRole → CloudResource
// attack path when a Kubernetes node's instance-profile role grants access
// to a sensitive cloud resource.
//
// This test covers the instance-profile (non-IRSA) IAM path introduced in
// Phase 14: pods inherit cloud permissions from the node's EC2 instance role
// rather than through a ServiceAccount IRSA annotation.
func TestAttackPathViaNodeRole(t *testing.T) {
	g := graph.NewGraph()

	// ── Infrastructure topology ───────────────────────────────────────────
	internet := &graph.Node{
		ID: "Internet", Type: graph.NodeTypeInternet, Name: "Internet",
		Metadata: map[string]string{},
	}
	lb := &graph.Node{
		ID: "LoadBalancer_frontend", Type: graph.NodeTypeLoadBalancer, Name: "frontend",
		Metadata: map[string]string{},
	}
	workload := &graph.Node{
		ID: "Deployment_api", Type: graph.NodeTypeWorkload, Name: "api",
		Metadata: map[string]string{},
	}
	node := &graph.Node{
		ID: "Node_ip-10-0-1-1", Type: graph.NodeTypeNode, Name: "ip-10-0-1-1",
		Metadata: map[string]string{"provider_id": "aws:///us-east-1a/i-0abc123"},
	}
	role := &graph.Node{
		ID: "IAMRole_eks-node-role", Type: graph.NodeTypeIAMRole, Name: "eks-node-role",
		Metadata: map[string]string{"arn": "arn:aws:iam::123456789012:role/eks-node-role"},
	}
	bucket := &graph.Node{
		ID:       "S3Bucket_customer-data",
		Type:     graph.NodeTypeS3Bucket,
		Name:     "customer-data",
		Metadata: map[string]string{"sensitivity": "high"},
	}

	for _, n := range []*graph.Node{internet, lb, workload, node, role, bucket} {
		g.AddNode(n)
	}

	// Path: Internet → LB → Workload → Node → IAMRole → S3Bucket
	g.AddEdge(internet.ID, lb.ID, graph.EdgeTypeExposes)
	g.AddEdge(lb.ID, workload.ID, graph.EdgeTypeRoutesTo)
	g.AddEdge(workload.ID, node.ID, graph.EdgeTypeRunsOn)
	g.AddEdge(node.ID, role.ID, graph.EdgeTypeAssumesRole)
	g.AddEdge(role.ID, bucket.ID, graph.EdgeTypeCanAccess)

	paths := FindGraphAttackPaths(g)
	if len(paths) == 0 {
		t.Fatal("expected at least one attack path via node IAM role; got none")
	}

	// Verify the path terminates at the S3 bucket (the sensitive cloud resource).
	found := false
	for _, p := range paths {
		for _, nid := range p.Nodes {
			if nid == bucket.ID {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected an attack path reaching %q; none found", bucket.ID)
	}

	// The path through a sensitive node-role resource should score CRITICAL (≥90).
	top := paths[0]
	if top.Score < 90 {
		t.Errorf("expected top path score >= 90 (CRITICAL) via node role; got %d", top.Score)
	}

	// Verify the node is included in the path.
	nodeInPath := false
	for _, p := range paths {
		for _, nid := range p.Nodes {
			if nid == node.ID {
				nodeInPath = true
			}
		}
	}
	if !nodeInPath {
		t.Errorf("expected Node node %q in at least one attack path", node.ID)
	}
}

// ── TestBlastRadiusNodeRole ───────────────────────────────────────────────────

// TestBlastRadiusNodeRole verifies that ComputeBlastRadius starting from a
// Deployment includes cloud resources reachable via the node instance-profile
// path: Deployment → Node → IAMRole → CloudResource.
//
// This is the blast radius analogue of TestAttackPathViaNodeRole: it confirms
// that the same graph topology that enables attack path detection also enables
// blast radius computation.
func TestBlastRadiusNodeRole(t *testing.T) {
	g := graph.NewGraph()

	workload := &graph.Node{
		ID: "Deployment_worker", Type: graph.NodeTypeWorkload, Name: "worker",
		Metadata: map[string]string{},
	}
	node := &graph.Node{
		ID: "Node_ip-10-0-2-5", Type: graph.NodeTypeNode, Name: "ip-10-0-2-5",
		Metadata: map[string]string{"provider_id": "aws:///us-west-2b/i-0xyz987"},
	}
	role := &graph.Node{
		ID: "IAMRole_node-access-role", Type: graph.NodeTypeIAMRole, Name: "node-access-role",
		Metadata: map[string]string{"arn": "arn:aws:iam::999888777:role/node-access-role"},
	}
	secret := &graph.Node{
		ID:       "SecretsManagerSecret_db-password",
		Type:     graph.NodeTypeSecretsManagerSecret,
		Name:     "db-password",
		Metadata: map[string]string{"sensitivity": "high"},
	}
	dynamo := &graph.Node{
		ID:       "DynamoDBTable_orders",
		Type:     graph.NodeTypeDynamoDBTable,
		Name:     "orders",
		Metadata: map[string]string{},
	}

	for _, n := range []*graph.Node{workload, node, role, secret, dynamo} {
		g.AddNode(n)
	}

	// Workload → Node (RUNS_ON) → IAMRole (ASSUMES_ROLE) → resources (CAN_ACCESS)
	g.AddEdge(workload.ID, node.ID, graph.EdgeTypeRunsOn)
	g.AddEdge(node.ID, role.ID, graph.EdgeTypeAssumesRole)
	g.AddEdge(role.ID, secret.ID, graph.EdgeTypeCanAccess)
	g.AddEdge(role.ID, dynamo.ID, graph.EdgeTypeCanAccess)

	result, err := graph.ComputeBlastRadius(g, workload.ID)
	if err != nil {
		t.Fatalf("ComputeBlastRadius: %v", err)
	}

	// IAM identity (the node role) must be reachable.
	if len(result.Identities) != 1 || result.Identities[0].Name != "node-access-role" {
		t.Errorf("expected identity [node-access-role] via node path; got %v", result.Identities)
	}

	// Both cloud resources must appear in the blast radius.
	secrets := result.Resources[graph.NodeTypeSecretsManagerSecret]
	if len(secrets) != 1 || secrets[0].Name != "db-password" {
		t.Errorf("expected SecretsManagerSecret [db-password] in blast radius; got %v", secrets)
	}

	dynamos := result.Resources[graph.NodeTypeDynamoDBTable]
	if len(dynamos) != 1 || dynamos[0].Name != "orders" {
		t.Errorf("expected DynamoDBTable [orders] in blast radius; got %v", dynamos)
	}
}
