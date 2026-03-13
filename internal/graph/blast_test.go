package graph

import (
	"testing"
)

// ── TestBlastRadius_S3Reachable ───────────────────────────────────────────────

// TestBlastRadius_S3Reachable verifies that a full Workload → SA → IAMRole →
// S3Bucket path is traversed correctly and the bucket appears in Resources.
func TestBlastRadius_S3Reachable(t *testing.T) {
	g := NewGraph()

	wID := sanitizeID("Deployment_api")
	saID := sanitizeID("ServiceAccount_api-sa")
	roleID := sanitizeID("IAMRole_api-role")
	bucketID := sanitizeID("S3Bucket_customer-data")

	g.AddNode(&Node{ID: wID, Type: NodeTypeWorkload, Name: "api"})
	g.AddNode(&Node{ID: saID, Type: NodeTypeServiceAccount, Name: "api-sa"})
	g.AddNode(&Node{ID: roleID, Type: NodeTypeIAMRole, Name: "api-role",
		Metadata: map[string]string{"arn": "arn:aws:iam::123456789012:role/api-role"}})
	g.AddNode(&Node{ID: bucketID, Type: NodeTypeS3Bucket, Name: "customer-data"})

	g.AddEdge(wID, saID, EdgeTypeRunsAs)
	g.AddEdge(saID, roleID, EdgeTypeAssumesRole)
	g.AddEdge(roleID, bucketID, EdgeTypeCanAccess)

	result, err := ComputeBlastRadius(g, wID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.StartNode == nil || result.StartNode.ID != wID {
		t.Errorf("expected StartNode to be set to deployment node")
	}

	if len(result.Identities) != 1 {
		t.Fatalf("expected 1 identity; got %d", len(result.Identities))
	}
	if result.Identities[0].Name != "api-role" {
		t.Errorf("expected identity name %q; got %q", "api-role", result.Identities[0].Name)
	}

	s3 := result.Resources[NodeTypeS3Bucket]
	if len(s3) != 1 {
		t.Fatalf("expected 1 S3 bucket; got %d", len(s3))
	}
	if s3[0].Name != "customer-data" {
		t.Errorf("expected bucket name %q; got %q", "customer-data", s3[0].Name)
	}

	// No other resource types present.
	for nt, nodes := range result.Resources {
		if nt == NodeTypeS3Bucket {
			continue
		}
		if len(nodes) > 0 {
			t.Errorf("unexpected resource type %q with %d nodes", nt, len(nodes))
		}
	}
}

// ── TestBlastRadius_SecretsReachable ─────────────────────────────────────────

// TestBlastRadius_SecretsReachable verifies traversal starting from a
// ServiceAccount node (no workload) and that a SecretsManagerSecret is collected.
func TestBlastRadius_SecretsReachable(t *testing.T) {
	g := NewGraph()

	saID := sanitizeID("ServiceAccount_backend-sa")
	roleID := sanitizeID("IAMRole_backend-role")
	secretID := sanitizeID("SecretsManagerSecret_prod/db-password")

	g.AddNode(&Node{ID: saID, Type: NodeTypeServiceAccount, Name: "backend-sa"})
	g.AddNode(&Node{ID: roleID, Type: NodeTypeIAMRole, Name: "backend-role"})
	g.AddNode(&Node{ID: secretID, Type: NodeTypeSecretsManagerSecret, Name: "prod/db-password"})

	g.AddEdge(saID, roleID, EdgeTypeAssumesRole)
	g.AddEdge(roleID, secretID, EdgeTypeCanAccess)

	result, err := ComputeBlastRadius(g, saID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Identities) != 1 || result.Identities[0].Name != "backend-role" {
		t.Errorf("expected identity backend-role; got %v", result.Identities)
	}

	secrets := result.Resources[NodeTypeSecretsManagerSecret]
	if len(secrets) != 1 || secrets[0].Name != "prod/db-password" {
		t.Errorf("expected secret prod/db-password; got %v", secrets)
	}
}

// ── TestBlastRadius_NoCloudAccess ────────────────────────────────────────────

// TestBlastRadius_NoCloudAccess verifies that a workload with a service account
// but no IAM role annotation produces empty Identities and Resources.
func TestBlastRadius_NoCloudAccess(t *testing.T) {
	g := NewGraph()

	wID := sanitizeID("Deployment_worker")
	saID := sanitizeID("ServiceAccount_worker-sa")

	g.AddNode(&Node{ID: wID, Type: NodeTypeWorkload, Name: "worker"})
	g.AddNode(&Node{ID: saID, Type: NodeTypeServiceAccount, Name: "worker-sa"})
	g.AddEdge(wID, saID, EdgeTypeRunsAs)

	result, err := ComputeBlastRadius(g, wID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Identities) != 0 {
		t.Errorf("expected 0 identities; got %d", len(result.Identities))
	}
	for nt, nodes := range result.Resources {
		if len(nodes) > 0 {
			t.Errorf("expected no resources; got %d nodes of type %q", len(nodes), nt)
		}
	}
}

// ── TestBlastRadius_NodeRolePath ─────────────────────────────────────────────

// TestBlastRadius_NodeRolePath verifies that a workload with an IAM role that
// can access multiple cloud resource types (S3 + Secrets) is correctly resolved,
// and that multiple S3 buckets are sorted alphabetically.
func TestBlastRadius_NodeRolePath(t *testing.T) {
	g := NewGraph()

	wID := sanitizeID("Deployment_platform-api")
	saID := sanitizeID("ServiceAccount_platform-sa")
	roleID := sanitizeID("IAMRole_platform-api-role")
	bucket1ID := sanitizeID("S3Bucket_customer-data")
	bucket2ID := sanitizeID("S3Bucket_backups")
	secretID := sanitizeID("SecretsManagerSecret_prod/db-password")

	g.AddNode(&Node{ID: wID, Type: NodeTypeWorkload, Name: "platform-api"})
	g.AddNode(&Node{ID: saID, Type: NodeTypeServiceAccount, Name: "platform-sa"})
	g.AddNode(&Node{ID: roleID, Type: NodeTypeIAMRole, Name: "platform-api-role"})
	g.AddNode(&Node{ID: bucket1ID, Type: NodeTypeS3Bucket, Name: "customer-data"})
	g.AddNode(&Node{ID: bucket2ID, Type: NodeTypeS3Bucket, Name: "backups"})
	g.AddNode(&Node{ID: secretID, Type: NodeTypeSecretsManagerSecret, Name: "prod/db-password"})

	g.AddEdge(wID, saID, EdgeTypeRunsAs)
	g.AddEdge(saID, roleID, EdgeTypeAssumesRole)
	g.AddEdge(roleID, bucket1ID, EdgeTypeCanAccess)
	g.AddEdge(roleID, bucket2ID, EdgeTypeCanAccess)
	g.AddEdge(roleID, secretID, EdgeTypeCanAccess)

	result, err := ComputeBlastRadius(g, wID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Identities) != 1 || result.Identities[0].Name != "platform-api-role" {
		t.Fatalf("expected 1 identity platform-api-role; got %v", result.Identities)
	}

	s3 := result.Resources[NodeTypeS3Bucket]
	if len(s3) != 2 {
		t.Fatalf("expected 2 S3 buckets; got %d", len(s3))
	}
	// Sorted ascending: "backups" < "customer-data"
	if s3[0].Name != "backups" || s3[1].Name != "customer-data" {
		t.Errorf("expected sorted buckets [backups, customer-data]; got [%s, %s]", s3[0].Name, s3[1].Name)
	}

	secrets := result.Resources[NodeTypeSecretsManagerSecret]
	if len(secrets) != 1 || secrets[0].Name != "prod/db-password" {
		t.Errorf("expected 1 secret prod/db-password; got %v", secrets)
	}

	// Unrecognised start node returns an error.
	_, err = ComputeBlastRadius(g, "nonexistent-node")
	if err == nil {
		t.Error("expected error for missing node; got nil")
	}
}
