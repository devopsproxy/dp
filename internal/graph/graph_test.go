package graph

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// ── TestGraphBuilder_IAMRoleS3Access ──────────────────────────────────────────

// TestGraphBuilder_IAMRoleS3Access verifies that EnrichWithCloudAccess creates
// an S3Bucket node and a CAN_ACCESS edge from the IAMRole node when the role
// has S3 bucket access in the provided access map.
func TestGraphBuilder_IAMRoleS3Access(t *testing.T) {
	const roleArn = "arn:aws:iam::123456789012:role/app-role"

	// Build a minimal graph that already has an IAMRole node (as BuildAssetGraph
	// would produce after the IRSA bridge).
	g := NewGraph()
	roleID := sanitizeID("IAMRole_app-role")
	g.AddNode(&Node{
		ID:       roleID,
		Type:     NodeTypeIAMRole,
		Name:     "app-role",
		Metadata: map[string]string{"arn": roleArn},
	})

	// Enrich with S3 bucket access.
	roleAccess := map[string][]models.RoleCloudAccess{
		roleArn: {
			{
				ResourceType: models.CloudResourceTypeS3Bucket,
				ResourceName: "my-data-bucket",
				ARN:          "arn:aws:s3:::my-data-bucket",
			},
		},
	}
	EnrichWithCloudAccess(g, roleAccess)

	bucketID := sanitizeID("S3Bucket_my-data-bucket")

	// S3Bucket node must exist with correct type and metadata.
	bucketNode := g.GetNode(bucketID)
	if bucketNode == nil {
		t.Fatalf("expected S3Bucket node %q to exist after enrichment", bucketID)
	}
	if bucketNode.Type != NodeTypeS3Bucket {
		t.Errorf("expected NodeTypeS3Bucket; got %q", bucketNode.Type)
	}
	if bucketNode.Name != "my-data-bucket" {
		t.Errorf("expected bucket name %q; got %q", "my-data-bucket", bucketNode.Name)
	}
	if bucketNode.Metadata["arn"] != "arn:aws:s3:::my-data-bucket" {
		t.Errorf("expected arn metadata %q; got %q", "arn:aws:s3:::my-data-bucket", bucketNode.Metadata["arn"])
	}

	// IAMRole → S3Bucket CAN_ACCESS edge must exist.
	if !g.HasEdge(roleID, bucketID) {
		t.Errorf("expected CAN_ACCESS edge %s → %s", roleID, bucketID)
	}
}

// ── TestGraphBuilder_IAMRoleSecretsManagerAccess ───────────────────────────────

// TestGraphBuilder_IAMRoleSecretsManagerAccess verifies that EnrichWithCloudAccess
// creates a SecretsManagerSecret node and a CAN_ACCESS edge for SM secret access,
// and skips a role ARN whose IAMRole node does not exist in the graph.
func TestGraphBuilder_IAMRoleSecretsManagerAccess(t *testing.T) {
	const roleArn = "arn:aws:iam::123456789012:role/api-role"
	const absentRoleArn = "arn:aws:iam::123456789012:role/absent-role"

	g := NewGraph()
	roleID := sanitizeID("IAMRole_api-role")
	g.AddNode(&Node{
		ID:       roleID,
		Type:     NodeTypeIAMRole,
		Name:     "api-role",
		Metadata: map[string]string{"arn": roleArn},
	})

	roleAccess := map[string][]models.RoleCloudAccess{
		roleArn: {
			{
				ResourceType: models.CloudResourceTypeSecretsManagerSecret,
				ResourceName: "prod/db-password",
				ARN:          "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-password",
			},
		},
		// absent-role has no node in the graph — its entry must be silently skipped.
		absentRoleArn: {
			{
				ResourceType: models.CloudResourceTypeS3Bucket,
				ResourceName: "orphan-bucket",
				ARN:          "arn:aws:s3:::orphan-bucket",
			},
		},
	}
	EnrichWithCloudAccess(g, roleAccess)

	secretID := sanitizeID("SecretsManagerSecret_prod/db-password")

	// SecretsManagerSecret node must exist.
	secretNode := g.GetNode(secretID)
	if secretNode == nil {
		t.Fatalf("expected SecretsManagerSecret node %q to exist", secretID)
	}
	if secretNode.Type != NodeTypeSecretsManagerSecret {
		t.Errorf("expected NodeTypeSecretsManagerSecret; got %q", secretNode.Type)
	}

	// IAMRole → SecretsManagerSecret CAN_ACCESS edge must exist.
	if !g.HasEdge(roleID, secretID) {
		t.Errorf("expected CAN_ACCESS edge %s → %s", roleID, secretID)
	}

	// Absent role's bucket must not have been added (no IAMRole node exists for it).
	orphanID := sanitizeID("S3Bucket_orphan-bucket")
	if g.GetNode(orphanID) != nil {
		t.Errorf("orphan bucket node should not exist when IAMRole node is absent")
	}
}

// ── TestGraph_AddNodeDeduplication ────────────────────────────────────────────

// TestGraph_AddNodeDeduplication verifies that adding a node with the same ID
// twice keeps only the first node (first-write-wins semantics).
func TestGraph_AddNodeDeduplication(t *testing.T) {
	g := NewGraph()

	g.AddNode(&Node{ID: "n1", Type: NodeTypeLoadBalancer, Name: "svc-a"})
	g.AddNode(&Node{ID: "n1", Type: NodeTypeWorkload, Name: "svc-b"}) // duplicate ID

	if len(g.Nodes) != 1 {
		t.Fatalf("expected 1 node after duplicate insert; got %d", len(g.Nodes))
	}
	if got := g.Nodes["n1"].Name; got != "svc-a" {
		t.Errorf("expected first-write name %q; got %q", "svc-a", got)
	}
}

// ── TestGraph_AddEdgeDeduplication ────────────────────────────────────────────

// TestGraph_AddEdgeDeduplication verifies that adding the same (from, to, type)
// triple twice produces only one edge.
func TestGraph_AddEdgeDeduplication(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "a", Type: NodeTypeInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "b", Type: NodeTypeLoadBalancer, Name: "svc"})

	g.AddEdge("a", "b", EdgeTypeExposes)
	g.AddEdge("a", "b", EdgeTypeExposes) // duplicate

	if len(g.Edges) != 1 {
		t.Errorf("expected 1 edge after duplicate insert; got %d", len(g.Edges))
	}
}

// ── TestGraph_NeighborTraversal ────────────────────────────────────────────────

// TestGraph_NeighborTraversal verifies that Neighbors returns all direct
// successors of a node and no others.
func TestGraph_NeighborTraversal(t *testing.T) {
	g := NewGraph()
	g.AddNode(&Node{ID: "internet", Type: NodeTypeInternet, Name: "Internet"})
	g.AddNode(&Node{ID: "lb1", Type: NodeTypeLoadBalancer, Name: "lb1"})
	g.AddNode(&Node{ID: "lb2", Type: NodeTypeLoadBalancer, Name: "lb2"})
	g.AddNode(&Node{ID: "workload", Type: NodeTypeWorkload, Name: "app"})

	g.AddEdge("internet", "lb1", EdgeTypeExposes)
	g.AddEdge("internet", "lb2", EdgeTypeExposes)
	g.AddEdge("lb1", "workload", EdgeTypeRoutesTo)

	neighbors := g.Neighbors("internet")
	if len(neighbors) != 2 {
		t.Fatalf("expected 2 neighbors of internet; got %d", len(neighbors))
	}

	ids := map[string]bool{}
	for _, n := range neighbors {
		ids[n.ID] = true
	}
	if !ids["lb1"] || !ids["lb2"] {
		t.Errorf("expected neighbors lb1 and lb2; got %v", ids)
	}

	// workload is not a direct neighbor of internet
	if ids["workload"] {
		t.Error("workload should not be a direct neighbor of internet")
	}

	// Neighbors of lb1
	n1 := g.Neighbors("lb1")
	if len(n1) != 1 || n1[0].ID != "workload" {
		t.Errorf("expected lb1 neighbor = workload; got %v", n1)
	}
}

// ── TestGraphBuilder_ServiceRouting ───────────────────────────────────────────

// TestGraphBuilder_ServiceRouting verifies that BuildAssetGraph creates
// Internet → LoadBalancer → Workload edges when Service selector matches pod labels.
func TestGraphBuilder_ServiceRouting(t *testing.T) {
	cluster := &models.KubernetesClusterData{
		Namespaces: []models.KubernetesNamespaceData{
			{Name: "prod"},
		},
		Services: []models.KubernetesServiceData{
			{
				Name:      "web-svc",
				Namespace: "prod",
				Type:      "LoadBalancer",
				Selector:  map[string]string{"app": "web"},
			},
		},
		Pods: []models.KubernetesPodData{
			{
				Name:               "web-pod-1",
				Namespace:          "prod",
				WorkloadKind:       "Deployment",
				WorkloadName:       "web",
				ServiceAccountName: "default",
				Labels:             map[string]string{"app": "web"},
			},
		},
		ServiceAccounts: []models.KubernetesServiceAccountData{
			{Name: "default", Namespace: "prod"},
		},
	}

	g, err := BuildAssetGraph(cluster)
	if err != nil {
		t.Fatalf("BuildAssetGraph returned error: %v", err)
	}

	lbID := sanitizeID("LoadBalancer_web-svc")
	wID := sanitizeID("Deployment_web")

	// Internet node must exist.
	if g.GetNode("Internet") == nil {
		t.Fatal("expected Internet node")
	}

	// LoadBalancer node must exist.
	if g.GetNode(lbID) == nil {
		t.Fatalf("expected LoadBalancer node %q", lbID)
	}

	// Workload node must exist.
	if g.GetNode(wID) == nil {
		t.Fatalf("expected Workload node %q", wID)
	}

	// Internet → LoadBalancer edge.
	if !g.HasEdge("Internet", lbID) {
		t.Errorf("expected Internet → %s (EXPOSES)", lbID)
	}

	// LoadBalancer → Workload edge.
	if !g.HasEdge(lbID, wID) {
		t.Errorf("expected %s → %s (ROUTES_TO)", lbID, wID)
	}
}

// ── TestGraphBuilder_IRSARoleEdge ─────────────────────────────────────────────

// TestGraphBuilder_IRSARoleEdge verifies that BuildAssetGraph creates a
// ServiceAccount → IAMRole edge when the SA has an IRSA annotation.
func TestGraphBuilder_IRSARoleEdge(t *testing.T) {
	const arn = "arn:aws:iam::123456789012:role/app-role"

	cluster := &models.KubernetesClusterData{
		Namespaces: []models.KubernetesNamespaceData{
			{Name: "prod"},
		},
		Services: []models.KubernetesServiceData{},
		Pods: []models.KubernetesPodData{
			{
				Name:               "api-pod",
				Namespace:          "prod",
				WorkloadKind:       "Deployment",
				WorkloadName:       "api",
				ServiceAccountName: "api-sa",
				Labels:             map[string]string{"app": "api"},
			},
		},
		ServiceAccounts: []models.KubernetesServiceAccountData{
			{
				Name:       "api-sa",
				Namespace:  "prod",
				IAMRoleArn: arn,
			},
		},
	}

	g, err := BuildAssetGraph(cluster)
	if err != nil {
		t.Fatalf("BuildAssetGraph returned error: %v", err)
	}

	saID := sanitizeID("ServiceAccount_api-sa")
	roleID := sanitizeID("IAMRole_app-role")
	wID := sanitizeID("Deployment_api")

	// ServiceAccount node must exist.
	if g.GetNode(saID) == nil {
		t.Fatalf("expected ServiceAccount node %q", saID)
	}

	// IAMRole node must exist with correct metadata.
	roleNode := g.GetNode(roleID)
	if roleNode == nil {
		t.Fatalf("expected IAMRole node %q", roleID)
	}
	if roleNode.Type != NodeTypeIAMRole {
		t.Errorf("expected node type %q; got %q", NodeTypeIAMRole, roleNode.Type)
	}
	if roleNode.Metadata["arn"] != arn {
		t.Errorf("expected arn metadata %q; got %q", arn, roleNode.Metadata["arn"])
	}

	// Workload → ServiceAccount edge.
	if !g.HasEdge(wID, saID) {
		t.Errorf("expected edge %s → %s (RUNS_AS)", wID, saID)
	}

	// ServiceAccount → IAMRole edge.
	if !g.HasEdge(saID, roleID) {
		t.Errorf("expected edge %s → %s (ASSUMES_ROLE)", saID, roleID)
	}
}
