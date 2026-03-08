// Package graph implements an internal Asset Graph engine for DevOps-Proxy.
// It models infrastructure relationships across Kubernetes and AWS resources,
// providing a reusable foundation for attack path reasoning, AI explanations,
// drift detection, and future SaaS backend integration.
//
// The graph is built from collected cluster inventory (KubernetesClusterData)
// and encodes real topological relationships — Service selectors, pod ownership,
// ServiceAccount bindings, and IRSA role associations — without consulting
// rule findings or heuristics.
package graph

// NodeType identifies the kind of infrastructure entity a Node represents.
type NodeType string

const (
	// NodeTypeInternet is the conceptual external attacker entry point.
	NodeTypeInternet NodeType = "Internet"

	// NodeTypeLoadBalancer is a Kubernetes Service of type LoadBalancer.
	NodeTypeLoadBalancer NodeType = "LoadBalancer"

	// NodeTypeService is a Kubernetes Service (any type).
	NodeTypeService NodeType = "Service"

	// NodeTypeWorkload is a top-level workload controller (Deployment,
	// StatefulSet, DaemonSet, Job, CronJob, ReplicaSet, or Pod).
	NodeTypeWorkload NodeType = "Workload"

	// NodeTypeServiceAccount is a Kubernetes ServiceAccount.
	NodeTypeServiceAccount NodeType = "ServiceAccount"

	// NodeTypeIAMRole is an AWS IAM role reachable via IRSA.
	NodeTypeIAMRole NodeType = "IAMRole"

	// NodeTypeCluster represents the Kubernetes cluster itself (for
	// cluster-scoped control-plane resources such as EKS configuration).
	NodeTypeCluster NodeType = "Cluster"

	// NodeTypeNamespace is a Kubernetes namespace (containment boundary).
	NodeTypeNamespace NodeType = "Namespace"

	// NodeTypeS3Bucket is an Amazon S3 bucket reachable via an IAM role
	// (Phase 12 cloud reachability).
	NodeTypeS3Bucket NodeType = "S3Bucket"

	// NodeTypeSecretsManagerSecret is an AWS Secrets Manager secret reachable
	// via an IAM role (Phase 12 cloud reachability).
	NodeTypeSecretsManagerSecret NodeType = "SecretsManagerSecret"

	// NodeTypeDynamoDBTable is an Amazon DynamoDB table reachable via an IAM
	// role (Phase 12 cloud reachability).
	NodeTypeDynamoDBTable NodeType = "DynamoDBTable"

	// NodeTypeKMSKey is an AWS KMS key reachable via an IAM role
	// (Phase 12 cloud reachability).
	NodeTypeKMSKey NodeType = "KMSKey"
)

// EdgeType describes the relationship direction between two Nodes.
type EdgeType string

const (
	// EdgeTypeExposes: Internet → LoadBalancer — the service is publicly
	// reachable from outside the cluster.
	EdgeTypeExposes EdgeType = "EXPOSES"

	// EdgeTypeRoutesTo: LoadBalancer → Workload — the Service's selector
	// matches the workload's pod labels.
	EdgeTypeRoutesTo EdgeType = "ROUTES_TO"

	// EdgeTypeRunsAs: Workload → ServiceAccount — pods in this workload
	// are bound to the ServiceAccount.
	EdgeTypeRunsAs EdgeType = "RUNS_AS"

	// EdgeTypeAssumesRole: ServiceAccount → IAMRole — the ServiceAccount
	// carries an IRSA annotation granting it permission to assume the
	// named AWS IAM role.
	EdgeTypeAssumesRole EdgeType = "ASSUMES_ROLE"

	// EdgeTypeContains: Namespace → Workload or Namespace → ServiceAccount —
	// the namespace is the ownership boundary for the child resource.
	EdgeTypeContains EdgeType = "CONTAINS"

	// EdgeTypePartOf: Workload → Namespace — the workload belongs to the
	// namespace (inverse of CONTAINS; reserved for future use).
	EdgeTypePartOf EdgeType = "PART_OF"

	// EdgeTypeCanAccess: IAMRole → Cloud Resource — the IAM role's attached
	// policies grant access to the target AWS resource (S3, Secrets Manager,
	// DynamoDB, KMS). Added by graph.EnrichWithCloudAccess (Phase 12).
	EdgeTypeCanAccess EdgeType = "CAN_ACCESS"
)

// Node represents a security-relevant infrastructure entity in the asset graph.
type Node struct {
	// ID is the stable, sanitized identifier used as a graph key.
	// Format: "{NodeType}_{sanitized_name}", e.g. "LoadBalancer_web_svc".
	ID string

	// Type classifies the entity (Internet, LoadBalancer, Workload, …).
	Type NodeType

	// Name is the human-readable resource name (e.g. "web-svc").
	Name string

	// Metadata carries optional key-value annotations such as "namespace",
	// "kind" (for workloads), and "arn" (for IAM roles).
	Metadata map[string]string
}

// Edge is a directional relationship between two Nodes.
type Edge struct {
	// From is the source Node ID.
	From string

	// To is the destination Node ID.
	To string

	// Type describes the semantic relationship.
	Type EdgeType
}

// Graph is the in-memory asset graph.
// Nodes are deduplicated by ID; Edges are deduplicated by (From, To, Type).
type Graph struct {
	// Nodes maps node ID → *Node for O(1) lookup.
	Nodes map[string]*Node

	// Edges holds all directed relationships in insertion order.
	Edges []*Edge

	// edgeSet is used internally for O(1) edge deduplication.
	// Key: "from\x00to\x00type"
	edgeSet map[string]bool
}
