package models

// KubernetesNodeData holds processed node resource data consumed by K8s rules.
type KubernetesNodeData struct {
	// Name is the Kubernetes node name.
	Name string `json:"name"`

	// CPUCapacityMillis is the total CPU capacity in millicores
	// (e.g. a "4" CPU node → 4000).
	CPUCapacityMillis int64 `json:"cpu_capacity_millis"`

	// AllocatableCPUMillis is the allocatable CPU in millicores
	// (capacity minus system and kubelet reservations).
	AllocatableCPUMillis int64 `json:"allocatable_cpu_millis"`

	// ProviderID is node.Spec.ProviderID, used for cloud provider detection.
	// Format examples: "aws:///us-east-1a/i-xxx", "gce://project/zone/name".
	ProviderID string `json:"provider_id,omitempty"`

	// Labels is a copy of the node's label map, used for provider detection
	// (e.g. "eks.amazonaws.com/nodegroup", "cloud.google.com/gke-nodepool").
	Labels map[string]string `json:"labels,omitempty"`
}

// KubernetesNamespaceData holds processed namespace data consumed by K8s rules.
type KubernetesNamespaceData struct {
	// Name is the Kubernetes namespace name.
	Name string `json:"name"`

	// HasLimitRange is true when at least one LimitRange object exists
	// in the namespace, indicating default resource limits are configured.
	HasLimitRange bool `json:"has_limit_range"`

	// Labels is a copy of the namespace's label map, used for Pod Security
	// Admission enforcement checks (pod-security.kubernetes.io/enforce).
	Labels map[string]string `json:"labels,omitempty"`
}

// KubernetesServiceAccountData holds processed ServiceAccount data consumed
// by K8s governance rules.
type KubernetesServiceAccountData struct {
	// Name is the ServiceAccount name.
	Name string `json:"name"`

	// Namespace is the Kubernetes namespace that owns this ServiceAccount.
	Namespace string `json:"namespace"`

	// AutomountServiceAccountToken reflects the automountServiceAccountToken
	// field on the ServiceAccount. Nil means the field was not set (Kubernetes
	// defaults to true). False means token auto-mounting is explicitly disabled.
	AutomountServiceAccountToken *bool `json:"automount_service_account_token,omitempty"`

	// Annotations is a copy of the ServiceAccount's annotation map.
	// Used to check for the IRSA annotation (eks.amazonaws.com/role-arn).
	Annotations map[string]string `json:"annotations,omitempty"`
}

// KubernetesContainerData holds processed container data consumed by K8s rules.
type KubernetesContainerData struct {
	// Name is the container name within the pod spec.
	Name string `json:"name"`

	// Privileged is true when securityContext.privileged == true.
	Privileged bool `json:"privileged"`

	// HasCPURequest is true when the container declares a non-zero CPU resource request.
	HasCPURequest bool `json:"has_cpu_request"`

	// HasMemoryRequest is true when the container declares a non-zero memory resource request.
	HasMemoryRequest bool `json:"has_memory_request"`

	// RunAsNonRoot is the effective runAsNonRoot flag resolved at collection time
	// (container-level overrides pod-level). Nil means not configured.
	RunAsNonRoot *bool `json:"run_as_non_root,omitempty"`

	// RunAsUser is the effective UID resolved at collection time
	// (container-level overrides pod-level). Nil means not configured.
	RunAsUser *int64 `json:"run_as_user,omitempty"`

	// AddedCapabilities lists the Linux capabilities added via
	// securityContext.capabilities.add.
	AddedCapabilities []string `json:"added_capabilities,omitempty"`

	// SeccompProfileType is the effective seccomp profile type resolved at
	// collection time (container-level overrides pod-level).
	// Values: "RuntimeDefault", "Localhost", "Unconfined", or "" when not set.
	SeccompProfileType string `json:"seccomp_profile_type,omitempty"`
}

// KubernetesPodData holds processed pod data consumed by K8s rules.
type KubernetesPodData struct {
	// Name is the pod name.
	Name string `json:"name"`

	// Namespace is the Kubernetes namespace that owns this pod.
	Namespace string `json:"namespace"`

	// HostNetwork is true when spec.hostNetwork == true.
	HostNetwork bool `json:"host_network,omitempty"`

	// HostPID is true when spec.hostPID == true.
	HostPID bool `json:"host_pid,omitempty"`

	// HostIPC is true when spec.hostIPC == true.
	HostIPC bool `json:"host_ipc,omitempty"`

	// ServiceAccountName is the service account the pod runs as
	// (spec.serviceAccountName). Empty string means Kubernetes will use the
	// "default" service account for the pod's namespace.
	ServiceAccountName string `json:"service_account_name,omitempty"`

	// Labels is a copy of the pod's label map (metadata.labels).
	// Used by the graph builder to match Service selectors to pods.
	Labels map[string]string `json:"labels,omitempty"`

	// WorkloadKind is the top-level controller kind resolved from ownerReferences.
	// Possible values: Deployment, StatefulSet, DaemonSet, Job, CronJob,
	// ReplicaSet (when RS has no known parent), or Pod (uncontrolled pod).
	WorkloadKind string `json:"workload_kind,omitempty"`

	// WorkloadName is the name of the top-level controller that owns this pod.
	// For uncontrolled pods this equals the pod name.
	WorkloadName string `json:"workload_name,omitempty"`

	// Containers holds per-container security and resource data.
	Containers []KubernetesContainerData `json:"containers,omitempty"`
}

// KubernetesServiceData holds processed Service data consumed by K8s rules.
type KubernetesServiceData struct {
	// Name is the Service name.
	Name string `json:"name"`

	// Namespace is the Kubernetes namespace that owns this Service.
	Namespace string `json:"namespace"`

	// Type is the Service type string (e.g. "ClusterIP", "NodePort", "LoadBalancer").
	Type string `json:"type"`

	// Annotations is a copy of the Service's annotation map.
	Annotations map[string]string `json:"annotations,omitempty"`

	// Selector is a copy of the Service's spec.selector label map.
	// Used by the graph builder to resolve which pods this Service routes to.
	// An empty map means the Service has no pod selector (e.g. ExternalName).
	Selector map[string]string `json:"selector,omitempty"`
}

// KubernetesEKSData holds EKS-specific cluster configuration collected from
// the AWS EKS API. It is populated only when the cluster provider is detected
// as "eks" and an EKS data collector is wired into the engine.
type KubernetesEKSData struct {
	// ClusterName is the EKS cluster name used to query the AWS EKS API.
	ClusterName string `json:"cluster_name"`

	// Region is the AWS region where the EKS cluster runs.
	Region string `json:"region"`

	// EndpointPublicAccess is true when the Kubernetes API server endpoint is
	// publicly accessible from the internet (ResourcesVpcConfig.EndpointPublicAccess).
	EndpointPublicAccess bool `json:"endpoint_public_access"`

	// LoggingEnabled is true when at least one control-plane log type is enabled
	// (audit, api, authenticator, controllerManager, scheduler).
	LoggingEnabled bool `json:"logging_enabled"`

	// LoggingTypes is the list of currently enabled control-plane log type strings
	// (e.g. "api", "audit", "authenticator", "controllerManager", "scheduler").
	// An empty slice means no log types are enabled.
	LoggingTypes []string `json:"logging_types,omitempty"`

	// EncryptionEnabled is true when at least one encryption provider is configured
	// for Kubernetes Secrets (cluster.EncryptionConfig is non-empty).
	// When false, secrets stored in etcd are not encrypted at rest.
	EncryptionEnabled bool `json:"encryption_enabled"`

	// OIDCIssuer is the OIDC provider issuer URL associated with the cluster
	// (cluster.Identity.Oidc.Issuer). Empty when no OIDC provider is configured.
	OIDCIssuer string `json:"oidc_issuer,omitempty"`

	// OIDCProviderARN is the IAM OIDC provider ARN associated with the cluster.
	// Populated by matching the OIDCIssuer URL against IAM OIDC providers.
	// Empty when no matching IAM OIDC provider exists — fires EKS_OIDC_PROVIDER_NOT_ASSOCIATED.
	// Format: arn:aws:iam::{accountID}:oidc-provider/oidc.eks.{region}.amazonaws.com/id/{hash}
	OIDCProviderARN string `json:"oidc_provider_arn,omitempty"`

	// NodeRolePolicies is a list of overpermissive IAM policy names found on the
	// node group IAM role (AdministratorAccess or inline policies with Action:"*").
	// A non-empty list fires EKS_NODE_ROLE_OVERPERMISSIVE (CRITICAL).
	NodeRolePolicies []string `json:"node_role_policies,omitempty"`
}

// KubernetesClusterData holds all cluster inventory consumed by Kubernetes rules.
// It is the K8s equivalent of RegionData and is passed via RuleContext.ClusterData.
type KubernetesClusterData struct {
	// ContextName is the kubeconfig context name identifying the cluster.
	ContextName string `json:"context_name"`

	// NodeCount is the total number of nodes in the cluster.
	NodeCount int `json:"node_count"`

	// ClusterProvider is the detected cloud provider: "eks", "gke", "aks", or "unknown".
	// Detected from node ProviderID prefixes and well-known node labels.
	ClusterProvider string `json:"cluster_provider"`

	// Nodes holds per-node CPU resource data.
	Nodes []KubernetesNodeData `json:"nodes,omitempty"`

	// Namespaces holds per-namespace governance data.
	Namespaces []KubernetesNamespaceData `json:"namespaces,omitempty"`

	// Pods holds per-pod workload security and resource data.
	Pods []KubernetesPodData `json:"pods,omitempty"`

	// Services holds per-Service network exposure data.
	Services []KubernetesServiceData `json:"services,omitempty"`

	// ServiceAccounts holds all ServiceAccounts collected from the cluster.
	ServiceAccounts []KubernetesServiceAccountData `json:"service_accounts,omitempty"`

	// EKSData holds EKS-specific control-plane configuration.
	// Nil for non-EKS clusters or when EKS data collection is disabled.
	EKSData *KubernetesEKSData `json:"eks_data,omitempty"`
}
