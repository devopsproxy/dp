package kubernetes

// ClusterInfo identifies a Kubernetes cluster and the kubeconfig context used
// to connect to it.
type ClusterInfo struct {
	// ContextName is the kubeconfig context name used to connect.
	ContextName string

	// Server is the Kubernetes API server URL resolved from the kubeconfig.
	Server string
}

// NodeInfo holds basic capacity and allocatable resource data for a cluster node.
type NodeInfo struct {
	Name string

	// CPUCapacity and MemoryCapacity are the total resources reported in
	// node.status.capacity, formatted as Kubernetes quantity strings (e.g. "4", "8Gi").
	CPUCapacity    string
	MemoryCapacity string

	// AllocatableCPU and AllocatableMemory are the resources available for
	// scheduling (capacity minus system/kubelet reservations).
	AllocatableCPU    string
	AllocatableMemory string

	// CPUCapacityMillis is CPUCapacity expressed in millicores for arithmetic
	// comparisons without string parsing in rule code.
	CPUCapacityMillis int64

	// AllocatableCPUMillis is AllocatableCPU expressed in millicores.
	AllocatableCPUMillis int64

	// ProviderID is node.Spec.ProviderID, used for cloud provider detection.
	// Format examples: "aws:///us-east-1a/i-xxx", "gce://project/zone/name".
	ProviderID string

	// Labels is a copy of the node's label map, used for provider detection
	// (e.g. "eks.amazonaws.com/nodegroup", "cloud.google.com/gke-nodepool").
	Labels map[string]string
}

// NamespaceInfo holds basic namespace metadata.
type NamespaceInfo struct {
	Name string

	// HasLimitRange is true when at least one LimitRange object exists in
	// this namespace, indicating default resource limits are configured.
	HasLimitRange bool

	// Labels is a copy of the namespace's label map, used for Pod Security
	// Admission enforcement checks.
	Labels map[string]string
}

// ServiceAccountInfo holds basic ServiceAccount metadata.
type ServiceAccountInfo struct {
	// Name is the ServiceAccount name.
	Name string

	// Namespace is the Kubernetes namespace that owns this ServiceAccount.
	Namespace string

	// AutomountServiceAccountToken reflects the automountServiceAccountToken
	// field. Nil means not set (Kubernetes defaults to true).
	AutomountServiceAccountToken *bool

	// Annotations is a copy of the ServiceAccount's annotation map.
	// Used to check for the IRSA annotation (eks.amazonaws.com/role-arn).
	Annotations map[string]string

	// IAMRoleArn is the value of the eks.amazonaws.com/role-arn annotation
	// when present. Non-empty means the ServiceAccount has been configured for
	// IRSA and workloads using it can assume the named IAM role.
	IAMRoleArn string
}

// ContainerInfo holds per-container security and resource request data.
type ContainerInfo struct {
	// Name is the container name within the pod spec.
	Name string

	// Privileged is true when securityContext.privileged == true.
	Privileged bool

	// HasCPURequest is true when the container declares a non-zero CPU resource request.
	HasCPURequest bool

	// HasMemoryRequest is true when the container declares a non-zero memory resource request.
	HasMemoryRequest bool

	// RunAsNonRoot is the effective runAsNonRoot flag (container-level overrides pod-level).
	// Nil means not configured.
	RunAsNonRoot *bool

	// RunAsUser is the effective UID (container-level overrides pod-level).
	// Nil means not configured.
	RunAsUser *int64

	// AddedCapabilities lists the Linux capabilities added via
	// securityContext.capabilities.add.
	AddedCapabilities []string

	// SeccompProfileType is the effective seccomp profile type (container-level
	// overrides pod-level). Values: "RuntimeDefault", "Localhost", "Unconfined",
	// or "" when not set.
	SeccompProfileType string
}

// PodInfo holds basic pod metadata and its container list.
type PodInfo struct {
	// Name is the pod name.
	Name string

	// Namespace is the Kubernetes namespace that owns this pod.
	Namespace string

	// HostNetwork is true when spec.hostNetwork == true.
	HostNetwork bool

	// HostPID is true when spec.hostPID == true.
	HostPID bool

	// HostIPC is true when spec.hostIPC == true.
	HostIPC bool

	// ServiceAccountName is the service account the pod runs as
	// (spec.serviceAccountName).
	ServiceAccountName string

	// Labels is a copy of the pod's label map (metadata.labels).
	// Used by the graph builder to match Service selectors to pods.
	Labels map[string]string

	// WorkloadKind is the top-level controller kind resolved from ownerReferences.
	// Possible values: Deployment, StatefulSet, DaemonSet, Job, CronJob,
	// ReplicaSet (when RS has no known parent), or Pod (uncontrolled pod).
	WorkloadKind string

	// WorkloadName is the name of the top-level controller that owns this pod.
	// For uncontrolled pods this equals the pod name.
	WorkloadName string

	// NodeName is the Kubernetes node name the pod is scheduled on
	// (spec.nodeName). Used in Phase 14 to build Workload → Node (RUNS_ON)
	// edges in the asset graph.
	NodeName string

	// Containers holds per-container security and resource data.
	Containers []ContainerInfo
}

// ServiceInfo holds basic Service metadata used for network exposure checks.
type ServiceInfo struct {
	// Name is the Service name.
	Name string

	// Namespace is the Kubernetes namespace that owns this Service.
	Namespace string

	// Type is the Service type string (e.g. "ClusterIP", "NodePort", "LoadBalancer").
	Type string

	// Annotations is a copy of the Service's annotation map.
	Annotations map[string]string

	// Selector is a copy of the Service's spec.selector label map.
	// Used by the graph builder to resolve which pods this Service routes to.
	// An empty map means the Service has no pod selector (e.g. ExternalName).
	Selector map[string]string
}

// ClusterData is the inventory collected from a single Kubernetes cluster.
// It is the k8s equivalent of models.AWSRegionData and is the input to k8s rules.
type ClusterData struct {
	ClusterInfo     ClusterInfo
	Nodes           []NodeInfo
	Namespaces      []NamespaceInfo
	Pods            []PodInfo
	Services        []ServiceInfo
	ServiceAccounts []ServiceAccountInfo
}
