package kubernetes

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
)

// CollectClusterData collects nodes and namespaces from the cluster using
// the provided clientset and attaches the resolved ClusterInfo to the result.
//
// Both collections are attempted; an error from either aborts the collection.
// The clientset parameter is an interface so tests can inject a fake clientset.
func CollectClusterData(ctx context.Context, clientset k8sclient.Interface, info ClusterInfo) (*ClusterData, error) {
	nodes, err := collectNodes(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("collect nodes: %w", err)
	}

	namespaces, err := collectNamespaces(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("collect namespaces: %w", err)
	}

	pods, err := collectPods(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("collect pods: %w", err)
	}

	services, err := collectServices(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("collect services: %w", err)
	}

	serviceAccounts, err := collectServiceAccounts(ctx, clientset)
	if err != nil {
		return nil, fmt.Errorf("collect service accounts: %w", err)
	}

	return &ClusterData{
		ClusterInfo:     info,
		Nodes:           nodes,
		Namespaces:      namespaces,
		Pods:            pods,
		Services:        services,
		ServiceAccounts: serviceAccounts,
	}, nil
}

// collectNodes lists all nodes and converts them to NodeInfo.
// CPU and memory values are formatted as Kubernetes quantity strings.
func collectNodes(ctx context.Context, clientset k8sclient.Interface) ([]NodeInfo, error) {
	nodeList, err := clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	nodes := make([]NodeInfo, 0, len(nodeList.Items))
	for _, n := range nodeList.Items {
		labels := make(map[string]string, len(n.Labels))
		for k, v := range n.Labels {
			labels[k] = v
		}
		nodes = append(nodes, NodeInfo{
			Name:                 n.Name,
			CPUCapacity:          n.Status.Capacity.Cpu().String(),
			MemoryCapacity:       n.Status.Capacity.Memory().String(),
			AllocatableCPU:       n.Status.Allocatable.Cpu().String(),
			AllocatableMemory:    n.Status.Allocatable.Memory().String(),
			CPUCapacityMillis:    n.Status.Capacity.Cpu().MilliValue(),
			AllocatableCPUMillis: n.Status.Allocatable.Cpu().MilliValue(),
			ProviderID:           n.Spec.ProviderID,
			Labels:               labels,
		})
	}
	return nodes, nil
}

// collectNamespaces lists all namespaces and converts them to NamespaceInfo.
// It also checks each namespace for the presence of at least one LimitRange,
// which governs default resource limits for pods.
func collectNamespaces(ctx context.Context, clientset k8sclient.Interface) ([]NamespaceInfo, error) {
	nsList, err := clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	namespaces := make([]NamespaceInfo, 0, len(nsList.Items))
	for _, ns := range nsList.Items {
		lrList, err := clientset.CoreV1().LimitRanges(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("collect limitranges for namespace %q: %w", ns.Name, err)
		}
		labels := make(map[string]string, len(ns.Labels))
		for k, v := range ns.Labels {
			labels[k] = v
		}
		namespaces = append(namespaces, NamespaceInfo{
			Name:          ns.Name,
			HasLimitRange: len(lrList.Items) > 0,
			Labels:        labels,
		})
	}
	return namespaces, nil
}

// collectPods lists all pods across all namespaces and converts them to PodInfo.
// For each container it extracts the privileged flag, CPU/memory resource requests,
// and PSS-relevant security context fields (runAsNonRoot, runAsUser, capabilities,
// seccompProfile). Container-level security context overrides pod-level for all
// effective PSS fields.
//
// Phase 10.4: resolves the top-level workload owner via ownerReferences.
// Pods owned by a ReplicaSet are followed one level up to detect Deployment
// ownership. The resolved kind/name are stored in WorkloadKind/WorkloadName.
func collectPods(ctx context.Context, clientset k8sclient.Interface) ([]PodInfo, error) {
	podList, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Pre-fetch all ReplicaSets to resolve Pod → ReplicaSet → Deployment chains.
	// Key: "namespace/rsName" → the RS's controlling ownerReference (if any).
	rsOwnerMap := make(map[string]metav1.OwnerReference)
	rsList, err := clientset.AppsV1().ReplicaSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("collect replicasets: %w", err)
	}
	for _, rs := range rsList.Items {
		for _, ref := range rs.OwnerReferences {
			if ref.Controller != nil && *ref.Controller {
				rsOwnerMap[rs.Namespace+"/"+rs.Name] = ref
				break
			}
		}
	}

	pods := make([]PodInfo, 0, len(podList.Items))
	for _, p := range podList.Items {
		podLabels := make(map[string]string, len(p.Labels))
		for k, v := range p.Labels {
			podLabels[k] = v
		}

		workloadKind, workloadName := resolveWorkloadOwner(p.Namespace, p.OwnerReferences, rsOwnerMap)
		if workloadName == "" {
			// No controller found — pod is its own workload.
			workloadKind = "Pod"
			workloadName = p.Name
		}

		pod := PodInfo{
			Name:               p.Name,
			Namespace:          p.Namespace,
			HostNetwork:        p.Spec.HostNetwork,
			HostPID:            p.Spec.HostPID,
			HostIPC:            p.Spec.HostIPC,
			ServiceAccountName: p.Spec.ServiceAccountName,
			Labels:             podLabels,
			WorkloadKind:       workloadKind,
			WorkloadName:       workloadName,
		}
		for _, c := range p.Spec.Containers {
			privileged := c.SecurityContext != nil &&
				c.SecurityContext.Privileged != nil &&
				*c.SecurityContext.Privileged

			cpuReq, hasCPU := c.Resources.Requests[corev1.ResourceCPU]
			hasCPURequest := hasCPU && !cpuReq.IsZero()

			memReq, hasMem := c.Resources.Requests[corev1.ResourceMemory]
			hasMemRequest := hasMem && !memReq.IsZero()

			// Effective runAsNonRoot: container-level overrides pod-level.
			var runAsNonRoot *bool
			if p.Spec.SecurityContext != nil && p.Spec.SecurityContext.RunAsNonRoot != nil {
				v := *p.Spec.SecurityContext.RunAsNonRoot
				runAsNonRoot = &v
			}
			if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil {
				v := *c.SecurityContext.RunAsNonRoot
				runAsNonRoot = &v
			}

			// Effective runAsUser: container-level overrides pod-level.
			var runAsUser *int64
			if p.Spec.SecurityContext != nil && p.Spec.SecurityContext.RunAsUser != nil {
				v := *p.Spec.SecurityContext.RunAsUser
				runAsUser = &v
			}
			if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil {
				v := *c.SecurityContext.RunAsUser
				runAsUser = &v
			}

			// Added capabilities from the container security context only.
			var addedCaps []string
			if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					addedCaps = append(addedCaps, string(cap))
				}
			}

			// Effective seccomp profile type: container-level overrides pod-level.
			var seccompProfileType string
			if p.Spec.SecurityContext != nil && p.Spec.SecurityContext.SeccompProfile != nil {
				seccompProfileType = string(p.Spec.SecurityContext.SeccompProfile.Type)
			}
			if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
				seccompProfileType = string(c.SecurityContext.SeccompProfile.Type)
			}

			pod.Containers = append(pod.Containers, ContainerInfo{
				Name:               c.Name,
				Privileged:         privileged,
				HasCPURequest:      hasCPURequest,
				HasMemoryRequest:   hasMemRequest,
				RunAsNonRoot:       runAsNonRoot,
				RunAsUser:          runAsUser,
				AddedCapabilities:  addedCaps,
				SeccompProfileType: seccompProfileType,
			})
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

// resolveWorkloadOwner walks a pod's ownerReferences to find the top-level
// controller kind and name. When the immediate owner is a ReplicaSet, it looks
// up that RS in rsOwnerMap to detect Deployment (or other) ownership one level
// up. Returns ("", "") when no controlling owner is found (caller substitutes
// "Pod" + pod.Name as the fallback).
//
// Supported controller kinds: Deployment, StatefulSet, DaemonSet, Job, CronJob.
// ReplicaSet is returned as a fallback when it has no known parent controller.
func resolveWorkloadOwner(namespace string, refs []metav1.OwnerReference, rsOwnerMap map[string]metav1.OwnerReference) (kind, name string) {
	for _, ref := range refs {
		if ref.Controller == nil || !*ref.Controller {
			continue
		}
		switch ref.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
			return ref.Kind, ref.Name
		case "ReplicaSet":
			// Follow up to the RS's owner to detect Deployment ownership.
			if ownerRef, ok := rsOwnerMap[namespace+"/"+ref.Name]; ok {
				switch ownerRef.Kind {
				case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
					return ownerRef.Kind, ownerRef.Name
				}
			}
			// RS has no known parent — use it as the workload boundary.
			return "ReplicaSet", ref.Name
		}
	}
	return "", ""
}

// collectServices lists all Services across all namespaces and converts them to ServiceInfo.
// Annotations are copied to avoid sharing the original map.
func collectServices(ctx context.Context, clientset k8sclient.Interface) ([]ServiceInfo, error) {
	svcList, err := clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	services := make([]ServiceInfo, 0, len(svcList.Items))
	for _, s := range svcList.Items {
		annotations := make(map[string]string, len(s.Annotations))
		for k, v := range s.Annotations {
			annotations[k] = v
		}
		selector := make(map[string]string, len(s.Spec.Selector))
		for k, v := range s.Spec.Selector {
			selector[k] = v
		}
		services = append(services, ServiceInfo{
			Name:        s.Name,
			Namespace:   s.Namespace,
			Type:        string(s.Spec.Type),
			Annotations: annotations,
			Selector:    selector,
		})
	}
	return services, nil
}

// collectServiceAccounts lists all ServiceAccounts across all namespaces and
// converts them to ServiceAccountInfo. The AutomountServiceAccountToken field
// is preserved as-is (nil = not set, Kubernetes defaults to true).
func collectServiceAccounts(ctx context.Context, clientset k8sclient.Interface) ([]ServiceAccountInfo, error) {
	saList, err := clientset.CoreV1().ServiceAccounts("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	accounts := make([]ServiceAccountInfo, 0, len(saList.Items))
	for _, sa := range saList.Items {
		annotations := make(map[string]string, len(sa.Annotations))
		for k, v := range sa.Annotations {
			annotations[k] = v
		}
		accounts = append(accounts, ServiceAccountInfo{
			Name:                         sa.Name,
			Namespace:                    sa.Namespace,
			AutomountServiceAccountToken: sa.AutomountServiceAccountToken,
			Annotations:                  annotations,
		})
	}
	return accounts, nil
}
