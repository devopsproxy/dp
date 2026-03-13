package rules_test

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/rules"
)

// newK8sCtx is a helper that builds a RuleContext with the given KubernetesClusterData.
func newK8sCtx(data *models.KubernetesClusterData) rules.RuleContext {
	return rules.RuleContext{ClusterData: data}
}

// ── K8S_CLUSTER_SINGLE_NODE ──────────────────────────────────────────────────

func TestK8SClusterSingleNode_NoFinding_MultiNode(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		NodeCount:   3,
	})
	findings := rules.K8SClusterSingleNodeRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 3-node cluster; got %d", len(findings))
	}
}

func TestK8SClusterSingleNode_Fires_OneNode(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "dev-cluster",
		NodeCount:   1,
	})
	findings := rules.K8SClusterSingleNodeRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_CLUSTER_SINGLE_NODE" {
		t.Errorf("RuleID = %q; want K8S_CLUSTER_SINGLE_NODE", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sCluster {
		t.Errorf("ResourceType = %q; want K8S_CLUSTER", f.ResourceType)
	}
	if f.ResourceID != "dev-cluster" {
		t.Errorf("ResourceID = %q; want dev-cluster", f.ResourceID)
	}
}

func TestK8SClusterSingleNode_NilClusterData(t *testing.T) {
	findings := rules.K8SClusterSingleNodeRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}

func TestK8SClusterSingleNode_ZeroNodes(t *testing.T) {
	// NodeCount == 0 should not fire (not a single node).
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "empty",
		NodeCount:   0,
	})
	findings := rules.K8SClusterSingleNodeRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for 0-node cluster; got %d", len(findings))
	}
}

// ── K8S_NODE_OVERALLOCATED ───────────────────────────────────────────────────

func TestK8SNodeOverallocated_NoFinding_HealthyNode(t *testing.T) {
	// 3800m / 4000m = 95% allocatable → well above 20% threshold
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "node-1", CPUCapacityMillis: 4000, AllocatableCPUMillis: 3800},
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings; got %d", len(findings))
	}
}

func TestK8SNodeOverallocated_Fires_BelowThreshold(t *testing.T) {
	// 500m / 4000m = 12.5% allocatable → below 20% threshold
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "node-overloaded", CPUCapacityMillis: 4000, AllocatableCPUMillis: 500},
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_NODE_OVERALLOCATED" {
		t.Errorf("RuleID = %q; want K8S_NODE_OVERALLOCATED", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sNode {
		t.Errorf("ResourceType = %q; want K8S_NODE", f.ResourceType)
	}
	if f.ResourceID != "node-overloaded" {
		t.Errorf("ResourceID = %q; want node-overloaded", f.ResourceID)
	}
}

func TestK8SNodeOverallocated_ExactThreshold_NoFinding(t *testing.T) {
	// exactly 20% allocatable → must NOT fire (threshold is strictly less than)
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "node-exact", CPUCapacityMillis: 4000, AllocatableCPUMillis: 800},
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings at exactly 20%% threshold; got %d", len(findings))
	}
}

func TestK8SNodeOverallocated_MultiNode_OnlyFiringNodes(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "healthy", CPUCapacityMillis: 4000, AllocatableCPUMillis: 3000},   // 75% → ok
			{Name: "overloaded", CPUCapacityMillis: 4000, AllocatableCPUMillis: 400}, // 10% → fires
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "overloaded" {
		t.Errorf("ResourceID = %q; want overloaded", findings[0].ResourceID)
	}
}

func TestK8SNodeOverallocated_ZeroCPUCapacity_Skipped(t *testing.T) {
	// CPUCapacityMillis == 0 should be skipped to avoid division-by-zero.
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Nodes: []models.KubernetesNodeData{
			{Name: "broken-node", CPUCapacityMillis: 0, AllocatableCPUMillis: 0},
		},
	})
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for zero-capacity node; got %d", len(findings))
	}
}

func TestK8SNodeOverallocated_NilClusterData(t *testing.T) {
	findings := rules.K8SNodeOverallocatedRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}

// ── K8S_NAMESPACE_WITHOUT_LIMITS ─────────────────────────────────────────────

func TestK8SNamespaceWithoutLimits_NoFinding_AllHaveLimits(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Namespaces: []models.KubernetesNamespaceData{
			{Name: "default", HasLimitRange: true},
			{Name: "kube-system", HasLimitRange: true},
		},
	})
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings; got %d", len(findings))
	}
}

func TestK8SNamespaceWithoutLimits_Fires_MissingLimitRange(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Namespaces: []models.KubernetesNamespaceData{
			{Name: "staging", HasLimitRange: false},
		},
	})
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_NAMESPACE_WITHOUT_LIMITS" {
		t.Errorf("RuleID = %q; want K8S_NAMESPACE_WITHOUT_LIMITS", f.RuleID)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sNamespace {
		t.Errorf("ResourceType = %q; want K8S_NAMESPACE", f.ResourceType)
	}
	if f.ResourceID != "staging" {
		t.Errorf("ResourceID = %q; want staging", f.ResourceID)
	}
}

func TestK8SNamespaceWithoutLimits_OnlyMissingFiresNotAll(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Namespaces: []models.KubernetesNamespaceData{
			{Name: "with-limits", HasLimitRange: true},
			{Name: "no-limits", HasLimitRange: false},
			{Name: "also-with-limits", HasLimitRange: true},
		},
	})
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "no-limits" {
		t.Errorf("ResourceID = %q; want no-limits", findings[0].ResourceID)
	}
}

func TestK8SNamespaceWithoutLimits_EmptyNamespaces(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{ContextName: "prod"})
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty namespace list; got %d", len(findings))
	}
}

func TestK8SNamespaceWithoutLimits_NilClusterData(t *testing.T) {
	findings := rules.K8SNamespaceWithoutLimitsRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}

// ── K8S_PRIVILEGED_CONTAINER ──────────────────────────────────────────────────

func TestK8SPrivilegedContainer_NilClusterData(t *testing.T) {
	findings := rules.K8SPrivilegedContainerRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}

func TestK8SPrivilegedContainer_NoPrivilegedContainers(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Pods: []models.KubernetesPodData{
			{
				Name:      "safe-pod",
				Namespace: "default",
				Containers: []models.KubernetesContainerData{
					{Name: "app", Privileged: false},
				},
			},
		},
	})
	findings := rules.K8SPrivilegedContainerRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-privileged container; got %d", len(findings))
	}
}

func TestK8SPrivilegedContainer_Fires_PrivilegedContainer(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Pods: []models.KubernetesPodData{
			{
				Name:      "priv-pod",
				Namespace: "kube-system",
				Containers: []models.KubernetesContainerData{
					{Name: "privileged-agent", Privileged: true},
				},
			},
		},
	})
	findings := rules.K8SPrivilegedContainerRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_PRIVILEGED_CONTAINER" {
		t.Errorf("RuleID = %q; want K8S_PRIVILEGED_CONTAINER", f.RuleID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("Severity = %q; want CRITICAL", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sPod {
		t.Errorf("ResourceType = %q; want K8S_POD", f.ResourceType)
	}
	if f.ResourceID != "priv-pod" {
		t.Errorf("ResourceID = %q; want priv-pod", f.ResourceID)
	}
}

func TestK8SPrivilegedContainer_Metadata(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Pods: []models.KubernetesPodData{
			{
				Name:      "agent",
				Namespace: "monitoring",
				Containers: []models.KubernetesContainerData{
					{Name: "collector", Privileged: true},
				},
			},
		},
	})
	findings := rules.K8SPrivilegedContainerRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.Metadata["namespace"] != "monitoring" {
		t.Errorf("metadata.namespace = %v; want monitoring", f.Metadata["namespace"])
	}
	if f.Metadata["container_name"] != "collector" {
		t.Errorf("metadata.container_name = %v; want collector", f.Metadata["container_name"])
	}
}

func TestK8SPrivilegedContainer_MultipleContainers_OnlyPrivilegedFire(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Pods: []models.KubernetesPodData{
			{
				Name:      "mixed-pod",
				Namespace: "default",
				Containers: []models.KubernetesContainerData{
					{Name: "safe", Privileged: false},
					{Name: "dangerous", Privileged: true},
					{Name: "also-safe", Privileged: false},
				},
			},
		},
	})
	findings := rules.K8SPrivilegedContainerRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for 1 privileged container; got %d", len(findings))
	}
	if findings[0].Metadata["container_name"] != "dangerous" {
		t.Errorf("metadata.container_name = %v; want dangerous", findings[0].Metadata["container_name"])
	}
}

func TestK8SPrivilegedContainer_EmptyPods(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{ContextName: "prod"})
	findings := rules.K8SPrivilegedContainerRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty pod list; got %d", len(findings))
	}
}

// ── K8S_SERVICE_PUBLIC_LOADBALANCER ──────────────────────────────────────────

func TestK8SServicePublicLoadBalancer_NilClusterData(t *testing.T) {
	findings := rules.K8SServicePublicLoadBalancerRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}

func TestK8SServicePublicLoadBalancer_ClusterIPNoFinding(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Services: []models.KubernetesServiceData{
			{Name: "internal-svc", Namespace: "default", Type: "ClusterIP", Annotations: nil},
		},
	})
	findings := rules.K8SServicePublicLoadBalancerRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for ClusterIP service; got %d", len(findings))
	}
}

func TestK8SServicePublicLoadBalancer_Fires_PublicLB(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Services: []models.KubernetesServiceData{
			{Name: "web", Namespace: "production", Type: "LoadBalancer", Annotations: map[string]string{}},
		},
	})
	findings := rules.K8SServicePublicLoadBalancerRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_SERVICE_PUBLIC_LOADBALANCER" {
		t.Errorf("RuleID = %q; want K8S_SERVICE_PUBLIC_LOADBALANCER", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sService {
		t.Errorf("ResourceType = %q; want K8S_SERVICE", f.ResourceType)
	}
	if f.ResourceID != "web" {
		t.Errorf("ResourceID = %q; want web", f.ResourceID)
	}
}

func TestK8SServicePublicLoadBalancer_InternalAnnotation_NoFinding(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Services: []models.KubernetesServiceData{
			{
				Name:      "internal-lb",
				Namespace: "default",
				Type:      "LoadBalancer",
				Annotations: map[string]string{
					"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
				},
			},
		},
	})
	findings := rules.K8SServicePublicLoadBalancerRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for internal LoadBalancer; got %d", len(findings))
	}
}

func TestK8SServicePublicLoadBalancer_OnlyPublicLBsFire(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Services: []models.KubernetesServiceData{
			{Name: "cluster-svc", Namespace: "default", Type: "ClusterIP"},
			{Name: "public-lb", Namespace: "default", Type: "LoadBalancer", Annotations: map[string]string{}},
			{
				Name:        "internal-lb",
				Namespace:   "default",
				Type:        "LoadBalancer",
				Annotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "true"},
			},
		},
	})
	findings := rules.K8SServicePublicLoadBalancerRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (only public LB fires); got %d", len(findings))
	}
	if findings[0].ResourceID != "public-lb" {
		t.Errorf("ResourceID = %q; want public-lb", findings[0].ResourceID)
	}
}

func TestK8SServicePublicLoadBalancer_EmptyServices(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{ContextName: "prod"})
	findings := rules.K8SServicePublicLoadBalancerRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty service list; got %d", len(findings))
	}
}

// ── K8S_POD_NO_RESOURCE_REQUESTS ─────────────────────────────────────────────

func TestK8SPodNoResourceRequests_NilClusterData(t *testing.T) {
	findings := rules.K8SPodNoResourceRequestsRule{}.Evaluate(rules.RuleContext{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(findings))
	}
}

func TestK8SPodNoResourceRequests_AllRequestsSet_NoFinding(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Pods: []models.KubernetesPodData{
			{
				Name:      "well-configured",
				Namespace: "default",
				Containers: []models.KubernetesContainerData{
					{Name: "app", HasCPURequest: true, HasMemoryRequest: true},
				},
			},
		},
	})
	findings := rules.K8SPodNoResourceRequestsRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when all requests are set; got %d", len(findings))
	}
}

func TestK8SPodNoResourceRequests_Fires_MissingCPURequest(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Pods: []models.KubernetesPodData{
			{
				Name:      "no-cpu-pod",
				Namespace: "staging",
				Containers: []models.KubernetesContainerData{
					{Name: "app", HasCPURequest: false, HasMemoryRequest: true},
				},
			},
		},
	})
	findings := rules.K8SPodNoResourceRequestsRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "K8S_POD_NO_RESOURCE_REQUESTS" {
		t.Errorf("RuleID = %q; want K8S_POD_NO_RESOURCE_REQUESTS", f.RuleID)
	}
	if f.Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", f.Severity)
	}
	if f.ResourceType != models.ResourceK8sPod {
		t.Errorf("ResourceType = %q; want K8S_POD", f.ResourceType)
	}
}

func TestK8SPodNoResourceRequests_Fires_MissingMemoryRequest(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Pods: []models.KubernetesPodData{
			{
				Name:      "no-mem-pod",
				Namespace: "default",
				Containers: []models.KubernetesContainerData{
					{Name: "app", HasCPURequest: true, HasMemoryRequest: false},
				},
			},
		},
	})
	findings := rules.K8SPodNoResourceRequestsRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for missing memory request; got %d", len(findings))
	}
}

func TestK8SPodNoResourceRequests_OnlyMissingContainersFire(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{
		ContextName: "prod",
		Pods: []models.KubernetesPodData{
			{
				Name:      "mixed-pod",
				Namespace: "default",
				Containers: []models.KubernetesContainerData{
					{Name: "configured", HasCPURequest: true, HasMemoryRequest: true},
					{Name: "unconfigured", HasCPURequest: false, HasMemoryRequest: false},
				},
			},
		},
	})
	findings := rules.K8SPodNoResourceRequestsRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unconfigured container; got %d", len(findings))
	}
	if findings[0].Metadata["container_name"] != "unconfigured" {
		t.Errorf("metadata.container_name = %v; want unconfigured", findings[0].Metadata["container_name"])
	}
}

func TestK8SPodNoResourceRequests_EmptyPods(t *testing.T) {
	ctx := newK8sCtx(&models.KubernetesClusterData{ContextName: "prod"})
	findings := rules.K8SPodNoResourceRequestsRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty pod list; got %d", len(findings))
	}
}
