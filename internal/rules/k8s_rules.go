package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// ── K8S_CLUSTER_SINGLE_NODE ──────────────────────────────────────────────────

// K8SClusterSingleNodeRule fires when the cluster has exactly one node,
// indicating no redundancy for workloads.
type K8SClusterSingleNodeRule struct{}

func (r K8SClusterSingleNodeRule) ID() string   { return "K8S_CLUSTER_SINGLE_NODE" }
func (r K8SClusterSingleNodeRule) Name() string { return "Kubernetes Cluster Has Single Node" }

func (r K8SClusterSingleNodeRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	if ctx.ClusterData.NodeCount != 1 {
		return nil
	}
	return []models.Finding{
		{
			ID:             fmt.Sprintf("%s:%s", r.ID(), ctx.ClusterData.ContextName),
			RuleID:         r.ID(),
			ResourceID:     ctx.ClusterData.ContextName,
			ResourceType:   models.ResourceK8sCluster,
			Region:         ctx.ClusterData.ContextName,
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityHigh,
			Explanation:    "Cluster has only 1 node; there is no redundancy for scheduled workloads.",
			Recommendation: "Add at least 2 more nodes to provide high availability for workloads.",
			DetectedAt:     time.Now().UTC(),
		},
	}
}

// ── K8S_NODE_OVERALLOCATED ───────────────────────────────────────────────────

// overallocatedCPUThresholdPercent is the minimum acceptable percentage of
// allocatable CPU relative to total capacity. Nodes below this threshold fire.
const overallocatedCPUThresholdPercent = 20.0

// K8SNodeOverallocatedRule fires for each node where the allocatable CPU is
// less than overallocatedCPUThresholdPercent of the node's total CPU capacity.
type K8SNodeOverallocatedRule struct{}

func (r K8SNodeOverallocatedRule) ID() string   { return "K8S_NODE_OVERALLOCATED" }
func (r K8SNodeOverallocatedRule) Name() string { return "Kubernetes Node CPU Overallocated" }

func (r K8SNodeOverallocatedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, node := range ctx.ClusterData.Nodes {
		if node.CPUCapacityMillis == 0 {
			continue // skip nodes with no reported CPU capacity
		}
		freePercent := float64(node.AllocatableCPUMillis) / float64(node.CPUCapacityMillis) * 100.0
		if freePercent < overallocatedCPUThresholdPercent {
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("%s:%s:%s", r.ID(), ctx.ClusterData.ContextName, node.Name),
				RuleID:       r.ID(),
				ResourceID:   node.Name,
				ResourceType: models.ResourceK8sNode,
				Region:       ctx.ClusterData.ContextName,
				AccountID:    ctx.AccountID,
				Profile:      ctx.Profile,
				Severity:     models.SeverityHigh,
				Explanation: fmt.Sprintf(
					"Node %q has only %.1f%% of CPU allocatable (threshold: %.0f%%).",
					node.Name, freePercent, overallocatedCPUThresholdPercent,
				),
				Recommendation: "Add more nodes or reduce pod resource requests on this node to restore scheduling headroom.",
				DetectedAt:     time.Now().UTC(),
			})
		}
	}
	return findings
}

// ── K8S_NAMESPACE_WITHOUT_LIMITS ─────────────────────────────────────────────

// K8SNamespaceWithoutLimitsRule fires for each namespace that has no LimitRange
// object, meaning pods can consume unbounded CPU and memory resources.
type K8SNamespaceWithoutLimitsRule struct{}

func (r K8SNamespaceWithoutLimitsRule) ID() string {
	return "K8S_NAMESPACE_WITHOUT_LIMITS"
}
func (r K8SNamespaceWithoutLimitsRule) Name() string {
	return "Kubernetes Namespace Without LimitRange"
}

func (r K8SNamespaceWithoutLimitsRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, ns := range ctx.ClusterData.Namespaces {
		if ns.HasLimitRange {
			continue
		}
		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("%s:%s:%s", r.ID(), ctx.ClusterData.ContextName, ns.Name),
			RuleID:       r.ID(),
			ResourceID:   ns.Name,
			ResourceType: models.ResourceK8sNamespace,
			Region:       ctx.ClusterData.ContextName,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityMedium,
			Explanation: fmt.Sprintf(
				"Namespace %q has no LimitRange; pods may consume unbounded CPU and memory.",
				ns.Name,
			),
			Recommendation: fmt.Sprintf(
				"Add a LimitRange to namespace %q to enforce default resource limits for pods.",
				ns.Name,
			),
			DetectedAt: time.Now().UTC(),
		})
	}
	return findings
}

// ── K8S_PRIVILEGED_CONTAINER ─────────────────────────────────────────────────

// K8SPrivilegedContainerRule fires for each container running with
// securityContext.privileged == true. Privileged containers have full host
// access and significantly expand the attack surface.
type K8SPrivilegedContainerRule struct{}

func (r K8SPrivilegedContainerRule) ID() string   { return "K8S_PRIVILEGED_CONTAINER" }
func (r K8SPrivilegedContainerRule) Name() string { return "Kubernetes Privileged Container Detected" }

func (r K8SPrivilegedContainerRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, pod := range ctx.ClusterData.Pods {
		for _, c := range pod.Containers {
			if !c.Privileged {
				continue
			}
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("%s:%s:%s/%s/%s", r.ID(), ctx.ClusterData.ContextName, pod.Namespace, pod.Name, c.Name),
				RuleID:       r.ID(),
				ResourceID:   pod.Name,
				ResourceType: models.ResourceK8sPod,
				Region:       ctx.ClusterData.ContextName,
				AccountID:    ctx.AccountID,
				Profile:      ctx.Profile,
				Severity:     models.SeverityCritical,
				Explanation: fmt.Sprintf(
					"Container %q in pod %q (namespace %q) is running with a privileged security context.",
					c.Name, pod.Name, pod.Namespace,
				),
				Recommendation: "Remove the privileged flag from the container security context. " +
					"Use Pod Security Admission to block privileged containers cluster-wide.",
				DetectedAt: time.Now().UTC(),
				Metadata: map[string]any{
					"namespace":      pod.Namespace,
					"container_name": c.Name,
				},
			})
		}
	}
	return findings
}

// ── K8S_SERVICE_PUBLIC_LOADBALANCER ──────────────────────────────────────────

// awsInternalLBAnnotation is the annotation that marks a LoadBalancer Service
// as internal (reachable only within the VPC).
const awsInternalLBAnnotation = "service.beta.kubernetes.io/aws-load-balancer-internal"

// K8SServicePublicLoadBalancerRule fires for each Service of type LoadBalancer
// that does NOT carry the AWS internal load-balancer annotation.
type K8SServicePublicLoadBalancerRule struct{}

func (r K8SServicePublicLoadBalancerRule) ID() string {
	return "K8S_SERVICE_PUBLIC_LOADBALANCER"
}
func (r K8SServicePublicLoadBalancerRule) Name() string {
	return "Kubernetes Service Exposes Public Load Balancer"
}

func (r K8SServicePublicLoadBalancerRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, svc := range ctx.ClusterData.Services {
		if svc.Type != "LoadBalancer" {
			continue
		}
		if svc.Annotations[awsInternalLBAnnotation] == "true" {
			continue
		}
		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("%s:%s:%s/%s", r.ID(), ctx.ClusterData.ContextName, svc.Namespace, svc.Name),
			RuleID:       r.ID(),
			ResourceID:   svc.Name,
			ResourceType: models.ResourceK8sService,
			Region:       ctx.ClusterData.ContextName,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityHigh,
			Explanation: fmt.Sprintf(
				"Service %q (namespace %q) uses type LoadBalancer without the internal annotation, exposing it publicly.",
				svc.Name, svc.Namespace,
			),
			Recommendation: fmt.Sprintf(
				"Add annotation %q: \"true\" to restrict the load balancer to internal VPC traffic, "+
					"or replace with an Ingress resource backed by an internal controller.",
				awsInternalLBAnnotation,
			),
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"namespace": svc.Namespace,
			},
		})
	}
	return findings
}

// ── K8S_POD_NO_RESOURCE_REQUESTS ─────────────────────────────────────────────

// K8SPodNoResourceRequestsRule fires for each container that is missing a CPU
// or memory resource request. Without requests the scheduler cannot make
// accurate placement decisions and quality-of-service guarantees are lost.
type K8SPodNoResourceRequestsRule struct{}

func (r K8SPodNoResourceRequestsRule) ID() string { return "K8S_POD_NO_RESOURCE_REQUESTS" }
func (r K8SPodNoResourceRequestsRule) Name() string {
	return "Kubernetes Pod Container Missing Resource Requests"
}

func (r K8SPodNoResourceRequestsRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, pod := range ctx.ClusterData.Pods {
		for _, c := range pod.Containers {
			if c.HasCPURequest && c.HasMemoryRequest {
				continue
			}
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("%s:%s:%s/%s/%s", r.ID(), ctx.ClusterData.ContextName, pod.Namespace, pod.Name, c.Name),
				RuleID:       r.ID(),
				ResourceID:   pod.Name,
				ResourceType: models.ResourceK8sPod,
				Region:       ctx.ClusterData.ContextName,
				AccountID:    ctx.AccountID,
				Profile:      ctx.Profile,
				Severity:     models.SeverityMedium,
				Explanation: fmt.Sprintf(
					"Container %q in pod %q (namespace %q) is missing CPU or memory resource requests.",
					c.Name, pod.Name, pod.Namespace,
				),
				Recommendation: "Set explicit CPU and memory resource requests on all containers " +
					"to enable accurate scheduler placement and Guaranteed/Burstable QoS.",
				DetectedAt: time.Now().UTC(),
				Metadata: map[string]any{
					"namespace":          pod.Namespace,
					"container_name":     c.Name,
					"has_cpu_request":    c.HasCPURequest,
					"has_memory_request": c.HasMemoryRequest,
				},
			})
		}
	}
	return findings
}
