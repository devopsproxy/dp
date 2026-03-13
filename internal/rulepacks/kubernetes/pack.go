// Package kubernetes provides the Kubernetes governance rule pack.
// It groups cluster-level deterministic checks into a single registration call.
package kubernetes

import "github.com/devopsproxy/dp/internal/rules"

// New returns the complete set of Kubernetes governance rules ordered by
// severity: CRITICAL first, then HIGH, then MEDIUM.
func New() []rules.Rule {
	return []rules.Rule{
		rules.K8SPrivilegedContainerRule{},       // CRITICAL
		rules.K8SClusterSingleNodeRule{},         // HIGH
		rules.K8SNodeOverallocatedRule{},         // HIGH
		rules.K8SServicePublicLoadBalancerRule{}, // HIGH
		rules.K8SNamespaceWithoutLimitsRule{},    // MEDIUM
		rules.K8SPodNoResourceRequestsRule{},     // MEDIUM
	}
}
