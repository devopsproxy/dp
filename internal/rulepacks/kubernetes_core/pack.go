// Package kubernetes_core provides the cloud-agnostic Kubernetes governance
// rule pack. These rules apply to any Kubernetes cluster regardless of the
// underlying cloud provider.
package kubernetes_core

import "github.com/devopsproxy/dp/internal/rules"

// New returns the complete set of cloud-agnostic Kubernetes governance rules
// ordered by severity: CRITICAL first, then HIGH, then MEDIUM.
// Includes PSS Phase 3A rules and Phase 3B admission/SA governance rules.
func New() []rules.Rule {
	return []rules.Rule{
		// CRITICAL
		rules.K8SPrivilegedContainerRule{},    // K8S_PRIVILEGED_CONTAINER
		rules.K8SPSSPrivilegedContainerRule{}, // K8S_POD_PRIVILEGED_CONTAINER (PSS)

		// HIGH
		rules.K8SClusterSingleNodeRule{},               // K8S_CLUSTER_SINGLE_NODE
		rules.K8SNodeOverallocatedRule{},               // K8S_NODE_OVERALLOCATED
		rules.K8SServicePublicLoadBalancerRule{},       // K8S_SERVICE_PUBLIC_LOADBALANCER
		rules.K8SPSSHostNetworkRule{},                  // K8S_POD_HOST_NETWORK (PSS)
		rules.K8SPSSHostPIDOrIPCRule{},                 // K8S_POD_HOST_PID_OR_IPC (PSS)
		rules.K8SPSSRunAsRootRule{},                    // K8S_POD_RUN_AS_ROOT (PSS)
		rules.K8SPSSCapSysAdminRule{},                  // K8S_POD_CAP_SYS_ADMIN (PSS)
		rules.K8SPodSecurityAdmissionNotEnforcedRule{}, // K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED

		// MEDIUM
		rules.K8SNamespaceWithoutLimitsRule{},       // K8S_NAMESPACE_WITHOUT_LIMITS
		rules.K8SPodNoResourceRequestsRule{},        // K8S_POD_NO_RESOURCE_REQUESTS
		rules.K8SPSSNoSeccompRule{},                 // K8S_POD_NO_SECCOMP (PSS)
		rules.K8SNamespacePSSNotSetRule{},           // K8S_NAMESPACE_PSS_NOT_SET
		rules.K8SServiceAccountTokenAutomountRule{}, // K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT
		rules.K8SDefaultServiceAccountUsedRule{},    // K8S_DEFAULT_SERVICEACCOUNT_USED
	}
}
