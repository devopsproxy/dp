package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// ── K8S_POD_PRIVILEGED_CONTAINER ─────────────────────────────────────────────

// K8SPSSPrivilegedContainerRule fires for each container running with
// securityContext.privileged == true. This is a PSS-enforcement-branded check
// under the Baseline and Restricted Pod Security Standards profiles.
type K8SPSSPrivilegedContainerRule struct{}

func (r K8SPSSPrivilegedContainerRule) ID() string   { return "K8S_POD_PRIVILEGED_CONTAINER" }
func (r K8SPSSPrivilegedContainerRule) Name() string { return "PSS: Privileged Container Detected" }

func (r K8SPSSPrivilegedContainerRule) Evaluate(ctx RuleContext) []models.Finding {
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

// ── K8S_POD_HOST_NETWORK ─────────────────────────────────────────────────────

// K8SPSSHostNetworkRule fires for each pod running with spec.hostNetwork == true.
// Sharing the host network namespace bypasses network isolation and exposes
// host network interfaces directly to the container.
type K8SPSSHostNetworkRule struct{}

func (r K8SPSSHostNetworkRule) ID() string   { return "K8S_POD_HOST_NETWORK" }
func (r K8SPSSHostNetworkRule) Name() string { return "PSS: Pod Uses Host Network Namespace" }

func (r K8SPSSHostNetworkRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, pod := range ctx.ClusterData.Pods {
		if !pod.HostNetwork {
			continue
		}
		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("%s:%s:%s/%s", r.ID(), ctx.ClusterData.ContextName, pod.Namespace, pod.Name),
			RuleID:       r.ID(),
			ResourceID:   pod.Name,
			ResourceType: models.ResourceK8sPod,
			Region:       ctx.ClusterData.ContextName,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityHigh,
			Explanation: fmt.Sprintf(
				"Pod %q (namespace %q) has hostNetwork enabled, sharing the node's network namespace.",
				pod.Name, pod.Namespace,
			),
			Recommendation: "Disable hostNetwork unless explicitly required by the workload. " +
				"Use NetworkPolicies to control pod-to-pod communication instead.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"namespace": pod.Namespace,
			},
		})
	}
	return findings
}

// ── K8S_POD_HOST_PID_OR_IPC ──────────────────────────────────────────────────

// K8SPSSHostPIDOrIPCRule fires for each pod with spec.hostPID == true or
// spec.hostIPC == true. These settings grant containers access to host-level
// process and IPC namespaces, enabling privilege escalation and data exfiltration.
type K8SPSSHostPIDOrIPCRule struct{}

func (r K8SPSSHostPIDOrIPCRule) ID() string   { return "K8S_POD_HOST_PID_OR_IPC" }
func (r K8SPSSHostPIDOrIPCRule) Name() string { return "PSS: Pod Uses Host PID or IPC Namespace" }

func (r K8SPSSHostPIDOrIPCRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, pod := range ctx.ClusterData.Pods {
		if !pod.HostPID && !pod.HostIPC {
			continue
		}
		var enabled []string
		if pod.HostPID {
			enabled = append(enabled, "hostPID")
		}
		if pod.HostIPC {
			enabled = append(enabled, "hostIPC")
		}
		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("%s:%s:%s/%s", r.ID(), ctx.ClusterData.ContextName, pod.Namespace, pod.Name),
			RuleID:       r.ID(),
			ResourceID:   pod.Name,
			ResourceType: models.ResourceK8sPod,
			Region:       ctx.ClusterData.ContextName,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityHigh,
			Explanation: fmt.Sprintf(
				"Pod %q (namespace %q) has %s enabled, allowing access to host process or IPC namespaces.",
				pod.Name, pod.Namespace, strings.Join(enabled, " and "),
			),
			Recommendation: "Disable hostPID and hostIPC unless explicitly required. " +
				"These settings allow containers to interact with host-level processes and IPC resources.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"namespace": pod.Namespace,
				"host_pid":  pod.HostPID,
				"host_ipc":  pod.HostIPC,
			},
		})
	}
	return findings
}

// ── K8S_POD_RUN_AS_ROOT ──────────────────────────────────────────────────────

// K8SPSSRunAsRootRule fires for each container where the effective security
// context does not prevent root execution: runAsNonRoot is absent or false,
// or runAsUser is explicitly 0 (root UID).
// The effective values are resolved at collection time (container overrides pod).
type K8SPSSRunAsRootRule struct{}

func (r K8SPSSRunAsRootRule) ID() string   { return "K8S_POD_RUN_AS_ROOT" }
func (r K8SPSSRunAsRootRule) Name() string { return "PSS: Container May Run as Root" }

func (r K8SPSSRunAsRootRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, pod := range ctx.ClusterData.Pods {
		for _, c := range pod.Containers {
			notEnforced := c.RunAsNonRoot == nil || !*c.RunAsNonRoot
			runAsRootUID := c.RunAsUser != nil && *c.RunAsUser == 0

			if !notEnforced && !runAsRootUID {
				continue
			}

			var reason string
			if runAsRootUID {
				reason = "runAsUser is 0 (root UID)"
			} else {
				reason = "runAsNonRoot is not set or is false"
			}
			findings = append(findings, models.Finding{
				ID:           fmt.Sprintf("%s:%s:%s/%s/%s", r.ID(), ctx.ClusterData.ContextName, pod.Namespace, pod.Name, c.Name),
				RuleID:       r.ID(),
				ResourceID:   pod.Name,
				ResourceType: models.ResourceK8sPod,
				Region:       ctx.ClusterData.ContextName,
				AccountID:    ctx.AccountID,
				Profile:      ctx.Profile,
				Severity:     models.SeverityHigh,
				Explanation: fmt.Sprintf(
					"Container %q in pod %q (namespace %q) may run as root: %s.",
					c.Name, pod.Name, pod.Namespace, reason,
				),
				Recommendation: "Set runAsNonRoot: true and a non-zero runAsUser in the container security context " +
					"to prevent containers from running with root privileges.",
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

// ── K8S_POD_CAP_SYS_ADMIN ────────────────────────────────────────────────────

// K8SPSSCapSysAdminRule fires for each container that adds the SYS_ADMIN Linux
// capability. SYS_ADMIN is the broadest Linux capability, providing near-root
// access and is explicitly prohibited under the PSS restricted profile.
type K8SPSSCapSysAdminRule struct{}

func (r K8SPSSCapSysAdminRule) ID() string   { return "K8S_POD_CAP_SYS_ADMIN" }
func (r K8SPSSCapSysAdminRule) Name() string { return "PSS: Container Adds SYS_ADMIN Capability" }

func (r K8SPSSCapSysAdminRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, pod := range ctx.ClusterData.Pods {
		for _, c := range pod.Containers {
			if !containsSysAdmin(c.AddedCapabilities) {
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
				Severity:     models.SeverityHigh,
				Explanation: fmt.Sprintf(
					"Container %q in pod %q (namespace %q) adds the SYS_ADMIN Linux capability.",
					c.Name, pod.Name, pod.Namespace,
				),
				Recommendation: "Remove SYS_ADMIN from capabilities.add. " +
					"SYS_ADMIN provides near-root access and is prohibited under the Pod Security Standards restricted profile.",
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

// containsSysAdmin reports whether "SYS_ADMIN" appears in the capability list.
func containsSysAdmin(caps []string) bool {
	for _, c := range caps {
		if c == "SYS_ADMIN" {
			return true
		}
	}
	return false
}

// ── K8S_POD_NO_SECCOMP ───────────────────────────────────────────────────────

// K8SPSSNoSeccompRule fires for each container whose effective seccomp profile
// type is not "RuntimeDefault" or "Localhost". An absent or "Unconfined" seccomp
// profile means no syscall filtering is applied, broadening the attack surface.
// The effective profile is resolved at collection time (container overrides pod).
type K8SPSSNoSeccompRule struct{}

func (r K8SPSSNoSeccompRule) ID() string   { return "K8S_POD_NO_SECCOMP" }
func (r K8SPSSNoSeccompRule) Name() string { return "PSS: Container Has No Seccomp Profile" }

func (r K8SPSSNoSeccompRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, pod := range ctx.ClusterData.Pods {
		for _, c := range pod.Containers {
			if c.SeccompProfileType == "RuntimeDefault" || c.SeccompProfileType == "Localhost" {
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
					"Container %q in pod %q (namespace %q) has no effective seccomp profile (type: %q).",
					c.Name, pod.Name, pod.Namespace, c.SeccompProfileType,
				),
				Recommendation: "Set seccompProfile.type: RuntimeDefault in the container or pod security context " +
					"to restrict system calls using the container runtime's default seccomp filter.",
				DetectedAt: time.Now().UTC(),
				Metadata: map[string]any{
					"namespace":            pod.Namespace,
					"container_name":       c.Name,
					"seccomp_profile_type": c.SeccompProfileType,
				},
			})
		}
	}
	return findings
}
