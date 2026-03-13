package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// psaEnforceLabel is the Pod Security Admission label that controls which Pod
// Security Standards profile is enforced in a namespace.
const psaEnforceLabel = "pod-security.kubernetes.io/enforce"

// ── K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED ───────────────────────────────────

// K8SPodSecurityAdmissionNotEnforcedRule fires once when no namespace in the
// cluster carries the pod-security.kubernetes.io/enforce label. This means Pod
// Security Admission (PSA) is not enforced anywhere in the cluster, so the
// Kubernetes API server will not reject non-compliant pods at admission time.
type K8SPodSecurityAdmissionNotEnforcedRule struct{}

func (r K8SPodSecurityAdmissionNotEnforcedRule) ID() string {
	return "K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED"
}
func (r K8SPodSecurityAdmissionNotEnforcedRule) Name() string {
	return "Pod Security Admission Not Enforced Cluster-Wide"
}

func (r K8SPodSecurityAdmissionNotEnforcedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	for _, ns := range ctx.ClusterData.Namespaces {
		if _, ok := ns.Labels[psaEnforceLabel]; ok {
			return nil // at least one namespace enforces PSA
		}
	}
	return []models.Finding{
		{
			ID:           fmt.Sprintf("%s:%s", r.ID(), ctx.ClusterData.ContextName),
			RuleID:       r.ID(),
			ResourceID:   ctx.ClusterData.ContextName,
			ResourceType: models.ResourceK8sCluster,
			Region:       ctx.ClusterData.ContextName,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityHigh,
			Explanation: "Cluster does not enforce Pod Security Admission via namespace labels. " +
				"No namespace carries the pod-security.kubernetes.io/enforce label, so the " +
				"API server will not reject non-compliant pods at admission time.",
			Recommendation: "Add pod-security.kubernetes.io/enforce: restricted (or baseline) " +
				"labels to namespaces to activate Pod Security Admission enforcement and " +
				"prevent workloads that violate the chosen policy from being scheduled.",
			DetectedAt: time.Now().UTC(),
		},
	}
}

// ── K8S_NAMESPACE_PSS_NOT_SET ─────────────────────────────────────────────────

// K8SNamespacePSSNotSetRule fires for each namespace that does not carry the
// pod-security.kubernetes.io/enforce label. Without this label the namespace
// has no Pod Security Standards enforcement, and any pod — including privileged
// ones — can be scheduled into it.
type K8SNamespacePSSNotSetRule struct{}

func (r K8SNamespacePSSNotSetRule) ID() string   { return "K8S_NAMESPACE_PSS_NOT_SET" }
func (r K8SNamespacePSSNotSetRule) Name() string { return "Namespace Missing PSS Enforcement Label" }

func (r K8SNamespacePSSNotSetRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, ns := range ctx.ClusterData.Namespaces {
		if _, ok := ns.Labels[psaEnforceLabel]; ok {
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
				"Namespace %q does not declare Pod Security enforcement level "+
					"(missing label %q).",
				ns.Name, psaEnforceLabel,
			),
			Recommendation: fmt.Sprintf(
				"Add label %q: restricted to namespace %q to enforce the restricted "+
					"Pod Security Standards profile. Use baseline as a stepping stone if "+
					"restricted is not yet achievable.",
				psaEnforceLabel, ns.Name,
			),
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"namespace": ns.Name,
			},
		})
	}
	return findings
}

// ── K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT ────────────────────────────────────────

// K8SServiceAccountTokenAutomountRule fires for each ServiceAccount whose
// automountServiceAccountToken field is not explicitly set to false. By default
// Kubernetes mounts the token into every pod that uses the ServiceAccount,
// giving any compromised container access to the Kubernetes API.
type K8SServiceAccountTokenAutomountRule struct{}

func (r K8SServiceAccountTokenAutomountRule) ID() string {
	return "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT"
}
func (r K8SServiceAccountTokenAutomountRule) Name() string {
	return "ServiceAccount Auto-Mounts API Token"
}

func (r K8SServiceAccountTokenAutomountRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, sa := range ctx.ClusterData.ServiceAccounts {
		// automountServiceAccountToken == nil → defaults to true (auto-mount)
		// automountServiceAccountToken == true → explicit auto-mount
		if sa.AutomountServiceAccountToken != nil && !*sa.AutomountServiceAccountToken {
			continue // explicitly disabled — safe
		}
		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("%s:%s:%s/%s", r.ID(), ctx.ClusterData.ContextName, sa.Namespace, sa.Name),
			RuleID:       r.ID(),
			ResourceID:   sa.Name,
			ResourceType: models.ResourceK8sServiceAccount,
			Region:       ctx.ClusterData.ContextName,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityMedium,
			Explanation: fmt.Sprintf(
				"ServiceAccount %q in namespace %q auto-mounts the API token into pods. "+
					"Any compromised container running under this ServiceAccount gains "+
					"access to the Kubernetes API with the ServiceAccount's permissions.",
				sa.Name, sa.Namespace,
			),
			Recommendation: fmt.Sprintf(
				"Set automountServiceAccountToken: false on ServiceAccount %q in namespace %q. "+
					"Opt-in to token mounting per-pod only when the workload requires API access.",
				sa.Name, sa.Namespace,
			),
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"namespace": sa.Namespace,
			},
		})
	}
	return findings
}

// ── K8S_DEFAULT_SERVICEACCOUNT_USED ──────────────────────────────────────────

// K8SDefaultServiceAccountUsedRule fires for each pod whose
// spec.serviceAccountName is "default". Using the default ServiceAccount
// violates the principle of least privilege: workloads inherit any permissions
// that accumulate on the cluster-scoped default account.
type K8SDefaultServiceAccountUsedRule struct{}

func (r K8SDefaultServiceAccountUsedRule) ID() string { return "K8S_DEFAULT_SERVICEACCOUNT_USED" }
func (r K8SDefaultServiceAccountUsedRule) Name() string {
	return "Pod Uses Default ServiceAccount"
}

func (r K8SDefaultServiceAccountUsedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}
	var findings []models.Finding
	for _, pod := range ctx.ClusterData.Pods {
		if pod.ServiceAccountName != "default" {
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
			Severity:     models.SeverityMedium,
			Explanation: fmt.Sprintf(
				"Pod %q (namespace %q) uses the default ServiceAccount; "+
					"this violates least privilege because any RBAC permissions granted "+
					"to the default account are shared with all pods that use it.",
				pod.Name, pod.Namespace,
			),
			Recommendation: fmt.Sprintf(
				"Create a dedicated ServiceAccount for pod %q with only the permissions "+
					"that workload requires, and set spec.serviceAccountName accordingly.",
				pod.Name,
			),
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"namespace":            pod.Namespace,
				"service_account_name": pod.ServiceAccountName,
			},
		})
	}
	return findings
}
