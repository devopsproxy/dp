package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// ── EKS_OIDC_PROVIDER_NOT_ASSOCIATED ─────────────────────────────────────────

// EKSOIDCProviderNotAssociatedRule fires when no IAM OIDC provider ARN is
// associated with the EKS cluster. Without an IAM OIDC provider, workloads
// cannot use IAM Roles for Service Accounts (IRSA) and must rely on the
// broader EC2 instance role, violating the principle of least privilege.
type EKSOIDCProviderNotAssociatedRule struct{}

func (r EKSOIDCProviderNotAssociatedRule) ID() string {
	return "EKS_OIDC_PROVIDER_NOT_ASSOCIATED"
}
func (r EKSOIDCProviderNotAssociatedRule) Name() string {
	return "EKS IAM OIDC Provider Not Associated"
}

// Evaluate returns a HIGH finding when EKSData.OIDCProviderARN is empty.
func (r EKSOIDCProviderNotAssociatedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData
	if eks.OIDCProviderARN != "" {
		return nil
	}
	return []models.Finding{
		{
			ID:           fmt.Sprintf("%s:%s", r.ID(), eks.ClusterName),
			RuleID:       r.ID(),
			ResourceID:   eks.ClusterName,
			ResourceType: models.ResourceK8sCluster,
			Region:       eks.Region,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityHigh,
			Explanation: fmt.Sprintf(
				"EKS cluster %q does not have an associated OIDC provider. "+
					"EKS cluster does not have an associated OIDC provider; IRSA cannot be used.",
				eks.ClusterName,
			),
			Recommendation: "Associate an IAM OIDC identity provider with the cluster " +
				"(eksctl utils associate-iam-oidc-provider or Terraform) to enable " +
				"per-workload IAM role assignment via IRSA.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"cluster_name": eks.ClusterName,
				"region":       eks.Region,
				"oidc_issuer":  eks.OIDCIssuer,
			},
		},
	}
}

// ── EKS_SERVICEACCOUNT_NO_IRSA ────────────────────────────────────────────────

// EKSServiceAccountNoIRSARule fires for each Kubernetes ServiceAccount that
// lacks the eks.amazonaws.com/role-arn annotation. Without IRSA, the workload
// running under that ServiceAccount inherits the broad EC2 instance role
// rather than a dedicated least-privilege IAM role.
// Scope: cluster-wide; use --exclude-system to skip kube-system findings.
type EKSServiceAccountNoIRSARule struct{}

func (r EKSServiceAccountNoIRSARule) ID() string   { return "EKS_SERVICEACCOUNT_NO_IRSA" }
func (r EKSServiceAccountNoIRSARule) Name() string { return "EKS ServiceAccount Does Not Use IRSA" }

// Evaluate returns one HIGH finding per ServiceAccount missing the IRSA annotation.
func (r EKSServiceAccountNoIRSARule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil {
		return nil
	}

	region := ""
	clusterName := ""
	if ctx.ClusterData.EKSData != nil {
		region = ctx.ClusterData.EKSData.Region
		clusterName = ctx.ClusterData.EKSData.ClusterName
	}

	var findings []models.Finding
	for _, sa := range ctx.ClusterData.ServiceAccounts {
		if sa.Annotations["eks.amazonaws.com/role-arn"] != "" {
			continue // SA has IRSA annotation — compliant
		}
		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("%s:%s/%s", r.ID(), sa.Namespace, sa.Name),
			RuleID:       r.ID(),
			ResourceID:   sa.Name,
			ResourceType: models.ResourceK8sServiceAccount,
			Region:       region,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityHigh,
			Explanation: fmt.Sprintf(
				"ServiceAccount %q in namespace %q does not have an IAM Roles for Service Accounts (IRSA) annotation. "+
					"ServiceAccount does not use IAM Roles for Service Accounts (IRSA).",
				sa.Name, sa.Namespace,
			),
			Recommendation: "Annotate the ServiceAccount with " +
				"eks.amazonaws.com/role-arn pointing to a dedicated least-privilege IAM role, " +
				"and configure the pod to use that ServiceAccount for fine-grained AWS API access.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"namespace":    sa.Namespace,
				"cluster_name": clusterName,
			},
		})
	}
	return findings
}

// ── EKS_NODE_ROLE_OVERPERMISSIVE ──────────────────────────────────────────────

// EKSNodeRoleOverpermissiveRule fires when the IAM role attached to a node group
// carries overpermissive policies (AdministratorAccess attached, or an inline
// policy with Action:"*"). A compromised node can then assume the instance role
// and perform unrestricted AWS API calls across the account.
type EKSNodeRoleOverpermissiveRule struct{}

func (r EKSNodeRoleOverpermissiveRule) ID() string {
	return "EKS_NODE_ROLE_OVERPERMISSIVE"
}
func (r EKSNodeRoleOverpermissiveRule) Name() string {
	return "EKS Node Group IAM Role Is Overpermissive"
}

// Evaluate returns a CRITICAL finding when EKSData.NodeRolePolicies is non-empty.
func (r EKSNodeRoleOverpermissiveRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData
	if len(eks.NodeRolePolicies) == 0 {
		return nil
	}
	return []models.Finding{
		{
			ID:           fmt.Sprintf("%s:%s", r.ID(), eks.ClusterName),
			RuleID:       r.ID(),
			ResourceID:   eks.ClusterName,
			ResourceType: models.ResourceK8sCluster,
			Region:       eks.Region,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			Severity:     models.SeverityCritical,
			Explanation: fmt.Sprintf(
				"EKS cluster %q has node group IAM role(s) with overpermissive policies (%s). "+
					"A compromised node can use the instance role to make unrestricted AWS API calls.",
				eks.ClusterName, joinPolicies(eks.NodeRolePolicies),
			),
			Recommendation: "Replace AdministratorAccess and wildcard-action policies with scoped " +
				"policies granting only the permissions needed for node bootstrap " +
				"(EC2, ECR, EKS node read-only). Follow the principle of least privilege.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"cluster_name":            eks.ClusterName,
				"region":                  eks.Region,
				"overpermissive_policies": eks.NodeRolePolicies,
			},
		},
	}
}

// joinPolicies formats a policy name slice for human-readable output.
func joinPolicies(policies []string) string {
	if len(policies) == 0 {
		return ""
	}
	result := policies[0]
	for _, p := range policies[1:] {
		result += ", " + p
	}
	return result
}
