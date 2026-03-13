package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// ── EKS_PUBLIC_ENDPOINT_ENABLED ──────────────────────────────────────────────

// EKSPublicEndpointRule fires when the EKS cluster API server endpoint is
// publicly accessible from the internet. Restricting endpoint access to
// private VPC traffic significantly reduces the control-plane attack surface.
type EKSPublicEndpointRule struct{}

func (r EKSPublicEndpointRule) ID() string   { return "EKS_PUBLIC_ENDPOINT_ENABLED" }
func (r EKSPublicEndpointRule) Name() string { return "EKS Control Plane Endpoint Publicly Accessible" }

func (r EKSPublicEndpointRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData
	if !eks.EndpointPublicAccess {
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
				"EKS cluster %q has the API server endpoint set to public access. "+
					"The Kubernetes control plane is reachable from any IP on the internet.",
				eks.ClusterName,
			),
			Recommendation: "Disable public endpoint access in the cluster's API server endpoint " +
				"configuration and restrict access to private VPC CIDR ranges only.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"cluster_name": eks.ClusterName,
				"region":       eks.Region,
			},
		},
	}
}

// ── EKS_CLUSTER_LOGGING_DISABLED ─────────────────────────────────────────────

// EKSClusterLoggingDisabledRule fires when no EKS control-plane log types are
// enabled. Without logging, audit and authentication events cannot be reviewed
// for anomalies or security incidents.
type EKSClusterLoggingDisabledRule struct{}

func (r EKSClusterLoggingDisabledRule) ID() string { return "EKS_CLUSTER_LOGGING_DISABLED" }
func (r EKSClusterLoggingDisabledRule) Name() string {
	return "EKS Control Plane Logging Not Enabled"
}

func (r EKSClusterLoggingDisabledRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData
	if eks.LoggingEnabled {
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
			Severity:     models.SeverityMedium,
			Explanation: fmt.Sprintf(
				"EKS cluster %q has no control-plane log types enabled. "+
					"API server, audit, authenticator, controller manager, and scheduler logs "+
					"are all disabled.",
				eks.ClusterName,
			),
			Recommendation: "Enable at least the audit log type in the cluster's logging configuration " +
				"to capture authentication and authorisation events for security review.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"cluster_name": eks.ClusterName,
				"region":       eks.Region,
			},
		},
	}
}

// ── EKS_OIDC_PROVIDER_MISSING ────────────────────────────────────────────────

// EKSOIDCProviderMissingRule fires when the EKS cluster has no OIDC provider
// configured. Without an OIDC provider, IAM Roles for Service Accounts (IRSA)
// cannot be used, forcing workloads to use EC2 instance role permissions
// which violate the principle of least privilege.
type EKSOIDCProviderMissingRule struct{}

func (r EKSOIDCProviderMissingRule) ID() string   { return "EKS_OIDC_PROVIDER_MISSING" }
func (r EKSOIDCProviderMissingRule) Name() string { return "EKS OIDC Provider Not Configured" }

func (r EKSOIDCProviderMissingRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData
	if eks.OIDCIssuer != "" {
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
				"EKS cluster %q has no OIDC provider configured. "+
					"Without OIDC, workloads cannot use IAM Roles for Service Accounts (IRSA) "+
					"and must rely on the broader EC2 instance role.",
				eks.ClusterName,
			),
			Recommendation: "Associate an IAM OIDC provider with the cluster and migrate workloads " +
				"to use IRSA to enforce per-workload IAM least privilege.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"cluster_name": eks.ClusterName,
				"region":       eks.Region,
			},
		},
	}
}
