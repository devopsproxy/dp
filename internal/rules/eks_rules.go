package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// requiredLoggingTypes are the EKS control-plane log categories that must all
// be enabled for the cluster to satisfy Phase 5A logging governance.
// Missing any one of them fires EKS_CONTROL_PLANE_LOGGING_DISABLED.
var requiredLoggingTypes = []string{"api", "audit", "authenticator"}

// ── EKS_CONTROL_PLANE_LOGGING_DISABLED ───────────────────────────────────────

// EKSControlPlaneLoggingDisabledRule fires when the EKS cluster does not have
// all required control-plane log types enabled (api, audit, authenticator).
// A partial or missing logging configuration leaves gaps in security audit trails:
// authentication events, API calls, and control-plane access are unrecorded.
type EKSControlPlaneLoggingDisabledRule struct{}

func (r EKSControlPlaneLoggingDisabledRule) ID() string {
	return "EKS_CONTROL_PLANE_LOGGING_DISABLED"
}
func (r EKSControlPlaneLoggingDisabledRule) Name() string {
	return "EKS Control Plane Logging Not Fully Enabled"
}

// Evaluate returns a finding when any of api, audit, or authenticator log types
// are absent from EKSData.LoggingTypes. The finding targets the EKS cluster resource.
func (r EKSControlPlaneLoggingDisabledRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData

	enabled := make(map[string]bool, len(eks.LoggingTypes))
	for _, t := range eks.LoggingTypes {
		enabled[t] = true
	}
	for _, req := range requiredLoggingTypes {
		if !enabled[req] {
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
						"EKS cluster %q does not have all required control-plane log types enabled. "+
							"EKS control plane logging is not fully enabled. "+
							"Required log types api, audit, and authenticator must all be active.",
						eks.ClusterName,
					),
					Recommendation: "Enable api, audit, and authenticator log types in the EKS cluster's " +
						"logging configuration to capture all authentication and authorisation events " +
						"for security review and compliance.",
					DetectedAt: time.Now().UTC(),
					Metadata: map[string]any{
						"cluster_name":  eks.ClusterName,
						"region":        eks.Region,
						"logging_types": eks.LoggingTypes,
					},
				},
			}
		}
	}
	return nil
}

// ── EKS_ENCRYPTION_DISABLED ──────────────────────────────────────────────────

// EKSEncryptionDisabledRule fires when the EKS cluster has no encryption
// configuration, leaving Kubernetes Secrets stored in etcd unencrypted at rest.
// Without envelope encryption via AWS KMS, a datastore compromise exposes all secrets.
type EKSEncryptionDisabledRule struct{}

func (r EKSEncryptionDisabledRule) ID() string   { return "EKS_ENCRYPTION_DISABLED" }
func (r EKSEncryptionDisabledRule) Name() string { return "EKS Secrets Encryption at Rest Not Enabled" }

// Evaluate returns a CRITICAL finding when EKSData.EncryptionEnabled is false.
func (r EKSEncryptionDisabledRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.ClusterData == nil || ctx.ClusterData.EKSData == nil {
		return nil
	}
	eks := ctx.ClusterData.EKSData
	if eks.EncryptionEnabled {
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
				"EKS cluster %q has no encryption configuration. "+
					"EKS secrets encryption at rest is not enabled. "+
					"Kubernetes Secrets stored in etcd are not protected by envelope encryption.",
				eks.ClusterName,
			),
			Recommendation: "Configure envelope encryption for Kubernetes Secrets using an AWS KMS key " +
				"in the cluster's encryption configuration. This protects Secret data at rest " +
				"against etcd datastore compromise.",
			DetectedAt: time.Now().UTC(),
			Metadata: map[string]any{
				"cluster_name": eks.ClusterName,
				"region":       eks.Region,
			},
		},
	}
}
