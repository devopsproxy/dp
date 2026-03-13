// Package kubernetes_eks provides EKS-specific Kubernetes governance rules.
// These rules are evaluated only when the cluster provider is detected as "eks"
// and require EKS control-plane data collected via the AWS EKS API.
package kubernetes_eks

import "github.com/devopsproxy/dp/internal/rules"

// New returns the Phase 5A + 5B EKS-specific governance rules ordered by severity:
// CRITICAL:
//   - EKS_ENCRYPTION_DISABLED          — secrets not encrypted at rest
//   - EKS_NODE_ROLE_OVERPERMISSIVE     — node group IAM role has AdministratorAccess or Action:"*"
//
// HIGH:
//   - EKS_PUBLIC_ENDPOINT_ENABLED      — API server endpoint publicly accessible
//   - EKS_CONTROL_PLANE_LOGGING_DISABLED — api/audit/authenticator logs not all enabled
//   - EKS_OIDC_PROVIDER_NOT_ASSOCIATED — no IAM OIDC provider associated; IRSA unavailable
//   - EKS_SERVICEACCOUNT_NO_IRSA       — ServiceAccount missing eks.amazonaws.com/role-arn
func New() []rules.Rule {
	return []rules.Rule{
		rules.EKSEncryptionDisabledRule{},          // CRITICAL (5A)
		rules.EKSNodeRoleOverpermissiveRule{},      // CRITICAL (5B)
		rules.EKSPublicEndpointRule{},              // HIGH (5A)
		rules.EKSControlPlaneLoggingDisabledRule{}, // HIGH (5A)
		rules.EKSOIDCProviderNotAssociatedRule{},   // HIGH (5B)
		rules.EKSServiceAccountNoIRSARule{},        // HIGH (5B)
	}
}
