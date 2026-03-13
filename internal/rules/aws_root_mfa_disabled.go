package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSRootAccountMFADisabledRule flags AWS accounts where the root account does
// not have MFA enabled. Without MFA, a compromised root password gives an
// attacker unrestricted account access with no second factor to stop them.
//
// DataAvailable must be true (GetAccountSummary succeeded) before evaluating
// MFA status to avoid false positives from collection failures.
type AWSRootAccountMFADisabledRule struct{}

func (r AWSRootAccountMFADisabledRule) ID() string   { return "ROOT_ACCOUNT_MFA_DISABLED" }
func (r AWSRootAccountMFADisabledRule) Name() string { return "Root Account MFA Not Enabled" }

// Evaluate returns one CRITICAL finding when the root account has no MFA.
func (r AWSRootAccountMFADisabledRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	root := ctx.RegionData.Security.Root
	// Skip if account summary was not successfully collected.
	if !root.DataAvailable {
		return nil
	}
	if root.MFAEnabled {
		return nil
	}
	return []models.Finding{
		{
			ID:             fmt.Sprintf("%s-%s", r.ID(), ctx.AccountID),
			RuleID:         r.ID(),
			ResourceID:     ctx.AccountID,
			ResourceType:   models.ResourceAWSRootAccount,
			Region:         "global",
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityCritical,
			Explanation:    "The AWS root account does not have MFA enabled.",
			Recommendation: "Enable MFA on the root account using a hardware token or virtual MFA device immediately.",
			DetectedAt:     time.Now().UTC(),
		},
	}
}
