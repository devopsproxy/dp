package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSRootAccessKeyExistsRule flags AWS accounts where the root account has active
// access keys. Root access keys represent the highest possible security risk:
// if compromised, the attacker has unrestricted access to the entire account.
type AWSRootAccessKeyExistsRule struct{}

func (r AWSRootAccessKeyExistsRule) ID() string   { return "ROOT_ACCESS_KEY" }
func (r AWSRootAccessKeyExistsRule) Name() string { return "Root Account Has Active Access Keys" }

// Evaluate returns one CRITICAL finding when the root account has access keys.
func (r AWSRootAccessKeyExistsRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	if !ctx.RegionData.Security.Root.HasAccessKeys {
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
			Explanation:    "The AWS root account has active access keys, which is a critical security risk.",
			Recommendation: "Delete all root account access keys immediately and use IAM users or roles with least-privilege policies instead.",
			DetectedAt:     time.Now().UTC(),
		},
	}
}
