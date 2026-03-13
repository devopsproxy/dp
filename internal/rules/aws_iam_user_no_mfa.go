package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSIAMUserWithoutMFARule flags IAM users that have console access (a login
// profile) but no MFA device registered. API-only users without a login
// profile are skipped because they cannot sign in to the console.
type AWSIAMUserWithoutMFARule struct{}

func (r AWSIAMUserWithoutMFARule) ID() string   { return "IAM_USER_NO_MFA" }
func (r AWSIAMUserWithoutMFARule) Name() string { return "IAM Console User Without MFA" }

// Evaluate returns one MEDIUM finding per IAM user that has a console login
// profile but no MFA device. Users without a login profile are skipped.
func (r AWSIAMUserWithoutMFARule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	var findings []models.Finding
	for _, u := range ctx.RegionData.Security.IAMUsers {
		if !u.HasLoginProfile {
			continue // API-only user; console MFA is irrelevant
		}
		if u.MFAEnabled {
			continue
		}
		findings = append(findings, models.Finding{
			ID:             fmt.Sprintf("%s-%s", r.ID(), u.UserName),
			RuleID:         r.ID(),
			ResourceID:     u.UserName,
			ResourceType:   models.ResourceAWSIAMUser,
			Region:         "global",
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityMedium,
			Explanation:    fmt.Sprintf("IAM user %q has console access but no MFA device registered.", u.UserName),
			Recommendation: "Enable MFA for all IAM users that have console access.",
			DetectedAt:     time.Now().UTC(),
		})
	}
	return findings
}
