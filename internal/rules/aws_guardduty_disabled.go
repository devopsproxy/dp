package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSGuardDutyDisabledRule flags regions where AWS GuardDuty is not enabled.
// GuardDuty provides continuous threat detection; disabled regions have no
// automated detection of reconnaissance, data exfiltration, or compromised
// credentials.
type AWSGuardDutyDisabledRule struct{}

func (r AWSGuardDutyDisabledRule) ID() string   { return "GUARDDUTY_DISABLED" }
func (r AWSGuardDutyDisabledRule) Name() string { return "GuardDuty Not Enabled In Region" }

// Evaluate returns one HIGH finding per region where GuardDuty is not enabled.
func (r AWSGuardDutyDisabledRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, gd := range ctx.RegionData.Security.GuardDuty {
		if gd.Enabled {
			continue
		}
		findings = append(findings, models.Finding{
			ID:             fmt.Sprintf("%s-%s-%s", r.ID(), ctx.AccountID, gd.Region),
			RuleID:         r.ID(),
			ResourceID:     ctx.AccountID,
			ResourceType:   models.ResourceAWSRootAccount,
			Region:         gd.Region,
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityHigh,
			Explanation:    fmt.Sprintf("AWS GuardDuty is not enabled in region %s.", gd.Region),
			Recommendation: "Enable GuardDuty in all active regions to ensure continuous threat detection.",
			DetectedAt:     time.Now().UTC(),
		})
	}
	return findings
}
