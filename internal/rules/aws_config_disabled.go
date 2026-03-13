package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSConfigDisabledRule flags regions where AWS Config is not actively
// recording. AWS Config is required for compliance monitoring, resource
// inventory, and change tracking; disabled regions have no configuration
// history or compliance evaluation.
type AWSConfigDisabledRule struct{}

func (r AWSConfigDisabledRule) ID() string   { return "AWS_CONFIG_DISABLED" }
func (r AWSConfigDisabledRule) Name() string { return "AWS Config Not Enabled In Region" }

// Evaluate returns one HIGH finding per region where AWS Config is not recording.
func (r AWSConfigDisabledRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, cfg := range ctx.RegionData.Security.Config {
		if cfg.Enabled {
			continue
		}
		findings = append(findings, models.Finding{
			ID:             fmt.Sprintf("%s-%s-%s", r.ID(), ctx.AccountID, cfg.Region),
			RuleID:         r.ID(),
			ResourceID:     ctx.AccountID,
			ResourceType:   models.ResourceAWSRootAccount,
			Region:         cfg.Region,
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityHigh,
			Explanation:    fmt.Sprintf("AWS Config is not recording in region %s.", cfg.Region),
			Recommendation: "Enable AWS Config with a configuration recorder and delivery channel in all active regions.",
			DetectedAt:     time.Now().UTC(),
		})
	}
	return findings
}
