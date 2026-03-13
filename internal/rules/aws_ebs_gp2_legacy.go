package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

const (
	ebsGP2LegacyRuleID = "EBS_GP2_LEGACY"
	// ebsGP2SavingsPerGBMonth is a placeholder representing the ~20% cost
	// reduction when migrating from gp2 ($0.10/GB-mo) to gp3 ($0.08/GB-mo).
	ebsGP2SavingsPerGBMonth = 0.02
)

// AWSEBSGP2LegacyRule flags EBS volumes still using the legacy gp2 volume type.
// gp2 volumes cost more per GB than gp3 and offer no performance advantage
// for most workloads; migrating is low-risk and requires no downtime.
type AWSEBSGP2LegacyRule struct{}

func (r AWSEBSGP2LegacyRule) ID() string   { return ebsGP2LegacyRuleID }
func (r AWSEBSGP2LegacyRule) Name() string { return "Legacy gp2 EBS Volume" }

// Evaluate returns one Finding per gp2 volume found in ctx.RegionData.
func (r AWSEBSGP2LegacyRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, vol := range ctx.RegionData.EBSVolumes {
		if vol.VolumeType != "gp2" {
			continue
		}

		savings := float64(vol.SizeGB) * ebsGP2SavingsPerGBMonth

		findings = append(findings, models.Finding{
			ID:                      fmt.Sprintf("%s-%s", ebsGP2LegacyRuleID, vol.VolumeID),
			RuleID:                  ebsGP2LegacyRuleID,
			ResourceID:              vol.VolumeID,
			ResourceType:            models.ResourceAWSEBS,
			Region:                  vol.Region,
			AccountID:               ctx.AccountID,
			Profile:                 ctx.Profile,
			Severity:                models.SeverityLow,
			EstimatedMonthlySavings: savings,
			Explanation:             "gp2 volumes are legacy and more expensive than gp3.",
			Recommendation:          "Migrate to gp3 volume type.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"volume_type": vol.VolumeType,
				"size_gb":     vol.SizeGB,
			},
		})
	}
	return findings
}
