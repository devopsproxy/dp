package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

const (
	ebsUnattachedRuleID = "EBS_UNATTACHED"
	// ebsPricePerGBMonth is a conservative placeholder for gp2/gp3 pricing.
	// $0.08/GB-month covers gp2 in most regions; adjust when a pricing service
	// is available.
	ebsPricePerGBMonth = 0.08
)

// AWSEBSUnattachedRule flags EBS volumes that are not attached to any instance.
// An unattached volume in the "available" state incurs storage charges with
// no workload benefit.
type AWSEBSUnattachedRule struct{}

func (r AWSEBSUnattachedRule) ID() string   { return ebsUnattachedRuleID }
func (r AWSEBSUnattachedRule) Name() string { return "Unattached EBS Volume" }

// Evaluate iterates all EBS volumes in ctx.RegionData and returns one Finding
// per volume where Attached == false and State == "available".
func (r AWSEBSUnattachedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, vol := range ctx.RegionData.EBSVolumes {
		if vol.Attached || vol.State != "available" {
			continue
		}

		savings := float64(vol.SizeGB) * ebsPricePerGBMonth

		findings = append(findings, models.Finding{
			ID:                      fmt.Sprintf("%s-%s", ebsUnattachedRuleID, vol.VolumeID),
			RuleID:                  ebsUnattachedRuleID,
			ResourceID:              vol.VolumeID,
			ResourceType:            models.ResourceAWSEBS,
			Region:                  vol.Region,
			AccountID:               ctx.AccountID,
			Profile:                 ctx.Profile,
			Severity:                models.SeverityMedium,
			EstimatedMonthlySavings: savings,
			Explanation:             "EBS volume is unattached.",
			Recommendation:          "Delete or attach the volume.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"volume_type": vol.VolumeType,
				"size_gb":     vol.SizeGB,
			},
		})
	}
	return findings
}
