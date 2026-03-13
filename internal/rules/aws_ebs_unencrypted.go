package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSEBSUnencryptedRule flags EBS volumes that do not have encryption enabled.
// Unencrypted volumes expose data at rest to anyone with physical or snapshot
// access, violating data-protection requirements.
type AWSEBSUnencryptedRule struct{}

func (r AWSEBSUnencryptedRule) ID() string   { return "EBS_UNENCRYPTED" }
func (r AWSEBSUnencryptedRule) Name() string { return "EBS Volume Without Encryption" }

// Evaluate returns one HIGH finding per EBS volume where Encrypted == false.
func (r AWSEBSUnencryptedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	var findings []models.Finding
	for _, vol := range ctx.RegionData.EBSVolumes {
		if vol.Encrypted {
			continue
		}
		findings = append(findings, models.Finding{
			ID:             fmt.Sprintf("%s-%s", r.ID(), vol.VolumeID),
			RuleID:         r.ID(),
			ResourceID:     vol.VolumeID,
			ResourceType:   models.ResourceAWSEBS,
			Region:         ctx.RegionData.Region,
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityHigh,
			Explanation:    fmt.Sprintf("EBS volume %s is not encrypted at rest.", vol.VolumeID),
			Recommendation: "Enable EBS encryption. For new volumes, enable encryption by default in the EC2 console. Existing unencrypted volumes must be re-created from an encrypted snapshot.",
			DetectedAt:     time.Now().UTC(),
			Metadata: map[string]any{
				"volume_type": vol.VolumeType,
				"size_gb":     vol.SizeGB,
				"state":       vol.State,
			},
		})
	}
	return findings
}
