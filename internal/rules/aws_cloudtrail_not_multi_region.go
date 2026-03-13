package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSCloudTrailNotMultiRegionRule flags accounts that have no multi-region
// CloudTrail trail. A multi-region trail is required to capture API activity
// across all regions; single-region trails leave blind spots that attackers
// can exploit by operating in unmonitored regions.
type AWSCloudTrailNotMultiRegionRule struct{}

func (r AWSCloudTrailNotMultiRegionRule) ID() string { return "CLOUDTRAIL_NOT_MULTI_REGION" }
func (r AWSCloudTrailNotMultiRegionRule) Name() string {
	return "No Multi-Region CloudTrail Trail"
}

// Evaluate returns one HIGH finding when no multi-region trail exists.
func (r AWSCloudTrailNotMultiRegionRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	if ctx.RegionData.Security.CloudTrail.HasMultiRegionTrail {
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
			Severity:       models.SeverityHigh,
			Explanation:    "No multi-region CloudTrail trail is configured. API activity in some regions may go unlogged.",
			Recommendation: "Create a multi-region CloudTrail trail that captures events from all AWS regions and stores logs in a secure S3 bucket.",
			DetectedAt:     time.Now().UTC(),
		},
	}
}
