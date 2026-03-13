package awssecurity

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudtrailsvc "github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/devopsproxy/dp/internal/models"
)

// collectCloudTrailStatus calls DescribeTrails to determine whether at least
// one multi-region trail exists for the account. IncludeShadowTrails is false
// so only trails owned by this account are returned (not shadow copies).
//
// Returns HasMultiRegionTrail == false on error (conservative: treat as not configured).
func collectCloudTrailStatus(ctx context.Context, client cloudTrailAPIClient) (models.AWSCloudTrailStatus, error) {
	out, err := client.DescribeTrails(ctx, &cloudtrailsvc.DescribeTrailsInput{
		IncludeShadowTrails: aws.Bool(false),
	})
	if err != nil {
		return models.AWSCloudTrailStatus{}, err
	}

	for _, trail := range out.TrailList {
		if trail.IsMultiRegionTrail != nil && *trail.IsMultiRegionTrail {
			return models.AWSCloudTrailStatus{HasMultiRegionTrail: true}, nil
		}
	}
	return models.AWSCloudTrailStatus{HasMultiRegionTrail: false}, nil
}
