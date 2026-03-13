package awssecurity

import (
	"context"

	guardduty "github.com/aws/aws-sdk-go-v2/service/guardduty"
	guarddutytype "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/devopsproxy/dp/internal/models"
)

// collectGuardDutyStatus checks whether GuardDuty has an enabled detector in
// the given region. It first lists detectors; if none exist, GuardDuty is not
// enabled. If a detector exists, GetDetector verifies its status is ENABLED.
//
// Returns Enabled == false on error (conservative: treat as not enabled).
func collectGuardDutyStatus(ctx context.Context, client guardDutyAPIClient, region string) (models.AWSGuardDutyStatus, error) {
	listOut, err := client.ListDetectors(ctx, &guardduty.ListDetectorsInput{})
	if err != nil {
		return models.AWSGuardDutyStatus{Region: region, Enabled: false}, err
	}

	if len(listOut.DetectorIds) == 0 {
		// No detector configured in this region.
		return models.AWSGuardDutyStatus{Region: region, Enabled: false}, nil
	}

	// Check the first (usually only) detector's status.
	detOut, err := client.GetDetector(ctx, &guardduty.GetDetectorInput{
		DetectorId: &listOut.DetectorIds[0],
	})
	if err != nil {
		return models.AWSGuardDutyStatus{Region: region, Enabled: false}, err
	}

	return models.AWSGuardDutyStatus{
		Region:  region,
		Enabled: detOut.Status == guarddutytype.DetectorStatus("ENABLED"),
	}, nil
}
