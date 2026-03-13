package awssecurity

import (
	"context"

	configsvc "github.com/aws/aws-sdk-go-v2/service/configservice"

	"github.com/devopsproxy/dp/internal/models"
)

// collectConfigStatus checks whether AWS Config has an active configuration
// recorder in the given region. DescribeConfigurationRecorderStatus returns
// the recording status for all recorders; Enabled is true when at least one
// recorder is actively recording (Recording == true).
//
// Returns Enabled == false on error (conservative: treat as not enabled).
func collectConfigStatus(ctx context.Context, client awsConfigAPIClient, region string) (models.AWSConfigStatus, error) {
	out, err := client.DescribeConfigurationRecorderStatus(ctx, &configsvc.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return models.AWSConfigStatus{Region: region, Enabled: false}, err
	}

	for _, status := range out.ConfigurationRecordersStatus {
		if status.Recording {
			return models.AWSConfigStatus{Region: region, Enabled: true}, nil
		}
	}
	return models.AWSConfigStatus{Region: region, Enabled: false}, nil
}
