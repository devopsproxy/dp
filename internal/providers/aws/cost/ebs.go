package cost

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/devopsproxy/dp/internal/models"
)

// collectEBSVolumes pages through all non-deleted EBS volumes in region and
// converts them to internal models. The Attached flag is derived from the
// volume state ("in-use" means attached).
func collectEBSVolumes(ctx context.Context, client costEC2Client, region string) ([]models.AWSEBSVolume, error) {
	input := &ec2svc.DescribeVolumesInput{
		Filters: []ec2types.Filter{
			{
				// Exclude deleted volumes; AWS does not surface them anyway but
				// this keeps intent explicit.
				Name:   aws.String("status"),
				Values: []string{"available", "in-use", "creating", "error"},
			},
		},
	}

	paginator := ec2svc.NewDescribeVolumesPaginator(client, input)

	var volumes []models.AWSEBSVolume
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeVolumes page: %w", err)
		}
		for _, v := range page.Volumes {
			volumes = append(volumes, toEBSVolume(v, region))
		}
	}
	return volumes, nil
}

// toEBSVolume converts an SDK EBS volume to the internal model.
func toEBSVolume(v ec2types.Volume, region string) models.AWSEBSVolume {
	state := string(v.State)
	attached := v.State == ec2types.VolumeStateInUse

	// Derive the attached instance ID from the first attachment, if any.
	var instanceID string
	if len(v.Attachments) > 0 {
		instanceID = aws.ToString(v.Attachments[0].InstanceId)
	}

	return models.AWSEBSVolume{
		VolumeID:   aws.ToString(v.VolumeId),
		Region:     region,
		VolumeType: string(v.VolumeType),
		SizeGB:     aws.ToInt32(v.Size),
		State:      state,
		Attached:   attached,
		Encrypted:  aws.ToBool(v.Encrypted),
		InstanceID: instanceID,
		Tags:       tagsFromEC2(v.Tags),
	}
}
