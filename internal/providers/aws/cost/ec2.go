package cost

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/devopsproxy/dp/internal/models"
)

// collectEC2Instances pages through all running and stopped EC2 instances in
// region, converts them to internal models, and enriches each running instance
// with its average CPUUtilization over the lookback window from CloudWatch.
//
// CloudWatch failures are non-fatal: affected instances retain
// AvgCPUPercent == 0, which the rule engine treats as "no data available"
// rather than "truly idle", preventing false-positive findings.
func collectEC2Instances(
	ctx context.Context,
	ec2Client costEC2Client,
	cwClient costCWClient,
	region string,
	daysBack int,
) ([]models.AWSEC2Instance, error) {
	input := &ec2svc.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("instance-state-name"),
				Values: []string{"running", "stopped"},
			},
		},
	}

	paginator := ec2svc.NewDescribeInstancesPaginator(ec2Client, input)

	var instances []models.AWSEC2Instance
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeInstances page: %w", err)
		}
		for _, reservation := range page.Reservations {
			for _, inst := range reservation.Instances {
				instances = append(instances, toEC2Instance(inst, region))
			}
		}
	}

	// Enrich running instances with CloudWatch CPU averages.
	// Stopped instances have no active CPU metric; skip them to avoid noise.
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -effectiveDaysBack(daysBack))
	for i := range instances {
		if instances[i].State != "running" {
			continue
		}
		instances[i].AvgCPUPercent = fetchAvgCPU(ctx, cwClient, instances[i].InstanceID, start, end)
	}

	return instances, nil
}

// toEC2Instance converts an SDK EC2 instance to the internal model.
func toEC2Instance(inst ec2types.Instance, region string) models.AWSEC2Instance {
	var state string
	if inst.State != nil {
		state = string(inst.State.Name)
	}

	var launchTime time.Time
	if inst.LaunchTime != nil {
		launchTime = *inst.LaunchTime
	}

	return models.AWSEC2Instance{
		InstanceID:    aws.ToString(inst.InstanceId),
		Region:        region,
		InstanceType:  string(inst.InstanceType),
		State:         state,
		LaunchTime:    launchTime,
		AvgCPUPercent: 0, // enriched by fetchAvgCPU after collection
		Tags:          tagsFromEC2(inst.Tags),
	}
}

// fetchAvgCPU calls CloudWatch GetMetricStatistics to retrieve the average
// CPUUtilization for instanceID over [start, end) at 1-day granularity.
//
// Returns 0 when the call fails or no data points exist. Callers must treat
// 0 as "data unavailable", not "truly idle at 0% CPU".
func fetchAvgCPU(
	ctx context.Context,
	cw costCWClient,
	instanceID string,
	start, end time.Time,
) float64 {
	out, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/EC2"),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cwtypes.Dimension{
			{
				Name:  aws.String("InstanceId"),
				Value: aws.String(instanceID),
			},
		},
		StartTime:  aws.Time(start),
		EndTime:    aws.Time(end),
		Period:     aws.Int32(86400), // 1-day granularity → ≤30 points for a 30d window
		Statistics: []cwtypes.Statistic{cwtypes.StatisticAverage},
	})
	if err != nil || len(out.Datapoints) == 0 {
		return 0
	}

	var total float64
	var count int
	for _, dp := range out.Datapoints {
		if dp.Average != nil {
			total += *dp.Average
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return total / float64(count)
}

// tagsFromEC2 converts EC2 SDK tags to a plain string map.
func tagsFromEC2(tags []ec2types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			m[*t.Key] = *t.Value
		}
	}
	return m
}
