package cost

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	rdssvc "github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/devopsproxy/dp/internal/models"
)

// collectRDSInstances pages through all RDS database instances in region,
// converts them to internal models, and enriches each instance with its
// average CPUUtilization over the lookback window from CloudWatch.
//
// CloudWatch failures are non-fatal: affected instances retain
// AvgCPUPercent == 0, which the rule engine treats as "no data available".
func collectRDSInstances(
	ctx context.Context,
	client costRDSClient,
	cwClient costCWClient,
	region string,
	daysBack int,
) ([]models.AWSRDSInstance, error) {
	paginator := rdssvc.NewDescribeDBInstancesPaginator(client, &rdssvc.DescribeDBInstancesInput{})

	var instances []models.AWSRDSInstance
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeDBInstances page: %w", err)
		}
		for _, db := range page.DBInstances {
			instances = append(instances, toRDSInstance(db, region))
		}
	}

	// Enrich available instances with CloudWatch CPU averages.
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -effectiveDaysBack(daysBack))
	for i := range instances {
		if instances[i].Status != "available" {
			continue
		}
		instances[i].AvgCPUPercent = fetchRDSAvgCPU(ctx, cwClient, instances[i].DBInstanceID, start, end)
	}

	return instances, nil
}

// toRDSInstance converts an SDK DBInstance to the internal model.
func toRDSInstance(db rdstypes.DBInstance, region string) models.AWSRDSInstance {
	return models.AWSRDSInstance{
		DBInstanceID:     aws.ToString(db.DBInstanceIdentifier),
		Region:           region,
		DBInstanceClass:  aws.ToString(db.DBInstanceClass),
		Engine:           aws.ToString(db.Engine),
		MultiAZ:          aws.ToBool(db.MultiAZ),
		Status:           aws.ToString(db.DBInstanceStatus),
		StorageEncrypted: aws.ToBool(db.StorageEncrypted),
		AvgCPUPercent:    0, // enriched by fetchRDSAvgCPU after collection
		Tags:             tagsFromRDS(db.TagList),
	}
}

// fetchRDSAvgCPU calls CloudWatch GetMetricStatistics to retrieve the average
// CPUUtilization for dbInstanceID over [start, end) at 1-day granularity.
//
// Returns 0 when the call fails or no data points exist. Callers must treat
// 0 as "data unavailable", not "truly idle at 0% CPU".
func fetchRDSAvgCPU(
	ctx context.Context,
	cw costCWClient,
	dbInstanceID string,
	start, end time.Time,
) float64 {
	out, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/RDS"),
		MetricName: aws.String("CPUUtilization"),
		Dimensions: []cwtypes.Dimension{
			{
				Name:  aws.String("DBInstanceIdentifier"),
				Value: aws.String(dbInstanceID),
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

// tagsFromRDS converts RDS SDK tags to a plain string map.
func tagsFromRDS(tags []rdstypes.Tag) map[string]string {
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
