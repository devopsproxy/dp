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

// collectNATGateways pages through all available NAT Gateways in region,
// converts them to internal models, and enriches each with its total outbound
// bytes over the lookback window from CloudWatch (BytesOutToDestination metric).
//
// CloudWatch failures are non-fatal: affected gateways retain
// BytesProcessedGB == 0, which the rule engine treats as negligible traffic.
func collectNATGateways(
	ctx context.Context,
	ec2Client costEC2Client,
	cwClient costCWClient,
	region string,
	daysBack int,
) ([]models.AWSNATGateway, error) {
	input := &ec2svc.DescribeNatGatewaysInput{
		Filter: []ec2types.Filter{
			{
				Name:   aws.String("state"),
				Values: []string{"available"},
			},
		},
	}

	paginator := ec2svc.NewDescribeNatGatewaysPaginator(ec2Client, input)

	var gateways []models.AWSNATGateway
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeNatGateways page: %w", err)
		}
		for _, ng := range page.NatGateways {
			gateways = append(gateways, toNATGateway(ng, region))
		}
	}

	// Enrich each gateway with CloudWatch BytesOutToDestination total.
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -effectiveDaysBack(daysBack))
	for i := range gateways {
		gateways[i].BytesProcessedGB = fetchNATBytesOutGB(ctx, cwClient, gateways[i].NATGatewayID, start, end)
	}

	return gateways, nil
}

// toNATGateway converts an SDK NAT Gateway to the internal model.
func toNATGateway(ng ec2types.NatGateway, region string) models.AWSNATGateway {
	return models.AWSNATGateway{
		NATGatewayID:     aws.ToString(ng.NatGatewayId),
		Region:           region,
		State:            string(ng.State),
		VPCID:            aws.ToString(ng.VpcId),
		SubnetID:         aws.ToString(ng.SubnetId),
		BytesProcessedGB: 0, // enriched by fetchNATBytesOutGB after collection
		Tags:             tagsFromEC2(ng.Tags),
	}
}

// fetchNATBytesOutGB calls CloudWatch GetMetricStatistics to retrieve the
// total BytesOutToDestination for natGatewayID over [start, end) at 1-day
// granularity, then converts the byte total to gigabytes.
//
// Returns 0 when the call fails or no data points exist. A return of 0 means
// no traffic was observed (or data was unavailable) — both indicate the NAT
// Gateway may be a candidate for removal.
func fetchNATBytesOutGB(
	ctx context.Context,
	cw costCWClient,
	natGatewayID string,
	start, end time.Time,
) float64 {
	out, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/NATGateway"),
		MetricName: aws.String("BytesOutToDestination"),
		Dimensions: []cwtypes.Dimension{
			{
				Name:  aws.String("NatGatewayId"),
				Value: aws.String(natGatewayID),
			},
		},
		StartTime:  aws.Time(start),
		EndTime:    aws.Time(end),
		Period:     aws.Int32(86400), // 1-day granularity → ≤30 points for a 30d window
		Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
	})
	if err != nil || len(out.Datapoints) == 0 {
		return 0
	}

	var totalBytes float64
	for _, dp := range out.Datapoints {
		if dp.Sum != nil {
			totalBytes += *dp.Sum
		}
	}
	return totalBytes / (1024 * 1024 * 1024) // bytes → GB
}
