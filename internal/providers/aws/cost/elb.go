package cost

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	elbv2svc "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/devopsproxy/dp/internal/models"
)

// collectLoadBalancers pages through all ELBv2 load balancers (Application,
// Network, Gateway) in region and converts them to internal models.
// Application Load Balancers are enriched with their CloudWatch RequestCount
// over the lookback window. NLB and GWLB use different CloudWatch metrics and
// are left with RequestCount == 0.
//
// Classic ELB (v1) is not collected here — add the elasticloadbalancing
// package and a separate collector if needed in a future step.
func collectLoadBalancers(
	ctx context.Context,
	elbClient costELBv2Client,
	cwClient costCWClient,
	region string,
	daysBack int,
) ([]models.AWSLoadBalancer, error) {
	paginator := elbv2svc.NewDescribeLoadBalancersPaginator(elbClient, &elbv2svc.DescribeLoadBalancersInput{})

	var lbs []models.AWSLoadBalancer
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeLoadBalancers page: %w", err)
		}
		for _, lb := range page.LoadBalancers {
			lbs = append(lbs, toLoadBalancer(lb, region))
		}
	}

	// Enrich Application Load Balancers with CloudWatch RequestCount.
	// RequestCount == 0 from CloudWatch means no traffic over the period.
	// NLB and GWLB are skipped — they use different metrics.
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -effectiveDaysBack(daysBack))
	for i := range lbs {
		if lbs[i].Type == "application" {
			lbs[i].RequestCount = fetchLBRequestCount(ctx, cwClient, lbs[i].LoadBalancerARN, start, end)
		}
	}

	return lbs, nil
}

// toLoadBalancer converts an SDK ELBv2 LoadBalancer to the internal model.
func toLoadBalancer(lb elbv2types.LoadBalancer, region string) models.AWSLoadBalancer {
	var state string
	if lb.State != nil {
		state = string(lb.State.Code)
	}

	return models.AWSLoadBalancer{
		LoadBalancerARN:  aws.ToString(lb.LoadBalancerArn),
		LoadBalancerName: aws.ToString(lb.LoadBalancerName),
		Region:           region,
		Type:             string(lb.Type),
		State:            state,
		RequestCount:     0, // enriched by fetchLBRequestCount for ALBs
		// Tags require a separate DescribeTags API call (not included here).
	}
}

// fetchLBRequestCount calls CloudWatch GetMetricStatistics to retrieve the
// total RequestCount for an ALB over [start, end) at 1-day granularity.
// The LoadBalancer dimension value is extracted from the ARN.
//
// Returns 0 when the call fails or no data points exist. Callers must treat
// 0 as "data unavailable or no traffic" — the ALB_IDLE rule handles both.
func fetchLBRequestCount(
	ctx context.Context,
	cw costCWClient,
	lbARN string,
	start, end time.Time,
) int64 {
	// Extract the CloudWatch LoadBalancer dimension from the ARN.
	// ARN format: arn:aws:elasticloadbalancing:<region>:<acct>:loadbalancer/app/<name>/<id>
	// Dimension value: app/<name>/<id>  (everything after "loadbalancer/")
	const marker = ":loadbalancer/"
	idx := strings.Index(lbARN, marker)
	if idx < 0 {
		return 0
	}
	lbDim := lbARN[idx+len(marker):]

	out, err := cw.GetMetricStatistics(ctx, &cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("AWS/ApplicationELB"),
		MetricName: aws.String("RequestCount"),
		Dimensions: []cwtypes.Dimension{
			{
				Name:  aws.String("LoadBalancer"),
				Value: aws.String(lbDim),
			},
		},
		StartTime:  aws.Time(start),
		EndTime:    aws.Time(end),
		Period:     aws.Int32(86400), // 1-day granularity
		Statistics: []cwtypes.Statistic{cwtypes.StatisticSum},
	})
	if err != nil || len(out.Datapoints) == 0 {
		return 0
	}

	var total float64
	for _, dp := range out.Datapoints {
		if dp.Sum != nil {
			total += *dp.Sum
		}
	}
	return int64(total)
}
