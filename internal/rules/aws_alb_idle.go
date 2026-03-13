package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// AWSALBIdleRule flags Application Load Balancers that received zero requests
// over the evaluation period, indicating the LB is likely idle and incurring
// unnecessary hourly charges.
//
// Only ALBs with state == "active" are evaluated. NLB and GWLB are excluded
// because they use different CloudWatch metrics. RequestCount == 0 means either
// no traffic reached the ALB or CloudWatch data was unavailable — both cases
// are flagged because an active ALB with no traffic is suspicious.
type AWSALBIdleRule struct{}

func (r AWSALBIdleRule) ID() string   { return "ALB_IDLE" }
func (r AWSALBIdleRule) Name() string { return "Application Load Balancer Idle" }

// Evaluate returns one HIGH finding per active ALB whose RequestCount is zero.
func (r AWSALBIdleRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, lb := range ctx.RegionData.LoadBalancers {
		if lb.Type != "application" {
			continue
		}
		if lb.State != "active" {
			continue
		}
		if lb.RequestCount != 0 {
			continue
		}

		findings = append(findings, models.Finding{
			ID:           fmt.Sprintf("ALB_IDLE-%s", lb.LoadBalancerName),
			RuleID:       r.ID(),
			ResourceID:   lb.LoadBalancerName,
			ResourceType: models.ResourceAWSLoadBalancer,
			Region:       lb.Region,
			AccountID:    ctx.AccountID,
			Profile:      ctx.Profile,
			// ALB fixed cost: ~$0.008/hr × 730 hr/mo = ~$5.84/mo base + LCU charges.
			// Conservative estimate of $18/mo covers base + minimal LCU usage.
			Severity:                models.SeverityHigh,
			EstimatedMonthlySavings: 18.0,
			Explanation:             "Application Load Balancer has received no traffic over the evaluation period.",
			Recommendation:          "Verify the load balancer is not needed and delete it to stop incurring hourly charges.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"load_balancer_arn": lb.LoadBalancerARN,
				"request_count":     lb.RequestCount,
			},
		})
	}
	return findings
}
