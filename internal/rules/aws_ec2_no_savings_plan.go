package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

const (
	ec2NoSavingsPlanRuleID = "EC2_NO_SAVINGS_PLAN"

	// ec2NoSavingsPlanSavingsFraction is the estimated savings from a 1-year
	// no-upfront Compute Savings Plan (~20% discount over on-demand).
	ec2NoSavingsPlanSavingsFraction = 0.20
)

// AWSEC2NoSavingsPlanRule flags running EC2 instances in regions where there
// is no Savings Plan coverage (CoveredCostUSD == 0 for the instance's region).
//
// This rule is distinct from AWSSavingsPlanUnderutilizedRule, which fires when
// an existing Savings Plan is underutilized (coverage < 60%). This rule fires
// when the region has no Savings Plan coverage at all — the instance is fully
// on-demand with no discount applied.
//
// Instances with MonthlyCostUSD == 0 are skipped: cost data from Cost Explorer
// was unavailable and savings cannot be estimated reliably.
type AWSEC2NoSavingsPlanRule struct{}

func (r AWSEC2NoSavingsPlanRule) ID() string   { return ec2NoSavingsPlanRuleID }
func (r AWSEC2NoSavingsPlanRule) Name() string { return "EC2 Instance Without Savings Plan Coverage" }

// Evaluate returns one HIGH finding per running EC2 instance whose region has
// no Savings Plan coverage (CoveredCostUSD == 0) and whose monthly cost is
// known from Cost Explorer (MonthlyCostUSD > 0).
func (r AWSEC2NoSavingsPlanRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	// Check whether any Savings Plan discount was applied in this region.
	// CoveredCostUSD > 0 means at least some SP discount was applied.
	hasAnyCoverage := false
	for _, sp := range ctx.RegionData.SavingsPlanCoverage {
		if sp.Region == ctx.RegionData.Region && sp.CoveredCostUSD > 0 {
			hasAnyCoverage = true
			break
		}
	}
	if hasAnyCoverage {
		return nil
	}

	var findings []models.Finding
	for _, inst := range ctx.RegionData.EC2Instances {
		if inst.State != "running" {
			continue
		}
		// 0 means Cost Explorer had no data; skip — savings cannot be estimated.
		if inst.MonthlyCostUSD == 0 {
			continue
		}

		findings = append(findings, models.Finding{
			ID:                      fmt.Sprintf("%s-%s", ec2NoSavingsPlanRuleID, inst.InstanceID),
			RuleID:                  ec2NoSavingsPlanRuleID,
			ResourceID:              inst.InstanceID,
			ResourceType:            models.ResourceAWSEC2,
			Region:                  inst.Region,
			AccountID:               ctx.AccountID,
			Profile:                 ctx.Profile,
			Severity:                models.SeverityHigh,
			EstimatedMonthlySavings: inst.MonthlyCostUSD * ec2NoSavingsPlanSavingsFraction,
			Explanation:             "Running EC2 instance has no Savings Plan coverage in this region.",
			Recommendation:          "Purchase a Compute Savings Plan or EC2 Instance Savings Plan to reduce on-demand costs by up to 66%.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"instance_type":    inst.InstanceType,
				"monthly_cost_usd": inst.MonthlyCostUSD,
			},
		})
	}
	return findings
}
