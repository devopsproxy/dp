package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

const (
	spUnderutilizedRuleID = "SAVINGS_PLAN_UNDERUTILIZED"

	// spUnderutilizedCoverageThreshold is the upper bound below which coverage
	// is considered low. 60% means at least 40% of EC2 compute spend is
	// on-demand and could be covered by a Savings Plan or Reserved Instance.
	spUnderutilizedCoverageThreshold = 60.0

	// spUnderutilizedHighThreshold separates HIGH from MEDIUM severity.
	// Coverage below 40% indicates very little Savings Plan adoption.
	spUnderutilizedHighThreshold = 40.0

	// spUnderutilizedMinOnDemandUSD is the minimum monthly on-demand cost
	// required to trigger the rule. Below $100 the absolute saving is small
	// enough that flagging it creates more noise than value.
	spUnderutilizedMinOnDemandUSD = 100.0

	// spUnderutilizedSavingsFraction is the conservative estimated fraction of
	// on-demand cost recoverable by purchasing a Savings Plan (~10% saving on
	// top of current partial coverage).
	spUnderutilizedSavingsFraction = 0.10
)

// AWSSavingsPlanUnderutilizedRule flags regions where Savings Plan coverage is
// below the threshold and the un-covered on-demand spend is material enough
// to justify action.
//
// One finding is emitted per region entry in RegionData.SavingsPlanCoverage.
// Severity is HIGH for coverage < 40% and MEDIUM for 40–60%.
type AWSSavingsPlanUnderutilizedRule struct{}

func (r AWSSavingsPlanUnderutilizedRule) ID() string   { return spUnderutilizedRuleID }
func (r AWSSavingsPlanUnderutilizedRule) Name() string { return "Savings Plan Underutilized" }

// Evaluate returns one Finding per SavingsPlanCoverage entry that has
// CoveragePercent < 60 and OnDemandCostUSD > 100.
func (r AWSSavingsPlanUnderutilizedRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, cov := range ctx.RegionData.SavingsPlanCoverage {
		if cov.CoveragePercent >= spUnderutilizedCoverageThreshold {
			continue
		}
		if cov.OnDemandCostUSD <= spUnderutilizedMinOnDemandUSD {
			continue
		}

		severity := models.SeverityMedium
		if cov.CoveragePercent < spUnderutilizedHighThreshold {
			severity = models.SeverityHigh
		}

		findings = append(findings, models.Finding{
			ID:                      fmt.Sprintf("%s-%s", spUnderutilizedRuleID, cov.Region),
			RuleID:                  spUnderutilizedRuleID,
			ResourceID:              "savings-plan-" + cov.Region,
			ResourceType:            models.ResourceAWSSavingsPlan,
			Region:                  cov.Region,
			AccountID:               ctx.AccountID,
			Profile:                 ctx.Profile,
			Severity:                severity,
			EstimatedMonthlySavings: cov.OnDemandCostUSD * spUnderutilizedSavingsFraction,
			Explanation:             "Savings Plan coverage is low for this region.",
			Recommendation:          "Evaluate Compute Savings Plans or Reserved Instances to reduce On-Demand cost.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"coverage_percent":   cov.CoveragePercent,
				"on_demand_cost_usd": cov.OnDemandCostUSD,
			},
		})
	}
	return findings
}
