package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
)

const (
	rdsLowCPURuleID = "RDS_LOW_CPU"

	// rdsLowCPUThresholdPercent is the average CPU below which an RDS instance
	// is considered underutilised.
	rdsLowCPUThresholdPercent = 10.0

	// rdsLowCPUHighThreshold separates HIGH from MEDIUM severity.
	// Below 5% indicates a very lightly loaded database.
	rdsLowCPUHighThreshold = 5.0

	// rdsLowCPUSavingsFraction is the estimated fraction of monthly cost
	// recoverable by downsizing the instance class (~30% for one size-step down).
	rdsLowCPUSavingsFraction = 0.30
)

// AWSRDSLowCPURule flags available RDS instances whose 30-day average CPU
// utilisation is below the threshold, indicating the instance is likely
// overprovisioned for its actual workload.
//
// Instances with AvgCPUPercent == 0 are skipped: 0 means CloudWatch data
// was unavailable, not that CPU is truly zero.
//
// Instances with MonthlyCostUSD == 0 are skipped: savings cannot be
// estimated without a known cost baseline from Cost Explorer.
type AWSRDSLowCPURule struct{}

func (r AWSRDSLowCPURule) ID() string   { return rdsLowCPURuleID }
func (r AWSRDSLowCPURule) Name() string { return "Low CPU RDS Instance" }

// Evaluate returns one Finding per available RDS instance whose AvgCPUPercent
// is greater than 0, below rdsLowCPUThresholdPercent, and MonthlyCostUSD > 0.
// Severity is HIGH for CPU < 5% and MEDIUM for 5–10%.
func (r AWSRDSLowCPURule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}

	var findings []models.Finding
	for _, inst := range ctx.RegionData.RDSInstances {
		if inst.Status != "available" {
			continue
		}
		// 0 means CloudWatch had no data; skip to avoid false positives.
		if inst.AvgCPUPercent == 0 {
			continue
		}
		threshold := policy.GetThreshold(rdsLowCPURuleID, "cpu_threshold", rdsLowCPUThresholdPercent, ctx.Policy)
		if inst.AvgCPUPercent >= threshold {
			continue
		}
		// 0 means Cost Explorer had no data; savings cannot be estimated.
		if inst.MonthlyCostUSD == 0 {
			continue
		}

		severity := models.SeverityMedium
		if inst.AvgCPUPercent < rdsLowCPUHighThreshold {
			severity = models.SeverityHigh
		}

		findings = append(findings, models.Finding{
			ID:                      fmt.Sprintf("%s-%s", rdsLowCPURuleID, inst.DBInstanceID),
			RuleID:                  rdsLowCPURuleID,
			ResourceID:              inst.DBInstanceID,
			ResourceType:            models.ResourceAWSRDS,
			Region:                  inst.Region,
			AccountID:               ctx.AccountID,
			Profile:                 ctx.Profile,
			Severity:                severity,
			EstimatedMonthlySavings: inst.MonthlyCostUSD * rdsLowCPUSavingsFraction,
			Explanation:             "RDS instance class may be overprovisioned.",
			Recommendation:          "Review instance sizing and consider downsizing to a smaller DB instance class.",
			DetectedAt:              time.Now().UTC(),
			Metadata: map[string]any{
				"avg_cpu_percent":  inst.AvgCPUPercent,
				"monthly_cost_usd": inst.MonthlyCostUSD,
			},
		})
	}
	return findings
}
