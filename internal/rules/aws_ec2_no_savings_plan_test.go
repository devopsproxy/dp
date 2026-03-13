package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSEC2NoSavingsPlanRule_ID(t *testing.T) {
	r := AWSEC2NoSavingsPlanRule{}
	if r.ID() != "EC2_NO_SAVINGS_PLAN" {
		t.Errorf("expected EC2_NO_SAVINGS_PLAN, got %s", r.ID())
	}
}

func TestAWSEC2NoSavingsPlanRule_NilRegionData(t *testing.T) {
	r := AWSEC2NoSavingsPlanRule{}
	if findings := r.Evaluate(RuleContext{RegionData: nil}); len(findings) != 0 {
		t.Errorf("expected 0 findings for nil RegionData, got %d", len(findings))
	}
}

func TestAWSEC2NoSavingsPlanRule_RegionHasCoverage_NotFlagged(t *testing.T) {
	r := AWSEC2NoSavingsPlanRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			EC2Instances: []models.AWSEC2Instance{
				{InstanceID: "i-abc123", State: "running", MonthlyCostUSD: 100.0},
			},
			SavingsPlanCoverage: []models.AWSSavingsPlanCoverage{
				{Region: "us-east-1", CoveredCostUSD: 50.0, CoveragePercent: 50.0},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings when region has SP coverage, got %d", len(findings))
	}
}

func TestAWSEC2NoSavingsPlanRule_NoCoverageRunningInstance_Flagged(t *testing.T) {
	r := AWSEC2NoSavingsPlanRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		Profile:   "prod",
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			EC2Instances: []models.AWSEC2Instance{
				{
					InstanceID:     "i-abc123",
					InstanceType:   "m5.large",
					State:          "running",
					Region:         "us-east-1",
					MonthlyCostUSD: 100.0,
				},
			},
			SavingsPlanCoverage: []models.AWSSavingsPlanCoverage{
				{Region: "us-east-1", CoveredCostUSD: 0.0, CoveragePercent: 0.0},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "EC2_NO_SAVINGS_PLAN" {
		t.Errorf("expected EC2_NO_SAVINGS_PLAN, got %s", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	wantSavings := 100.0 * 0.20
	if f.EstimatedMonthlySavings != wantSavings {
		t.Errorf("expected savings %.2f, got %.2f", wantSavings, f.EstimatedMonthlySavings)
	}
}

func TestAWSEC2NoSavingsPlanRule_StoppedInstance_NotFlagged(t *testing.T) {
	r := AWSEC2NoSavingsPlanRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			EC2Instances: []models.AWSEC2Instance{
				{InstanceID: "i-stopped", State: "stopped", MonthlyCostUSD: 50.0},
			},
			SavingsPlanCoverage: nil, // no coverage
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings for stopped instance, got %d", len(findings))
	}
}

func TestAWSEC2NoSavingsPlanRule_ZeroCostInstance_NotFlagged(t *testing.T) {
	r := AWSEC2NoSavingsPlanRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			EC2Instances: []models.AWSEC2Instance{
				{InstanceID: "i-nocost", State: "running", MonthlyCostUSD: 0}, // CE data unavailable
			},
			SavingsPlanCoverage: nil,
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings for zero-cost instance (no CE data), got %d", len(findings))
	}
}

func TestAWSEC2NoSavingsPlanRule_NoCoverageSlice_Flagged(t *testing.T) {
	// Region has no SavingsPlanCoverage entries at all (not collected)
	r := AWSEC2NoSavingsPlanRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "eu-west-1",
			EC2Instances: []models.AWSEC2Instance{
				{InstanceID: "i-eu1", State: "running", MonthlyCostUSD: 200.0},
			},
			SavingsPlanCoverage: nil,
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when no SP coverage slice, got %d", len(findings))
	}
}

func TestAWSEC2NoSavingsPlanRule_DistinctFromSPUnderutilized(t *testing.T) {
	// SAVINGS_PLAN_UNDERUTILIZED fires at 45% coverage with $150 on-demand.
	// EC2_NO_SAVINGS_PLAN should NOT fire because there IS coverage (CoveredCostUSD > 0).
	r := AWSEC2NoSavingsPlanRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			EC2Instances: []models.AWSEC2Instance{
				{InstanceID: "i-partial", State: "running", MonthlyCostUSD: 150.0},
			},
			SavingsPlanCoverage: []models.AWSSavingsPlanCoverage{
				{Region: "us-east-1", CoveragePercent: 45.0, OnDemandCostUSD: 150.0, CoveredCostUSD: 120.0},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings (has partial SP coverage), got %d", len(findings))
	}
}
