package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSSavingsPlanUnderutilizedRule_IDAndName(t *testing.T) {
	r := AWSSavingsPlanUnderutilizedRule{}
	if r.ID() != "SAVINGS_PLAN_UNDERUTILIZED" {
		t.Errorf("ID = %q; want SAVINGS_PLAN_UNDERUTILIZED", r.ID())
	}
	if r.Name() == "" {
		t.Error("Name must not be empty")
	}
}

func TestAWSSavingsPlanUnderutilizedRule_NilRegionData(t *testing.T) {
	if got := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(RuleContext{}); got != nil {
		t.Errorf("expected nil for nil RegionData, got len=%d", len(got))
	}
}

func TestAWSSavingsPlanUnderutilizedRule_Evaluate(t *testing.T) {
	const (
		account = "111122223333"
		profile = "test"
		region  = "us-east-1"
	)

	makeCtx := func(coverages ...models.AWSSavingsPlanCoverage) RuleContext {
		return RuleContext{
			AccountID: account,
			Profile:   profile,
			RegionData: &models.AWSRegionData{
				Region:              region,
				SavingsPlanCoverage: coverages,
			},
		}
	}

	t.Run("coverage 30% and cost 500 is HIGH", func(t *testing.T) {
		ctx := makeCtx(models.AWSSavingsPlanCoverage{
			Region:          region,
			CoveragePercent: 30.0,
			OnDemandCostUSD: 500.0,
		})
		findings := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx)
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != models.SeverityHigh {
			t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
		}
		if want := 50.0; findings[0].EstimatedMonthlySavings != want { // 500 * 0.10
			t.Errorf("EstimatedMonthlySavings = %.2f; want %.2f", findings[0].EstimatedMonthlySavings, want)
		}
	})

	t.Run("coverage 50% and cost 500 is MEDIUM", func(t *testing.T) {
		ctx := makeCtx(models.AWSSavingsPlanCoverage{
			Region:          region,
			CoveragePercent: 50.0,
			OnDemandCostUSD: 500.0,
		})
		findings := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx)
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != models.SeverityMedium {
			t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
		}
		if want := 50.0; findings[0].EstimatedMonthlySavings != want { // 500 * 0.10
			t.Errorf("EstimatedMonthlySavings = %.2f; want %.2f", findings[0].EstimatedMonthlySavings, want)
		}
	})

	t.Run("coverage 70% is not flagged (above threshold)", func(t *testing.T) {
		ctx := makeCtx(models.AWSSavingsPlanCoverage{
			Region:          region,
			CoveragePercent: 70.0,
			OnDemandCostUSD: 500.0,
		})
		if got := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("coverage=70%%: expected 0 findings, got %d", len(got))
		}
	})

	t.Run("coverage 60% is not flagged (at threshold)", func(t *testing.T) {
		ctx := makeCtx(models.AWSSavingsPlanCoverage{
			Region:          region,
			CoveragePercent: 60.0,
			OnDemandCostUSD: 500.0,
		})
		if got := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("coverage=60%% (at threshold): expected 0 findings, got %d", len(got))
		}
	})

	t.Run("coverage 50% and cost 50 is not flagged (below min on-demand)", func(t *testing.T) {
		ctx := makeCtx(models.AWSSavingsPlanCoverage{
			Region:          region,
			CoveragePercent: 50.0,
			OnDemandCostUSD: 50.0,
		})
		if got := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("on_demand=50: expected 0 findings, got %d", len(got))
		}
	})

	t.Run("coverage 50% and cost exactly 100 is not flagged (at min threshold)", func(t *testing.T) {
		ctx := makeCtx(models.AWSSavingsPlanCoverage{
			Region:          region,
			CoveragePercent: 50.0,
			OnDemandCostUSD: 100.0,
		})
		if got := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("on_demand=100 (at threshold): expected 0 findings, got %d", len(got))
		}
	})

	t.Run("finding has correct fields", func(t *testing.T) {
		ctx := makeCtx(models.AWSSavingsPlanCoverage{
			Region:          region,
			CoveragePercent: 25.0,
			OnDemandCostUSD: 200.0,
		})
		findings := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx)
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		f := findings[0]

		if want := "SAVINGS_PLAN_UNDERUTILIZED-" + region; f.ID != want {
			t.Errorf("ID = %q; want %q", f.ID, want)
		}
		if f.RuleID != "SAVINGS_PLAN_UNDERUTILIZED" {
			t.Errorf("RuleID = %q; want SAVINGS_PLAN_UNDERUTILIZED", f.RuleID)
		}
		if want := "savings-plan-" + region; f.ResourceID != want {
			t.Errorf("ResourceID = %q; want %q", f.ResourceID, want)
		}
		if f.ResourceType != models.ResourceAWSSavingsPlan {
			t.Errorf("ResourceType = %q; want %q", f.ResourceType, models.ResourceAWSSavingsPlan)
		}
		if f.Severity != models.SeverityHigh {
			t.Errorf("Severity = %q; want HIGH", f.Severity)
		}
		if f.Region != region {
			t.Errorf("Region = %q; want %q", f.Region, region)
		}
		if f.AccountID != account {
			t.Errorf("AccountID = %q; want %q", f.AccountID, account)
		}
		if f.Profile != profile {
			t.Errorf("Profile = %q; want %q", f.Profile, profile)
		}
		if want := 20.0; f.EstimatedMonthlySavings != want { // 200 * 0.10
			t.Errorf("EstimatedMonthlySavings = %.2f; want %.2f", f.EstimatedMonthlySavings, want)
		}
		if f.Metadata["coverage_percent"] != 25.0 {
			t.Errorf("Metadata[coverage_percent] = %v; want 25.0", f.Metadata["coverage_percent"])
		}
		if f.Metadata["on_demand_cost_usd"] != 200.0 {
			t.Errorf("Metadata[on_demand_cost_usd] = %v; want 200.0", f.Metadata["on_demand_cost_usd"])
		}
		if f.Explanation == "" {
			t.Error("Explanation must not be empty")
		}
		if f.Recommendation == "" {
			t.Error("Recommendation must not be empty")
		}
		if f.DetectedAt.IsZero() {
			t.Error("DetectedAt must not be zero")
		}
	})

	t.Run("savings proportional to on-demand cost", func(t *testing.T) {
		cases := []struct {
			onDemand    float64
			wantSavings float64
		}{
			{200.0, 20.0},
			{1000.0, 100.0},
			{500.0, 50.0},
		}
		for _, tc := range cases {
			ctx := makeCtx(models.AWSSavingsPlanCoverage{
				Region:          region,
				CoveragePercent: 30.0,
				OnDemandCostUSD: tc.onDemand,
			})
			findings := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx)
			if len(findings) != 1 {
				t.Fatalf("onDemand=%.0f: want 1 finding, got %d", tc.onDemand, len(findings))
			}
			if findings[0].EstimatedMonthlySavings != tc.wantSavings {
				t.Errorf("onDemand=%.0f: savings = %.2f; want %.2f",
					tc.onDemand, findings[0].EstimatedMonthlySavings, tc.wantSavings)
			}
		}
	})

	t.Run("only low-coverage regions with sufficient cost flagged from mixed set", func(t *testing.T) {
		ctx := makeCtx(
			models.AWSSavingsPlanCoverage{Region: "us-east-1", CoveragePercent: 30.0, OnDemandCostUSD: 500.0},  // flagged: HIGH
			models.AWSSavingsPlanCoverage{Region: "us-west-2", CoveragePercent: 75.0, OnDemandCostUSD: 500.0},  // not flagged: coverage OK
			models.AWSSavingsPlanCoverage{Region: "eu-west-1", CoveragePercent: 50.0, OnDemandCostUSD: 50.0},   // not flagged: cost too low
			models.AWSSavingsPlanCoverage{Region: "ap-south-1", CoveragePercent: 55.0, OnDemandCostUSD: 300.0}, // flagged: MEDIUM
		)
		findings := (AWSSavingsPlanUnderutilizedRule{}).Evaluate(ctx)
		if len(findings) != 2 {
			t.Fatalf("want 2 findings, got %d", len(findings))
		}
		want := map[string]bool{"savings-plan-us-east-1": true, "savings-plan-ap-south-1": true}
		for _, f := range findings {
			if !want[f.ResourceID] {
				t.Errorf("unexpected ResourceID %q in findings", f.ResourceID)
			}
		}
	})
}
