package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
)

func TestAWSRDSLowCPURule_IDAndName(t *testing.T) {
	r := AWSRDSLowCPURule{}
	if r.ID() != "RDS_LOW_CPU" {
		t.Errorf("ID = %q; want RDS_LOW_CPU", r.ID())
	}
	if r.Name() == "" {
		t.Error("Name must not be empty")
	}
}

func TestAWSRDSLowCPURule_NilRegionData(t *testing.T) {
	if got := (AWSRDSLowCPURule{}).Evaluate(RuleContext{}); got != nil {
		t.Errorf("expected nil for nil RegionData, got len=%d", len(got))
	}
}

func TestAWSRDSLowCPURule_Evaluate(t *testing.T) {
	const (
		account = "111122223333"
		profile = "test"
		region  = "us-east-1"
	)

	makeCtx := func(instances ...models.AWSRDSInstance) RuleContext {
		return RuleContext{
			AccountID: account,
			Profile:   profile,
			RegionData: &models.AWSRegionData{
				Region:       region,
				RDSInstances: instances,
			},
		}
	}

	t.Run("CPU 2% + cost 100 → HIGH, savings 30", func(t *testing.T) {
		ctx := makeCtx(models.AWSRDSInstance{
			DBInstanceID:    "db-1",
			Region:          region,
			DBInstanceClass: "db.t3.medium",
			Status:          "available",
			AvgCPUPercent:   2.0,
			MonthlyCostUSD:  100.0,
		})
		findings := (AWSRDSLowCPURule{}).Evaluate(ctx)
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != models.SeverityHigh {
			t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
		}
		if want := 30.0; findings[0].EstimatedMonthlySavings != want { // 100 * 0.30
			t.Errorf("EstimatedMonthlySavings = %.2f; want %.2f", findings[0].EstimatedMonthlySavings, want)
		}
	})

	t.Run("CPU 7% + cost 200 → MEDIUM, savings 60", func(t *testing.T) {
		ctx := makeCtx(models.AWSRDSInstance{
			DBInstanceID:    "db-1",
			Region:          region,
			DBInstanceClass: "db.m5.large",
			Status:          "available",
			AvgCPUPercent:   7.0,
			MonthlyCostUSD:  200.0,
		})
		findings := (AWSRDSLowCPURule{}).Evaluate(ctx)
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != models.SeverityMedium {
			t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
		}
		if want := 60.0; findings[0].EstimatedMonthlySavings != want { // 200 * 0.30
			t.Errorf("EstimatedMonthlySavings = %.2f; want %.2f", findings[0].EstimatedMonthlySavings, want)
		}
	})

	t.Run("CPU 5% is MEDIUM (at high boundary)", func(t *testing.T) {
		ctx := makeCtx(models.AWSRDSInstance{
			DBInstanceID:    "db-1",
			Region:          region,
			DBInstanceClass: "db.m5.large",
			Status:          "available",
			AvgCPUPercent:   5.0, // exactly at boundary — MEDIUM not HIGH
			MonthlyCostUSD:  100.0,
		})
		findings := (AWSRDSLowCPURule{}).Evaluate(ctx)
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != models.SeverityMedium {
			t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
		}
	})

	t.Run("CPU 15% → not flagged", func(t *testing.T) {
		ctx := makeCtx(models.AWSRDSInstance{
			DBInstanceID:    "db-1",
			Region:          region,
			DBInstanceClass: "db.m5.large",
			Status:          "available",
			AvgCPUPercent:   15.0,
			MonthlyCostUSD:  100.0,
		})
		if got := (AWSRDSLowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("CPU=15%%: expected 0 findings, got %d", len(got))
		}
	})

	t.Run("CPU at threshold (10%) → not flagged", func(t *testing.T) {
		ctx := makeCtx(models.AWSRDSInstance{
			DBInstanceID:    "db-1",
			Region:          region,
			DBInstanceClass: "db.m5.large",
			Status:          "available",
			AvgCPUPercent:   10.0,
			MonthlyCostUSD:  100.0,
		})
		if got := (AWSRDSLowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("CPU=10%% (at threshold): expected 0 findings, got %d", len(got))
		}
	})

	t.Run("cost 0 → skipped (cost unknown)", func(t *testing.T) {
		ctx := makeCtx(models.AWSRDSInstance{
			DBInstanceID:    "db-1",
			Region:          region,
			DBInstanceClass: "db.m5.large",
			Status:          "available",
			AvgCPUPercent:   3.0,
			MonthlyCostUSD:  0,
		})
		if got := (AWSRDSLowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("cost=0: expected 0 findings, got %d", len(got))
		}
	})

	t.Run("zero AvgCPUPercent → skipped (no CloudWatch data)", func(t *testing.T) {
		ctx := makeCtx(models.AWSRDSInstance{
			DBInstanceID:    "db-1",
			Region:          region,
			DBInstanceClass: "db.m5.large",
			Status:          "available",
			AvgCPUPercent:   0.0,
			MonthlyCostUSD:  100.0,
		})
		if got := (AWSRDSLowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("CPU=0 (no CW data): expected 0 findings, got %d", len(got))
		}
	})

	t.Run("non-available status → not flagged", func(t *testing.T) {
		for _, status := range []string{"stopped", "stopping", "rebooting", "creating", "deleting", "failed"} {
			status := status
			t.Run(status, func(t *testing.T) {
				ctx := makeCtx(models.AWSRDSInstance{
					DBInstanceID:    "db-1",
					Region:          region,
					DBInstanceClass: "db.m5.large",
					Status:          status,
					AvgCPUPercent:   3.0,
					MonthlyCostUSD:  100.0,
				})
				if got := (AWSRDSLowCPURule{}).Evaluate(ctx); len(got) != 0 {
					t.Errorf("status=%q: expected 0 findings, got %d", status, len(got))
				}
			})
		}
	})

	t.Run("finding has correct fields", func(t *testing.T) {
		inst := models.AWSRDSInstance{
			DBInstanceID:    "mydb-prod",
			Region:          region,
			DBInstanceClass: "db.r5.large",
			Status:          "available",
			AvgCPUPercent:   3.0,
			MonthlyCostUSD:  150.0,
		}
		findings := (AWSRDSLowCPURule{}).Evaluate(makeCtx(inst))
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		f := findings[0]

		if want := "RDS_LOW_CPU-mydb-prod"; f.ID != want {
			t.Errorf("ID = %q; want %q", f.ID, want)
		}
		if f.RuleID != "RDS_LOW_CPU" {
			t.Errorf("RuleID = %q; want RDS_LOW_CPU", f.RuleID)
		}
		if f.ResourceID != "mydb-prod" {
			t.Errorf("ResourceID = %q; want mydb-prod", f.ResourceID)
		}
		if f.ResourceType != models.ResourceAWSRDS {
			t.Errorf("ResourceType = %q; want %q", f.ResourceType, models.ResourceAWSRDS)
		}
		if f.Severity != models.SeverityHigh { // 3.0 < 5.0 → HIGH
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
		if want := 45.0; f.EstimatedMonthlySavings != want { // 150 * 0.30
			t.Errorf("EstimatedMonthlySavings = %.2f; want %.2f", f.EstimatedMonthlySavings, want)
		}
		if f.Metadata["avg_cpu_percent"] != 3.0 {
			t.Errorf("Metadata[avg_cpu_percent] = %v; want 3.0", f.Metadata["avg_cpu_percent"])
		}
		if f.Metadata["monthly_cost_usd"] != 150.0 {
			t.Errorf("Metadata[monthly_cost_usd] = %v; want 150.0", f.Metadata["monthly_cost_usd"])
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

	t.Run("savings proportional to monthly cost", func(t *testing.T) {
		cases := []struct {
			costUSD     float64
			wantSavings float64
		}{
			{100.0, 30.0},
			{200.0, 60.0},
			{500.0, 150.0},
		}
		for _, tc := range cases {
			ctx := makeCtx(models.AWSRDSInstance{
				DBInstanceID:    "db-1",
				Region:          region,
				DBInstanceClass: "db.m5.large",
				Status:          "available",
				AvgCPUPercent:   3.0,
				MonthlyCostUSD:  tc.costUSD,
			})
			findings := (AWSRDSLowCPURule{}).Evaluate(ctx)
			if len(findings) != 1 {
				t.Fatalf("costUSD=%.0f: want 1 finding, got %d", tc.costUSD, len(findings))
			}
			if findings[0].EstimatedMonthlySavings != tc.wantSavings {
				t.Errorf("costUSD=%.0f: savings = %.2f; want %.2f",
					tc.costUSD, findings[0].EstimatedMonthlySavings, tc.wantSavings)
			}
		}
	})

	t.Run("only available low-CPU instances with known cost flagged from mixed set", func(t *testing.T) {
		ctx := makeCtx(
			models.AWSRDSInstance{DBInstanceID: "db-1", Region: region, Status: "available", AvgCPUPercent: 3.0, MonthlyCostUSD: 100.0},  // flagged: HIGH
			models.AWSRDSInstance{DBInstanceID: "db-2", Region: region, Status: "available", AvgCPUPercent: 0.0, MonthlyCostUSD: 100.0},  // skipped: no CW data
			models.AWSRDSInstance{DBInstanceID: "db-3", Region: region, Status: "available", AvgCPUPercent: 50.0, MonthlyCostUSD: 100.0}, // skipped: high CPU
			models.AWSRDSInstance{DBInstanceID: "db-4", Region: region, Status: "stopped", AvgCPUPercent: 3.0, MonthlyCostUSD: 100.0},    // skipped: not available
			models.AWSRDSInstance{DBInstanceID: "db-5", Region: region, Status: "available", AvgCPUPercent: 2.0, MonthlyCostUSD: 0},      // skipped: no cost data
			models.AWSRDSInstance{DBInstanceID: "db-6", Region: region, Status: "available", AvgCPUPercent: 7.0, MonthlyCostUSD: 200.0},  // flagged: MEDIUM
		)
		findings := (AWSRDSLowCPURule{}).Evaluate(ctx)
		if len(findings) != 2 {
			t.Fatalf("want 2 findings, got %d", len(findings))
		}
		want := map[string]bool{"db-1": true, "db-6": true}
		for _, f := range findings {
			if !want[f.ResourceID] {
				t.Errorf("unexpected ResourceID %q in findings", f.ResourceID)
			}
		}
	})
}

func TestAWSRDSLowCPURule_ThresholdOverride(t *testing.T) {
	// Instance at 12% CPU is above the default 10% threshold and would NOT be
	// flagged without a policy. A policy raising cpu_threshold to 15% makes
	// 12% fall below the threshold, so the instance MUST be flagged.
	cfg := &policy.PolicyConfig{
		Rules: map[string]policy.RuleConfig{
			"RDS_LOW_CPU": {
				Params: map[string]float64{"cpu_threshold": 15.0},
			},
		},
	}
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "test",
		Policy:    cfg,
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			RDSInstances: []models.AWSRDSInstance{{
				DBInstanceID:   "db-override",
				Region:         "us-east-1",
				Status:         "available",
				AvgCPUPercent:  12.0,
				MonthlyCostUSD: 200.0,
			}},
		},
	}
	findings := (AWSRDSLowCPURule{}).Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding (cpu_threshold raised to 15%%), got %d", len(findings))
	}
	if findings[0].ResourceID != "db-override" {
		t.Errorf("ResourceID = %q; want db-override", findings[0].ResourceID)
	}
}
