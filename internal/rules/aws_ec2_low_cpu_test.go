package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
)

func TestAWSEC2LowCPURule_IDAndName(t *testing.T) {
	r := AWSEC2LowCPURule{}
	if r.ID() != "EC2_LOW_CPU" {
		t.Errorf("ID = %q; want EC2_LOW_CPU", r.ID())
	}
	if r.Name() == "" {
		t.Error("Name must not be empty")
	}
}

func TestAWSEC2LowCPURule_NilRegionData(t *testing.T) {
	if got := (AWSEC2LowCPURule{}).Evaluate(RuleContext{}); got != nil {
		t.Errorf("expected nil for nil RegionData, got len=%d", len(got))
	}
}

func TestAWSEC2LowCPURule_Evaluate(t *testing.T) {
	const (
		account = "111122223333"
		profile = "test"
		region  = "us-east-1"
	)

	makeCtx := func(instances ...models.AWSEC2Instance) RuleContext {
		return RuleContext{
			AccountID: account,
			Profile:   profile,
			RegionData: &models.AWSRegionData{
				Region:       region,
				EC2Instances: instances,
			},
		}
	}

	t.Run("non-running states are not flagged", func(t *testing.T) {
		for _, state := range []string{"stopped", "terminated", "pending", "shutting-down"} {
			state := state
			t.Run(state, func(t *testing.T) {
				ctx := makeCtx(models.AWSEC2Instance{
					InstanceID:     "i-1",
					Region:         region,
					InstanceType:   "t3.medium",
					State:          state,
					AvgCPUPercent:  5.0,
					MonthlyCostUSD: 100.0,
				})
				if got := (AWSEC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
					t.Errorf("state=%q: expected 0 findings, got %d", state, len(got))
				}
			})
		}
	})

	t.Run("zero AvgCPUPercent is skipped (no CloudWatch data)", func(t *testing.T) {
		ctx := makeCtx(models.AWSEC2Instance{
			InstanceID:     "i-1",
			Region:         region,
			InstanceType:   "m5.large",
			State:          "running",
			AvgCPUPercent:  0.0,
			MonthlyCostUSD: 100.0,
		})
		if got := (AWSEC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("expected 0 findings for zero CPU (no CW data), got %d", len(got))
		}
	})

	t.Run("zero MonthlyCostUSD is skipped (cost unknown)", func(t *testing.T) {
		ctx := makeCtx(models.AWSEC2Instance{
			InstanceID:     "i-1",
			Region:         region,
			InstanceType:   "m5.large",
			State:          "running",
			AvgCPUPercent:  5.0,
			MonthlyCostUSD: 0,
		})
		if got := (AWSEC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("expected 0 findings for zero MonthlyCostUSD (cost unknown), got %d", len(got))
		}
	})

	t.Run("CPU at threshold is not flagged", func(t *testing.T) {
		ctx := makeCtx(models.AWSEC2Instance{
			InstanceID:     "i-1",
			Region:         region,
			InstanceType:   "m5.large",
			State:          "running",
			AvgCPUPercent:  10.0, // exactly at threshold — should not fire
			MonthlyCostUSD: 100.0,
		})
		if got := (AWSEC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("CPU=10.0 (at threshold): expected 0 findings, got %d", len(got))
		}
	})

	t.Run("CPU above threshold is not flagged", func(t *testing.T) {
		ctx := makeCtx(models.AWSEC2Instance{
			InstanceID:     "i-1",
			Region:         region,
			InstanceType:   "m5.large",
			State:          "running",
			AvgCPUPercent:  50.0,
			MonthlyCostUSD: 100.0,
		})
		if got := (AWSEC2LowCPURule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("CPU=50.0: expected 0 findings, got %d", len(got))
		}
	})

	t.Run("running instance with low CPU is flagged with correct fields", func(t *testing.T) {
		inst := models.AWSEC2Instance{
			InstanceID:     "i-abc123",
			Region:         region,
			InstanceType:   "m5.large",
			State:          "running",
			AvgCPUPercent:  3.5,
			MonthlyCostUSD: 100.0,
		}
		findings := (AWSEC2LowCPURule{}).Evaluate(makeCtx(inst))
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		f := findings[0]

		if want := "EC2_LOW_CPU-i-abc123"; f.ID != want {
			t.Errorf("ID = %q; want %q", f.ID, want)
		}
		if f.RuleID != "EC2_LOW_CPU" {
			t.Errorf("RuleID = %q; want EC2_LOW_CPU", f.RuleID)
		}
		if f.ResourceID != "i-abc123" {
			t.Errorf("ResourceID = %q; want i-abc123", f.ResourceID)
		}
		if f.ResourceType != models.ResourceAWSEC2 {
			t.Errorf("ResourceType = %q; want %q", f.ResourceType, models.ResourceAWSEC2)
		}
		if f.Severity != models.SeverityMedium {
			t.Errorf("Severity = %q; want MEDIUM", f.Severity)
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
		if want := 30.00; f.EstimatedMonthlySavings != want { // 100.0 * 0.30
			t.Errorf("EstimatedMonthlySavings = %.4f; want %.2f", f.EstimatedMonthlySavings, want)
		}
		if f.Metadata["instance_type"] != "m5.large" {
			t.Errorf("Metadata[instance_type] = %v; want m5.large", f.Metadata["instance_type"])
		}
		if f.Metadata["avg_cpu_percent"] != 3.5 {
			t.Errorf("Metadata[avg_cpu_percent] = %v; want 3.5", f.Metadata["avg_cpu_percent"])
		}
		if f.Metadata["monthly_cost_usd"] != 100.0 {
			t.Errorf("Metadata[monthly_cost_usd] = %v; want 100.0", f.Metadata["monthly_cost_usd"])
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

	t.Run("savings are proportional to monthly cost", func(t *testing.T) {
		cases := []struct {
			costUSD     float64
			wantSavings float64
		}{
			{100.0, 30.0},
			{200.0, 60.0},
			{50.0, 15.0},
		}
		for _, tc := range cases {
			ctx := makeCtx(models.AWSEC2Instance{
				InstanceID:     "i-1",
				Region:         region,
				InstanceType:   "m5.large",
				State:          "running",
				AvgCPUPercent:  5.0,
				MonthlyCostUSD: tc.costUSD,
			})
			findings := (AWSEC2LowCPURule{}).Evaluate(ctx)
			if len(findings) != 1 {
				t.Fatalf("costUSD=%.0f: want 1 finding, got %d", tc.costUSD, len(findings))
			}
			if findings[0].EstimatedMonthlySavings != tc.wantSavings {
				t.Errorf("costUSD=%.0f: savings = %.2f; want %.2f",
					tc.costUSD, findings[0].EstimatedMonthlySavings, tc.wantSavings)
			}
		}
	})

	t.Run("CPU just below threshold is flagged", func(t *testing.T) {
		ctx := makeCtx(models.AWSEC2Instance{
			InstanceID:     "i-1",
			Region:         region,
			InstanceType:   "t3.medium",
			State:          "running",
			AvgCPUPercent:  9.9,
			MonthlyCostUSD: 50.0,
		})
		if got := (AWSEC2LowCPURule{}).Evaluate(ctx); len(got) != 1 {
			t.Errorf("CPU=9.9 (just below threshold): want 1 finding, got %d", len(got))
		}
	})

	t.Run("only low-CPU running instances with known cost flagged from mixed set", func(t *testing.T) {
		ctx := makeCtx(
			models.AWSEC2Instance{InstanceID: "i-1", Region: region, InstanceType: "m5.large", State: "running", AvgCPUPercent: 5.0, MonthlyCostUSD: 100.0},  // flagged
			models.AWSEC2Instance{InstanceID: "i-2", Region: region, InstanceType: "m5.large", State: "running", AvgCPUPercent: 0.0, MonthlyCostUSD: 100.0},  // skipped: no CW data
			models.AWSEC2Instance{InstanceID: "i-3", Region: region, InstanceType: "m5.large", State: "running", AvgCPUPercent: 50.0, MonthlyCostUSD: 100.0}, // skipped: high CPU
			models.AWSEC2Instance{InstanceID: "i-4", Region: region, InstanceType: "m5.large", State: "stopped", AvgCPUPercent: 3.0, MonthlyCostUSD: 100.0},  // skipped: not running
			models.AWSEC2Instance{InstanceID: "i-5", Region: region, InstanceType: "t3.small", State: "running", AvgCPUPercent: 1.5, MonthlyCostUSD: 0},      // skipped: no cost data
			models.AWSEC2Instance{InstanceID: "i-6", Region: region, InstanceType: "t3.small", State: "running", AvgCPUPercent: 3.0, MonthlyCostUSD: 80.0},   // flagged
		)
		findings := (AWSEC2LowCPURule{}).Evaluate(ctx)
		if len(findings) != 2 {
			t.Fatalf("want 2 findings, got %d", len(findings))
		}
		want := map[string]bool{"i-1": true, "i-6": true}
		for _, f := range findings {
			if !want[f.ResourceID] {
				t.Errorf("unexpected ResourceID %q in findings", f.ResourceID)
			}
		}
	})
}

func TestAWSEC2LowCPURule_ThresholdOverride(t *testing.T) {
	// Instance at 12% CPU is above the default 10% threshold, so it would NOT
	// be flagged without a policy. A policy raising cpu_threshold to 15% makes
	// 12% fall below the threshold, so the instance MUST be flagged.
	cfg := &policy.PolicyConfig{
		Rules: map[string]policy.RuleConfig{
			"EC2_LOW_CPU": {
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
			EC2Instances: []models.AWSEC2Instance{{
				InstanceID:     "i-override",
				Region:         "us-east-1",
				InstanceType:   "m5.large",
				State:          "running",
				AvgCPUPercent:  12.0,
				MonthlyCostUSD: 100.0,
			}},
		},
	}
	findings := (AWSEC2LowCPURule{}).Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding (cpu_threshold raised to 15%%), got %d", len(findings))
	}
	if findings[0].ResourceID != "i-override" {
		t.Errorf("ResourceID = %q; want i-override", findings[0].ResourceID)
	}
}
