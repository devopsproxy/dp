package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
)

func TestAWSNATLowTrafficRule_IDAndName(t *testing.T) {
	r := AWSNATLowTrafficRule{}
	if r.ID() != "NAT_LOW_TRAFFIC" {
		t.Errorf("ID = %q; want NAT_LOW_TRAFFIC", r.ID())
	}
	if r.Name() == "" {
		t.Error("Name must not be empty")
	}
}

func TestAWSNATLowTrafficRule_NilRegionData(t *testing.T) {
	if got := (AWSNATLowTrafficRule{}).Evaluate(RuleContext{}); got != nil {
		t.Errorf("expected nil for nil RegionData, got len=%d", len(got))
	}
}

func TestAWSNATLowTrafficRule_Evaluate(t *testing.T) {
	const (
		account = "111122223333"
		profile = "test"
		region  = "us-east-1"
	)

	makeCtx := func(gws ...models.AWSNATGateway) RuleContext {
		return RuleContext{
			AccountID: account,
			Profile:   profile,
			RegionData: &models.AWSRegionData{
				Region:      region,
				NATGateways: gws,
			},
		}
	}

	t.Run("zero traffic is flagged", func(t *testing.T) {
		ctx := makeCtx(models.AWSNATGateway{
			NATGatewayID:     "nat-zero",
			Region:           region,
			State:            "available",
			BytesProcessedGB: 0,
		})
		if got := (AWSNATLowTrafficRule{}).Evaluate(ctx); len(got) != 1 {
			t.Errorf("want 1 finding, got %d", len(got))
		}
	})

	t.Run("0.5 GB is flagged", func(t *testing.T) {
		ctx := makeCtx(models.AWSNATGateway{
			NATGatewayID:     "nat-half",
			Region:           region,
			State:            "available",
			BytesProcessedGB: 0.5,
		})
		if got := (AWSNATLowTrafficRule{}).Evaluate(ctx); len(got) != 1 {
			t.Errorf("want 1 finding, got %d", len(got))
		}
	})

	t.Run("1.0 GB is NOT flagged (at threshold)", func(t *testing.T) {
		ctx := makeCtx(models.AWSNATGateway{
			NATGatewayID:     "nat-1gb",
			Region:           region,
			State:            "available",
			BytesProcessedGB: 1.0,
		})
		if got := (AWSNATLowTrafficRule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("want 0 findings, got %d", len(got))
		}
	})

	t.Run("5 GB is NOT flagged", func(t *testing.T) {
		ctx := makeCtx(models.AWSNATGateway{
			NATGatewayID:     "nat-5gb",
			Region:           region,
			State:            "available",
			BytesProcessedGB: 5.0,
		})
		if got := (AWSNATLowTrafficRule{}).Evaluate(ctx); len(got) != 0 {
			t.Errorf("want 0 findings, got %d", len(got))
		}
	})

	t.Run("non-available state is NOT flagged", func(t *testing.T) {
		for _, state := range []string{"deleting", "deleted", "failed", "pending"} {
			state := state
			t.Run(state, func(t *testing.T) {
				ctx := makeCtx(models.AWSNATGateway{
					NATGatewayID:     "nat-x",
					Region:           region,
					State:            state,
					BytesProcessedGB: 0,
				})
				if got := (AWSNATLowTrafficRule{}).Evaluate(ctx); len(got) != 0 {
					t.Errorf("state=%q: want 0 findings, got %d", state, len(got))
				}
			})
		}
	})

	t.Run("finding has correct fields", func(t *testing.T) {
		ng := models.AWSNATGateway{
			NATGatewayID:     "nat-abc",
			Region:           region,
			State:            "available",
			BytesProcessedGB: 0.1,
		}
		findings := (AWSNATLowTrafficRule{}).Evaluate(makeCtx(ng))
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		f := findings[0]

		if want := "NAT_LOW_TRAFFIC-nat-abc"; f.ID != want {
			t.Errorf("ID = %q; want %q", f.ID, want)
		}
		if f.RuleID != "NAT_LOW_TRAFFIC" {
			t.Errorf("RuleID = %q; want NAT_LOW_TRAFFIC", f.RuleID)
		}
		if f.ResourceID != "nat-abc" {
			t.Errorf("ResourceID = %q; want nat-abc", f.ResourceID)
		}
		if f.ResourceType != models.ResourceAWSNATGateway {
			t.Errorf("ResourceType = %q; want %q", f.ResourceType, models.ResourceAWSNATGateway)
		}
		if f.Severity != models.SeverityHigh {
			t.Errorf("Severity = %q; want HIGH", f.Severity)
		}
		if f.EstimatedMonthlySavings != 32.0 {
			t.Errorf("EstimatedMonthlySavings = %.2f; want 32.00", f.EstimatedMonthlySavings)
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
		if f.Explanation == "" {
			t.Error("Explanation must not be empty")
		}
		if f.Recommendation == "" {
			t.Error("Recommendation must not be empty")
		}
		if f.DetectedAt.IsZero() {
			t.Error("DetectedAt must not be zero")
		}
		if f.Metadata["bytes_processed_gb"] != 0.1 {
			t.Errorf("Metadata[bytes_processed_gb] = %v; want 0.1", f.Metadata["bytes_processed_gb"])
		}
	})

	t.Run("only low-traffic available gateways flagged from mixed set", func(t *testing.T) {
		ctx := makeCtx(
			models.AWSNATGateway{NATGatewayID: "nat-1", Region: region, State: "available", BytesProcessedGB: 0},   // flagged
			models.AWSNATGateway{NATGatewayID: "nat-2", Region: region, State: "available", BytesProcessedGB: 5.0}, // not flagged (high traffic)
			models.AWSNATGateway{NATGatewayID: "nat-3", Region: region, State: "deleting", BytesProcessedGB: 0},    // not flagged (wrong state)
			models.AWSNATGateway{NATGatewayID: "nat-4", Region: region, State: "available", BytesProcessedGB: 0.5}, // flagged
		)
		findings := (AWSNATLowTrafficRule{}).Evaluate(ctx)
		if len(findings) != 2 {
			t.Fatalf("want 2 findings, got %d", len(findings))
		}
		want := map[string]bool{"nat-1": true, "nat-4": true}
		for _, f := range findings {
			if !want[f.ResourceID] {
				t.Errorf("unexpected ResourceID %q in findings", f.ResourceID)
			}
		}
	})
}

func TestAWSNATLowTrafficRule_ThresholdOverride(t *testing.T) {
	// Gateway at 1.5 GB is above the default 1 GB threshold and would NOT be
	// flagged without a policy. A policy raising traffic_gb_threshold to 2 GB
	// makes 1.5 GB fall below the threshold, so the gateway MUST be flagged.
	cfg := &policy.PolicyConfig{
		Rules: map[string]policy.RuleConfig{
			"NAT_LOW_TRAFFIC": {
				Params: map[string]float64{"traffic_gb_threshold": 2.0},
			},
		},
	}
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "test",
		Policy:    cfg,
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			NATGateways: []models.AWSNATGateway{{
				NATGatewayID:     "nat-override",
				Region:           "us-east-1",
				State:            "available",
				BytesProcessedGB: 1.5,
			}},
		},
	}
	findings := (AWSNATLowTrafficRule{}).Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding (traffic_gb_threshold raised to 2 GB), got %d", len(findings))
	}
	if findings[0].ResourceID != "nat-override" {
		t.Errorf("ResourceID = %q; want nat-override", findings[0].ResourceID)
	}
}
