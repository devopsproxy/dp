package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSEBSGP2LegacyRule_IDAndName(t *testing.T) {
	r := AWSEBSGP2LegacyRule{}
	if r.ID() != "EBS_GP2_LEGACY" {
		t.Errorf("ID = %q; want EBS_GP2_LEGACY", r.ID())
	}
	if r.Name() == "" {
		t.Error("Name must not be empty")
	}
}

func TestAWSEBSGP2LegacyRule_NilRegionData(t *testing.T) {
	if got := (AWSEBSGP2LegacyRule{}).Evaluate(RuleContext{}); got != nil {
		t.Errorf("expected nil for nil RegionData, got len=%d", len(got))
	}
}

func TestAWSEBSGP2LegacyRule_Evaluate(t *testing.T) {
	const (
		account = "111122223333"
		profile = "test"
		region  = "us-east-1"
	)

	makeCtx := func(vols ...models.AWSEBSVolume) RuleContext {
		return RuleContext{
			AccountID: account,
			Profile:   profile,
			RegionData: &models.AWSRegionData{
				Region:     region,
				EBSVolumes: vols,
			},
		}
	}

	t.Run("non-gp2 volume types are not flagged", func(t *testing.T) {
		for _, vtype := range []string{"gp3", "io1", "io2", "sc1", "st1", "standard"} {
			vtype := vtype
			t.Run(vtype, func(t *testing.T) {
				ctx := makeCtx(models.AWSEBSVolume{
					VolumeID: "vol-1", Region: region, VolumeType: vtype,
					SizeGB: 100, State: "in-use", Attached: true,
				})
				if got := (AWSEBSGP2LegacyRule{}).Evaluate(ctx); len(got) != 0 {
					t.Errorf("type=%q: expected 0 findings, got %d", vtype, len(got))
				}
			})
		}
	})

	t.Run("gp2 volume is flagged with correct fields", func(t *testing.T) {
		vol := models.AWSEBSVolume{
			VolumeID: "vol-gp2", Region: region, VolumeType: "gp2",
			SizeGB: 100, State: "in-use", Attached: true,
		}
		findings := (AWSEBSGP2LegacyRule{}).Evaluate(makeCtx(vol))
		if len(findings) != 1 {
			t.Fatalf("want 1 finding, got %d", len(findings))
		}
		f := findings[0]

		if want := "EBS_GP2_LEGACY-vol-gp2"; f.ID != want {
			t.Errorf("ID = %q; want %q", f.ID, want)
		}
		if f.RuleID != "EBS_GP2_LEGACY" {
			t.Errorf("RuleID = %q; want EBS_GP2_LEGACY", f.RuleID)
		}
		if f.ResourceID != "vol-gp2" {
			t.Errorf("ResourceID = %q; want vol-gp2", f.ResourceID)
		}
		if f.ResourceType != models.ResourceAWSEBS {
			t.Errorf("ResourceType = %q; want %q", f.ResourceType, models.ResourceAWSEBS)
		}
		if f.Severity != models.SeverityLow {
			t.Errorf("Severity = %q; want LOW", f.Severity)
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
		if f.EstimatedMonthlySavings != 2.00 { // 100 * 0.02
			t.Errorf("EstimatedMonthlySavings = %.4f; want 2.00", f.EstimatedMonthlySavings)
		}
		if f.Metadata["volume_type"] != "gp2" {
			t.Errorf("Metadata[volume_type] = %v; want gp2", f.Metadata["volume_type"])
		}
		if f.Metadata["size_gb"] != int32(100) {
			t.Errorf("Metadata[size_gb] = %v (%T); want int32(100)", f.Metadata["size_gb"], f.Metadata["size_gb"])
		}
		if f.Explanation == "" {
			t.Error("Explanation must not be empty")
		}
		if f.Recommendation == "" {
			t.Error("Recommendation must not be empty")
		}
	})

	t.Run("gp2 volume is flagged regardless of attached state", func(t *testing.T) {
		for _, attached := range []bool{true, false} {
			attached := attached
			t.Run("", func(t *testing.T) {
				ctx := makeCtx(models.AWSEBSVolume{
					VolumeID: "vol-1", Region: region, VolumeType: "gp2",
					SizeGB: 50, State: "available", Attached: attached,
				})
				if got := (AWSEBSGP2LegacyRule{}).Evaluate(ctx); len(got) != 1 {
					t.Errorf("attached=%v: want 1 finding, got %d", attached, len(got))
				}
			})
		}
	})

	t.Run("savings are proportional to volume size", func(t *testing.T) {
		cases := []struct {
			sizeGB  int32
			wantUSD float64
		}{
			{50, 1.00},
			{200, 4.00},
			{1000, 20.00},
		}
		for _, tc := range cases {
			ctx := makeCtx(models.AWSEBSVolume{
				VolumeID: "vol-x", Region: region, VolumeType: "gp2",
				SizeGB: tc.sizeGB, State: "in-use", Attached: true,
			})
			findings := (AWSEBSGP2LegacyRule{}).Evaluate(ctx)
			if len(findings) != 1 {
				t.Fatalf("sizeGB=%d: want 1 finding, got %d", tc.sizeGB, len(findings))
			}
			if findings[0].EstimatedMonthlySavings != tc.wantUSD {
				t.Errorf("sizeGB=%d: savings = %.2f; want %.2f",
					tc.sizeGB, findings[0].EstimatedMonthlySavings, tc.wantUSD)
			}
		}
	})

	t.Run("only gp2 volumes flagged from mixed set", func(t *testing.T) {
		ctx := makeCtx(
			models.AWSEBSVolume{VolumeID: "vol-1", Region: region, VolumeType: "gp2", SizeGB: 10, State: "in-use", Attached: true}, // flagged
			models.AWSEBSVolume{VolumeID: "vol-2", Region: region, VolumeType: "gp3", SizeGB: 10, State: "in-use", Attached: true}, // not flagged
			models.AWSEBSVolume{VolumeID: "vol-3", Region: region, VolumeType: "gp2", SizeGB: 10, State: "in-use", Attached: true}, // flagged
			models.AWSEBSVolume{VolumeID: "vol-4", Region: region, VolumeType: "io2", SizeGB: 10, State: "in-use", Attached: true}, // not flagged
		)
		findings := (AWSEBSGP2LegacyRule{}).Evaluate(ctx)
		if len(findings) != 2 {
			t.Fatalf("want 2 findings, got %d", len(findings))
		}
		want := map[string]bool{"vol-1": true, "vol-3": true}
		for _, f := range findings {
			if !want[f.ResourceID] {
				t.Errorf("unexpected ResourceID %q in findings", f.ResourceID)
			}
		}
	})
}
