package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSCloudTrailNotMultiRegionRule_ID(t *testing.T) {
	r := AWSCloudTrailNotMultiRegionRule{}
	if r.ID() != "CLOUDTRAIL_NOT_MULTI_REGION" {
		t.Errorf("expected CLOUDTRAIL_NOT_MULTI_REGION, got %s", r.ID())
	}
}

func TestAWSCloudTrailNotMultiRegionRule_NilRegionData(t *testing.T) {
	r := AWSCloudTrailNotMultiRegionRule{}
	if findings := r.Evaluate(RuleContext{RegionData: nil}); len(findings) != 0 {
		t.Errorf("expected 0 findings for nil RegionData, got %d", len(findings))
	}
}

func TestAWSCloudTrailNotMultiRegionRule_HasMultiRegion_NotFlagged(t *testing.T) {
	r := AWSCloudTrailNotMultiRegionRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				CloudTrail: models.AWSCloudTrailStatus{HasMultiRegionTrail: true},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings when multi-region trail exists, got %d", len(findings))
	}
}

func TestAWSCloudTrailNotMultiRegionRule_NoMultiRegion_Flagged(t *testing.T) {
	r := AWSCloudTrailNotMultiRegionRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		Profile:   "prod",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				CloudTrail: models.AWSCloudTrailStatus{HasMultiRegionTrail: false},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when no multi-region trail, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "CLOUDTRAIL_NOT_MULTI_REGION" {
		t.Errorf("expected CLOUDTRAIL_NOT_MULTI_REGION, got %s", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Region != "global" {
		t.Errorf("expected global region, got %s", f.Region)
	}
}

func TestAWSCloudTrailNotMultiRegionRule_NoTrailsAtAll_Flagged(t *testing.T) {
	// Zero value for AWSCloudTrailStatus means HasMultiRegionTrail == false.
	r := AWSCloudTrailNotMultiRegionRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 1 {
		t.Errorf("expected 1 finding when no trails configured, got %d", len(findings))
	}
}
