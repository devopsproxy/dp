package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSConfigDisabledRule_ID(t *testing.T) {
	r := AWSConfigDisabledRule{}
	if r.ID() != "AWS_CONFIG_DISABLED" {
		t.Errorf("expected AWS_CONFIG_DISABLED, got %s", r.ID())
	}
}

func TestAWSConfigDisabledRule_NilRegionData(t *testing.T) {
	r := AWSConfigDisabledRule{}
	if findings := r.Evaluate(RuleContext{RegionData: nil}); len(findings) != 0 {
		t.Errorf("expected 0 findings for nil RegionData, got %d", len(findings))
	}
}

func TestAWSConfigDisabledRule_NoStatuses_NoFindings(t *testing.T) {
	r := AWSConfigDisabledRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{Config: nil},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings when no Config statuses, got %d", len(findings))
	}
}

func TestAWSConfigDisabledRule_AllEnabled_NoFindings(t *testing.T) {
	r := AWSConfigDisabledRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Config: []models.AWSConfigStatus{
					{Region: "us-east-1", Enabled: true},
					{Region: "eu-west-1", Enabled: true},
				},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings when all regions enabled, got %d", len(findings))
	}
}

func TestAWSConfigDisabledRule_DisabledRegion_Flagged(t *testing.T) {
	r := AWSConfigDisabledRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		Profile:   "prod",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Config: []models.AWSConfigStatus{
					{Region: "us-east-1", Enabled: true},
					{Region: "us-west-2", Enabled: false},
				},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for disabled region, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "AWS_CONFIG_DISABLED" {
		t.Errorf("expected AWS_CONFIG_DISABLED, got %s", f.RuleID)
	}
	if f.Region != "us-west-2" {
		t.Errorf("expected us-west-2, got %s", f.Region)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}

func TestAWSConfigDisabledRule_MultipleDisabled_MultipleFlagged(t *testing.T) {
	r := AWSConfigDisabledRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Config: []models.AWSConfigStatus{
					{Region: "us-east-1", Enabled: false},
					{Region: "eu-central-1", Enabled: false},
					{Region: "ap-south-1", Enabled: true},
				},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (2 disabled regions), got %d", len(findings))
	}
}
