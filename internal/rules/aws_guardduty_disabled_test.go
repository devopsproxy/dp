package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSGuardDutyDisabledRule_ID(t *testing.T) {
	r := AWSGuardDutyDisabledRule{}
	if r.ID() != "GUARDDUTY_DISABLED" {
		t.Errorf("expected GUARDDUTY_DISABLED, got %s", r.ID())
	}
}

func TestAWSGuardDutyDisabledRule_NilRegionData(t *testing.T) {
	r := AWSGuardDutyDisabledRule{}
	if findings := r.Evaluate(RuleContext{RegionData: nil}); len(findings) != 0 {
		t.Errorf("expected 0 findings for nil RegionData, got %d", len(findings))
	}
}

func TestAWSGuardDutyDisabledRule_NoStatuses_NoFindings(t *testing.T) {
	r := AWSGuardDutyDisabledRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{GuardDuty: nil},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings when no GuardDuty statuses, got %d", len(findings))
	}
}

func TestAWSGuardDutyDisabledRule_AllEnabled_NoFindings(t *testing.T) {
	r := AWSGuardDutyDisabledRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				GuardDuty: []models.AWSGuardDutyStatus{
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

func TestAWSGuardDutyDisabledRule_DisabledRegion_Flagged(t *testing.T) {
	r := AWSGuardDutyDisabledRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		Profile:   "prod",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				GuardDuty: []models.AWSGuardDutyStatus{
					{Region: "us-east-1", Enabled: true},
					{Region: "ap-southeast-1", Enabled: false},
				},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for disabled region, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "GUARDDUTY_DISABLED" {
		t.Errorf("expected GUARDDUTY_DISABLED, got %s", f.RuleID)
	}
	if f.Region != "ap-southeast-1" {
		t.Errorf("expected ap-southeast-1, got %s", f.Region)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}

func TestAWSGuardDutyDisabledRule_MultipleDisabled_MultipleFlagged(t *testing.T) {
	r := AWSGuardDutyDisabledRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				GuardDuty: []models.AWSGuardDutyStatus{
					{Region: "us-east-1", Enabled: false},
					{Region: "eu-west-1", Enabled: false},
					{Region: "ap-northeast-1", Enabled: true},
				},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (2 disabled regions), got %d", len(findings))
	}
}
