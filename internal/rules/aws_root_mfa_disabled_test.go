package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSRootAccountMFADisabledRule_ID(t *testing.T) {
	r := AWSRootAccountMFADisabledRule{}
	if r.ID() != "ROOT_ACCOUNT_MFA_DISABLED" {
		t.Errorf("expected ROOT_ACCOUNT_MFA_DISABLED, got %s", r.ID())
	}
}

func TestAWSRootAccountMFADisabledRule_NilRegionData(t *testing.T) {
	r := AWSRootAccountMFADisabledRule{}
	if findings := r.Evaluate(RuleContext{RegionData: nil}); len(findings) != 0 {
		t.Errorf("expected 0 findings for nil RegionData, got %d", len(findings))
	}
}

func TestAWSRootAccountMFADisabledRule_DataNotAvailable_NotFlagged(t *testing.T) {
	// DataAvailable == false means GetAccountSummary failed; skip to avoid false positive.
	r := AWSRootAccountMFADisabledRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Root: models.AWSRootAccountInfo{
					MFAEnabled:    false,
					DataAvailable: false, // collection failed
				},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings when DataAvailable == false, got %d", len(findings))
	}
}

func TestAWSRootAccountMFADisabledRule_MFAEnabled_NotFlagged(t *testing.T) {
	r := AWSRootAccountMFADisabledRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Root: models.AWSRootAccountInfo{
					MFAEnabled:    true,
					DataAvailable: true,
				},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings when MFA is enabled, got %d", len(findings))
	}
}

func TestAWSRootAccountMFADisabledRule_MFADisabled_Flagged(t *testing.T) {
	r := AWSRootAccountMFADisabledRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		Profile:   "prod",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Root: models.AWSRootAccountInfo{
					MFAEnabled:    false,
					DataAvailable: true,
				},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when root MFA disabled, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "ROOT_ACCOUNT_MFA_DISABLED" {
		t.Errorf("expected ROOT_ACCOUNT_MFA_DISABLED, got %s", f.RuleID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
	if f.Region != "global" {
		t.Errorf("expected global region, got %s", f.Region)
	}
}
