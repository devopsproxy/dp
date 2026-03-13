package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestRootAccessKeyRule_ID(t *testing.T) {
	r := AWSRootAccessKeyExistsRule{}
	if r.ID() != "ROOT_ACCESS_KEY" {
		t.Error("unexpected rule ID")
	}
}

func TestRootAccessKeyRule_NilRegionData(t *testing.T) {
	findings := AWSRootAccessKeyExistsRule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

func TestRootAccessKeyRule_NoKeys(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123456789012",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Root: models.AWSRootAccountInfo{HasAccessKeys: false},
			},
		},
	}
	findings := AWSRootAccessKeyExistsRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings when no root access keys, got %d", len(findings))
	}
}

func TestRootAccessKeyRule_HasKeys(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "prod",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Root: models.AWSRootAccountInfo{HasAccessKeys: true},
			},
		},
	}
	findings := AWSRootAccessKeyExistsRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != models.SeverityCritical {
		t.Errorf("severity: got %q; want CRITICAL", f.Severity)
	}
	if f.ResourceID != "111122223333" {
		t.Errorf("resource_id: got %q; want account ID", f.ResourceID)
	}
	if f.ResourceType != models.ResourceAWSRootAccount {
		t.Errorf("resource_type: got %q; want ROOT_ACCOUNT", f.ResourceType)
	}
	if f.Region != "global" {
		t.Errorf("region: got %q; want global", f.Region)
	}
	if f.AccountID != "111122223333" {
		t.Errorf("account_id: got %q; want 111122223333", f.AccountID)
	}
}
