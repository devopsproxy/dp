package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSRDSUnencryptedRule_ID(t *testing.T) {
	r := AWSRDSUnencryptedRule{}
	if r.ID() != "RDS_UNENCRYPTED" {
		t.Error("unexpected rule ID")
	}
}

func TestAWSRDSUnencryptedRule_NilRegionData(t *testing.T) {
	findings := AWSRDSUnencryptedRule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

func TestAWSRDSUnencryptedRule_EncryptedInstance_NoFinding(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			RDSInstances: []models.AWSRDSInstance{
				{DBInstanceID: "db-enc", Engine: "mysql", Status: "available", StorageEncrypted: true},
			},
		},
	}
	findings := AWSRDSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for encrypted RDS, got %d", len(findings))
	}
}

func TestAWSRDSUnencryptedRule_UnencryptedInstance_CriticalSeverity(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "prod",
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			RDSInstances: []models.AWSRDSInstance{
				{DBInstanceID: "db-prod", Engine: "postgres", DBInstanceClass: "db.t3.medium", Status: "available", StorageEncrypted: false},
			},
		},
	}
	findings := AWSRDSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ResourceID != "db-prod" {
		t.Errorf("resource_id: got %q; want db-prod", f.ResourceID)
	}
	if f.Severity != models.SeverityCritical {
		t.Errorf("severity: got %q; want CRITICAL", f.Severity)
	}
	if f.ResourceType != models.ResourceAWSRDS {
		t.Errorf("resource_type: got %q; want RDS_INSTANCE", f.ResourceType)
	}
	if f.Region != "us-east-1" {
		t.Errorf("region: got %q; want us-east-1", f.Region)
	}
}

func TestAWSRDSUnencryptedRule_NoInstances(t *testing.T) {
	ctx := RuleContext{
		AccountID:  "123",
		RegionData: &models.AWSRegionData{Region: "us-west-2"},
	}
	findings := AWSRDSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings with no instances, got %d", len(findings))
	}
}

func TestAWSRDSUnencryptedRule_MultipleUnencrypted(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Region: "ap-southeast-1",
			RDSInstances: []models.AWSRDSInstance{
				{DBInstanceID: "db-a", StorageEncrypted: false},
				{DBInstanceID: "db-b", StorageEncrypted: true},
				{DBInstanceID: "db-c", StorageEncrypted: false},
			},
		},
	}
	findings := AWSRDSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("want 2 findings, got %d", len(findings))
	}
}
