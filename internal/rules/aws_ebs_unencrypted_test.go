package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSEBSUnencryptedRule_ID(t *testing.T) {
	r := AWSEBSUnencryptedRule{}
	if r.ID() != "EBS_UNENCRYPTED" {
		t.Error("unexpected rule ID")
	}
}

func TestAWSEBSUnencryptedRule_NilRegionData(t *testing.T) {
	findings := AWSEBSUnencryptedRule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

func TestAWSEBSUnencryptedRule_EncryptedVolume_NoFinding(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			EBSVolumes: []models.AWSEBSVolume{
				{VolumeID: "vol-enc", VolumeType: "gp3", SizeGB: 100, Encrypted: true},
			},
		},
	}
	findings := AWSEBSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for encrypted volume, got %d", len(findings))
	}
}

func TestAWSEBSUnencryptedRule_UnencryptedVolume_HighSeverity(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "test",
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			EBSVolumes: []models.AWSEBSVolume{
				{VolumeID: "vol-bare", VolumeType: "gp3", SizeGB: 200, Encrypted: false, State: "in-use"},
			},
		},
	}
	findings := AWSEBSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ResourceID != "vol-bare" {
		t.Errorf("resource_id: got %q; want vol-bare", f.ResourceID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity: got %q; want HIGH", f.Severity)
	}
	if f.ResourceType != models.ResourceAWSEBS {
		t.Errorf("resource_type: got %q; want EBS_VOLUME", f.ResourceType)
	}
	if f.Region != "us-east-1" {
		t.Errorf("region: got %q; want us-east-1", f.Region)
	}
}

func TestAWSEBSUnencryptedRule_NoVolumes(t *testing.T) {
	ctx := RuleContext{
		AccountID:  "123",
		RegionData: &models.AWSRegionData{Region: "us-east-1"},
	}
	findings := AWSEBSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings with no volumes, got %d", len(findings))
	}
}

func TestAWSEBSUnencryptedRule_MixedVolumes(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Region: "eu-west-1",
			EBSVolumes: []models.AWSEBSVolume{
				{VolumeID: "vol-enc", Encrypted: true},
				{VolumeID: "vol-a", Encrypted: false},
				{VolumeID: "vol-b", Encrypted: false},
			},
		},
	}
	findings := AWSEBSUnencryptedRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("want 2 findings for 2 unencrypted volumes, got %d", len(findings))
	}
}
