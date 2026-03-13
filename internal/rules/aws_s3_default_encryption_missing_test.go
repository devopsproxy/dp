package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSS3DefaultEncryptionMissingRule_ID(t *testing.T) {
	r := AWSS3DefaultEncryptionMissingRule{}
	if r.ID() != "S3_DEFAULT_ENCRYPTION_MISSING" {
		t.Error("unexpected rule ID")
	}
}

func TestAWSS3DefaultEncryptionMissingRule_NilRegionData(t *testing.T) {
	findings := AWSS3DefaultEncryptionMissingRule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

// TestAWSS3DefaultEncryptionMissingRule_EncryptionEnabled_NoFinding verifies
// that a bucket with SSE configured is not flagged.
func TestAWSS3DefaultEncryptionMissingRule_EncryptionEnabled_NoFinding(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Buckets: []models.AWSS3Bucket{
					{Name: "encrypted-bucket", DefaultEncryptionEnabled: true},
				},
			},
		},
	}
	findings := AWSS3DefaultEncryptionMissingRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for encrypted bucket, got %d", len(findings))
	}
}

// TestAWSS3DefaultEncryptionMissingRule_NoEncryption_HighSeverity verifies that
// a bucket without SSE is flagged with HIGH severity at region "global".
func TestAWSS3DefaultEncryptionMissingRule_NoEncryption_HighSeverity(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "test",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Buckets: []models.AWSS3Bucket{
					{Name: "plain-bucket", DefaultEncryptionEnabled: false},
				},
			},
		},
	}
	findings := AWSS3DefaultEncryptionMissingRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ResourceID != "plain-bucket" {
		t.Errorf("resource_id: got %q; want plain-bucket", f.ResourceID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("severity: got %q; want HIGH", f.Severity)
	}
	if f.ResourceType != models.ResourceAWSS3Bucket {
		t.Errorf("resource_type: got %q; want S3_BUCKET", f.ResourceType)
	}
	if f.Region != "global" {
		t.Errorf("region: got %q; want global", f.Region)
	}
}

func TestAWSS3DefaultEncryptionMissingRule_NoBuckets(t *testing.T) {
	ctx := RuleContext{
		AccountID:  "123",
		RegionData: &models.AWSRegionData{Security: models.AWSSecurityData{}},
	}
	findings := AWSS3DefaultEncryptionMissingRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings with no buckets, got %d", len(findings))
	}
}

func TestAWSS3DefaultEncryptionMissingRule_MultipleBuckets(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Buckets: []models.AWSS3Bucket{
					{Name: "bucket-a", DefaultEncryptionEnabled: false},
					{Name: "bucket-b", DefaultEncryptionEnabled: true},
					{Name: "bucket-c", DefaultEncryptionEnabled: false},
				},
			},
		},
	}
	findings := AWSS3DefaultEncryptionMissingRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("want 2 findings for 2 unencrypted buckets, got %d", len(findings))
	}
}
