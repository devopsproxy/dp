package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSS3PublicBucketRule_ID(t *testing.T) {
	r := AWSS3PublicBucketRule{}
	if r.ID() != "S3_PUBLIC_BUCKET" {
		t.Error("unexpected rule ID")
	}
}

func TestAWSS3PublicBucketRule_NilRegionData(t *testing.T) {
	findings := AWSS3PublicBucketRule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

func TestAWSS3PublicBucketRule_NoPublicBuckets(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "test",
		RegionData: &models.AWSRegionData{
			Region: "global",
			Security: models.AWSSecurityData{
				Buckets: []models.AWSS3Bucket{
					{Name: "my-private-bucket", Public: false},
					{Name: "another-private", Public: false},
				},
			},
		},
	}
	findings := AWSS3PublicBucketRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for private buckets, got %d", len(findings))
	}
}

func TestAWSS3PublicBucketRule_PublicBucket(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		Profile:   "test",
		RegionData: &models.AWSRegionData{
			Region: "global",
			Security: models.AWSSecurityData{
				Buckets: []models.AWSS3Bucket{
					{Name: "public-bucket", Public: true},
					{Name: "private-bucket", Public: false},
				},
			},
		},
	}
	findings := AWSS3PublicBucketRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].ResourceID != "public-bucket" {
		t.Errorf("resource_id: got %q; want public-bucket", findings[0].ResourceID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("severity: got %q; want HIGH", findings[0].Severity)
	}
	if findings[0].ResourceType != models.ResourceAWSS3Bucket {
		t.Errorf("resource_type: got %q; want S3_BUCKET", findings[0].ResourceType)
	}
}

// TestAWSS3PublicBucketRule_NoPolicyBucket verifies that a bucket without a
// bucket policy is not flagged. The collector sets Public == false when
// GetBucketPolicyStatus returns NoSuchBucketPolicy; the rule must honour that.
func TestAWSS3PublicBucketRule_NoPolicyBucket(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Buckets: []models.AWSS3Bucket{
					// No policy → collector sets Public: false → must not be flagged.
					{Name: "no-policy-bucket", Public: false},
				},
			},
		},
	}
	findings := AWSS3PublicBucketRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for bucket without policy, got %d", len(findings))
	}
}

func TestAWSS3PublicBucketRule_MultiplePublicBuckets(t *testing.T) {
	ctx := RuleContext{
		AccountID: "111122223333",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				Buckets: []models.AWSS3Bucket{
					{Name: "bucket-a", Public: true},
					{Name: "bucket-b", Public: true},
					{Name: "bucket-c", Public: false},
				},
			},
		},
	}
	findings := AWSS3PublicBucketRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("want 2 findings, got %d", len(findings))
	}
}
