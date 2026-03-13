package sensitivity

import (
	"testing"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// TestSensitivity_S3BucketDetection verifies that S3 bucket names containing
// high-risk keywords are classified as HIGH and others as MEDIUM.
func TestSensitivity_S3BucketDetection(t *testing.T) {
	cases := []struct {
		name     string
		want     models.SensitivityLevel
	}{
		// HIGH: contains a keyword.
		{"prod-assets", models.SensitivityHigh},
		{"customer-uploads", models.SensitivityHigh},
		{"pii-data", models.SensitivityHigh},
		{"payments-archive", models.SensitivityHigh},
		{"backup-2024", models.SensitivityHigh},
		{"raw-data-lake", models.SensitivityHigh},
		// HIGH: keyword embedded in a longer name.
		{"myapp-production-logs", models.SensitivityHigh},
		{"acme-customer-records", models.SensitivityHigh},
		// MEDIUM: no keyword.
		{"static-assets", models.SensitivityMedium},
		{"build-artifacts", models.SensitivityMedium},
		{"infra-logs", models.SensitivityMedium},
		// MEDIUM: empty name.
		{"", models.SensitivityMedium},
	}

	for _, tc := range cases {
		got := ClassifyResource(models.CloudResourceTypeS3Bucket, tc.name)
		if got != tc.want {
			t.Errorf("S3Bucket %q: want %s, got %s", tc.name, tc.want, got)
		}
	}
}

// TestSensitivity_SecretsAlwaysSensitive verifies that SecretsManager secrets
// are always classified as HIGH regardless of name.
func TestSensitivity_SecretsAlwaysSensitive(t *testing.T) {
	names := []string{
		"prod-db-password",
		"random-secret",
		"test",
		"",
		"innocuous-looking-name",
	}
	for _, name := range names {
		got := ClassifyResource(models.CloudResourceTypeSecretsManagerSecret, name)
		if got != models.SensitivityHigh {
			t.Errorf("SecretsManagerSecret %q: want HIGH, got %s", name, got)
		}
	}
}

// TestSensitivity_SSMParameter verifies SSM parameter classification.
func TestSensitivity_SSMParameter(t *testing.T) {
	cases := []struct {
		name string
		want models.SensitivityLevel
	}{
		// HIGH: keyword in name.
		{"/app/db/password", models.SensitivityHigh},
		{"/service/api-token", models.SensitivityHigh},
		{"/infra/secret-key", models.SensitivityHigh},
		{"/auth/private-key", models.SensitivityHigh},
		// HIGH: keyword is part of a longer word (case-insensitive).
		{"/APP/APIPASSWORD", models.SensitivityHigh},
		// MEDIUM: no keyword.
		{"/app/feature-flag", models.SensitivityMedium},
		{"/service/log-level", models.SensitivityMedium},
		{"", models.SensitivityMedium},
	}

	for _, tc := range cases {
		got := ClassifyResource(models.CloudResourceTypeSSMParameter, tc.name)
		if got != tc.want {
			t.Errorf("SSMParameter %q: want %s, got %s", tc.name, tc.want, got)
		}
	}
}

// TestSensitivity_DefaultMedium verifies that unrecognised resource types
// default to MEDIUM.
func TestSensitivity_DefaultMedium(t *testing.T) {
	got := ClassifyResource(models.CloudResourceTypeDynamoDBTable, "orders")
	if got != models.SensitivityMedium {
		t.Errorf("DynamoDBTable: want MEDIUM, got %s", got)
	}
	got = ClassifyResource(models.CloudResourceTypeKMSKey, "alias/my-key")
	if got != models.SensitivityMedium {
		t.Errorf("KMSKey: want MEDIUM, got %s", got)
	}
}
