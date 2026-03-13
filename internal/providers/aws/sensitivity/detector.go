// Package sensitivity classifies AWS cloud resources by data sensitivity.
// Rules are name-pattern based and require no AWS API calls — classification
// runs purely on the resource type and name as recorded in the asset graph.
package sensitivity

import (
	"strings"

	"github.com/devopsproxy/dp/internal/models"
)

// s3HighKeywords are substrings in an S3 bucket name that indicate the bucket
// is likely to hold sensitive or regulated data.
var s3HighKeywords = []string{
	"prod",
	"data",
	"customer",
	"backup",
	"payment",
	"pii",
}

// ssmHighKeywords are substrings in an SSM parameter name that indicate the
// parameter holds a secret or credential value.
var ssmHighKeywords = []string{
	"password",
	"token",
	"secret",
	"key",
}

// ClassifyResource returns the sensitivity level for a cloud resource.
//
// Classification rules:
//
//   - S3Bucket: HIGH when the bucket name contains any of the s3HighKeywords;
//     MEDIUM otherwise.
//   - SecretsManagerSecret: always HIGH.
//   - SSMParameter: HIGH when the parameter name contains any of the
//     ssmHighKeywords; MEDIUM otherwise.
//   - All other resource types: MEDIUM (conservative default).
func ClassifyResource(resourceType models.CloudResourceType, resourceName string) models.SensitivityLevel {
	nameLower := strings.ToLower(resourceName)

	switch resourceType {
	case models.CloudResourceTypeS3Bucket:
		for _, kw := range s3HighKeywords {
			if strings.Contains(nameLower, kw) {
				return models.SensitivityHigh
			}
		}
		return models.SensitivityMedium

	case models.CloudResourceTypeSecretsManagerSecret:
		// Secrets Manager secrets are always considered highly sensitive.
		return models.SensitivityHigh

	case models.CloudResourceTypeSSMParameter:
		for _, kw := range ssmHighKeywords {
			if strings.Contains(nameLower, kw) {
				return models.SensitivityHigh
			}
		}
		return models.SensitivityMedium

	default:
		return models.SensitivityMedium
	}
}
