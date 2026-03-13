// Package aws_dataprotection provides the AWS data-protection rule pack.
// It groups encryption-at-rest checks for EBS volumes, RDS instances,
// and S3 buckets into a single registration call.
package aws_dataprotection

import "github.com/devopsproxy/dp/internal/rules"

// New returns the complete set of AWS data-protection rules ordered by severity:
// CRITICAL first (RDS), then HIGH (EBS, S3).
func New() []rules.Rule {
	return []rules.Rule{
		rules.AWSRDSUnencryptedRule{},             // CRITICAL
		rules.AWSEBSUnencryptedRule{},             // HIGH
		rules.AWSS3DefaultEncryptionMissingRule{}, // HIGH
	}
}
