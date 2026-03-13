// Package aws_security provides the AWS security audit rule pack.
// It groups all AWS security rules into a single New() function that the CLI
// wires into a DefaultRuleRegistry before invoking the security engine.
//
// Convention: every rule pack lives in internal/rulepacks/<domain>/pack.go
// and exposes a single New() func returning []rules.Rule.
// Future AWS security rules should be added to the slice returned by New().
package aws_security

import "github.com/devopsproxy/dp/internal/rules"

// New returns the default AWS security audit rule pack.
func New() []rules.Rule {
	return []rules.Rule{
		rules.AWSRootAccessKeyExistsRule{},      // CRITICAL: root access keys present
		rules.AWSRootAccountMFADisabledRule{},   // CRITICAL: root account MFA not enabled
		rules.AWSCloudTrailNotMultiRegionRule{}, // HIGH:     no multi-region CloudTrail trail
		rules.AWSS3PublicBucketRule{},           // HIGH:     S3 bucket lacks public access block
		rules.AWSSecurityGroupOpenSSHRule{},     // HIGH:     security group exposes SSH to internet
		rules.AWSGuardDutyDisabledRule{},        // HIGH:     GuardDuty not enabled in region
		rules.AWSConfigDisabledRule{},           // HIGH:     AWS Config not enabled in region
		rules.AWSIAMUserWithoutMFARule{},        // MEDIUM:   IAM user has no MFA device
	}
}
