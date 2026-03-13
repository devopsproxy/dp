// Package aws_cost provides the rule pack for AWS cost audit.
// New returns every AWS cost rule in evaluation order; callers register them
// into a RuleRegistry via a loop rather than listing each rule explicitly.
//
// Adding a new AWS cost rule:
//  1. Implement the rule in internal/rules/ following the Rule interface.
//  2. Append it to the slice returned by New().
//  3. No other files need to change.
package aws_cost

import "github.com/devopsproxy/dp/internal/rules"

// New returns all AWS cost rules in the order they should be evaluated.
func New() []rules.Rule {
	return []rules.Rule{
		rules.AWSEBSUnattachedRule{},
		rules.AWSEBSGP2LegacyRule{},
		rules.AWSEC2LowCPURule{},
		rules.AWSNATLowTrafficRule{},
		rules.AWSSavingsPlanUnderutilizedRule{},
		rules.AWSRDSLowCPURule{},
		rules.AWSALBIdleRule{},
		rules.AWSEC2NoSavingsPlanRule{},
	}
}
