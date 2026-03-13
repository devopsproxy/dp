package rules

import (
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

const (
	sshPort = 22
	rdpPort = 3389
)

// AWSSecurityGroupOpenSSHRule flags EC2 security groups that allow unrestricted
// inbound access to remote admin ports (SSH port 22 or RDP port 3389) from
// the public internet (0.0.0.0/0 or ::/0). Each security group produces at
// most one finding regardless of how many open rules it contains.
type AWSSecurityGroupOpenSSHRule struct{}

func (r AWSSecurityGroupOpenSSHRule) ID() string { return "SG_OPEN_SSH" }
func (r AWSSecurityGroupOpenSSHRule) Name() string {
	return "Security Group With Open Remote Admin Access"
}

// Evaluate returns one HIGH finding per security group that exposes SSH (22)
// or RDP (3389) to the internet. Duplicate matches within the same group are
// deduplicated so one security group produces exactly one finding.
func (r AWSSecurityGroupOpenSSHRule) Evaluate(ctx RuleContext) []models.Finding {
	if ctx.RegionData == nil {
		return nil
	}
	seen := make(map[string]bool)
	var findings []models.Finding
	for _, sg := range ctx.RegionData.Security.SecurityGroupRules {
		if sg.Port != sshPort && sg.Port != rdpPort {
			continue
		}
		if sg.CIDR != "0.0.0.0/0" && sg.CIDR != "::/0" {
			continue
		}
		if seen[sg.GroupID] {
			continue // one finding per security group
		}
		seen[sg.GroupID] = true
		findings = append(findings, models.Finding{
			ID:             fmt.Sprintf("%s-%s", r.ID(), sg.GroupID),
			RuleID:         r.ID(),
			ResourceID:     sg.GroupID,
			ResourceType:   models.ResourceAWSSecurityGroup,
			Region:         sg.Region,
			AccountID:      ctx.AccountID,
			Profile:        ctx.Profile,
			Severity:       models.SeverityHigh,
			Explanation:    fmt.Sprintf("Security group %s allows unrestricted remote admin access (port %d) from %s.", sg.GroupID, sg.Port, sg.CIDR),
			Recommendation: "Restrict SSH/RDP access to specific trusted IP ranges or use AWS Systems Manager Session Manager instead.",
			DetectedAt:     time.Now().UTC(),
			Metadata: map[string]any{
				"open_cidr": sg.CIDR,
				"port":      sg.Port,
			},
		})
	}
	return findings
}
