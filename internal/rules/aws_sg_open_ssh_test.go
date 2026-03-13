package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestSGOpenSSHRule_ID(t *testing.T) {
	r := AWSSecurityGroupOpenSSHRule{}
	if r.ID() != "SG_OPEN_SSH" {
		t.Error("unexpected rule ID")
	}
}

func TestSGOpenSSHRule_NilRegionData(t *testing.T) {
	findings := AWSSecurityGroupOpenSSHRule{}.Evaluate(RuleContext{})
	if findings != nil {
		t.Errorf("want nil with nil RegionData, got %v", findings)
	}
}

// TestSGOpenSSHRule_NonAdminPorts_NoFindings verifies that ports 80 and 443
// open to the internet do not trigger findings; only SSH/RDP are flagged.
func TestSGOpenSSHRule_NonAdminPorts_NoFindings(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				SecurityGroupRules: []models.AWSSecurityGroupRule{
					{GroupID: "sg-web", Port: 443, CIDR: "0.0.0.0/0", Region: "us-east-1"},
					{GroupID: "sg-http", Port: 80, CIDR: "0.0.0.0/0", Region: "us-east-1"},
				},
			},
		},
	}
	findings := AWSSecurityGroupOpenSSHRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for non-admin ports (80, 443), got %d", len(findings))
	}
}

// TestSGOpenSSHRule_OpenRDP_IPv4 verifies that port 3389 open to 0.0.0.0/0
// is flagged with HIGH severity (same as SSH).
func TestSGOpenSSHRule_OpenRDP_IPv4(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		Profile:   "test",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				SecurityGroupRules: []models.AWSSecurityGroupRule{
					{GroupID: "sg-rdp", Port: 3389, CIDR: "0.0.0.0/0", Region: "us-west-2"},
				},
			},
		},
	}
	findings := AWSSecurityGroupOpenSSHRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding for open RDP, got %d", len(findings))
	}
	if findings[0].ResourceID != "sg-rdp" {
		t.Errorf("resource_id: got %q; want sg-rdp", findings[0].ResourceID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("severity: got %q; want HIGH", findings[0].Severity)
	}
	if findings[0].Region != "us-west-2" {
		t.Errorf("region: got %q; want us-west-2", findings[0].Region)
	}
}

func TestSGOpenSSHRule_RestrictedCIDR_NoFindings(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				SecurityGroupRules: []models.AWSSecurityGroupRule{
					{GroupID: "sg-1", Port: 22, CIDR: "10.0.0.0/8", Region: "us-east-1"},
					{GroupID: "sg-2", Port: 22, CIDR: "192.168.1.0/24", Region: "us-east-1"},
				},
			},
		},
	}
	findings := AWSSecurityGroupOpenSSHRule{}.Evaluate(ctx)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for restricted CIDR, got %d", len(findings))
	}
}

func TestSGOpenSSHRule_OpenSSH_IPv4(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		Profile:   "test",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				SecurityGroupRules: []models.AWSSecurityGroupRule{
					{GroupID: "sg-open", Port: 22, CIDR: "0.0.0.0/0", Region: "us-east-1"},
				},
			},
		},
	}
	findings := AWSSecurityGroupOpenSSHRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("severity: got %q; want HIGH", findings[0].Severity)
	}
	if findings[0].Region != "us-east-1" {
		t.Errorf("region: got %q; want us-east-1", findings[0].Region)
	}
	if findings[0].ResourceType != models.ResourceAWSSecurityGroup {
		t.Errorf("resource_type: got %q; want SECURITY_GROUP", findings[0].ResourceType)
	}
}

func TestSGOpenSSHRule_OpenSSH_IPv6(t *testing.T) {
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				SecurityGroupRules: []models.AWSSecurityGroupRule{
					{GroupID: "sg-ipv6", Port: 22, CIDR: "::/0", Region: "eu-west-1"},
				},
			},
		},
	}
	findings := AWSSecurityGroupOpenSSHRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding for IPv6 open SSH, got %d", len(findings))
	}
	if findings[0].ResourceID != "sg-ipv6" {
		t.Errorf("resource_id: got %q; want sg-ipv6", findings[0].ResourceID)
	}
}

func TestSGOpenSSHRule_Deduplication(t *testing.T) {
	// Same SG has both SSH (22) and RDP (3389) open → only one finding.
	ctx := RuleContext{
		AccountID: "123",
		RegionData: &models.AWSRegionData{
			Security: models.AWSSecurityData{
				SecurityGroupRules: []models.AWSSecurityGroupRule{
					{GroupID: "sg-1", Port: 22, CIDR: "0.0.0.0/0", Region: "us-east-1"},
					{GroupID: "sg-1", Port: 3389, CIDR: "0.0.0.0/0", Region: "us-east-1"},
				},
			},
		},
	}
	findings := AWSSecurityGroupOpenSSHRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Errorf("want 1 finding (deduplicated by group ID), got %d", len(findings))
	}
}
