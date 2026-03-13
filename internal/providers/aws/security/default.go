package awssecurity

import (
	"context"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/providers/aws/common"
)

// DefaultSecurityCollector is the production SecurityCollector.
// It collects S3, IAM, root account, and CloudTrail data from us-east-1
// (global AWS services) and aggregates EC2 security group rules, GuardDuty
// status, and AWS Config status across all audited regions.
type DefaultSecurityCollector struct {
	factory secClientFactory
}

// NewDefaultSecurityCollector returns a DefaultSecurityCollector wired to
// production AWS SDK clients.
func NewDefaultSecurityCollector() *DefaultSecurityCollector {
	return &DefaultSecurityCollector{factory: newDefaultSecClients}
}

// NewDefaultSecurityCollectorWithFactory returns a DefaultSecurityCollector
// that uses the supplied factory, allowing tests to inject fake clients.
func NewDefaultSecurityCollectorWithFactory(f secClientFactory) *DefaultSecurityCollector {
	return &DefaultSecurityCollector{factory: f}
}

// CollectAll gathers account-level security data for the given profile and
// regions. Global resources (S3, IAM, root, CloudTrail) are collected once
// using a us-east-1 config. Security group rules, GuardDuty detector status,
// and AWS Config recorder status are collected per region and aggregated.
// All collection failures are silently skipped (non-fatal).
func (c *DefaultSecurityCollector) CollectAll(
	ctx context.Context,
	profile *common.ProfileConfig,
	provider common.AWSClientProvider,
	regions []string,
) (*models.AWSSecurityData, error) {
	// Global clients: us-east-1 is the canonical region for S3, IAM, and CloudTrail.
	globalCfg := provider.ConfigForRegion(profile, "us-east-1")
	globalClients := c.factory(globalCfg)

	buckets, _ := collectS3Buckets(ctx, globalClients.S3)
	iamUsers, _ := collectIAMUsers(ctx, globalClients.IAM)
	root, _ := collectRootAccountInfo(ctx, globalClients.IAM)
	cloudTrail, _ := collectCloudTrailStatus(ctx, globalClients.CloudTrail)

	// Regional: collect security groups, GuardDuty, and Config per region.
	var allSGRules []models.AWSSecurityGroupRule
	var allGuardDuty []models.AWSGuardDutyStatus
	var allConfig []models.AWSConfigStatus

	for _, region := range regions {
		regCfg := provider.ConfigForRegion(profile, region)
		regClients := c.factory(regCfg)

		// Security groups — non-fatal: only skip SG data for this region on error.
		sgRules, err := collectSecurityGroupRules(ctx, regClients.EC2, region)
		if err == nil {
			allSGRules = append(allSGRules, sgRules...)
		}

		// GuardDuty detector status — non-fatal.
		gdStatus, _ := collectGuardDutyStatus(ctx, regClients.GuardDuty, region)
		allGuardDuty = append(allGuardDuty, gdStatus)

		// AWS Config recorder status — non-fatal.
		cfgStatus, _ := collectConfigStatus(ctx, regClients.Config, region)
		allConfig = append(allConfig, cfgStatus)
	}

	return &models.AWSSecurityData{
		Buckets:            buckets,
		SecurityGroupRules: allSGRules,
		IAMUsers:           iamUsers,
		Root:               root,
		CloudTrail:         cloudTrail,
		GuardDuty:          allGuardDuty,
		Config:             allConfig,
	}, nil
}
