package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
	"github.com/devopsproxy/dp/internal/providers/aws/common"
	awscost "github.com/devopsproxy/dp/internal/providers/aws/cost"
	awssecurity "github.com/devopsproxy/dp/internal/providers/aws/security"
	"github.com/devopsproxy/dp/internal/rules"
)

// AWSDataProtectionEngine implements Engine for AuditTypeDataProtection.
// It coordinates data collection from two sources:
//   - CostCollector: provides per-region EBSVolumes and RDSInstances with
//     their Encrypted / StorageEncrypted fields populated.
//   - SecurityCollector: provides account-level S3 bucket data with
//     DefaultEncryptionEnabled populated by GetBucketEncryption.
//
// Rules are evaluated per-region for EBS/RDS and once globally for S3.
// The engine never calls AWS SDK clients directly.
type AWSDataProtectionEngine struct {
	provider common.AWSClientProvider
	cost     awscost.CostCollector
	security awssecurity.SecurityCollector
	registry rules.RuleRegistry
	policy   *policy.PolicyConfig
}

// NewAWSDataProtectionEngine constructs a AWSDataProtectionEngine
// wired to the supplied provider, cost collector, security collector, and
// rule registry.
func NewAWSDataProtectionEngine(
	provider common.AWSClientProvider,
	cost awscost.CostCollector,
	security awssecurity.SecurityCollector,
	registry rules.RuleRegistry,
	policyCfg *policy.PolicyConfig,
) *AWSDataProtectionEngine {
	return &AWSDataProtectionEngine{
		provider: provider,
		cost:     cost,
		security: security,
		registry: registry,
		policy:   policyCfg,
	}
}

// RunAudit implements Engine. Only AuditTypeDataProtection is accepted.
func (e *AWSDataProtectionEngine) RunAudit(ctx context.Context, opts AuditOptions) (*models.AuditReport, error) {
	if opts.AuditType != AuditTypeDataProtection {
		return nil, fmt.Errorf("unsupported audit type: %q", opts.AuditType)
	}
	if opts.AllProfiles {
		return e.runAllProfilesDP(ctx, opts)
	}
	return e.runSingleProfileDP(ctx, opts)
}

// runSingleProfileDP executes a data-protection audit for one AWS profile.
func (e *AWSDataProtectionEngine) runSingleProfileDP(
	ctx context.Context,
	opts AuditOptions,
) (*models.AuditReport, error) {
	profile, err := e.provider.LoadProfile(ctx, opts.Profile)
	if err != nil {
		return nil, fmt.Errorf("load profile %q: %w", opts.Profile, err)
	}

	regions, err := e.resolveRegionsDP(ctx, profile, opts.Regions)
	if err != nil {
		return nil, fmt.Errorf("resolve regions for profile %q: %w", profile.ProfileName, err)
	}

	// DaysBack=1 minimises CloudWatch API calls; the data protection engine
	// does not use CPU or cost metrics, only the Encrypted / StorageEncrypted
	// fields which come from DescribeVolumes / DescribeDBInstances directly.
	regionData, _, err := e.cost.CollectAll(ctx, profile, e.provider, regions, 1)
	if err != nil {
		return nil, fmt.Errorf("collect region data for profile %q: %w", profile.ProfileName, err)
	}

	secData, err := e.security.CollectAll(ctx, profile, e.provider, regions)
	if err != nil {
		return nil, fmt.Errorf("collect security data for profile %q: %w", profile.ProfileName, err)
	}

	findings := e.evaluateDataProtection(regionData, secData, profile.AccountID, profile.ProfileName)
	return buildDataProtectionReport(profile.ProfileName, profile.AccountID, regions, findings, e.policy), nil
}

// runAllProfilesDP runs a data-protection audit across every configured AWS
// profile and merges findings into a single report. Profile failures are
// skipped non-fatally; an error is returned only when no profile succeeds.
func (e *AWSDataProtectionEngine) runAllProfilesDP(
	ctx context.Context,
	opts AuditOptions,
) (*models.AuditReport, error) {
	profiles, err := e.provider.LoadAllProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("load all profiles: %w", err)
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("no AWS profiles found")
	}

	var (
		allFindings []models.Finding
		allRegions  []string
		seenRegions = make(map[string]struct{})
		audited     int
	)

	for _, profile := range profiles {
		regions, err := e.resolveRegionsDP(ctx, profile, opts.Regions)
		if err != nil {
			continue
		}
		regionData, _, err := e.cost.CollectAll(ctx, profile, e.provider, regions, 1)
		if err != nil {
			continue
		}
		secData, err := e.security.CollectAll(ctx, profile, e.provider, regions)
		if err != nil {
			continue
		}
		audited++
		allFindings = append(allFindings, e.evaluateDataProtection(regionData, secData, profile.AccountID, profile.ProfileName)...)
		for _, r := range regions {
			if _, seen := seenRegions[r]; !seen {
				seenRegions[r] = struct{}{}
				allRegions = append(allRegions, r)
			}
		}
	}

	if audited == 0 {
		return nil, fmt.Errorf("all profiles failed; no data collected")
	}
	return buildDataProtectionReport("multi", "", allRegions, allFindings, e.policy), nil
}

// resolveRegionsDP returns explicit regions or discovers active regions.
func (e *AWSDataProtectionEngine) resolveRegionsDP(
	ctx context.Context,
	profile *common.ProfileConfig,
	explicit []string,
) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
	}
	return e.provider.GetActiveRegions(ctx, profile)
}

// evaluateDataProtection applies all registered data-protection rules:
//   - Per-region: one RuleContext per region; EBS and RDS rules fire on
//     actual resource data; the S3 rule sees empty Buckets and returns nothing.
//   - Global: one synthetic RuleContext with only Security.Buckets populated;
//     EBS and RDS rules see empty slices and return nothing.
//
// Results from all contexts are merged (same ResourceID+Region deduplication)
// before being returned.
func (e *AWSDataProtectionEngine) evaluateDataProtection(
	regionData []models.AWSRegionData,
	secData *models.AWSSecurityData,
	accountID, profile string,
) []models.Finding {
	var raw []models.Finding

	// Per-region: AWSEBSUnencryptedRule and AWSRDSUnencryptedRule fire here.
	for i := range regionData {
		rctx := rules.RuleContext{
			AccountID:  accountID,
			Profile:    profile,
			RegionData: &regionData[i],
			Policy:     e.policy,
		}
		raw = append(raw, e.registry.EvaluateAll(rctx)...)
	}

	// Global: AWSS3DefaultEncryptionMissingRule fires here.
	rctx := rules.RuleContext{
		AccountID: accountID,
		Profile:   profile,
		RegionData: &models.AWSRegionData{
			Region:   "global",
			Security: *secData,
		},
		Policy: e.policy,
	}
	raw = append(raw, e.registry.EvaluateAll(rctx)...)

	stampDomain(raw, "dataprotection")
	return mergeFindings(raw)
}

// buildDataProtectionReport assembles the final AuditReport for a data
// protection audit. No cost savings are associated with these findings.
func buildDataProtectionReport(
	profile, accountID string,
	regions []string,
	findings []models.Finding,
	policyCfg *policy.PolicyConfig,
) *models.AuditReport {
	findings = policy.ApplyPolicy(findings, "dataprotection", policyCfg)
	sortFindings(findings)
	return &models.AuditReport{
		ReportID:    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
		AuditType:   string(AuditTypeDataProtection),
		Profile:     profile,
		AccountID:   accountID,
		Regions:     regions,
		Summary:     computeSummary(findings),
		Findings:    findings,
	}
}
