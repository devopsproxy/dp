package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
	"github.com/devopsproxy/dp/internal/providers/aws/common"
	awssecurity "github.com/devopsproxy/dp/internal/providers/aws/security"
	"github.com/devopsproxy/dp/internal/rules"
)

// AWSSecurityEngine implements Engine for AuditTypeSecurity.
// It coordinates security data collection, rule evaluation, and report assembly.
// It never calls AWS SDK or LLM clients directly; all calls are delegated to
// the SecurityCollector and RuleRegistry.
type AWSSecurityEngine struct {
	provider  common.AWSClientProvider
	collector awssecurity.SecurityCollector
	registry  rules.RuleRegistry
	policy    *policy.PolicyConfig
}

// NewAWSSecurityEngine constructs a AWSSecurityEngine wired to the
// supplied provider, security collector, and rule registry.
func NewAWSSecurityEngine(
	provider common.AWSClientProvider,
	collector awssecurity.SecurityCollector,
	registry rules.RuleRegistry,
	policyCfg *policy.PolicyConfig,
) *AWSSecurityEngine {
	return &AWSSecurityEngine{
		provider:  provider,
		collector: collector,
		registry:  registry,
		policy:    policyCfg,
	}
}

// RunAudit implements Engine. Only AuditTypeSecurity is accepted.
func (e *AWSSecurityEngine) RunAudit(ctx context.Context, opts AuditOptions) (*models.AuditReport, error) {
	if opts.AuditType != AuditTypeSecurity {
		return nil, fmt.Errorf("unsupported audit type: %q", opts.AuditType)
	}
	if opts.AllProfiles {
		return e.runAllProfilesSec(ctx, opts)
	}
	return e.runSingleProfileSec(ctx, opts)
}

// runSingleProfileSec executes a security audit for one AWS profile.
func (e *AWSSecurityEngine) runSingleProfileSec(
	ctx context.Context,
	opts AuditOptions,
) (*models.AuditReport, error) {
	profile, err := e.provider.LoadProfile(ctx, opts.Profile)
	if err != nil {
		return nil, fmt.Errorf("load profile %q: %w", opts.Profile, err)
	}

	regions, err := e.resolveRegionsSec(ctx, profile, opts.Regions)
	if err != nil {
		return nil, fmt.Errorf("resolve regions for profile %q: %w", profile.ProfileName, err)
	}

	secData, err := e.collector.CollectAll(ctx, profile, e.provider, regions)
	if err != nil {
		return nil, fmt.Errorf("collect security data for profile %q: %w", profile.ProfileName, err)
	}

	findings := e.evaluateSecurity(secData, profile.AccountID, profile.ProfileName)
	return buildSecurityReport(profile.ProfileName, profile.AccountID, regions, findings, e.policy), nil
}

// runAllProfilesSec runs a security audit across every configured AWS profile
// and merges findings into a single report. Profile failures are skipped
// non-fatally; an error is returned only when no profile can be audited.
func (e *AWSSecurityEngine) runAllProfilesSec(
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
		regions, err := e.resolveRegionsSec(ctx, profile, opts.Regions)
		if err != nil {
			continue
		}
		secData, err := e.collector.CollectAll(ctx, profile, e.provider, regions)
		if err != nil {
			continue
		}
		audited++
		allFindings = append(allFindings, e.evaluateSecurity(secData, profile.AccountID, profile.ProfileName)...)
		for _, r := range regions {
			if _, seen := seenRegions[r]; !seen {
				seenRegions[r] = struct{}{}
				allRegions = append(allRegions, r)
			}
		}
	}

	if audited == 0 {
		return nil, fmt.Errorf("all profiles failed; no security data collected")
	}
	return buildSecurityReport("multi", "", allRegions, allFindings, e.policy), nil
}

// resolveRegionsSec returns the explicit region list or discovers active regions.
func (e *AWSSecurityEngine) resolveRegionsSec(
	ctx context.Context,
	profile *common.ProfileConfig,
	explicit []string,
) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
	}
	return e.provider.GetActiveRegions(ctx, profile)
}

// evaluateSecurity builds a synthetic RegionData carrying the full security
// snapshot and evaluates all registered security rules against it.
// A single RuleContext is used because security data is account-level: IAM,
// root, and S3 are global; SG rules carry their own region via the Region field.
func (e *AWSSecurityEngine) evaluateSecurity(
	secData *models.AWSSecurityData,
	accountID, profile string,
) []models.Finding {
	rctx := rules.RuleContext{
		AccountID: accountID,
		Profile:   profile,
		RegionData: &models.AWSRegionData{
			Region:   "global",
			Security: *secData,
		},
		Policy: e.policy,
	}
	raw := e.registry.EvaluateAll(rctx)
	stampDomain(raw, "security")
	return mergeFindings(raw)
}

// buildSecurityReport assembles the final AuditReport for a security audit.
func buildSecurityReport(
	profile, accountID string,
	regions []string,
	findings []models.Finding,
	policyCfg *policy.PolicyConfig,
) *models.AuditReport {
	findings = policy.ApplyPolicy(findings, "security", policyCfg)
	sortFindings(findings)
	return &models.AuditReport{
		ReportID:    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
		AuditType:   string(AuditTypeSecurity),
		Profile:     profile,
		AccountID:   accountID,
		Regions:     regions,
		Summary:     computeSummary(findings),
		Findings:    findings,
	}
}
