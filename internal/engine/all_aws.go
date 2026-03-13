package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
)

// awsDomainEngine abstracts a single AWS-typed audit engine (cost, security,
// dataprotection). Storing the field as an interface decouples AllAWSDomainsEngine
// from concrete implementations and allows stub injection in tests.
type awsDomainEngine interface {
	RunAudit(ctx context.Context, opts AuditOptions) (*models.AuditReport, error)
}

// AllAWSDomainsEngine orchestrates a unified audit across the three AWS domains:
// cost, security, and dataprotection.
//
// Kubernetes is intentionally excluded. It belongs to its own provider layer
// (dp kubernetes audit) and must not be invoked from an AWS-scoped audit.
//
// Each domain engine applies its own per-domain policy filtering internally.
// AllAWSDomainsEngine then concatenates the filtered findings, runs one global
// mergeFindings pass (cross-domain deduplication by ResourceID+Region), and
// sorts by severity to produce a single unified AuditReport.
type AllAWSDomainsEngine struct {
	cost   awsDomainEngine
	sec    awsDomainEngine
	dp     awsDomainEngine
	policy *policy.PolicyConfig
}

// NewAllAWSDomainsEngine constructs an AllAWSDomainsEngine wired to the three AWS
// domain engines and shared policy config.
func NewAllAWSDomainsEngine(
	cost *AWSCostEngine,
	sec *AWSSecurityEngine,
	dp *AWSDataProtectionEngine,
	policyCfg *policy.PolicyConfig,
) *AllAWSDomainsEngine {
	return &AllAWSDomainsEngine{
		cost:   cost,
		sec:    sec,
		dp:     dp,
		policy: policyCfg,
	}
}

// AllAWSAuditOptions configures a cross-domain AWS unified audit run.
type AllAWSAuditOptions struct {
	// Profile is the named AWS profile to use. Empty means the default credential chain.
	Profile string

	// AllProfiles, when true, runs all AWS domain audits across every configured profile.
	AllProfiles bool

	// Regions is an explicit list of AWS regions to audit.
	// When empty each engine discovers and iterates all active regions.
	Regions []string

	// DaysBack is the lookback window in days for cost queries. Defaults to 30 when zero.
	DaysBack int
}

// RunAllAWSAudit executes the three AWS domain engines sequentially, checks
// per-domain policy enforcement, concatenates all policy-filtered findings,
// runs mergeFindings once for cross-domain deduplication, and sorts globally
// by severity.
//
// The returned []string lists the domains that triggered policy enforcement
// (findings at or above the configured fail_on_severity threshold). Callers
// must inspect this list and exit with code 1 when it is non-empty.
//
// The returned error covers only engine-level failures (provider errors, rule
// evaluation errors). Policy enforcement is not an error; it is signalled via
// the returned slice.
func (e *AllAWSDomainsEngine) RunAllAWSAudit(
	ctx context.Context,
	opts AllAWSAuditOptions,
) (*models.AuditReport, []string, error) {
	daysBack := opts.DaysBack
	if daysBack <= 0 {
		daysBack = 30
	}

	// -- Cost domain --
	costReport, err := e.cost.RunAudit(ctx, AuditOptions{
		AuditType:   AuditTypeCost,
		Profile:     opts.Profile,
		AllProfiles: opts.AllProfiles,
		Regions:     opts.Regions,
		DaysBack:    daysBack,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("cost audit: %w", err)
	}

	// -- Security domain --
	secReport, err := e.sec.RunAudit(ctx, AuditOptions{
		AuditType:   AuditTypeSecurity,
		Profile:     opts.Profile,
		AllProfiles: opts.AllProfiles,
		Regions:     opts.Regions,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("security audit: %w", err)
	}

	// -- Data protection domain --
	dpReport, err := e.dp.RunAudit(ctx, AuditOptions{
		AuditType:   AuditTypeDataProtection,
		Profile:     opts.Profile,
		AllProfiles: opts.AllProfiles,
		Regions:     opts.Regions,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("dataprotection audit: %w", err)
	}

	// -- Per-domain enforcement check (against domain-filtered findings) --
	var enforcedDomains []string
	if policy.ShouldFail("cost", costReport.Findings, e.policy) {
		enforcedDomains = append(enforcedDomains, "cost")
	}
	if policy.ShouldFail("security", secReport.Findings, e.policy) {
		enforcedDomains = append(enforcedDomains, "security")
	}
	if policy.ShouldFail("dataprotection", dpReport.Findings, e.policy) {
		enforcedDomains = append(enforcedDomains, "dataprotection")
	}

	// -- Global concatenate + sort (no cross-domain merge) --
	//
	// Each domain engine already performs intra-domain deduplication via its
	// own mergeFindings call. Running mergeFindings again here would collapse
	// findings for the same resource from different domains (e.g. vol-xxx
	// appearing as MEDIUM in cost and HIGH in dataprotection) into a single
	// finding at the highest severity — silently escalating a cost MEDIUM to
	// HIGH. Domain membership must NOT influence severity (see requirement 4).
	//
	// Each domain's findings are therefore concatenated as-is; per-domain
	// severity is preserved. sortFindings provides the global ordering.
	var all []models.Finding
	all = append(all, costReport.Findings...)
	all = append(all, secReport.Findings...)
	all = append(all, dpReport.Findings...)
	sortFindings(all)

	// -- Deduplicate region list across all three domain reports --
	seen := make(map[string]struct{})
	var regions []string
	for _, r := range append(append(costReport.Regions, secReport.Regions...), dpReport.Regions...) {
		if _, ok := seen[r]; !ok {
			seen[r] = struct{}{}
			regions = append(regions, r)
		}
	}

	report := &models.AuditReport{
		ReportID:    fmt.Sprintf("all-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
		AuditType:   string(AuditTypeAll),
		Profile:     costReport.Profile,
		AccountID:   costReport.AccountID,
		Regions:     regions,
		Summary:     computeSummary(all),
		Findings:    all,
		CostSummary: costReport.CostSummary,
	}

	return report, enforcedDomains, nil
}
