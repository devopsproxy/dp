package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
	"github.com/devopsproxy/dp/internal/providers/aws/common"
	awscost "github.com/devopsproxy/dp/internal/providers/aws/cost"
	"github.com/devopsproxy/dp/internal/rules"
)

// AWSCostEngine is the production implementation of Engine.
// It coordinates data collection, rule evaluation, and report assembly.
// It never calls the AWS SDK, LLM, or any external service directly.
type AWSCostEngine struct {
	provider common.AWSClientProvider
	cost     awscost.CostCollector
	registry rules.RuleRegistry
	policy   *policy.PolicyConfig
}

// NewAWSCostEngine constructs a AWSCostEngine wired to the supplied provider,
// cost collector, and rule registry.
func NewAWSCostEngine(
	provider common.AWSClientProvider,
	costCollector awscost.CostCollector,
	registry rules.RuleRegistry,
	policyCfg *policy.PolicyConfig,
) *AWSCostEngine {
	return &AWSCostEngine{
		provider: provider,
		cost:     costCollector,
		registry: registry,
		policy:   policyCfg,
	}
}

// RunAudit implements Engine. Only AuditTypeCost is supported in the MVP.
// It loads the requested AWS profile(s), discovers regions if not explicitly
// provided, collects cost data, evaluates all registered rules, and returns a
// fully populated AuditReport.
func (e *AWSCostEngine) RunAudit(ctx context.Context, opts AuditOptions) (*models.AuditReport, error) {
	if opts.AuditType != AuditTypeCost {
		return nil, fmt.Errorf("unsupported audit type: %q", opts.AuditType)
	}

	daysBack := opts.DaysBack
	if daysBack <= 0 {
		daysBack = 30
	}

	if opts.AllProfiles {
		return e.runAllProfiles(ctx, opts, daysBack)
	}
	return e.runSingleProfile(ctx, opts, daysBack)
}

// runSingleProfile executes a cost audit for one AWS profile and returns the
// resulting report.
func (e *AWSCostEngine) runSingleProfile(
	ctx context.Context,
	opts AuditOptions,
	daysBack int,
) (*models.AuditReport, error) {
	profile, err := e.provider.LoadProfile(ctx, opts.Profile)
	if err != nil {
		return nil, fmt.Errorf("load profile %q: %w", opts.Profile, err)
	}

	regions, err := e.resolveRegions(ctx, profile, opts.Regions)
	if err != nil {
		return nil, fmt.Errorf("resolve regions for profile %q: %w", profile.ProfileName, err)
	}

	regionData, costSummary, err := e.cost.CollectAll(ctx, profile, e.provider, regions, daysBack)
	if err != nil {
		return nil, fmt.Errorf("collect data for profile %q: %w", profile.ProfileName, err)
	}

	findings := e.evaluateAll(regionData, costSummary, profile.AccountID, profile.ProfileName)
	return buildReport(profile.ProfileName, profile.AccountID, regions, findings, costSummary, e.policy), nil
}

// maxConcurrentProfiles caps the number of profiles audited in parallel.
// Keeps outbound AWS API concurrency predictable when many profiles are configured.
const maxConcurrentProfiles = 3

// runAllProfiles loads every configured AWS profile, audits each one in
// parallel (max maxConcurrentProfiles at a time), and merges all findings into
// a single report. The report-level Profile field is set to "multi"; each
// individual Finding carries its own Profile and AccountID.
// Fail-fast: the first profile error cancels all remaining profile goroutines.
func (e *AWSCostEngine) runAllProfiles(
	ctx context.Context,
	opts AuditOptions,
	daysBack int,
) (*models.AuditReport, error) {
	profiles, err := e.provider.LoadAllProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("load all profiles: %w", err)
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("no AWS profiles found")
	}

	sem := make(chan struct{}, maxConcurrentProfiles)
	var (
		mu               sync.Mutex
		allFindings      []models.Finding
		allRegions       []string
		seenRegions      = make(map[string]struct{})
		allCostSummaries []*models.AWSCostSummary
	)

	g, gctx := errgroup.WithContext(ctx)

PROFILES:
	for _, profile := range profiles {
		profile := profile // capture loop variable for goroutine closure
		select {
		case sem <- struct{}{}: // acquire semaphore slot; blocks when at capacity
		case <-gctx.Done():
			break PROFILES // context cancelled by a prior goroutine error
		}

		g.Go(func() error {
			defer func() { <-sem }() // release semaphore slot on return

			regions, err := e.resolveRegions(gctx, profile, opts.Regions)
			if err != nil {
				return fmt.Errorf("resolve regions for profile %q: %w", profile.ProfileName, err)
			}

			regionData, costSummary, err := e.cost.CollectAll(gctx, profile, e.provider, regions, daysBack)
			if err != nil {
				return fmt.Errorf("collect data for profile %q: %w", profile.ProfileName, err)
			}

			findings := e.evaluateAll(regionData, costSummary, profile.AccountID, profile.ProfileName)

			mu.Lock()
			allFindings = append(allFindings, findings...)
			for _, r := range regions {
				if _, seen := seenRegions[r]; !seen {
					seenRegions[r] = struct{}{}
					allRegions = append(allRegions, r)
				}
			}
			if costSummary != nil {
				allCostSummaries = append(allCostSummaries, costSummary)
			}
			mu.Unlock()

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return buildReport("multi", "", allRegions, allFindings, aggregateCostSummaries(allCostSummaries), e.policy), nil
}

// aggregateCostSummaries merges cost summaries from multiple AWS profiles into
// a single summary. TotalCostUSD is summed; ServiceBreakdown entries are
// accumulated by service name. PeriodStart takes the earliest date and PeriodEnd
// takes the latest date across all summaries. Returns nil when the input is empty.
func aggregateCostSummaries(summaries []*models.AWSCostSummary) *models.AWSCostSummary {
	if len(summaries) == 0 {
		return nil
	}

	result := &models.AWSCostSummary{
		PeriodStart: summaries[0].PeriodStart,
		PeriodEnd:   summaries[0].PeriodEnd,
	}
	svcTotals := make(map[string]float64)

	for _, s := range summaries {
		result.TotalCostUSD += s.TotalCostUSD

		// Track the earliest PeriodStart and latest PeriodEnd across profiles.
		if s.PeriodStart != "" && (result.PeriodStart == "" || s.PeriodStart < result.PeriodStart) {
			result.PeriodStart = s.PeriodStart
		}
		if s.PeriodEnd != "" && s.PeriodEnd > result.PeriodEnd {
			result.PeriodEnd = s.PeriodEnd
		}

		for _, svc := range s.ServiceBreakdown {
			svcTotals[svc.Service] += svc.CostUSD
		}
	}

	// Rebuild ServiceBreakdown in deterministic order.
	services := make([]string, 0, len(svcTotals))
	for svc := range svcTotals {
		services = append(services, svc)
	}
	sort.Strings(services)
	for _, svc := range services {
		result.ServiceBreakdown = append(result.ServiceBreakdown, models.AWSServiceCost{
			Service: svc,
			CostUSD: svcTotals[svc],
		})
	}

	return result
}

// resolveRegions returns the explicit region list when provided, otherwise
// calls GetActiveRegions to discover opted-in regions for the profile.
func (e *AWSCostEngine) resolveRegions(
	ctx context.Context,
	profile *common.ProfileConfig,
	explicit []string,
) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
	}
	return e.provider.GetActiveRegions(ctx, profile)
}

// evaluateAll applies every registered rule to each region's collected data
// and returns the merged findings slice with Domain stamped.
func (e *AWSCostEngine) evaluateAll(
	regionData []models.AWSRegionData,
	costSummary *models.AWSCostSummary,
	accountID, profile string,
) []models.Finding {
	var findings []models.Finding
	for i := range regionData {
		rctx := rules.RuleContext{
			AccountID:   accountID,
			Profile:     profile,
			RegionData:  &regionData[i],
			CostSummary: costSummary,
			Policy:      e.policy,
		}
		findings = append(findings, e.registry.EvaluateAll(rctx)...)
	}
	stampDomain(findings, "cost")
	return findings
}

// stampDomain sets the Domain field on every finding in the slice.
// It is called once per engine, immediately after rule evaluation,
// before any merge or sort. This is the canonical location for domain tagging.
func stampDomain(findings []models.Finding, domain string) {
	for i := range findings {
		findings[i].Domain = domain
	}
}

// buildReport assembles the final AuditReport from collected data and findings.
// Raw findings are first merged per resource (same ResourceID+Region), then
// sorted: CRITICAL → HIGH → MEDIUM → LOW → INFO, ties broken by
// EstimatedMonthlySavings descending.
func buildReport(
	profile, accountID string,
	regions []string,
	findings []models.Finding,
	costSummary *models.AWSCostSummary,
	policyCfg *policy.PolicyConfig,
) *models.AuditReport {
	merged := mergeFindings(findings)
	// Apply policy (if present)
	merged = policy.ApplyPolicy(merged, "cost", policyCfg)
	sortFindings(merged)
	return &models.AuditReport{
		ReportID:    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
		AuditType:   string(AuditTypeCost),
		Profile:     profile,
		AccountID:   accountID,
		Regions:     regions,
		Summary:     computeSummary(merged),
		Findings:    merged,
		CostSummary: costSummary,
	}
}

// findingGroupKey is the composite key used to group findings by resource.
type findingGroupKey struct {
	resourceID string
	region     string
}

// mergeFindings collapses findings that refer to the same resource
// (same ResourceID + Region) into a single Finding:
//   - Severity: highest (lowest severityRank) across the group
//   - EstimatedMonthlySavings: sum across the group
//   - Metadata["rules"]: []string of every RuleID that fired on this resource
//
// All other fields (ID, RuleID, ResourceType, Explanation, Recommendation,
// DetectedAt, AccountID, Profile, Domain) are taken from the first finding in the group.
// Additional Metadata keys from later findings are merged in without overwriting
// keys already set by earlier findings.
// Insertion order of groups is preserved so sortFindings controls final order.
func mergeFindings(raw []models.Finding) []models.Finding {
	type entry struct {
		f       models.Finding
		ruleIDs []string
	}

	index := make(map[findingGroupKey]int) // key → position in entries
	var order []findingGroupKey
	entries := make([]entry, 0, len(raw))

	for _, f := range raw {
		key := findingGroupKey{resourceID: f.ResourceID, region: f.Region}
		pos, exists := index[key]
		if !exists {
			// First finding for this resource — clone metadata map and use as base.
			meta := make(map[string]any, len(f.Metadata)+1)
			for k, v := range f.Metadata {
				meta[k] = v
			}
			f.Metadata = meta
			entries = append(entries, entry{f: f, ruleIDs: []string{f.RuleID}})
			index[key] = len(entries) - 1
			order = append(order, key)
			continue
		}

		e := &entries[pos]
		e.ruleIDs = append(e.ruleIDs, f.RuleID)

		// Upgrade severity if this finding is more severe.
		if severityRank[f.Severity] < severityRank[e.f.Severity] {
			e.f.Severity = f.Severity
		}

		// Accumulate estimated savings.
		e.f.EstimatedMonthlySavings += f.EstimatedMonthlySavings

		// Merge any new metadata keys from this finding; do not overwrite existing.
		for k, v := range f.Metadata {
			if _, alreadySet := e.f.Metadata[k]; !alreadySet {
				e.f.Metadata[k] = v
			}
		}
	}

	// Stamp Metadata["rules"] and collect results in group-insertion order.
	result := make([]models.Finding, 0, len(entries))
	for _, key := range order {
		e := &entries[index[key]]
		e.f.Metadata["rules"] = e.ruleIDs
		result = append(result, e.f)
	}
	return result
}

// severityRank maps Severity values to sort keys (lower = higher priority).
var severityRank = map[models.Severity]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
	models.SeverityInfo:     4,
}

// sortFindings sorts findings in-place: severity descending (CRITICAL first),
// then EstimatedMonthlySavings descending within the same severity.
func sortFindings(findings []models.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri := severityRank[findings[i].Severity]
		rj := severityRank[findings[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return findings[i].EstimatedMonthlySavings > findings[j].EstimatedMonthlySavings
	})
}

// computeSummary aggregates finding counts and total estimated savings across
// all severity levels.
func computeSummary(findings []models.Finding) models.AuditSummary {
	var s models.AuditSummary
	s.TotalFindings = len(findings)
	for _, f := range findings {
		s.TotalEstimatedMonthlySavings += f.EstimatedMonthlySavings
		switch f.Severity {
		case models.SeverityCritical:
			s.CriticalFindings++
		case models.SeverityHigh:
			s.HighFindings++
		case models.SeverityMedium:
			s.MediumFindings++
		case models.SeverityLow:
			s.LowFindings++
		}
	}
	return s
}
