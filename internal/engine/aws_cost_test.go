package engine

import (
	"testing"
	"time"

	"github.com/devopsproxy/dp/internal/models"
)

// newFinding constructs a minimal Finding for use in engine tests.
// Metadata is initialised with a rule-specific sentinel key so merge tests
// can verify cross-finding metadata propagation.
func newFinding(resourceID, region, ruleID string, sev models.Severity, savings float64) models.Finding {
	return models.Finding{
		ID:                      ruleID + "-" + resourceID,
		RuleID:                  ruleID,
		ResourceID:              resourceID,
		ResourceType:            models.ResourceAWSEBS,
		Region:                  region,
		AccountID:               "111122223333",
		Profile:                 "test",
		Severity:                sev,
		EstimatedMonthlySavings: savings,
		DetectedAt:              time.Now().UTC(),
		Metadata:                map[string]any{"src_" + ruleID: true},
	}
}

// ── mergeFindings ────────────────────────────────────────────────────────────

func TestMergeFindings_Empty(t *testing.T) {
	got := mergeFindings(nil)
	if len(got) != 0 {
		t.Errorf("want 0, got %d", len(got))
	}
	got = mergeFindings([]models.Finding{})
	if len(got) != 0 {
		t.Errorf("want 0, got %d", len(got))
	}
}

func TestMergeFindings_SingleFinding(t *testing.T) {
	raw := []models.Finding{newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0)}
	got := mergeFindings(raw)

	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	f := got[0]
	if f.ResourceID != "vol-1" {
		t.Errorf("ResourceID = %q; want vol-1", f.ResourceID)
	}
	if f.EstimatedMonthlySavings != 8.0 {
		t.Errorf("savings = %.2f; want 8.00", f.EstimatedMonthlySavings)
	}

	// Metadata["rules"] must be set to a slice containing the single rule ID.
	rules, ok := f.Metadata["rules"].([]string)
	if !ok {
		t.Fatalf("Metadata[rules] type = %T; want []string", f.Metadata["rules"])
	}
	if len(rules) != 1 || rules[0] != "EBS_UNATTACHED" {
		t.Errorf("Metadata[rules] = %v; want [EBS_UNATTACHED]", rules)
	}
}

func TestMergeFindings_DifferentResourcesNotMerged(t *testing.T) {
	raw := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
		newFinding("vol-2", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 4.0),
	}
	got := mergeFindings(raw)
	if len(got) != 2 {
		t.Errorf("want 2 separate findings, got %d", len(got))
	}
}

func TestMergeFindings_DifferentRegionsSameIDNotMerged(t *testing.T) {
	// Same resource ID but different regions must NOT be merged.
	raw := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
		newFinding("vol-1", "eu-west-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
	}
	got := mergeFindings(raw)
	if len(got) != 2 {
		t.Errorf("want 2 findings (different regions), got %d", len(got))
	}
}

func TestMergeFindings_SameResourceSumsSavings(t *testing.T) {
	raw := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
		newFinding("vol-1", "us-east-1", "EBS_GP2_LEGACY", models.SeverityLow, 2.0),
	}
	got := mergeFindings(raw)
	if len(got) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(got))
	}
	if got[0].EstimatedMonthlySavings != 10.0 {
		t.Errorf("savings = %.2f; want 10.00 (8+2)", got[0].EstimatedMonthlySavings)
	}
}

func TestMergeFindings_SameResourceUpgradesSevertiy(t *testing.T) {
	// First finding is LOW; second is MEDIUM — merged result must use MEDIUM.
	raw := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_GP2_LEGACY", models.SeverityLow, 2.0),
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
	}
	got := mergeFindings(raw)
	if len(got) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(got))
	}
	if got[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM (upgraded from LOW)", got[0].Severity)
	}
}

func TestMergeFindings_SameResourceKeepsHigherSeverity(t *testing.T) {
	// First finding is HIGH; second is LOW — result must stay HIGH.
	raw := []models.Finding{
		newFinding("i-1", "us-east-1", "EC2_NO_SP", models.SeverityHigh, 50.0),
		newFinding("i-1", "us-east-1", "EC2_LOW_CPU", models.SeverityMedium, 30.0),
	}
	got := mergeFindings(raw)
	if len(got) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(got))
	}
	if got[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH (must not be downgraded)", got[0].Severity)
	}
}

func TestMergeFindings_RuleIDsCollectedInMetadata(t *testing.T) {
	raw := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
		newFinding("vol-1", "us-east-1", "EBS_GP2_LEGACY", models.SeverityLow, 2.0),
	}
	got := mergeFindings(raw)
	if len(got) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(got))
	}

	rules, ok := got[0].Metadata["rules"].([]string)
	if !ok {
		t.Fatalf("Metadata[rules] type = %T; want []string", got[0].Metadata["rules"])
	}
	if len(rules) != 2 {
		t.Fatalf("len(Metadata[rules]) = %d; want 2", len(rules))
	}
	// Order must follow registration/evaluation order.
	if rules[0] != "EBS_UNATTACHED" || rules[1] != "EBS_GP2_LEGACY" {
		t.Errorf("Metadata[rules] = %v; want [EBS_UNATTACHED EBS_GP2_LEGACY]", rules)
	}
}

func TestMergeFindings_MetadataMergedFromLaterFindings(t *testing.T) {
	// First finding has key "a"; second has keys "b" and "a" (conflicting).
	// Result must contain "a" from first and "b" from second; "a" must not be overwritten.
	f1 := newFinding("vol-1", "us-east-1", "RULE_A", models.SeverityLow, 1.0)
	f1.Metadata = map[string]any{"a": "first", "src_RULE_A": true}

	f2 := newFinding("vol-1", "us-east-1", "RULE_B", models.SeverityLow, 1.0)
	f2.Metadata = map[string]any{"b": "second", "a": "should-not-overwrite", "src_RULE_B": true}

	got := mergeFindings([]models.Finding{f1, f2})
	if len(got) != 1 {
		t.Fatalf("want 1 merged finding, got %d", len(got))
	}
	m := got[0].Metadata
	if m["a"] != "first" {
		t.Errorf("Metadata[a] = %v; want 'first' (must not be overwritten by second finding)", m["a"])
	}
	if m["b"] != "second" {
		t.Errorf("Metadata[b] = %v; want 'second' (merged from second finding)", m["b"])
	}
}

func TestMergeFindings_PreservesInsertionOrder(t *testing.T) {
	// Three distinct resources; order of groups must match order first seen.
	raw := []models.Finding{
		newFinding("vol-c", "us-east-1", "RULE", models.SeverityLow, 1.0),
		newFinding("vol-a", "us-east-1", "RULE", models.SeverityLow, 2.0),
		newFinding("vol-b", "us-east-1", "RULE", models.SeverityLow, 3.0),
	}
	got := mergeFindings(raw)
	if len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
	order := []string{got[0].ResourceID, got[1].ResourceID, got[2].ResourceID}
	want := []string{"vol-c", "vol-a", "vol-b"}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("position %d: got %q; want %q", i, order[i], want[i])
		}
	}
}

func TestMergeFindings_DoesNotMutateInput(t *testing.T) {
	// The raw input must not have Metadata["rules"] added to it.
	raw := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
	}
	originalMeta := raw[0].Metadata // keep reference to original map

	mergeFindings(raw)

	if _, found := originalMeta["rules"]; found {
		t.Error("mergeFindings must not add 'rules' key to the original finding's Metadata map")
	}
}

func TestMergeFindings_NilMetadataHandled(t *testing.T) {
	// Findings with nil Metadata must not panic and must still get Metadata["rules"].
	f := models.Finding{
		ID:           "RULE-vol-1",
		RuleID:       "RULE",
		ResourceID:   "vol-1",
		ResourceType: models.ResourceAWSEBS,
		Region:       "us-east-1",
		Severity:     models.SeverityLow,
		Metadata:     nil,
	}
	got := mergeFindings([]models.Finding{f})
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if _, ok := got[0].Metadata["rules"]; !ok {
		t.Error("Metadata[rules] must be set even when input Metadata is nil")
	}
}

// ── sortFindings ─────────────────────────────────────────────────────────────

func TestSortFindings_DeterministicAcrossInputOrder(t *testing.T) {
	// Parallel region collectors append findings in non-deterministic order.
	// sortFindings must produce the same canonical sequence regardless of the
	// order in which findings were appended to the shared slice.
	base := []models.Finding{
		newFinding("i-low", "us-east-1", "R1", models.SeverityLow, 5.0),
		newFinding("i-critical", "us-east-1", "R2", models.SeverityCritical, 20.0),
		newFinding("i-high-a", "us-east-1", "R3", models.SeverityHigh, 30.0),
		newFinding("i-medium", "us-east-1", "R4", models.SeverityMedium, 10.0),
		newFinding("i-high-b", "us-east-1", "R5", models.SeverityHigh, 50.0),
	}
	// Expected: CRITICAL first, then HIGH by savings desc, then MEDIUM, then LOW.
	wantOrder := []string{"i-critical", "i-high-b", "i-high-a", "i-medium", "i-low"}

	permutations := [][]models.Finding{
		{base[0], base[1], base[2], base[3], base[4]},
		{base[4], base[3], base[2], base[1], base[0]},
		{base[2], base[0], base[4], base[1], base[3]},
	}

	for pi, perm := range permutations {
		cp := make([]models.Finding, len(perm))
		copy(cp, perm)
		sortFindings(cp)
		for i, wantID := range wantOrder {
			if cp[i].ResourceID != wantID {
				t.Errorf("permutation %d: position %d got %q; want %q",
					pi, i, cp[i].ResourceID, wantID)
			}
		}
	}
}

func TestSortFindings_DeterministicAcrossProfiles(t *testing.T) {
	// Parallel profile goroutines append findings in non-deterministic order.
	// sortFindings must produce the same canonical sequence regardless of
	// which profile's findings were appended first.
	profileA := []models.Finding{
		newFinding("i-critical-a", "us-east-1", "EC2_LOW_CPU", models.SeverityCritical, 100.0),
		newFinding("vol-medium-a", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 20.0),
	}
	profileB := []models.Finding{
		newFinding("i-high-b", "eu-west-1", "EC2_NO_SP", models.SeverityHigh, 60.0),
		newFinding("vol-low-b", "eu-west-1", "EBS_GP2_LEGACY", models.SeverityLow, 5.0),
	}

	// Expected canonical order: CRITICAL → HIGH → MEDIUM → LOW
	wantOrder := []string{"i-critical-a", "i-high-b", "vol-medium-a", "vol-low-b"}

	// Two orderings that simulate different goroutine append races
	orderings := [][]models.Finding{
		append(append([]models.Finding{}, profileA...), profileB...),
		append(append([]models.Finding{}, profileB...), profileA...),
	}

	for oi, ordering := range orderings {
		cp := make([]models.Finding, len(ordering))
		copy(cp, ordering)
		sortFindings(cp)
		for i, wantID := range wantOrder {
			if cp[i].ResourceID != wantID {
				t.Errorf("ordering %d: position %d got %q; want %q", oi, i, cp[i].ResourceID, wantID)
			}
		}
	}
}

// ── computeSummary ──────────────────────────────────────────────────────────

func TestComputeSummary_Empty(t *testing.T) {
	s := computeSummary(nil)
	if s.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d; want 0", s.TotalFindings)
	}
	if s.TotalEstimatedMonthlySavings != 0 {
		t.Errorf("TotalEstimatedMonthlySavings = %.2f; want 0", s.TotalEstimatedMonthlySavings)
	}
	if s.CriticalFindings != 0 || s.HighFindings != 0 || s.MediumFindings != 0 || s.LowFindings != 0 {
		t.Error("all severity counts must be 0 for empty input")
	}
}

func TestComputeSummary_CountsPerSeverity(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical, EstimatedMonthlySavings: 100},
		{Severity: models.SeverityHigh, EstimatedMonthlySavings: 50},
		{Severity: models.SeverityMedium, EstimatedMonthlySavings: 30},
		{Severity: models.SeverityLow, EstimatedMonthlySavings: 8},
		{Severity: models.SeverityInfo, EstimatedMonthlySavings: 0},
	}
	s := computeSummary(findings)

	if s.TotalFindings != 5 {
		t.Errorf("TotalFindings = %d; want 5", s.TotalFindings)
	}
	if s.CriticalFindings != 1 {
		t.Errorf("CriticalFindings = %d; want 1", s.CriticalFindings)
	}
	if s.HighFindings != 1 {
		t.Errorf("HighFindings = %d; want 1", s.HighFindings)
	}
	if s.MediumFindings != 1 {
		t.Errorf("MediumFindings = %d; want 1", s.MediumFindings)
	}
	if s.LowFindings != 1 {
		t.Errorf("LowFindings = %d; want 1", s.LowFindings)
	}
}

func TestComputeSummary_InfoCountedInTotalOnly(t *testing.T) {
	// INFO findings count toward TotalFindings but no severity-specific bucket.
	findings := []models.Finding{
		{Severity: models.SeverityInfo, EstimatedMonthlySavings: 5},
		{Severity: models.SeverityInfo, EstimatedMonthlySavings: 5},
	}
	s := computeSummary(findings)

	if s.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d; want 2", s.TotalFindings)
	}
	if s.CriticalFindings+s.HighFindings+s.MediumFindings+s.LowFindings != 0 {
		t.Error("severity buckets must all be 0 for INFO findings")
	}
}

func TestComputeSummary_SumsSavings(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityMedium, EstimatedMonthlySavings: 8.00},
		{Severity: models.SeverityMedium, EstimatedMonthlySavings: 30.00},
		{Severity: models.SeverityLow, EstimatedMonthlySavings: 2.00},
	}
	s := computeSummary(findings)

	const wantSavings = 40.00
	if s.TotalEstimatedMonthlySavings != wantSavings {
		t.Errorf("TotalEstimatedMonthlySavings = %.2f; want %.2f", s.TotalEstimatedMonthlySavings, wantSavings)
	}
}

func TestComputeSummary_MultipleFindingsSameSeverity(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityHigh, EstimatedMonthlySavings: 10},
		{Severity: models.SeverityHigh, EstimatedMonthlySavings: 20},
		{Severity: models.SeverityHigh, EstimatedMonthlySavings: 30},
	}
	s := computeSummary(findings)

	if s.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d; want 3", s.TotalFindings)
	}
	if s.HighFindings != 3 {
		t.Errorf("HighFindings = %d; want 3", s.HighFindings)
	}
	if s.TotalEstimatedMonthlySavings != 60.0 {
		t.Errorf("TotalEstimatedMonthlySavings = %.2f; want 60.00", s.TotalEstimatedMonthlySavings)
	}
}

// ── aggregateCostSummaries ───────────────────────────────────────────────────

func TestAggregateCostSummaries_NilInput(t *testing.T) {
	if got := aggregateCostSummaries(nil); got != nil {
		t.Errorf("want nil for nil input, got %+v", got)
	}
}

func TestAggregateCostSummaries_EmptySlice(t *testing.T) {
	if got := aggregateCostSummaries([]*models.AWSCostSummary{}); got != nil {
		t.Errorf("want nil for empty slice, got %+v", got)
	}
}

func TestAggregateCostSummaries_SingleSummary(t *testing.T) {
	input := []*models.AWSCostSummary{
		{
			PeriodStart:  "2026-01-01",
			PeriodEnd:    "2026-02-01",
			TotalCostUSD: 150.0,
			ServiceBreakdown: []models.AWSServiceCost{
				{Service: "EC2", CostUSD: 100.0},
				{Service: "S3", CostUSD: 50.0},
			},
		},
	}
	got := aggregateCostSummaries(input)
	if got == nil {
		t.Fatal("want non-nil result for single summary")
	}
	if got.TotalCostUSD != 150.0 {
		t.Errorf("TotalCostUSD = %.2f; want 150.00", got.TotalCostUSD)
	}
	if got.PeriodStart != "2026-01-01" {
		t.Errorf("PeriodStart = %q; want 2026-01-01", got.PeriodStart)
	}
	if got.PeriodEnd != "2026-02-01" {
		t.Errorf("PeriodEnd = %q; want 2026-02-01", got.PeriodEnd)
	}
	if len(got.ServiceBreakdown) != 2 {
		t.Errorf("len(ServiceBreakdown) = %d; want 2", len(got.ServiceBreakdown))
	}
}

func TestAggregateCostSummaries_SumsTotalCostAcrossProfiles(t *testing.T) {
	input := []*models.AWSCostSummary{
		{TotalCostUSD: 100.0, PeriodStart: "2026-01-01", PeriodEnd: "2026-02-01"},
		{TotalCostUSD: 200.0, PeriodStart: "2026-01-01", PeriodEnd: "2026-02-01"},
		{TotalCostUSD: 50.0, PeriodStart: "2026-01-01", PeriodEnd: "2026-02-01"},
	}
	got := aggregateCostSummaries(input)
	if got.TotalCostUSD != 350.0 {
		t.Errorf("TotalCostUSD = %.2f; want 350.00 (100+200+50)", got.TotalCostUSD)
	}
}

func TestAggregateCostSummaries_MergesServiceBreakdownByName(t *testing.T) {
	input := []*models.AWSCostSummary{
		{
			TotalCostUSD: 150.0,
			ServiceBreakdown: []models.AWSServiceCost{
				{Service: "EC2", CostUSD: 100.0},
				{Service: "S3", CostUSD: 50.0},
			},
		},
		{
			TotalCostUSD: 80.0,
			ServiceBreakdown: []models.AWSServiceCost{
				{Service: "EC2", CostUSD: 60.0},
				{Service: "RDS", CostUSD: 20.0},
			},
		},
	}
	got := aggregateCostSummaries(input)
	if got.TotalCostUSD != 230.0 {
		t.Errorf("TotalCostUSD = %.2f; want 230.00", got.TotalCostUSD)
	}
	// ServiceBreakdown should be sorted by service name: EC2, RDS, S3
	svcMap := make(map[string]float64)
	for _, sc := range got.ServiceBreakdown {
		svcMap[sc.Service] = sc.CostUSD
	}
	if svcMap["EC2"] != 160.0 {
		t.Errorf("EC2 cost = %.2f; want 160.00 (100+60)", svcMap["EC2"])
	}
	if svcMap["S3"] != 50.0 {
		t.Errorf("S3 cost = %.2f; want 50.00", svcMap["S3"])
	}
	if svcMap["RDS"] != 20.0 {
		t.Errorf("RDS cost = %.2f; want 20.00", svcMap["RDS"])
	}
}

func TestAggregateCostSummaries_EarliestStartLatestEnd(t *testing.T) {
	input := []*models.AWSCostSummary{
		{PeriodStart: "2026-01-15", PeriodEnd: "2026-02-15"},
		{PeriodStart: "2026-01-01", PeriodEnd: "2026-02-28"},
		{PeriodStart: "2026-01-10", PeriodEnd: "2026-02-10"},
	}
	got := aggregateCostSummaries(input)
	if got.PeriodStart != "2026-01-01" {
		t.Errorf("PeriodStart = %q; want 2026-01-01 (earliest)", got.PeriodStart)
	}
	if got.PeriodEnd != "2026-02-28" {
		t.Errorf("PeriodEnd = %q; want 2026-02-28 (latest)", got.PeriodEnd)
	}
}
