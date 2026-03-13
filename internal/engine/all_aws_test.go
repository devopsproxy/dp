package engine

import (
	"context"
	"testing"
	"time"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
)

// ── test double ───────────────────────────────────────────────────────────────

// stubAWSEngine returns a fixed report (or error) from RunAudit.
// It satisfies awsDomainEngine.
type stubAWSEngine struct {
	report *models.AuditReport
	err    error
}

func (s *stubAWSEngine) RunAudit(_ context.Context, _ AuditOptions) (*models.AuditReport, error) {
	return s.report, s.err
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newAllAWSEngine builds an AllAWSDomainsEngine wired to three AWS domain stubs.
// There is intentionally no kube parameter: AllAWSDomainsEngine is AWS-only.
func newAllAWSEngine(
	costReport, secReport, dpReport *models.AuditReport,
	policyCfg *policy.PolicyConfig,
) *AllAWSDomainsEngine {
	return &AllAWSDomainsEngine{
		cost:   &stubAWSEngine{report: costReport},
		sec:    &stubAWSEngine{report: secReport},
		dp:     &stubAWSEngine{report: dpReport},
		policy: policyCfg,
	}
}

// emptyDomainReport returns a minimal report with no findings.
func emptyDomainReport(auditType, profile, accountID string, regions []string) *models.AuditReport {
	return &models.AuditReport{
		ReportID:    "test-" + auditType,
		GeneratedAt: time.Now().UTC(),
		AuditType:   auditType,
		Profile:     profile,
		AccountID:   accountID,
		Regions:     regions,
	}
}

// domainReportWith returns a report containing the supplied findings.
func domainReportWith(auditType string, findings []models.Finding) *models.AuditReport {
	return &models.AuditReport{
		ReportID:    "test-" + auditType,
		GeneratedAt: time.Now().UTC(),
		AuditType:   auditType,
		Profile:     "test",
		AccountID:   "111122223333",
		Regions:     []string{"us-east-1"},
		Findings:    findings,
		Summary:     computeSummary(findings),
	}
}

// ── TestAuditAll_MergeBehavior ────────────────────────────────────────────────

// TestAuditAll_NoCrossDomainEscalation verifies that when the same resource
// appears in two different domains with different severities, the findings are
// kept separate and each retains its original per-domain severity.
//
// Previously (bug): vol-1 from cost (LOW) and vol-1 from dataprotection (HIGH)
// were merged into one finding at HIGH — silently escalating the cost severity.
// Running "dp aws audit cost" showed LOW; "dp aws audit --all" showed HIGH.
// Domain membership must not influence severity.
func TestAuditAll_NoCrossDomainEscalation(t *testing.T) {
	costFindings := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityLow, 5.0),
	}
	dpFindings := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNENCRYPTED", models.SeverityHigh, 0.0),
	}

	eng := newAllAWSEngine(
		domainReportWith("cost", costFindings),
		emptyDomainReport("security", "test", "111122223333", []string{"us-east-1"}),
		domainReportWith("dataprotection", dpFindings),
		nil,
	)

	report, enforced, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(enforced) != 0 {
		t.Errorf("expected no enforced domains; got %v", enforced)
	}

	// Two separate findings must be present — cross-domain must NOT collapse them.
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings (one per domain); got %d", len(report.Findings))
	}

	// Findings sorted by severity: HIGH first (DP), then LOW (cost).
	if report.Findings[0].Severity != models.SeverityHigh {
		t.Errorf("findings[0].Severity = %q; want HIGH (dataprotection finding)", report.Findings[0].Severity)
	}
	if report.Findings[1].Severity != models.SeverityLow {
		t.Errorf("findings[1].Severity = %q; want LOW (cost finding)", report.Findings[1].Severity)
	}

	// The cost finding's savings must be intact on the cost finding itself.
	var costSavings float64
	for _, f := range report.Findings {
		if f.RuleID == "EBS_UNATTACHED" {
			costSavings = f.EstimatedMonthlySavings
		}
	}
	if costSavings != 5.0 {
		t.Errorf("cost finding EstimatedMonthlySavings = %.2f; want 5.00", costSavings)
	}

	if report.AuditType != string(AuditTypeAll) {
		t.Errorf("AuditType = %q; want %q", report.AuditType, string(AuditTypeAll))
	}
}

// ── TestAuditAll_PolicyRespected ─────────────────────────────────────────────

// TestAuditAll_PolicyRespected verifies that per-domain policy enforcement is
// detected independently: only the domain that has a finding at or above the
// configured fail_on_severity threshold appears in the enforcedDomains slice.
func TestAuditAll_PolicyRespected(t *testing.T) {
	// Security domain has a CRITICAL finding; policy enforces at HIGH for security.
	secFindings := []models.Finding{
		newFinding("root-account", "global", "ROOT_ACCESS_KEY", models.SeverityCritical, 0.0),
	}
	policyCfg := &policy.PolicyConfig{
		Version: 1,
		Enforcement: map[string]policy.EnforcementConfig{
			"security": {FailOnSeverity: "HIGH"},
		},
	}

	eng := newAllAWSEngine(
		emptyDomainReport("cost", "test", "111122223333", []string{"us-east-1"}),
		domainReportWith("security", secFindings),
		emptyDomainReport("dataprotection", "test", "111122223333", []string{"us-east-1"}),
		policyCfg,
	)

	_, enforced, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the security domain must be flagged for enforcement.
	if len(enforced) != 1 || enforced[0] != "security" {
		t.Errorf("enforced = %v; want [security]", enforced)
	}
}

// ── TestAuditAll_SeverityOrdering ────────────────────────────────────────────

// TestAuditAll_SeverityOrdering verifies that merged findings from all three
// AWS domains are sorted globally: CRITICAL first, then HIGH, MEDIUM, LOW.
// It also checks that the unified report's summary counts are correct.
func TestAuditAll_SeverityOrdering(t *testing.T) {
	// Four findings across three AWS domains, each at a different severity level.
	// Security contributes two findings (HIGH + MEDIUM) to cover all four levels.
	costFindings := []models.Finding{
		newFinding("ec2-1", "us-east-1", "EC2_LOW_CPU", models.SeverityLow, 10.0),
	}
	secFindings := []models.Finding{
		newFinding("sg-1", "us-east-1", "SG_OPEN_SSH", models.SeverityHigh, 0.0),
		newFinding("alice", "us-east-1", "IAM_NO_MFA", models.SeverityMedium, 0.0),
	}
	dpFindings := []models.Finding{
		newFinding("rds-1", "us-east-1", "RDS_UNENCRYPTED", models.SeverityCritical, 0.0),
	}

	eng := newAllAWSEngine(
		domainReportWith("cost", costFindings),
		domainReportWith("security", secFindings),
		domainReportWith("dataprotection", dpFindings),
		nil,
	)

	report, _, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All four findings must be present (no cross-domain deduplication here).
	if len(report.Findings) != 4 {
		t.Fatalf("expected 4 findings; got %d", len(report.Findings))
	}

	// Global sort: CRITICAL → HIGH → MEDIUM → LOW.
	wantOrder := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
	}
	for i, want := range wantOrder {
		if report.Findings[i].Severity != want {
			t.Errorf("findings[%d].Severity = %q; want %q",
				i, report.Findings[i].Severity, want)
		}
	}

	// Summary counts must reflect all four merged findings.
	s := report.Summary
	if s.TotalFindings != 4 {
		t.Errorf("Summary.TotalFindings = %d; want 4", s.TotalFindings)
	}
	if s.CriticalFindings != 1 {
		t.Errorf("Summary.CriticalFindings = %d; want 1", s.CriticalFindings)
	}
	if s.HighFindings != 1 {
		t.Errorf("Summary.HighFindings = %d; want 1", s.HighFindings)
	}
	if s.MediumFindings != 1 {
		t.Errorf("Summary.MediumFindings = %d; want 1", s.MediumFindings)
	}
	if s.LowFindings != 1 {
		t.Errorf("Summary.LowFindings = %d; want 1", s.LowFindings)
	}
}

// ── TestAuditAll_KubernetesNotInvoked ────────────────────────────────────────

// TestAuditAll_KubernetesNotInvoked asserts that AllAWSDomainsEngine operates
// exclusively with the three AWS domain engines and requires no Kubernetes
// provider. The absence of a kube field on AllAWSDomainsEngine enforces this at
// compile time; this test confirms the engine runs to completion without any
// kubeconfig access.
func TestAuditAll_KubernetesNotInvoked(t *testing.T) {
	// Construct the engine using struct literal — no kube field exists.
	eng := &AllAWSDomainsEngine{
		cost: &stubAWSEngine{
			report: emptyDomainReport("cost", "test", "111122223333", []string{"us-east-1"}),
		},
		sec: &stubAWSEngine{
			report: emptyDomainReport("security", "test", "111122223333", []string{"us-east-1"}),
		},
		dp: &stubAWSEngine{
			report: emptyDomainReport("dataprotection", "test", "111122223333", []string{"us-east-1"}),
		},
	}

	report, enforced, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{
		Profile: "test-profile",
		Regions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("RunAllAWSAudit returned unexpected error: %v", err)
	}
	if len(enforced) != 0 {
		t.Errorf("expected no enforced domains; got %v", enforced)
	}
	if report.AuditType != string(AuditTypeAll) {
		t.Errorf("AuditType = %q; want %q", report.AuditType, string(AuditTypeAll))
	}
	// Verify no kubernetes resource types leaked into the report.
	for _, f := range report.Findings {
		rt := string(f.ResourceType)
		if len(rt) >= 3 && rt[:3] == "K8S" {
			t.Errorf("unexpected kubernetes finding in aws --all report: resource_type=%q", rt)
		}
	}
}

// ── Severity preservation tests ───────────────────────────────────────────────

// TestAuditAll_SingleCostFinding_SeverityUnchanged verifies that a single cost
// finding passed through RunAllAWSAudit is not escalated in any way.
// Running "dp aws audit cost" and "dp aws audit --all" must produce the same
// severity for a resource that appears only in the cost domain.
func TestAuditAll_SingleCostFinding_SeverityUnchanged(t *testing.T) {
	costFindings := []models.Finding{
		newFinding("i-0abc123", "us-east-1", "EC2_LOW_CPU", models.SeverityMedium, 12.0),
	}

	eng := newAllAWSEngine(
		domainReportWith("cost", costFindings),
		emptyDomainReport("security", "test", "111122223333", []string{"us-east-1"}),
		emptyDomainReport("dataprotection", "test", "111122223333", []string{"us-east-1"}),
		nil,
	)

	report, _, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(report.Findings))
	}
	// Severity must be identical to what the cost engine produced.
	if report.Findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM (cost-only finding must not be escalated)", report.Findings[0].Severity)
	}
	if report.Findings[0].RuleID != "EC2_LOW_CPU" {
		t.Errorf("RuleID = %q; want EC2_LOW_CPU", report.Findings[0].RuleID)
	}
}

// TestAuditAll_IntraDomainMerge_SeverityPreserved verifies that when a domain
// engine returns a finding whose severity already reflects an intra-domain merge
// (e.g. two cost rules fired for the same resource and the higher severity won),
// RunAllAWSAudit preserves that merged severity without modification.
func TestAuditAll_IntraDomainMerge_SeverityPreserved(t *testing.T) {
	// Simulate the output of a domain engine that merged two cost findings for
	// the same resource: EC2_LOW_CPU (MEDIUM) + EC2_NO_SAVINGS_PLAN (MEDIUM).
	// The domain engine's own mergeFindings produced one MEDIUM finding.
	merged := newFinding("i-0xyz789", "eu-west-1", "EC2_LOW_CPU", models.SeverityMedium, 20.0)
	merged.Metadata = map[string]any{
		"rules": []string{"EC2_LOW_CPU", "EC2_NO_SAVINGS_PLAN"},
	}

	eng := newAllAWSEngine(
		domainReportWith("cost", []models.Finding{merged}),
		emptyDomainReport("security", "test", "111122223333", []string{"eu-west-1"}),
		emptyDomainReport("dataprotection", "test", "111122223333", []string{"eu-west-1"}),
		nil,
	)

	report, _, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(report.Findings))
	}
	if report.Findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM (intra-domain merge must be preserved)", report.Findings[0].Severity)
	}
}

// TestAuditAll_CrossDomain_IndependentSeverities verifies that the three AWS
// domain engines each contribute their own findings independently to the
// unified report, and that no cross-domain severity escalation occurs.
//
// The same EBS volume (vol-00112233) appears as:
//   - cost domain:           MEDIUM (GP2 legacy volume — inefficient)
//   - dataprotection domain: HIGH   (unencrypted at rest)
//
// After the fix: both findings must appear at their original severities.
// Before the fix: the cross-domain merge would escalate the MEDIUM to HIGH.
func TestAuditAll_CrossDomain_IndependentSeverities(t *testing.T) {
	vol := "vol-00112233"
	region := "ap-southeast-1"

	costFindings := []models.Finding{
		newFinding(vol, region, "EBS_GP2_LEGACY", models.SeverityMedium, 3.0),
	}
	dpFindings := []models.Finding{
		newFinding(vol, region, "EBS_UNENCRYPTED", models.SeverityHigh, 0.0),
	}

	eng := newAllAWSEngine(
		domainReportWith("cost", costFindings),
		emptyDomainReport("security", "test", "111122223333", []string{region}),
		domainReportWith("dataprotection", dpFindings),
		nil,
	)

	report, _, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Two independent findings — one per domain.
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings (one per domain); got %d — cross-domain escalation may have occurred", len(report.Findings))
	}

	sevByRule := make(map[string]models.Severity, 2)
	for _, f := range report.Findings {
		sevByRule[f.RuleID] = f.Severity
	}

	// Cost finding: must remain MEDIUM regardless of the DP finding.
	if sevByRule["EBS_GP2_LEGACY"] != models.SeverityMedium {
		t.Errorf("EBS_GP2_LEGACY severity = %q; want MEDIUM (must not be escalated by DP domain)", sevByRule["EBS_GP2_LEGACY"])
	}
	// DP finding: must remain HIGH.
	if sevByRule["EBS_UNENCRYPTED"] != models.SeverityHigh {
		t.Errorf("EBS_UNENCRYPTED severity = %q; want HIGH", sevByRule["EBS_UNENCRYPTED"])
	}
}
