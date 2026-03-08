package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	kube "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/kubernetes"
)

// ── kubernetes inspect test helpers ──────────────────────────────────────────

// testKubeProvider implements kube.KubeClientProvider backed by a pre-built
// fake clientset. It records the context name passed to ClientsetForContext so
// tests can assert the flag is forwarded correctly.
type testKubeProvider struct {
	clientset      k8sclient.Interface
	info           kube.ClusterInfo
	calledWithCtx  string
}

func (p *testKubeProvider) ClientsetForContext(contextName string) (k8sclient.Interface, kube.ClusterInfo, error) {
	p.calledWithCtx = contextName
	return p.clientset, p.info, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func makeReport(findings []models.Finding) *models.AuditReport {
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
	return &models.AuditReport{
		ReportID:    "audit-test",
		GeneratedAt: time.Now().UTC(),
		AuditType:   "cost",
		Profile:     "staging",
		AccountID:   "111122223333",
		Regions:     []string{"us-east-1", "eu-west-1"},
		Summary:     s,
		Findings:    findings,
	}
}

func capture(fn func(w *bytes.Buffer)) string {
	var buf bytes.Buffer
	fn(&buf)
	return buf.String()
}

// ── printSummary ─────────────────────────────────────────────────────────────

func TestPrintSummary_Header(t *testing.T) {
	report := makeReport(nil)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	for _, want := range []string{"111122223333", "staging", "2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, out)
		}
	}
}

func TestPrintSummary_TotalsAndSavings(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "vol-1", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 8.00},
		{ResourceID: "vol-2", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 30.00},
		{ResourceID: "i-1", Region: "eu-west-1", Severity: models.SeverityHigh, EstimatedMonthlySavings: 50.00},
	}
	report := makeReport(findings)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	if !strings.Contains(out, "3") {
		t.Errorf("output missing total findings count 3\ngot:\n%s", out)
	}
	if !strings.Contains(out, "88.00") {
		t.Errorf("output missing total savings 88.00\ngot:\n%s", out)
	}
}

func TestPrintSummary_SeverityBreakdown(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "r-1", Severity: models.SeverityCritical, EstimatedMonthlySavings: 100},
		{ResourceID: "r-2", Severity: models.SeverityHigh, EstimatedMonthlySavings: 50},
		{ResourceID: "r-3", Severity: models.SeverityHigh, EstimatedMonthlySavings: 50},
		{ResourceID: "r-4", Severity: models.SeverityMedium, EstimatedMonthlySavings: 30},
		{ResourceID: "r-5", Severity: models.SeverityLow, EstimatedMonthlySavings: 8},
	}
	report := makeReport(findings)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	for _, label := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if !strings.Contains(out, label) {
			t.Errorf("output missing severity label %q\ngot:\n%s", label, out)
		}
	}
}

func TestPrintSummary_NoFindings_SkipsTopTable(t *testing.T) {
	report := makeReport(nil)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	if strings.Contains(out, "Top Findings") {
		t.Errorf("empty report must not print Top Findings section\ngot:\n%s", out)
	}
}

func TestPrintSummary_TopFindingsPresent(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "vol-cheap", Region: "us-east-1", Severity: models.SeverityLow, EstimatedMonthlySavings: 2.00},
		{ResourceID: "i-expensive", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 30.00},
		{ResourceID: "vol-mid", Region: "eu-west-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 8.00},
	}
	report := makeReport(findings)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	if !strings.Contains(out, "Top Findings") {
		t.Errorf("output missing Top Findings section\ngot:\n%s", out)
	}
	// Most expensive finding must appear; cheapest must also appear (only 3 findings < 5).
	if !strings.Contains(out, "i-expensive") {
		t.Errorf("output missing top-savings resource i-expensive\ngot:\n%s", out)
	}
	if !strings.Contains(out, "vol-cheap") {
		t.Errorf("output missing vol-cheap (fewer than 5 findings total)\ngot:\n%s", out)
	}
}

func TestPrintSummary_TopFindingsCappedAtFive(t *testing.T) {
	findings := make([]models.Finding, 8)
	for i := range findings {
		findings[i] = models.Finding{
			ResourceID:              fmt.Sprintf("vol-%02d", i),
			Region:                  "us-east-1",
			Severity:                models.SeverityLow,
			EstimatedMonthlySavings: float64(i + 1),
		}
	}
	report := makeReport(findings)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	// The 3 lowest-savings resources (vol-00, vol-01, vol-02) must NOT appear.
	for _, absent := range []string{"vol-00", "vol-01", "vol-02"} {
		if strings.Contains(out, absent) {
			t.Errorf("output must not contain %q (outside top-5)\ngot:\n%s", absent, out)
		}
	}
	// Top resource by savings is vol-07 (savings=8).
	if !strings.Contains(out, "vol-07") {
		t.Errorf("output missing highest-savings resource vol-07\ngot:\n%s", out)
	}
}

// ── topFindingsBySavings ─────────────────────────────────────────────────────

func TestTopFindingsBySavings_Empty(t *testing.T) {
	got := topFindingsBySavings(nil, 5)
	if len(got) != 0 {
		t.Errorf("want 0, got %d", len(got))
	}
}

func TestTopFindingsBySavings_FewerThanN(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "a", EstimatedMonthlySavings: 10},
		{ResourceID: "b", EstimatedMonthlySavings: 5},
	}
	got := topFindingsBySavings(findings, 5)
	if len(got) != 2 {
		t.Errorf("want 2, got %d", len(got))
	}
}

func TestTopFindingsBySavings_ReturnsTopN(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "low", EstimatedMonthlySavings: 1},
		{ResourceID: "high", EstimatedMonthlySavings: 100},
		{ResourceID: "mid", EstimatedMonthlySavings: 50},
		{ResourceID: "mid2", EstimatedMonthlySavings: 30},
	}
	got := topFindingsBySavings(findings, 2)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	if got[0].ResourceID != "high" {
		t.Errorf("position 0: got %q; want high", got[0].ResourceID)
	}
	if got[1].ResourceID != "mid" {
		t.Errorf("position 1: got %q; want mid", got[1].ResourceID)
	}
}

func TestTopFindingsBySavings_SortedDescending(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "a", EstimatedMonthlySavings: 5},
		{ResourceID: "b", EstimatedMonthlySavings: 50},
		{ResourceID: "c", EstimatedMonthlySavings: 20},
		{ResourceID: "d", EstimatedMonthlySavings: 80},
		{ResourceID: "e", EstimatedMonthlySavings: 10},
	}
	got := topFindingsBySavings(findings, 5)
	for i := 1; i < len(got); i++ {
		if got[i].EstimatedMonthlySavings > got[i-1].EstimatedMonthlySavings {
			t.Errorf("not sorted desc at position %d: %.2f > %.2f",
				i, got[i].EstimatedMonthlySavings, got[i-1].EstimatedMonthlySavings)
		}
	}
}

func TestTopFindingsBySavings_DoesNotMutateInput(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "a", EstimatedMonthlySavings: 1},
		{ResourceID: "b", EstimatedMonthlySavings: 100},
	}
	topFindingsBySavings(findings, 2)
	// Original order must be preserved.
	if findings[0].ResourceID != "a" || findings[1].ResourceID != "b" {
		t.Error("topFindingsBySavings must not modify the input slice")
	}
}

// ── writeReportToFile ─────────────────────────────────────────────────────────

func TestWriteReportToFile_Success(t *testing.T) {
	report := makeReport(nil)
	path := filepath.Join(t.TempDir(), "report.json")

	if err := writeReportToFile(path, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestWriteReportToFile_InvalidPath(t *testing.T) {
	report := makeReport(nil)
	// Directory does not exist — write must fail.
	path := filepath.Join(t.TempDir(), "nonexistent", "report.json")

	if err := writeReportToFile(path, report); err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

func TestWriteReportToFile_ContentMatchesJSON(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "vol-abc", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 16.00},
	}
	report := makeReport(findings)
	path := filepath.Join(t.TempDir(), "report.json")

	if err := writeReportToFile(path, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	var got models.AuditReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.AccountID != report.AccountID {
		t.Errorf("account_id: got %q; want %q", got.AccountID, report.AccountID)
	}
	if got.Profile != report.Profile {
		t.Errorf("profile: got %q; want %q", got.Profile, report.Profile)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings count: got %d; want 1", len(got.Findings))
	}
	if got.Findings[0].ResourceID != "vol-abc" {
		t.Errorf("finding resource_id: got %q; want vol-abc", got.Findings[0].ResourceID)
	}
	if got.Summary.TotalEstimatedMonthlySavings != 16.00 {
		t.Errorf("savings: got %.2f; want 16.00", got.Summary.TotalEstimatedMonthlySavings)
	}
}

// ── runKubernetesInspect ──────────────────────────────────────────────────────

// TestRunKubernetesInspect_Output verifies that all four fields (Context,
// API Server, Nodes, Namespaces) appear in the output with the correct values.
func TestRunKubernetesInspect_Output(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "staging"}},
	)
	provider := &testKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "dev-cluster", Server: "https://192.168.1.100:6443"},
	}

	var buf bytes.Buffer
	if err := runKubernetesInspect(context.Background(), provider, "", &buf); err != nil {
		t.Fatalf("runKubernetesInspect error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"dev-cluster",
		"https://192.168.1.100:6443",
		"2",  // node count
		"3",  // namespace count
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, out)
		}
	}
}

// ── newKubernetesAuditCmd flags ───────────────────────────────────────────────

// TestKubernetesAuditCmd_ExcludeSystemFlag_Registered verifies that the
// --exclude-system flag is declared on the kubernetes audit command with the
// correct default value (false).
func TestKubernetesAuditCmd_ExcludeSystemFlag_Registered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("exclude-system")
	if flag == nil {
		t.Fatal("--exclude-system flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "false" {
		t.Errorf("--exclude-system default = %q; want false", flag.DefValue)
	}
}

// TestKubernetesAuditCmd_ExcludeSystemFlag_Type verifies the flag is a bool.
func TestKubernetesAuditCmd_ExcludeSystemFlag_Type(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("exclude-system")
	if flag == nil {
		t.Fatal("--exclude-system flag not registered")
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("--exclude-system flag type = %q; want bool", flag.Value.Type())
	}
}

// TestKubernetesAuditCmd_ShowRiskChainsFlag_Registered verifies that the
// --show-risk-chains flag is declared on the kubernetes audit command with the
// correct default value (false).
func TestKubernetesAuditCmd_ShowRiskChainsFlag_Registered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("show-risk-chains")
	if flag == nil {
		t.Fatal("--show-risk-chains flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "false" {
		t.Errorf("--show-risk-chains default = %q; want false", flag.DefValue)
	}
}

// TestKubernetesAuditCmd_ShowRiskChainsFlag_Type verifies the flag is a bool.
func TestKubernetesAuditCmd_ShowRiskChainsFlag_Type(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("show-risk-chains")
	if flag == nil {
		t.Fatal("--show-risk-chains flag not registered")
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("--show-risk-chains flag type = %q; want bool", flag.Value.Type())
	}
}

// TestRunKubernetesInspect_ContextForwarded verifies that the --context flag
// value is passed through to the KubeClientProvider unchanged.
func TestRunKubernetesInspect_ContextForwarded(t *testing.T) {
	provider := &testKubeProvider{
		clientset: fake.NewSimpleClientset(),
		info:      kube.ClusterInfo{},
	}

	var buf bytes.Buffer
	if err := runKubernetesInspect(context.Background(), provider, "my-context", &buf); err != nil {
		t.Fatalf("runKubernetesInspect error: %v", err)
	}

	if provider.calledWithCtx != "my-context" {
		t.Errorf("provider called with context %q; want my-context", provider.calledWithCtx)
	}
}

// ── renderKubernetesAuditOutput ───────────────────────────────────────────────

// TestRenderKubernetesAuditOutput_JSONMode_PureJSON verifies that in JSON mode
// stdout begins with '{' and does not contain any banner lines.
func TestRenderKubernetesAuditOutput_JSONMode_PureJSON(t *testing.T) {
	report := makeReport([]models.Finding{
		{ResourceID: "pod-1", Severity: models.SeverityCritical},
	})
	report.Profile = "my-cluster"

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON output must start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Context:", "Profile:", "Findings:"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain %q; got non-empty match", banned)
		}
	}
}

// TestRenderKubernetesAuditOutput_JSONMode_SummaryIgnored verifies that JSON
// mode takes priority over --summary: output must still be pure JSON.
func TestRenderKubernetesAuditOutput_JSONMode_SummaryIgnored(t *testing.T) {
	report := makeReport(nil)
	report.Profile = "my-cluster"

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", true, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON mode with summary=true must still start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Context:", "Profile:", "Findings:", "CRITICAL", "Severity"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain human-readable banner %q", banned)
		}
	}
}

// TestRenderKubernetesAuditOutput_JSONMode_IsValidJSON verifies the output
// parses cleanly as an AuditReport.
func TestRenderKubernetesAuditOutput_JSONMode_IsValidJSON(t *testing.T) {
	report := makeReport([]models.Finding{
		{ResourceID: "pod-1", Severity: models.SeverityHigh},
	})

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
}

// TestRenderKubernetesAuditOutput_TableMode_ContextPresent verifies that in
// table mode the "Context:" banner is written to the output.
func TestRenderKubernetesAuditOutput_TableMode_ContextPresent(t *testing.T) {
	report := makeReport(nil)
	report.Profile = "prod-cluster"

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Context:") {
		t.Errorf("table output must contain 'Context:'; got:\n%s", out)
	}
	if !strings.Contains(out, "prod-cluster") {
		t.Errorf("table output must contain cluster name; got:\n%s", out)
	}
}

// TestRenderKubernetesAuditOutput_ShowRiskChains_NoChains_FallbackMessage verifies
// that when showRiskChains=true but no chains are present, the output contains
// the fallback message "No risk chains detected."
func TestRenderKubernetesAuditOutput_ShowRiskChains_NoChains_FallbackMessage(t *testing.T) {
	report := makeReport([]models.Finding{
		{ID: "f1", ResourceID: "ns-1", Severity: models.SeverityMedium},
	})
	report.Profile = "test-cluster"
	// No RiskChains populated (ShowRiskChains was false in the engine or no chain fired).

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No risk chains detected.") {
		t.Errorf("output should contain fallback message; got:\n%s", out)
	}
}

// TestRenderKubernetesAuditOutput_ShowRiskChains_ChainHeader verifies that when
// RiskChains are present and showRiskChains=true, the output contains chain
// headers with the score and reason.
func TestRenderKubernetesAuditOutput_ShowRiskChains_ChainHeader(t *testing.T) {
	report := makeReport([]models.Finding{
		{
			ID:         "f1",
			ResourceID: "web-svc",
			Severity:   models.SeverityHigh,
			Metadata: map[string]any{
				"risk_chain_score":  80,
				"risk_chain_reason": "Public service exposes privileged workload",
			},
		},
	})
	report.Profile = "test-cluster"
	report.Summary.RiskChains = []models.RiskChain{
		{Score: 80, Reason: "Public service exposes privileged workload", FindingIDs: []string{"f1"}},
	}

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "RISK CHAIN (Score: 80)") {
		t.Errorf("output should contain chain header; got:\n%s", out)
	}
	if !strings.Contains(out, "Public service exposes privileged workload") {
		t.Errorf("output should contain chain reason; got:\n%s", out)
	}
}

// TestRenderKubernetesAuditOutput_ShowRiskChains_JSON_RiskChainsIncluded verifies
// that in JSON mode with risk_chains populated, the JSON output contains the
// risk_chains field.
func TestRenderKubernetesAuditOutput_ShowRiskChains_JSON_RiskChainsIncluded(t *testing.T) {
	report := makeReport(nil)
	report.Profile = "test-cluster"
	report.Summary.RiskChains = []models.RiskChain{
		{Score: 95, Reason: "Cluster lacks OIDC provider and has high-risk workload findings.", FindingIDs: []string{"oidc-f1"}},
	}

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"risk_chains"`) {
		t.Errorf("JSON output should contain risk_chains field; got:\n%s", out)
	}
	if !strings.Contains(out, `"score": 95`) {
		t.Errorf("JSON output should contain chain score 95; got:\n%s", out)
	}
}

// TestRenderKubernetesAuditOutput_ShowRiskChains_OtherFindings verifies that
// findings not part of any chain are listed under "Other Findings".
func TestRenderKubernetesAuditOutput_ShowRiskChains_OtherFindings(t *testing.T) {
	report := makeReport([]models.Finding{
		{
			ID:         "chain-f",
			ResourceID: "web-svc",
			Severity:   models.SeverityHigh,
		},
		{
			ID:         "other-f",
			ResourceID: "lone-finding",
			Severity:   models.SeverityMedium,
		},
	})
	report.Profile = "test-cluster"
	report.Summary.RiskChains = []models.RiskChain{
		{Score: 80, Reason: "some chain", FindingIDs: []string{"chain-f"}},
	}

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Other Findings") {
		t.Errorf("output should contain 'Other Findings' section for unchained finding; got:\n%s", out)
	}
}

// ── Phase 6: attack path render tests ────────────────────────────────────────

// TestRenderRiskChainTable_AttackPathBeforeChain verifies that ATTACK PATH
// sections appear before RISK CHAIN sections in table output.
func TestRenderRiskChainTable_AttackPathBeforeChain(t *testing.T) {
	report := makeReport([]models.Finding{
		{ID: "f1", ResourceID: "web-svc", Severity: models.SeverityHigh},
		{ID: "f2", ResourceID: "priv-pod", Severity: models.SeverityHigh},
	})
	report.Profile = "test-cluster"
	report.Summary.AttackPaths = []models.AttackPath{
		{
			Score:       98,
			Description: "Externally exposed privileged workload with weak identity isolation.",
			Layers:      []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs:  []string{"f1", "f2"},
		},
	}
	report.Summary.RiskChains = []models.RiskChain{
		{Score: 80, Reason: "Public service exposes privileged workload", FindingIDs: []string{"f1", "f2"}},
	}

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	attackPos := strings.Index(out, "ATTACK PATH")
	chainPos := strings.Index(out, "RISK CHAIN")

	if attackPos < 0 {
		t.Error("expected 'ATTACK PATH' in output")
	}
	if chainPos < 0 {
		t.Error("expected 'RISK CHAIN' in output")
	}
	if attackPos > chainPos {
		t.Errorf("expected ATTACK PATH (pos %d) to appear before RISK CHAIN (pos %d)", attackPos, chainPos)
	}
}

// TestRenderRiskChainTable_AttackPathContent verifies score, description, and
// layer line are rendered correctly in table output.
func TestRenderRiskChainTable_AttackPathContent(t *testing.T) {
	report := makeReport([]models.Finding{
		{ID: "f1", ResourceID: "cluster", Severity: models.SeverityCritical},
	})
	report.Profile = "test-cluster"
	report.Summary.AttackPaths = []models.AttackPath{
		{
			Score:       90,
			Description: "Cluster governance protections disabled with no redundancy.",
			Layers:      []string{"Encryption Disabled", "Logging Disabled", "No Redundancy"},
			FindingIDs:  []string{"f1"},
		},
	}

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"ATTACK PATH (Score: 90)",
		"Cluster governance protections disabled with no redundancy.",
		"Encryption Disabled → Logging Disabled → No Redundancy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output; got:\n%s", want, out)
		}
	}
}

// TestRenderRiskChainTable_OnlyAttackPaths verifies rendering when attack paths
// are present but no risk chains.
func TestRenderRiskChainTable_OnlyAttackPaths(t *testing.T) {
	report := makeReport([]models.Finding{
		{ID: "f1", ResourceID: "svc", Severity: models.SeverityHigh},
	})
	report.Profile = "test-cluster"
	report.Summary.AttackPaths = []models.AttackPath{
		{
			Score:       98,
			Description: "Externally exposed privileged workload with weak identity isolation.",
			Layers:      []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs:  []string{"f1"},
		},
	}
	// RiskChains intentionally nil.

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "ATTACK PATH") {
		t.Error("expected 'ATTACK PATH' in output")
	}
	if strings.Contains(out, "RISK CHAIN") {
		t.Error("unexpected 'RISK CHAIN' when no chains present")
	}
	if strings.Contains(out, "No risk chains detected.") {
		t.Error("unexpected 'No risk chains detected.' when attack paths are present")
	}
}

// TestRenderRiskChainTable_AttackPaths_JSON_Included verifies that attack_paths
// appear in JSON output when present.
func TestRenderRiskChainTable_AttackPaths_JSON_Included(t *testing.T) {
	report := makeReport(nil)
	report.Profile = "test-cluster"
	report.Summary.AttackPaths = []models.AttackPath{
		{
			Score:       98,
			Description: "Externally exposed privileged workload with weak identity isolation.",
			Layers:      []string{"Network Exposure", "Workload Privilege", "Identity Weakness"},
			FindingIDs:  []string{},
		},
	}

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `"attack_paths"`) {
		t.Errorf("JSON output should contain attack_paths field; got:\n%s", out)
	}
	if !strings.Contains(out, `"score": 98`) {
		t.Errorf("JSON output should contain score 98; got:\n%s", out)
	}
	if !strings.Contains(out, "Externally exposed privileged workload with weak identity isolation.") {
		t.Errorf("JSON output should contain attack path description; got:\n%s", out)
	}
}

// ── renderAWSCostOutput ───────────────────────────────────────────────────────

// TestRenderAWSCostOutput_JSONMode_PureJSON verifies that JSON mode produces
// no banner lines — only the JSON payload.
func TestRenderAWSCostOutput_JSONMode_PureJSON(t *testing.T) {
	report := makeReport([]models.Finding{
		{ResourceID: "vol-1", Region: "us-east-1", Severity: models.SeverityHigh},
	})

	var buf bytes.Buffer
	if err := renderAWSCostOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON output must start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Profile:", "Findings:", "Savings"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain banner text %q", banned)
		}
	}
}

// TestRenderAWSCostOutput_JSONMode_SummaryIgnored verifies that JSON mode takes
// priority when --summary is also set.
func TestRenderAWSCostOutput_JSONMode_SummaryIgnored(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSCostOutput(&buf, report, "json", true, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON mode with summary=true must still start with '{'; got: %.40s", out)
	}
}

// TestRenderAWSCostOutput_JSONMode_IsValidJSON verifies the output is parseable.
func TestRenderAWSCostOutput_JSONMode_IsValidJSON(t *testing.T) {
	report := makeReport([]models.Finding{
		{ResourceID: "vol-1", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 8.0},
	})

	var buf bytes.Buffer
	if err := renderAWSCostOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
	if len(got.Findings) != 1 || got.Findings[0].ResourceID != "vol-1" {
		t.Errorf("findings not preserved in JSON; got: %+v", got.Findings)
	}
}

// TestRenderAWSCostOutput_TableMode_ProfilePresent verifies that in table mode
// the "Profile:" banner is written to the output.
func TestRenderAWSCostOutput_TableMode_ProfilePresent(t *testing.T) {
	report := makeReport(nil)
	// report.Profile is set by makeReport to "staging"

	var buf bytes.Buffer
	if err := renderAWSCostOutput(&buf, report, "table", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Profile:") {
		t.Errorf("table output must contain 'Profile:'; got:\n%s", out)
	}
	if !strings.Contains(out, "staging") {
		t.Errorf("table output must contain profile name; got:\n%s", out)
	}
}

// ── renderAWSSecurityOutput ───────────────────────────────────────────────────

// TestRenderAWSSecurityOutput_JSONMode_PureJSON verifies that JSON mode for
// the security command produces no banner text.
func TestRenderAWSSecurityOutput_JSONMode_PureJSON(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSSecurityOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON output must start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Profile:", "Findings:"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain banner text %q", banned)
		}
	}
}

// TestRenderAWSSecurityOutput_JSONMode_SummaryIgnored verifies JSON takes priority.
func TestRenderAWSSecurityOutput_JSONMode_SummaryIgnored(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSSecurityOutput(&buf, report, "json", true, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Errorf("JSON mode with summary=true must still start with '{'")
	}
}

// ── renderAWSDataProtectionOutput ────────────────────────────────────────────

// TestRenderAWSDataProtectionOutput_JSONMode_PureJSON verifies that JSON mode
// for the data-protection command produces no banner text.
func TestRenderAWSDataProtectionOutput_JSONMode_PureJSON(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSDataProtectionOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON output must start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Profile:", "Findings:"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain banner text %q", banned)
		}
	}
}

// TestRenderAWSDataProtectionOutput_JSONMode_SummaryIgnored verifies JSON priority.
func TestRenderAWSDataProtectionOutput_JSONMode_SummaryIgnored(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSDataProtectionOutput(&buf, report, "json", true, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Errorf("JSON mode with summary=true must still start with '{'")
	}
}

// ── hasCriticalOrHighFindings ─────────────────────────────────────────────────

// TestHasCriticalOrHighFindings_NilFindings verifies that nil input returns false.
func TestHasCriticalOrHighFindings_NilFindings(t *testing.T) {
	if hasCriticalOrHighFindings(nil) {
		t.Error("hasCriticalOrHighFindings(nil) = true; want false")
	}
}

// TestHasCriticalOrHighFindings_EmptySlice verifies that an empty slice returns false.
func TestHasCriticalOrHighFindings_EmptySlice(t *testing.T) {
	if hasCriticalOrHighFindings([]models.Finding{}) {
		t.Error("hasCriticalOrHighFindings([]) = true; want false")
	}
}

// TestHasCriticalOrHighFindings_OnlyLowMedium verifies that only LOW/MEDIUM
// findings return false (exit code 0 — no alert).
func TestHasCriticalOrHighFindings_OnlyLowMedium(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "r-1", Severity: models.SeverityLow},
		{ResourceID: "r-2", Severity: models.SeverityMedium},
	}
	if hasCriticalOrHighFindings(findings) {
		t.Error("hasCriticalOrHighFindings(LOW+MEDIUM only) = true; want false")
	}
}

// TestHasCriticalOrHighFindings_CriticalPresent verifies that a CRITICAL finding
// returns true — the exit-code-1 path must trigger.
func TestHasCriticalOrHighFindings_CriticalPresent(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "r-1", Severity: models.SeverityMedium},
		{ResourceID: "r-2", Severity: models.SeverityCritical},
	}
	if !hasCriticalOrHighFindings(findings) {
		t.Error("hasCriticalOrHighFindings with CRITICAL = false; want true")
	}
}

// TestHasCriticalOrHighFindings_HighPresent verifies that a HIGH finding
// returns true — the exit-code-1 path must trigger.
func TestHasCriticalOrHighFindings_HighPresent(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "r-1", Severity: models.SeverityLow},
		{ResourceID: "r-2", Severity: models.SeverityHigh},
	}
	if !hasCriticalOrHighFindings(findings) {
		t.Error("hasCriticalOrHighFindings with HIGH = false; want true")
	}
}

// ── --output / --file flag registration ──────────────────────────────────────
// These tests verify that every audit command declares --output (format, default
// "table") and --file (file path, default "") flags consistently.

// TestCostCmd_OutputFlagRegistered verifies --output flag on dp aws audit cost.
func TestCostCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newCostCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on cost command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestCostCmd_FileFlagRegistered verifies --file flag on dp aws audit cost.
func TestCostCmd_FileFlagRegistered(t *testing.T) {
	cmd := newCostCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on cost command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// TestSecurityCmd_OutputFlagRegistered verifies --output flag on dp aws audit security.
func TestSecurityCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newSecurityCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on security command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestSecurityCmd_FileFlagRegistered verifies --file flag on dp aws audit security.
func TestSecurityCmd_FileFlagRegistered(t *testing.T) {
	cmd := newSecurityCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on security command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// TestDataProtectionCmd_OutputFlagRegistered verifies --output flag on dp aws audit dataprotection.
func TestDataProtectionCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newDataProtectionCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on dataprotection command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestDataProtectionCmd_FileFlagRegistered verifies --file flag on dp aws audit dataprotection.
func TestDataProtectionCmd_FileFlagRegistered(t *testing.T) {
	cmd := newDataProtectionCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on dataprotection command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// TestKubernetesAuditCmd_OutputFlagRegistered verifies --output flag on dp kubernetes audit.
func TestKubernetesAuditCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestKubernetesAuditCmd_FileFlagRegistered verifies --file flag on dp kubernetes audit.
func TestKubernetesAuditCmd_FileFlagRegistered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// TestAuditAllCmd_OutputFlagRegistered verifies --output flag on dp aws audit --all.
func TestAuditAllCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newAuditCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on aws audit command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestAuditAllCmd_FileFlagRegistered verifies --file flag on dp aws audit --all.
func TestAuditAllCmd_FileFlagRegistered(t *testing.T) {
	cmd := newAuditCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on aws audit command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// ── Phase 8: --explain-path flag and validation ───────────────────────────────

// TestCLI_ExplainRequiresShowRiskChains verifies the validateExplainFlags
// helper: --explain-path > 0 without --show-risk-chains must return an error;
// all other combinations must return nil.
func TestCLI_ExplainRequiresShowRiskChains(t *testing.T) {
	// --explain-path set, --show-risk-chains false → must error.
	if err := validateExplainFlags(98, false); err == nil {
		t.Error("validateExplainFlags(98, false) = nil; want non-nil error")
	} else if !strings.Contains(err.Error(), "--explain-path requires --show-risk-chains") {
		t.Errorf("unexpected error message: %q", err.Error())
	}

	// --explain-path set, --show-risk-chains true → no error.
	if err := validateExplainFlags(98, true); err != nil {
		t.Errorf("validateExplainFlags(98, true) = %v; want nil", err)
	}

	// --explain-path zero (not set) → no error regardless of showRiskChains.
	if err := validateExplainFlags(0, false); err != nil {
		t.Errorf("validateExplainFlags(0, false) = %v; want nil", err)
	}
	if err := validateExplainFlags(0, true); err != nil {
		t.Errorf("validateExplainFlags(0, true) = %v; want nil", err)
	}
}

// TestKubernetesAuditCmd_ExplainPathFlag_Registered verifies that the
// --explain-path flag is declared with default value 0 and type int.
func TestKubernetesAuditCmd_ExplainPathFlag_Registered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("explain-path")
	if flag == nil {
		t.Fatal("--explain-path flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "0" {
		t.Errorf("--explain-path default = %q; want 0", flag.DefValue)
	}
	if flag.Value.Type() != "int" {
		t.Errorf("--explain-path type = %q; want int", flag.Value.Type())
	}
}

// ── Phase 9: --min-attack-score flag and validation ───────────────────────────

// TestCLI_MinAttackScoreRequiresShowRiskChains verifies validateMinAttackScoreFlags:
// min > 0 without --show-risk-chains must error; all other combos return nil.
func TestCLI_MinAttackScoreRequiresShowRiskChains(t *testing.T) {
	// min set, showRiskChains false → must error.
	if err := validateMinAttackScoreFlags(95, false); err == nil {
		t.Error("validateMinAttackScoreFlags(95, false) = nil; want non-nil error")
	} else if !strings.Contains(err.Error(), "--min-attack-score requires --show-risk-chains") {
		t.Errorf("unexpected error message: %q", err.Error())
	}

	// min set, showRiskChains true → no error.
	if err := validateMinAttackScoreFlags(95, true); err != nil {
		t.Errorf("validateMinAttackScoreFlags(95, true) = %v; want nil", err)
	}

	// min zero (not set) → no error regardless of showRiskChains.
	if err := validateMinAttackScoreFlags(0, false); err != nil {
		t.Errorf("validateMinAttackScoreFlags(0, false) = %v; want nil", err)
	}
	if err := validateMinAttackScoreFlags(0, true); err != nil {
		t.Errorf("validateMinAttackScoreFlags(0, true) = %v; want nil", err)
	}
}

// TestMinAttackScore_ExplainBelowThreshold verifies explainBelowThreshold:
// returns true only when explain score is set and strictly below the min threshold.
func TestMinAttackScore_ExplainBelowThreshold(t *testing.T) {
	// explain < min → below threshold.
	if !explainBelowThreshold(92, 95) {
		t.Error("explainBelowThreshold(92, 95) = false; want true")
	}

	// explain == min → at threshold (allowed).
	if explainBelowThreshold(95, 95) {
		t.Error("explainBelowThreshold(95, 95) = true; want false (equal is allowed)")
	}

	// explain > min → above threshold (allowed).
	if explainBelowThreshold(96, 95) {
		t.Error("explainBelowThreshold(96, 95) = true; want false")
	}

	// min == 0 (filter disabled) → never below threshold.
	if explainBelowThreshold(92, 0) {
		t.Error("explainBelowThreshold(92, 0) = true; want false (filter disabled)")
	}

	// explain == 0 (not set) → never triggers.
	if explainBelowThreshold(0, 95) {
		t.Error("explainBelowThreshold(0, 95) = true; want false (explain not set)")
	}
}

// TestKubernetesAuditCmd_MinAttackScoreFlag_Registered verifies that the
// --min-attack-score flag is declared with default value 0 and type int.
func TestKubernetesAuditCmd_MinAttackScoreFlag_Registered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("min-attack-score")
	if flag == nil {
		t.Fatal("--min-attack-score flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "0" {
		t.Errorf("--min-attack-score default = %q; want 0", flag.DefValue)
	}
	if flag.Value.Type() != "int" {
		t.Errorf("--min-attack-score type = %q; want int", flag.Value.Type())
	}
}

// TestMinAttackScore_RenderFiltered verifies that renderKubernetesAuditOutput
// only renders attack paths present in the report (i.e. pre-filtered paths).
// When only score-98 path is passed, score-92 must not appear in table output.
func TestMinAttackScore_RenderFiltered(t *testing.T) {
	report := makeReport([]models.Finding{
		{ID: "f1", ResourceID: "svc", Severity: models.SeverityHigh},
		{ID: "f2", ResourceID: "pod", Severity: models.SeverityCritical},
	})
	report.Profile = "test-cluster"
	// Simulate a pre-filtered report: only score-98 path passed to renderer.
	report.Summary.AttackPaths = []models.AttackPath{
		{
			Score:       98,
			Description: "Filtered path at 98",
			Layers:      []string{"L1", "L2"},
			FindingIDs:  []string{"f1"},
		},
	}

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, "ATTACK PATH (Score: 98)") {
		t.Errorf("output missing score-98 path; got:\n%s", out)
	}
	// score-92 was filtered out before render — must not appear.
	if strings.Contains(out, "Score: 92") {
		t.Errorf("output must not contain filtered score-92 path; got:\n%s", out)
	}
}

// TestMinAttackScore_JSONRenderFiltered verifies that when a pre-filtered report
// (only score-98 path) is passed in JSON mode, the JSON attack_paths contains
// only the remaining path and risk_score is unaffected.
func TestMinAttackScore_JSONRenderFiltered(t *testing.T) {
	report := makeReport(nil)
	report.Profile = "test-cluster"
	report.Summary.RiskScore = 98 // set by engine before filtering
	report.Summary.AttackPaths = []models.AttackPath{
		{Score: 98, Description: "desc-98", Layers: []string{"L1"}, FindingIDs: []string{}},
		// score-92 path intentionally excluded to simulate filtering
	}

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", false, false, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\ngot:\n%s", err, buf.String())
	}

	// Only the pre-filtered path must be present.
	if len(got.Summary.AttackPaths) != 1 {
		t.Errorf("JSON attack_paths count = %d; want 1", len(got.Summary.AttackPaths))
	}
	if len(got.Summary.AttackPaths) > 0 && got.Summary.AttackPaths[0].Score != 98 {
		t.Errorf("JSON attack_paths[0].Score = %d; want 98", got.Summary.AttackPaths[0].Score)
	}

	// risk_score must remain 98 (set before filtering by engine).
	if got.Summary.RiskScore != 98 {
		t.Errorf("JSON risk_score = %d; want 98", got.Summary.RiskScore)
	}
}

// ── Phase 10: --attack-graph flag and validation ──────────────────────────────

// TestCLI_AttackGraphRequiresRiskChains verifies that validateAttackGraphFlags
// returns an error when --attack-graph is true but --show-risk-chains is false,
// and returns nil for all other combinations.
func TestCLI_AttackGraphRequiresRiskChains(t *testing.T) {
	// attackGraph=true, showRiskChains=false → must error.
	if err := validateAttackGraphFlags(true, false); err == nil {
		t.Error("validateAttackGraphFlags(true, false) = nil; want non-nil error")
	} else if !strings.Contains(err.Error(), "--attack-graph requires --show-risk-chains") {
		t.Errorf("unexpected error message: %q", err.Error())
	}

	// attackGraph=true, showRiskChains=true → no error.
	if err := validateAttackGraphFlags(true, true); err != nil {
		t.Errorf("validateAttackGraphFlags(true, true) = %v; want nil", err)
	}

	// attackGraph=false → no error regardless of showRiskChains.
	if err := validateAttackGraphFlags(false, false); err != nil {
		t.Errorf("validateAttackGraphFlags(false, false) = %v; want nil", err)
	}
	if err := validateAttackGraphFlags(false, true); err != nil {
		t.Errorf("validateAttackGraphFlags(false, true) = %v; want nil", err)
	}
}

// TestCLI_GraphFormatValidation verifies that validateGraphFormat accepts
// "mermaid" and "graphviz" and rejects everything else.
func TestCLI_GraphFormatValidation(t *testing.T) {
	validFormats := []string{"mermaid", "graphviz"}
	for _, f := range validFormats {
		if err := validateGraphFormat(f); err != nil {
			t.Errorf("validateGraphFormat(%q) = %v; want nil", f, err)
		}
	}

	invalidFormats := []string{"", "dot", "json", "svg", "Mermaid", "GRAPHVIZ"}
	for _, f := range invalidFormats {
		if err := validateGraphFormat(f); err == nil {
			t.Errorf("validateGraphFormat(%q) = nil; want non-nil error", f)
		}
	}
}

// TestKubernetesAuditCmd_AttackGraphFlag_Registered verifies that --attack-graph
// is declared as a bool flag with default value false.
func TestKubernetesAuditCmd_AttackGraphFlag_Registered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("attack-graph")
	if flag == nil {
		t.Fatal("--attack-graph flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "false" {
		t.Errorf("--attack-graph default = %q; want false", flag.DefValue)
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("--attack-graph type = %q; want bool", flag.Value.Type())
	}
}

// TestKubernetesAuditCmd_GraphFormatFlag_Registered verifies that --graph-format
// is declared as a string flag with default value "mermaid".
func TestKubernetesAuditCmd_GraphFormatFlag_Registered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("graph-format")
	if flag == nil {
		t.Fatal("--graph-format flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "mermaid" {
		t.Errorf("--graph-format default = %q; want mermaid", flag.DefValue)
	}
	if flag.Value.Type() != "string" {
		t.Errorf("--graph-format type = %q; want string", flag.Value.Type())
	}
}
