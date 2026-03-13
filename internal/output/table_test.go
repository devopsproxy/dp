package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/output"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func renderToString(findings []models.Finding, opts output.TableOptions) string {
	var buf bytes.Buffer
	output.RenderTable(&buf, findings, opts)
	return buf.String()
}

func oneFinding(overrides ...func(*models.Finding)) models.Finding {
	f := models.Finding{
		ResourceID:              "i-0123456789abcdef0",
		ResourceType:            models.ResourceAWSEC2,
		Region:                  "us-east-1",
		Profile:                 "prod",
		Domain:                  "cost",
		Severity:                models.SeverityHigh,
		EstimatedMonthlySavings: 42.00,
		Explanation:             "Instance CPU utilisation has been below 5% for 30 days.",
	}
	for _, fn := range overrides {
		fn(&f)
	}
	return f
}

// ── PROFILE column ────────────────────────────────────────────────────────────

func TestRenderTable_ProfileColumn_WhenEnabled(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		IncludeProfile: true,
	})
	if !strings.Contains(out, "PROFILE") {
		t.Errorf("expected PROFILE column header in output\ngot:\n%s", out)
	}
	if !strings.Contains(out, "prod") {
		t.Errorf("expected profile value 'prod' in output\ngot:\n%s", out)
	}
}

func TestRenderTable_ProfileColumn_WhenDisabled(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		IncludeProfile: false,
	})
	if strings.Contains(out, "PROFILE") {
		t.Errorf("PROFILE column must not appear when IncludeProfile=false\ngot:\n%s", out)
	}
}

// ── DOMAIN column ─────────────────────────────────────────────────────────────

func TestRenderTable_DomainColumn_WhenEnabled(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		IncludeDomain: true,
	})
	if !strings.Contains(out, "DOMAIN") {
		t.Errorf("expected DOMAIN column header in output\ngot:\n%s", out)
	}
	if !strings.Contains(out, "cost") {
		t.Errorf("expected domain value 'cost' in output\ngot:\n%s", out)
	}
}

func TestRenderTable_DomainColumn_WhenDisabled(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		IncludeDomain: false,
	})
	if strings.Contains(out, "DOMAIN") {
		t.Errorf("DOMAIN column must not appear when IncludeDomain=false\ngot:\n%s", out)
	}
}

// ── SAVINGS/MO column ─────────────────────────────────────────────────────────

func TestRenderTable_SavingsColumn_AppearsWhenIncludeSavingsAndNonZero(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		IncludeSavings: true,
	})
	if !strings.Contains(out, "SAVINGS/MO") {
		t.Errorf("expected SAVINGS/MO header when IncludeSavings=true and savings > 0\ngot:\n%s", out)
	}
	if !strings.Contains(out, "$42.00") {
		t.Errorf("expected savings value $42.00\ngot:\n%s", out)
	}
}

func TestRenderTable_SavingsColumn_AbsentWhenIncludeSavingsFalse(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		IncludeSavings: false,
	})
	if strings.Contains(out, "SAVINGS/MO") {
		t.Errorf("SAVINGS/MO must not appear when IncludeSavings=false\ngot:\n%s", out)
	}
}

func TestRenderTable_SavingsColumn_AbsentWhenAllSavingsZero(t *testing.T) {
	f := oneFinding(func(f *models.Finding) { f.EstimatedMonthlySavings = 0 })
	out := renderToString([]models.Finding{f}, output.TableOptions{
		IncludeSavings: true,
	})
	if strings.Contains(out, "SAVINGS/MO") {
		t.Errorf("SAVINGS/MO must not appear when all findings have zero savings\ngot:\n%s", out)
	}
}

// ── message shortening ────────────────────────────────────────────────────────

func TestRenderTable_MessageIsTruncatedWhenTooLong(t *testing.T) {
	long := strings.Repeat("x", 100) // 100 chars, exceeds wMessage=55
	f := oneFinding(func(f *models.Finding) { f.Explanation = long })
	out := renderToString([]models.Finding{f}, output.TableOptions{})

	if strings.Contains(out, long) {
		t.Errorf("full 100-char message must not appear verbatim in output\ngot:\n%s", out)
	}
	if !strings.Contains(out, "...") {
		t.Errorf("truncated message must end with ellipsis\ngot:\n%s", out)
	}
}

func TestRenderTable_ShortMessageIsNotTruncated(t *testing.T) {
	short := "Short explanation."
	f := oneFinding(func(f *models.Finding) { f.Explanation = short })
	out := renderToString([]models.Finding{f}, output.TableOptions{})

	if !strings.Contains(out, short) {
		t.Errorf("short message must appear verbatim\ngot:\n%s", out)
	}
}

// ── empty findings ────────────────────────────────────────────────────────────

func TestRenderTable_EmptyFindings_PrintsNoFindings(t *testing.T) {
	out := renderToString(nil, output.TableOptions{})
	if !strings.Contains(out, "No findings.") {
		t.Errorf("expected 'No findings.' for empty slice\ngot:\n%s", out)
	}
}

func TestRenderTable_EmptyFindings_NoColumnHeaders(t *testing.T) {
	out := renderToString(nil, output.TableOptions{})
	if strings.Contains(out, "RESOURCE ID") {
		t.Errorf("column headers must not appear for empty findings\ngot:\n%s", out)
	}
}

// ── color mode ────────────────────────────────────────────────────────────────

func TestRenderTable_ColoredFalse_NoAnsiCodes(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		Colored: false,
	})
	if strings.Contains(out, "\033[") {
		t.Errorf("no ANSI codes must appear when Colored=false\ngot (hex): %q", out)
	}
}

func TestRenderTable_ColoredTrue_HasAnsiCodes(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		Colored: true,
	})
	if !strings.Contains(out, "\033[") {
		t.Errorf("ANSI codes expected when Colored=true\ngot:\n%s", out)
	}
}

// ── location label ────────────────────────────────────────────────────────────

func TestRenderTable_LocationLabel_DefaultsToRegion(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{})
	if !strings.Contains(out, "REGION") {
		t.Errorf("default location label must be REGION\ngot:\n%s", out)
	}
}

func TestRenderTable_LocationLabel_ContextForKubernetes(t *testing.T) {
	f := oneFinding(func(f *models.Finding) { f.Region = "my-cluster" })
	out := renderToString([]models.Finding{f}, output.TableOptions{
		LocationLabel: "CONTEXT",
	})
	if !strings.Contains(out, "CONTEXT") {
		t.Errorf("location label must be CONTEXT when set\ngot:\n%s", out)
	}
	if !strings.Contains(out, "my-cluster") {
		t.Errorf("cluster name must appear in CONTEXT column\ngot:\n%s", out)
	}
}

// ── ShortenMessage unit tests ─────────────────────────────────────────────────

func TestShortenMessage_ShortString_Unchanged(t *testing.T) {
	s := "hello"
	got := output.ShortenMessage(s, 80)
	if got != s {
		t.Errorf("got %q; want %q", got, s)
	}
}

func TestShortenMessage_ExactLength_Unchanged(t *testing.T) {
	s := strings.Repeat("a", 80)
	got := output.ShortenMessage(s, 80)
	if got != s {
		t.Errorf("string of exact max length must not be truncated")
	}
}

func TestShortenMessage_TooLong_TruncatedWithEllipsis(t *testing.T) {
	s := strings.Repeat("a", 100)
	got := output.ShortenMessage(s, 80)
	if len([]rune(got)) != 80 {
		t.Errorf("truncated string should be 80 runes, got %d", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncated string must end with '...', got %q", got)
	}
}

func TestShortenMessage_VerySmallMax_DoesNotPanic(t *testing.T) {
	s := "hello world"
	// max < 4 should not panic; implementation treats it as 4
	got := output.ShortenMessage(s, 2)
	if got == "" {
		t.Error("ShortenMessage with tiny max must return non-empty string")
	}
}

// ── combined column set ───────────────────────────────────────────────────────

func TestRenderTable_AllColumns_AllPresent(t *testing.T) {
	out := renderToString([]models.Finding{oneFinding()}, output.TableOptions{
		Colored:        false,
		IncludeSavings: true,
		IncludeDomain:  true,
		IncludeProfile: true,
		LocationLabel:  "REGION",
	})
	for _, want := range []string{"RESOURCE ID", "PROFILE", "REGION", "SEVERITY", "DOMAIN", "TYPE", "MESSAGE", "SAVINGS/MO"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected column %q in output\ngot:\n%s", want, out)
		}
	}
}

func TestRenderTable_BaseColumnsOnly_NoneOptional(t *testing.T) {
	f := oneFinding(func(f *models.Finding) { f.EstimatedMonthlySavings = 0 })
	out := renderToString([]models.Finding{f}, output.TableOptions{
		Colored:        false,
		IncludeSavings: false,
		IncludeDomain:  false,
		IncludeProfile: false,
		LocationLabel:  "REGION",
	})
	for _, absent := range []string{"PROFILE", "DOMAIN", "SAVINGS/MO"} {
		if strings.Contains(out, absent) {
			t.Errorf("column %q must not appear in base-only mode\ngot:\n%s", absent, out)
		}
	}
	for _, want := range []string{"RESOURCE ID", "REGION", "SEVERITY", "TYPE", "MESSAGE"} {
		if !strings.Contains(out, want) {
			t.Errorf("base column %q must always appear\ngot:\n%s", want, out)
		}
	}
}
