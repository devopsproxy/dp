package engine

import (
	"context"
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// ── stampDomain ───────────────────────────────────────────────────────────────

// TestStampDomain_SetsAllFindings verifies that stampDomain writes the
// provided domain string to every finding in the slice.
func TestStampDomain_SetsAllFindings(t *testing.T) {
	findings := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
		newFinding("vol-2", "us-east-1", "EBS_UNATTACHED", models.SeverityLow, 4.0),
		newFinding("i-1", "eu-west-1", "EC2_LOW_CPU", models.SeverityMedium, 30.0),
	}

	stampDomain(findings, "cost")

	for i, f := range findings {
		if f.Domain != "cost" {
			t.Errorf("findings[%d].Domain = %q; want \"cost\"", i, f.Domain)
		}
	}
}

// TestStampDomain_Empty verifies that stampDomain does not panic on an empty slice.
func TestStampDomain_Empty(t *testing.T) {
	stampDomain(nil, "cost")
	stampDomain([]models.Finding{}, "security")
}

// TestStampDomain_OverwritesExisting verifies that stampDomain overwrites any
// previously set domain value.
func TestStampDomain_OverwritesExisting(t *testing.T) {
	findings := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0),
	}
	findings[0].Domain = "old-value"

	stampDomain(findings, "security")

	if findings[0].Domain != "security" {
		t.Errorf("Domain = %q; want \"security\"", findings[0].Domain)
	}
}

// ── mergeFindings preserves Domain ───────────────────────────────────────────

// TestMergeFindings_PreservesDomainFromFirstFinding verifies that when two
// findings for the same resource are merged, the Domain from the first
// finding is kept (not overwritten by the second finding's domain).
func TestMergeFindings_PreservesDomainFromFirstFinding(t *testing.T) {
	f1 := newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0)
	f1.Domain = "cost"

	f2 := newFinding("vol-1", "us-east-1", "EBS_UNENCRYPTED", models.SeverityHigh, 0.0)
	f2.Domain = "dataprotection"

	merged := mergeFindings([]models.Finding{f1, f2})

	if len(merged) != 1 {
		t.Fatalf("want 1 merged finding; got %d", len(merged))
	}
	// Domain is taken from the first finding in the group.
	if merged[0].Domain != "cost" {
		t.Errorf("Domain = %q; want \"cost\" (first finding in group)", merged[0].Domain)
	}
}

// TestMergeFindings_DifferentResourcesDomainKept verifies that when findings
// for different resources are not merged, each finding retains its own domain.
func TestMergeFindings_DifferentResourcesDomainKept(t *testing.T) {
	f1 := newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityMedium, 8.0)
	f1.Domain = "cost"

	f2 := newFinding("rds-1", "us-east-1", "RDS_UNENCRYPTED", models.SeverityCritical, 0.0)
	f2.Domain = "dataprotection"

	merged := mergeFindings([]models.Finding{f1, f2})

	if len(merged) != 2 {
		t.Fatalf("want 2 findings; got %d", len(merged))
	}
	if merged[0].Domain != "cost" {
		t.Errorf("merged[0].Domain = %q; want \"cost\"", merged[0].Domain)
	}
	if merged[1].Domain != "dataprotection" {
		t.Errorf("merged[1].Domain = %q; want \"dataprotection\"", merged[1].Domain)
	}
}

// ── Domain flows through AllAWSDomainsEngine ─────────────────────────────────

// TestAllAWSAudit_DomainPropagated verifies that when reports with pre-stamped
// domains are fed through AllAWSDomainsEngine.RunAllAWSAudit, domain values
// survive the global merge and appear correctly in the unified report.
func TestAllAWSAudit_DomainPropagated(t *testing.T) {
	costF := newFinding("i-1", "us-east-1", "EC2_LOW_CPU", models.SeverityMedium, 30.0)
	costF.Domain = "cost"

	secF := newFinding("sg-1", "us-east-1", "SG_OPEN_SSH", models.SeverityHigh, 0.0)
	secF.Domain = "security"

	dpF := newFinding("rds-1", "us-east-1", "RDS_UNENCRYPTED", models.SeverityCritical, 0.0)
	dpF.Domain = "dataprotection"

	eng := newAllAWSEngine(
		domainReportWith("cost", []models.Finding{costF}),
		domainReportWith("security", []models.Finding{secF}),
		domainReportWith("dataprotection", []models.Finding{dpF}),
		nil,
	)

	report, _, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Findings) != 3 {
		t.Fatalf("want 3 findings; got %d", len(report.Findings))
	}

	// Build domain lookup by ResourceID for assertion.
	domainByResource := make(map[string]string, len(report.Findings))
	for _, f := range report.Findings {
		domainByResource[f.ResourceID] = f.Domain
	}

	cases := []struct {
		resource string
		domain   string
	}{
		{"i-1", "cost"},
		{"sg-1", "security"},
		{"rds-1", "dataprotection"},
	}
	for _, tc := range cases {
		got, ok := domainByResource[tc.resource]
		if !ok {
			t.Errorf("resource %q missing from report", tc.resource)
			continue
		}
		if got != tc.domain {
			t.Errorf("resource %q: Domain = %q; want %q", tc.resource, got, tc.domain)
		}
	}
}
