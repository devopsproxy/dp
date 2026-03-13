package policy

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func boolPtr(b bool) *bool { return &b }

func TestApplyPolicy_DomainDisabled(t *testing.T) {
	cfg := &PolicyConfig{
		Domains: map[string]DomainConfig{
			"cost": {Enabled: false},
		},
	}

	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU"},
	}

	result := ApplyPolicy(findings, "cost", cfg)

	if len(result) != 0 {
		t.Fatalf("expected all findings dropped")
	}
}

func TestApplyPolicy_RuleDisabled(t *testing.T) {
	cfg := &PolicyConfig{
		Rules: map[string]RuleConfig{
			"EC2_LOW_CPU": {Enabled: boolPtr(false)},
		},
	}

	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU"},
		{RuleID: "EBS_UNATTACHED"},
	}

	result := ApplyPolicy(findings, "cost", cfg)

	if len(result) != 1 {
		t.Fatalf("expected one finding remaining")
	}
	if result[0].RuleID != "EBS_UNATTACHED" {
		t.Fatalf("wrong finding kept")
	}
}

func TestApplyPolicy_SeverityOverride(t *testing.T) {
	cfg := &PolicyConfig{
		Rules: map[string]RuleConfig{
			"EC2_LOW_CPU": {Severity: "CRITICAL"},
		},
	}

	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU", Severity: "MEDIUM"},
	}

	result := ApplyPolicy(findings, "cost", cfg)

	if result[0].Severity != "CRITICAL" {
		t.Fatalf("severity override failed")
	}
}

func TestApplyPolicy_NoPolicy(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU"},
	}

	result := ApplyPolicy(findings, "cost", nil)

	if len(result) != 1 {
		t.Fatalf("nil policy should not modify findings")
	}
}

func TestApplyPolicy_MinSeverityNotSet(t *testing.T) {
	// No min_severity → all findings pass through regardless of severity.
	cfg := &PolicyConfig{
		Domains: map[string]DomainConfig{
			"cost": {Enabled: true},
		},
	}
	findings := []models.Finding{
		{RuleID: "A", Severity: models.SeverityCritical},
		{RuleID: "B", Severity: models.SeverityHigh},
		{RuleID: "C", Severity: models.SeverityMedium},
		{RuleID: "D", Severity: models.SeverityLow},
		{RuleID: "E", Severity: models.SeverityInfo},
	}
	result := ApplyPolicy(findings, "cost", cfg)
	if len(result) != 5 {
		t.Fatalf("want 5 findings (no min_severity), got %d", len(result))
	}
}

func TestApplyPolicy_MinSeverityHigh(t *testing.T) {
	// min_severity=HIGH → MEDIUM, LOW, INFO are dropped; CRITICAL and HIGH survive.
	cfg := &PolicyConfig{
		Domains: map[string]DomainConfig{
			"cost": {Enabled: true, MinSeverity: "HIGH"},
		},
	}
	findings := []models.Finding{
		{RuleID: "A", Severity: models.SeverityCritical},
		{RuleID: "B", Severity: models.SeverityHigh},
		{RuleID: "C", Severity: models.SeverityMedium},
		{RuleID: "D", Severity: models.SeverityLow},
		{RuleID: "E", Severity: models.SeverityInfo},
	}
	result := ApplyPolicy(findings, "cost", cfg)
	if len(result) != 2 {
		t.Fatalf("want 2 findings (CRITICAL + HIGH), got %d", len(result))
	}
	for _, f := range result {
		if f.Severity != models.SeverityCritical && f.Severity != models.SeverityHigh {
			t.Errorf("unexpected severity %q survived min_severity=HIGH filter", f.Severity)
		}
	}
}

func TestApplyPolicy_MinSeverityCritical(t *testing.T) {
	// min_severity=CRITICAL → only CRITICAL findings survive.
	cfg := &PolicyConfig{
		Domains: map[string]DomainConfig{
			"security": {Enabled: true, MinSeverity: "CRITICAL"},
		},
	}
	findings := []models.Finding{
		{RuleID: "A", Severity: models.SeverityCritical},
		{RuleID: "B", Severity: models.SeverityHigh},
		{RuleID: "C", Severity: models.SeverityMedium},
	}
	result := ApplyPolicy(findings, "security", cfg)
	if len(result) != 1 {
		t.Fatalf("want 1 finding (CRITICAL only), got %d", len(result))
	}
	if result[0].Severity != models.SeverityCritical {
		t.Errorf("want CRITICAL, got %q", result[0].Severity)
	}
}

func TestApplyPolicy_SeverityOverrideThenMinSeverity(t *testing.T) {
	// Severity override elevates MEDIUM → CRITICAL; min_severity=HIGH then keeps it.
	cfg := &PolicyConfig{
		Domains: map[string]DomainConfig{
			"cost": {Enabled: true, MinSeverity: "HIGH"},
		},
		Rules: map[string]RuleConfig{
			"EC2_LOW_CPU": {Severity: "CRITICAL"},
		},
	}
	findings := []models.Finding{
		{RuleID: "EC2_LOW_CPU", Severity: models.SeverityMedium},
		{RuleID: "EBS_UNATTACHED", Severity: models.SeverityLow},
	}
	result := ApplyPolicy(findings, "cost", cfg)
	// EC2_LOW_CPU: overridden to CRITICAL (rank 5) ≥ HIGH (rank 4) → kept.
	// EBS_UNATTACHED: stays LOW (rank 2) < HIGH (rank 4) → dropped.
	if len(result) != 1 {
		t.Fatalf("want 1 finding after override+min_severity filter, got %d", len(result))
	}
	if result[0].RuleID != "EC2_LOW_CPU" {
		t.Errorf("wrong finding kept: %q", result[0].RuleID)
	}
	if result[0].Severity != models.SeverityCritical {
		t.Errorf("want CRITICAL after override, got %q", result[0].Severity)
	}
}

func TestApplyPolicy_MinSeverityInvalidValue(t *testing.T) {
	// An unrecognised min_severity string is ignored safely — no filtering applied.
	cfg := &PolicyConfig{
		Domains: map[string]DomainConfig{
			"cost": {Enabled: true, MinSeverity: "BOGUS"},
		},
	}
	findings := []models.Finding{
		{RuleID: "A", Severity: models.SeverityLow},
		{RuleID: "B", Severity: models.SeverityInfo},
	}
	result := ApplyPolicy(findings, "cost", cfg)
	if len(result) != 2 {
		t.Fatalf("invalid min_severity must not filter findings; got %d", len(result))
	}
}
