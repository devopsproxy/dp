package policy_test

import (
	"testing"

	"github.com/devopsproxy/dp/internal/policy"
)

// knownRules is a fixed rule ID set used by all validator tests.
// These are made-up IDs; they are not tied to any specific rule pack.
var knownRules = []string{"RULE_A", "RULE_B", "RULE_C"}

func boolPtr(b bool) *bool { return &b }

// ── happy path ────────────────────────────────────────────────────────────────

func TestValidate_ValidMinimalConfig(t *testing.T) {
	// A config with only version=1 and no other sections must be valid.
	cfg := &policy.PolicyConfig{Version: 1}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) != 0 {
		t.Errorf("expected no errors; got %d: %v", len(errs), errs)
	}
}

func TestValidate_ValidFullConfig(t *testing.T) {
	cfg := &policy.PolicyConfig{
		Version: 1,
		Domains: map[string]policy.DomainConfig{
			"cost":     {Enabled: true, MinSeverity: "medium"},
			"security": {Enabled: true, MinSeverity: "HIGH"},
		},
		Rules: map[string]policy.RuleConfig{
			"RULE_A": {Enabled: boolPtr(false)},
			"RULE_B": {Severity: "low"},
			"RULE_C": {Severity: "CRITICAL"},
		},
		Enforcement: map[string]policy.EnforcementConfig{
			"cost":     {FailOnSeverity: "critical"},
			"security": {FailOnSeverity: "HIGH"},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) != 0 {
		t.Errorf("expected no errors; got %d: %v", len(errs), errs)
	}
}

func TestValidate_SeverityCaseInsensitive(t *testing.T) {
	// Severity values must be accepted in any case.
	severities := []string{
		"critical", "CRITICAL", "Critical",
		"high", "HIGH", "High",
		"medium", "MEDIUM", "Medium",
		"low", "LOW", "Low",
		"info", "INFO", "Info",
	}
	for _, sev := range severities {
		cfg := &policy.PolicyConfig{
			Version: 1,
			Rules:   map[string]policy.RuleConfig{"RULE_A": {Severity: sev}},
		}
		errs := policy.Validate(cfg, knownRules)
		if len(errs) != 0 {
			t.Errorf("severity %q: expected no errors; got %v", sev, errs)
		}
	}
}

// ── version ───────────────────────────────────────────────────────────────────

func TestValidate_InvalidVersion(t *testing.T) {
	cfg := &policy.PolicyConfig{Version: 2}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected version error; got none")
	}
	// Exactly one error and it mentions "version".
	if len(errs) != 1 {
		t.Errorf("expected 1 error; got %d: %v", len(errs), errs)
	}
}

func TestValidate_VersionZeroInvalid(t *testing.T) {
	cfg := &policy.PolicyConfig{Version: 0}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected version error for version=0; got none")
	}
}

// ── domains ───────────────────────────────────────────────────────────────────

func TestValidate_UnknownDomain(t *testing.T) {
	cfg := &policy.PolicyConfig{
		Version: 1,
		Domains: map[string]policy.DomainConfig{
			"networking": {Enabled: true},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected domain error; got none")
	}
}

func TestValidate_AllValidDomainsAccepted(t *testing.T) {
	for _, domain := range []string{"cost", "security", "dataprotection", "kubernetes"} {
		cfg := &policy.PolicyConfig{
			Version: 1,
			Domains: map[string]policy.DomainConfig{
				domain: {Enabled: true},
			},
		}
		errs := policy.Validate(cfg, knownRules)
		if len(errs) != 0 {
			t.Errorf("domain %q: expected no errors; got %v", domain, errs)
		}
	}
}

// ── min_severity ──────────────────────────────────────────────────────────────

func TestValidate_InvalidMinSeverity(t *testing.T) {
	cfg := &policy.PolicyConfig{
		Version: 1,
		Domains: map[string]policy.DomainConfig{
			"cost": {Enabled: true, MinSeverity: "severe"},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected min_severity error; got none")
	}
}

func TestValidate_EmptyMinSeverityAccepted(t *testing.T) {
	// min_severity="" means "no filter"; must not produce an error.
	cfg := &policy.PolicyConfig{
		Version: 1,
		Domains: map[string]policy.DomainConfig{
			"cost": {Enabled: true, MinSeverity: ""},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) != 0 {
		t.Errorf("expected no errors; got %v", errs)
	}
}

// ── rules ─────────────────────────────────────────────────────────────────────

func TestValidate_UnknownRule(t *testing.T) {
	cfg := &policy.PolicyConfig{
		Version: 1,
		Rules: map[string]policy.RuleConfig{
			"RULE_DOES_NOT_EXIST": {Severity: "low"},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected rule error; got none")
	}
}

func TestValidate_InvalidSeverityOnRule(t *testing.T) {
	cfg := &policy.PolicyConfig{
		Version: 1,
		Rules: map[string]policy.RuleConfig{
			"RULE_A": {Severity: "urgent"},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected severity error; got none")
	}
}

func TestValidate_EmptyRuleSeverityAccepted(t *testing.T) {
	// severity="" means "no override"; must not produce an error.
	cfg := &policy.PolicyConfig{
		Version: 1,
		Rules:   map[string]policy.RuleConfig{"RULE_A": {Severity: ""}},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) != 0 {
		t.Errorf("expected no errors; got %v", errs)
	}
}

// ── fail_on_severity ──────────────────────────────────────────────────────────

func TestValidate_InvalidFailOnSeverity(t *testing.T) {
	cfg := &policy.PolicyConfig{
		Version: 1,
		Enforcement: map[string]policy.EnforcementConfig{
			"security": {FailOnSeverity: "blocker"},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected fail_on_severity error; got none")
	}
}

func TestValidate_EmptyFailOnSeverityAccepted(t *testing.T) {
	// fail_on_severity="" means disabled; must not produce an error.
	cfg := &policy.PolicyConfig{
		Version: 1,
		Enforcement: map[string]policy.EnforcementConfig{
			"cost": {FailOnSeverity: ""},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) != 0 {
		t.Errorf("expected no errors; got %v", errs)
	}
}

func TestValidate_UnknownEnforcementDomain(t *testing.T) {
	cfg := &policy.PolicyConfig{
		Version: 1,
		Enforcement: map[string]policy.EnforcementConfig{
			"terraform": {FailOnSeverity: "critical"},
		},
	}
	errs := policy.Validate(cfg, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected enforcement domain error; got none")
	}
}

// ── multiple errors ───────────────────────────────────────────────────────────

func TestValidate_MultipleErrorsAggregated(t *testing.T) {
	// Config with four distinct problems; all must be reported together.
	cfg := &policy.PolicyConfig{
		Version: 2, // invalid
		Domains: map[string]policy.DomainConfig{
			"networking": {Enabled: true, MinSeverity: "notavalue"}, // unknown domain + invalid min_severity
		},
		Rules: map[string]policy.RuleConfig{
			"UNKNOWN_RULE": {Severity: "blocker"}, // unknown rule ID + invalid severity
		},
	}
	errs := policy.Validate(cfg, knownRules)
	// version(1) + domain(1) + min_severity(1) + rule_id(1) + rule_severity(1) = 5 errors
	if len(errs) < 4 {
		t.Errorf("expected at least 4 errors; got %d: %v", len(errs), errs)
	}
}

func TestValidate_NilConfig(t *testing.T) {
	errs := policy.Validate(nil, knownRules)
	if len(errs) == 0 {
		t.Fatal("expected error for nil config; got none")
	}
}
