package policy

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestShouldFail_NilConfig(t *testing.T) {
	findings := []models.Finding{{Severity: models.SeverityCritical}}
	if ShouldFail("cost", findings, nil) {
		t.Error("nil cfg must return false")
	}
}

func TestShouldFail_NoEnforcementBlock(t *testing.T) {
	// PolicyConfig with no enforcement section at all.
	cfg := &PolicyConfig{}
	findings := []models.Finding{{Severity: models.SeverityCritical}}
	if ShouldFail("cost", findings, cfg) {
		t.Error("absent enforcement block must return false")
	}
}

func TestShouldFail_DomainNotConfigured(t *testing.T) {
	// Enforcement for security is configured; cost lookup must return false.
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"security": {FailOnSeverity: "HIGH"},
		},
	}
	findings := []models.Finding{{Severity: models.SeverityCritical}}
	if ShouldFail("cost", findings, cfg) {
		t.Error("enforcement for a different domain must not affect cost lookup")
	}
}

func TestShouldFail_NoFindings(t *testing.T) {
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"cost": {FailOnSeverity: "HIGH"},
		},
	}
	if ShouldFail("cost", nil, cfg) {
		t.Error("empty findings slice must return false")
	}
}

func TestShouldFail_InvalidSeverityIgnored(t *testing.T) {
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"cost": {FailOnSeverity: "BOGUS"},
		},
	}
	findings := []models.Finding{{Severity: models.SeverityCritical}}
	if ShouldFail("cost", findings, cfg) {
		t.Error("unrecognised fail_on_severity must return false")
	}
}

func TestShouldFail_HighThreshold_HighFindingTriggers(t *testing.T) {
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"cost": {FailOnSeverity: "HIGH"},
		},
	}
	findings := []models.Finding{{Severity: models.SeverityHigh}}
	if !ShouldFail("cost", findings, cfg) {
		t.Error("HIGH finding with fail_on=HIGH must return true")
	}
}

func TestShouldFail_HighThreshold_CriticalFindingTriggers(t *testing.T) {
	// CRITICAL is above HIGH, so it must also trigger.
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"cost": {FailOnSeverity: "HIGH"},
		},
	}
	findings := []models.Finding{{Severity: models.SeverityCritical}}
	if !ShouldFail("cost", findings, cfg) {
		t.Error("CRITICAL finding with fail_on=HIGH must return true")
	}
}

func TestShouldFail_HighThreshold_MediumFindingDoesNotTrigger(t *testing.T) {
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"cost": {FailOnSeverity: "HIGH"},
		},
	}
	findings := []models.Finding{{Severity: models.SeverityMedium}}
	if ShouldFail("cost", findings, cfg) {
		t.Error("MEDIUM finding with fail_on=HIGH must return false")
	}
}

func TestShouldFail_CriticalThreshold_HighFindingDoesNotTrigger(t *testing.T) {
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"security": {FailOnSeverity: "CRITICAL"},
		},
	}
	findings := []models.Finding{{Severity: models.SeverityHigh}}
	if ShouldFail("security", findings, cfg) {
		t.Error("HIGH finding with fail_on=CRITICAL must return false")
	}
}

func TestShouldFail_CriticalThreshold_CriticalFindingTriggers(t *testing.T) {
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"security": {FailOnSeverity: "CRITICAL"},
		},
	}
	findings := []models.Finding{{Severity: models.SeverityCritical}}
	if !ShouldFail("security", findings, cfg) {
		t.Error("CRITICAL finding with fail_on=CRITICAL must return true")
	}
}

func TestShouldFail_MixedFindings_AnyMatchTriggers(t *testing.T) {
	// Only one CRITICAL among several lower-severity findings.
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"cost": {FailOnSeverity: "HIGH"},
		},
	}
	findings := []models.Finding{
		{Severity: models.SeverityLow},
		{Severity: models.SeverityMedium},
		{Severity: models.SeverityCritical}, // this one triggers
	}
	if !ShouldFail("cost", findings, cfg) {
		t.Error("any finding at or above threshold must trigger ShouldFail")
	}
}

func TestShouldFail_AllFindingsBelowThreshold(t *testing.T) {
	cfg := &PolicyConfig{
		Enforcement: map[string]EnforcementConfig{
			"cost": {FailOnSeverity: "HIGH"},
		},
	}
	findings := []models.Finding{
		{Severity: models.SeverityLow},
		{Severity: models.SeverityMedium},
		{Severity: models.SeverityInfo},
	}
	if ShouldFail("cost", findings, cfg) {
		t.Error("all findings below HIGH threshold must return false")
	}
}
