package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// eksClusterDataPhase5 builds a minimal KubernetesClusterData with EKSData
// carrying Phase 5A fields (LoggingTypes, EncryptionEnabled) for rule isolation tests.
func eksClusterDataPhase5(clusterName, region string, publicEndpoint bool, loggingTypes []string, encryptionEnabled bool) *models.KubernetesClusterData {
	return &models.KubernetesClusterData{
		ContextName:     clusterName,
		ClusterProvider: "eks",
		EKSData: &models.KubernetesEKSData{
			ClusterName:          clusterName,
			Region:               region,
			EndpointPublicAccess: publicEndpoint,
			LoggingTypes:         loggingTypes,
			EncryptionEnabled:    encryptionEnabled,
		},
	}
}

// ── EKS_CONTROL_PLANE_LOGGING_DISABLED ───────────────────────────────────────

// TestEKSControlPlaneLoggingDisabledRule_Fires_WhenNoTypes verifies that the
// rule fires when LoggingTypes is empty (no log types enabled at all).
func TestEKSControlPlaneLoggingDisabledRule_Fires_WhenNoTypes(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("log-cluster", "us-east-1", false, nil, true),
	}
	r := EKSControlPlaneLoggingDisabledRule{}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when no log types enabled; got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_CONTROL_PLANE_LOGGING_DISABLED" {
		t.Errorf("RuleID = %q; want EKS_CONTROL_PLANE_LOGGING_DISABLED", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
	if findings[0].ResourceID != "log-cluster" {
		t.Errorf("ResourceID = %q; want log-cluster", findings[0].ResourceID)
	}
}

// TestEKSControlPlaneLoggingDisabledRule_Fires_WhenPartialTypes verifies that the
// rule fires when only some required log types are enabled (api+audit, missing authenticator).
func TestEKSControlPlaneLoggingDisabledRule_Fires_WhenPartialTypes(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("partial-cluster", "eu-west-1", false,
			[]string{"api", "audit"}, // missing "authenticator"
			true),
	}
	findings := (EKSControlPlaneLoggingDisabledRule{}).Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for partial logging (missing authenticator); got %d", len(findings))
	}
}

// TestEKSControlPlaneLoggingDisabledRule_Fires_WhenOnlyAuthenticator verifies that
// the rule fires when only authenticator is enabled (api+audit missing).
func TestEKSControlPlaneLoggingDisabledRule_Fires_WhenOnlyAuthenticator(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("auth-only-cluster", "ap-southeast-1", false,
			[]string{"authenticator"}, // missing "api" and "audit"
			true),
	}
	findings := (EKSControlPlaneLoggingDisabledRule{}).Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when only authenticator is enabled; got %d", len(findings))
	}
}

// TestEKSControlPlaneLoggingDisabledRule_Silent_WhenAllRequired verifies that the
// rule is silent when api, audit, and authenticator are all present.
func TestEKSControlPlaneLoggingDisabledRule_Silent_WhenAllRequired(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("full-log-cluster", "us-west-2", false,
			[]string{"api", "audit", "authenticator"},
			true),
	}
	if got := (EKSControlPlaneLoggingDisabledRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when all required log types enabled; got %d", len(got))
	}
}

// TestEKSControlPlaneLoggingDisabledRule_Silent_WhenSupersetTypes verifies that
// the rule is silent when all required types are present plus extras.
func TestEKSControlPlaneLoggingDisabledRule_Silent_WhenSupersetTypes(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("full-log-cluster", "us-east-1", false,
			[]string{"api", "audit", "authenticator", "controllerManager", "scheduler"},
			true),
	}
	if got := (EKSControlPlaneLoggingDisabledRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings for superset of required log types; got %d", len(got))
	}
}

// TestEKSControlPlaneLoggingDisabledRule_Silent_WhenEKSDataNil verifies that nil
// EKSData does not panic and produces no findings.
func TestEKSControlPlaneLoggingDisabledRule_Silent_WhenEKSDataNil(t *testing.T) {
	ctx := RuleContext{
		ClusterData: &models.KubernetesClusterData{ContextName: "generic"},
	}
	if got := (EKSControlPlaneLoggingDisabledRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when EKSData is nil; got %d", len(got))
	}
}

// TestEKSControlPlaneLoggingDisabledRule_Silent_WhenClusterDataNil verifies that
// nil ClusterData does not panic and produces no findings.
func TestEKSControlPlaneLoggingDisabledRule_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (EKSControlPlaneLoggingDisabledRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings when ClusterData is nil; got %d", len(got))
	}
}

// ── EKS_ENCRYPTION_DISABLED ──────────────────────────────────────────────────

// TestEKSEncryptionDisabledRule_Fires_WhenNotEnabled verifies that the rule fires
// when EncryptionEnabled is false.
func TestEKSEncryptionDisabledRule_Fires_WhenNotEnabled(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("no-enc-cluster", "us-east-1", false,
			[]string{"api", "audit", "authenticator"}, false),
	}
	r := EKSEncryptionDisabledRule{}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when encryption disabled; got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_ENCRYPTION_DISABLED" {
		t.Errorf("RuleID = %q; want EKS_ENCRYPTION_DISABLED", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("Severity = %q; want CRITICAL", findings[0].Severity)
	}
	if findings[0].ResourceID != "no-enc-cluster" {
		t.Errorf("ResourceID = %q; want no-enc-cluster", findings[0].ResourceID)
	}
	if findings[0].ResourceType != models.ResourceK8sCluster {
		t.Errorf("ResourceType = %q; want K8S_CLUSTER", findings[0].ResourceType)
	}
}

// TestEKSEncryptionDisabledRule_Silent_WhenEnabled verifies that the rule is silent
// when EncryptionEnabled is true.
func TestEKSEncryptionDisabledRule_Silent_WhenEnabled(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("enc-ok-cluster", "eu-central-1", false,
			[]string{"api", "audit", "authenticator"}, true),
	}
	if got := (EKSEncryptionDisabledRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when encryption is enabled; got %d", len(got))
	}
}

// TestEKSEncryptionDisabledRule_Silent_WhenEKSDataNil verifies that nil EKSData
// does not panic and produces no findings.
func TestEKSEncryptionDisabledRule_Silent_WhenEKSDataNil(t *testing.T) {
	ctx := RuleContext{
		ClusterData: &models.KubernetesClusterData{ContextName: "generic"},
	}
	if got := (EKSEncryptionDisabledRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when EKSData is nil; got %d", len(got))
	}
}

// TestEKSEncryptionDisabledRule_Silent_WhenClusterDataNil verifies that nil
// ClusterData does not panic and produces no findings.
func TestEKSEncryptionDisabledRule_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (EKSEncryptionDisabledRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings when ClusterData is nil; got %d", len(got))
	}
}

// ── Cross-rule: Phase 5A all-fire / none-fire ─────────────────────────────────

// TestPhase5AEKSRules_AllThreeFire verifies that all three Phase 5A rules fire
// simultaneously for a cluster with all bad configurations.
func TestPhase5AEKSRules_AllThreeFire(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("all-bad-cluster", "us-east-1",
			true,  // fires EKS_PUBLIC_ENDPOINT_ENABLED
			nil,   // fires EKS_CONTROL_PLANE_LOGGING_DISABLED
			false, // fires EKS_ENCRYPTION_DISABLED
		),
	}
	phase5Rules := []Rule{
		EKSPublicEndpointRule{},
		EKSControlPlaneLoggingDisabledRule{},
		EKSEncryptionDisabledRule{},
	}
	for _, r := range phase5Rules {
		findings := r.Evaluate(ctx)
		if len(findings) != 1 {
			t.Errorf("rule %q: expected 1 finding; got %d", r.ID(), len(findings))
		}
	}
}

// TestPhase5AEKSRules_NoneFire_WhenAllSecure verifies that all three Phase 5A
// rules are silent for a correctly configured EKS cluster.
func TestPhase5AEKSRules_NoneFire_WhenAllSecure(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterDataPhase5("all-good-cluster", "us-east-1",
			false, // private endpoint
			[]string{"api", "audit", "authenticator"}, // all required log types
			true, // encryption enabled
		),
	}
	phase5Rules := []Rule{
		EKSPublicEndpointRule{},
		EKSControlPlaneLoggingDisabledRule{},
		EKSEncryptionDisabledRule{},
	}
	for _, r := range phase5Rules {
		if got := r.Evaluate(ctx); len(got) != 0 {
			t.Errorf("rule %q: expected 0 findings for secure cluster; got %d", r.ID(), len(got))
		}
	}
}
