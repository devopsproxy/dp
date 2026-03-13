package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// eksClusterData builds a minimal KubernetesClusterData with EKSData attached,
// suitable for testing EKS-specific rules in isolation.
func eksClusterData(clusterName, region string, publicEndpoint, loggingEnabled bool, oidcIssuer string) *models.KubernetesClusterData {
	return &models.KubernetesClusterData{
		ContextName:     clusterName,
		ClusterProvider: "eks",
		EKSData: &models.KubernetesEKSData{
			ClusterName:          clusterName,
			Region:               region,
			EndpointPublicAccess: publicEndpoint,
			LoggingEnabled:       loggingEnabled,
			OIDCIssuer:           oidcIssuer,
		},
	}
}

// ── EKS_PUBLIC_ENDPOINT_ENABLED ──────────────────────────────────────────────

func TestEKSPublicEndpointRule_Fires_WhenPublic(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterData("my-cluster", "us-east-1", true, true, "https://oidc.eks.us-east-1.amazonaws.com/id/ABC"),
	}
	r := EKSPublicEndpointRule{}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_PUBLIC_ENDPOINT_ENABLED" {
		t.Errorf("RuleID = %q; want EKS_PUBLIC_ENDPOINT_ENABLED", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
	if findings[0].ResourceID != "my-cluster" {
		t.Errorf("ResourceID = %q; want my-cluster", findings[0].ResourceID)
	}
}

func TestEKSPublicEndpointRule_Silent_WhenPrivate(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterData("private-cluster", "eu-west-1", false, true, "https://oidc.example.com"),
	}
	if got := (EKSPublicEndpointRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings for private endpoint; got %d", len(got))
	}
}

func TestEKSPublicEndpointRule_Silent_WhenEKSDataNil(t *testing.T) {
	ctx := RuleContext{
		ClusterData: &models.KubernetesClusterData{ContextName: "generic-cluster"},
	}
	if got := (EKSPublicEndpointRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when EKSData is nil; got %d", len(got))
	}
}

func TestEKSPublicEndpointRule_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (EKSPublicEndpointRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings when ClusterData is nil; got %d", len(got))
	}
}

// ── EKS_CLUSTER_LOGGING_DISABLED ─────────────────────────────────────────────

func TestEKSClusterLoggingDisabledRule_Fires_WhenLoggingOff(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterData("log-cluster", "us-west-2", false, false, ""),
	}
	r := EKSClusterLoggingDisabledRule{}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_CLUSTER_LOGGING_DISABLED" {
		t.Errorf("RuleID = %q; want EKS_CLUSTER_LOGGING_DISABLED", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
	}
}

func TestEKSClusterLoggingDisabledRule_Silent_WhenLoggingOn(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterData("log-ok-cluster", "us-east-1", false, true, ""),
	}
	if got := (EKSClusterLoggingDisabledRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when logging is enabled; got %d", len(got))
	}
}

func TestEKSClusterLoggingDisabledRule_Silent_WhenEKSDataNil(t *testing.T) {
	ctx := RuleContext{
		ClusterData: &models.KubernetesClusterData{ContextName: "generic"},
	}
	if got := (EKSClusterLoggingDisabledRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when EKSData is nil; got %d", len(got))
	}
}

// ── EKS_OIDC_PROVIDER_MISSING ────────────────────────────────────────────────

func TestEKSOIDCProviderMissingRule_Fires_WhenNoOIDC(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterData("oidc-cluster", "ap-southeast-1", false, true, ""),
	}
	r := EKSOIDCProviderMissingRule{}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_OIDC_PROVIDER_MISSING" {
		t.Errorf("RuleID = %q; want EKS_OIDC_PROVIDER_MISSING", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
}

func TestEKSOIDCProviderMissingRule_Silent_WhenOIDCPresent(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksClusterData("oidc-ok", "us-east-1", false, true, "https://oidc.eks.us-east-1.amazonaws.com/id/XYZ"),
	}
	if got := (EKSOIDCProviderMissingRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when OIDC issuer is set; got %d", len(got))
	}
}

func TestEKSOIDCProviderMissingRule_Silent_WhenEKSDataNil(t *testing.T) {
	ctx := RuleContext{
		ClusterData: &models.KubernetesClusterData{ContextName: "plain"},
	}
	if got := (EKSOIDCProviderMissingRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when EKSData is nil; got %d", len(got))
	}
}

// ── Cross-rule: all three fire when all conditions met ────────────────────────

func TestEKSRules_AllThreeFire(t *testing.T) {
	// public endpoint, no logging, no OIDC — all three rules should fire
	ctx := RuleContext{
		ClusterData: eksClusterData("bad-cluster", "us-east-1", true, false, ""),
	}
	rules := []Rule{
		EKSPublicEndpointRule{},
		EKSClusterLoggingDisabledRule{},
		EKSOIDCProviderMissingRule{},
	}
	for _, r := range rules {
		findings := r.Evaluate(ctx)
		if len(findings) != 1 {
			t.Errorf("rule %q: expected 1 finding; got %d", r.ID(), len(findings))
		}
	}
}

// ── Cross-rule: none fire when all conditions met ─────────────────────────────

func TestEKSRules_NoneFire_WhenAllSecure(t *testing.T) {
	// private endpoint, logging on, OIDC present — no rules should fire
	ctx := RuleContext{
		ClusterData: eksClusterData("good-cluster", "us-east-1", false, true, "https://oidc.eks.us-east-1.amazonaws.com/id/ABC123"),
	}
	rules := []Rule{
		EKSPublicEndpointRule{},
		EKSClusterLoggingDisabledRule{},
		EKSOIDCProviderMissingRule{},
	}
	for _, r := range rules {
		if got := r.Evaluate(ctx); len(got) != 0 {
			t.Errorf("rule %q: expected 0 findings for secure cluster; got %d", r.ID(), len(got))
		}
	}
}
