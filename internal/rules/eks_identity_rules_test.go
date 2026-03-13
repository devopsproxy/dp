package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// eksIdentityClusterData builds a KubernetesClusterData with EKSData for
// Phase 5B identity rule isolation tests.
func eksIdentityClusterData(clusterName, region, oidcProviderARN string, nodeRolePolicies []string) *models.KubernetesClusterData {
	return &models.KubernetesClusterData{
		ContextName:     clusterName,
		ClusterProvider: "eks",
		EKSData: &models.KubernetesEKSData{
			ClusterName:      clusterName,
			Region:           region,
			OIDCProviderARN:  oidcProviderARN,
			NodeRolePolicies: nodeRolePolicies,
		},
	}
}

// eksIdentityClusterDataWithSAs extends eksIdentityClusterData with ServiceAccounts.
func eksIdentityClusterDataWithSAs(clusterName, region string, sas []models.KubernetesServiceAccountData) *models.KubernetesClusterData {
	return &models.KubernetesClusterData{
		ContextName:     clusterName,
		ClusterProvider: "eks",
		EKSData: &models.KubernetesEKSData{
			ClusterName:     clusterName,
			Region:          region,
			OIDCProviderARN: "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/TEST",
		},
		ServiceAccounts: sas,
	}
}

// ── EKS_OIDC_PROVIDER_NOT_ASSOCIATED ─────────────────────────────────────────

// TestEKSOIDCProviderNotAssociatedRule_Fires_WhenARNEmpty verifies that the rule
// fires when OIDCProviderARN is empty (no IAM OIDC provider exists).
func TestEKSOIDCProviderNotAssociatedRule_Fires_WhenARNEmpty(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksIdentityClusterData("no-oidc-cluster", "us-east-1", "", nil),
	}
	r := EKSOIDCProviderNotAssociatedRule{}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when OIDCProviderARN is empty; got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_OIDC_PROVIDER_NOT_ASSOCIATED" {
		t.Errorf("RuleID = %q; want EKS_OIDC_PROVIDER_NOT_ASSOCIATED", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
	if findings[0].ResourceID != "no-oidc-cluster" {
		t.Errorf("ResourceID = %q; want no-oidc-cluster", findings[0].ResourceID)
	}
	if findings[0].ResourceType != models.ResourceK8sCluster {
		t.Errorf("ResourceType = %q; want K8S_CLUSTER", findings[0].ResourceType)
	}
}

// TestEKSOIDCProviderNotAssociatedRule_Silent_WhenARNPresent verifies that the
// rule is silent when OIDCProviderARN is set.
func TestEKSOIDCProviderNotAssociatedRule_Silent_WhenARNPresent(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksIdentityClusterData("oidc-ok-cluster", "eu-central-1",
			"arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-central-1.amazonaws.com/id/ABCD",
			nil),
	}
	if got := (EKSOIDCProviderNotAssociatedRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when OIDCProviderARN is present; got %d", len(got))
	}
}

// TestEKSOIDCProviderNotAssociatedRule_Silent_WhenEKSDataNil verifies that nil
// EKSData does not panic and produces no findings.
func TestEKSOIDCProviderNotAssociatedRule_Silent_WhenEKSDataNil(t *testing.T) {
	ctx := RuleContext{
		ClusterData: &models.KubernetesClusterData{ContextName: "generic"},
	}
	if got := (EKSOIDCProviderNotAssociatedRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when EKSData is nil; got %d", len(got))
	}
}

// TestEKSOIDCProviderNotAssociatedRule_Silent_WhenClusterDataNil verifies that nil
// ClusterData does not panic and produces no findings.
func TestEKSOIDCProviderNotAssociatedRule_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (EKSOIDCProviderNotAssociatedRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings when ClusterData is nil; got %d", len(got))
	}
}

// ── EKS_SERVICEACCOUNT_NO_IRSA ────────────────────────────────────────────────

// TestEKSServiceAccountNoIRSARule_Fires_WhenNoAnnotation verifies that the rule
// fires for a ServiceAccount with no annotations.
func TestEKSServiceAccountNoIRSARule_Fires_WhenNoAnnotation(t *testing.T) {
	sas := []models.KubernetesServiceAccountData{
		{Name: "my-sa", Namespace: "prod", Annotations: nil},
	}
	ctx := RuleContext{
		ClusterData: eksIdentityClusterDataWithSAs("test-cluster", "us-east-1", sas),
	}
	r := EKSServiceAccountNoIRSARule{}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for SA with no annotations; got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_SERVICEACCOUNT_NO_IRSA" {
		t.Errorf("RuleID = %q; want EKS_SERVICEACCOUNT_NO_IRSA", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
	if findings[0].ResourceID != "my-sa" {
		t.Errorf("ResourceID = %q; want my-sa", findings[0].ResourceID)
	}
	if findings[0].ResourceType != models.ResourceK8sServiceAccount {
		t.Errorf("ResourceType = %q; want K8S_SERVICEACCOUNT", findings[0].ResourceType)
	}
}

// TestEKSServiceAccountNoIRSARule_Fires_HasNamespaceMetadata verifies that the
// finding includes the namespace in metadata so --exclude-system can filter it.
func TestEKSServiceAccountNoIRSARule_Fires_HasNamespaceMetadata(t *testing.T) {
	sas := []models.KubernetesServiceAccountData{
		{Name: "app-sa", Namespace: "staging", Annotations: map[string]string{"other": "val"}},
	}
	ctx := RuleContext{
		ClusterData: eksIdentityClusterDataWithSAs("test-cluster", "us-east-1", sas),
	}
	findings := (EKSServiceAccountNoIRSARule{}).Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if ns, ok := findings[0].Metadata["namespace"].(string); !ok || ns != "staging" {
		t.Errorf("Metadata[\"namespace\"] = %v; want \"staging\"", findings[0].Metadata["namespace"])
	}
}

// TestEKSServiceAccountNoIRSARule_Silent_WhenIRSAAnnotationPresent verifies that
// the rule is silent for a ServiceAccount with the IRSA annotation set.
func TestEKSServiceAccountNoIRSARule_Silent_WhenIRSAAnnotationPresent(t *testing.T) {
	sas := []models.KubernetesServiceAccountData{
		{
			Name:      "irsa-sa",
			Namespace: "prod",
			Annotations: map[string]string{
				"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/my-role",
			},
		},
	}
	ctx := RuleContext{
		ClusterData: eksIdentityClusterDataWithSAs("test-cluster", "us-east-1", sas),
	}
	if got := (EKSServiceAccountNoIRSARule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when IRSA annotation is present; got %d", len(got))
	}
}

// TestEKSServiceAccountNoIRSARule_MultipleFindings_MixedSAs verifies that the
// rule fires only for SAs lacking the annotation and skips those with it.
func TestEKSServiceAccountNoIRSARule_MultipleFindings_MixedSAs(t *testing.T) {
	sas := []models.KubernetesServiceAccountData{
		{Name: "no-irsa-1", Namespace: "ns1"},
		{
			Name:      "has-irsa",
			Namespace: "ns1",
			Annotations: map[string]string{
				"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/role1",
			},
		},
		{Name: "no-irsa-2", Namespace: "ns2"},
	}
	ctx := RuleContext{
		ClusterData: eksIdentityClusterDataWithSAs("mixed-cluster", "ap-southeast-1", sas),
	}
	findings := (EKSServiceAccountNoIRSARule{}).Evaluate(ctx)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for 2 SAs without IRSA; got %d", len(findings))
	}
	ids := map[string]bool{findings[0].ResourceID: true, findings[1].ResourceID: true}
	if !ids["no-irsa-1"] || !ids["no-irsa-2"] {
		t.Errorf("expected findings for no-irsa-1 and no-irsa-2; got %v", ids)
	}
}

// TestEKSServiceAccountNoIRSARule_Silent_WhenNoServiceAccounts verifies that the
// rule produces no findings when the cluster has no service accounts.
func TestEKSServiceAccountNoIRSARule_Silent_WhenNoServiceAccounts(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksIdentityClusterDataWithSAs("empty-cluster", "us-west-2", nil),
	}
	if got := (EKSServiceAccountNoIRSARule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when ServiceAccounts is empty; got %d", len(got))
	}
}

// TestEKSServiceAccountNoIRSARule_Silent_WhenClusterDataNil verifies that nil
// ClusterData does not panic and produces no findings.
func TestEKSServiceAccountNoIRSARule_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (EKSServiceAccountNoIRSARule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings when ClusterData is nil; got %d", len(got))
	}
}

// ── EKS_NODE_ROLE_OVERPERMISSIVE ──────────────────────────────────────────────

// TestEKSNodeRoleOverpermissiveRule_Fires_WhenPoliciesPresent verifies that the
// rule fires when NodeRolePolicies is non-empty.
func TestEKSNodeRoleOverpermissiveRule_Fires_WhenPoliciesPresent(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksIdentityClusterData("bad-node-cluster", "us-east-1", "",
			[]string{"AdministratorAccess"}),
	}
	r := EKSNodeRoleOverpermissiveRule{}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding when NodeRolePolicies is non-empty; got %d", len(findings))
	}
	if findings[0].RuleID != "EKS_NODE_ROLE_OVERPERMISSIVE" {
		t.Errorf("RuleID = %q; want EKS_NODE_ROLE_OVERPERMISSIVE", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityCritical {
		t.Errorf("Severity = %q; want CRITICAL", findings[0].Severity)
	}
	if findings[0].ResourceID != "bad-node-cluster" {
		t.Errorf("ResourceID = %q; want bad-node-cluster", findings[0].ResourceID)
	}
	if findings[0].ResourceType != models.ResourceK8sCluster {
		t.Errorf("ResourceType = %q; want K8S_CLUSTER", findings[0].ResourceType)
	}
}

// TestEKSNodeRoleOverpermissiveRule_Fires_MetadataPolicies verifies that
// Metadata["overpermissive_policies"] contains the policy names.
func TestEKSNodeRoleOverpermissiveRule_Fires_MetadataPolicies(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksIdentityClusterData("overperm-cluster", "eu-west-1", "",
			[]string{"AdministratorAccess", "wildcard-inline"}),
	}
	findings := (EKSNodeRoleOverpermissiveRule{}).Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	policies, ok := findings[0].Metadata["overpermissive_policies"].([]string)
	if !ok {
		t.Fatalf("Metadata[overpermissive_policies] not []string; got %T", findings[0].Metadata["overpermissive_policies"])
	}
	if len(policies) != 2 {
		t.Errorf("expected 2 policies in metadata; got %d", len(policies))
	}
}

// TestEKSNodeRoleOverpermissiveRule_Silent_WhenNoPolicies verifies that the
// rule is silent when NodeRolePolicies is empty.
func TestEKSNodeRoleOverpermissiveRule_Silent_WhenNoPolicies(t *testing.T) {
	ctx := RuleContext{
		ClusterData: eksIdentityClusterData("good-node-cluster", "us-east-1", "", nil),
	}
	if got := (EKSNodeRoleOverpermissiveRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when NodeRolePolicies is empty; got %d", len(got))
	}
}

// TestEKSNodeRoleOverpermissiveRule_Silent_WhenEKSDataNil verifies that nil
// EKSData does not panic and produces no findings.
func TestEKSNodeRoleOverpermissiveRule_Silent_WhenEKSDataNil(t *testing.T) {
	ctx := RuleContext{
		ClusterData: &models.KubernetesClusterData{ContextName: "generic"},
	}
	if got := (EKSNodeRoleOverpermissiveRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when EKSData is nil; got %d", len(got))
	}
}

// TestEKSNodeRoleOverpermissiveRule_Silent_WhenClusterDataNil verifies that nil
// ClusterData does not panic and produces no findings.
func TestEKSNodeRoleOverpermissiveRule_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (EKSNodeRoleOverpermissiveRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings when ClusterData is nil; got %d", len(got))
	}
}

// ── Cross-rule: Phase 5B all-fire / none-fire ─────────────────────────────────

// TestPhase5BEKSRules_AllThreeFire verifies that all three Phase 5B rules fire
// simultaneously for a cluster with all bad identity configurations.
func TestPhase5BEKSRules_AllThreeFire(t *testing.T) {
	// Cluster with: no OIDC ARN, no IRSA SAs, and overpermissive node role.
	clusterData := &models.KubernetesClusterData{
		ContextName:     "all-bad-identity",
		ClusterProvider: "eks",
		EKSData: &models.KubernetesEKSData{
			ClusterName:      "all-bad-identity",
			Region:           "us-east-1",
			OIDCProviderARN:  "",                              // fires EKS_OIDC_PROVIDER_NOT_ASSOCIATED
			NodeRolePolicies: []string{"AdministratorAccess"}, // fires EKS_NODE_ROLE_OVERPERMISSIVE
		},
		ServiceAccounts: []models.KubernetesServiceAccountData{
			{Name: "default", Namespace: "default"}, // fires EKS_SERVICEACCOUNT_NO_IRSA
		},
	}
	ctx := RuleContext{ClusterData: clusterData}

	phase5BRules := []Rule{
		EKSOIDCProviderNotAssociatedRule{},
		EKSServiceAccountNoIRSARule{},
		EKSNodeRoleOverpermissiveRule{},
	}
	for _, r := range phase5BRules {
		findings := r.Evaluate(ctx)
		if len(findings) == 0 {
			t.Errorf("rule %q: expected ≥1 finding; got 0", r.ID())
		}
	}
}

// TestPhase5BEKSRules_NoneFire_WhenAllSecure verifies that all three Phase 5B
// rules are silent for a correctly configured EKS cluster.
func TestPhase5BEKSRules_NoneFire_WhenAllSecure(t *testing.T) {
	clusterData := &models.KubernetesClusterData{
		ContextName:     "all-good-identity",
		ClusterProvider: "eks",
		EKSData: &models.KubernetesEKSData{
			ClusterName:      "all-good-identity",
			Region:           "us-east-1",
			OIDCProviderARN:  "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/OK",
			NodeRolePolicies: nil,
		},
		ServiceAccounts: []models.KubernetesServiceAccountData{
			{
				Name:      "app-sa",
				Namespace: "prod",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/app-role",
				},
			},
		},
	}
	ctx := RuleContext{ClusterData: clusterData}

	phase5BRules := []Rule{
		EKSOIDCProviderNotAssociatedRule{},
		EKSNodeRoleOverpermissiveRule{},
	}
	for _, r := range phase5BRules {
		if got := r.Evaluate(ctx); len(got) != 0 {
			t.Errorf("rule %q: expected 0 findings for secure cluster; got %d", r.ID(), len(got))
		}
	}
	// SA rule: one SA with IRSA → no findings.
	if got := (EKSServiceAccountNoIRSARule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("EKSServiceAccountNoIRSARule: expected 0 findings when all SAs have IRSA; got %d", len(got))
	}
}
