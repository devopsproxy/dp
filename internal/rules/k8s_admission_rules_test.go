package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// admissionCluster builds a KubernetesClusterData with explicit namespace
// labels and optional service accounts / pods for admission rule tests.
func admissionCluster(
	namespaces []models.KubernetesNamespaceData,
	serviceAccounts []models.KubernetesServiceAccountData,
	pods []models.KubernetesPodData,
) *models.KubernetesClusterData {
	return &models.KubernetesClusterData{
		ContextName:     "test-cluster",
		Namespaces:      namespaces,
		ServiceAccounts: serviceAccounts,
		Pods:            pods,
	}
}

// nsWithLabel returns a KubernetesNamespaceData carrying the PSA enforce label.
func nsWithLabel(name string) models.KubernetesNamespaceData {
	return models.KubernetesNamespaceData{
		Name:   name,
		Labels: map[string]string{psaEnforceLabel: "restricted"},
	}
}

// nsWithoutLabel returns a KubernetesNamespaceData with no PSA enforce label.
func nsWithoutLabel(name string) models.KubernetesNamespaceData {
	return models.KubernetesNamespaceData{Name: name}
}

// saAutoMount returns a ServiceAccountData where automount is nil (default = true).
func saAutoMount(name, ns string) models.KubernetesServiceAccountData {
	return models.KubernetesServiceAccountData{Name: name, Namespace: ns}
}

// saDisabled returns a ServiceAccountData where automount is explicitly false.
func saDisabled(name, ns string) models.KubernetesServiceAccountData {
	f := false
	return models.KubernetesServiceAccountData{
		Name:                         name,
		Namespace:                    ns,
		AutomountServiceAccountToken: &f,
	}
}

// saEnabled returns a ServiceAccountData where automount is explicitly true.
func saEnabled(name, ns string) models.KubernetesServiceAccountData {
	t := true
	return models.KubernetesServiceAccountData{
		Name:                         name,
		Namespace:                    ns,
		AutomountServiceAccountToken: &t,
	}
}

// podWithSA returns a KubernetesPodData using the given service account.
func podWithSA(name, ns, sa string) models.KubernetesPodData {
	return models.KubernetesPodData{
		Name:               name,
		Namespace:          ns,
		ServiceAccountName: sa,
	}
}

// ── K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED ───────────────────────────────────

func TestPSANotEnforced_Fires_WhenNoNamespaceHasLabel(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(
			[]models.KubernetesNamespaceData{nsWithoutLabel("default"), nsWithoutLabel("production")},
			nil, nil,
		),
	}
	findings := K8SPodSecurityAdmissionNotEnforcedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED" {
		t.Errorf("RuleID = %q; want K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH", findings[0].Severity)
	}
}

func TestPSANotEnforced_Silent_WhenAtLeastOneNamespaceHasLabel(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(
			[]models.KubernetesNamespaceData{nsWithoutLabel("default"), nsWithLabel("production")},
			nil, nil,
		),
	}
	if got := (K8SPodSecurityAdmissionNotEnforcedRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when at least one ns has PSA label; got %d", len(got))
	}
}

func TestPSANotEnforced_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SPodSecurityAdmissionNotEnforcedRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestPSANotEnforced_Silent_WhenNoNamespaces(t *testing.T) {
	// A cluster with no namespaces at all — should still fire (no label means
	// no enforcement, so the cluster-level finding is appropriate).
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, nil, nil),
	}
	findings := K8SPodSecurityAdmissionNotEnforcedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for empty namespace list; got %d", len(findings))
	}
}

func TestPSANotEnforced_ResourceID_IsContextName(t *testing.T) {
	ctx := RuleContext{
		ClusterData: &models.KubernetesClusterData{
			ContextName: "my-prod-cluster",
			Namespaces:  []models.KubernetesNamespaceData{nsWithoutLabel("default")},
		},
	}
	findings := K8SPodSecurityAdmissionNotEnforcedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "my-prod-cluster" {
		t.Errorf("ResourceID = %q; want my-prod-cluster", findings[0].ResourceID)
	}
}

// ── K8S_NAMESPACE_PSS_NOT_SET ─────────────────────────────────────────────────

func TestNamespacePSSNotSet_Fires_PerNamespaceMissingLabel(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(
			[]models.KubernetesNamespaceData{
				nsWithoutLabel("default"),
				nsWithoutLabel("staging"),
				nsWithLabel("production"),
			},
			nil, nil,
		),
	}
	findings := K8SNamespacePSSNotSetRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (default + staging); got %d", len(findings))
	}
}

func TestNamespacePSSNotSet_Silent_WhenAllNamespacesHaveLabel(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(
			[]models.KubernetesNamespaceData{nsWithLabel("default"), nsWithLabel("prod")},
			nil, nil,
		),
	}
	if got := (K8SNamespacePSSNotSetRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings; got %d", len(got))
	}
}

func TestNamespacePSSNotSet_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SNamespacePSSNotSetRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestNamespacePSSNotSet_RuleID_Correct(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(
			[]models.KubernetesNamespaceData{nsWithoutLabel("default")},
			nil, nil,
		),
	}
	findings := K8SNamespacePSSNotSetRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_NAMESPACE_PSS_NOT_SET" {
		t.Errorf("RuleID = %q; want K8S_NAMESPACE_PSS_NOT_SET", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
	}
}

func TestNamespacePSSNotSet_ResourceID_IsNamespaceName(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(
			[]models.KubernetesNamespaceData{nsWithoutLabel("payments")},
			nil, nil,
		),
	}
	findings := K8SNamespacePSSNotSetRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].ResourceID != "payments" {
		t.Errorf("ResourceID = %q; want payments", findings[0].ResourceID)
	}
}

// ── K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT ────────────────────────────────────────

func TestSATokenAutomount_Fires_WhenAutomountNil(t *testing.T) {
	// nil means not set — Kubernetes defaults to true (auto-mount)
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, []models.KubernetesServiceAccountData{
			saAutoMount("default", "default"),
		}, nil),
	}
	findings := K8SServiceAccountTokenAutomountRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT" {
		t.Errorf("RuleID = %q; want K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
	}
}

func TestSATokenAutomount_Fires_WhenAutomountExplicitlyTrue(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, []models.KubernetesServiceAccountData{
			saEnabled("worker", "jobs"),
		}, nil),
	}
	findings := K8SServiceAccountTokenAutomountRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for explicit true; got %d", len(findings))
	}
}

func TestSATokenAutomount_Silent_WhenAutomountFalse(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, []models.KubernetesServiceAccountData{
			saDisabled("secure-sa", "default"),
		}, nil),
	}
	if got := (K8SServiceAccountTokenAutomountRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings when automount=false; got %d", len(got))
	}
}

func TestSATokenAutomount_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SServiceAccountTokenAutomountRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestSATokenAutomount_MultipleSAs_OnlyUnsafeFire(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, []models.KubernetesServiceAccountData{
			saDisabled("safe-sa", "default"),
			saAutoMount("default", "production"),
			saEnabled("enabled-sa", "staging"),
		}, nil),
	}
	findings := K8SServiceAccountTokenAutomountRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (default + enabled-sa); got %d", len(findings))
	}
}

// ── K8S_DEFAULT_SERVICEACCOUNT_USED ──────────────────────────────────────────

func TestDefaultSAUsed_Fires_WhenPodUsesDefaultSA(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, nil, []models.KubernetesPodData{
			podWithSA("my-pod", "default", "default"),
		}),
	}
	findings := K8SDefaultServiceAccountUsedRule{}.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding; got %d", len(findings))
	}
	if findings[0].RuleID != "K8S_DEFAULT_SERVICEACCOUNT_USED" {
		t.Errorf("RuleID = %q; want K8S_DEFAULT_SERVICEACCOUNT_USED", findings[0].RuleID)
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("Severity = %q; want MEDIUM", findings[0].Severity)
	}
}

func TestDefaultSAUsed_Silent_WhenPodUsesDedicatedSA(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, nil, []models.KubernetesPodData{
			podWithSA("my-pod", "default", "app-sa"),
		}),
	}
	if got := (K8SDefaultServiceAccountUsedRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings for dedicated SA; got %d", len(got))
	}
}

func TestDefaultSAUsed_Silent_WhenClusterDataNil(t *testing.T) {
	if got := (K8SDefaultServiceAccountUsedRule{}).Evaluate(RuleContext{}); len(got) != 0 {
		t.Errorf("expected 0 findings for nil ClusterData; got %d", len(got))
	}
}

func TestDefaultSAUsed_Silent_WhenSANameEmpty(t *testing.T) {
	// An empty serviceAccountName is not the same as "default" in the spec;
	// the rule only fires on the explicit string "default".
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, nil, []models.KubernetesPodData{
			podWithSA("unset-pod", "default", ""),
		}),
	}
	if got := (K8SDefaultServiceAccountUsedRule{}).Evaluate(ctx); len(got) != 0 {
		t.Errorf("expected 0 findings for empty SA name; got %d", len(got))
	}
}

func TestDefaultSAUsed_MultiplePods_OnlyDefaultFires(t *testing.T) {
	ctx := RuleContext{
		ClusterData: admissionCluster(nil, nil, []models.KubernetesPodData{
			podWithSA("pod-a", "default", "app-sa"),
			podWithSA("pod-b", "default", "default"),
			podWithSA("pod-c", "staging", "custom-sa"),
			podWithSA("pod-d", "staging", "default"),
		}),
	}
	findings := K8SDefaultServiceAccountUsedRule{}.Evaluate(ctx)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (pod-b + pod-d); got %d", len(findings))
	}
	names := map[string]bool{}
	for _, f := range findings {
		names[f.ResourceID] = true
	}
	if !names["pod-b"] || !names["pod-d"] {
		t.Errorf("expected findings for pod-b and pod-d; got %v", names)
	}
}
