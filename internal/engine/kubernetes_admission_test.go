package engine

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	k8scorepack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_core"
	"github.com/devopsproxy/dp/internal/rules"
)

// admissionEngine builds a KubernetesEngine wired to the full kubernetes_core
// pack (which now includes all 4 Phase 3B admission rules).
func admissionEngine(cs *fake.Clientset) *KubernetesEngine {
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "admission-cluster", Server: "https://fake"},
	}
	registry := rules.NewDefaultRuleRegistry()
	for _, r := range k8scorepack.New() {
		registry.Register(r)
	}
	return NewKubernetesEngine(provider, registry, nil)
}

// nsWithPSA builds a corev1.Namespace carrying the PSA enforce label.
func nsWithPSA(name, level string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": level},
		},
	}
}

// nsWithoutPSA builds a corev1.Namespace with no PSA label.
func nsWithoutPSA(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// saAutoMountFake builds a corev1.ServiceAccount where automount is nil.
func saAutoMountFake(name, ns string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
}

// saDisabledFake builds a corev1.ServiceAccount with automount explicitly false.
func saDisabledFake(name, ns string) *corev1.ServiceAccount {
	f := false
	return &corev1.ServiceAccount{
		ObjectMeta:                   metav1.ObjectMeta{Name: name, Namespace: ns},
		AutomountServiceAccountToken: &f,
	}
}

// podWithDefaultSA builds a corev1.Pod using the "default" service account.
func podWithDefaultSA(name, ns string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "app"}},
		},
	}
}

// podWithCustomSA builds a corev1.Pod using a named service account.
func podWithCustomSA(name, ns, sa string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			ServiceAccountName: sa,
			Containers:         []corev1.Container{{Name: "app"}},
		},
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestAdmission_ClusterWithNoPSALabels verifies that the cluster-level rule
// K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED fires when no namespace has the label.
func TestAdmission_ClusterWithNoPSALabels(t *testing.T) {
	cs := fake.NewSimpleClientset(
		nsWithoutPSA("default"),
		nsWithoutPSA("production"),
	)
	report, err := admissionEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED"]; !ok {
		t.Errorf("expected K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED; got %v", ruleIDs)
	}
}

// TestAdmission_ClusterWithPSALabel_ClusterRuleSilent verifies that when at
// least one namespace has the enforce label the cluster-level rule does not fire.
func TestAdmission_ClusterWithPSALabel_ClusterRuleSilent(t *testing.T) {
	cs := fake.NewSimpleClientset(
		nsWithoutPSA("default"),
		nsWithPSA("production", "restricted"),
	)
	report, err := admissionEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	for _, f := range report.Findings {
		if f.RuleID == "K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED" {
			t.Errorf("K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED should not fire when a namespace has the label")
		}
	}
}

// TestAdmission_MultipleNamespaceMissingPSS verifies K8S_NAMESPACE_PSS_NOT_SET
// fires for namespaces missing the enforce label. Because mergeFindings groups
// by {ResourceID, Region} and K8S_NAMESPACE_WITHOUT_LIMITS fires for the same
// namespace resources, the two rules are merged per namespace. We therefore count
// occurrences via the full rule-ID scan (primary + Metadata["rules"]).
func TestAdmission_MultipleNamespaceMissingPSS(t *testing.T) {
	cs := fake.NewSimpleClientset(
		nsWithoutPSA("default"),
		nsWithoutPSA("staging"),
		nsWithPSA("production", "baseline"),
	)
	report, err := admissionEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	// Count every finding that carries K8S_NAMESPACE_PSS_NOT_SET in its
	// primary RuleID or in its Metadata["rules"] slice.
	count := 0
	for _, f := range report.Findings {
		if f.RuleID == "K8S_NAMESPACE_PSS_NOT_SET" {
			count++
			continue
		}
		if ruleIDs, ok := f.Metadata["rules"].([]string); ok {
			for _, rid := range ruleIDs {
				if rid == "K8S_NAMESPACE_PSS_NOT_SET" {
					count++
					break
				}
			}
		}
	}
	if count != 2 {
		t.Errorf("expected 2 findings carrying K8S_NAMESPACE_PSS_NOT_SET (default + staging); got %d", count)
	}
}

// TestAdmission_SATokenAutomount_Fires verifies that service accounts with
// automount not explicitly disabled trigger K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT.
func TestAdmission_SATokenAutomount_Fires(t *testing.T) {
	cs := fake.NewSimpleClientset(
		nsWithoutPSA("default"),
		saAutoMountFake("default", "default"),
	)
	report, err := admissionEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT"]; !ok {
		t.Errorf("expected K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT; got %v", ruleIDs)
	}
}

// TestAdmission_SATokenAutomountDisabled_Silent verifies that a service account
// with automount=false does not trigger K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT.
func TestAdmission_SATokenAutomountDisabled_Silent(t *testing.T) {
	cs := fake.NewSimpleClientset(
		nsWithPSA("default", "restricted"),
		saDisabledFake("app-sa", "default"),
	)
	report, err := admissionEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	for _, f := range report.Findings {
		if f.RuleID == "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT" {
			t.Errorf("K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT should not fire for automount=false SA")
		}
	}
}

// TestAdmission_DefaultSA_Fires verifies that pods using "default" SA trigger
// K8S_DEFAULT_SERVICEACCOUNT_USED.
func TestAdmission_DefaultSA_Fires(t *testing.T) {
	cs := fake.NewSimpleClientset(
		nsWithoutPSA("default"),
		podWithDefaultSA("risky-pod", "default"),
	)
	report, err := admissionEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_DEFAULT_SERVICEACCOUNT_USED"]; !ok {
		t.Errorf("expected K8S_DEFAULT_SERVICEACCOUNT_USED; got %v", ruleIDs)
	}
}

// TestAdmission_CustomSA_Silent verifies that pods with a dedicated SA do not
// trigger K8S_DEFAULT_SERVICEACCOUNT_USED.
func TestAdmission_CustomSA_Silent(t *testing.T) {
	cs := fake.NewSimpleClientset(
		nsWithPSA("default", "restricted"),
		podWithCustomSA("safe-pod", "default", "app-sa"),
	)
	report, err := admissionEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	for _, f := range report.Findings {
		if f.RuleID == "K8S_DEFAULT_SERVICEACCOUNT_USED" {
			t.Errorf("K8S_DEFAULT_SERVICEACCOUNT_USED should not fire for custom SA pod")
		}
	}
}

// TestAdmission_SAAndPodRulesInteract verifies that both SA and pod findings
// are generated when the cluster has both an auto-mounting SA and a pod using
// the default SA. The SA "default" and the namespace "default" share the same
// ResourceID so their findings will be merged; we use allPSSRuleIDs to check
// both rule IDs are captured. The pod finding has a distinct ResourceID.
func TestAdmission_SAAndPodRulesInteract(t *testing.T) {
	cs := fake.NewSimpleClientset(
		nsWithoutPSA("default"),
		saAutoMountFake("default", "default"),
		podWithDefaultSA("bad-pod", "default"),
	)
	report, err := admissionEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	// allPSSRuleIDs scans both primary RuleID and Metadata["rules"] across all findings.
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT"]; !ok {
		t.Errorf("expected K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT in report; got %v", ruleIDs)
	}
	if _, ok := ruleIDs["K8S_DEFAULT_SERVICEACCOUNT_USED"]; !ok {
		t.Errorf("expected K8S_DEFAULT_SERVICEACCOUNT_USED in report; got %v", ruleIDs)
	}
}
