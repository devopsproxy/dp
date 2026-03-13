package engine

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	k8scorepack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_core"
	"github.com/devopsproxy/dp/internal/rules"
)

// pssEngine builds a KubernetesEngine wired to the full kubernetes_core pack
// (which includes all 6 PSS rules) using a fake clientset.
func pssEngine(cs *fake.Clientset) *KubernetesEngine {
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "pss-cluster", Server: "https://fake"},
	}
	registry := rules.NewDefaultRuleRegistry()
	for _, r := range k8scorepack.New() {
		registry.Register(r)
	}
	return NewKubernetesEngine(provider, registry, nil)
}

// allPSSRuleIDs collects every rule ID visible in the report, including those
// stored in Metadata["rules"] when multiple findings were merged by the engine.
func allPSSRuleIDs(report *models.AuditReport) map[string]struct{} {
	out := make(map[string]struct{})
	for _, f := range report.Findings {
		out[f.RuleID] = struct{}{}
		if rr, ok := f.Metadata["rules"]; ok {
			switch v := rr.(type) {
			case []string:
				for _, r := range v {
					out[r] = struct{}{}
				}
			}
		}
	}
	return out
}

// pssPrivilegedPod creates a corev1.Pod with a privileged container.
func pssPrivilegedPod(name, ns string) *corev1.Pod {
	priv := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &priv,
					},
				},
			},
		},
	}
}

// pssHostNetworkPod creates a corev1.Pod with hostNetwork enabled.
func pssHostNetworkPod(name, ns string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers:  []corev1.Container{{Name: "app"}},
		},
	}
}

// pssMultiViolationPod creates a pod with both hostNetwork and privileged container.
func pssMultiViolationPod(name, ns string) *corev1.Pod {
	priv := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			HostNetwork: true,
			Containers: []corev1.Container{
				{
					Name: "bad",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &priv,
					},
				},
			},
		},
	}
}

// pssRunAsRootPod creates a pod whose container has runAsUser == 0.
func pssRunAsRootPod(name, ns string) *corev1.Pod {
	var uid int64 = 0
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "root-app",
					SecurityContext: &corev1.SecurityContext{
						RunAsUser: &uid,
					},
				},
			},
		},
	}
}

// pssSafePod creates a pod with a fully compliant security context.
func pssSafePod(name, ns string) *corev1.Pod {
	nonRoot := true
	var uid int64 = 1000
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "safe-app",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot: &nonRoot,
						RunAsUser:    &uid,
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
				},
			},
		},
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestPSSEngine_PrivilegedContainer_Fires verifies that a privileged pod triggers
// both K8S_PRIVILEGED_CONTAINER and K8S_POD_PRIVILEGED_CONTAINER at CRITICAL.
func TestPSSEngine_PrivilegedContainer_Fires(t *testing.T) {
	cs := fake.NewSimpleClientset(pssPrivilegedPod("priv-pod", "default"))
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_POD_PRIVILEGED_CONTAINER"]; !ok {
		t.Errorf("expected K8S_POD_PRIVILEGED_CONTAINER in findings; got %v", ruleIDs)
	}
}

// TestPSSEngine_HostNetwork_Fires verifies that a pod with hostNetwork fires
// K8S_POD_HOST_NETWORK at HIGH.
func TestPSSEngine_HostNetwork_Fires(t *testing.T) {
	cs := fake.NewSimpleClientset(pssHostNetworkPod("hostnet-pod", "default"))
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_POD_HOST_NETWORK"]; !ok {
		t.Errorf("expected K8S_POD_HOST_NETWORK in findings; got %v", ruleIDs)
	}
}

// TestPSSEngine_RunAsRoot_Fires verifies that a pod with runAsUser==0 fires
// K8S_POD_RUN_AS_ROOT at HIGH.
func TestPSSEngine_RunAsRoot_Fires(t *testing.T) {
	cs := fake.NewSimpleClientset(pssRunAsRootPod("root-pod", "default"))
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_POD_RUN_AS_ROOT"]; !ok {
		t.Errorf("expected K8S_POD_RUN_AS_ROOT in findings; got %v", ruleIDs)
	}
}

// TestPSSEngine_MultiViolation_BothRuleIDsPresent verifies that when a pod has
// multiple PSS violations (hostNetwork + privileged), both rule IDs appear in
// the report (possibly merged into one finding's Metadata["rules"]).
func TestPSSEngine_MultiViolation_BothRuleIDsPresent(t *testing.T) {
	cs := fake.NewSimpleClientset(pssMultiViolationPod("bad-pod", "default"))
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	want := []string{"K8S_POD_HOST_NETWORK", "K8S_POD_PRIVILEGED_CONTAINER"}
	for _, id := range want {
		if _, ok := ruleIDs[id]; !ok {
			t.Errorf("expected %q in report rule IDs; got %v", id, ruleIDs)
		}
	}
}

// TestPSSEngine_SafePod_NoPSSFindings verifies that a fully compliant pod with
// a non-root UID, runAsNonRoot enforced, and RuntimeDefault seccomp profile
// produces no PSS-specific findings.
func TestPSSEngine_SafePod_NoPSSFindings(t *testing.T) {
	cs := fake.NewSimpleClientset(pssSafePod("good-pod", "default"))
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	pssRules := []string{
		"K8S_POD_PRIVILEGED_CONTAINER",
		"K8S_POD_HOST_NETWORK",
		"K8S_POD_HOST_PID_OR_IPC",
		"K8S_POD_RUN_AS_ROOT",
		"K8S_POD_CAP_SYS_ADMIN",
		"K8S_POD_NO_SECCOMP",
	}
	ruleIDs := allPSSRuleIDs(report)
	for _, id := range pssRules {
		if _, ok := ruleIDs[id]; ok {
			t.Errorf("unexpected PSS finding %q for compliant pod", id)
		}
	}
}

// TestPSSEngine_NoSeccomp_Fires verifies that a pod with no seccomp profile
// fires K8S_POD_NO_SECCOMP at MEDIUM.
func TestPSSEngine_NoSeccomp_Fires(t *testing.T) {
	// A plain pod with no seccomp profile set.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "no-seccomp-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot: func() *bool { b := true; return &b }(),
						RunAsUser:    func() *int64 { v := int64(1000); return &v }(),
						// SeccompProfile intentionally omitted
					},
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_POD_NO_SECCOMP"]; !ok {
		t.Errorf("expected K8S_POD_NO_SECCOMP in findings; got %v", ruleIDs)
	}
	// Confirm severity is at most MEDIUM for this finding.
	for _, f := range report.Findings {
		if f.RuleID == "K8S_POD_NO_SECCOMP" && f.Severity != models.SeverityMedium {
			t.Errorf("K8S_POD_NO_SECCOMP severity = %q; want MEDIUM", f.Severity)
		}
	}
}

// TestPSSEngine_HostPID_Fires verifies that a pod with hostPID fires
// K8S_POD_HOST_PID_OR_IPC.
func TestPSSEngine_HostPID_Fires(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hostpid-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			HostPID:    true,
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_POD_HOST_PID_OR_IPC"]; !ok {
		t.Errorf("expected K8S_POD_HOST_PID_OR_IPC in findings; got %v", ruleIDs)
	}
}

// TestPSSEngine_CapSysAdmin_Fires verifies that a container adding SYS_ADMIN
// fires K8S_POD_CAP_SYS_ADMIN.
func TestPSSEngine_CapSysAdmin_Fires(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sysadmin-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"SYS_ADMIN"},
						},
					},
				},
			},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	ruleIDs := allPSSRuleIDs(report)
	if _, ok := ruleIDs["K8S_POD_CAP_SYS_ADMIN"]; !ok {
		t.Errorf("expected K8S_POD_CAP_SYS_ADMIN in findings; got %v", ruleIDs)
	}
}

// TestPSSEngine_MergeDoesNotCollapseAcrossRules verifies that findings for
// different pods are not merged together even when they have the same rule.
func TestPSSEngine_MergeDoesNotCollapseAcrossRules(t *testing.T) {
	cs := fake.NewSimpleClientset(
		pssPrivilegedPod("pod-a", "default"),
		pssPrivilegedPod("pod-b", "default"),
	)
	report, err := pssEngine(cs).RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	// Each pod is a distinct resource, so they must not be merged into one finding.
	podAFound, podBFound := false, false
	for _, f := range report.Findings {
		if f.ResourceID == "pod-a" {
			podAFound = true
		}
		if f.ResourceID == "pod-b" {
			podBFound = true
		}
	}
	if !podAFound {
		t.Errorf("expected finding for pod-a; not found in %v", report.Findings)
	}
	if !podBFound {
		t.Errorf("expected finding for pod-b; not found in %v", report.Findings)
	}
}

// TestPSSEngine_PolicyFiltering verifies that policy enforcement still works
// for PSS findings — a policy blocking MEDIUM findings suppresses K8S_POD_NO_SECCOMP.
func TestPSSEngine_PolicyFiltering(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "policy-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app"}},
		},
	}
	cs := fake.NewSimpleClientset(pod)

	// Policy: only surface CRITICAL and HIGH findings for the kubernetes domain.
	policyCfg := &policy.PolicyConfig{
		Domains: map[string]policy.DomainConfig{
			"kubernetes": {Enabled: true, MinSeverity: "HIGH"},
		},
	}

	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "pss-cluster"},
	}
	registry := rules.NewDefaultRuleRegistry()
	for _, r := range k8scorepack.New() {
		registry.Register(r)
	}
	eng := NewKubernetesEngine(provider, registry, policyCfg)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	for _, f := range report.Findings {
		if f.RuleID == "K8S_POD_NO_SECCOMP" {
			t.Errorf("K8S_POD_NO_SECCOMP (MEDIUM) should be filtered out by HIGH minimum_severity policy")
		}
	}
}
