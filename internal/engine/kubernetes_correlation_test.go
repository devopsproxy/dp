package engine

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/devopsproxy/dp/internal/models"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// chainPrivAndSysAdminPod creates a pod that is both privileged and adds
// SYS_ADMIN capability. Fires K8S_PRIVILEGED_CONTAINER + K8S_POD_PRIVILEGED_CONTAINER
// (both CRITICAL) and K8S_POD_CAP_SYS_ADMIN (HIGH) — all merged into one finding.
func chainPrivAndSysAdminPod(name, ns string) *corev1.Pod {
	priv := true
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &priv,
						Capabilities: &corev1.Capabilities{
							Add: []corev1.Capability{"SYS_ADMIN"},
						},
					},
				},
			},
		},
	}
}

// chainSysAdminPod creates a pod that adds SYS_ADMIN capability only (not privileged).
// Fires K8S_POD_CAP_SYS_ADMIN (HIGH).
func chainSysAdminPod(name, ns string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
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
}

// correlationEngine builds a KubernetesEngine backed by the full kubernetes_core
// pack using the given fake clientset and context name.
func correlationEngine(cs *fake.Clientset, contextName string) *KubernetesEngine {
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: contextName, Server: "https://fake"},
	}
	return newK8sEngine(provider, nil)
}

// ── Unit tests: ruleIDsForFinding ─────────────────────────────────────────────

// TestRuleIDsForFinding_PrimaryOnly verifies that a finding with no merged rules
// returns only the primary RuleID.
func TestRuleIDsForFinding_PrimaryOnly(t *testing.T) {
	f := models.Finding{RuleID: "K8S_PRIVILEGED_CONTAINER"}
	ids := ruleIDsForFinding(&f)
	if len(ids) != 1 || ids[0] != "K8S_PRIVILEGED_CONTAINER" {
		t.Errorf("expected [K8S_PRIVILEGED_CONTAINER]; got %v", ids)
	}
}

// TestRuleIDsForFinding_WithMergedRules verifies that rule IDs in
// Metadata["rules"] are included alongside the primary RuleID.
func TestRuleIDsForFinding_WithMergedRules(t *testing.T) {
	f := models.Finding{
		RuleID: "K8S_PRIVILEGED_CONTAINER",
		Metadata: map[string]any{
			"rules": []string{"K8S_POD_PRIVILEGED_CONTAINER", "K8S_POD_CAP_SYS_ADMIN"},
		},
	}
	ids := ruleIDsForFinding(&f)
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs; got %v", ids)
	}
	want := map[string]struct{}{
		"K8S_PRIVILEGED_CONTAINER":     {},
		"K8S_POD_PRIVILEGED_CONTAINER": {},
		"K8S_POD_CAP_SYS_ADMIN":        {},
	}
	for _, id := range ids {
		if _, ok := want[id]; !ok {
			t.Errorf("unexpected rule ID %q in result", id)
		}
	}
}

// TestRuleIDsForFinding_NilMetadata verifies that nil Metadata does not panic
// and only the primary RuleID is returned.
func TestRuleIDsForFinding_NilMetadata(t *testing.T) {
	f := models.Finding{RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nil}
	ids := ruleIDsForFinding(&f)
	if len(ids) != 1 || ids[0] != "K8S_POD_RUN_AS_ROOT" {
		t.Errorf("expected [K8S_POD_RUN_AS_ROOT]; got %v", ids)
	}
}

// ── Unit tests: buildNamespaceRuleIndex ───────────────────────────────────────

// TestBuildNamespaceRuleIndex_BasicMapping verifies that the index correctly
// maps each namespace to the rule IDs of its findings.
func TestBuildNamespaceRuleIndex_BasicMapping(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			Metadata:     map[string]any{"namespace": "production"},
		},
		{
			RuleID:       "K8S_POD_RUN_AS_ROOT",
			ResourceType: models.ResourceK8sPod,
			Metadata:     map[string]any{"namespace": "production"},
		},
		{
			RuleID:       "K8S_DEFAULT_SERVICEACCOUNT_USED",
			ResourceType: models.ResourceK8sPod,
			Metadata:     map[string]any{"namespace": "apps"},
		},
		{
			RuleID:       "K8S_CLUSTER_SINGLE_NODE",
			ResourceType: models.ResourceK8sCluster,
			// No namespace — cluster-scoped; must not appear in index.
		},
	}
	index := buildNamespaceRuleIndex(findings)

	if !nsIndexHas(index, "production", "K8S_SERVICE_PUBLIC_LOADBALANCER") {
		t.Error("expected K8S_SERVICE_PUBLIC_LOADBALANCER in production index")
	}
	if !nsIndexHas(index, "production", "K8S_POD_RUN_AS_ROOT") {
		t.Error("expected K8S_POD_RUN_AS_ROOT in production index")
	}
	if !nsIndexHas(index, "apps", "K8S_DEFAULT_SERVICEACCOUNT_USED") {
		t.Error("expected K8S_DEFAULT_SERVICEACCOUNT_USED in apps index")
	}
	if _, ok := index[""]; ok {
		t.Error("cluster-scoped finding (empty namespace) must not appear in the index")
	}
}

// TestBuildNamespaceRuleIndex_MergedRulesExpanded verifies that merged rule IDs
// from Metadata["rules"] are expanded into the namespace index.
func TestBuildNamespaceRuleIndex_MergedRulesExpanded(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_PRIVILEGED_CONTAINER",
			ResourceType: models.ResourceK8sPod,
			Metadata: map[string]any{
				"namespace": "production",
				"rules":     []string{"K8S_POD_CAP_SYS_ADMIN"},
			},
		},
	}
	index := buildNamespaceRuleIndex(findings)
	if !nsIndexHas(index, "production", "K8S_PRIVILEGED_CONTAINER") {
		t.Error("expected K8S_PRIVILEGED_CONTAINER in production index")
	}
	if !nsIndexHas(index, "production", "K8S_POD_CAP_SYS_ADMIN") {
		t.Error("expected merged K8S_POD_CAP_SYS_ADMIN in production index")
	}
}

// ── Unit tests: correlateRiskChains direct calls ──────────────────────────────

// TestCorrelateRiskChains_NoFindings verifies that nil and empty input do not panic.
func TestCorrelateRiskChains_NoFindings(t *testing.T) {
	correlateRiskChains(nil)
	correlateRiskChains([]models.Finding{})
}

// TestCorrelateRiskChains_Chain1_DirectUnit verifies that chain 1 annotates
// both the LB service finding and the pod-with-run-as-root finding in the same
// namespace with score=80.
func TestCorrelateRiskChains_Chain1_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "production"},
		},
		{
			RuleID:       "K8S_POD_RUN_AS_ROOT",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "root-pod",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "production"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 80 {
			t.Errorf("finding %q: risk_chain_score = %v; want 80", f.ResourceID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Public service exposes privileged workload" {
			t.Errorf("finding %q: risk_chain_reason = %q; want 'Public service exposes privileged workload'", f.ResourceID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain1_CapSysAdmin verifies that K8S_POD_CAP_SYS_ADMIN
// also triggers chain 1 (not just K8S_POD_RUN_AS_ROOT).
func TestCorrelateRiskChains_Chain1_CapSysAdmin(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "staging"},
		},
		{
			RuleID:       "K8S_POD_CAP_SYS_ADMIN",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "cap-pod",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "staging"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 80 {
			t.Errorf("finding %q: risk_chain_score = %v; want 80", f.ResourceID, f.Metadata["risk_chain_score"])
		}
	}
}

// TestCorrelateRiskChains_Chain1_NegativeDifferentNamespaces verifies that chain 1
// does NOT fire when LB and privileged pod are in different namespaces.
func TestCorrelateRiskChains_Chain1_NegativeDifferentNamespaces(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "production"},
		},
		{
			RuleID:       "K8S_POD_RUN_AS_ROOT",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "root-pod",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "staging"}, // different namespace
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("finding %q should have no chain annotation; got risk_chain_score=%v",
				f.ResourceID, f.Metadata["risk_chain_score"])
		}
	}
}

// TestCorrelateRiskChains_Chain1_NegativeLBOnly verifies that a standalone LB
// finding with no privileged pod in the same namespace is not annotated.
func TestCorrelateRiskChains_Chain1_NegativeLBOnly(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "production"},
		},
	}
	correlateRiskChains(findings)
	if _, ok := findings[0].Metadata["risk_chain_score"]; ok {
		t.Errorf("standalone LB finding should not have chain annotation; got %v",
			findings[0].Metadata["risk_chain_score"])
	}
}

// TestCorrelateRiskChains_Chain2_DirectUnit verifies that chain 2 annotates
// both the default-SA pod finding and the SA automount finding in the same
// namespace with score=60.
func TestCorrelateRiskChains_Chain2_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_DEFAULT_SERVICEACCOUNT_USED",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "app-pod",
			Severity:     models.SeverityMedium,
			Metadata:     map[string]any{"namespace": "apps"},
		},
		{
			RuleID:       "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT",
			ResourceType: models.ResourceK8sServiceAccount,
			ResourceID:   "default",
			Severity:     models.SeverityMedium,
			Metadata:     map[string]any{"namespace": "apps"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 60 {
			t.Errorf("finding %q: risk_chain_score = %v; want 60", f.ResourceID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Default service account with auto-mounted token" {
			t.Errorf("finding %q: risk_chain_reason = %q; want 'Default service account with auto-mounted token'",
				f.ResourceID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain2_NegativeNoDefaultSA verifies that chain 2 does
// NOT fire when there is an SA automount finding but no default-SA pod finding
// in the same namespace.
func TestCorrelateRiskChains_Chain2_NegativeNoDefaultSA(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT",
			ResourceType: models.ResourceK8sServiceAccount,
			ResourceID:   "custom-sa",
			Severity:     models.SeverityMedium,
			Metadata:     map[string]any{"namespace": "apps"},
		},
		// No K8S_DEFAULT_SERVICEACCOUNT_USED in "apps".
	}
	correlateRiskChains(findings)
	if _, ok := findings[0].Metadata["risk_chain_score"]; ok {
		t.Errorf("SA automount finding without default SA should not have chain annotation; got %v",
			findings[0].Metadata["risk_chain_score"])
	}
}

// TestCorrelateRiskChains_Chain3_DirectUnit verifies that chain 3 annotates
// both the K8S_CLUSTER_SINGLE_NODE finding and the CRITICAL pod finding with
// score=50.
func TestCorrelateRiskChains_Chain3_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_CLUSTER_SINGLE_NODE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "test-cluster",
			Severity:     models.SeverityHigh,
			// No namespace — cluster-scoped.
		},
		{
			RuleID:       "K8S_POD_PRIVILEGED_CONTAINER",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "priv-pod",
			Severity:     models.SeverityCritical,
			Metadata:     map[string]any{"namespace": "production"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 50 {
			t.Errorf("finding %q: risk_chain_score = %v; want 50", f.ResourceID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Single-node cluster with critical pod security violation" {
			t.Errorf("finding %q: risk_chain_reason = %q; want 'Single-node cluster with critical pod security violation'",
				f.ResourceID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain3_NegativeNoCritical verifies that chain 3 does
// NOT fire when the cluster has a single node but no CRITICAL finding exists.
func TestCorrelateRiskChains_Chain3_NegativeNoCritical(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_CLUSTER_SINGLE_NODE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "test-cluster",
			Severity:     models.SeverityHigh, // HIGH, not CRITICAL
		},
		{
			RuleID:       "K8S_NAMESPACE_WITHOUT_LIMITS",
			ResourceType: models.ResourceK8sNamespace,
			ResourceID:   "default",
			Severity:     models.SeverityMedium,
		},
	}
	correlateRiskChains(findings)
	for _, f := range findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("finding %q should have no chain annotation (no CRITICAL); got %v",
				f.ResourceID, f.Metadata["risk_chain_score"])
		}
	}
}

// TestCorrelateRiskChains_HighestScoreWins_DirectUnit verifies that when a
// finding participates in multiple chains, the highest score is kept.
func TestCorrelateRiskChains_HighestScoreWins_DirectUnit(t *testing.T) {
	// bad-pod finding: has K8S_POD_CAP_SYS_ADMIN (chain 1 eligible) and is CRITICAL (chain 3 eligible).
	// LB finding in same namespace triggers chain 1 (score 80) for bad-pod.
	// single-node finding triggers chain 3 (score 50) for bad-pod.
	// Highest should win: 80.
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "apps"},
		},
		{
			RuleID:       "K8S_POD_CAP_SYS_ADMIN",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "bad-pod",
			Severity:     models.SeverityCritical, // CRITICAL so chain 3 also considers it
			Metadata:     map[string]any{"namespace": "apps"},
		},
		{
			RuleID:       "K8S_CLUSTER_SINGLE_NODE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "test-cluster",
			Severity:     models.SeverityHigh,
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		if f.ResourceID != "bad-pod" {
			continue
		}
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 80 {
			t.Errorf("bad-pod: risk_chain_score = %v; want 80 (chain 1 > chain 3)", f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Public service exposes privileged workload" {
			t.Errorf("bad-pod: risk_chain_reason = %q; want chain 1 reason", reason)
		}
		return
	}
	t.Error("expected bad-pod finding")
}

// ── Engine-level integration tests ───────────────────────────────────────────

// TestCorrelationEngine_Chain1_BothFindingsAnnotated verifies that at engine level,
// both the public LB service finding and the run-as-root pod finding in the same
// namespace receive risk_chain_score=80.
func TestCorrelationEngine_Chain1_BothFindingsAnnotated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "chain1-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var lbAnnotated, podAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			lbAnnotated = ok && score == 80
		}
		if idsContain(ids, "K8S_POD_RUN_AS_ROOT") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			podAnnotated = ok && score == 80
		}
	}
	if !lbAnnotated {
		t.Error("K8S_SERVICE_PUBLIC_LOADBALANCER finding should have risk_chain_score=80")
	}
	if !podAnnotated {
		t.Error("K8S_POD_RUN_AS_ROOT finding should have risk_chain_score=80")
	}
}

// TestCorrelationEngine_Chain1_DifferentNamespaces verifies that chain 1 does
// NOT fire when the LB service and the privileged pod are in different namespaces.
func TestCorrelationEngine_Chain1_DifferentNamespaces(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "staging"), // different namespace
	)
	report, err := correlationEngine(cs, "chain1-diff-ns-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("no chain annotation expected (different namespaces); got risk_chain_score on %q (rule %q)",
				f.ResourceID, f.RuleID)
		}
	}
}

// TestCorrelationEngine_Chain2_BothFindingsAnnotated verifies that both the
// default-SA pod finding and the SA automount finding in the same namespace
// receive risk_chain_score=60 at engine level.
func TestCorrelationEngine_Chain2_BothFindingsAnnotated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		nsWithPSA("apps", "restricted"), // suppress namespace-level PSS/limits findings
		saAutoMountFake("default", "apps"),
		podWithDefaultSA("app-pod", "apps"),
	)
	report, err := correlationEngine(cs, "chain2-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var saAnnotated, podAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			saAnnotated = ok && score == 60
		}
		if idsContain(ids, "K8S_DEFAULT_SERVICEACCOUNT_USED") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			podAnnotated = ok && score == 60
		}
	}
	if !saAnnotated {
		t.Error("K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT finding should have risk_chain_score=60")
	}
	if !podAnnotated {
		t.Error("K8S_DEFAULT_SERVICEACCOUNT_USED finding should have risk_chain_score=60")
	}
}

// TestCorrelationEngine_Chain2_NoDefaultSA verifies that chain 2 does NOT fire
// when the pod uses a custom (non-default) ServiceAccount even if the SA has
// automount enabled.
func TestCorrelationEngine_Chain2_NoDefaultSA(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		nsWithPSA("apps", "restricted"),
		saAutoMountFake("custom-sa", "apps"),
		podWithCustomSA("app-pod", "apps", "custom-sa"),
	)
	report, err := correlationEngine(cs, "chain2-no-default-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("no chain annotation expected (custom SA); got risk_chain_score on %q (rule %q)",
				f.ResourceID, f.RuleID)
		}
	}
}

// TestCorrelationEngine_Chain3_BothFindingsAnnotated verifies that both the
// K8S_CLUSTER_SINGLE_NODE finding and the CRITICAL pod finding receive
// risk_chain_score=50.
func TestCorrelationEngine_Chain3_BothFindingsAnnotated(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"), // single node — fires K8S_CLUSTER_SINGLE_NODE
		pssPrivilegedPod("priv-pod", "production"),    // CRITICAL
	)
	report, err := correlationEngine(cs, "chain3-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var singleNodeAnnotated, criticalAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_CLUSTER_SINGLE_NODE") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			singleNodeAnnotated = ok && score == 50
		}
		if f.Severity == models.SeverityCritical {
			score, ok := f.Metadata["risk_chain_score"].(int)
			criticalAnnotated = ok && score == 50
		}
	}
	if !singleNodeAnnotated {
		t.Error("K8S_CLUSTER_SINGLE_NODE finding should have risk_chain_score=50")
	}
	if !criticalAnnotated {
		t.Error("CRITICAL finding should have risk_chain_score=50")
	}
}

// TestCorrelationEngine_Chain3_MultipleNodes verifies that chain 3 does NOT fire
// when the cluster has multiple nodes (no K8S_CLUSTER_SINGLE_NODE finding).
func TestCorrelationEngine_Chain3_MultipleNodes(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"), // multiple nodes
		pssPrivilegedPod("priv-pod", "production"),    // CRITICAL
	)
	report, err := correlationEngine(cs, "chain3-multi-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("no chain annotation expected (multiple nodes); got risk_chain_score on %q (rule %q)",
				f.ResourceID, f.RuleID)
		}
	}
}

// TestCorrelationEngine_Chain3_NoCritical verifies that chain 3 does NOT fire
// when the cluster has a single node but no CRITICAL findings exist.
func TestCorrelationEngine_Chain3_NoCritical(t *testing.T) {
	// 1 node fires K8S_CLUSTER_SINGLE_NODE (HIGH) only; no pods = no CRITICAL.
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
	)
	report, err := correlationEngine(cs, "chain3-no-crit-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("no chain annotation expected (no CRITICAL finding); got risk_chain_score on %q (rule %q)",
				f.ResourceID, f.RuleID)
		}
	}
}

// TestCorrelationEngine_HighestScoreWins verifies that a finding participating in
// both chain 1 (score 80) and chain 3 (score 50) keeps the highest score (80).
// Setup: 1 node + public LB in "apps" + pod with SYS_ADMIN+privileged in "apps".
// The merged pod finding is CRITICAL (chain 3: 50) and has K8S_POD_CAP_SYS_ADMIN
// with LB in same namespace (chain 1: 80).  Chain 1 wins.
func TestCorrelationEngine_HighestScoreWins(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sService("apps", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		chainPrivAndSysAdminPod("bad-pod", "apps"),
	)
	report, err := correlationEngine(cs, "highest-score-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// bad-pod merges: K8S_PRIVILEGED_CONTAINER + K8S_POD_PRIVILEGED_CONTAINER (CRITICAL)
	// + K8S_POD_CAP_SYS_ADMIN (HIGH) → one CRITICAL merged finding with K8S_POD_CAP_SYS_ADMIN
	// in ruleIDsForFinding.
	// Chain 1: nsHasLB=true, isPriv=true (K8S_POD_CAP_SYS_ADMIN) → score 80.
	// Chain 3: isCritical=true, hasSingleNode=true → score 50.
	// Highest = 80.
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if !idsContain(ids, "K8S_POD_CAP_SYS_ADMIN") {
			continue
		}
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 80 {
			t.Errorf("bad-pod finding: risk_chain_score = %v; want 80", f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Public service exposes privileged workload" {
			t.Errorf("bad-pod finding: risk_chain_reason = %q; want chain 1 reason", reason)
		}
		return
	}
	t.Error("expected finding with K8S_POD_CAP_SYS_ADMIN in ruleIDsForFinding; not found")
}

// TestCorrelationEngine_SortingUnaffected verifies that risk_chain annotations
// do not change the CRITICAL → HIGH → MEDIUM sort order of findings.
func TestCorrelationEngine_SortingUnaffected(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssPrivilegedPod("priv-pod", "production"), // CRITICAL
		pssRunAsRootPod("root-pod", "production"),  // HIGH (+ chain 1)
	)
	report, err := correlationEngine(cs, "sort-unaffected-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	if len(report.Findings) < 2 {
		t.Fatal("expected at least 2 findings")
	}
	// Findings must remain sorted highest severity first.
	for i := 1; i < len(report.Findings); i++ {
		prev := severityRank[report.Findings[i-1].Severity]
		curr := severityRank[report.Findings[i].Severity]
		if curr < prev {
			t.Errorf("findings not sorted at position %d (%s) vs %d (%s)",
				i, report.Findings[i].Severity, i-1, report.Findings[i-1].Severity)
		}
	}
	// CRITICAL finding must be first.
	if report.Findings[0].Severity != models.SeverityCritical {
		t.Errorf("findings[0].Severity = %q; want CRITICAL", report.Findings[0].Severity)
	}
}

// TestCorrelationEngine_Chain1_CapSysAdmin_Engine verifies that K8S_POD_CAP_SYS_ADMIN
// (not just K8S_POD_RUN_AS_ROOT) also triggers chain 1 at engine level.
func TestCorrelationEngine_Chain1_CapSysAdmin_Engine(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		chainSysAdminPod("sysadmin-pod", "production"),
	)
	report, err := correlationEngine(cs, "chain1-cap-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var lbAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			lbAnnotated = ok && score == 80
		}
	}
	if !lbAnnotated {
		t.Error("K8S_SERVICE_PUBLIC_LOADBALANCER should have risk_chain_score=80 when CAP_SYS_ADMIN pod is in same namespace")
	}
}

// TestCorrelationEngine_ExcludeSystem_ChainStillFires verifies that correlation
// works correctly when ExcludeSystem=true; workload findings still get annotated.
func TestCorrelationEngine_ExcludeSystem_ChainStillFires(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		// Workload namespace findings — should be correlated.
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
		// System namespace pod — excluded before correlation.
		k8sPod("kube-system", "sys-priv", true, "100m", "128Mi"),
	)
	report, err := correlationEngine(cs, "excl-chain-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		ExcludeSystem: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var lbAnnotated bool
	for _, f := range report.Findings {
		// No system findings should survive.
		if nst, ok := f.Metadata["namespace_type"].(string); ok && nst == "system" {
			t.Errorf("system finding %q survived ExcludeSystem=true", f.ResourceID)
		}
		ids := ruleIDsForFinding(&f)
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			score, ok := f.Metadata["risk_chain_score"].(int)
			lbAnnotated = ok && score == 80
		}
	}
	if !lbAnnotated {
		t.Error("workload LB finding should still have risk_chain_score=80 with ExcludeSystem=true")
	}
}

// ── Unit tests: getRiskScore ──────────────────────────────────────────────────

// TestGetRiskScore_Present verifies that getRiskScore returns the stored int score.
func TestGetRiskScore_Present(t *testing.T) {
	f := models.Finding{
		RuleID:   "K8S_SERVICE_PUBLIC_LOADBALANCER",
		Metadata: map[string]any{"risk_chain_score": 80},
	}
	if got := getRiskScore(f); got != 80 {
		t.Errorf("getRiskScore = %d; want 80", got)
	}
}

// TestGetRiskScore_Absent verifies that getRiskScore returns 0 when the key is missing.
func TestGetRiskScore_Absent(t *testing.T) {
	f := models.Finding{RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: map[string]any{"namespace": "prod"}}
	if got := getRiskScore(f); got != 0 {
		t.Errorf("getRiskScore = %d; want 0", got)
	}
}

// TestGetRiskScore_NilMetadata verifies that getRiskScore does not panic on nil Metadata.
func TestGetRiskScore_NilMetadata(t *testing.T) {
	f := models.Finding{RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nil}
	if got := getRiskScore(f); got != 0 {
		t.Errorf("getRiskScore = %d; want 0", got)
	}
}

// ── Engine-level summary.risk_score tests ─────────────────────────────────────

// TestCorrelationEngine_SummaryRiskScore_Chain1 verifies that when chain 1 fires
// (public LB + privileged workload in same namespace), report.Summary.RiskScore == 80.
func TestCorrelationEngine_SummaryRiskScore_Chain1(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "summary-risk-chain1-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if report.Summary.RiskScore != 80 {
		t.Errorf("Summary.RiskScore = %d; want 80 (chain 1 triggered)", report.Summary.RiskScore)
	}
}

// TestCorrelationEngine_SummaryRiskScore_NoChain verifies that when no risk chain
// fires, report.Summary.RiskScore == 0.
func TestCorrelationEngine_SummaryRiskScore_NoChain(t *testing.T) {
	// Two nodes, no pods, no services — only K8S_NAMESPACE_WITHOUT_LIMITS on default ns.
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
	)
	report, err := correlationEngine(cs, "summary-risk-nochain-ctx").RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if report.Summary.RiskScore != 0 {
		t.Errorf("Summary.RiskScore = %d; want 0 (no chain triggered)", report.Summary.RiskScore)
	}
}

// ── Unit tests: filterByMinRiskScore ─────────────────────────────────────────

// TestFilterByMinRiskScore_KeepsAboveMin verifies that findings at or above the
// minimum score are retained.
func TestFilterByMinRiskScore_KeepsAboveMin(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "A", Metadata: map[string]any{"risk_chain_score": 80}},
		{RuleID: "B", Metadata: map[string]any{"risk_chain_score": 60}},
		{RuleID: "C", Metadata: map[string]any{"risk_chain_score": 50}},
	}
	got := filterByMinRiskScore(findings, 60)
	if len(got) != 2 {
		t.Fatalf("filterByMinRiskScore(60) returned %d findings; want 2", len(got))
	}
	for _, f := range got {
		if getRiskScore(f) < 60 {
			t.Errorf("finding %q has score %d; should have been excluded", f.RuleID, getRiskScore(f))
		}
	}
}

// TestFilterByMinRiskScore_ExcludesNoScore verifies that findings with no
// risk_chain_score (score == 0) are excluded when min > 0.
func TestFilterByMinRiskScore_ExcludesNoScore(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "A", Metadata: map[string]any{"risk_chain_score": 80}},
		{RuleID: "B", Metadata: map[string]any{"namespace": "prod"}}, // no score
		{RuleID: "C", Metadata: nil},                                 // nil metadata
	}
	got := filterByMinRiskScore(findings, 10)
	if len(got) != 1 || got[0].RuleID != "A" {
		t.Errorf("filterByMinRiskScore(10) returned %v; want [A]", got)
	}
}

// TestFilterByMinRiskScore_AllExcluded verifies that a threshold higher than any
// chain score results in an empty slice.
func TestFilterByMinRiskScore_AllExcluded(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "A", Metadata: map[string]any{"risk_chain_score": 80}},
		{RuleID: "B", Metadata: map[string]any{"risk_chain_score": 60}},
	}
	got := filterByMinRiskScore(findings, 90)
	if len(got) != 0 {
		t.Errorf("filterByMinRiskScore(90) returned %d findings; want 0", len(got))
	}
}

// TestFilterByMinRiskScore_ZeroMinReturnsAll verifies that min==0 is a no-op
// (all findings returned). The engine guards with opts.MinRiskScore > 0 before
// calling filterByMinRiskScore, but the function itself must also be safe at 0.
func TestFilterByMinRiskScore_ZeroMinReturnsAll(t *testing.T) {
	findings := []models.Finding{
		{RuleID: "A", Metadata: map[string]any{"risk_chain_score": 80}},
		{RuleID: "B", Metadata: map[string]any{"namespace": "prod"}},
	}
	got := filterByMinRiskScore(findings, 0)
	if len(got) != 2 {
		t.Errorf("filterByMinRiskScore(0) returned %d findings; want 2 (all)", len(got))
	}
}

// ── Engine-level integration tests: MinRiskScore ─────────────────────────────

// TestCorrelationEngine_MinRiskScore_Chain1_PassesAt60 verifies that with
// MinRiskScore=60, chain 1 findings (score 80) are retained in the report.
func TestCorrelationEngine_MinRiskScore_Chain1_PassesAt60(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "min-risk-60-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 60,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected findings with MinRiskScore=60 when chain 1 (score 80) fires")
	}
	for _, f := range report.Findings {
		if getRiskScore(f) < 60 {
			t.Errorf("finding %q has score %d; should have been excluded by MinRiskScore=60",
				f.RuleID, getRiskScore(f))
		}
	}
}

// TestCorrelationEngine_MinRiskScore_Chain1_ExcludedAt90 verifies that with
// MinRiskScore=90, chain 1 findings (score 80) are excluded and the report is empty.
func TestCorrelationEngine_MinRiskScore_Chain1_ExcludedAt90(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "min-risk-90-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 90,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings with MinRiskScore=90 (chain 1 score is 80); got %d", len(report.Findings))
	}
}

// TestCorrelationEngine_MinRiskScore_NoChain_ExcludedAt10 verifies that when no
// chain fires (all scores are 0), MinRiskScore=10 excludes all findings.
func TestCorrelationEngine_MinRiskScore_NoChain_ExcludedAt10(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
	)
	report, err := correlationEngine(cs, "min-risk-no-chain-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 10,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings with MinRiskScore=10 and no chain; got %d", len(report.Findings))
	}
}

// TestCorrelationEngine_MinRiskScore_SummaryRiskScoreUnchanged verifies that
// Summary.RiskScore reflects the pre-filter risk picture even when MinRiskScore
// causes all findings to be excluded.
func TestCorrelationEngine_MinRiskScore_SummaryRiskScoreUnchanged(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "min-risk-summary-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 90, // excludes all (chain 1 score is 80)
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	// Findings filtered out, but Summary.RiskScore must still show the chain 1 score.
	if report.Summary.RiskScore != 80 {
		t.Errorf("Summary.RiskScore = %d; want 80 (pre-filter chain 1 score preserved)", report.Summary.RiskScore)
	}
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings (all excluded by MinRiskScore=90); got %d", len(report.Findings))
	}
}

// TestCorrelationEngine_MinRiskScore_SortingUnaffected verifies that findings
// retained after MinRiskScore filtering remain in CRITICAL → HIGH → MEDIUM order.
func TestCorrelationEngine_MinRiskScore_SortingUnaffected(t *testing.T) {
	// Chain 1 (score 80): LB in production + run-as-root pod in production
	// Chain 3 (score 50): single node + CRITICAL pod
	// MinRiskScore=60 → only chain 1 findings (80) survive
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssPrivilegedPod("priv-pod", "production"), // CRITICAL — chain 3 (50)
		pssRunAsRootPod("root-pod", "production"),  // HIGH — chain 1 (80)
	)
	report, err := correlationEngine(cs, "min-risk-sort-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		MinRiskScore: 60,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	for i := 1; i < len(report.Findings); i++ {
		prev := severityRank[report.Findings[i-1].Severity]
		curr := severityRank[report.Findings[i].Severity]
		if curr < prev {
			t.Errorf("findings not sorted at position %d (%s) after MinRiskScore filter",
				i, report.Findings[i].Severity)
		}
	}
}

// ── Phase 5C: EKS Identity Risk Correlation — direct unit tests ───────────────

// TestCorrelateRiskChains_Chain4_DirectUnit verifies that chain 4 annotates
// both EKS_NODE_ROLE_OVERPERMISSIVE and K8S_SERVICE_PUBLIC_LOADBALANCER with
// score=90 when both exist anywhere in the cluster (global scope).
func TestCorrelateRiskChains_Chain4_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "EKS_NODE_ROLE_OVERPERMISSIVE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "eks-cluster",
			Severity:     models.SeverityCritical,
			// No namespace — cluster-scoped.
		},
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "prod"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 90 {
			t.Errorf("finding %q: risk_chain_score = %v; want 90 (chain 4)",
				f.RuleID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Public service exposed in cluster with over-permissive node IAM role." {
			t.Errorf("finding %q: risk_chain_reason = %q; want chain 4 reason", f.RuleID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain4_Negative_NoPublicLB verifies that chain 4 does
// NOT fire when there is an over-permissive node role but no public LB.
func TestCorrelateRiskChains_Chain4_Negative_NoPublicLB(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "EKS_NODE_ROLE_OVERPERMISSIVE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "eks-cluster",
			Severity:     models.SeverityCritical,
		},
	}
	correlateRiskChains(findings)
	if _, ok := findings[0].Metadata["risk_chain_score"]; ok {
		t.Errorf("EKS_NODE_ROLE_OVERPERMISSIVE without public LB should not have chain 4 annotation; got %v",
			findings[0].Metadata["risk_chain_score"])
	}
}

// TestCorrelateRiskChains_Chain5_DirectUnit verifies that chain 5 annotates
// EKS_SERVICEACCOUNT_NO_IRSA and K8S_DEFAULT_SERVICEACCOUNT_USED findings in
// the same namespace with score=85.
func TestCorrelateRiskChains_Chain5_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "EKS_SERVICEACCOUNT_NO_IRSA",
			ResourceType: models.ResourceK8sServiceAccount,
			ResourceID:   "app-sa",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "prod"},
		},
		{
			RuleID:       "K8S_DEFAULT_SERVICEACCOUNT_USED",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "app-pod",
			Severity:     models.SeverityMedium,
			Metadata:     map[string]any{"namespace": "prod"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 85 {
			t.Errorf("finding %q: risk_chain_score = %v; want 85 (chain 5)",
				f.RuleID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Default service account used without IRSA." {
			t.Errorf("finding %q: risk_chain_reason = %q; want chain 5 reason", f.RuleID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain5_Negative_DifferentNamespace verifies that chain 5
// does NOT fire when EKS_SERVICEACCOUNT_NO_IRSA and K8S_DEFAULT_SERVICEACCOUNT_USED
// are in different namespaces.
func TestCorrelateRiskChains_Chain5_Negative_DifferentNamespace(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "EKS_SERVICEACCOUNT_NO_IRSA",
			ResourceType: models.ResourceK8sServiceAccount,
			ResourceID:   "app-sa",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "team-a"},
		},
		{
			RuleID:       "K8S_DEFAULT_SERVICEACCOUNT_USED",
			ResourceType: models.ResourceK8sPod,
			ResourceID:   "app-pod",
			Severity:     models.SeverityMedium,
			Metadata:     map[string]any{"namespace": "team-b"},
		},
	}
	correlateRiskChains(findings)
	for _, f := range findings {
		if _, ok := f.Metadata["risk_chain_score"]; ok {
			t.Errorf("finding %q in different namespace should not have chain 5 annotation; got %v",
				f.RuleID, f.Metadata["risk_chain_score"])
		}
	}
}

// TestCorrelateRiskChains_Chain6_DirectUnit verifies that chain 6 annotates
// EKS_OIDC_PROVIDER_NOT_ASSOCIATED and any HIGH severity findings with score=95
// when both conditions exist (global scope).
func TestCorrelateRiskChains_Chain6_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "EKS_OIDC_PROVIDER_NOT_ASSOCIATED",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "eks-cluster",
			Severity:     models.SeverityHigh,
			// No namespace — cluster-scoped.
		},
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "prod"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 95 {
			t.Errorf("finding %q: risk_chain_score = %v; want 95 (chain 6)",
				f.RuleID, f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Cluster lacks OIDC provider and has high-risk workload findings." {
			t.Errorf("finding %q: risk_chain_reason = %q; want chain 6 reason", f.RuleID, reason)
		}
	}
}

// TestCorrelateRiskChains_Chain6_Negative_NoOIDCFinding verifies that chain 6 does
// NOT fire when HIGH findings exist but EKS_OIDC_PROVIDER_NOT_ASSOCIATED is absent.
func TestCorrelateRiskChains_Chain6_Negative_NoOIDCFinding(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "prod"},
		},
	}
	correlateRiskChains(findings)
	if _, ok := findings[0].Metadata["risk_chain_score"]; ok {
		t.Errorf("HIGH finding without OIDC finding should not have chain 6 annotation; got %v",
			findings[0].Metadata["risk_chain_score"])
	}
}

// TestCorrelateRiskChains_Chain6Beats4_HighestScoreWins_DirectUnit verifies that
// when a finding qualifies for both chain 4 (score 90) and chain 6 (score 95),
// chain 6 wins and the finding receives score=95.
//
// The K8S_SERVICE_PUBLIC_LOADBALANCER finding (HIGH) participates in:
//   - Chain 4 (90): because EKS_NODE_ROLE_OVERPERMISSIVE and K8S_SERVICE_PUBLIC_LOADBALANCER both exist
//   - Chain 6 (95): because EKS_OIDC_PROVIDER_NOT_ASSOCIATED exists and the LB finding is HIGH
//
// Chain 6 (95) must win.
func TestCorrelateRiskChains_Chain6Beats4_HighestScoreWins_DirectUnit(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "EKS_NODE_ROLE_OVERPERMISSIVE",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "eks-cluster",
			Severity:     models.SeverityCritical,
		},
		{
			RuleID:       "EKS_OIDC_PROVIDER_NOT_ASSOCIATED",
			ResourceType: models.ResourceK8sCluster,
			ResourceID:   "eks-cluster-oidc",
			Severity:     models.SeverityHigh,
		},
		{
			RuleID:       "K8S_SERVICE_PUBLIC_LOADBALANCER",
			ResourceType: models.ResourceK8sService,
			ResourceID:   "web-svc",
			Severity:     models.SeverityHigh,
			Metadata:     map[string]any{"namespace": "prod"},
		},
	}
	correlateRiskChains(findings)

	for _, f := range findings {
		if f.RuleID != "K8S_SERVICE_PUBLIC_LOADBALANCER" {
			continue
		}
		score, ok := f.Metadata["risk_chain_score"].(int)
		if !ok || score != 95 {
			t.Errorf("K8S_SERVICE_PUBLIC_LOADBALANCER: risk_chain_score = %v; want 95 (chain 6 beats chain 4)",
				f.Metadata["risk_chain_score"])
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		if reason != "Cluster lacks OIDC provider and has high-risk workload findings." {
			t.Errorf("K8S_SERVICE_PUBLIC_LOADBALANCER: risk_chain_reason = %q; want chain 6 reason", reason)
		}
		return
	}
	t.Error("expected K8S_SERVICE_PUBLIC_LOADBALANCER finding")
}

// ── Phase 5C: EKS Identity Risk Correlation — engine integration tests ─────────

// TestCorrelationEngine_Chain4_NodeRoleAndPublicLB verifies that at engine level,
// both EKS_NODE_ROLE_OVERPERMISSIVE and K8S_SERVICE_PUBLIC_LOADBALANCER findings
// receive risk_chain_score=90 when they co-exist in the same cluster.
func TestCorrelationEngine_Chain4_NodeRoleAndPublicLB(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "chain4-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "arn:aws:iam::123:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/OK",
		NodeRolePolicies:     []string{"AdministratorAccess"}, // fires EKS_NODE_ROLE_OVERPERMISSIVE
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
		k8sNamespace("prod"),
		k8sService("prod", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "chain4-ctx"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var nodeRoleAnnotated, lbAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "EKS_NODE_ROLE_OVERPERMISSIVE") {
			score, _ := f.Metadata["risk_chain_score"].(int)
			nodeRoleAnnotated = score == 90
		}
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			score, _ := f.Metadata["risk_chain_score"].(int)
			lbAnnotated = score == 90
		}
	}
	if !nodeRoleAnnotated {
		t.Error("EKS_NODE_ROLE_OVERPERMISSIVE finding should have risk_chain_score=90 (chain 4)")
	}
	if !lbAnnotated {
		t.Error("K8S_SERVICE_PUBLIC_LOADBALANCER finding should have risk_chain_score=90 (chain 4)")
	}
}

// TestCorrelationEngine_Chain5_NoIRSAAndDefaultSA verifies that at engine level,
// EKS_SERVICEACCOUNT_NO_IRSA and K8S_DEFAULT_SERVICEACCOUNT_USED findings in the
// same namespace both receive risk_chain_score=85.
func TestCorrelationEngine_Chain5_NoIRSAAndDefaultSA(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "chain5-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "arn:aws:iam::123:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/OK",
		NodeRolePolicies:     nil,
	}

	noAutomount := false
	noIRSASA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app-sa",
			Namespace: "prod",
			// No IRSA annotation → fires EKS_SERVICEACCOUNT_NO_IRSA.
		},
		AutomountServiceAccountToken: &noAutomount, // disable to isolate chain 5 from chain 2
	}
	defaultSAPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "app-pod", Namespace: "prod"},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default", // fires K8S_DEFAULT_SERVICEACCOUNT_USED
			Containers:         []corev1.Container{{Name: "app", Image: "nginx"}},
		},
	}

	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
		k8sNamespace("prod"),
		noIRSASA,
		defaultSAPod,
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "chain5-ctx"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var noIRSAAnnotated, defaultSAAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "EKS_SERVICEACCOUNT_NO_IRSA") {
			score, _ := f.Metadata["risk_chain_score"].(int)
			noIRSAAnnotated = score == 85
		}
		if idsContain(ids, "K8S_DEFAULT_SERVICEACCOUNT_USED") {
			score, _ := f.Metadata["risk_chain_score"].(int)
			defaultSAAnnotated = score == 85
		}
	}
	if !noIRSAAnnotated {
		t.Error("EKS_SERVICEACCOUNT_NO_IRSA finding should have risk_chain_score=85 (chain 5)")
	}
	if !defaultSAAnnotated {
		t.Error("K8S_DEFAULT_SERVICEACCOUNT_USED finding should have risk_chain_score=85 (chain 5)")
	}
}

// TestCorrelationEngine_Chain6_OIDCMissingAndHighFinding verifies that at engine
// level, EKS_OIDC_PROVIDER_NOT_ASSOCIATED and any co-existing HIGH finding both
// receive risk_chain_score=95.
func TestCorrelationEngine_Chain6_OIDCMissingAndHighFinding(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "chain6-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "", // fires EKS_OIDC_PROVIDER_NOT_ASSOCIATED (HIGH)
		NodeRolePolicies:     nil,
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
		k8sNamespace("prod"),
		k8sService("prod", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "chain6-ctx"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var oidcAnnotated, lbAnnotated bool
	for i := range report.Findings {
		f := &report.Findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "EKS_OIDC_PROVIDER_NOT_ASSOCIATED") {
			score, _ := f.Metadata["risk_chain_score"].(int)
			oidcAnnotated = score == 95
		}
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			score, _ := f.Metadata["risk_chain_score"].(int)
			lbAnnotated = score == 95
		}
	}
	if !oidcAnnotated {
		t.Error("EKS_OIDC_PROVIDER_NOT_ASSOCIATED finding should have risk_chain_score=95 (chain 6)")
	}
	if !lbAnnotated {
		t.Error("K8S_SERVICE_PUBLIC_LOADBALANCER finding should have risk_chain_score=95 (chain 6)")
	}
}

// TestCorrelationEngine_Chain6Beats4_HighestScoreWins verifies that when both
// chain 4 (score 90) and chain 6 (score 95) apply to the same finding, chain 6
// wins. The K8S_SERVICE_PUBLIC_LOADBALANCER finding participates in both chains
// but must receive score=95.
func TestCorrelationEngine_Chain6Beats4_HighestScoreWins(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "chain-wins-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "",                              // chain 6 trigger: no OIDC
		NodeRolePolicies:     []string{"AdministratorAccess"}, // chain 4 trigger: over-permissive
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
		k8sNamespace("prod"),
		k8sService("prod", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "chain-wins-ctx"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// The LB finding is HIGH and participates in both chain 4 (90) and chain 6 (95).
	// Chain 6 must win.
	lbScore := -1
	for i := range report.Findings {
		f := &report.Findings[i]
		if idsContain(ruleIDsForFinding(f), "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			lbScore, _ = f.Metadata["risk_chain_score"].(int)
		}
	}
	if lbScore != 95 {
		t.Errorf("K8S_SERVICE_PUBLIC_LOADBALANCER: risk_chain_score = %d; want 95 (chain 6 beats chain 4 at 90)",
			lbScore)
	}
}

// ── Phase 5D: buildRiskChains unit tests ──────────────────────────────────────

// TestBuildRiskChains_Empty verifies that an empty finding slice yields nil chains.
func TestBuildRiskChains_Empty(t *testing.T) {
	chains := buildRiskChains(nil)
	if len(chains) != 0 {
		t.Errorf("buildRiskChains(nil): got %d chains; want 0", len(chains))
	}
}

// TestBuildRiskChains_NoChainFindings verifies that findings with no
// risk_chain_score produce no chains.
func TestBuildRiskChains_NoChainFindings(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_CLUSTER_SINGLE_NODE", Severity: models.SeverityHigh},
		{ID: "f2", RuleID: "K8S_NAMESPACE_WITHOUT_LIMITS", Severity: models.SeverityMedium},
	}
	chains := buildRiskChains(findings)
	if len(chains) != 0 {
		t.Errorf("buildRiskChains: got %d chains for unchained findings; want 0", len(chains))
	}
}

// TestBuildRiskChains_SingleChain verifies that two findings with the same
// score and reason are grouped into one chain entry.
func TestBuildRiskChains_SingleChain(t *testing.T) {
	findings := []models.Finding{
		{
			ID:       "f1",
			RuleID:   "K8S_SERVICE_PUBLIC_LOADBALANCER",
			Severity: models.SeverityHigh,
			Metadata: map[string]any{
				"risk_chain_score":  80,
				"risk_chain_reason": "Public service exposes privileged workload",
				"namespace":         "prod",
			},
		},
		{
			ID:       "f2",
			RuleID:   "K8S_POD_RUN_AS_ROOT",
			Severity: models.SeverityHigh,
			Metadata: map[string]any{
				"risk_chain_score":  80,
				"risk_chain_reason": "Public service exposes privileged workload",
				"namespace":         "prod",
			},
		},
	}
	chains := buildRiskChains(findings)
	if len(chains) != 1 {
		t.Fatalf("buildRiskChains: got %d chains; want 1", len(chains))
	}
	if chains[0].Score != 80 {
		t.Errorf("chain score = %d; want 80", chains[0].Score)
	}
	if chains[0].Reason != "Public service exposes privileged workload" {
		t.Errorf("chain reason = %q; unexpected", chains[0].Reason)
	}
	if len(chains[0].FindingIDs) != 2 {
		t.Errorf("chain finding IDs count = %d; want 2", len(chains[0].FindingIDs))
	}
}

// TestBuildRiskChains_MultipleChains verifies that findings with different scores
// are placed in separate chains and ordered by descending score.
func TestBuildRiskChains_MultipleChains(t *testing.T) {
	findings := []models.Finding{
		{
			ID:     "oidc",
			RuleID: "EKS_OIDC_PROVIDER_NOT_ASSOCIATED",
			Metadata: map[string]any{
				"risk_chain_score":  95,
				"risk_chain_reason": "Cluster lacks OIDC provider and has high-risk workload findings.",
			},
		},
		{
			ID:     "lb",
			RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER",
			Metadata: map[string]any{
				"risk_chain_score":  95,
				"risk_chain_reason": "Cluster lacks OIDC provider and has high-risk workload findings.",
			},
		},
		{
			ID:     "node-role",
			RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE",
			Metadata: map[string]any{
				"risk_chain_score":  90,
				"risk_chain_reason": "Public service exposed in cluster with over-permissive node IAM role.",
			},
		},
		{
			ID:     "chain2-sa",
			RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED",
			Metadata: map[string]any{
				"risk_chain_score":  60,
				"risk_chain_reason": "Default service account with auto-mounted token",
			},
		},
		{
			ID:     "unchained",
			RuleID: "K8S_CLUSTER_SINGLE_NODE",
		},
	}
	chains := buildRiskChains(findings)

	// Expect 3 chains: score 95, 90, 60 (unchained finding excluded).
	if len(chains) != 3 {
		t.Fatalf("buildRiskChains: got %d chains; want 3", len(chains))
	}
	if chains[0].Score != 95 {
		t.Errorf("chains[0].Score = %d; want 95 (descending order)", chains[0].Score)
	}
	if chains[1].Score != 90 {
		t.Errorf("chains[1].Score = %d; want 90", chains[1].Score)
	}
	if chains[2].Score != 60 {
		t.Errorf("chains[2].Score = %d; want 60", chains[2].Score)
	}
	// Score-95 chain must have 2 findings (oidc + lb).
	if len(chains[0].FindingIDs) != 2 {
		t.Errorf("chains[0].FindingIDs count = %d; want 2", len(chains[0].FindingIDs))
	}
}

// ── Phase 5D: ShowRiskChains engine integration tests ─────────────────────────

// TestShowRiskChains_Disabled_SummaryRiskChainsNil verifies that when
// ShowRiskChains is false (the default), Summary.RiskChains is nil.
func TestShowRiskChains_Disabled_SummaryRiskChainsNil(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "show-chains-off-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		ShowRiskChains: false,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if report.Summary.RiskChains != nil {
		t.Errorf("Summary.RiskChains should be nil when ShowRiskChains=false; got %v", report.Summary.RiskChains)
	}
}

// TestShowRiskChains_Enabled_SummaryPopulated verifies that when ShowRiskChains
// is true, Summary.RiskChains is populated with at least one chain entry.
func TestShowRiskChains_Enabled_SummaryPopulated(t *testing.T) {
	// Chain 1 (80): LB + run-as-root pod in same namespace.
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssRunAsRootPod("root-pod", "production"),
	)
	report, err := correlationEngine(cs, "show-chains-on-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		ShowRiskChains: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Summary.RiskChains) == 0 {
		t.Fatal("Summary.RiskChains should be populated when ShowRiskChains=true and chain 1 fires")
	}
	// The chain with score 80 must be present.
	found := false
	for _, c := range report.Summary.RiskChains {
		if c.Score == 80 {
			found = true
			if len(c.FindingIDs) == 0 {
				t.Error("chain score=80 has no FindingIDs; want at least 1")
			}
			break
		}
	}
	if !found {
		t.Errorf("no chain with score=80 found; got: %v", report.Summary.RiskChains)
	}
}

// TestShowRiskChains_Enabled_NoChain_EmptySlice verifies that when ShowRiskChains
// is true but no chain fires, Summary.RiskChains is an empty (non-nil) slice.
func TestShowRiskChains_Enabled_NoChain_EmptySlice(t *testing.T) {
	// Just two nodes, no chain-triggering conditions.
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
	)
	report, err := correlationEngine(cs, "show-chains-nochain-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		ShowRiskChains: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	// buildRiskChains on a set with no chain findings returns an empty slice (len 0).
	if len(report.Summary.RiskChains) != 0 {
		t.Errorf("expected 0 chains when no chain fires; got %d", len(report.Summary.RiskChains))
	}
}

// TestShowRiskChains_Enabled_OrderedDescending verifies that Summary.RiskChains
// is ordered by descending score.
func TestShowRiskChains_Enabled_OrderedDescending(t *testing.T) {
	// Chain 1 (80) + Chain 3 (50): LB + run-as-root pod (chain 1), single node + CRITICAL pod (chain 3).
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"), // single node → chain 3
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		pssPrivilegedPod("priv-pod", "production"), // CRITICAL → chain 3
		pssRunAsRootPod("root-pod", "production"),  // HIGH → chain 1
	)
	report, err := correlationEngine(cs, "show-chains-order-ctx").RunAudit(context.Background(), KubernetesAuditOptions{
		ShowRiskChains: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	chains := report.Summary.RiskChains
	for i := 1; i < len(chains); i++ {
		if chains[i].Score > chains[i-1].Score {
			t.Errorf("RiskChains not sorted at index %d: score %d follows %d",
				i, chains[i].Score, chains[i-1].Score)
		}
	}
}
