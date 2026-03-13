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

// ── annotateNamespaceType unit tests ─────────────────────────────────────────

// TestAnnotateNamespaceType_SystemNamespace verifies that a finding carrying
// Metadata["namespace"] = "kube-system" receives namespace_type = "system".
func TestAnnotateNamespaceType_SystemNamespace(t *testing.T) {
	findings := []models.Finding{
		{
			ResourceType: models.ResourceK8sPod,
			Metadata:     map[string]any{"namespace": "kube-system"},
		},
	}
	annotateNamespaceType(findings)
	if got := findings[0].Metadata["namespace_type"]; got != "system" {
		t.Errorf("namespace_type = %q; want system", got)
	}
}

// TestAnnotateNamespaceType_KubePublic verifies kube-public is tagged "system".
func TestAnnotateNamespaceType_KubePublic(t *testing.T) {
	findings := []models.Finding{
		{
			ResourceType: models.ResourceK8sPod,
			Metadata:     map[string]any{"namespace": "kube-public"},
		},
	}
	annotateNamespaceType(findings)
	if got := findings[0].Metadata["namespace_type"]; got != "system" {
		t.Errorf("namespace_type = %q; want system", got)
	}
}

// TestAnnotateNamespaceType_KubeNodeLease verifies kube-node-lease is tagged "system".
func TestAnnotateNamespaceType_KubeNodeLease(t *testing.T) {
	findings := []models.Finding{
		{
			ResourceType: models.ResourceK8sPod,
			Metadata:     map[string]any{"namespace": "kube-node-lease"},
		},
	}
	annotateNamespaceType(findings)
	if got := findings[0].Metadata["namespace_type"]; got != "system" {
		t.Errorf("namespace_type = %q; want system", got)
	}
}

// TestAnnotateNamespaceType_WorkloadNamespace verifies that a user namespace
// finding receives namespace_type = "workload".
func TestAnnotateNamespaceType_WorkloadNamespace(t *testing.T) {
	findings := []models.Finding{
		{
			ResourceType: models.ResourceK8sPod,
			Metadata:     map[string]any{"namespace": "production"},
		},
	}
	annotateNamespaceType(findings)
	if got := findings[0].Metadata["namespace_type"]; got != "workload" {
		t.Errorf("namespace_type = %q; want workload", got)
	}
}

// TestAnnotateNamespaceType_ClusterScoped verifies that a finding with no
// namespace metadata (cluster-scoped resource) receives namespace_type = "cluster".
func TestAnnotateNamespaceType_ClusterScoped(t *testing.T) {
	findings := []models.Finding{
		{
			ResourceType: models.ResourceK8sCluster,
			// No Metadata set — cluster-scoped finding.
		},
	}
	annotateNamespaceType(findings)
	if got := findings[0].Metadata["namespace_type"]; got != "cluster" {
		t.Errorf("namespace_type = %q; want cluster", got)
	}
}

// TestAnnotateNamespaceType_NodeScoped verifies K8S_NODE findings are "cluster".
func TestAnnotateNamespaceType_NodeScoped(t *testing.T) {
	findings := []models.Finding{
		{
			ResourceType: models.ResourceK8sNode,
			Metadata:     map[string]any{},
		},
	}
	annotateNamespaceType(findings)
	if got := findings[0].Metadata["namespace_type"]; got != "cluster" {
		t.Errorf("namespace_type = %q; want cluster", got)
	}
}

// TestAnnotateNamespaceType_NamespaceFinding verifies that a K8S_NAMESPACE
// finding (ResourceID = namespace name) is classified via ResourceType path.
func TestAnnotateNamespaceType_NamespaceFinding_System(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_NAMESPACE_WITHOUT_LIMITS",
			ResourceType: models.ResourceK8sNamespace,
			ResourceID:   "kube-system",
		},
	}
	annotateNamespaceType(findings)
	if got := findings[0].Metadata["namespace_type"]; got != "system" {
		t.Errorf("namespace_type = %q; want system", got)
	}
}

// TestAnnotateNamespaceType_NamespaceFinding_Workload verifies that a
// K8S_NAMESPACE finding for a user namespace is tagged "workload".
func TestAnnotateNamespaceType_NamespaceFinding_Workload(t *testing.T) {
	findings := []models.Finding{
		{
			RuleID:       "K8S_NAMESPACE_WITHOUT_LIMITS",
			ResourceType: models.ResourceK8sNamespace,
			ResourceID:   "staging",
		},
	}
	annotateNamespaceType(findings)
	if got := findings[0].Metadata["namespace_type"]; got != "workload" {
		t.Errorf("namespace_type = %q; want workload", got)
	}
}

// TestAnnotateNamespaceType_NilMetadata verifies that nil Metadata is
// initialised before writing namespace_type (no nil-pointer panic).
func TestAnnotateNamespaceType_NilMetadata(t *testing.T) {
	findings := []models.Finding{
		{
			ResourceType: models.ResourceK8sPod,
			Metadata:     nil, // explicitly nil
		},
	}
	annotateNamespaceType(findings) // must not panic
	if findings[0].Metadata == nil {
		t.Fatal("Metadata was not initialised")
	}
	if _, ok := findings[0].Metadata["namespace_type"]; !ok {
		t.Error("namespace_type key not set after nil Metadata initialisation")
	}
}

// ── excludeSystemFindings unit tests ─────────────────────────────────────────

// TestExcludeSystemFindings_RemovesSystem verifies that system findings are removed.
func TestExcludeSystemFindings_RemovesSystem(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "sys-pod", Metadata: map[string]any{"namespace_type": "system"}},
		{ResourceID: "app-pod", Metadata: map[string]any{"namespace_type": "workload"}},
		{ResourceID: "cluster-node", Metadata: map[string]any{"namespace_type": "cluster"}},
	}
	out := excludeSystemFindings(findings)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings after exclusion; got %d", len(out))
	}
	for _, f := range out {
		if f.Metadata["namespace_type"] == "system" {
			t.Errorf("system finding %q was not removed", f.ResourceID)
		}
	}
}

// TestExcludeSystemFindings_RetainsWorkloadAndCluster verifies workload and
// cluster findings survive the filter.
func TestExcludeSystemFindings_RetainsWorkloadAndCluster(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "app-pod", Metadata: map[string]any{"namespace_type": "workload"}},
		{ResourceID: "node-1", Metadata: map[string]any{"namespace_type": "cluster"}},
	}
	out := excludeSystemFindings(findings)
	if len(out) != 2 {
		t.Fatalf("expected 2 findings; got %d", len(out))
	}
}

// TestExcludeSystemFindings_EmptyInput verifies nil/empty input is handled.
func TestExcludeSystemFindings_EmptyInput(t *testing.T) {
	out := excludeSystemFindings(nil)
	if len(out) != 0 {
		t.Errorf("expected 0 findings for nil input; got %d", len(out))
	}
}

// ── Engine-level integration tests ───────────────────────────────────────────

// TestEngine_SystemNamespace_TaggedSystem verifies that a pod in kube-system
// receives namespace_type="system" in the audit report.
func TestEngine_SystemNamespace_TaggedSystem(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sPod("kube-system", "sys-priv", true, "100m", "128Mi"),
	)
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "ns-tag-ctx"},
	}
	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var found bool
	for _, f := range report.Findings {
		if f.ResourceID == "sys-priv" {
			found = true
			nst, ok := f.Metadata["namespace_type"].(string)
			if !ok || nst != "system" {
				t.Errorf("sys-priv namespace_type = %q; want system", nst)
			}
		}
	}
	if !found {
		t.Error("expected a finding for sys-priv; got none")
	}
}

// TestEngine_WorkloadNamespace_TaggedWorkload verifies that a pod in a user
// namespace receives namespace_type="workload".
func TestEngine_WorkloadNamespace_TaggedWorkload(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sPod("production", "app-priv", true, "100m", "128Mi"),
	)
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "workload-tag-ctx"},
	}
	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var found bool
	for _, f := range report.Findings {
		if f.ResourceID == "app-priv" {
			found = true
			nst, ok := f.Metadata["namespace_type"].(string)
			if !ok || nst != "workload" {
				t.Errorf("app-priv namespace_type = %q; want workload", nst)
			}
		}
	}
	if !found {
		t.Error("expected a finding for app-priv; got none")
	}
}

// TestEngine_ClusterScoped_TaggedCluster verifies that a cluster-scoped finding
// (K8S_CLUSTER_SINGLE_NODE) receives namespace_type="cluster".
func TestEngine_ClusterScoped_TaggedCluster(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"), // single node → fires
	)
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "single-node-ctx"},
	}
	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.RuleID == "K8S_CLUSTER_SINGLE_NODE" {
			nst, ok := f.Metadata["namespace_type"].(string)
			if !ok || nst != "cluster" {
				t.Errorf("K8S_CLUSTER_SINGLE_NODE namespace_type = %q; want cluster", nst)
			}
			return
		}
	}
	t.Error("expected K8S_CLUSTER_SINGLE_NODE finding; got none")
}

// TestEngine_NamespaceFinding_SystemTagged verifies that a namespace finding for
// kube-system (ResourceType=K8S_NAMESPACE, ResourceID="kube-system") is tagged "system".
func TestEngine_NamespaceFinding_SystemTagged(t *testing.T) {
	// kube-system namespace without a LimitRange fires K8S_NAMESPACE_WITHOUT_LIMITS.
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
	)
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "ns-system-ctx"},
	}
	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.ResourceID == "kube-system" {
			nst, ok := f.Metadata["namespace_type"].(string)
			if !ok || nst != "system" {
				t.Errorf("kube-system finding namespace_type = %q; want system", nst)
			}
			return
		}
	}
	t.Error("expected finding for kube-system namespace; got none")
}

// TestEngine_ExcludeSystem_RemovesSystemFindings verifies that --exclude-system
// removes findings tagged "system" while retaining workload findings.
func TestEngine_ExcludeSystem_RemovesSystemFindings(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sPod("kube-system", "sys-priv", true, "100m", "128Mi"),
		k8sPod("production", "app-priv", true, "100m", "128Mi"),
	)
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "excl-ctx"},
	}
	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{
		ExcludeSystem: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if nst, ok := f.Metadata["namespace_type"].(string); ok && nst == "system" {
			t.Errorf("found system finding after ExcludeSystem=true: ResourceID=%q RuleID=%q",
				f.ResourceID, f.RuleID)
		}
	}

	// Workload finding must still be present.
	var foundWorkload bool
	for _, f := range report.Findings {
		if f.ResourceID == "app-priv" {
			foundWorkload = true
		}
	}
	if !foundWorkload {
		t.Error("expected workload finding for app-priv to remain after ExcludeSystem=true")
	}
}

// TestEngine_ExcludeSystem_DefaultShowsAll verifies that the default (ExcludeSystem=false)
// includes both system and workload findings.
func TestEngine_ExcludeSystem_DefaultShowsAll(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sPod("kube-system", "sys-priv", true, "100m", "128Mi"),
		k8sPod("production", "app-priv", true, "100m", "128Mi"),
	)
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "default-show-ctx"},
	}
	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{
		ExcludeSystem: false,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var hasSystem, hasWorkload bool
	for _, f := range report.Findings {
		nst, _ := f.Metadata["namespace_type"].(string)
		if nst == "system" {
			hasSystem = true
		}
		if nst == "workload" {
			hasWorkload = true
		}
	}
	if !hasSystem {
		t.Error("expected at least one system finding when ExcludeSystem=false")
	}
	if !hasWorkload {
		t.Error("expected at least one workload finding when ExcludeSystem=false")
	}
}

// TestEngine_ServiceFinding_NamespaceTagged verifies that a service finding
// (K8S_SERVICE_PUBLIC_LOADBALANCER) receives the correct namespace_type.
func TestEngine_ServiceFinding_NamespaceTagged(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
	)
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "svc-ns-ctx"},
	}
	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.RuleID == "K8S_SERVICE_PUBLIC_LOADBALANCER" {
			nst, ok := f.Metadata["namespace_type"].(string)
			if !ok || nst != "workload" {
				t.Errorf("service finding namespace_type = %q; want workload", nst)
			}
			return
		}
	}
	t.Error("expected K8S_SERVICE_PUBLIC_LOADBALANCER finding; got none")
}

// TestEngine_AllFindingsHaveNamespaceType verifies that every finding in a
// mixed-resource cluster report carries a namespace_type metadata key.
func TestEngine_AllFindingsHaveNamespaceType(t *testing.T) {
	cs := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "400m", "7Gi"), // overallocated
		k8sPod("default", "priv-pod", true, "100m", "128Mi"),
		k8sService("staging", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
		k8sNamespace("default"),
	)
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: "all-tagged-ctx"},
	}
	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	if len(report.Findings) == 0 {
		t.Fatal("expected findings; got none")
	}
	for _, f := range report.Findings {
		nst, ok := f.Metadata["namespace_type"].(string)
		if !ok || nst == "" {
			t.Errorf("finding %q (rule %q) missing namespace_type", f.ResourceID, f.RuleID)
		}
	}
}
