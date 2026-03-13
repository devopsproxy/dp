package engine

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	k8scorepack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_core"
	"github.com/devopsproxy/dp/internal/rules"
)

// fakeKubeProvider is a test double for kube.KubeClientProvider that returns
// a pre-built fake clientset.
type fakeKubeProvider struct {
	clientset k8sclient.Interface
	info      kube.ClusterInfo
}

func (f *fakeKubeProvider) ClientsetForContext(_ string) (k8sclient.Interface, kube.ClusterInfo, error) {
	return f.clientset, f.info, nil
}

// k8sNode builds a corev1.Node for use with the fake clientset.
func k8sNode(name, cpuCap, memCap, cpuAlloc, memAlloc string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpuCap),
				corev1.ResourceMemory: resource.MustParse(memCap),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(cpuAlloc),
				corev1.ResourceMemory: resource.MustParse(memAlloc),
			},
		},
	}
}

// k8sNamespace builds a corev1.Namespace for use with the fake clientset.
func k8sNamespace(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

// k8sLimitRange builds a corev1.LimitRange in the given namespace.
func k8sLimitRange(namespace, name string) *corev1.LimitRange {
	return &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
}

// newK8sEngine builds a KubernetesEngine backed by the full rule pack and the
// supplied fake provider.
func newK8sEngine(provider kube.KubeClientProvider, policyCfg *policy.PolicyConfig) *KubernetesEngine {
	registry := rules.NewDefaultRuleRegistry()
	for _, r := range k8scorepack.New() {
		registry.Register(r)
	}
	return NewKubernetesEngine(provider, registry, policyCfg)
}

// TestKubernetesEngine_SingleNodeCluster verifies that a single-node cluster
// triggers K8S_CLUSTER_SINGLE_NODE (HIGH) and that namespaces without
// LimitRanges trigger K8S_NAMESPACE_WITHOUT_LIMITS (MEDIUM).
func TestKubernetesEngine_SingleNodeCluster(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		// 1 node with healthy CPU — only cluster-single-node fires, not overallocated
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNamespace("default"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "test-ctx", Server: "https://127.0.0.1:6443"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// Expect: K8S_CLUSTER_SINGLE_NODE (HIGH) + K8S_NAMESPACE_WITHOUT_LIMITS (MEDIUM)
	if report.Summary.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings; got %d", report.Summary.TotalFindings)
	}
	if report.Summary.HighFindings < 1 {
		t.Error("expected at least 1 HIGH finding (cluster single node)")
	}
	if report.Summary.MediumFindings < 1 {
		t.Error("expected at least 1 MEDIUM finding (namespace without limits)")
	}

	// AuditType must be "kubernetes"
	if report.AuditType != "kubernetes" {
		t.Errorf("AuditType = %q; want kubernetes", report.AuditType)
	}
	// Profile must reflect context name
	if report.Profile != "test-ctx" {
		t.Errorf("Profile = %q; want test-ctx", report.Profile)
	}
}

// TestKubernetesEngine_SortingDeterministic verifies that findings are sorted
// HIGH before MEDIUM regardless of rule evaluation order.
func TestKubernetesEngine_SortingDeterministic(t *testing.T) {
	// 1 node (→ K8S_CLUSTER_SINGLE_NODE HIGH), 2 namespaces without limits (→ MEDIUM each)
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNamespace("ns-a"),
		k8sNamespace("ns-b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "sort-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// First finding must be HIGH.
	if len(report.Findings) == 0 {
		t.Fatal("no findings returned")
	}
	if report.Findings[0].Severity != models.SeverityHigh {
		t.Errorf("findings[0].Severity = %q; want HIGH", report.Findings[0].Severity)
	}
	// All subsequent findings must be <= severity of previous (non-ascending order).
	for i := 1; i < len(report.Findings); i++ {
		prev := severityRank[report.Findings[i-1].Severity]
		curr := severityRank[report.Findings[i].Severity]
		if curr < prev {
			t.Errorf("findings not sorted: position %d (%s) is more severe than position %d (%s)",
				i, report.Findings[i].Severity, i-1, report.Findings[i-1].Severity)
		}
	}
}

// TestKubernetesEngine_PolicyDomainDisabled verifies that when the kubernetes
// domain is disabled in the policy, all findings are suppressed.
func TestKubernetesEngine_PolicyDomainDisabled(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNamespace("default"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "policy-ctx"},
	}

	policyCfg := &policy.PolicyConfig{
		Version: 1,
		Domains: map[string]policy.DomainConfig{
			"kubernetes": {Enabled: false},
		},
	}

	eng := newK8sEngine(provider, policyCfg)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	if report.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 findings with domain disabled; got %d", report.Summary.TotalFindings)
	}
}

// TestKubernetesEngine_PolicyRuleDisabled verifies that a specific rule can be
// suppressed via the rules section of the policy config.
func TestKubernetesEngine_PolicyRuleDisabled(t *testing.T) {
	disabled := false
	policyCfg := &policy.PolicyConfig{
		Version: 1,
		Rules: map[string]policy.RuleConfig{
			"K8S_CLUSTER_SINGLE_NODE": {Enabled: &disabled},
		},
	}

	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNamespace("default"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "rule-disabled-ctx"},
	}

	eng := newK8sEngine(provider, policyCfg)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// K8S_CLUSTER_SINGLE_NODE should be suppressed; only MEDIUM namespace finding remains.
	for _, f := range report.Findings {
		if f.RuleID == "K8S_CLUSTER_SINGLE_NODE" {
			t.Errorf("K8S_CLUSTER_SINGLE_NODE finding present despite rule being disabled")
		}
	}
}

// TestKubernetesEngine_NodeOverallocated verifies that an overallocated node
// triggers K8S_NODE_OVERALLOCATED.
func TestKubernetesEngine_NodeOverallocated(t *testing.T) {
	// 400m / 4000m = 10% < 20% threshold → should fire
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "400m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "400m", "7Gi"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "overalloc-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var overallocCount int
	for _, f := range report.Findings {
		if f.RuleID == "K8S_NODE_OVERALLOCATED" {
			overallocCount++
		}
	}
	if overallocCount != 2 {
		t.Errorf("expected 2 K8S_NODE_OVERALLOCATED findings; got %d", overallocCount)
	}
}

// TestKubernetesEngine_NamespaceWithLimitRange verifies that a namespace that
// has a LimitRange does NOT trigger K8S_NAMESPACE_WITHOUT_LIMITS.
func TestKubernetesEngine_NamespaceWithLimitRange(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"), // 2 nodes: no single-node rule
		k8sNamespace("default"),
		k8sLimitRange("default", "resource-limits"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "lr-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.RuleID == "K8S_NAMESPACE_WITHOUT_LIMITS" {
			t.Errorf("K8S_NAMESPACE_WITHOUT_LIMITS fired for namespace with LimitRange")
		}
	}
}

// k8sPod builds a corev1.Pod for use with the fake clientset.
// cpuReq and memReq may be "" to omit resource requests.
func k8sPod(namespace, name string, privileged bool, cpuReq, memReq string) *corev1.Pod {
	privPtr := &privileged
	requests := corev1.ResourceList{}
	if cpuReq != "" {
		requests[corev1.ResourceCPU] = resource.MustParse(cpuReq)
	}
	if memReq != "" {
		requests[corev1.ResourceMemory] = resource.MustParse(memReq)
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "app",
					SecurityContext: &corev1.SecurityContext{
						Privileged: privPtr,
					},
					Resources: corev1.ResourceRequirements{
						Requests: requests,
					},
				},
			},
		},
	}
}

// k8sService builds a corev1.Service for use with the fake clientset.
func k8sService(namespace, name string, svcType corev1.ServiceType, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Annotations: annotations},
		Spec:       corev1.ServiceSpec{Type: svcType},
	}
}

// TestKubernetesEngine_PrivilegedContainer verifies that a privileged container
// triggers K8S_PRIVILEGED_CONTAINER (CRITICAL).
func TestKubernetesEngine_PrivilegedContainer(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		// privileged pod: true, with resource requests set (avoids no-request rule)
		k8sPod("default", "priv-pod", true, "100m", "128Mi"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "priv-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var privCount int
	for _, f := range report.Findings {
		if f.RuleID == "K8S_PRIVILEGED_CONTAINER" {
			privCount++
			if f.Severity != models.SeverityCritical {
				t.Errorf("K8S_PRIVILEGED_CONTAINER severity = %q; want CRITICAL", f.Severity)
			}
		}
	}
	if privCount != 1 {
		t.Errorf("expected 1 K8S_PRIVILEGED_CONTAINER finding; got %d", privCount)
	}
	if report.Summary.CriticalFindings < 1 {
		t.Error("expected at least 1 CRITICAL finding in summary")
	}
}

// TestKubernetesEngine_PublicLoadBalancer verifies that a public LoadBalancer
// Service triggers K8S_SERVICE_PUBLIC_LOADBALANCER (HIGH).
func TestKubernetesEngine_PublicLoadBalancer(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("production", "web-lb", corev1.ServiceTypeLoadBalancer, map[string]string{}),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "lb-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	var lbCount int
	for _, f := range report.Findings {
		if f.RuleID == "K8S_SERVICE_PUBLIC_LOADBALANCER" {
			lbCount++
		}
	}
	if lbCount != 1 {
		t.Errorf("expected 1 K8S_SERVICE_PUBLIC_LOADBALANCER finding; got %d", lbCount)
	}
}

// TestKubernetesEngine_InternalLoadBalancer verifies that a LoadBalancer Service
// annotated as internal does NOT trigger K8S_SERVICE_PUBLIC_LOADBALANCER.
func TestKubernetesEngine_InternalLoadBalancer(t *testing.T) {
	annotations := map[string]string{
		"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
	}
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		k8sService("default", "internal-lb", corev1.ServiceTypeLoadBalancer, annotations),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "internal-lb-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.RuleID == "K8S_SERVICE_PUBLIC_LOADBALANCER" {
			t.Errorf("K8S_SERVICE_PUBLIC_LOADBALANCER fired for internal LoadBalancer")
		}
	}
}

// TestKubernetesEngine_MixedFindings verifies that all three new rules fire
// together in a cluster with privileged pods, public LBs, and pods missing requests.
func TestKubernetesEngine_MixedFindings(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		k8sNode("node-1", "4", "8Gi", "3800m", "7Gi"),
		k8sNode("node-2", "4", "8Gi", "3800m", "7Gi"),
		// privileged container with resource requests (avoids no-request rule)
		k8sPod("kube-system", "priv-pod", true, "100m", "128Mi"),
		// pod without any resource requests
		k8sPod("default", "no-req-pod", false, "", ""),
		// public LoadBalancer
		k8sService("production", "web", corev1.ServiceTypeLoadBalancer, map[string]string{}),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "mixed-ctx"},
	}

	eng := newK8sEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// Use allPSSRuleIDs to check both primary RuleID and Metadata["rules"],
	// since PSS rules may merge with other rules for the same pod resource.
	ruleIDs := allPSSRuleIDs(report)
	for _, want := range []string{
		"K8S_PRIVILEGED_CONTAINER",
		"K8S_SERVICE_PUBLIC_LOADBALANCER",
		"K8S_POD_NO_RESOURCE_REQUESTS",
	} {
		if _, ok := ruleIDs[want]; !ok {
			t.Errorf("expected finding for rule %q; not found in report", want)
		}
	}
	// CRITICAL finding should be first (sorted highest severity first)
	if len(report.Findings) > 0 && report.Findings[0].Severity != models.SeverityCritical {
		t.Errorf("findings[0].Severity = %q; want CRITICAL (privileged container)", report.Findings[0].Severity)
	}
}
