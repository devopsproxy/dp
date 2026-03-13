package engine

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/devopsproxy/dp/internal/models"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	k8scorepack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_core"
	k8sekpack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_eks"
	"github.com/devopsproxy/dp/internal/rules"
)

// fakeEKSCollector implements EKSDataCollector for tests.
type fakeEKSCollector struct {
	data *models.KubernetesEKSData
	err  error
}

func (f *fakeEKSCollector) CollectEKSData(_ context.Context, _, _ string) (*models.KubernetesEKSData, error) {
	return f.data, f.err
}

// eksNode builds a Node with an EKS ProviderID and appropriate labels.
func eksNode(name, az string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"eks.amazonaws.com/nodegroup":    "workers",
				"eks.amazonaws.com/cluster-name": "test-cluster",
				"topology.kubernetes.io/region":  regionFromAZ(az),
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: "aws:///" + az + "/i-0abcdef1234567890",
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("3800m"),
				corev1.ResourceMemory: resource.MustParse("7Gi"),
			},
		},
	}
}

// gkeNode builds a Node with a GKE ProviderID.
func gkeNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"cloud.google.com/gke-nodepool": "default-pool",
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: "gce://my-project/us-central1-a/" + name,
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("8Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("3800m"),
				corev1.ResourceMemory: resource.MustParse("7Gi"),
			},
		},
	}
}

// regionFromAZ strips the trailing AZ letter to derive a region string.
func regionFromAZ(az string) string {
	if len(az) < 1 {
		return ""
	}
	return az[:len(az)-1]
}

// newEKSEngine builds a KubernetesEngineWithEKS using real rule packs and the given
// fake EKS collector.
func newEKSEngine(provider kube.KubeClientProvider, eksCollector EKSDataCollector) *KubernetesEngine {
	coreReg := rules.NewDefaultRuleRegistry()
	for _, r := range k8scorepack.New() {
		coreReg.Register(r)
	}
	eksReg := rules.NewDefaultRuleRegistry()
	for _, r := range k8sekpack.New() {
		eksReg.Register(r)
	}
	return NewKubernetesEngineWithEKS(provider, coreReg, eksReg, eksCollector, nil)
}

// ── Provider detection ────────────────────────────────────────────────────────

// TestDetectClusterProvider_EKS_ProviderID verifies aws:// ProviderID → "eks".
func TestDetectClusterProvider_EKS_ProviderID(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "node-1", ProviderID: "aws:///us-east-1a/i-abc"},
	}
	if got := detectClusterProvider(nodes); got != "eks" {
		t.Errorf("detectClusterProvider = %q; want eks", got)
	}
}

// TestDetectClusterProvider_EKS_Label verifies eks.amazonaws.com/nodegroup label → "eks".
func TestDetectClusterProvider_EKS_Label(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "node-1", Labels: map[string]string{"eks.amazonaws.com/nodegroup": "workers"}},
	}
	if got := detectClusterProvider(nodes); got != "eks" {
		t.Errorf("detectClusterProvider = %q; want eks", got)
	}
}

// TestDetectClusterProvider_GKE_ProviderID verifies gce:// ProviderID → "gke".
func TestDetectClusterProvider_GKE_ProviderID(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "node-1", ProviderID: "gce://project/zone/node-1"},
	}
	if got := detectClusterProvider(nodes); got != "gke" {
		t.Errorf("detectClusterProvider = %q; want gke", got)
	}
}

// TestDetectClusterProvider_GKE_Label verifies cloud.google.com/gke-nodepool label → "gke".
func TestDetectClusterProvider_GKE_Label(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "node-1", Labels: map[string]string{"cloud.google.com/gke-nodepool": "default"}},
	}
	if got := detectClusterProvider(nodes); got != "gke" {
		t.Errorf("detectClusterProvider = %q; want gke", got)
	}
}

// TestDetectClusterProvider_AKS_ProviderID verifies azure:// ProviderID → "aks".
func TestDetectClusterProvider_AKS_ProviderID(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "node-1", ProviderID: "azure:///subscriptions/xxx/resourceGroups/yyy/providers/Microsoft.Compute/virtualMachines/node-1"},
	}
	if got := detectClusterProvider(nodes); got != "aks" {
		t.Errorf("detectClusterProvider = %q; want aks", got)
	}
}

// TestDetectClusterProvider_AKS_Label verifies kubernetes.azure.com/cluster label → "aks".
func TestDetectClusterProvider_AKS_Label(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "node-1", Labels: map[string]string{"kubernetes.azure.com/cluster": "my-aks"}},
	}
	if got := detectClusterProvider(nodes); got != "aks" {
		t.Errorf("detectClusterProvider = %q; want aks", got)
	}
}

// TestDetectClusterProvider_Unknown verifies nodes without provider signals → "unknown".
func TestDetectClusterProvider_Unknown(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "node-1"},
	}
	if got := detectClusterProvider(nodes); got != "unknown" {
		t.Errorf("detectClusterProvider = %q; want unknown", got)
	}
}

// TestDetectClusterProvider_Empty verifies empty node list → "unknown".
func TestDetectClusterProvider_Empty(t *testing.T) {
	if got := detectClusterProvider(nil); got != "unknown" {
		t.Errorf("detectClusterProvider(nil) = %q; want unknown", got)
	}
}

// ── extractEKSInfo ────────────────────────────────────────────────────────────

// TestExtractEKSInfo_FromLabels verifies cluster name and region from labels.
func TestExtractEKSInfo_FromLabels(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{
			Name: "node-1",
			Labels: map[string]string{
				"eks.amazonaws.com/cluster-name": "prod-cluster",
				"topology.kubernetes.io/region":  "eu-west-1",
			},
		},
	}
	name, region := extractEKSInfo(nodes)
	if name != "prod-cluster" {
		t.Errorf("clusterName = %q; want prod-cluster", name)
	}
	if region != "eu-west-1" {
		t.Errorf("region = %q; want eu-west-1", region)
	}
}

// TestExtractEKSInfo_RegionFromProviderID verifies region fallback from ProviderID AZ.
func TestExtractEKSInfo_RegionFromProviderID(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{
			Name:       "node-1",
			ProviderID: "aws:///us-east-1a/i-0abcdef",
			Labels: map[string]string{
				"eks.amazonaws.com/cluster-name": "my-cluster",
			},
		},
	}
	name, region := extractEKSInfo(nodes)
	if name != "my-cluster" {
		t.Errorf("clusterName = %q; want my-cluster", name)
	}
	if region != "us-east-1" {
		t.Errorf("region = %q; want us-east-1", region)
	}
}

// TestExtractEKSInfo_NotFound verifies empty return when labels are missing.
func TestExtractEKSInfo_NotFound(t *testing.T) {
	nodes := []models.KubernetesNodeData{
		{Name: "node-1"},
	}
	name, region := extractEKSInfo(nodes)
	if name != "" || region != "" {
		t.Errorf("expected empty; got name=%q region=%q", name, region)
	}
}

// ── Engine integration: provider detection flows through RunAudit ─────────────

// TestKubernetesEngine_EKS_ProviderDetected verifies that an EKS cluster
// sets cluster_provider="eks" in the report metadata.
func TestKubernetesEngine_EKS_ProviderDetected(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "test-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingEnabled:       true,
		OIDCIssuer:           "https://oidc.eks.us-east-1.amazonaws.com/id/TEST",
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
		k8sNamespace("default"),
		k8sLimitRange("default", "limits"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-test"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	if report.Metadata == nil {
		t.Fatal("report.Metadata is nil; expected cluster_provider key")
	}
	prov, ok := report.Metadata["cluster_provider"]
	if !ok {
		t.Fatal("report.Metadata missing cluster_provider")
	}
	if prov != "eks" {
		t.Errorf("cluster_provider = %q; want eks", prov)
	}
}

// TestKubernetesEngine_GKE_ProviderDetected verifies that a GKE cluster
// sets cluster_provider="gke" in the report metadata.
func TestKubernetesEngine_GKE_ProviderDetected(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		gkeNode("gke-node-1"),
		gkeNode("gke-node-2"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "gke-test"},
	}

	// Use a nil EKS collector — GKE clusters don't call EKS API
	eng := newEKSEngine(provider, nil)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	prov, _ := report.Metadata["cluster_provider"]
	if prov != "gke" {
		t.Errorf("cluster_provider = %q; want gke", prov)
	}
}

// TestKubernetesEngine_EKS_RulesFire verifies that Phase 5A EKS-specific rules
// fire for a cluster with a public endpoint, no required log types, and no encryption.
func TestKubernetesEngine_EKS_RulesFire(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "bad-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: true,  // fires EKS_PUBLIC_ENDPOINT_ENABLED
		LoggingEnabled:       false, // kept for compat; new rule uses LoggingTypes
		LoggingTypes:         nil,   // fires EKS_CONTROL_PLANE_LOGGING_DISABLED
		EncryptionEnabled:    false, // fires EKS_ENCRYPTION_DISABLED
		OIDCIssuer:           "https://oidc.eks.us-east-1.amazonaws.com/id/X",
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-bad"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// All three EKS findings target the same resource (cluster name + region) so
	// mergeFindings collapses them into one finding. The merged finding preserves
	// every triggered rule ID in Metadata["rules"]. We collect all IDs from both
	// the top-level RuleID field and the merged rules list.
	allRuleIDs := make(map[string]bool)
	for _, f := range report.Findings {
		allRuleIDs[f.RuleID] = true
		if raw, ok := f.Metadata["rules"]; ok {
			if ruleList, ok := raw.([]string); ok {
				for _, id := range ruleList {
					allRuleIDs[id] = true
				}
			}
		}
	}
	for _, want := range []string{
		"EKS_PUBLIC_ENDPOINT_ENABLED",
		"EKS_CONTROL_PLANE_LOGGING_DISABLED",
		"EKS_ENCRYPTION_DISABLED",
	} {
		if !allRuleIDs[want] {
			t.Errorf("expected EKS rule %q in findings or merged rules; not found", want)
		}
	}
}

// TestKubernetesEngine_EKS_NoRulesFire_WhenSecure verifies that a correctly
// configured EKS cluster produces no EKS-specific findings.
func TestKubernetesEngine_EKS_NoRulesFire_WhenSecure(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "good-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingEnabled:       true,
		LoggingTypes:         []string{"api", "audit", "authenticator"}, // all required types present
		EncryptionEnabled:    true,
		OIDCIssuer:           "https://oidc.eks.us-east-1.amazonaws.com/id/OK",
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-good"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.RuleID == "EKS_PUBLIC_ENDPOINT_ENABLED" ||
			f.RuleID == "EKS_CONTROL_PLANE_LOGGING_DISABLED" ||
			f.RuleID == "EKS_ENCRYPTION_DISABLED" {
			t.Errorf("unexpected EKS finding %q for a secure cluster", f.RuleID)
		}
	}
}

// TestKubernetesEngine_EKS_CollectorFailure verifies that EKS collection
// failure is non-fatal: the audit completes with no EKS-specific findings.
func TestKubernetesEngine_EKS_CollectorFailure(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-fail"},
	}

	// Collector returns an error — EKS rules should be silently skipped.
	failCollector := &fakeEKSCollector{err: errors.New("simulated AWS API failure")}
	eng := newEKSEngine(provider, failCollector)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit should not return error on EKS collection failure; got: %v", err)
	}

	// No EKS-specific rule findings should appear (EKSData is nil after failure).
	for _, f := range report.Findings {
		if f.RuleID == "EKS_PUBLIC_ENDPOINT_ENABLED" ||
			f.RuleID == "EKS_CONTROL_PLANE_LOGGING_DISABLED" ||
			f.RuleID == "EKS_ENCRYPTION_DISABLED" {
			t.Errorf("unexpected EKS finding %q when collector failed", f.RuleID)
		}
	}

	// Provider should still be detected correctly.
	if prov := report.Metadata["cluster_provider"]; prov != "eks" {
		t.Errorf("cluster_provider = %q; want eks", prov)
	}
}

// TestKubernetesEngine_NonEKS_EKSRulesNotEvaluated verifies that EKS rules
// do not fire on non-EKS clusters even with a healthy EKS collector.
func TestKubernetesEngine_NonEKS_EKSRulesNotEvaluated(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		gkeNode("gke-node-1"),
		gkeNode("gke-node-2"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "gke-no-eks"},
	}

	// Collector would return EKS data — but should never be called for GKE.
	shouldNotCall := &fakeEKSCollector{data: &models.KubernetesEKSData{
		EndpointPublicAccess: true, // would fire if called
		OIDCIssuer:           "",
	}}
	eng := newEKSEngine(provider, shouldNotCall)
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	for _, f := range report.Findings {
		if f.RuleID == "EKS_PUBLIC_ENDPOINT_ENABLED" ||
			f.RuleID == "EKS_CONTROL_PLANE_LOGGING_DISABLED" ||
			f.RuleID == "EKS_ENCRYPTION_DISABLED" {
			t.Errorf("EKS rule %q fired on non-EKS cluster (GKE)", f.RuleID)
		}
	}
}

// ── Phase 5A engine integration tests ────────────────────────────────────────

// TestKubernetesEngine_EKS_EncryptionDisabled_IsCritical verifies that
// EKS_ENCRYPTION_DISABLED produces a CRITICAL severity finding.
func TestKubernetesEngine_EKS_EncryptionDisabled_IsCritical(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "no-enc-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    false, // fires EKS_ENCRYPTION_DISABLED (CRITICAL)
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-no-enc"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	// Collect all rule IDs across merged findings.
	allRuleIDs := make(map[string]bool)
	for _, f := range report.Findings {
		allRuleIDs[f.RuleID] = true
		if raw, ok := f.Metadata["rules"]; ok {
			if ruleList, ok := raw.([]string); ok {
				for _, id := range ruleList {
					allRuleIDs[id] = true
				}
			}
		}
	}
	if !allRuleIDs["EKS_ENCRYPTION_DISABLED"] {
		t.Fatal("expected EKS_ENCRYPTION_DISABLED finding; not found")
	}
	// Verify the merged finding carrying EKS_ENCRYPTION_DISABLED is at least CRITICAL.
	for _, f := range report.Findings {
		ids := ruleIDsForFinding(&f)
		hasEnc := false
		for _, id := range ids {
			if id == "EKS_ENCRYPTION_DISABLED" {
				hasEnc = true
			}
		}
		if hasEnc && f.Severity != models.SeverityCritical {
			t.Errorf("EKS_ENCRYPTION_DISABLED finding severity = %q; want CRITICAL", f.Severity)
		}
	}
}

// TestKubernetesEngine_EKS_PartialLogging_Fires verifies that
// EKS_CONTROL_PLANE_LOGGING_DISABLED fires when only some required log types
// are enabled (e.g. "api" and "audit" but not "authenticator").
func TestKubernetesEngine_EKS_PartialLogging_Fires(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "partial-log-cluster",
		Region:               "eu-west-1",
		EndpointPublicAccess: false,
		LoggingEnabled:       true,
		LoggingTypes:         []string{"api", "audit"}, // missing "authenticator"
		EncryptionEnabled:    true,
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "eu-west-1a"),
		eksNode("node-2", "eu-west-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-partial-log"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	allRuleIDs := make(map[string]bool)
	for _, f := range report.Findings {
		allRuleIDs[f.RuleID] = true
		if raw, ok := f.Metadata["rules"]; ok {
			if ruleList, ok := raw.([]string); ok {
				for _, id := range ruleList {
					allRuleIDs[id] = true
				}
			}
		}
	}
	if !allRuleIDs["EKS_CONTROL_PLANE_LOGGING_DISABLED"] {
		t.Error("expected EKS_CONTROL_PLANE_LOGGING_DISABLED when authenticator log type is missing")
	}
	if allRuleIDs["EKS_PUBLIC_ENDPOINT_ENABLED"] {
		t.Error("EKS_PUBLIC_ENDPOINT_ENABLED should not fire (endpoint is private)")
	}
	if allRuleIDs["EKS_ENCRYPTION_DISABLED"] {
		t.Error("EKS_ENCRYPTION_DISABLED should not fire (encryption is enabled)")
	}
}

// ── Phase 5B engine integration tests ────────────────────────────────────────

// allRuleIDsFromReport collects every rule ID across all findings (including
// merged-rule metadata) and returns them as a map for quick membership checks.
func allRuleIDsFromReport(findings []models.Finding) map[string]bool {
	out := make(map[string]bool)
	for _, f := range findings {
		out[f.RuleID] = true
		if raw, ok := f.Metadata["rules"]; ok {
			if ruleList, ok := raw.([]string); ok {
				for _, id := range ruleList {
					out[id] = true
				}
			}
		}
	}
	return out
}

// TestKubernetesEngine_EKS5B_OIDCNotAssociated_Fires verifies that
// EKS_OIDC_PROVIDER_NOT_ASSOCIATED fires when OIDCProviderARN is empty.
func TestKubernetesEngine_EKS5B_OIDCNotAssociated_Fires(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "no-oidc-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "", // fires EKS_OIDC_PROVIDER_NOT_ASSOCIATED
		NodeRolePolicies:     nil,
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-no-oidc"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	ids := allRuleIDsFromReport(report.Findings)
	if !ids["EKS_OIDC_PROVIDER_NOT_ASSOCIATED"] {
		t.Error("expected EKS_OIDC_PROVIDER_NOT_ASSOCIATED finding when OIDCProviderARN is empty")
	}
}

// TestKubernetesEngine_EKS5B_OIDCNotAssociated_Silent verifies that
// EKS_OIDC_PROVIDER_NOT_ASSOCIATED is silent when the OIDC provider ARN is set.
func TestKubernetesEngine_EKS5B_OIDCNotAssociated_Silent(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "oidc-ok-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/OK",
		NodeRolePolicies:     nil,
	}
	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-oidc-ok"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	ids := allRuleIDsFromReport(report.Findings)
	if ids["EKS_OIDC_PROVIDER_NOT_ASSOCIATED"] {
		t.Error("EKS_OIDC_PROVIDER_NOT_ASSOCIATED should not fire when OIDCProviderARN is set")
	}
}

// TestKubernetesEngine_EKS5B_NodeRoleOverpermissive_IsCritical verifies that
// EKS_NODE_ROLE_OVERPERMISSIVE fires with CRITICAL severity.
func TestKubernetesEngine_EKS5B_NodeRoleOverpermissive_IsCritical(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "overperm-cluster",
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
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-overperm"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	ids := allRuleIDsFromReport(report.Findings)
	if !ids["EKS_NODE_ROLE_OVERPERMISSIVE"] {
		t.Fatal("expected EKS_NODE_ROLE_OVERPERMISSIVE finding; not found")
	}
	// Verify the merged finding is at least CRITICAL.
	for _, f := range report.Findings {
		rids := ruleIDsForFinding(&f)
		hasRule := false
		for _, rid := range rids {
			if rid == "EKS_NODE_ROLE_OVERPERMISSIVE" {
				hasRule = true
			}
		}
		if hasRule && f.Severity != models.SeverityCritical {
			t.Errorf("EKS_NODE_ROLE_OVERPERMISSIVE finding severity = %q; want CRITICAL", f.Severity)
		}
	}
}

// TestKubernetesEngine_EKS5B_ServiceAccountNoIRSA_Fires verifies that
// EKS_SERVICEACCOUNT_NO_IRSA fires for a SA without the annotation.
func TestKubernetesEngine_EKS5B_ServiceAccountNoIRSA_Fires(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "irsa-test-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "arn:aws:iam::123:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/OK",
		NodeRolePolicies:     nil,
	}

	// SA without IRSA annotation — should fire the rule.
	noIRSASA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "no-irsa-sa",
			Namespace:   "prod",
			Annotations: nil,
		},
	}

	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
		k8sNamespace("prod"),
		noIRSASA,
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-irsa-test"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	ids := allRuleIDsFromReport(report.Findings)
	if !ids["EKS_SERVICEACCOUNT_NO_IRSA"] {
		t.Error("expected EKS_SERVICEACCOUNT_NO_IRSA finding for SA with no IRSA annotation")
	}
}

// TestKubernetesEngine_EKS5B_ServiceAccountNoIRSA_SilentWhenAnnotated verifies
// that EKS_SERVICEACCOUNT_NO_IRSA is silent when all SAs have the annotation.
func TestKubernetesEngine_EKS5B_ServiceAccountNoIRSA_SilentWhenAnnotated(t *testing.T) {
	eksData := &models.KubernetesEKSData{
		ClusterName:          "irsa-ok-cluster",
		Region:               "us-east-1",
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "arn:aws:iam::123:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/OK",
		NodeRolePolicies:     nil,
	}

	// SA with IRSA annotation — should not fire.
	irsaSA := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "irsa-sa",
			Namespace: "prod",
			Annotations: map[string]string{
				"eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/prod-role",
			},
		},
	}

	fakeClient := fake.NewSimpleClientset(
		eksNode("node-1", "us-east-1a"),
		eksNode("node-2", "us-east-1b"),
		k8sNamespace("prod"),
		irsaSA,
	)
	provider := &fakeKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "eks-irsa-ok"},
	}

	eng := newEKSEngine(provider, &fakeEKSCollector{data: eksData})
	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	ids := allRuleIDsFromReport(report.Findings)
	if ids["EKS_SERVICEACCOUNT_NO_IRSA"] {
		t.Error("EKS_SERVICEACCOUNT_NO_IRSA should not fire when all SAs have IRSA annotation")
	}
}
