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

// ── Helpers ───────────────────────────────────────────────────────────────────

// findPathByScore returns the first AttackPath with the given score, or zero value.
func findPathByScore(paths []models.AttackPath, score int) (models.AttackPath, bool) {
	for _, p := range paths {
		if p.Score == score {
			return p, true
		}
	}
	return models.AttackPath{}, false
}

// findAllPathsByScore returns all AttackPaths with the given score.
func findAllPathsByScore(paths []models.AttackPath, score int) []models.AttackPath {
	var out []models.AttackPath
	for _, p := range paths {
		if p.Score == score {
			out = append(out, p)
		}
	}
	return out
}

// attackPathEngineFor builds a KubernetesEngine backed by the full kubernetes_core
// and kubernetes_eks packs with an injected EKS collector.
func attackPathEngineFor(cs *fake.Clientset, contextName string, eksData *models.KubernetesEKSData) *KubernetesEngine {
	provider := &fakeKubeProvider{
		clientset: cs,
		info:      kube.ClusterInfo{ContextName: contextName, Server: "https://fake"},
	}
	return newEKSEngine(provider, &fakeEKSCollector{data: eksData})
}

// nsMeta returns a Metadata map with namespace set to ns.
// Additional key-value pairs can be supplied as alternating k, v arguments.
func nsMeta(ns string, kvs ...any) map[string]any {
	m := map[string]any{"namespace": ns}
	for i := 0; i+1 < len(kvs); i += 2 {
		if key, ok := kvs[i].(string); ok {
			m[key] = kvs[i+1]
		}
	}
	return m
}

// ── Unit tests: buildAttackPaths ──────────────────────────────────────────────

// TestBuildAttackPaths_NoFindings verifies nil and empty input do not panic.
func TestBuildAttackPaths_NoFindings(t *testing.T) {
	if got := buildAttackPaths(nil); len(got) != 0 {
		t.Errorf("expected nil/empty for nil input; got %v", got)
	}
	if got := buildAttackPaths([]models.Finding{}); len(got) != 0 {
		t.Errorf("expected nil/empty for empty input; got %v", got)
	}
}

// TestBuildAttackPaths_Path1_ThreeLayers verifies PATH 1 (score 98) triggers
// with the minimum required rule set (no optional IAM layer).
// All three findings are in the same namespace "prod".
func TestBuildAttackPaths_Path1_ThreeLayers(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f2", RuleID: "K8S_POD_RUN_AS_ROOT", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f3", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
	}
	paths := buildAttackPaths(findings)

	p, ok := findPathByScore(paths, 98)
	if !ok {
		t.Fatalf("expected PATH 1 (score 98); paths = %v", paths)
	}
	if p.Description != "Externally exposed privileged workload with weak identity isolation." {
		t.Errorf("unexpected description: %q", p.Description)
	}
	if len(p.Layers) != 3 {
		t.Errorf("expected 3 layers without IAM; got %v", p.Layers)
	}
	if p.Layers[0] != "Network Exposure" || p.Layers[1] != "Workload Privilege" || p.Layers[2] != "Identity Weakness" {
		t.Errorf("unexpected layers: %v", p.Layers)
	}
	// All three finding IDs must be present.
	fids := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fids[id] = struct{}{}
	}
	for _, want := range []string{"f1", "f2", "f3"} {
		if _, ok := fids[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 1; got %v", want, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path1_FourLayers verifies PATH 1 includes the optional
// "IAM Over-permission" layer when EKS_NODE_ROLE_OVERPERMISSIVE is present.
// The node role finding is cluster-scoped (no namespace metadata).
func TestBuildAttackPaths_Path1_FourLayers(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f2", RuleID: "K8S_POD_CAP_SYS_ADMIN", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f3", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		// EKS_NODE_ROLE_OVERPERMISSIVE is cluster-scoped — no namespace.
		{ID: "f4", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE", Severity: models.SeverityCritical},
	}
	paths := buildAttackPaths(findings)

	p, ok := findPathByScore(paths, 98)
	if !ok {
		t.Fatalf("expected PATH 1 (score 98); paths = %v", paths)
	}
	if len(p.Layers) != 4 {
		t.Errorf("expected 4 layers with IAM; got %v", p.Layers)
	}
	if p.Layers[3] != "IAM Over-permission" {
		t.Errorf("expected 4th layer to be 'IAM Over-permission'; got %q", p.Layers[3])
	}
	// All four finding IDs must be present.
	fids := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fids[id] = struct{}{}
	}
	for _, want := range []string{"f1", "f2", "f3", "f4"} {
		if _, ok := fids[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 1; got %v", want, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path1_CapSysAdminAlternative verifies PATH 1 triggers
// when K8S_POD_CAP_SYS_ADMIN satisfies the privilege condition (not RunAsRoot).
func TestBuildAttackPaths_Path1_CapSysAdminAlternative(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f2", RuleID: "K8S_POD_CAP_SYS_ADMIN", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f3", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 98); !ok {
		t.Errorf("expected PATH 1 to trigger with K8S_POD_CAP_SYS_ADMIN; paths = %v", paths)
	}
}

// TestBuildAttackPaths_Path1_NoPrivilege verifies PATH 1 does NOT trigger
// when no privilege-related rule (RunAsRoot / CapSysAdmin) is present.
func TestBuildAttackPaths_Path1_NoPrivilege(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		// no privilege rule
		{ID: "f3", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 98); ok {
		t.Errorf("expected PATH 1 NOT to trigger without privilege rule; got %v", paths)
	}
}

// TestBuildAttackPaths_Path1_NoIdentityWeak verifies PATH 1 does NOT trigger
// when neither EKS_SERVICEACCOUNT_NO_IRSA nor K8S_DEFAULT_SERVICEACCOUNT_USED is present.
func TestBuildAttackPaths_Path1_NoIdentityWeak(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f2", RuleID: "K8S_POD_RUN_AS_ROOT", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		// no identity weakness rule
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 98); ok {
		t.Errorf("expected PATH 1 NOT to trigger without identity weakness; got %v", paths)
	}
}

// TestBuildAttackPaths_Path2_Full verifies PATH 2 (score 92) triggers when
// the namespace-scoped rules coexist in a namespace AND the cluster has no OIDC.
func TestBuildAttackPaths_Path2_Full(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
		{ID: "f2", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
		{ID: "f3", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		// EKS_OIDC_PROVIDER_NOT_ASSOCIATED is cluster-scoped — no namespace.
		{ID: "f4", RuleID: "EKS_OIDC_PROVIDER_NOT_ASSOCIATED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)

	p, ok := findPathByScore(paths, 92)
	if !ok {
		t.Fatalf("expected PATH 2 (score 92); paths = %v", paths)
	}
	if p.Description != "Service account token misuse combined with missing IRSA and OIDC." {
		t.Errorf("unexpected description: %q", p.Description)
	}
	if len(p.Layers) != 3 {
		t.Errorf("expected 3 layers; got %v", p.Layers)
	}
	expectedLayers := []string{"Service Account Usage", "Token Exposure", "Identity Federation Missing"}
	for i, want := range expectedLayers {
		if i >= len(p.Layers) || p.Layers[i] != want {
			t.Errorf("layers[%d]: expected %q; got %q", i, want, p.Layers[i])
		}
	}
	fids := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fids[id] = struct{}{}
	}
	for _, want := range []string{"f1", "f2", "f3", "f4"} {
		if _, ok := fids[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 2; got %v", want, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path2_Incomplete verifies PATH 2 does NOT trigger when
// one of the required namespace-scoped rules is missing.
func TestBuildAttackPaths_Path2_Incomplete(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
		{ID: "f2", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
		{ID: "f3", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		// missing EKS_OIDC_PROVIDER_NOT_ASSOCIATED (cluster-level)
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 92); ok {
		t.Errorf("expected PATH 2 NOT to trigger with incomplete rules; got %v", paths)
	}
}

// TestBuildAttackPaths_Path3_Full verifies PATH 3 (score 90) triggers when
// all three cluster-scoped governance rules are present.
func TestBuildAttackPaths_Path3_Full(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "EKS_ENCRYPTION_DISABLED", Severity: models.SeverityCritical},
		{ID: "f2", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
		{ID: "f3", RuleID: "K8S_CLUSTER_SINGLE_NODE", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)

	p, ok := findPathByScore(paths, 90)
	if !ok {
		t.Fatalf("expected PATH 3 (score 90); paths = %v", paths)
	}
	if p.Description != "Cluster governance protections disabled with no redundancy." {
		t.Errorf("unexpected description: %q", p.Description)
	}
	if len(p.Layers) != 3 {
		t.Errorf("expected 3 layers; got %v", p.Layers)
	}
	expectedLayers := []string{"Encryption Disabled", "Logging Disabled", "No Redundancy"}
	for i, want := range expectedLayers {
		if i >= len(p.Layers) || p.Layers[i] != want {
			t.Errorf("layers[%d]: expected %q; got %q", i, want, p.Layers[i])
		}
	}
	fids := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fids[id] = struct{}{}
	}
	for _, want := range []string{"f1", "f2", "f3"} {
		if _, ok := fids[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 3; got %v", want, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path3_MissingEncryption verifies PATH 3 does NOT trigger
// when EKS_ENCRYPTION_DISABLED is absent.
func TestBuildAttackPaths_Path3_MissingEncryption(t *testing.T) {
	findings := []models.Finding{
		{ID: "f2", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
		{ID: "f3", RuleID: "K8S_CLUSTER_SINGLE_NODE", Severity: models.SeverityHigh},
		// missing EKS_ENCRYPTION_DISABLED
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 90); ok {
		t.Errorf("expected PATH 3 NOT to trigger without encryption rule; got %v", paths)
	}
}

// TestBuildAttackPaths_DescendingScore verifies that when multiple paths are
// detected they are returned in descending score order.
// PATH 1 (98) and PATH 3 (90) both trigger: namespace-scoped LB+priv+SA in
// "prod", plus cluster-scoped governance rules.
func TestBuildAttackPaths_DescendingScore(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f2", RuleID: "K8S_POD_RUN_AS_ROOT", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f3", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
		// Cluster-scoped governance findings (no namespace).
		{ID: "f4", RuleID: "EKS_ENCRYPTION_DISABLED", Severity: models.SeverityCritical},
		{ID: "f5", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
		{ID: "f6", RuleID: "K8S_CLUSTER_SINGLE_NODE", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)
	if len(paths) < 2 {
		t.Fatalf("expected at least 2 paths; got %d", len(paths))
	}
	if paths[0].Score <= paths[1].Score {
		t.Errorf("expected descending order; scores = %d, %d", paths[0].Score, paths[1].Score)
	}
	if paths[0].Score != 98 {
		t.Errorf("expected first path score 98; got %d", paths[0].Score)
	}
}

// TestBuildAttackPaths_PrimaryRuleIDContributes verifies that each finding
// contributes to attack path detection and collection via its PRIMARY rule ID.
// A finding with primary K8S_POD_RUN_AS_ROOT (PATH 1 allowed) and a merged
// K8S_POD_NO_SECCOMP (NOT in PATH 1 allowed set) must:
//   - Satisfy the privilege condition for PATH 1 (primary is allowed)
//   - Appear in PATH 1's FindingIDs (primary is allowed)
//   - NOT cause any K8S_POD_NO_SECCOMP-primary finding to appear in FindingIDs
func TestBuildAttackPaths_PrimaryRuleIDContributes(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		// Primary is K8S_POD_RUN_AS_ROOT (PATH 1 allowed); merged rule K8S_POD_NO_SECCOMP is not.
		{
			ID:     "priv-with-seccomp",
			RuleID: "K8S_POD_RUN_AS_ROOT",
			Metadata: map[string]any{
				"namespace": "prod",
				"rules":     []string{"K8S_POD_NO_SECCOMP"},
			},
			Severity: models.SeverityHigh,
		},
		{ID: "f-sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
	}
	paths := buildAttackPaths(findings)

	p, ok := findPathByScore(paths, 98)
	if !ok {
		t.Fatalf("expected PATH 1 to trigger (primary K8S_POD_RUN_AS_ROOT satisfies priv condition); paths=%v", paths)
	}

	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	// priv-with-seccomp MUST be included — its primary K8S_POD_RUN_AS_ROOT is allowed.
	if _, ok := fidSet["priv-with-seccomp"]; !ok {
		t.Errorf("expected priv-with-seccomp (primary=K8S_POD_RUN_AS_ROOT) in FindingIDs; got %v", p.FindingIDs)
	}
	// Verify: no finding with primary K8S_POD_NO_SECCOMP is in FindingIDs.
	// (There's no separate K8S_POD_NO_SECCOMP-primary finding in this test,
	// but the merged rule should not have added an unexpected entry.)
	for _, id := range p.FindingIDs {
		if id != "f-lb" && id != "priv-with-seccomp" && id != "f-sa" {
			t.Errorf("unexpected finding ID %q in PATH 1 FindingIDs; only allowed IDs expected", id)
		}
	}
}

// TestBuildAttackPaths_NoDuplicateFindingIDs verifies that each finding ID
// appears at most once in an AttackPath.FindingIDs slice.
// priv-merged has primary K8S_POD_RUN_AS_ROOT and merged K8S_POD_CAP_SYS_ADMIN.
// Under primary-only indexing, only K8S_POD_RUN_AS_ROOT indexes priv-merged,
// so it is collected exactly once.
func TestBuildAttackPaths_NoDuplicateFindingIDs(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{
			ID:     "priv-merged",
			RuleID: "K8S_POD_RUN_AS_ROOT",
			Metadata: map[string]any{
				"namespace": "prod",
				"rules":     []string{"K8S_POD_CAP_SYS_ADMIN"},
			},
			Severity: models.SeverityHigh,
		},
		{ID: "f3", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
	}
	paths := buildAttackPaths(findings)
	p, ok := findPathByScore(paths, 98)
	if !ok {
		t.Fatalf("expected PATH 1; paths = %v", paths)
	}
	seen := make(map[string]int)
	for _, id := range p.FindingIDs {
		seen[id]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("finding ID %q appears %d times (want 1) in PATH 1 FindingIDs", id, count)
		}
	}
}

// ── Strict rule-scoped filter tests ──────────────────────────────────────────

// TestBuildAttackPaths_StrictFilter_UnrelatedPrimaryExcluded verifies the dual-index
// design: when f-seccomp has PRIMARY=K8S_POD_NO_SECCOMP (not PATH 1 allowed) but
// Metadata["rules"] contains K8S_POD_RUN_AS_ROOT (a PATH 1 privilege rule), then:
//   - PATH 1 DOES trigger (expanded detection index finds K8S_POD_RUN_AS_ROOT)
//   - f-seccomp is NOT in PATH 1's FindingIDs (primary-only collection excludes it)
func TestBuildAttackPaths_StrictFilter_UnrelatedPrimaryExcluded(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		// PRIMARY is K8S_POD_NO_SECCOMP — NOT in PATH 1's collection set.
		// K8S_POD_RUN_AS_ROOT appears in Metadata["rules"] (merged) — detected but not collected.
		{
			ID:     "f-seccomp",
			RuleID: "K8S_POD_NO_SECCOMP",
			Metadata: map[string]any{
				"namespace": "prod",
				"rules":     []string{"K8S_POD_RUN_AS_ROOT"},
			},
			Severity: models.SeverityMedium,
		},
		{ID: "f-sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
	}
	paths := buildAttackPaths(findings)

	// PATH 1 must trigger: K8S_POD_RUN_AS_ROOT is in the expanded detection index.
	p, ok := findPathByScore(paths, 98)
	if !ok {
		t.Fatalf("expected PATH 1 to trigger via expanded detection (K8S_POD_RUN_AS_ROOT in merged rules); paths=%v", paths)
	}

	// f-seccomp (primary=K8S_POD_NO_SECCOMP) must NOT appear in FindingIDs.
	for _, fid := range p.FindingIDs {
		if fid == "f-seccomp" {
			t.Errorf("f-seccomp (primary=K8S_POD_NO_SECCOMP) must not appear in PATH 1 FindingIDs; got %v", p.FindingIDs)
		}
	}

	// f-lb and f-sa (allowed primaries) must be present.
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	for _, want := range []string{"f-lb", "f-sa"} {
		if _, ok := fidSet[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 1 FindingIDs; got %v", want, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_StrictFilter_Path1_OnlyAllowedRules verifies that PATH 1
// FindingIDs contain only findings whose primary rule ID is in PATH 1's allowed
// set, even when additional unrelated findings exist in the same namespace.
func TestBuildAttackPaths_StrictFilter_Path1_OnlyAllowedRules(t *testing.T) {
	allowedPath1 := map[string]bool{
		"K8S_SERVICE_PUBLIC_LOADBALANCER": true,
		"K8S_POD_RUN_AS_ROOT":             true,
		"K8S_POD_CAP_SYS_ADMIN":           true,
		"EKS_SERVICEACCOUNT_NO_IRSA":      true,
		"K8S_DEFAULT_SERVICEACCOUNT_USED": true,
		"EKS_NODE_ROLE_OVERPERMISSIVE":    true,
	}
	findings := []models.Finding{
		// PATH 1 qualifying findings.
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Severity: models.SeverityHigh,
			Metadata: nsMeta("prod")},
		{ID: "f-sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
		// Unrelated findings in the same namespace — must NOT appear in PATH 1.
		{ID: "f-seccomp", RuleID: "K8S_POD_NO_SECCOMP", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
		{ID: "f-requests", RuleID: "K8S_POD_NO_RESOURCE_REQUESTS", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
		{ID: "f-limits", RuleID: "K8S_NAMESPACE_WITHOUT_LIMITS", Severity: models.SeverityMedium,
			Metadata: nsMeta("prod")},
	}
	paths := buildAttackPaths(findings)
	p, ok := findPathByScore(paths, 98)
	if !ok {
		t.Fatalf("expected PATH 1 to trigger; paths=%v", paths)
	}
	// Every finding in PATH 1 must have a primary rule ID from the allowed set.
	for _, fid := range p.FindingIDs {
		// Find the finding by ID to get its RuleID.
		var found *models.Finding
		for i := range findings {
			if findings[i].ID == fid {
				found = &findings[i]
				break
			}
		}
		if found == nil {
			t.Errorf("PATH 1 FindingIDs contains unknown ID %q", fid)
			continue
		}
		if !allowedPath1[found.RuleID] {
			t.Errorf("PATH 1 contains finding %q with unallowed primary rule %q", fid, found.RuleID)
		}
	}
	// Unrelated findings must NOT be in PATH 1's FindingIDs.
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	for _, unrelated := range []string{"f-seccomp", "f-requests", "f-limits"} {
		if _, bad := fidSet[unrelated]; bad {
			t.Errorf("unrelated finding %q should not appear in PATH 1 FindingIDs; got %v", unrelated, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_StrictFilter_Path2_OnlyAllowedRules verifies that PATH 2
// FindingIDs contain only findings with primary rule IDs in PATH 2's allowed set.
func TestBuildAttackPaths_StrictFilter_Path2_OnlyAllowedRules(t *testing.T) {
	allowedPath2 := map[string]bool{
		"K8S_DEFAULT_SERVICEACCOUNT_USED":    true,
		"K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT": true,
		"EKS_SERVICEACCOUNT_NO_IRSA":         true,
		"EKS_OIDC_PROVIDER_NOT_ASSOCIATED":   true,
	}
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("app")},
		{ID: "f2", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Severity: models.SeverityMedium,
			Metadata: nsMeta("app")},
		{ID: "f3", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("app")},
		{ID: "oidc", RuleID: "EKS_OIDC_PROVIDER_NOT_ASSOCIATED", Severity: models.SeverityHigh},
		// Unrelated finding in same namespace — must NOT appear in PATH 2.
		{ID: "f-unrelated", RuleID: "K8S_POD_NO_SECCOMP", Severity: models.SeverityMedium,
			Metadata: nsMeta("app")},
	}
	paths := buildAttackPaths(findings)
	p, ok := findPathByScore(paths, 92)
	if !ok {
		t.Fatalf("expected PATH 2 to trigger; paths=%v", paths)
	}
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	// All expected findings must be present.
	for _, want := range []string{"f1", "f2", "f3", "oidc"} {
		if _, ok := fidSet[want]; !ok {
			t.Errorf("expected %q in PATH 2 FindingIDs; got %v", want, p.FindingIDs)
		}
	}
	// Unrelated finding must NOT be present.
	if _, bad := fidSet["f-unrelated"]; bad {
		t.Errorf("unrelated finding f-unrelated should not appear in PATH 2 FindingIDs; got %v", p.FindingIDs)
	}
	// All collected findings must have allowed primary rule IDs.
	for _, fid := range p.FindingIDs {
		var found *models.Finding
		for i := range findings {
			if findings[i].ID == fid {
				found = &findings[i]
				break
			}
		}
		if found != nil && !allowedPath2[found.RuleID] {
			t.Errorf("PATH 2 contains finding %q with unallowed primary rule %q", fid, found.RuleID)
		}
	}
}

// TestBuildAttackPaths_StrictFilter_Path3_OnlyAllowedRules verifies that PATH 3
// FindingIDs contain only findings with primary rule IDs in PATH 3's allowed set,
// even when other cluster-scoped findings are present.
func TestBuildAttackPaths_StrictFilter_Path3_OnlyAllowedRules(t *testing.T) {
	allowedPath3 := map[string]bool{
		"EKS_ENCRYPTION_DISABLED":            true,
		"EKS_CONTROL_PLANE_LOGGING_DISABLED": true,
		"K8S_CLUSTER_SINGLE_NODE":            true,
	}
	findings := []models.Finding{
		{ID: "f-enc", RuleID: "EKS_ENCRYPTION_DISABLED", Severity: models.SeverityCritical},
		{ID: "f-log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
		{ID: "f-sn", RuleID: "K8S_CLUSTER_SINGLE_NODE", Severity: models.SeverityHigh},
		// Unrelated cluster-scoped finding — must NOT appear in PATH 3.
		{ID: "f-oidc", RuleID: "EKS_OIDC_PROVIDER_NOT_ASSOCIATED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)
	p, ok := findPathByScore(paths, 90)
	if !ok {
		t.Fatalf("expected PATH 3 to trigger; paths=%v", paths)
	}
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	// All expected findings must be present.
	for _, want := range []string{"f-enc", "f-log", "f-sn"} {
		if _, ok := fidSet[want]; !ok {
			t.Errorf("expected %q in PATH 3 FindingIDs; got %v", want, p.FindingIDs)
		}
	}
	// Unrelated finding must NOT be present.
	if _, bad := fidSet["f-oidc"]; bad {
		t.Errorf("unrelated finding f-oidc should not appear in PATH 3 FindingIDs; got %v", p.FindingIDs)
	}
	// All collected findings must have allowed primary rule IDs.
	for _, fid := range p.FindingIDs {
		var found *models.Finding
		for i := range findings {
			if findings[i].ID == fid {
				found = &findings[i]
				break
			}
		}
		if found != nil && !allowedPath3[found.RuleID] {
			t.Errorf("PATH 3 contains finding %q with unallowed primary rule %q", fid, found.RuleID)
		}
	}
}

// ── Namespace-scoping tests ───────────────────────────────────────────────────

// TestBuildAttackPaths_Path1_TwoNamespaces_TwoPaths verifies that when two
// different namespaces independently satisfy the PATH 1 conditions, two separate
// AttackPath entries with score 98 are produced.
func TestBuildAttackPaths_Path1_TwoNamespaces_TwoPaths(t *testing.T) {
	findings := []models.Finding{
		// Namespace "ns-a": LB + RunAsRoot + DefaultSA
		{ID: "a-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-a")},
		{ID: "a-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-a")},
		{ID: "a-sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("ns-a")},
		// Namespace "ns-b": LB + CapSysAdmin + NoIRSA
		{ID: "b-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-b")},
		{ID: "b-priv", RuleID: "K8S_POD_CAP_SYS_ADMIN", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-b")},
		{ID: "b-sa", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-b")},
	}
	paths := buildAttackPaths(findings)

	p1Paths := findAllPathsByScore(paths, 98)
	if len(p1Paths) != 2 {
		t.Fatalf("expected 2 PATH 1 entries (one per namespace); got %d: %v", len(p1Paths), paths)
	}

	// Verify no cross-namespace contamination: collect all finding IDs per AttackPath.
	nsAIDs := map[string]struct{}{"a-lb": {}, "a-priv": {}, "a-sa": {}}
	nsBIDs := map[string]struct{}{"b-lb": {}, "b-priv": {}, "b-sa": {}}

	for _, ap := range p1Paths {
		fidSet := make(map[string]struct{})
		for _, id := range ap.FindingIDs {
			fidSet[id] = struct{}{}
		}
		isA := func() bool {
			for id := range nsAIDs {
				if _, ok := fidSet[id]; ok {
					return true
				}
			}
			return false
		}
		if isA() {
			// This AttackPath is for ns-a — must not contain ns-b findings.
			for id := range nsBIDs {
				if _, ok := fidSet[id]; ok {
					t.Errorf("ns-a attack path should not contain ns-b finding %q; findingIDs=%v", id, ap.FindingIDs)
				}
			}
		} else {
			// This AttackPath is for ns-b — must not contain ns-a findings.
			for id := range nsAIDs {
				if _, ok := fidSet[id]; ok {
					t.Errorf("ns-b attack path should not contain ns-a finding %q; findingIDs=%v", id, ap.FindingIDs)
				}
			}
		}
	}
}

// TestBuildAttackPaths_Path1_PrivPodInDifferentNamespace_NoPath verifies that
// when the LB is in ns-a and the privileged pod is only in ns-b, neither
// namespace satisfies PATH 1 (no cross-namespace path is built).
func TestBuildAttackPaths_Path1_PrivPodInDifferentNamespace_NoPath(t *testing.T) {
	findings := []models.Finding{
		// ns-a: LB + DefaultSA — no priv
		{ID: "a-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-a")},
		{ID: "a-sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("ns-a")},
		// ns-b: priv only — no LB, no SA
		{ID: "b-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-b")},
	}
	paths := buildAttackPaths(findings)
	if p1Paths := findAllPathsByScore(paths, 98); len(p1Paths) != 0 {
		t.Errorf("expected no PATH 1 when priv pod is in a different namespace; got %v", paths)
	}
}

// TestBuildAttackPaths_Path2_NamespaceScoped verifies PATH 2 (score 92) is built
// per-namespace: the cluster-level OIDC finding is included in the path together
// with namespace-scoped SA findings.
func TestBuildAttackPaths_Path2_NamespaceScoped(t *testing.T) {
	findings := []models.Finding{
		{ID: "f1", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("app")},
		{ID: "f2", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Severity: models.SeverityMedium,
			Metadata: nsMeta("app")},
		{ID: "f3", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("app")},
		// Cluster-level: no namespace.
		{ID: "oidc", RuleID: "EKS_OIDC_PROVIDER_NOT_ASSOCIATED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)

	p, ok := findPathByScore(paths, 92)
	if !ok {
		t.Fatalf("expected PATH 2 (score 92); paths = %v", paths)
	}
	// All four IDs must be present.
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	for _, want := range []string{"f1", "f2", "f3", "oidc"} {
		if _, ok := fidSet[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 2; got %v", want, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_UnrelatedNamespaceExcluded verifies that findings in an
// unrelated namespace do not contribute to the qualifying namespace's attack path.
func TestBuildAttackPaths_UnrelatedNamespaceExcluded(t *testing.T) {
	findings := []models.Finding{
		// ns-a qualifies for PATH 1.
		{ID: "a-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-a")},
		{ID: "a-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-a")},
		{ID: "a-sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("ns-a")},
		// ns-b has unrelated findings.
		{ID: "b-other1", RuleID: "K8S_POD_NO_RESOURCE_REQUESTS", Severity: models.SeverityMedium,
			Metadata: nsMeta("ns-b")},
		{ID: "b-other2", RuleID: "K8S_NAMESPACE_WITHOUT_LIMITS", Severity: models.SeverityMedium,
			Metadata: nsMeta("ns-b")},
	}
	paths := buildAttackPaths(findings)

	p1Paths := findAllPathsByScore(paths, 98)
	if len(p1Paths) != 1 {
		t.Fatalf("expected exactly 1 PATH 1 (for ns-a only); got %d: %v", len(p1Paths), paths)
	}

	// The single PATH 1 must not contain ns-b findings.
	ap := p1Paths[0]
	unrelated := map[string]struct{}{"b-other1": {}, "b-other2": {}}
	for _, fid := range ap.FindingIDs {
		if _, bad := unrelated[fid]; bad {
			t.Errorf("PATH 1 for ns-a should not contain unrelated ns-b finding %q; findingIDs=%v",
				fid, ap.FindingIDs)
		}
	}
	// Must contain ns-a findings.
	required := map[string]struct{}{"a-lb": {}, "a-priv": {}, "a-sa": {}}
	fidSet := make(map[string]struct{})
	for _, id := range ap.FindingIDs {
		fidSet[id] = struct{}{}
	}
	for want := range required {
		if _, ok := fidSet[want]; !ok {
			t.Errorf("expected finding ID %q from ns-a in PATH 1; got %v", want, ap.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path2_TwoNamespaces_TwoPaths verifies that two namespaces
// independently satisfying PATH 2 conditions produce two separate AttackPath entries.
func TestBuildAttackPaths_Path2_TwoNamespaces_TwoPaths(t *testing.T) {
	findings := []models.Finding{
		// Namespace "svc-a": DefaultSA + TokenAutomount + NoIRSA
		{ID: "a1", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("svc-a")},
		{ID: "a2", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Severity: models.SeverityMedium,
			Metadata: nsMeta("svc-a")},
		{ID: "a3", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("svc-a")},
		// Namespace "svc-b": DefaultSA + TokenAutomount + NoIRSA
		{ID: "b1", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("svc-b")},
		{ID: "b2", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Severity: models.SeverityMedium,
			Metadata: nsMeta("svc-b")},
		{ID: "b3", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("svc-b")},
		// Cluster-level OIDC (shared).
		{ID: "oidc", RuleID: "EKS_OIDC_PROVIDER_NOT_ASSOCIATED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)

	p2Paths := findAllPathsByScore(paths, 92)
	if len(p2Paths) != 2 {
		t.Fatalf("expected 2 PATH 2 entries (one per namespace); got %d: %v", len(p2Paths), paths)
	}

	// Both paths must include the shared OIDC finding.
	for _, ap := range p2Paths {
		found := false
		for _, fid := range ap.FindingIDs {
			if fid == "oidc" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("PATH 2 entry missing cluster-level OIDC finding; findingIDs=%v", ap.FindingIDs)
		}
	}

	// Each path must only contain its own namespace findings (not cross-contaminated).
	allFindingIDsInBothPaths := make(map[string]int) // findingID -> count of paths it appears in
	for _, ap := range p2Paths {
		for _, fid := range ap.FindingIDs {
			allFindingIDsInBothPaths[fid]++
		}
	}
	// The OIDC finding should appear in both paths (it's shared cluster-level).
	if allFindingIDsInBothPaths["oidc"] != 2 {
		t.Errorf("expected OIDC finding in both PATH 2 entries; counts=%v", allFindingIDsInBothPaths)
	}
	// Namespace-scoped findings should appear in exactly one path.
	for _, id := range []string{"a1", "a2", "a3", "b1", "b2", "b3"} {
		if allFindingIDsInBothPaths[id] != 1 {
			t.Errorf("expected namespace-scoped finding %q in exactly 1 PATH 2 entry; got %d",
				id, allFindingIDsInBothPaths[id])
		}
	}
}

// TestBuildAttackPaths_SortStable verifies that multiple PATH 1 entries (same
// score 98) are both returned when two namespaces qualify simultaneously.
func TestBuildAttackPaths_SortStable(t *testing.T) {
	// Build PATH 1 for two namespaces + PATH 3 (cluster-scoped, score 90).
	findings := []models.Finding{
		{ID: "a-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-a")},
		{ID: "a-p", RuleID: "K8S_POD_RUN_AS_ROOT", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-a")},
		{ID: "a-sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Severity: models.SeverityMedium,
			Metadata: nsMeta("ns-a")},
		{ID: "b-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-b")},
		{ID: "b-p", RuleID: "K8S_POD_CAP_SYS_ADMIN", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-b")},
		{ID: "b-sa", RuleID: "EKS_SERVICEACCOUNT_NO_IRSA", Severity: models.SeverityHigh,
			Metadata: nsMeta("ns-b")},
		// PATH 3: cluster-scoped.
		{ID: "enc", RuleID: "EKS_ENCRYPTION_DISABLED", Severity: models.SeverityCritical},
		{ID: "log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
		{ID: "sn", RuleID: "K8S_CLUSTER_SINGLE_NODE", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)

	// Expect 2 PATH 1 entries + 1 PATH 3 entry = 3 total.
	if len(paths) != 3 {
		t.Fatalf("expected 3 paths (2×98 + 1×90); got %d: %v", len(paths), paths)
	}
	// Verify no score ever increases between adjacent paths (descending order).
	for i := 0; i < len(paths)-1; i++ {
		if paths[i].Score < paths[i+1].Score {
			t.Errorf("paths not in descending score order at index %d: %d < %d; paths=%v",
				i, paths[i].Score, paths[i+1].Score, paths)
		}
	}
}

// ── Engine integration tests ──────────────────────────────────────────────────

// TestKubernetesEngine_AttackPath1_RiskScoreOverride verifies that when PATH 1
// is detected, Summary.RiskScore is 98 (overriding any lower chain score).
func TestKubernetesEngine_AttackPath1_RiskScoreOverride(t *testing.T) {
	ns := "prod"
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
	pod := chainSysAdminPod("priv-pod", ns)
	defaultPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "default-pod", Namespace: ns},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "app", Image: "nginx"}},
		},
	}
	node := eksNode("node1", "us-east-1a")

	cs := fake.NewSimpleClientset(node, svc, pod, defaultPod)
	eng := attackPathEngineFor(cs, "test-ctx", &models.KubernetesEKSData{
		EndpointPublicAccess: false,
		LoggingTypes:         []string{"api", "audit", "authenticator"},
		EncryptionEnabled:    true,
		OIDCProviderARN:      "arn:aws:iam::123456789012:oidc-provider/test",
	})

	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{
		ShowRiskChains: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}

	if report.Summary.RiskScore != 98 {
		t.Errorf("expected RiskScore=98 from attack path; got %d", report.Summary.RiskScore)
	}
	if len(report.Summary.AttackPaths) == 0 {
		t.Fatal("expected at least one attack path in summary")
	}
	found := false
	for _, ap := range report.Summary.AttackPaths {
		if ap.Score == 98 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected attack path with score 98; got %v", report.Summary.AttackPaths)
	}
}

// TestKubernetesEngine_AttackPaths_NotPopulatedWhenFlagOff verifies that
// Summary.AttackPaths is nil when ShowRiskChains is false.
func TestKubernetesEngine_AttackPaths_NotPopulatedWhenFlagOff(t *testing.T) {
	ns := "prod"
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: ns},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
	pod := chainSysAdminPod("priv-pod", ns)
	defaultPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "default-pod", Namespace: ns},
		Spec: corev1.PodSpec{
			ServiceAccountName: "default",
			Containers:         []corev1.Container{{Name: "app", Image: "nginx"}},
		},
	}
	node := eksNode("node1", "us-east-1a")
	cs := fake.NewSimpleClientset(node, svc, pod, defaultPod)
	eng := attackPathEngineFor(cs, "test-ctx", &models.KubernetesEKSData{
		EncryptionEnabled: true,
		LoggingTypes:      []string{"api", "audit", "authenticator"},
		OIDCProviderARN:   "arn:aws:iam::123:oidc-provider/test",
	})

	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{
		ShowRiskChains: false, // flag off
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Summary.AttackPaths) != 0 {
		t.Errorf("expected AttackPaths nil when ShowRiskChains=false; got %v", report.Summary.AttackPaths)
	}
}

// TestKubernetesEngine_AttackPath3_GovernanceCollapse verifies PATH 3 triggers
// when EKS_ENCRYPTION_DISABLED + EKS_CONTROL_PLANE_LOGGING_DISABLED + K8S_CLUSTER_SINGLE_NODE.
func TestKubernetesEngine_AttackPath3_GovernanceCollapse(t *testing.T) {
	node := eksNode("node1", "us-east-1a")
	cs := fake.NewSimpleClientset(node)
	eng := attackPathEngineFor(cs, "test-ctx", &models.KubernetesEKSData{
		EncryptionEnabled: false,      // triggers EKS_ENCRYPTION_DISABLED
		LoggingTypes:      []string{}, // empty = EKS_CONTROL_PLANE_LOGGING_DISABLED
		OIDCProviderARN:   "arn:aws:iam::123:oidc-provider/test",
	})

	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{
		ShowRiskChains: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if _, found := findPathByScore(report.Summary.AttackPaths, 90); !found {
		t.Errorf("expected PATH 3 (score 90); attack paths = %v", report.Summary.AttackPaths)
	}
}

// TestKubernetesEngine_RiskScoreFallbackToChainWhenNoAttackPaths verifies that
// when no attack paths are detected, Summary.RiskScore falls back to the
// highest risk chain score.
func TestKubernetesEngine_RiskScoreFallbackToChainWhenNoAttackPaths(t *testing.T) {
	// A single-node cluster with a CRITICAL finding triggers Chain 3 (score 50).
	// No attack path rules are satisfied, so fallback to chain score.
	priv := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-pod", Namespace: "default"},
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
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node1"},
	}
	cs := fake.NewSimpleClientset(node, pod)
	// Use core-only engine (no EKS) to avoid EKS rules triggering attack paths.
	eng := correlationEngine(cs, "test-ctx")

	report, err := eng.RunAudit(context.Background(), KubernetesAuditOptions{
		ShowRiskChains: true,
	})
	if err != nil {
		t.Fatalf("RunAudit error: %v", err)
	}
	if len(report.Summary.AttackPaths) != 0 {
		t.Errorf("expected no attack paths; got %v", report.Summary.AttackPaths)
	}
	// Chain 3 (score 50) should be used as the fallback RiskScore.
	if report.Summary.RiskScore != 50 {
		t.Errorf("expected RiskScore=50 (chain fallback); got %d", report.Summary.RiskScore)
	}
}

// ── PATH 4 unit tests ─────────────────────────────────────────────────────────

// TestBuildAttackPaths_Path4_Happy verifies PATH 4 (score 94) triggers when all
// three cluster-scoped conditions are met using EKS_NODE_ROLE_OVERPERMISSIVE
// as the IAM condition.
func TestBuildAttackPaths_Path4_Happy(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-pub", RuleID: "EKS_PUBLIC_ENDPOINT_ENABLED", Severity: models.SeverityHigh},
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE", Severity: models.SeverityCritical},
		{ID: "f-log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)

	p, ok := findPathByScore(paths, 94)
	if !ok {
		t.Fatalf("expected PATH 4 (score 94); paths = %v", paths)
	}
	if p.Description != "Public EKS control plane exposed with weak IAM and insufficient audit logging." {
		t.Errorf("unexpected description: %q", p.Description)
	}
	if len(p.Layers) != 3 {
		t.Errorf("expected 3 layers; got %v", p.Layers)
	}
	expectedLayers := []string{"Control Plane Exposure", "IAM Over-Permission", "Observability Gap"}
	for i, want := range expectedLayers {
		if i >= len(p.Layers) || p.Layers[i] != want {
			t.Errorf("layers[%d]: expected %q; got %q", i, want, p.Layers[i])
		}
	}
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	for _, want := range []string{"f-pub", "f-node", "f-log"} {
		if _, ok := fidSet[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 4; got %v", want, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path4_WildcardIAM verifies PATH 4 also triggers when
// EKS_IAM_ROLE_WILDCARD satisfies the IAM condition (instead of EKS_NODE_ROLE_OVERPERMISSIVE).
func TestBuildAttackPaths_Path4_WildcardIAM(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-pub", RuleID: "EKS_PUBLIC_ENDPOINT_ENABLED", Severity: models.SeverityHigh},
		{ID: "f-wild", RuleID: "EKS_IAM_ROLE_WILDCARD", Severity: models.SeverityCritical},
		{ID: "f-log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)
	p, ok := findPathByScore(paths, 94)
	if !ok {
		t.Fatalf("expected PATH 4 to trigger with EKS_IAM_ROLE_WILDCARD; paths = %v", paths)
	}
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	for _, want := range []string{"f-pub", "f-wild", "f-log"} {
		if _, ok := fidSet[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 4; got %v", want, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path4_MissingPublic_NoPath verifies PATH 4 does NOT trigger
// when EKS_PUBLIC_ENDPOINT_ENABLED is absent.
func TestBuildAttackPaths_Path4_MissingPublic_NoPath(t *testing.T) {
	findings := []models.Finding{
		// missing EKS_PUBLIC_ENDPOINT_ENABLED
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE", Severity: models.SeverityCritical},
		{ID: "f-log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 94); ok {
		t.Errorf("expected PATH 4 NOT to trigger without EKS_PUBLIC_ENDPOINT_ENABLED; got %v", paths)
	}
}

// TestBuildAttackPaths_Path4_MissingIAM_NoPath verifies PATH 4 does NOT trigger
// when neither EKS_NODE_ROLE_OVERPERMISSIVE nor EKS_IAM_ROLE_WILDCARD is present.
func TestBuildAttackPaths_Path4_MissingIAM_NoPath(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-pub", RuleID: "EKS_PUBLIC_ENDPOINT_ENABLED", Severity: models.SeverityHigh},
		// missing both EKS_NODE_ROLE_OVERPERMISSIVE and EKS_IAM_ROLE_WILDCARD
		{ID: "f-log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 94); ok {
		t.Errorf("expected PATH 4 NOT to trigger without any IAM overpermissive rule; got %v", paths)
	}
}

// TestBuildAttackPaths_Path4_MissingLogging_NoPath verifies PATH 4 does NOT trigger
// when EKS_CONTROL_PLANE_LOGGING_DISABLED is absent.
func TestBuildAttackPaths_Path4_MissingLogging_NoPath(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-pub", RuleID: "EKS_PUBLIC_ENDPOINT_ENABLED", Severity: models.SeverityHigh},
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE", Severity: models.SeverityCritical},
		// missing EKS_CONTROL_PLANE_LOGGING_DISABLED
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 94); ok {
		t.Errorf("expected PATH 4 NOT to trigger without EKS_CONTROL_PLANE_LOGGING_DISABLED; got %v", paths)
	}
}

// TestBuildAttackPaths_Path4_StrictFiltering verifies that unrelated cluster-scoped
// findings do NOT appear in PATH 4's FindingIDs, even when present alongside
// the required rules.
func TestBuildAttackPaths_Path4_StrictFiltering(t *testing.T) {
	allowedPath4 := map[string]bool{
		"EKS_PUBLIC_ENDPOINT_ENABLED":        true,
		"EKS_NODE_ROLE_OVERPERMISSIVE":       true,
		"EKS_IAM_ROLE_WILDCARD":              true,
		"EKS_CONTROL_PLANE_LOGGING_DISABLED": true,
	}
	findings := []models.Finding{
		// PATH 4 qualifying findings (all cluster-scoped: no namespace metadata).
		{ID: "f-pub", RuleID: "EKS_PUBLIC_ENDPOINT_ENABLED", Severity: models.SeverityHigh},
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE", Severity: models.SeverityCritical},
		{ID: "f-log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED", Severity: models.SeverityHigh},
		// Unrelated cluster-scoped findings — must NOT appear in PATH 4.
		{ID: "f-enc", RuleID: "EKS_ENCRYPTION_DISABLED", Severity: models.SeverityCritical},
		{ID: "f-oidc", RuleID: "EKS_OIDC_PROVIDER_NOT_ASSOCIATED", Severity: models.SeverityHigh},
	}
	paths := buildAttackPaths(findings)
	p, ok := findPathByScore(paths, 94)
	if !ok {
		t.Fatalf("expected PATH 4 to trigger; paths=%v", paths)
	}

	// Every finding in PATH 4 must have a primary rule ID from the allowed set.
	for _, fid := range p.FindingIDs {
		var found *models.Finding
		for i := range findings {
			if findings[i].ID == fid {
				found = &findings[i]
				break
			}
		}
		if found == nil {
			t.Errorf("PATH 4 FindingIDs contains unknown ID %q", fid)
			continue
		}
		if !allowedPath4[found.RuleID] {
			t.Errorf("PATH 4 contains finding %q with unallowed primary rule %q", fid, found.RuleID)
		}
	}

	// Unrelated findings must NOT be in PATH 4's FindingIDs.
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	for _, unrelated := range []string{"f-enc", "f-oidc"} {
		if _, bad := fidSet[unrelated]; bad {
			t.Errorf("unrelated finding %q should not appear in PATH 4 FindingIDs; got %v", unrelated, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path4_SortingOrder verifies that PATH 4 (score 94) sorts
// correctly between PATH 1 (98) and PATH 2 (92) in the returned slice.
func TestBuildAttackPaths_Path4_SortingOrder(t *testing.T) {
	findings := []models.Finding{
		// PATH 1 conditions (namespace "prod").
		{ID: "lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Metadata: nsMeta("prod")},
		{ID: "priv", RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nsMeta("prod")},
		{ID: "sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Metadata: nsMeta("prod")},
		// PATH 4 conditions (cluster-scoped).
		{ID: "pub", RuleID: "EKS_PUBLIC_ENDPOINT_ENABLED"},
		{ID: "node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE"},
		{ID: "log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED"},
	}
	paths := buildAttackPaths(findings)

	// Expect at least PATH 1 (98) and PATH 4 (94).
	if len(paths) < 2 {
		t.Fatalf("expected at least 2 paths; got %d: %v", len(paths), paths)
	}
	// Verify descending score order across all paths.
	for i := 0; i < len(paths)-1; i++ {
		if paths[i].Score < paths[i+1].Score {
			t.Errorf("paths not in descending score order at index %d: %d < %d; paths=%v",
				i, paths[i].Score, paths[i+1].Score, paths)
		}
	}
	// PATH 1 must come first.
	if paths[0].Score != 98 {
		t.Errorf("expected first path score 98; got %d", paths[0].Score)
	}
	// PATH 4 must appear after PATH 1.
	found94 := false
	for _, p := range paths {
		if p.Score == 94 {
			found94 = true
			break
		}
	}
	if !found94 {
		t.Errorf("expected PATH 4 (score 94) in sorted results; got %v", paths)
	}
}

// ── Unit tests: PATH 5 (score 96) ────────────────────────────────────────────

// TestBuildAttackPaths_Path5_Happy verifies PATH 5 (score 96) triggers correctly
// when the identity weakness is K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT (the option
// exclusive to PATH 5 vs PATH 1), ensuring PATH 1 does NOT fire in this setup.
// Findings: ns "prod" LB + RUN_AS_ROOT + AUTOMOUNT; cluster NODE_ROLE.
func TestBuildAttackPaths_Path5_Happy(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Metadata: nsMeta("prod")},
		{ID: "f-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nsMeta("prod")},
		{ID: "f-automount", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Metadata: nsMeta("prod")},
		// Cluster-scoped IAM (required for PATH 5).
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE"},
	}
	paths := buildAttackPaths(findings)

	p, ok := findPathByScore(paths, 96)
	if !ok {
		t.Fatalf("expected PATH 5 (score 96); paths=%v", paths)
	}
	if p.Description != "Externally reachable workload can assume over-permissive cloud IAM role (cross-plane privilege escalation)." {
		t.Errorf("unexpected description: %q", p.Description)
	}
	if len(p.Layers) != 3 {
		t.Errorf("expected 3 layers; got %v", p.Layers)
	}
	if p.Layers[0] != "Network Exposure" || p.Layers[1] != "Workload Compromise" || p.Layers[2] != "Cloud IAM Escalation" {
		t.Errorf("unexpected layers: %v", p.Layers)
	}
	// All four finding IDs must be present.
	fids := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fids[id] = struct{}{}
	}
	for _, want := range []string{"f-lb", "f-priv", "f-automount", "f-node"} {
		if _, ok := fids[want]; !ok {
			t.Errorf("expected finding ID %q in PATH 5; got %v", want, p.FindingIDs)
		}
	}
	// PATH 1 must NOT fire because K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT alone does
	// not satisfy PATH 1's identity condition (only NO_IRSA or DEFAULT_SA do).
	if _, bad := findPathByScore(paths, 98); bad {
		t.Errorf("expected PATH 1 NOT to trigger; got %v", paths)
	}
}

// TestBuildAttackPaths_Path5_MissingPublic_NoPath verifies PATH 5 does NOT trigger
// when K8S_SERVICE_PUBLIC_LOADBALANCER is absent from the namespace.
func TestBuildAttackPaths_Path5_MissingPublic_NoPath(t *testing.T) {
	findings := []models.Finding{
		// No LB in the namespace.
		{ID: "f-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nsMeta("prod")},
		{ID: "f-automount", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Metadata: nsMeta("prod")},
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE"},
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 96); ok {
		t.Errorf("expected PATH 5 NOT to trigger without K8S_SERVICE_PUBLIC_LOADBALANCER; got %v", paths)
	}
}

// TestBuildAttackPaths_Path5_MissingPriv_NoPath verifies PATH 5 does NOT trigger
// when neither K8S_POD_RUN_AS_ROOT nor K8S_POD_CAP_SYS_ADMIN is present.
func TestBuildAttackPaths_Path5_MissingPriv_NoPath(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Metadata: nsMeta("prod")},
		// No privilege escalation rule.
		{ID: "f-automount", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Metadata: nsMeta("prod")},
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE"},
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 96); ok {
		t.Errorf("expected PATH 5 NOT to trigger without privilege rule; got %v", paths)
	}
}

// TestBuildAttackPaths_Path5_MissingIdentity_NoPath verifies PATH 5 does NOT trigger
// when no identity weakness rule is present in the namespace.
func TestBuildAttackPaths_Path5_MissingIdentity_NoPath(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Metadata: nsMeta("prod")},
		{ID: "f-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nsMeta("prod")},
		// No identity weakness rule (no NO_IRSA, no DEFAULT_SA, no AUTOMOUNT).
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE"},
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 96); ok {
		t.Errorf("expected PATH 5 NOT to trigger without identity weakness rule; got %v", paths)
	}
}

// TestBuildAttackPaths_Path5_MissingClusterIAM_NoPath verifies PATH 5 does NOT
// trigger when neither EKS_NODE_ROLE_OVERPERMISSIVE nor EKS_IAM_ROLE_WILDCARD
// is present as a cluster-scoped finding.
func TestBuildAttackPaths_Path5_MissingClusterIAM_NoPath(t *testing.T) {
	findings := []models.Finding{
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Metadata: nsMeta("prod")},
		{ID: "f-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nsMeta("prod")},
		{ID: "f-automount", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Metadata: nsMeta("prod")},
		// No cluster-scoped IAM over-permission finding.
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 96); ok {
		t.Errorf("expected PATH 5 NOT to trigger without cluster IAM rule; got %v", paths)
	}
}

// TestBuildAttackPaths_Path5_StrictFiltering verifies that findings whose primary
// rule ID is NOT in PATH 5's allowed set are excluded from FindingIDs, even when
// present alongside the qualifying findings.
func TestBuildAttackPaths_Path5_StrictFiltering(t *testing.T) {
	allowedPath5 := map[string]bool{
		"K8S_SERVICE_PUBLIC_LOADBALANCER":    true,
		"K8S_POD_RUN_AS_ROOT":                true,
		"K8S_POD_CAP_SYS_ADMIN":              true,
		"EKS_SERVICEACCOUNT_NO_IRSA":         true,
		"K8S_DEFAULT_SERVICEACCOUNT_USED":    true,
		"K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT": true,
		"EKS_NODE_ROLE_OVERPERMISSIVE":       true,
		"EKS_IAM_ROLE_WILDCARD":              true,
	}
	findings := []models.Finding{
		// PATH 5 qualifying namespace findings.
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Metadata: nsMeta("prod")},
		{ID: "f-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nsMeta("prod")},
		{ID: "f-automount", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Metadata: nsMeta("prod")},
		// Unrelated namespace finding — must NOT appear in PATH 5.
		{ID: "f-seccomp", RuleID: "K8S_POD_NO_SECCOMP", Metadata: nsMeta("prod")},
		// PATH 5 cluster IAM.
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE"},
		// Unrelated cluster finding — must NOT appear in PATH 5.
		{ID: "f-enc", RuleID: "EKS_ENCRYPTION_DISABLED"},
	}
	paths := buildAttackPaths(findings)
	p, ok := findPathByScore(paths, 96)
	if !ok {
		t.Fatalf("expected PATH 5 to trigger; paths=%v", paths)
	}

	// Every finding in PATH 5 must have a primary rule ID from the allowed set.
	for _, fid := range p.FindingIDs {
		var found *models.Finding
		for i := range findings {
			if findings[i].ID == fid {
				found = &findings[i]
				break
			}
		}
		if found == nil {
			t.Errorf("PATH 5 FindingIDs contains unknown ID %q", fid)
			continue
		}
		if !allowedPath5[found.RuleID] {
			t.Errorf("PATH 5 contains finding %q with unallowed primary rule %q", fid, found.RuleID)
		}
	}

	// Unrelated findings must NOT appear in PATH 5's FindingIDs.
	fidSet := make(map[string]struct{})
	for _, id := range p.FindingIDs {
		fidSet[id] = struct{}{}
	}
	for _, unrelated := range []string{"f-seccomp", "f-enc"} {
		if _, bad := fidSet[unrelated]; bad {
			t.Errorf("unrelated finding %q should not appear in PATH 5 FindingIDs; got %v", unrelated, p.FindingIDs)
		}
	}
}

// TestBuildAttackPaths_Path5_NamespaceIsolation verifies that PATH 5 does NOT
// trigger when its namespace conditions are split across two different namespaces
// (LB+priv in "alpha", identity weakness in "beta").
func TestBuildAttackPaths_Path5_NamespaceIsolation(t *testing.T) {
	findings := []models.Finding{
		// "alpha" has LB + priv but no identity weakness.
		{ID: "f-lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Metadata: nsMeta("alpha")},
		{ID: "f-priv", RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nsMeta("alpha")},
		// "beta" has identity weakness but no LB or priv.
		{ID: "f-automount", RuleID: "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT", Metadata: nsMeta("beta")},
		// Cluster IAM is present.
		{ID: "f-node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE"},
	}
	paths := buildAttackPaths(findings)
	if _, ok := findPathByScore(paths, 96); ok {
		t.Errorf("expected PATH 5 NOT to trigger when conditions split across namespaces; got %v", paths)
	}
}

// TestBuildAttackPaths_Path5_SortingOrder verifies that PATH 5 (score 96) sorts
// correctly between PATH 1 (score 98) and PATH 4 (score 94) in the returned slice.
func TestBuildAttackPaths_Path5_SortingOrder(t *testing.T) {
	findings := []models.Finding{
		// PATH 1 + PATH 5 conditions in same namespace "prod".
		// K8S_DEFAULT_SERVICEACCOUNT_USED satisfies PATH 1 identity AND PATH 5 identity.
		{ID: "lb", RuleID: "K8S_SERVICE_PUBLIC_LOADBALANCER", Metadata: nsMeta("prod")},
		{ID: "priv", RuleID: "K8S_POD_RUN_AS_ROOT", Metadata: nsMeta("prod")},
		{ID: "sa", RuleID: "K8S_DEFAULT_SERVICEACCOUNT_USED", Metadata: nsMeta("prod")},
		// Cluster IAM: required for PATH 5; optional for PATH 1.
		{ID: "node", RuleID: "EKS_NODE_ROLE_OVERPERMISSIVE"},
		// PATH 4 conditions (cluster-scoped).
		{ID: "pub", RuleID: "EKS_PUBLIC_ENDPOINT_ENABLED"},
		{ID: "log", RuleID: "EKS_CONTROL_PLANE_LOGGING_DISABLED"},
	}
	paths := buildAttackPaths(findings)

	// Expect at least PATH 1 (98), PATH 5 (96), and PATH 4 (94).
	if len(paths) < 3 {
		t.Fatalf("expected at least 3 paths; got %d: %v", len(paths), paths)
	}
	// Verify strict descending score order across all returned paths.
	for i := 0; i < len(paths)-1; i++ {
		if paths[i].Score < paths[i+1].Score {
			t.Errorf("paths not in descending score order at index %d: %d < %d; paths=%v",
				i, paths[i].Score, paths[i+1].Score, paths)
		}
	}
	// PATH 1 must be first (score 98).
	if paths[0].Score != 98 {
		t.Errorf("expected first path score 98; got %d", paths[0].Score)
	}
	// PATH 5 must appear with score 96.
	if _, ok := findPathByScore(paths, 96); !ok {
		t.Errorf("expected PATH 5 (score 96) in sorted results; got %v", paths)
	}
	// PATH 4 must appear with score 94.
	if _, ok := findPathByScore(paths, 94); !ok {
		t.Errorf("expected PATH 4 (score 94) in sorted results; got %v", paths)
	}
}
