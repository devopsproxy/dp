package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// ── test helpers ──────────────────────────────────────────────────────────────

func makePath(score int, desc string, layers []string, ids []string) models.AttackPath {
	return models.AttackPath{
		Score:       score,
		Description: desc,
		Layers:      layers,
		FindingIDs:  ids,
	}
}

func makeFinding(id, ruleID, resourceID string, meta map[string]any) models.Finding {
	f := models.Finding{
		ID:         id,
		RuleID:     ruleID,
		ResourceID: resourceID,
	}
	if meta != nil {
		f.Metadata = meta
	}
	return f
}

// ── TestExplain_HappyPath ─────────────────────────────────────────────────────

// TestExplain_HappyPath verifies that RenderAttackPathExplanation writes the
// correct header lines, all rule IDs (as ✓ markers), resource IDs with
// namespace suffixes, and excludes unrelated findings (strict filtering).
func TestExplain_HappyPath(t *testing.T) {
	path := makePath(96,
		"Externally reachable workload can assume over-permissive cloud IAM role.",
		[]string{"Network Exposure", "Workload Compromise", "Cloud IAM Escalation"},
		[]string{"f1", "f2", "f3"},
	)
	findings := []models.Finding{
		makeFinding("f1", "EKS_NODE_ROLE_OVERPERMISSIVE", "my-cluster", nil),
		makeFinding("f2", "K8S_SERVICE_PUBLIC_LOADBALANCER", "web-svc", map[string]any{"namespace": "prod"}),
		makeFinding("f3", "K8S_POD_RUN_AS_ROOT", "web-pod", map[string]any{"namespace": "prod"}),
		// Unrelated finding — must be excluded by strict filtering.
		makeFinding("f-unrelated", "K8S_PRIVILEGED_CONTAINER", "priv-pod", nil),
	}

	var buf bytes.Buffer
	RenderAttackPathExplanation(&buf, path, findings)
	out := buf.String()

	// Header checks.
	for _, want := range []string{
		"ATTACK PATH (Score: 96)",
		"Description: Externally reachable workload can assume over-permissive cloud IAM role.",
		"Layers: Network Exposure → Workload Compromise → Cloud IAM Escalation",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}

	// All 3 referenced rule IDs must appear with ✓ marker.
	for _, rule := range []string{
		"EKS_NODE_ROLE_OVERPERMISSIVE",
		"K8S_SERVICE_PUBLIC_LOADBALANCER",
		"K8S_POD_RUN_AS_ROOT",
	} {
		if !strings.Contains(out, "✓ "+rule) {
			t.Errorf("missing rule marker ✓ %s in output:\n%s", rule, out)
		}
	}

	// Resource IDs with correct namespace suffix.
	if !strings.Contains(out, "my-cluster") {
		t.Errorf("missing resource my-cluster in output:\n%s", out)
	}
	if !strings.Contains(out, "web-svc (prod)") {
		t.Errorf("missing resource web-svc (prod) in output:\n%s", out)
	}
	if !strings.Contains(out, "web-pod (prod)") {
		t.Errorf("missing resource web-pod (prod) in output:\n%s", out)
	}

	// Strict filtering: unrelated finding must not appear.
	if strings.Contains(out, "priv-pod") {
		t.Errorf("output must not contain unrelated finding priv-pod:\n%s", out)
	}
	if strings.Contains(out, "K8S_PRIVILEGED_CONTAINER") {
		t.Errorf("output must not contain unrelated rule K8S_PRIVILEGED_CONTAINER:\n%s", out)
	}
}

// ── TestExplain_NoSuchScore ───────────────────────────────────────────────────

// TestExplain_NoSuchScore verifies that FindPathByScore returns nil when no
// path matches the requested score, and returns the correct pointer for a
// matching score.
func TestExplain_NoSuchScore(t *testing.T) {
	paths := []models.AttackPath{
		makePath(98, "desc-98", []string{"L1", "L2"}, []string{"f1"}),
		makePath(92, "desc-92", []string{"L1"}, []string{"f2"}),
	}

	// Score not in the list — must return nil.
	result := FindPathByScore(paths, 999)
	if result != nil {
		t.Errorf("FindPathByScore(999) = %+v; want nil", result)
	}

	// Empty slice — must return nil.
	if FindPathByScore(nil, 98) != nil {
		t.Error("FindPathByScore(nil, 98) must return nil")
	}

	// Matching score — must return the correct path.
	got := FindPathByScore(paths, 92)
	if got == nil {
		t.Fatal("FindPathByScore(92) = nil; want non-nil")
	}
	if got.Score != 92 {
		t.Errorf("FindPathByScore(92).Score = %d; want 92", got.Score)
	}
	if got.Description != "desc-92" {
		t.Errorf("FindPathByScore(92).Description = %q; want desc-92", got.Description)
	}
}

// ── TestExplain_StrictFiltering ───────────────────────────────────────────────

// TestExplain_StrictFiltering verifies that findings NOT referenced in
// path.FindingIDs are fully excluded from the rendered output, and that
// findings referenced in path.FindingIDs are included.
func TestExplain_StrictFiltering(t *testing.T) {
	// Path only references f1 and f2. f3 must be silently excluded.
	path := makePath(80, "desc", []string{"L1"}, []string{"f1", "f2"})
	findings := []models.Finding{
		makeFinding("f1", "RULE_A", "res-a", nil),
		makeFinding("f2", "RULE_B", "res-b", nil),
		makeFinding("f3", "RULE_C", "res-c", nil), // NOT in path.FindingIDs
	}

	var buf bytes.Buffer
	RenderAttackPathExplanation(&buf, path, findings)
	out := buf.String()

	// Referenced findings must appear.
	if !strings.Contains(out, "res-a") {
		t.Errorf("missing res-a in output:\n%s", out)
	}
	if !strings.Contains(out, "res-b") {
		t.Errorf("missing res-b in output:\n%s", out)
	}
	if !strings.Contains(out, "RULE_A") {
		t.Errorf("missing RULE_A in output:\n%s", out)
	}
	if !strings.Contains(out, "RULE_B") {
		t.Errorf("missing RULE_B in output:\n%s", out)
	}

	// Unreferenced finding must not appear.
	if strings.Contains(out, "res-c") {
		t.Errorf("output must not contain excluded finding res-c:\n%s", out)
	}
	if strings.Contains(out, "RULE_C") {
		t.Errorf("output must not contain excluded rule RULE_C:\n%s", out)
	}
}

// ── TestExplain_JSONMode ──────────────────────────────────────────────────────

// TestExplain_JSONMode verifies that WriteExplainJSON produces:
//   - {"attack_path": {...}} with path fields for a non-nil path
//   - {"error": "No attack path found with score N"} for a nil path
func TestExplain_JSONMode(t *testing.T) {
	t.Run("non-nil path", func(t *testing.T) {
		path := makePath(96, "some description", []string{"L1", "L2"}, []string{"f1"})
		var buf bytes.Buffer
		if err := WriteExplainJSON(&buf, &path, 96); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var got map[string]any
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("invalid JSON: %v\ngot:\n%s", err, buf.String())
		}

		if _, ok := got["attack_path"]; !ok {
			t.Errorf("JSON missing 'attack_path' key; got: %s", buf.String())
		}
		if _, ok := got["error"]; ok {
			t.Errorf("JSON must not contain 'error' key for non-nil path; got: %s", buf.String())
		}
		// Score and description must be present in the nested object.
		if !strings.Contains(buf.String(), `"score"`) {
			t.Errorf("JSON missing score field; got: %s", buf.String())
		}
		if !strings.Contains(buf.String(), "some description") {
			t.Errorf("JSON missing description; got: %s", buf.String())
		}
	})

	t.Run("nil path", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteExplainJSON(&buf, nil, 123); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var got map[string]string
		if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
			t.Fatalf("invalid JSON: %v\ngot:\n%s", err, buf.String())
		}

		errMsg, ok := got["error"]
		if !ok {
			t.Errorf("JSON missing 'error' key for nil path; got: %s", buf.String())
		}
		if !strings.Contains(errMsg, "123") {
			t.Errorf("error message missing score 123; got: %q", errMsg)
		}
		if strings.Contains(buf.String(), "attack_path") {
			t.Errorf("nil-path JSON must not contain 'attack_path' key; got: %s", buf.String())
		}
	})
}
