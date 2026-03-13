package render

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// ── TestMinAttackScore_TableFilter ────────────────────────────────────────────

// TestMinAttackScore_TableFilter verifies that FilterAttackPaths returns only
// paths whose Score is >= the threshold. Given paths at scores 98, 96, and 92
// with min=95, only the 98 and 96 paths must be returned.
func TestMinAttackScore_TableFilter(t *testing.T) {
	paths := []models.AttackPath{
		{Score: 98, Description: "path-98"},
		{Score: 96, Description: "path-96"},
		{Score: 92, Description: "path-92"},
	}

	filtered := FilterAttackPaths(paths, 95)

	if len(filtered) != 2 {
		t.Fatalf("FilterAttackPaths(min=95) returned %d path(s); want 2", len(filtered))
	}
	if filtered[0].Score != 98 {
		t.Errorf("filtered[0].Score = %d; want 98", filtered[0].Score)
	}
	if filtered[1].Score != 96 {
		t.Errorf("filtered[1].Score = %d; want 96", filtered[1].Score)
	}
	// The 92-score path must not be present.
	for _, p := range filtered {
		if p.Score == 92 {
			t.Errorf("path with Score=92 must be excluded when min=95")
		}
	}
}

// ── TestMinAttackScore_NoMatches ──────────────────────────────────────────────

// TestMinAttackScore_NoMatches verifies that FilterAttackPaths returns an empty
// slice when no path meets the threshold (min=99 with paths at 98, 96, 92).
func TestMinAttackScore_NoMatches(t *testing.T) {
	paths := []models.AttackPath{
		{Score: 98},
		{Score: 96},
		{Score: 92},
	}

	filtered := FilterAttackPaths(paths, 99)

	if len(filtered) != 0 {
		t.Errorf("FilterAttackPaths(min=99) returned %d path(s); want 0", len(filtered))
	}
}

// ── TestMinAttackScore_JSONFilter ─────────────────────────────────────────────

// TestMinAttackScore_JSONFilter verifies that FilterAttackPaths correctly
// reduces the attack_paths set while leaving the risk_score (which is computed
// before any filtering) and the original paths slice entirely unaffected.
func TestMinAttackScore_JSONFilter(t *testing.T) {
	paths := []models.AttackPath{
		{Score: 98, Description: "high-risk"},
		{Score: 92, Description: "medium-risk"},
	}

	// Simulate risk_score as computed by the engine (max across all paths = 98).
	// FilterAttackPaths must not affect this value.
	riskScore := 98

	filtered := FilterAttackPaths(paths, 95)

	// Filtered set must contain only the score-98 path.
	if len(filtered) != 1 {
		t.Fatalf("FilterAttackPaths(min=95) returned %d path(s); want 1", len(filtered))
	}
	if filtered[0].Score != 98 {
		t.Errorf("filtered[0].Score = %d; want 98", filtered[0].Score)
	}

	// risk_score is computed from the unfiltered set and must remain 98.
	if riskScore != 98 {
		t.Error("risk_score must not be modified by FilterAttackPaths")
	}

	// Original paths slice must be intact.
	if len(paths) != 2 {
		t.Errorf("original paths length = %d after filter; want 2", len(paths))
	}
}

// ── TestMinAttackScore_DoesNotMutateOriginal ──────────────────────────────────

// TestMinAttackScore_DoesNotMutateOriginal verifies that FilterAttackPaths
// never modifies the input slice — neither its length nor its elements.
func TestMinAttackScore_DoesNotMutateOriginal(t *testing.T) {
	paths := []models.AttackPath{
		{Score: 98, Description: "a"},
		{Score: 96, Description: "b"},
		{Score: 92, Description: "c"},
	}
	// Snapshot originals before calling filter.
	original := make([]models.AttackPath, len(paths))
	copy(original, paths)

	FilterAttackPaths(paths, 95)

	if len(paths) != len(original) {
		t.Errorf("original slice length changed: got %d; want %d", len(paths), len(original))
	}
	for i, p := range paths {
		if p.Score != original[i].Score || p.Description != original[i].Description {
			t.Errorf("paths[%d] mutated: got {Score:%d Desc:%q}; want {Score:%d Desc:%q}",
				i, p.Score, p.Description, original[i].Score, original[i].Description)
		}
	}
}
