// Package render provides presentation-layer helpers for DevOps-Proxy CLI output.
// It is a pure rendering package — no correlation logic, no scoring, no AWS/Kubernetes API calls.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/devopsproxy/dp/internal/models"
)

// FindPathByScore returns a pointer to the first AttackPath in paths whose Score
// equals score, or nil when no match is found. The caller owns the returned
// pointer — it points into the slice element directly.
func FindPathByScore(paths []models.AttackPath, score int) *models.AttackPath {
	for i := range paths {
		if paths[i].Score == score {
			return &paths[i]
		}
	}
	return nil
}

// RenderAttackPathExplanation writes a structured breakdown of a single attack
// path to w. findings is the full report finding set; only findings whose IDs
// appear in path.FindingIDs are rendered (strict filtering). Findings are
// grouped by primary rule_id and rule IDs are sorted ascending for stable output.
//
// Example output:
//
//	ATTACK PATH (Score: 96)
//	Description: Externally reachable workload can assume over-permissive cloud IAM role.
//	Layers: Network Exposure → Workload Compromise → Cloud IAM Escalation
//
//	Findings (4):
//
//	  ✓ EKS_NODE_ROLE_OVERPERMISSIVE
//	    - my-cluster
//
//	  ✓ K8S_SERVICE_PUBLIC_LOADBALANCER
//	    - web-svc (prod)
func RenderAttackPathExplanation(w io.Writer, path models.AttackPath, findings []models.Finding) {
	// Header.
	fmt.Fprintf(w, "ATTACK PATH (Score: %d)\n", path.Score)
	fmt.Fprintf(w, "Description: %s\n", path.Description)
	fmt.Fprintf(w, "Layers: %s\n", strings.Join(path.Layers, " → "))
	fmt.Fprintln(w)

	// Build findingByID for fast lookup.
	findingByID := make(map[string]*models.Finding, len(findings))
	for i := range findings {
		f := &findings[i]
		findingByID[f.ID] = f
	}

	// Collect only findings referenced by path.FindingIDs (strict filtering).
	// Group by RuleID preserving first-seen order, then sort rule IDs for stability.
	ruleToFindings := make(map[string][]*models.Finding)
	var ruleOrder []string
	seenRule := make(map[string]bool)

	for _, fid := range path.FindingIDs {
		f, ok := findingByID[fid]
		if !ok {
			continue
		}
		if !seenRule[f.RuleID] {
			seenRule[f.RuleID] = true
			ruleOrder = append(ruleOrder, f.RuleID)
		}
		ruleToFindings[f.RuleID] = append(ruleToFindings[f.RuleID], f)
	}

	sort.Strings(ruleOrder)

	fmt.Fprintf(w, "Findings (%d):\n", len(path.FindingIDs))

	for _, ruleID := range ruleOrder {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  \u2713 %s\n", ruleID)
		for _, f := range ruleToFindings[ruleID] {
			ns := ""
			if f.Metadata != nil {
				if n, ok := f.Metadata["namespace"].(string); ok && n != "" {
					ns = " (" + n + ")"
				}
			}
			fmt.Fprintf(w, "    - %s%s\n", f.ResourceID, ns)
		}
	}
}

// WriteExplainJSON writes the attack path explanation as indented JSON to w.
//
// When path is non-nil, the output is:
//
//	{"attack_path": { ...path fields... }}
//
// When path is nil (score not found in the report), the output is:
//
//	{"error": "No attack path found with score N"}
func WriteExplainJSON(w io.Writer, path *models.AttackPath, score int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	if path == nil {
		return enc.Encode(map[string]string{
			"error": fmt.Sprintf("No attack path found with score %d", score),
		})
	}
	return enc.Encode(map[string]any{
		"attack_path": path,
	})
}
