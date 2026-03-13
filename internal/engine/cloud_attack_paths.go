// Package engine — cloud_attack_paths.go
//
// Phase 16: Internet-to-sensitive-data attack path detection.
//
// DetectCloudAttackPaths bridges the graph traversal engine (Phase 15.1)
// and the AuditSummary model by converting GraphAttackPath results into
// models.CloudAttackPath values suitable for JSON output and CLI rendering.
//
// Detection works for both identity paths:
//   - Workload → ServiceAccount → IAMRole → Cloud Resource  (IRSA)
//   - Workload → Node → IAMRole → Cloud Resource            (instance profile)
//
// This module only reads the asset graph — it never modifies findings, scores,
// or any engine state, and it contains no rule-based logic.
package engine

import (
	"github.com/devopsproxy/dp/internal/graph"
	"github.com/devopsproxy/dp/internal/models"
)

// DetectCloudAttackPaths uses the graph traversal engine to discover all
// Internet → sensitive cloud resource attack paths in the asset graph.
//
// It delegates path enumeration and scoring to FindGraphAttackPaths (Phase 15.1)
// and converts the internal GraphAttackPath results into models.CloudAttackPath
// values for inclusion in AuditSummary.CloudAttackPaths.
//
// Returns nil when g is nil or when no qualifying paths exist.
func DetectCloudAttackPaths(g *graph.Graph) []models.CloudAttackPath {
	if g == nil {
		return nil
	}

	graphPaths := FindGraphAttackPaths(g)
	if len(graphPaths) == 0 {
		return nil
	}

	result := make([]models.CloudAttackPath, 0, len(graphPaths))
	for _, gp := range graphPaths {
		cp := models.CloudAttackPath{
			Score: gp.Score,
			Nodes: gp.Nodes,
		}
		if len(gp.Nodes) > 0 {
			cp.Source = gp.Nodes[0]
			cp.Target = gp.Nodes[len(gp.Nodes)-1]
		}
		result = append(result, cp)
	}
	return result
}
