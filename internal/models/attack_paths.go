// Package models — attack_paths.go
//
// Phase 17.1: Attack path prioritization types.
// AttackPathSeverity classifies a CloudAttackPath into a three-level severity
// band derived from its numeric score.
package models

// AttackPathSeverity is a three-level classification for a CloudAttackPath.
// It is derived from the path score and is used to sort and render paths
// in order of descending risk.
type AttackPathSeverity string

const (
	// AttackPathSeverityCritical applies when score >= 90.
	// These paths represent immediate, Internet-reachable paths to sensitive data.
	AttackPathSeverityCritical AttackPathSeverity = "CRITICAL"

	// AttackPathSeverityHigh applies when 70 <= score < 90.
	// These paths have significant risk but lack one or more amplifying factors.
	AttackPathSeverityHigh AttackPathSeverity = "HIGH"

	// AttackPathSeverityMedium applies when score < 70.
	// These paths represent a partial attack chain with lower overall impact.
	AttackPathSeverityMedium AttackPathSeverity = "MEDIUM"
)

// AttackPathSeverityFromScore derives the AttackPathSeverity from a numeric
// path score using the following thresholds:
//
//	score >= 90  → CRITICAL
//	score >= 70  → HIGH
//	else         → MEDIUM
func AttackPathSeverityFromScore(score int) AttackPathSeverity {
	switch {
	case score >= 90:
		return AttackPathSeverityCritical
	case score >= 70:
		return AttackPathSeverityHigh
	default:
		return AttackPathSeverityMedium
	}
}

// severityRankAP maps AttackPathSeverity to a sort rank (lower = higher priority).
// Used to sort []CloudAttackPath by severity descending.
var severityRankAP = map[AttackPathSeverity]int{
	AttackPathSeverityCritical: 0,
	AttackPathSeverityHigh:     1,
	AttackPathSeverityMedium:   2,
}

// SeverityRank returns the sort rank for an AttackPathSeverity.
// Lower rank = higher priority. Unknown values return 3.
func (s AttackPathSeverity) SeverityRank() int {
	if r, ok := severityRankAP[s]; ok {
		return r
	}
	return 3
}
