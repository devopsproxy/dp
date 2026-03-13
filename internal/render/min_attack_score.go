package render

import "github.com/devopsproxy/dp/internal/models"

// FilterAttackPaths returns a new slice containing only those attack paths
// whose Score is >= minScore. When minScore is 0 or negative the original
// slice is returned unchanged without allocation. The input slice is never
// mutated — callers may use both the original and the filtered result safely.
func FilterAttackPaths(paths []models.AttackPath, minScore int) []models.AttackPath {
	if minScore <= 0 {
		return paths
	}
	out := make([]models.AttackPath, 0, len(paths))
	for _, p := range paths {
		if p.Score >= minScore {
			out = append(out, p)
		}
	}
	return out
}
