package policy

import (
	"strings"

	"github.com/devopsproxy/dp/internal/models"
)

// ShouldFail reports whether any finding in findings has a severity at or above
// the configured fail_on_severity threshold for the given domain.
//
// It returns false when:
//   - cfg is nil (no policy loaded)
//   - no enforcement block is configured for domain
//   - fail_on_severity is empty or an unrecognised value
//   - findings is empty
//
// It returns true when at least one finding has a severity whose rank is
// greater than or equal to the configured threshold rank.
// SeverityRank ordering: CRITICAL (5) > HIGH (4) > MEDIUM (3) > LOW (2) > INFO (1).
func ShouldFail(domain string, findings []models.Finding, cfg *PolicyConfig) bool {
	if cfg == nil {
		return false
	}
	enfCfg, ok := cfg.Enforcement[domain]
	if !ok || enfCfg.FailOnSeverity == "" {
		return false
	}
	threshold, ok := severityRank[models.Severity(strings.ToUpper(enfCfg.FailOnSeverity))]
	if !ok {
		return false
	}
	for _, f := range findings {
		if r, ok := severityRank[f.Severity]; ok && r >= threshold {
			return true
		}
	}
	return false
}
