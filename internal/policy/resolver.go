package policy

import (
	"strings"

	"github.com/devopsproxy/dp/internal/models"
)

// severityRank maps each severity level to an integer for ordered comparison.
// Higher value means higher severity. CRITICAL > HIGH > MEDIUM > LOW > INFO.
var severityRank = map[models.Severity]int{
	models.SeverityCritical: 5,
	models.SeverityHigh:     4,
	models.SeverityMedium:   3,
	models.SeverityLow:      2,
	models.SeverityInfo:     1,
}

func ApplyPolicy(findings []models.Finding, domain string, cfg *PolicyConfig) []models.Finding {
	if cfg == nil {
		return findings
	}

	// Domain-level disable
	domainCfg, hasDomain := cfg.Domains[domain]
	if hasDomain && !domainCfg.Enabled {
		return []models.Finding{}
	}

	// Determine minimum severity rank enforced for this domain (0 = no filtering).
	minRank := 0
	if hasDomain && domainCfg.MinSeverity != "" {
		if r, ok := severityRank[models.Severity(strings.ToUpper(domainCfg.MinSeverity))]; ok {
			minRank = r
		}
	}

	var result []models.Finding

	for _, f := range findings {
		ruleCfg, hasRule := cfg.Rules[f.RuleID]

		// Rule-level disable
		if hasRule && ruleCfg.Enabled != nil && !*ruleCfg.Enabled {
			continue
		}

		// Severity override
		if hasRule && ruleCfg.Severity != "" {
			f.Severity = models.Severity(strings.ToUpper(ruleCfg.Severity))
		}

		// Min-severity filter: drop findings below the domain threshold.
		if minRank > 0 {
			if r, ok := severityRank[f.Severity]; !ok || r < minRank {
				continue
			}
		}

		result = append(result, f)
	}

	return result
}
