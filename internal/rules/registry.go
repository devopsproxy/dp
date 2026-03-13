package rules

import (
	"fmt"

	"github.com/devopsproxy/dp/internal/models"
)

// DefaultRuleRegistry is a simple, ordered, in-memory registry.
// Rules are evaluated in registration order.
// Register panics on duplicate rule IDs to catch wiring mistakes at startup.
type DefaultRuleRegistry struct {
	rules []Rule
	index map[string]struct{}
}

// NewDefaultRuleRegistry returns an empty registry ready for rule registration.
func NewDefaultRuleRegistry() *DefaultRuleRegistry {
	return &DefaultRuleRegistry{
		index: make(map[string]struct{}),
	}
}

// Register adds rule to the registry. Panics if the same ID is registered twice.
func (r *DefaultRuleRegistry) Register(rule Rule) {
	if _, exists := r.index[rule.ID()]; exists {
		panic(fmt.Sprintf("duplicate rule ID: %q", rule.ID()))
	}
	r.rules = append(r.rules, rule)
	r.index[rule.ID()] = struct{}{}
}

// All returns all registered rules in registration order.
func (r *DefaultRuleRegistry) All() []Rule {
	return r.rules
}

// EvaluateAll runs every registered rule against ctx and returns the merged
// findings slice. Rules are called sequentially in registration order.
func (r *DefaultRuleRegistry) EvaluateAll(ctx RuleContext) []models.Finding {
	var findings []models.Finding
	for _, rule := range r.rules {
		findings = append(findings, rule.Evaluate(ctx)...)
	}
	return findings
}
