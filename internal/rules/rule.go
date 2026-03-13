package rules

import (
	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
)

// RuleContext carries all collected data for a single region and profile.
// It is the sole input to Rule.Evaluate and must contain everything a rule
// needs; rules must never make network calls or read external state.
type RuleContext struct {
	// AccountID is the AWS account being evaluated.
	AccountID string

	// Profile is the AWS profile name for this evaluation run.
	Profile string

	// RegionData holds all resources collected from the target region.
	RegionData *models.AWSRegionData

	// CostSummary is the account-level Cost Explorer data, shared across
	// all regional evaluations. May be nil if collection failed.
	CostSummary *models.AWSCostSummary

	// Policy holds the active PolicyConfig for threshold overrides. May be nil
	// when no policy file is loaded; rules must treat nil as "use defaults".
	Policy *policy.PolicyConfig

	// ClusterData holds Kubernetes cluster inventory for K8s rule evaluation.
	// Nil when running AWS audits; K8s rules must check for nil before use.
	ClusterData *models.KubernetesClusterData
}

// Rule is a single deterministic waste-detection rule.
// Rules must be stateless and safe to call concurrently.
// They must never call the AWS SDK, LLM, or any external service.
type Rule interface {
	// ID returns the unique, stable identifier for this rule (e.g. "EC2_LOW_CPU").
	ID() string

	// Name returns a short human-readable rule name.
	Name() string

	// Evaluate inspects the provided context and returns zero or more findings.
	// An empty slice means no issue was detected.
	Evaluate(ctx RuleContext) []models.Finding
}

// RuleRegistry manages the set of active rules and drives evaluation.
type RuleRegistry interface {
	// Register adds a rule to the registry. Panics on duplicate ID.
	Register(rule Rule)

	// All returns all registered rules in registration order.
	All() []Rule

	// EvaluateAll runs every registered rule against ctx and merges results.
	EvaluateAll(ctx RuleContext) []models.Finding
}
