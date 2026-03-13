package models

import "time"

// Severity represents the impact level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ResourceType identifies the kind of cloud resource a finding refers to.
type ResourceType string

const (
	// AWS resource types
	ResourceAWSEC2           ResourceType = "EC2_INSTANCE"
	ResourceAWSEBS           ResourceType = "EBS_VOLUME"
	ResourceAWSNATGateway    ResourceType = "NAT_GATEWAY"
	ResourceAWSRDS           ResourceType = "RDS_INSTANCE"
	ResourceAWSLoadBalancer  ResourceType = "LOAD_BALANCER"
	ResourceAWSSavingsPlan   ResourceType = "SAVINGS_PLAN"
	ResourceAWSS3Bucket      ResourceType = "S3_BUCKET"
	ResourceAWSSecurityGroup ResourceType = "SECURITY_GROUP"
	ResourceAWSIAMUser       ResourceType = "IAM_USER"
	ResourceAWSRootAccount   ResourceType = "ROOT_ACCOUNT"

	// Kubernetes resource types
	ResourceK8sNode           ResourceType = "K8S_NODE"
	ResourceK8sNamespace      ResourceType = "K8S_NAMESPACE"
	ResourceK8sCluster        ResourceType = "K8S_CLUSTER"
	ResourceK8sPod            ResourceType = "K8S_POD"
	ResourceK8sService        ResourceType = "K8S_SERVICE"
	ResourceK8sServiceAccount ResourceType = "K8S_SERVICEACCOUNT"
)

// Finding is a single detected waste or inefficiency issue.
// It is the atomic output unit of the rule engine.
type Finding struct {
	ID                      string         `json:"id"`
	RuleID                  string         `json:"rule_id"`
	ResourceID              string         `json:"resource_id"`
	ResourceType            ResourceType   `json:"resource_type"`
	Region                  string         `json:"region"`
	AccountID               string         `json:"account_id"`
	Profile                 string         `json:"profile"`
	Domain                  string         `json:"domain"`
	Severity                Severity       `json:"severity"`
	EstimatedMonthlySavings float64        `json:"estimated_monthly_savings_usd"`
	Explanation             string         `json:"explanation"`
	Recommendation          string         `json:"recommendation"`
	DetectedAt              time.Time      `json:"detected_at"`
	Metadata                map[string]any `json:"metadata,omitempty"`
}

// RiskChain groups findings that participate in the same compound risk
// correlation chain. Populated in AuditSummary when ShowRiskChains is requested.
type RiskChain struct {
	// Score is the numeric risk weight for this chain (higher = more critical).
	Score int `json:"score"`
	// Reason is the human-readable explanation of why this chain is risky.
	Reason string `json:"reason"`
	// FindingIDs lists the Finding.ID values that participate in this chain.
	FindingIDs []string `json:"finding_ids"`
}

// AttackPath represents a multi-layer compound attack path detected across
// multiple correlated findings. Scores are higher than individual risk chains
// because they require the convergence of multiple security control failures.
// Populated in AuditSummary when ShowRiskChains is requested.
type AttackPath struct {
	// Score is the composite risk weight for this path (98, 92, or 90).
	Score int `json:"score"`
	// Layers describes the sequential stages of the attack path.
	Layers []string `json:"layers"`
	// FindingIDs lists the Finding.ID values that contribute to this path.
	FindingIDs []string `json:"finding_ids"`
	// Description is the human-readable summary of the attack scenario.
	Description string `json:"description"`
}

// CloudAttackPath represents a complete Internet-to-sensitive-data attack path
// discovered through graph traversal. Unlike rule-based AttackPaths, these are
// derived purely from the asset graph topology and cloud resource sensitivity
// metadata. Populated by the graph traversal engine (Phase 16).
type CloudAttackPath struct {
	// Score is the computed risk score (0–110). Additive: +40 Internet exposure,
	// +20 privileged workload, +20 IAM role involved, +20 sensitive data reached,
	// +10 IAMRole→IAMRole cross-role escalation (Phase 16.1).
	Score int `json:"score"`
	// Source is the ID of the first node in the path (typically "Internet").
	Source string `json:"source"`
	// Target is the ID of the last node in the path (a sensitive cloud resource).
	Target string `json:"target"`
	// Nodes contains the ordered node IDs from source to target (inclusive).
	Nodes []string `json:"nodes"`
	// Severity classifies the path into CRITICAL / HIGH / MEDIUM based on
	// score thresholds (Phase 17.1). Derived from Score; never empty.
	Severity AttackPathSeverity `json:"severity,omitempty"`
	// HasSensitiveData is true when the target cloud resource carries
	// sensitivity == "high" metadata, indicating direct access to sensitive
	// data (Phase 17.1).
	HasSensitiveData bool `json:"has_sensitive_data,omitempty"`
	// Explanation is a deterministic, offline human-readable description of
	// the attack path generated from node type analysis (Phase 17).
	Explanation string `json:"explanation,omitempty"`
	// AIExplanation is an AI-generated description of the attack path produced
	// by Anthropic or OpenAI when --ai-explain is set (Phase 17). Empty when
	// no AI key is configured or the API call fails.
	AIExplanation string `json:"ai_explanation,omitempty"`
}

// AuditSummary aggregates counts and totals across all findings.
type AuditSummary struct {
	TotalFindings                int     `json:"total_findings"`
	CriticalFindings             int     `json:"critical_findings"`
	HighFindings                 int     `json:"high_findings"`
	MediumFindings               int     `json:"medium_findings"`
	LowFindings                  int     `json:"low_findings"`
	TotalEstimatedMonthlySavings float64 `json:"total_estimated_monthly_savings_usd"`
	// RiskScore is the highest score across all detected attack paths or risk
	// chains (attack paths take precedence when present). 0 means no correlation
	// was detected. Populated only for Kubernetes audits.
	RiskScore int `json:"risk_score"`
	// AttackPaths lists multi-layer compound attack paths ordered by descending
	// score. Populated only when ShowRiskChains is requested (omitted otherwise).
	AttackPaths []AttackPath `json:"attack_paths,omitempty"`
	// RiskChains groups findings by compound risk chain, ordered by descending
	// score. Populated only when ShowRiskChains is requested (omitted otherwise).
	RiskChains []RiskChain `json:"risk_chains,omitempty"`
	// CloudAttackPaths lists graph-traversal-derived Internet→sensitive-data
	// attack paths ordered by descending score (Phase 16). Populated whenever
	// the asset graph is available and contains Internet-to-cloud-resource paths.
	CloudAttackPaths []CloudAttackPath `json:"cloud_attack_paths,omitempty"`
}

// AuditReport is the top-level, SaaS-compatible output of any audit run.
type AuditReport struct {
	ReportID    string          `json:"report_id"`
	GeneratedAt time.Time       `json:"generated_at"`
	AuditType   string          `json:"audit_type"`
	Profile     string          `json:"profile"`
	AccountID   string          `json:"account_id"`
	Regions     []string        `json:"regions"`
	Summary     AuditSummary    `json:"summary"`
	Findings    []Finding       `json:"findings"`
	CostSummary *AWSCostSummary `json:"cost_summary,omitempty"`
	// Metadata carries optional, audit-type-specific key/value pairs.
	// For Kubernetes audits this includes "cluster_provider".
	Metadata map[string]any `json:"metadata,omitempty"`
}
