package models

// SensitivityLevel classifies how sensitive a cloud resource is.
// It is attached to cloud resource nodes in the asset graph and surfaced in
// blast radius output and attack-path graphs to highlight high-value targets.
type SensitivityLevel string

const (
	// SensitivityUnknown is the default when no classification rule applies.
	SensitivityUnknown SensitivityLevel = "unknown"

	// SensitivityLow means the resource contains non-sensitive data.
	SensitivityLow SensitivityLevel = "low"

	// SensitivityMedium means the resource may contain sensitive data but does
	// not match any high-risk naming pattern.
	SensitivityMedium SensitivityLevel = "medium"

	// SensitivityHigh means the resource is very likely to contain sensitive or
	// regulated data (PII, credentials, customer data, backups, payments).
	SensitivityHigh SensitivityLevel = "high"
)
