package engine

import (
	"context"

	"github.com/devopsproxy/dp/internal/models"
)

// AuditType identifies the category of audit to run.
type AuditType string

const (
	AuditTypeCost           AuditType = "cost"
	AuditTypeSecurity       AuditType = "security"
	AuditTypeDataProtection AuditType = "dataprotection"
	AuditTypeAll            AuditType = "all"
)

// ReportFormat controls the CLI output format.
type ReportFormat string

const (
	ReportFormatJSON  ReportFormat = "json"
	ReportFormatTable ReportFormat = "table"
)

// AuditOptions configures a single audit run.
// It is the sole input to Engine.RunAudit.
type AuditOptions struct {
	// AuditType selects the audit module (e.g. "cost").
	AuditType AuditType

	// Profile is the named AWS profile to use. Empty means the default profile.
	Profile string

	// AllProfiles, when true, runs the audit across every configured AWS profile.
	AllProfiles bool

	// Regions is an explicit list of AWS regions to audit.
	// When empty the engine discovers and iterates all active regions.
	Regions []string

	// ReportFormat controls how the CLI renders the returned report.
	ReportFormat ReportFormat

	// DaysBack is the lookback window in days for cost and metric queries.
	// Defaults to 30 when zero.
	DaysBack int
}

// Engine is the central orchestration interface.
// It coordinates provider collection, rule evaluation, and optional LLM
// summarization, returning a fully populated AuditReport.
//
// Engine must not call AWS SDK or LLM clients directly; it delegates to
// the appropriate provider and rule interfaces.
type Engine interface {
	RunAudit(ctx context.Context, opts AuditOptions) (*models.AuditReport, error)
}
