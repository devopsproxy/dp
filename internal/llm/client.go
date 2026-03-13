package llm

import (
	"context"

	"github.com/devopsproxy/dp/internal/models"
)

// SummaryRequest asks the LLM to produce a human-readable summary of a
// completed audit report.
type SummaryRequest struct {
	// Report is the structured audit output to summarise.
	Report *models.AuditReport

	// MaxWords is an advisory limit on the generated summary length.
	MaxWords int
}

// SummaryResponse contains the generated summary and usage metadata.
type SummaryResponse struct {
	Summary    string `json:"summary"`
	TokensUsed int    `json:"tokens_used"`
}

// LLMClient is the interface for all AI-assisted operations.
// Implementations are optional; the engine functions correctly without one.
//
// The LLM must never:
//   - Execute shell commands
//   - Control program flow
//   - Make AWS SDK calls
//   - Generate executable code dynamically
//
// The LLM is only for summarization, prioritization, and report generation.
type LLMClient interface {
	// SummarizeReport generates a concise, prioritised summary of an audit report.
	SummarizeReport(ctx context.Context, req SummaryRequest) (*SummaryResponse, error)

	// IsAvailable returns true when the LLM backend is configured and reachable.
	// Use this to gate LLM calls and provide graceful degradation.
	IsAvailable(ctx context.Context) bool
}
