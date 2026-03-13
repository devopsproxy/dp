package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/devopsproxy/dp/internal/models"
)

// ANSI color codes for severity output (used when Colored=true).
const (
	ansiReset   = "\033[0m"
	ansiBoldRed = "\033[1;31m"
	ansiRed     = "\033[0;31m"
	ansiYellow  = "\033[0;33m"
	ansiBlue    = "\033[0;34m"
)

// TableOptions controls which columns RenderTable renders and how severity is coloured.
type TableOptions struct {
	// Colored wraps severity labels with ANSI codes. Default false (CI-safe).
	Colored bool

	// IncludeSavings adds a SAVINGS/MO column when any finding has EstimatedMonthlySavings > 0.
	IncludeSavings bool

	// IncludeDomain adds a DOMAIN column.
	IncludeDomain bool

	// IncludeProfile adds a PROFILE column (useful with --all-profiles).
	IncludeProfile bool

	// LocationLabel is the column header for the region/context column.
	// Defaults to "REGION". Use "CONTEXT" for Kubernetes audits.
	LocationLabel string
}

// ColorSeverity wraps a severity string with ANSI codes when colored is true.
// When colored is false the string is returned unchanged (CI-safe default).
func ColorSeverity(sev models.Severity, colored bool) string {
	s := string(sev)
	if !colored {
		return s
	}
	switch sev {
	case models.SeverityCritical:
		return ansiBoldRed + s + ansiReset
	case models.SeverityHigh:
		return ansiRed + s + ansiReset
	case models.SeverityMedium:
		return ansiYellow + s + ansiReset
	case models.SeverityLow:
		return ansiBlue + s + ansiReset
	default:
		return s
	}
}

// ShortenMessage truncates msg to at most max runes, appending "..." when truncated.
// max is treated as at least 4 to guarantee space for the ellipsis.
func ShortenMessage(msg string, max int) string {
	if max < 4 {
		max = 4
	}
	runes := []rune(msg)
	if len(runes) <= max {
		return msg
	}
	return string(runes[:max-3]) + "..."
}

// hasSavings reports whether any finding has EstimatedMonthlySavings > 0.
func hasSavings(findings []models.Finding) bool {
	for _, f := range findings {
		if f.EstimatedMonthlySavings > 0 {
			return true
		}
	}
	return false
}

// severityCell returns the severity padded to width characters.
// When colored, ANSI codes wrap only the text; trailing padding spaces are plain
// so subsequent columns stay visually aligned regardless of terminal ANSI support.
func severityCell(sev models.Severity, width int, colored bool) string {
	text := string(sev)
	if !colored {
		return fmt.Sprintf("%-*s", width, text)
	}
	var code string
	switch sev {
	case models.SeverityCritical:
		code = ansiBoldRed
	case models.SeverityHigh:
		code = ansiRed
	case models.SeverityMedium:
		code = ansiYellow
	case models.SeverityLow:
		code = ansiBlue
	default:
		return fmt.Sprintf("%-*s", width, text)
	}
	spaces := width - len(text)
	if spaces < 0 {
		spaces = 0
	}
	return code + text + ansiReset + strings.Repeat(" ", spaces)
}

// truncateField shortens s to at most max bytes for ID/label columns.
// A single-char ellipsis replaces the last byte when truncation occurs.
func truncateField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// RenderTable writes a formatted findings table to w.
// Columns are dynamically selected based on opts; the separator line width is
// derived from the header row so all rows align correctly.
//
// Column order:
//
//	RESOURCE ID  [PROFILE]  LOCATION  SEVERITY  [DOMAIN]  TYPE  MESSAGE  [SAVINGS/MO]
func RenderTable(w io.Writer, findings []models.Finding, opts TableOptions) {
	if opts.LocationLabel == "" {
		opts.LocationLabel = "REGION"
	}

	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}

	showSavings := opts.IncludeSavings && hasSavings(findings)

	// Fixed column display widths.
	const (
		wResource = 30
		wProfile  = 12
		wLocation = 15
		wSeverity = 10
		wDomain   = 15
		wType     = 18
		wMessage  = 55
	)

	// Build the header row.
	var hb strings.Builder
	hb.WriteString(fmt.Sprintf("%-*s", wResource, "RESOURCE ID"))
	if opts.IncludeProfile {
		hb.WriteString(fmt.Sprintf("  %-*s", wProfile, "PROFILE"))
	}
	hb.WriteString(fmt.Sprintf("  %-*s", wLocation, opts.LocationLabel))
	hb.WriteString(fmt.Sprintf("  %-*s", wSeverity, "SEVERITY"))
	if opts.IncludeDomain {
		hb.WriteString(fmt.Sprintf("  %-*s", wDomain, "DOMAIN"))
	}
	hb.WriteString(fmt.Sprintf("  %-*s", wType, "TYPE"))
	hb.WriteString(fmt.Sprintf("  %-*s", wMessage, "MESSAGE"))
	if showSavings {
		hb.WriteString("  SAVINGS/MO")
	}
	header := hb.String()

	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("-", len(header)))

	for _, f := range findings {
		var rb strings.Builder
		rb.WriteString(fmt.Sprintf("%-*s", wResource, truncateField(f.ResourceID, wResource)))
		if opts.IncludeProfile {
			rb.WriteString(fmt.Sprintf("  %-*s", wProfile, truncateField(f.Profile, wProfile)))
		}
		rb.WriteString(fmt.Sprintf("  %-*s", wLocation, truncateField(f.Region, wLocation)))
		rb.WriteString("  " + severityCell(f.Severity, wSeverity, opts.Colored))
		if opts.IncludeDomain {
			rb.WriteString(fmt.Sprintf("  %-*s", wDomain, truncateField(f.Domain, wDomain)))
		}
		rb.WriteString(fmt.Sprintf("  %-*s", wType, truncateField(string(f.ResourceType), wType)))
		rb.WriteString(fmt.Sprintf("  %-*s", wMessage, ShortenMessage(f.Explanation, wMessage)))
		if showSavings {
			rb.WriteString(fmt.Sprintf("  $%.2f", f.EstimatedMonthlySavings))
		}
		fmt.Fprintln(w, rb.String())
	}
}
