package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/devopsproxy/dp/internal/engine"
	dpgraph "github.com/devopsproxy/dp/internal/graph"
	"github.com/devopsproxy/dp/internal/models"
	dpoutput "github.com/devopsproxy/dp/internal/output"
	"github.com/devopsproxy/dp/internal/policy"
	"github.com/devopsproxy/dp/internal/providers/aws/common"
	awscost "github.com/devopsproxy/dp/internal/providers/aws/cost"
	awseks "github.com/devopsproxy/dp/internal/providers/aws/eks"
	awssecurity "github.com/devopsproxy/dp/internal/providers/aws/security"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	dpexplain "github.com/devopsproxy/dp/internal/explain"
	dprender "github.com/devopsproxy/dp/internal/render"
	costpack "github.com/devopsproxy/dp/internal/rulepacks/aws_cost"
	dppack "github.com/devopsproxy/dp/internal/rulepacks/aws_dataprotection"
	secpack "github.com/devopsproxy/dp/internal/rulepacks/aws_security"
	k8scorepack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_core"
	k8sekpack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_eks"
	"github.com/devopsproxy/dp/internal/rules"
	"github.com/devopsproxy/dp/internal/version"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "dp",
		Short: "DevOps Proxy — extensible DevOps execution engine",
	}
	root.AddCommand(newAWSCmd())
	root.AddCommand(newKubernetesCmd())
	root.AddCommand(newPolicyCmd())
	root.AddCommand(newVersionCmd())
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newBlastRadiusCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print dp version, commit, and build date",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprint(cmd.OutOrStdout(), version.Info())
		},
	}
}

func newAWSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "AWS provider commands",
	}
	cmd.AddCommand(newAuditCmd())
	return cmd
}

func newAuditCmd() *cobra.Command {
	var (
		all         bool
		profile     string
		allProfiles bool
		regions     []string
		days        int
		outputFmt   string
		summary     bool
		filePath    string
		policyPath  string
		color       bool
	)

	cmd := &cobra.Command{
		Use:          "audit",
		Short:        "Run an audit against an AWS account",
		SilenceUsage: true, // business-outcome exits must not print usage
		RunE: func(cmd *cobra.Command, args []string) error {
			if !all {
				return cmd.Help()
			}
			return runAllDomainsAudit(
				cmd.Context(),
				profile, allProfiles, regions, days,
				outputFmt, summary, filePath, policyPath, color,
				cmd.OutOrStdout(),
			)
		},
	}

	cmd.AddCommand(newCostCmd())
	cmd.AddCommand(newSecurityCmd())
	cmd.AddCommand(newDataProtectionCmd())

	cmd.Flags().BoolVar(&all, "all", false, "Run all AWS audit domains: cost, security, dataprotection")
	cmd.Flags().StringVar(&profile, "profile", "", "AWS profile name (default: uses environment / default profile)")
	cmd.Flags().BoolVar(&allProfiles, "all-profiles", false, "Audit all configured AWS profiles")
	cmd.Flags().StringSliceVar(&regions, "region", nil, "AWS region(s) to audit (default: all active regions)")
	cmd.Flags().IntVar(&days, "days", 30, "Lookback window in days for cost queries")
	cmd.Flags().StringVar(&outputFmt, "output", "table", "Output format: json or table")
	cmd.Flags().BoolVar(&summary, "summary", false, "Print compact summary: totals, severity breakdown, top-5 findings by savings")
	cmd.Flags().StringVar(&filePath, "file", "", "Write full JSON report to this file path (in addition to stdout output)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists)")
	cmd.Flags().BoolVar(&color, "color", false, "Enable colored severity output in table format (not CI-safe)")

	return cmd
}

// runAllDomainsAudit wires the three AWS domain engines, executes the unified
// audit, renders output to w, and returns an error when policy enforcement
// fires on any domain or when CRITICAL/HIGH findings exist.
// Kubernetes is intentionally excluded — use dp kubernetes audit for Kubernetes governance checks.
func runAllDomainsAudit(
	ctx context.Context,
	profile string,
	allProfiles bool,
	regions []string,
	days int,
	outputFmt string,
	summary bool,
	filePath string,
	policyPath string,
	colored bool,
	w io.Writer,
) error {
	policyCfg, err := loadPolicyFile(policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	awsProvider := common.NewDefaultAWSClientProvider()
	costCollector := awscost.NewDefaultCostCollector()
	secCollector := awssecurity.NewDefaultSecurityCollector()

	costReg := rules.NewDefaultRuleRegistry()
	for _, r := range costpack.New() {
		costReg.Register(r)
	}
	secReg := rules.NewDefaultRuleRegistry()
	for _, r := range secpack.New() {
		secReg.Register(r)
	}
	dpReg := rules.NewDefaultRuleRegistry()
	for _, r := range dppack.New() {
		dpReg.Register(r)
	}

	costEng := engine.NewAWSCostEngine(awsProvider, costCollector, costReg, policyCfg)
	secEng := engine.NewAWSSecurityEngine(awsProvider, secCollector, secReg, policyCfg)
	dpEng := engine.NewAWSDataProtectionEngine(awsProvider, costCollector, secCollector, dpReg, policyCfg)

	allEng := engine.NewAllAWSDomainsEngine(costEng, secEng, dpEng, policyCfg)

	opts := engine.AllAWSAuditOptions{
		Profile:     profile,
		AllProfiles: allProfiles,
		Regions:     regions,
		DaysBack:    days,
	}

	report, enforcedDomains, err := allEng.RunAllAWSAudit(ctx, opts)
	if err != nil {
		return fmt.Errorf("all-domain audit failed: %w", err)
	}

	if filePath != "" {
		if err := writeReportToFile(filePath, report); err != nil {
			return err
		}
	}

	if outputFmt == "json" {
		if err := encodeJSON(w, report); err != nil {
			return fmt.Errorf("encode report: %w", err)
		}
	} else if summary {
		printSummary(w, report)
	} else {
		s := report.Summary
		fmt.Fprintf(w, "Profile: %-20s  Account: %-14s  Regions: %d  Findings: %d  Est. Savings: $%.2f/mo\n",
			report.Profile, report.AccountID, len(report.Regions), s.TotalFindings, s.TotalEstimatedMonthlySavings)
		if len(report.Findings) > 0 {
			fmt.Fprintln(w)
		}
		dpoutput.RenderTable(w, report.Findings, dpoutput.TableOptions{
			Colored:        colored,
			IncludeSavings: true,
			IncludeDomain:  true,
			IncludeProfile: allProfiles,
			LocationLabel:  "REGION",
		})
	}

	if len(enforcedDomains) > 0 {
		return fmt.Errorf("policy enforcement triggered on domain(s): %s",
			strings.Join(enforcedDomains, ", "))
	}
	if hasCriticalOrHighFindings(report.Findings) {
		if outputFmt != "json" {
			fmt.Fprintln(os.Stderr, "audit completed with CRITICAL or HIGH findings")
		}
		os.Exit(1)
	}
	return nil
}

// loadPolicyFile returns a PolicyConfig for the given path.
// If path is empty, it auto-discovers dp.yaml in the current directory.
// If neither is found, it returns nil (policy disabled — default behaviour).
func loadPolicyFile(path string) (*policy.PolicyConfig, error) {
	if path != "" {
		return policy.LoadPolicy(path)
	}
	if _, err := os.Stat("dp.yaml"); err == nil {
		return policy.LoadPolicy("dp.yaml")
	}
	return nil, nil
}

func newCostCmd() *cobra.Command {
	var (
		profile     string
		allProfiles bool
		regions     []string
		days        int
		outputFmt   string
		summary     bool
		filePath    string
		policyPath  string
		color       bool
	)

	cmd := &cobra.Command{
		Use:          "cost",
		Short:        "Audit AWS cost and identify wasted spend",
		SilenceUsage: true, // business-outcome exits must not print usage
		RunE: func(cmd *cobra.Command, args []string) error {
			policyCfg, err := loadPolicyFile(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}

			provider := common.NewDefaultAWSClientProvider()
			collector := awscost.NewDefaultCostCollector()

			registry := rules.NewDefaultRuleRegistry()
			for _, r := range costpack.New() {
				registry.Register(r)
			}

			eng := engine.NewAWSCostEngine(provider, collector, registry, policyCfg)

			opts := engine.AuditOptions{
				AuditType:    engine.AuditTypeCost,
				Profile:      profile,
				AllProfiles:  allProfiles,
				Regions:      regions,
				DaysBack:     days,
				ReportFormat: engine.ReportFormat(outputFmt),
			}

			report, err := eng.RunAudit(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("audit failed: %w", err)
			}

			if filePath != "" {
				if err := writeReportToFile(filePath, report); err != nil {
					return err
				}
			}

			if err := renderAWSCostOutput(os.Stdout, report, outputFmt, summary, color, allProfiles); err != nil {
				return err
			}

			if policy.ShouldFail("cost", report.Findings, policyCfg) {
				return fmt.Errorf("policy enforcement triggered: findings at or above configured fail_on_severity")
			}
			if hasCriticalOrHighFindings(report.Findings) {
				if outputFmt != "json" {
					fmt.Fprintln(os.Stderr, "audit completed with CRITICAL or HIGH findings")
				}
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS profile name (default: uses environment / default profile)")
	cmd.Flags().BoolVar(&allProfiles, "all-profiles", false, "Audit all configured AWS profiles")
	cmd.Flags().StringSliceVar(&regions, "region", nil, "AWS region(s) to audit (default: all active regions)")
	cmd.Flags().IntVar(&days, "days", 30, "Lookback window in days for cost and metric queries")
	cmd.Flags().StringVar(&outputFmt, "output", "table", "Output format: json or table")
	cmd.Flags().BoolVar(&summary, "summary", false, "Print compact summary: totals, severity breakdown, top-5 findings by savings")
	cmd.Flags().StringVar(&filePath, "file", "", "Write full JSON report to this file path (in addition to stdout output)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists)")
	cmd.Flags().BoolVar(&color, "color", false, "Enable colored severity output in table format (not CI-safe)")

	return cmd
}

func newSecurityCmd() *cobra.Command {
	var (
		profile     string
		allProfiles bool
		regions     []string
		outputFmt   string
		summary     bool
		filePath    string
		policyPath  string
		color       bool
	)

	cmd := &cobra.Command{
		Use:          "security",
		Short:        "Audit AWS security posture: S3 public access, open SSH, IAM MFA, root access keys",
		SilenceUsage: true, // business-outcome exits must not print usage
		RunE: func(cmd *cobra.Command, args []string) error {
			policyCfg, err := loadPolicyFile(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}

			provider := common.NewDefaultAWSClientProvider()
			collector := awssecurity.NewDefaultSecurityCollector()

			registry := rules.NewDefaultRuleRegistry()
			for _, r := range secpack.New() {
				registry.Register(r)
			}

			eng := engine.NewAWSSecurityEngine(provider, collector, registry, policyCfg)

			opts := engine.AuditOptions{
				AuditType:    engine.AuditTypeSecurity,
				Profile:      profile,
				AllProfiles:  allProfiles,
				Regions:      regions,
				ReportFormat: engine.ReportFormat(outputFmt),
			}

			report, err := eng.RunAudit(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("security audit failed: %w", err)
			}

			if filePath != "" {
				if err := writeReportToFile(filePath, report); err != nil {
					return err
				}
			}

			if err := renderAWSSecurityOutput(os.Stdout, report, outputFmt, summary, color, allProfiles); err != nil {
				return err
			}

			if policy.ShouldFail("security", report.Findings, policyCfg) {
				return fmt.Errorf("policy enforcement triggered: findings at or above configured fail_on_severity")
			}
			if hasCriticalOrHighFindings(report.Findings) {
				if outputFmt != "json" {
					fmt.Fprintln(os.Stderr, "audit completed with CRITICAL or HIGH findings")
				}
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS profile name (default: uses environment / default profile)")
	cmd.Flags().BoolVar(&allProfiles, "all-profiles", false, "Audit all configured AWS profiles")
	cmd.Flags().StringSliceVar(&regions, "region", nil, "AWS region(s) to audit (default: all active regions)")
	cmd.Flags().StringVar(&outputFmt, "output", "table", "Output format: json or table")
	cmd.Flags().BoolVar(&summary, "summary", false, "Print compact summary: totals, severity breakdown, top-5 findings")
	cmd.Flags().StringVar(&filePath, "file", "", "Write full JSON report to this file path (in addition to stdout output)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists)")
	cmd.Flags().BoolVar(&color, "color", false, "Enable colored severity output in table format (not CI-safe)")

	return cmd
}

func newDataProtectionCmd() *cobra.Command {
	var (
		profile     string
		allProfiles bool
		regions     []string
		outputFmt   string
		summary     bool
		filePath    string
		policyPath  string
		color       bool
	)

	cmd := &cobra.Command{
		Use:          "dataprotection",
		Short:        "Audit AWS data protection: EBS encryption, RDS encryption, S3 default encryption",
		SilenceUsage: true, // business-outcome exits must not print usage
		RunE: func(cmd *cobra.Command, args []string) error {
			policyCfg, err := loadPolicyFile(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}

			provider := common.NewDefaultAWSClientProvider()
			costCollector := awscost.NewDefaultCostCollector()
			secCollector := awssecurity.NewDefaultSecurityCollector()

			registry := rules.NewDefaultRuleRegistry()
			for _, r := range dppack.New() {
				registry.Register(r)
			}

			eng := engine.NewAWSDataProtectionEngine(provider, costCollector, secCollector, registry, policyCfg)

			opts := engine.AuditOptions{
				AuditType:    engine.AuditTypeDataProtection,
				Profile:      profile,
				AllProfiles:  allProfiles,
				Regions:      regions,
				ReportFormat: engine.ReportFormat(outputFmt),
			}

			report, err := eng.RunAudit(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("data protection audit failed: %w", err)
			}

			if filePath != "" {
				if err := writeReportToFile(filePath, report); err != nil {
					return err
				}
			}

			if err := renderAWSDataProtectionOutput(os.Stdout, report, outputFmt, summary, color, allProfiles); err != nil {
				return err
			}

			if policy.ShouldFail("dataprotection", report.Findings, policyCfg) {
				return fmt.Errorf("policy enforcement triggered: findings at or above configured fail_on_severity")
			}
			if hasCriticalOrHighFindings(report.Findings) {
				if outputFmt != "json" {
					fmt.Fprintln(os.Stderr, "audit completed with CRITICAL or HIGH findings")
				}
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS profile name (default: uses environment / default profile)")
	cmd.Flags().BoolVar(&allProfiles, "all-profiles", false, "Audit all configured AWS profiles")
	cmd.Flags().StringSliceVar(&regions, "region", nil, "AWS region(s) to audit (default: all active regions)")
	cmd.Flags().StringVar(&outputFmt, "output", "table", "Output format: json or table")
	cmd.Flags().BoolVar(&summary, "summary", false, "Print compact summary: totals, severity breakdown, top-5 findings")
	cmd.Flags().StringVar(&filePath, "file", "", "Write full JSON report to this file path (in addition to stdout output)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists)")
	cmd.Flags().BoolVar(&color, "color", false, "Enable colored severity output in table format (not CI-safe)")

	return cmd
}

// hasCriticalOrHighFindings returns true when any finding has CRITICAL or HIGH
// severity. This check is unconditional and independent of policy enforcement:
// it fires regardless of dp.yaml settings.
func hasCriticalOrHighFindings(findings []models.Finding) bool {
	for _, f := range findings {
		if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
			return true
		}
	}
	return false
}

// encodeJSON writes report as indented JSON to w.
// All render functions use this so tests can inject a bytes.Buffer.
func encodeJSON(w io.Writer, report *models.AuditReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// renderKubernetesAuditOutput writes the kubernetes audit report to w.
// JSON mode is checked first so it takes priority over --summary.
// In JSON mode only the JSON payload is written; no banner or table.
// When showRiskChains is true in table mode, findings are grouped by risk chain.
func renderKubernetesAuditOutput(w io.Writer, report *models.AuditReport, outputFmt string, summary bool, colored bool, showRiskChains bool) error {
	if outputFmt == "json" {
		return encodeJSON(w, report)
	}
	if summary {
		printSummary(w, report)
		return nil
	}
	s := report.Summary
	fmt.Fprintf(w, "Context: %-30s  Findings: %d\n", report.Profile, s.TotalFindings)
	if len(report.Findings) > 0 {
		fmt.Fprintln(w)
	}
	if showRiskChains {
		renderRiskChainTable(w, report, colored)
		return nil
	}
	// Phase 16: surface graph-traversal cloud attack paths in table mode.
	if len(report.Summary.CloudAttackPaths) > 0 {
		renderCloudAttackPaths(w, report.Summary.CloudAttackPaths)
	}
	// Phase 19: surface toxic combinations in table mode.
	if len(report.Summary.ToxicCombinations) > 0 {
		renderToxicCombinations(w, report.Summary.ToxicCombinations)
	}
	dpoutput.RenderTable(w, report.Findings, dpoutput.TableOptions{
		Colored:        colored,
		IncludeSavings: false,
		IncludeDomain:  false,
		IncludeProfile: false,
		LocationLabel:  "CONTEXT",
	})
	return nil
}

// renderCloudAttackPaths prints a severity summary followed by individual
// ATTACK PATH sections (Phase 16/17.1). Each section renders one node per
// line with a leading " →" arrow, and marks the target node [SENSITIVE] when
// HasSensitiveData is set. Explanation lines follow when present (Phase 17).
func renderCloudAttackPaths(w io.Writer, paths []models.CloudAttackPath) {
	// ── Severity summary ────────────────────────────────────────────────────
	counts := map[models.AttackPathSeverity]int{}
	for _, p := range paths {
		sev := p.Severity
		if sev == "" {
			sev = models.AttackPathSeverityFromScore(p.Score)
		}
		counts[sev]++
	}
	fmt.Fprintln(w, "ATTACK PATH SUMMARY")
	fmt.Fprintln(w)
	for _, sev := range []models.AttackPathSeverity{
		models.AttackPathSeverityCritical,
		models.AttackPathSeverityHigh,
		models.AttackPathSeverityMedium,
	} {
		if n := counts[sev]; n > 0 {
			fmt.Fprintf(w, "  %s: %d\n", sev, n)
		}
	}
	fmt.Fprintln(w)

	// ── Individual path sections ─────────────────────────────────────────────
	for _, p := range paths {
		sev := p.Severity
		if sev == "" {
			sev = models.AttackPathSeverityFromScore(p.Score)
		}
		fmt.Fprintf(w, "%s ATTACK PATH (Score: %d)\n", sev, p.Score)
		fmt.Fprintln(w)

		for i, nodeID := range p.Nodes {
			label := renderCloudAttackPathNode(nodeID)
			if i == len(p.Nodes)-1 && p.HasSensitiveData {
				label += " [SENSITIVE]"
			}
			if i == 0 {
				fmt.Fprintln(w, label)
			} else {
				fmt.Fprintf(w, " → %s\n", label)
			}
		}
		fmt.Fprintln(w)

		if p.AIExplanation != "" {
			fmt.Fprintf(w, "Explanation (AI): %s\n", p.AIExplanation)
			fmt.Fprintln(w)
		} else if p.Explanation != "" {
			fmt.Fprintf(w, "Explanation: %s\n", p.Explanation)
			fmt.Fprintln(w)
		}
	}
}

// renderCloudAttackPathNode formats a graph node ID for display in an attack
// path section. Misconfiguration nodes (Phase 18) are rendered using the
// human-readable name stored in the ID, e.g.:
//
//	"Misconfiguration_PublicLoadBalancer_kafka-ui" → "PublicLoadBalancer (kafka-ui)"
//	"Misconfiguration_WildcardIAMRole"             → "WildcardIAMRole"
//	"Misconfiguration_PrivilegedContainer_web"     → "PrivilegedContainer (web)"
//
// All other nodes are returned as-is.
func renderCloudAttackPathNode(nodeID string) string {
	const prefix = "Misconfiguration_"
	if !strings.HasPrefix(nodeID, prefix) {
		return nodeID
	}
	rest := nodeID[len(prefix):]
	// rest is e.g. "PublicLoadBalancer_kafka-ui" or "WildcardIAMRole"
	idx := strings.Index(rest, "_")
	if idx < 0 {
		// No resource suffix — return the misconfig type name directly.
		return rest
	}
	miscType := rest[:idx]
	resourceName := strings.ReplaceAll(rest[idx+1:], "_", "-")
	return fmt.Sprintf("%s (%s)", miscType, resourceName)
}

// renderToxicCombinations prints a TOXIC COMBINATIONS section (Phase 19) listing
// high-risk exploit chains detected by the analysis package.
// Each entry shows the severity and the ordered path of node names.
func renderToxicCombinations(w io.Writer, toxics []models.ToxicRisk) {
	if len(toxics) == 0 {
		return
	}
	fmt.Fprintln(w, "TOXIC COMBINATIONS")
	fmt.Fprintln(w)
	for _, t := range toxics {
		fmt.Fprintf(w, "  %s  %s\n", t.Severity, strings.Join(t.Path, " → "))
	}
	fmt.Fprintln(w)
}

// renderRiskChainTable prints attack paths (Phase 6) and risk chains (Phase 5D)
// grouped by score to w. Attack path sections are printed BEFORE risk chain
// sections. Findings not part of any path or chain are shown last under
// "Other Findings".
func renderRiskChainTable(w io.Writer, report *models.AuditReport, colored bool) {
	tableOpts := dpoutput.TableOptions{
		Colored:       colored,
		LocationLabel: "CONTEXT",
	}

	hasPaths := len(report.Summary.AttackPaths) > 0
	hasChains := len(report.Summary.RiskChains) > 0

	// Phase 16: cloud attack paths are surfaced regardless of hasPaths/hasChains.
	if len(report.Summary.CloudAttackPaths) > 0 {
		renderCloudAttackPaths(w, report.Summary.CloudAttackPaths)
	}
	// Phase 19: toxic combinations are surfaced alongside cloud attack paths.
	if len(report.Summary.ToxicCombinations) > 0 {
		renderToxicCombinations(w, report.Summary.ToxicCombinations)
	}

	if !hasPaths && !hasChains {
		fmt.Fprintln(w, "No risk chains detected.")
		dpoutput.RenderTable(w, report.Findings, tableOpts)
		return
	}

	// Build finding ID → finding pointer for fast lookup.
	findingByID := make(map[string]*models.Finding, len(report.Findings))
	for i := range report.Findings {
		f := &report.Findings[i]
		findingByID[f.ID] = f
	}

	shownIDs := make(map[string]bool)

	// ── Attack paths (highest priority; printed first) ────────────────────────
	for _, ap := range report.Summary.AttackPaths {
		fmt.Fprintf(w, "ATTACK PATH (Score: %d)\n", ap.Score)
		fmt.Fprintf(w, "Description: %s\n", ap.Description)
		fmt.Fprintf(w, "Layers: %s\n\n", strings.Join(ap.Layers, " → "))

		var pathFindings []models.Finding
		for _, id := range ap.FindingIDs {
			if f, ok := findingByID[id]; ok {
				pathFindings = append(pathFindings, *f)
				shownIDs[id] = true
			}
		}
		dpoutput.RenderTable(w, pathFindings, tableOpts)
		fmt.Fprintln(w)
	}

	// ── Risk chains (printed after attack paths) ──────────────────────────────
	for _, chain := range report.Summary.RiskChains {
		fmt.Fprintf(w, "RISK CHAIN (Score: %d)\n", chain.Score)
		fmt.Fprintf(w, "Reason: %s\n\n", chain.Reason)

		var chainFindings []models.Finding
		for _, id := range chain.FindingIDs {
			if f, ok := findingByID[id]; ok {
				chainFindings = append(chainFindings, *f)
				shownIDs[id] = true
			}
		}
		dpoutput.RenderTable(w, chainFindings, tableOpts)
		fmt.Fprintln(w)
	}

	// ── Findings not in any path or chain ─────────────────────────────────────
	var remaining []models.Finding
	for _, f := range report.Findings {
		if !shownIDs[f.ID] {
			remaining = append(remaining, f)
		}
	}
	if len(remaining) > 0 {
		fmt.Fprintln(w, "Other Findings:")
		fmt.Fprintln(w)
		dpoutput.RenderTable(w, remaining, tableOpts)
	}
}

// renderAWSCostOutput writes the cost audit report to w.
// JSON mode is checked first so it takes priority over --summary.
func renderAWSCostOutput(w io.Writer, report *models.AuditReport, outputFmt string, summary bool, colored bool, allProfiles bool) error {
	if outputFmt == "json" {
		return encodeJSON(w, report)
	}
	if summary {
		printSummary(w, report)
		return nil
	}
	s := report.Summary
	fmt.Fprintf(w, "Profile: %-20s  Account: %-14s  Regions: %d  Findings: %d  Est. Savings: $%.2f/mo\n",
		report.Profile, report.AccountID, len(report.Regions), s.TotalFindings, s.TotalEstimatedMonthlySavings)
	if len(report.Findings) > 0 {
		fmt.Fprintln(w)
	}
	dpoutput.RenderTable(w, report.Findings, dpoutput.TableOptions{
		Colored:        colored,
		IncludeSavings: true,
		IncludeDomain:  false,
		IncludeProfile: allProfiles,
		LocationLabel:  "REGION",
	})
	return nil
}

// renderAWSSecurityOutput writes the security audit report to w.
// JSON mode is checked first so it takes priority over --summary.
func renderAWSSecurityOutput(w io.Writer, report *models.AuditReport, outputFmt string, summary bool, colored bool, allProfiles bool) error {
	if outputFmt == "json" {
		return encodeJSON(w, report)
	}
	if summary {
		printSummary(w, report)
		return nil
	}
	s := report.Summary
	fmt.Fprintf(w, "Profile: %-20s  Account: %-14s  Regions: %d  Findings: %d\n",
		report.Profile, report.AccountID, len(report.Regions), s.TotalFindings)
	if len(report.Findings) > 0 {
		fmt.Fprintln(w)
	}
	dpoutput.RenderTable(w, report.Findings, dpoutput.TableOptions{
		Colored:        colored,
		IncludeSavings: false,
		IncludeDomain:  false,
		IncludeProfile: allProfiles,
		LocationLabel:  "REGION",
	})
	return nil
}

// renderAWSDataProtectionOutput writes the data-protection audit report to w.
// JSON mode is checked first so it takes priority over --summary.
func renderAWSDataProtectionOutput(w io.Writer, report *models.AuditReport, outputFmt string, summary bool, colored bool, allProfiles bool) error {
	if outputFmt == "json" {
		return encodeJSON(w, report)
	}
	if summary {
		printSummary(w, report)
		return nil
	}
	s := report.Summary
	fmt.Fprintf(w, "Profile: %-20s  Account: %-14s  Regions: %d  Findings: %d\n",
		report.Profile, report.AccountID, len(report.Regions), s.TotalFindings)
	if len(report.Findings) > 0 {
		fmt.Fprintln(w)
	}
	dpoutput.RenderTable(w, report.Findings, dpoutput.TableOptions{
		Colored:        colored,
		IncludeSavings: false,
		IncludeDomain:  false,
		IncludeProfile: allProfiles,
		LocationLabel:  "REGION",
	})
	return nil
}

// writeReportToFile serialises report as indented JSON and writes it to path,
// creating or overwriting the file. It does not affect stdout output.
func writeReportToFile(path string, report *models.AuditReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write report file %q: %w", path, err)
	}
	return nil
}

// printSummary renders a compact summary view to w:
//   - Account / profile / region header
//   - Total findings and total estimated monthly savings
//   - Per-severity finding counts
//   - Top 5 findings ranked by EstimatedMonthlySavings
//
// It reuses the already-computed AuditReport; no engine logic is duplicated.
func printSummary(w io.Writer, report *models.AuditReport) {
	s := report.Summary

	fmt.Fprintf(w, "Account:  %s\n", report.AccountID)
	fmt.Fprintf(w, "Profile:  %s\n", report.Profile)
	fmt.Fprintf(w, "Regions:  %d\n", len(report.Regions))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Total Findings:        %d\n", s.TotalFindings)
	fmt.Fprintf(w, "Est. Monthly Savings:  $%.2f\n", s.TotalEstimatedMonthlySavings)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Severity Breakdown")
	fmt.Fprintf(w, "  %-10s  %d\n", "CRITICAL", s.CriticalFindings)
	fmt.Fprintf(w, "  %-10s  %d\n", "HIGH", s.HighFindings)
	fmt.Fprintf(w, "  %-10s  %d\n", "MEDIUM", s.MediumFindings)
	fmt.Fprintf(w, "  %-10s  %d\n", "LOW", s.LowFindings)

	top := topFindingsBySavings(report.Findings, 5)
	if len(top) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Top Findings by Savings")
	fmt.Fprintf(w, "  %-42s  %-15s  %-10s  %s\n", "RESOURCE ID", "REGION", "SEVERITY", "SAVINGS/MO")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 82))
	for _, f := range top {
		fmt.Fprintf(w, "  %-42s  %-15s  %-10s  $%.2f\n",
			f.ResourceID, f.Region, string(f.Severity), f.EstimatedMonthlySavings)
	}
}

// topFindingsBySavings returns up to n findings from the provided slice,
// ordered by EstimatedMonthlySavings descending.
// The original slice is not modified.
func topFindingsBySavings(findings []models.Finding, n int) []models.Finding {
	sorted := make([]models.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].EstimatedMonthlySavings > sorted[j].EstimatedMonthlySavings
	})
	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}

// ── policy commands ───────────────────────────────────────────────────────────

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Policy management commands",
	}
	cmd.AddCommand(newPolicyValidateCmd())
	return cmd
}

func newPolicyValidateCmd() *cobra.Command {
	var policyPath string

	cmd := &cobra.Command{
		Use:          "validate",
		Short:        "Validate a dp.yaml policy file without running an audit",
		SilenceUsage: true, // don't print usage on validation errors
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadPolicyFile(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}
			if cfg == nil {
				return fmt.Errorf("no policy file found at %q", policyPath)
			}

			// Collect all known rule IDs from every registered pack.
			var ruleIDs []string
			for _, r := range costpack.New() {
				ruleIDs = append(ruleIDs, r.ID())
			}
			for _, r := range secpack.New() {
				ruleIDs = append(ruleIDs, r.ID())
			}
			for _, r := range dppack.New() {
				ruleIDs = append(ruleIDs, r.ID())
			}
			for _, r := range k8scorepack.New() {
				ruleIDs = append(ruleIDs, r.ID())
			}
			for _, r := range k8sekpack.New() {
				ruleIDs = append(ruleIDs, r.ID())
			}

			errs := policy.Validate(cfg, ruleIDs)
			if len(errs) > 0 {
				for _, e := range errs {
					fmt.Println(e)
				}
				return fmt.Errorf("policy validation failed: %d error(s)", len(errs))
			}

			fmt.Println("Policy file is valid.")
			return nil
		},
	}

	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file to validate")
	_ = cmd.MarkFlagRequired("policy")

	return cmd
}

// ── kubernetes commands ───────────────────────────────────────────────────────

func newKubernetesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "Kubernetes provider commands",
	}
	cmd.AddCommand(newInspectCmd())
	cmd.AddCommand(newKubernetesAuditCmd())
	return cmd
}

func newInspectCmd() *cobra.Command {
	var contextName string

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a Kubernetes cluster: context, API server, node count, namespace count",
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := kube.NewDefaultKubeClientProvider()
			return runKubernetesInspect(cmd.Context(), provider, contextName, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "", "Kubeconfig context to use (default: current context)")

	return cmd
}

// runKubernetesInspect is the testable core of the inspect command.
// It accepts a KubeClientProvider so tests can inject a fake clientset.
func runKubernetesInspect(ctx context.Context, provider kube.KubeClientProvider, contextName string, w io.Writer) error {
	clientset, info, err := provider.ClientsetForContext(contextName)
	if err != nil {
		return fmt.Errorf("connect to cluster: %w", err)
	}

	data, err := kube.CollectClusterData(ctx, clientset, info)
	if err != nil {
		return fmt.Errorf("collect cluster data: %w", err)
	}

	printClusterInspect(w, data)
	return nil
}

// printClusterInspect writes the four-line cluster summary to w.
func printClusterInspect(w io.Writer, data *kube.ClusterData) {
	fmt.Fprintf(w, "Context:     %s\n", data.ClusterInfo.ContextName)
	fmt.Fprintf(w, "API Server:  %s\n", data.ClusterInfo.Server)
	fmt.Fprintf(w, "Nodes:       %d\n", len(data.Nodes))
	fmt.Fprintf(w, "Namespaces:  %d\n", len(data.Namespaces))
}

// validateExplainFlags returns an error when --explain-path is set without
// --show-risk-chains. Attack paths are only computed when ShowRiskChains is
// enabled, so --explain-path requires it as a prerequisite.
func validateExplainFlags(explainScore int, showRiskChains bool) error {
	if explainScore > 0 && !showRiskChains {
		return fmt.Errorf("--explain-path requires --show-risk-chains")
	}
	return nil
}

// validateMinAttackScoreFlags returns an error when --min-attack-score is set
// without --show-risk-chains. Attack paths are only computed when ShowRiskChains
// is enabled, so --min-attack-score requires it as a prerequisite.
func validateMinAttackScoreFlags(minAttackScore int, showRiskChains bool) error {
	if minAttackScore > 0 && !showRiskChains {
		return fmt.Errorf("--min-attack-score requires --show-risk-chains")
	}
	return nil
}

// validateAttackGraphFlags returns an error when --attack-graph is set without
// --show-risk-chains. The graph is built from computed attack paths, which are
// only populated when ShowRiskChains is enabled.
func validateAttackGraphFlags(attackGraph bool, showRiskChains bool) error {
	if attackGraph && !showRiskChains {
		return fmt.Errorf("--attack-graph requires --show-risk-chains")
	}
	return nil
}

// validateGraphFormat returns an error when graphFormat is not one of the
// recognised values: "mermaid" or "graphviz".
func validateGraphFormat(graphFormat string) error {
	switch graphFormat {
	case "mermaid", "graphviz":
		return nil
	default:
		return fmt.Errorf("--graph-format must be 'mermaid' or 'graphviz'; got %q", graphFormat)
	}
}

// explainBelowThreshold reports whether the requested --explain-path score
// falls below the active --min-attack-score threshold. When true the explain
// request is rejected with an informative message — the score is filtered out
// by the user-configured minimum.
func explainBelowThreshold(explainScore, minAttackScore int) bool {
	return explainScore > 0 && minAttackScore > 0 && explainScore < minAttackScore
}

// newKubernetesAuditCmd implements dp kubernetes audit.
func newKubernetesAuditCmd() *cobra.Command {
	var (
		contextName    string
		outputFmt      string
		summary        bool
		filePath       string
		policyPath     string
		color          bool
		excludeSystem  bool
		minRiskScore   int
		showRiskChains bool
		explainScore   int
		minAttackScore int
		attackGraph    bool
		graphFormat    string
		aiExplain      bool
	)

	cmd := &cobra.Command{
		Use:          "audit",
		Short:        "Audit a Kubernetes cluster: single-node, overallocated nodes, namespaces without LimitRanges",
		SilenceUsage: true, // business-outcome exits must not print usage
		RunE: func(cmd *cobra.Command, args []string) error {
			policyCfg, err := loadPolicyFile(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}

			if err := validateExplainFlags(explainScore, showRiskChains); err != nil {
				return err
			}
			if err := validateMinAttackScoreFlags(minAttackScore, showRiskChains); err != nil {
				return err
			}
			if err := validateAttackGraphFlags(attackGraph, showRiskChains); err != nil {
				return err
			}
			if attackGraph {
				if err := validateGraphFormat(graphFormat); err != nil {
					return err
				}
			}

			provider := kube.NewDefaultKubeClientProvider()

			coreRegistry := rules.NewDefaultRuleRegistry()
			for _, r := range k8scorepack.New() {
				coreRegistry.Register(r)
			}

			eksRegistry := rules.NewDefaultRuleRegistry()
			for _, r := range k8sekpack.New() {
				eksRegistry.Register(r)
			}

			eng := engine.NewKubernetesEngineWithEKS(
				provider,
				coreRegistry,
				eksRegistry,
				awseks.NewDefaultEKSCollector(),
				policyCfg,
			)

			opts := engine.KubernetesAuditOptions{
				ContextName:    contextName,
				ReportFormat:   engine.ReportFormat(outputFmt),
				ExcludeSystem:  excludeSystem,
				MinRiskScore:   minRiskScore,
				ShowRiskChains: showRiskChains,
			}

			report, err := eng.RunAudit(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("kubernetes audit failed: %w", err)
			}

			// Populate deterministic and (optionally) AI explanations on cloud
			// attack paths before file write so they appear in JSON output too.
			if len(report.Summary.CloudAttackPaths) > 0 {
				report.Summary.CloudAttackPaths = dpexplain.PopulateExplanations(
					cmd.Context(), report.Summary.CloudAttackPaths, aiExplain,
				)
			}

			if filePath != "" {
				if err := writeReportToFile(filePath, report); err != nil {
					return err
				}
			}

			// Filter attack paths for rendering only; the original report is
			// never mutated — risk_score, findings, and all other fields stay intact.
			filteredPaths := dprender.FilterAttackPaths(report.Summary.AttackPaths, minAttackScore)

			// Build a render-only copy of the report with filtered attack paths.
			renderSummary := report.Summary
			renderSummary.AttackPaths = filteredPaths
			renderReport := *report
			renderReport.Summary = renderSummary

			// attack-graph mode: build graph from computed paths and render it.
			// Skips all normal table/JSON output. Policy enforcement and
			// exit-code-1 logic are also skipped (graph export is view-only).
			if attackGraph {
				graph := dprender.BuildAttackGraph(report.Summary, report.Findings, eng.AssetGraph())
				var graphOut string
				if graphFormat == "graphviz" {
					graphOut = dprender.RenderGraphvizGraph(graph)
				} else {
					graphOut = dprender.RenderMermaidGraph(graph)
				}
				fmt.Fprint(os.Stdout, graphOut)
				return nil
			}

			// explain-path mode: render a single attack path and exit early.
			// No normal table, no policy enforcement, no exit-code-1 logic.
			if explainScore > 0 {
				if explainBelowThreshold(explainScore, minAttackScore) {
					fmt.Fprintf(os.Stdout, "Requested attack path score %d is below --min-attack-score threshold\n", explainScore)
					return nil
				}
				path := dprender.FindPathByScore(report.Summary.AttackPaths, explainScore)
				if outputFmt == "json" {
					return dprender.WriteExplainJSON(os.Stdout, path, explainScore)
				}
				if path == nil {
					fmt.Fprintf(os.Stdout, "No attack path found with score %d\n", explainScore)
					return nil
				}
				dprender.RenderAttackPathExplanation(os.Stdout, *path, report.Findings)
				return nil
			}

			// In table mode, notify when the score filter removed all attack paths.
			if minAttackScore > 0 && len(report.Summary.AttackPaths) > 0 &&
				len(filteredPaths) == 0 && outputFmt != "json" {
				fmt.Fprintf(os.Stdout, "No attack paths with score >= %d\n", minAttackScore)
			}

			if err := renderKubernetesAuditOutput(os.Stdout, &renderReport, outputFmt, summary, color, showRiskChains); err != nil {
				return err
			}

			if policy.ShouldFail("kubernetes", report.Findings, policyCfg) {
				return fmt.Errorf("policy enforcement triggered: findings at or above configured fail_on_severity")
			}
			if hasCriticalOrHighFindings(report.Findings) {
				if outputFmt != "json" {
					fmt.Fprintln(os.Stderr, "audit completed with CRITICAL or HIGH findings")
				}
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "", "Kubeconfig context to use (default: current context)")
	cmd.Flags().StringVar(&outputFmt, "output", "table", "Output format: json or table")
	cmd.Flags().BoolVar(&summary, "summary", false, "Print compact summary: totals, severity breakdown, top-5 findings")
	cmd.Flags().StringVar(&filePath, "file", "", "Write full JSON report to this file path (in addition to stdout output)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists)")
	cmd.Flags().BoolVar(&color, "color", false, "Enable colored severity output in table format (not CI-safe)")
	cmd.Flags().BoolVar(&excludeSystem, "exclude-system", false, "Exclude findings from system namespaces (kube-system, kube-public, kube-node-lease)")
	cmd.Flags().IntVar(&minRiskScore, "min-risk-score", 0, "Only include findings with a risk chain score >= this value (0 = include all)")
	cmd.Flags().BoolVar(&showRiskChains, "show-risk-chains", false, "Group findings by risk chain in table output; add risk_chains to JSON output")
	cmd.Flags().IntVar(&explainScore, "explain-path", 0, "Print structured breakdown of the attack path with this score (requires --show-risk-chains)")
	cmd.Flags().IntVar(&minAttackScore, "min-attack-score", 0, "Only render attack paths with score >= this value (requires --show-risk-chains)")
	cmd.Flags().BoolVar(&attackGraph, "attack-graph", false, "Render attack paths as a graph (requires --show-risk-chains)")
	cmd.Flags().StringVar(&graphFormat, "graph-format", "mermaid", "Graph output format: mermaid or graphviz (used with --attack-graph)")
	cmd.Flags().BoolVar(&aiExplain, "ai-explain", false, "Add AI-generated explanations to cloud attack paths (requires DP_ANTHROPIC_API_KEY or DP_OPENAI_API_KEY)")

	return cmd
}

// ── blast-radius command ──────────────────────────────────────────────────────

// newBlastRadiusCmd implements dp blast-radius <resource>.
// It connects to the cluster, builds the asset graph, and computes which cloud
// identities and resources are reachable from the given workload or service
// account via RUNS_AS → ASSUMES_ROLE → CAN_ACCESS traversal.
func newBlastRadiusCmd() *cobra.Command {
	var (
		contextName string
		outputFmt   string
	)

	cmd := &cobra.Command{
		Use:          "blast-radius <resource>",
		Short:        "Compute cloud resources reachable from a Kubernetes workload or service account",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resourceRef := args[0]

			nodeID, ok := dpgraph.ResolveStartNode(resourceRef)
			if !ok {
				return fmt.Errorf("unrecognised resource reference %q: use kind/name (e.g. deployment/my-app, serviceaccount/my-sa)", resourceRef)
			}

			provider := kube.NewDefaultKubeClientProvider()

			coreRegistry := rules.NewDefaultRuleRegistry()
			for _, r := range k8scorepack.New() {
				coreRegistry.Register(r)
			}
			eksRegistry := rules.NewDefaultRuleRegistry()
			for _, r := range k8sekpack.New() {
				eksRegistry.Register(r)
			}

			eng := engine.NewKubernetesEngineWithEKS(
				provider, coreRegistry, eksRegistry,
				awseks.NewDefaultEKSCollector(), nil,
			)

			if _, err := eng.RunAudit(cmd.Context(), engine.KubernetesAuditOptions{
				ContextName: contextName,
			}); err != nil {
				return fmt.Errorf("collect cluster data: %w", err)
			}

			ag := eng.AssetGraph()
			if ag == nil {
				return fmt.Errorf("asset graph could not be built for this cluster")
			}

			result, err := dpgraph.ComputeBlastRadius(ag, nodeID)
			if err != nil {
				return fmt.Errorf("blast radius: %w", err)
			}

			return renderBlastRadius(os.Stdout, resourceRef, result, outputFmt)
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "", "Kubeconfig context to use (default: current context)")
	cmd.Flags().StringVar(&outputFmt, "output", "table", "Output format: json or table")

	return cmd
}

// renderBlastRadius dispatches to the JSON or table renderer.
func renderBlastRadius(w io.Writer, source string, result *dpgraph.BlastResult, outputFmt string) error {
	if outputFmt == "json" {
		return renderBlastRadiusJSON(w, source, result)
	}
	return renderBlastRadiusTable(w, source, result)
}

// blastResourceKey maps a graph NodeType to its JSON output key.
func blastResourceKey(nt dpgraph.NodeType) string {
	switch nt {
	case dpgraph.NodeTypeS3Bucket:
		return "s3"
	case dpgraph.NodeTypeSecretsManagerSecret:
		return "secretsmanager"
	case dpgraph.NodeTypeDynamoDBTable:
		return "dynamodb"
	case dpgraph.NodeTypeKMSKey:
		return "kms"
	default:
		return strings.ToLower(string(nt))
	}
}

// blastResourceLabel maps a graph NodeType to its human-readable section header.
func blastResourceLabel(nt dpgraph.NodeType) string {
	switch nt {
	case dpgraph.NodeTypeS3Bucket:
		return "S3 Buckets"
	case dpgraph.NodeTypeSecretsManagerSecret:
		return "Secrets"
	case dpgraph.NodeTypeDynamoDBTable:
		return "DynamoDB Tables"
	case dpgraph.NodeTypeKMSKey:
		return "KMS Keys"
	default:
		return string(nt)
	}
}

// blastSourceDisplay formats a human-readable source label from the start node.
func blastSourceDisplay(node *dpgraph.Node) string {
	if node == nil {
		return ""
	}
	kind := node.Metadata["kind"]
	if kind == "" {
		kind = string(node.Type)
	}
	ns := node.Metadata["namespace"]
	if ns != "" {
		return fmt.Sprintf("%s %s (%s)", kind, node.Name, ns)
	}
	return fmt.Sprintf("%s %s", kind, node.Name)
}

// renderBlastRadiusTable writes a human-readable blast radius report.
func renderBlastRadiusTable(w io.Writer, _ string, result *dpgraph.BlastResult) error {
	fmt.Fprintln(w, "Blast Radius")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Source: %s\n", blastSourceDisplay(result.StartNode))
	fmt.Fprintln(w)

	if len(result.Identities) == 0 && len(result.Resources) == 0 {
		fmt.Fprintln(w, "No reachable cloud identities or resources found.")
		return nil
	}

	if len(result.Identities) > 0 {
		fmt.Fprintln(w, "Reachable identities:")
		for _, n := range result.Identities {
			fmt.Fprintf(w, "  IAM Role: %s\n", n.Name)
		}
		fmt.Fprintln(w)
	}

	if len(result.Resources) > 0 {
		fmt.Fprintln(w, "Reachable resources:")
		fmt.Fprintln(w)
		// Print resource sections in a consistent order.
		order := []dpgraph.NodeType{
			dpgraph.NodeTypeS3Bucket,
			dpgraph.NodeTypeSecretsManagerSecret,
			dpgraph.NodeTypeDynamoDBTable,
			dpgraph.NodeTypeKMSKey,
		}
		for _, nt := range order {
			nodes, ok := result.Resources[nt]
			if !ok || len(nodes) == 0 {
				continue
			}
			fmt.Fprintf(w, "%s:\n", blastResourceLabel(nt))
			for _, n := range nodes {
				prefix := ""
				if n.Metadata["sensitivity"] == "high" {
					prefix = "[SENSITIVE] "
				}
				fmt.Fprintf(w, "  - %s%s\n", prefix, n.Name)
			}
		}
	}
	return nil
}

// renderBlastRadiusJSON writes the blast radius result as indented JSON.
func renderBlastRadiusJSON(w io.Writer, source string, result *dpgraph.BlastResult) error {
	type output struct {
		Source     string              `json:"source"`
		Identities []string            `json:"identities"`
		Resources  map[string][]string `json:"resources"`
	}

	out := output{
		Source:    source,
		Resources: make(map[string][]string),
	}

	for _, n := range result.Identities {
		out.Identities = append(out.Identities, n.Name)
	}
	if out.Identities == nil {
		out.Identities = []string{}
	}

	for nt, nodes := range result.Resources {
		key := blastResourceKey(nt)
		for _, n := range nodes {
			out.Resources[key] = append(out.Resources[key], n.Name)
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
