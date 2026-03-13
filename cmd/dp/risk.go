package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/devopsproxy/dp/internal/engine"
	awseks "github.com/devopsproxy/dp/internal/providers/aws/eks"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	"github.com/devopsproxy/dp/internal/risk"
	k8scorepack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_core"
	k8sekpack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_eks"
	"github.com/devopsproxy/dp/internal/rules"
)

// newRiskCmd returns the `dp kubernetes risk` command group.
func newRiskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Risk prioritization commands",
	}
	cmd.AddCommand(newRiskTopCmd())
	cmd.AddCommand(newRiskExplainCmd())
	return cmd
}

// newRiskTopCmd returns the `dp kubernetes risk top` command.
// It runs the Kubernetes audit pipeline, builds the asset graph, and prints
// the top-scored risk findings detected by the risk prioritization engine.
func newRiskTopCmd() *cobra.Command {
	var (
		contextName string
		topN        int
		outputFmt   string
	)

	cmd := &cobra.Command{
		Use:          "top",
		Short:        "Show top attack path risks detected in the Kubernetes asset graph",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRiskTop(cmd.Context(), contextName, topN, outputFmt, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "",
		"Kubeconfig context to use (default: current context)")
	cmd.Flags().IntVar(&topN, "top", 10,
		"Maximum number of risk findings to display (0 = all)")
	cmd.Flags().StringVar(&outputFmt, "output", "table",
		"Output format: table or json")

	return cmd
}

// runRiskTop is the testable core of `dp kubernetes risk top`.
// It runs a minimal Kubernetes audit to build the asset graph, then calls
// risk.AnalyzeTopRisks and renders the findings to w.
func runRiskTop(ctx context.Context, contextName string, topN int, outputFmt string, w io.Writer) error {
	eng, err := buildRiskEngine(contextName)
	if err != nil {
		return err
	}

	if _, err := eng.RunAudit(ctx, engine.KubernetesAuditOptions{ContextName: contextName}); err != nil {
		return fmt.Errorf("kubernetes audit failed: %w", err)
	}

	findings := risk.AnalyzeTopRisks(eng.AssetGraph())
	if topN > 0 && len(findings) > topN {
		findings = findings[:topN]
	}

	if outputFmt == "json" {
		return encodeRiskJSON(w, findings)
	}

	if len(findings) == 0 {
		fmt.Fprintln(w, "No attack path risks detected.")
		return nil
	}

	renderRiskTop(w, findings)
	return nil
}

// renderRiskTop prints findings in column-aligned table format.
func renderRiskTop(w io.Writer, findings []risk.RiskFinding) {
	fmt.Fprintln(w, "TOP ATTACK PATH RISKS")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-4s  %-10s  %-6s  %s\n", "#", "SEVERITY", "SCORE", "ATTACK PATH")
	for i, f := range findings {
		fmt.Fprintf(w, "%-4d  %-10s  %-6d  %s\n",
			i+1, f.Severity, f.Score, strings.Join(f.Path, " → "))
	}
}

// newRiskExplainCmd returns the `dp kubernetes risk explain` command.
// It runs the Kubernetes audit pipeline, builds the asset graph, calls
// AnalyzeTopRisks, and prints a structured plain-English explanation of the
// highest-scored finding. No external API calls are made.
func newRiskExplainCmd() *cobra.Command {
	var (
		contextName string
		outputFmt   string
	)

	cmd := &cobra.Command{
		Use:          "explain",
		Short:        "Print a structured security explanation for the top-scored attack path risk",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRiskExplain(cmd.Context(), contextName, outputFmt, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "",
		"Kubeconfig context to use (default: current context)")
	cmd.Flags().StringVar(&outputFmt, "output", "table",
		"Output format: table or json")

	return cmd
}

// runRiskExplain is the testable core of `dp kubernetes risk explain`.
func runRiskExplain(ctx context.Context, contextName string, outputFmt string, w io.Writer) error {
	eng, err := buildRiskEngine(contextName)
	if err != nil {
		return err
	}

	if _, err := eng.RunAudit(ctx, engine.KubernetesAuditOptions{ContextName: contextName}); err != nil {
		return fmt.Errorf("kubernetes audit failed: %w", err)
	}

	findings := risk.AnalyzeTopRisks(eng.AssetGraph())
	if len(findings) == 0 {
		if outputFmt == "json" {
			_, err := fmt.Fprintln(w, `{"error": "No attack path risks detected."}`)
			return err
		}
		fmt.Fprintln(w, "No attack path risks detected.")
		return nil
	}

	if outputFmt == "json" {
		return encodeRiskJSON(w, findings[:1])
	}

	fmt.Fprint(w, risk.ExplainRisk(findings[0]))
	return nil
}

// ── shared helpers ────────────────────────────────────────────────────────────

// buildRiskEngine wires a KubernetesEngineWithEKS for the risk commands.
// It is extracted to avoid duplication between runRiskTop and runRiskExplain.
func buildRiskEngine(contextName string) (*engine.KubernetesEngine, error) {
	provider := kube.NewDefaultKubeClientProvider()

	coreRegistry := rules.NewDefaultRuleRegistry()
	for _, r := range k8scorepack.New() {
		coreRegistry.Register(r)
	}
	eksRegistry := rules.NewDefaultRuleRegistry()
	for _, r := range k8sekpack.New() {
		eksRegistry.Register(r)
	}

	return engine.NewKubernetesEngineWithEKS(
		provider,
		coreRegistry,
		eksRegistry,
		awseks.NewDefaultEKSCollector(),
		nil, // no policy enforcement
	), nil
}

// riskJSON is the JSON-specific projection of a RiskFinding.
// It omits the "title" field (redundant: identical information is in "path")
// to keep the API surface clean for automation consumers.
type riskJSON struct {
	Severity    string   `json:"severity"`
	Score       int      `json:"score"`
	Path        []string `json:"path"`
	Explanation string   `json:"explanation"`
}

// encodeRiskJSON converts findings to riskJSON and writes an indented JSON
// array to w. JSON output contains only the payload — no banners or headers.
func encodeRiskJSON(w io.Writer, findings []risk.RiskFinding) error {
	out := make([]riskJSON, len(findings))
	for i, f := range findings {
		out[i] = riskJSON{
			Severity:    f.Severity,
			Score:       f.Score,
			Path:        f.Path,
			Explanation: f.Explanation,
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
