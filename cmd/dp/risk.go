package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/devopsproxy/dp/internal/engine"
	awseks "github.com/devopsproxy/dp/internal/providers/aws/eks"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	"github.com/devopsproxy/dp/internal/risk"
	k8scorepack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_core"
	k8sekpack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes_eks"
	"github.com/devopsproxy/dp/internal/rules"
)

// newRiskCmd returns the `dp risk` command group.
func newRiskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk",
		Short: "Risk prioritization commands",
	}
	cmd.AddCommand(newRiskTopCmd())
	cmd.AddCommand(newRiskExplainCmd())
	return cmd
}

// newRiskTopCmd returns the `dp risk top` command.
// It runs the Kubernetes audit pipeline, builds the asset graph, and prints
// the top-scored risk findings detected by the risk prioritization engine.
func newRiskTopCmd() *cobra.Command {
	var (
		contextName string
		topN        int
	)

	cmd := &cobra.Command{
		Use:          "top",
		Short:        "Show top attack path risks detected in the Kubernetes asset graph",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRiskTop(cmd.Context(), contextName, topN, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "",
		"Kubeconfig context to use (default: current context)")
	cmd.Flags().IntVar(&topN, "top", 10,
		"Maximum number of risk findings to display (0 = all)")

	return cmd
}

// runRiskTop is the testable core of `dp risk top`.
// It runs a minimal Kubernetes audit to build the asset graph, then calls
// risk.AnalyzeTopRisks and renders the findings to w.
func runRiskTop(ctx context.Context, contextName string, topN int, w io.Writer) error {
	// Wire the Kubernetes engine (same as dp kubernetes audit, minimal options).
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
		nil, // no policy enforcement
	)

	opts := engine.KubernetesAuditOptions{
		ContextName: contextName,
	}

	// RunAudit builds the asset graph as a side-effect (stored in engine context).
	if _, err := eng.RunAudit(ctx, opts); err != nil {
		return fmt.Errorf("kubernetes audit failed: %w", err)
	}

	g := eng.AssetGraph()
	findings := risk.AnalyzeTopRisks(g)
	if len(findings) == 0 {
		fmt.Fprintln(w, "No attack path risks detected.")
		return nil
	}

	// Apply top-N limit.
	if topN > 0 && len(findings) > topN {
		findings = findings[:topN]
	}

	renderRiskTop(w, findings)
	return nil
}

// renderRiskTop prints findings in the spec output format.
func renderRiskTop(w io.Writer, findings []risk.RiskFinding) {
	fmt.Fprintln(w, "TOP ATTACK PATH RISKS")
	fmt.Fprintln(w)
	for i, f := range findings {
		fmt.Fprintf(w, "%d. %s\n", i+1, f.Title)
		fmt.Fprintf(w, "   Score: %d\n", f.Score)
		fmt.Fprintf(w, "   Severity: %s\n", f.Severity)
		fmt.Fprintf(w, "   Explanation:\n   %s\n", f.Explanation)
		fmt.Fprintln(w)
	}
}

// newRiskExplainCmd returns the `dp kubernetes risk explain` command.
// It runs the Kubernetes audit pipeline, builds the asset graph, calls
// AnalyzeTopRisks, and prints a structured plain-English explanation of the
// highest-scored finding. No external API calls are made.
func newRiskExplainCmd() *cobra.Command {
	var contextName string

	cmd := &cobra.Command{
		Use:          "explain",
		Short:        "Print a structured security explanation for the top-scored attack path risk",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRiskExplain(cmd.Context(), contextName, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "",
		"Kubeconfig context to use (default: current context)")

	return cmd
}

// runRiskExplain is the testable core of `dp kubernetes risk explain`.
func runRiskExplain(ctx context.Context, contextName string, w io.Writer) error {
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
		nil,
	)

	opts := engine.KubernetesAuditOptions{
		ContextName: contextName,
	}

	if _, err := eng.RunAudit(ctx, opts); err != nil {
		return fmt.Errorf("kubernetes audit failed: %w", err)
	}

	g := eng.AssetGraph()
	findings := risk.AnalyzeTopRisks(g)
	if len(findings) == 0 {
		fmt.Fprintln(w, "No attack path risks detected.")
		return nil
	}

	fmt.Fprint(w, risk.ExplainRisk(findings[0]))
	return nil
}
