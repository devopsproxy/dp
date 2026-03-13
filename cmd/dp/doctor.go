package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/devopsproxy/dp/internal/policy"
	"github.com/devopsproxy/dp/internal/providers/aws/common"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	costpack "github.com/devopsproxy/dp/internal/rulepacks/aws_cost"
	dppack "github.com/devopsproxy/dp/internal/rulepacks/aws_dataprotection"
	secpack "github.com/devopsproxy/dp/internal/rulepacks/aws_security"
	k8spack "github.com/devopsproxy/dp/internal/rulepacks/kubernetes"
)

// DoctorResult is the structured output of dp doctor. It can be serialised to
// JSON via --format=json or rendered as a human-readable table (default).
type DoctorResult struct {
	AWS struct {
		Profile     string `json:"profile,omitempty"`
		Credentials bool   `json:"credentials_ok"`
		AccountID   string `json:"account_id,omitempty"`
		RegionsOK   bool   `json:"regions_ok"`
		Error       string `json:"error,omitempty"`
	} `json:"aws"`

	Kubernetes struct {
		KubeconfigOK bool   `json:"kubeconfig_ok"`
		Context      string `json:"context,omitempty"`
		APIReachable bool   `json:"api_reachable"`
		Error        string `json:"error,omitempty"`
	} `json:"kubernetes"`

	Policy struct {
		Present bool     `json:"present"`
		Valid   bool     `json:"valid"`
		Errors  []string `json:"errors,omitempty"`
	} `json:"policy"`

	OverallHealthy bool `json:"overall_healthy"`
}

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "doctor",
		Short:         "Run environment diagnostics",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, _ := cmd.Flags().GetString("format")
			profile, _ := cmd.Flags().GetString("profile")
			result, err := runDoctor(
				context.Background(),
				common.NewDefaultAWSClientProvider(),
				kube.NewDefaultKubeClientProvider(),
				cmd.OutOrStdout(),
				format,
				profile,
			)
			if err != nil {
				// Rendering failure — let Cobra/main handle it.
				return err
			}
			if !result.OverallHealthy {
				// Exit directly so no error text reaches main.go's
				// fmt.Fprintln(os.Stderr, err) path.
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().String("format", "table", `Output format: "table" or "json"`)
	cmd.Flags().String("profile", "", "AWS profile to use (default: credential chain)")
	return cmd
}

// runDoctor collects all diagnostic results, renders them to w in the
// requested format, and returns the result.
// The returned error covers only rendering failures (e.g. JSON encode error).
// Callers must inspect result.OverallHealthy to determine whether the
// environment is healthy; runDoctor itself never returns an error for an
// unhealthy result so that no error text leaks to callers (such as main).
func runDoctor(ctx context.Context, awsProvider common.AWSClientProvider, kubeProvider kube.KubeClientProvider, w io.Writer, format, profile string) (DoctorResult, error) {
	result := collectDoctorResult(ctx, awsProvider, kubeProvider, profile)

	switch format {
	case "json":
		if err := json.NewEncoder(w).Encode(result); err != nil {
			return result, fmt.Errorf("encode doctor result: %w", err)
		}
	default:
		renderDoctorTable(result, w)
	}

	return result, nil
}

// collectDoctorResult runs all environment checks and populates a DoctorResult.
// It performs no rendering; callers decide how to present the result.
func collectDoctorResult(ctx context.Context, awsProvider common.AWSClientProvider, kubeProvider kube.KubeClientProvider, profile string) DoctorResult {
	var result DoctorResult

	// AWS: credentials → STS account ID → region discovery.
	// An empty profile string selects the default credential chain.
	if profile != "" {
		result.AWS.Profile = profile
	}
	profileCfg, err := awsProvider.LoadProfile(ctx, profile)
	if err != nil {
		result.AWS.Error = err.Error()
	} else {
		result.AWS.Credentials = true
		result.AWS.AccountID = profileCfg.AccountID
		_, err = awsProvider.GetActiveRegions(ctx, profileCfg)
		if err != nil {
			result.AWS.Error = err.Error()
		} else {
			result.AWS.RegionsOK = true
		}
	}

	// Kubernetes: kubeconfig load → context → API reachability probe.
	clientset, info, err := kubeProvider.ClientsetForContext("")
	if err != nil {
		result.Kubernetes.Error = err.Error()
	} else {
		result.Kubernetes.KubeconfigOK = true
		result.Kubernetes.Context = info.ContextName
		_, err = clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			result.Kubernetes.Error = err.Error()
		} else {
			result.Kubernetes.APIReachable = true
		}
	}

	// Policy: stat → load → validate (file is optional).
	_, statErr := os.Stat("./dp.yaml")
	if statErr == nil {
		result.Policy.Present = true
		cfg, loadErr := policy.LoadPolicy("./dp.yaml")
		if loadErr != nil {
			result.Policy.Errors = []string{loadErr.Error()}
		} else {
			errs := policy.Validate(cfg, doctorAllRuleIDs())
			if len(errs) == 0 {
				result.Policy.Valid = true
			} else {
				for _, e := range errs {
					result.Policy.Errors = append(result.Policy.Errors, e.Error())
				}
			}
		}
	} else if !os.IsNotExist(statErr) {
		// Stat error other than "not found" — treat as present but unreadable.
		result.Policy.Present = true
		result.Policy.Errors = []string{statErr.Error()}
	}

	result.OverallHealthy = result.AWS.Credentials &&
		result.AWS.RegionsOK &&
		result.Kubernetes.KubeconfigOK &&
		result.Kubernetes.APIReachable &&
		(!result.Policy.Present || result.Policy.Valid)

	return result
}

// renderDoctorTable writes the human-readable diagnostic output from result to w.
func renderDoctorTable(result DoctorResult, w io.Writer) {
	fmt.Fprintln(w, "Environment Diagnostics")

	if result.AWS.Profile != "" {
		fmt.Fprintf(w, "\nAWS (profile: %s):\n", result.AWS.Profile)
	} else {
		fmt.Fprintln(w, "\nAWS:")
	}
	if !result.AWS.Credentials {
		doctorPrint(w, "Credentials", "FAIL", result.AWS.Error)
		doctorPrint(w, "STS Identity", "FAIL", "skipped")
		doctorPrint(w, "Regions API", "FAIL", "skipped")
	} else {
		doctorPrint(w, "Credentials", "OK", "")
		doctorPrint(w, "STS Identity", "OK", "Account: "+result.AWS.AccountID)
		if result.AWS.RegionsOK {
			doctorPrint(w, "Regions API", "OK", "")
		} else {
			doctorPrint(w, "Regions API", "FAIL", result.AWS.Error)
		}
	}

	fmt.Fprintln(w, "\nKubernetes:")
	if !result.Kubernetes.KubeconfigOK {
		doctorPrint(w, "Kubeconfig", "FAIL", result.Kubernetes.Error)
		doctorPrint(w, "Current Context", "FAIL", "skipped")
		doctorPrint(w, "API Reachable", "FAIL", "skipped")
	} else {
		doctorPrint(w, "Kubeconfig", "OK", "")
		doctorPrint(w, "Current Context", "OK", result.Kubernetes.Context)
		if result.Kubernetes.APIReachable {
			doctorPrint(w, "API Reachable", "OK", "")
		} else {
			doctorPrint(w, "API Reachable", "FAIL", result.Kubernetes.Error)
		}
	}

	fmt.Fprintln(w, "\nPolicy:")
	if !result.Policy.Present {
		doctorPrint(w, "dp.yaml present", "Not found (optional)", "")
	} else {
		doctorPrint(w, "dp.yaml present", "YES", "")
		if result.Policy.Valid {
			doctorPrint(w, "Policy valid", "OK", "")
		} else {
			for _, e := range result.Policy.Errors {
				doctorPrint(w, "Policy valid", "FAIL", e)
			}
		}
	}
}

// doctorAllRuleIDs returns the union of all known rule IDs from every rule pack.
func doctorAllRuleIDs() []string {
	var ids []string
	for _, r := range costpack.New() {
		ids = append(ids, r.ID())
	}
	for _, r := range secpack.New() {
		ids = append(ids, r.ID())
	}
	for _, r := range dppack.New() {
		ids = append(ids, r.ID())
	}
	for _, r := range k8spack.New() {
		ids = append(ids, r.ID())
	}
	return ids
}

// doctorPrint writes a single diagnostic check line to w.
// When detail is non-empty it is appended in parentheses.
func doctorPrint(w io.Writer, label, status, detail string) {
	if detail != "" {
		fmt.Fprintf(w, "  %s: %s (%s)\n", label, status, detail)
	} else {
		fmt.Fprintf(w, "  %s: %s\n", label, status)
	}
}
