package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/devopsproxy/dp/internal/providers/aws/common"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
)

// ── AWS mock ──────────────────────────────────────────────────────────────────

type mockAWSProvider struct {
	profileResult *common.ProfileConfig
	profileErr    error
	regionsResult []string
	regionsErr    error
	lastProfile   string // records the profile name passed to LoadProfile
}

func (m *mockAWSProvider) LoadProfile(_ context.Context, profile string) (*common.ProfileConfig, error) {
	m.lastProfile = profile
	return m.profileResult, m.profileErr
}

func (m *mockAWSProvider) LoadAllProfiles(_ context.Context) ([]*common.ProfileConfig, error) {
	if m.profileResult != nil {
		return []*common.ProfileConfig{m.profileResult}, nil
	}
	return nil, m.profileErr
}

func (m *mockAWSProvider) GetActiveRegions(_ context.Context, _ *common.ProfileConfig) ([]string, error) {
	return m.regionsResult, m.regionsErr
}

func (m *mockAWSProvider) ConfigForRegion(_ *common.ProfileConfig, _ string) aws.Config {
	return aws.Config{}
}

// ── Kubernetes error mock ─────────────────────────────────────────────────────

type failKubeProvider struct{}

func (p *failKubeProvider) ClientsetForContext(_ string) (k8sclient.Interface, kube.ClusterInfo, error) {
	return nil, kube.ClusterInfo{}, errors.New("kubeconfig not found")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func goodMockAWS() *mockAWSProvider {
	return &mockAWSProvider{
		profileResult: &common.ProfileConfig{
			AccountID: "123456789012",
			Region:    "us-east-1",
		},
		regionsResult: []string{"us-east-1", "eu-west-1"},
	}
}

func goodMockKube() *testKubeProvider {
	return &testKubeProvider{
		clientset: fake.NewSimpleClientset(),
		info:      kube.ClusterInfo{ContextName: "prod-eks"},
	}
}

// runDoctorInTmp changes to a fresh temp directory (no dp.yaml), runs
// runDoctor with the given format and profile, restores the working directory,
// and returns the captured output, the DoctorResult, and any rendering error.
func runDoctorInTmp(t *testing.T, awsP common.AWSClientProvider, kubeP kube.KubeClientProvider, format, profile string) (string, DoctorResult, error) {
	t.Helper()
	tmp := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck

	var buf bytes.Buffer
	result, runErr := runDoctor(context.Background(), awsP, kubeP, &buf, format, profile)
	return buf.String(), result, runErr
}

// ── table format tests ────────────────────────────────────────────────────────

func TestDoctorAllOK(t *testing.T) {
	out, result, err := runDoctorInTmp(t, goodMockAWS(), goodMockKube(), "table", "")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if !result.OverallHealthy {
		t.Error("expected OverallHealthy=true")
	}
	for _, want := range []string{
		"Credentials: OK",
		"STS Identity: OK",
		"Regions API: OK",
		"Kubeconfig: OK",
		"Current Context: OK",
		"API Reachable: OK",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q;\ngot:\n%s", want, out)
		}
	}
}

func TestDoctorAWSCredentialsFail(t *testing.T) {
	awsP := &mockAWSProvider{profileErr: errors.New("no credentials configured")}
	out, result, err := runDoctorInTmp(t, awsP, goodMockKube(), "table", "")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if result.OverallHealthy {
		t.Error("expected OverallHealthy=false")
	}
	if !strings.Contains(out, "Credentials: FAIL") {
		t.Errorf("expected 'Credentials: FAIL'; got:\n%s", out)
	}
}

func TestDoctorAWSRegionsFail(t *testing.T) {
	awsP := &mockAWSProvider{
		profileResult: &common.ProfileConfig{AccountID: "111111111111", Region: "us-east-1"},
		regionsErr:    errors.New("EC2 API error"),
	}
	out, result, err := runDoctorInTmp(t, awsP, goodMockKube(), "table", "")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if result.OverallHealthy {
		t.Error("expected OverallHealthy=false")
	}
	if !strings.Contains(out, "Credentials: OK") {
		t.Errorf("expected 'Credentials: OK'; got:\n%s", out)
	}
	if !strings.Contains(out, "Regions API: FAIL") {
		t.Errorf("expected 'Regions API: FAIL'; got:\n%s", out)
	}
}

func TestDoctorKubernetesFail(t *testing.T) {
	out, result, err := runDoctorInTmp(t, goodMockAWS(), &failKubeProvider{}, "table", "")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if result.OverallHealthy {
		t.Error("expected OverallHealthy=false")
	}
	if !strings.Contains(out, "Kubeconfig: FAIL") {
		t.Errorf("expected 'Kubeconfig: FAIL'; got:\n%s", out)
	}
}

func TestDoctorPolicyMissing(t *testing.T) {
	out, result, err := runDoctorInTmp(t, goodMockAWS(), goodMockKube(), "table", "")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if !result.OverallHealthy {
		t.Error("expected OverallHealthy=true (missing policy is not a failure)")
	}
	if !strings.Contains(out, "Not found (optional)") {
		t.Errorf("expected 'Not found (optional)'; got:\n%s", out)
	}
}

func TestDoctorPolicyValid(t *testing.T) {
	tmp := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck

	if err := os.WriteFile(filepath.Join(tmp, "dp.yaml"), []byte("version: 1\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	result, err := runDoctor(context.Background(), goodMockAWS(), goodMockKube(), &buf, "table", "")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if !result.OverallHealthy {
		t.Error("expected OverallHealthy=true")
	}
	out := buf.String()
	if !strings.Contains(out, "dp.yaml present: YES") {
		t.Errorf("expected 'dp.yaml present: YES'; got:\n%s", out)
	}
	if !strings.Contains(out, "Policy valid: OK") {
		t.Errorf("expected 'Policy valid: OK'; got:\n%s", out)
	}
}

func TestDoctorPolicyInvalid(t *testing.T) {
	tmp := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck

	// version: 99 causes LoadPolicy to return "unsupported policy version"
	if err := os.WriteFile(filepath.Join(tmp, "dp.yaml"), []byte("version: 99\n"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	result, err := runDoctor(context.Background(), goodMockAWS(), goodMockKube(), &buf, "table", "")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if result.OverallHealthy {
		t.Error("expected OverallHealthy=false for invalid policy")
	}
	out := buf.String()
	if !strings.Contains(out, "Policy valid: FAIL") {
		t.Errorf("expected 'Policy valid: FAIL'; got:\n%s", out)
	}
}

// ── JSON format tests ─────────────────────────────────────────────────────────

func TestDoctorJSON_AllOK(t *testing.T) {
	out, result, err := runDoctorInTmp(t, goodMockAWS(), goodMockKube(), "json", "")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if !result.OverallHealthy {
		t.Error("expected OverallHealthy=true")
	}

	var parsed DoctorResult
	if jsonErr := json.Unmarshal([]byte(out), &parsed); jsonErr != nil {
		t.Fatalf("invalid JSON output: %v\nraw:\n%s", jsonErr, out)
	}

	if !parsed.AWS.Credentials {
		t.Error("expected AWS.Credentials=true")
	}
	if parsed.AWS.AccountID != "123456789012" {
		t.Errorf("expected AccountID=123456789012; got %q", parsed.AWS.AccountID)
	}
	if !parsed.AWS.RegionsOK {
		t.Error("expected AWS.RegionsOK=true")
	}
	if !parsed.Kubernetes.KubeconfigOK {
		t.Error("expected Kubernetes.KubeconfigOK=true")
	}
	if parsed.Kubernetes.Context != "prod-eks" {
		t.Errorf("expected Context=prod-eks; got %q", parsed.Kubernetes.Context)
	}
	if !parsed.Kubernetes.APIReachable {
		t.Error("expected Kubernetes.APIReachable=true")
	}
	if !parsed.OverallHealthy {
		t.Error("expected OverallHealthy=true")
	}
}

// TestDoctorJSON_Failure verifies that when the environment is unhealthy:
//   - runDoctor returns (result, nil) — NOT an error — so callers never pass
//     the error to Cobra or main, which would print it as plain text
//   - the output is valid JSON with overall_healthy=false
//   - the output contains NO trailing text beyond the JSON blob
//   - no "Error:" or "Usage:" cobra noise appears
func TestDoctorJSON_Failure(t *testing.T) {
	awsP := &mockAWSProvider{profileErr: errors.New("no credentials configured")}
	out, result, err := runDoctorInTmp(t, awsP, goodMockKube(), "json", "")

	// runDoctor must NOT return an error for an unhealthy result.
	// If it did, main.go would print it: fmt.Fprintln(os.Stderr, err).
	if err != nil {
		t.Fatalf("runDoctor must not return error for unhealthy result; got: %v", err)
	}
	if result.OverallHealthy {
		t.Error("expected OverallHealthy=false")
	}

	// Output must be valid JSON.
	var parsed DoctorResult
	if jsonErr := json.Unmarshal([]byte(out), &parsed); jsonErr != nil {
		t.Fatalf("invalid JSON output: %v\nraw:\n%s", jsonErr, out)
	}
	if parsed.AWS.Credentials {
		t.Error("expected AWS.Credentials=false")
	}
	if parsed.AWS.Error == "" {
		t.Error("expected AWS.Error to be non-empty")
	}
	if parsed.OverallHealthy {
		t.Error("expected OverallHealthy=false")
	}

	// Output must be ONLY the JSON blob — no trailing text.
	// json.NewEncoder appends exactly one newline; nothing else must follow.
	want, _ := json.Marshal(result)
	if strings.TrimSpace(out) != string(want) {
		t.Errorf("JSON output has unexpected trailing content;\ngot:  %q\nwant: %q",
			strings.TrimSpace(out), string(want))
	}

	// No Cobra noise must appear in the output buffer.
	for _, noisy := range []string{"Error:", "Usage:"} {
		if strings.Contains(out, noisy) {
			t.Errorf("cobra noise %q must not appear in JSON output; got:\n%s", noisy, out)
		}
	}
}

// TestDoctorCmd_CobraCleanOutput verifies that newDoctorCmd sets SilenceErrors
// and SilenceUsage so Cobra does not append "Error: ..." or the usage block to
// output when RunE returns an error. This is the mechanism that keeps
// --format=json output clean for CI consumers.
func TestDoctorCmd_CobraCleanOutput(t *testing.T) {
	cmd := newDoctorCmd()
	if !cmd.SilenceErrors {
		t.Error("doctor command must have SilenceErrors=true; " +
			"otherwise cobra prints 'Error: ...' after JSON output on failure")
	}
	if !cmd.SilenceUsage {
		t.Error("doctor command must have SilenceUsage=true; " +
			"otherwise cobra prints the usage block after JSON output on failure")
	}
}

// ── profile flag tests ────────────────────────────────────────────────────────

// TestDoctorProfile_Success verifies that --profile is forwarded to the AWS
// provider and that the resolved profile name appears in both the result struct
// and the table output.
func TestDoctorProfile_Success(t *testing.T) {
	awsP := &mockAWSProvider{
		profileResult: &common.ProfileConfig{AccountID: "999999999999", Region: "eu-west-1"},
		regionsResult: []string{"eu-west-1"},
	}
	out, result, err := runDoctorInTmp(t, awsP, goodMockKube(), "table", "prod")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if !result.OverallHealthy {
		t.Error("expected OverallHealthy=true")
	}
	if result.AWS.Profile != "prod" {
		t.Errorf("expected AWS.Profile=prod; got %q", result.AWS.Profile)
	}
	// The mock must have received the correct profile name.
	if awsP.lastProfile != "prod" {
		t.Errorf("LoadProfile called with %q; want prod", awsP.lastProfile)
	}
	// Table output must mention the profile.
	if !strings.Contains(out, "prod") {
		t.Errorf("expected profile 'prod' in output; got:\n%s", out)
	}
}

// TestDoctorProfile_Failure verifies that when credentials fail for a named
// profile, the profile name is still recorded in the result and the table shows
// the credential failure.
func TestDoctorProfile_Failure(t *testing.T) {
	awsP := &mockAWSProvider{profileErr: errors.New("profile not found: prod")}
	out, result, err := runDoctorInTmp(t, awsP, goodMockKube(), "table", "prod")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if result.OverallHealthy {
		t.Error("expected OverallHealthy=false")
	}
	if result.AWS.Profile != "prod" {
		t.Errorf("expected AWS.Profile=prod; got %q", result.AWS.Profile)
	}
	if awsP.lastProfile != "prod" {
		t.Errorf("LoadProfile called with %q; want prod", awsP.lastProfile)
	}
	if !strings.Contains(out, "Credentials: FAIL") {
		t.Errorf("expected 'Credentials: FAIL'; got:\n%s", out)
	}
}

// TestDoctorProfile_JSON verifies that when --profile is set the profile name
// appears in the JSON output under aws.profile.
func TestDoctorProfile_JSON(t *testing.T) {
	awsP := &mockAWSProvider{
		profileResult: &common.ProfileConfig{AccountID: "555555555555", Region: "ap-southeast-1"},
		regionsResult: []string{"ap-southeast-1"},
	}
	out, result, err := runDoctorInTmp(t, awsP, goodMockKube(), "json", "staging")
	if err != nil {
		t.Fatalf("unexpected render error: %v", err)
	}
	if result.AWS.Profile != "staging" {
		t.Errorf("expected AWS.Profile=staging; got %q", result.AWS.Profile)
	}

	var parsed DoctorResult
	if jsonErr := json.Unmarshal([]byte(out), &parsed); jsonErr != nil {
		t.Fatalf("invalid JSON: %v\nraw:\n%s", jsonErr, out)
	}
	if parsed.AWS.Profile != "staging" {
		t.Errorf("JSON aws.profile: expected staging; got %q", parsed.AWS.Profile)
	}
	if parsed.AWS.AccountID != "555555555555" {
		t.Errorf("JSON aws.account_id: expected 555555555555; got %q", parsed.AWS.AccountID)
	}
}
