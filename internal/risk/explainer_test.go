package risk

import (
	"strings"
	"testing"
)

// TestExplainRisk_InternetWorkloadNode verifies the P1 explanation
// (Internet → LB → Workload → Node, score 70, hasInternet=true).
func TestExplainRisk_InternetWorkloadNode(t *testing.T) {
	r := RiskFinding{
		Title:    "Internet → api → worker-1",
		Path:     []string{"Internet", "web-lb", "api", "worker-1"},
		Score:    scoreInternet + scoreNode, // 70
		Severity: "HIGH",
	}
	out := ExplainRisk(r)

	mustContain(t, out, "AI SECURITY EXPLANATION")
	mustContain(t, out, "Severity: HIGH")
	mustContain(t, out, "Score: 70")
	mustContain(t, out, "Attack Path")
	mustContain(t, out, "Internet → web-lb → api → worker-1")
	mustContain(t, out, "What This Means")
	mustContain(t, out, `"api"`)
	mustContain(t, out, `"worker-1"`)
	mustContain(t, out, "Why This Is Dangerous")
	mustContain(t, out, "Recommended Actions")
	mustContain(t, out, "NetworkPolicy")
}

// TestExplainRisk_InternetWorkloadIAMRole verifies the P2 explanation
// (Internet → LB → Workload → IAMRole, score 80, hasInternet=true).
func TestExplainRisk_InternetWorkloadIAMRole(t *testing.T) {
	r := RiskFinding{
		Title:    "Internet → svc → app-role",
		Path:     []string{"Internet", "svc-lb", "svc", "app-role"},
		Score:    scoreInternet + scoreIAMRole, // 80
		Severity: "HIGH",
	}
	out := ExplainRisk(r)

	mustContain(t, out, "AI SECURITY EXPLANATION")
	mustContain(t, out, "Severity: HIGH")
	mustContain(t, out, "Score: 80")
	mustContain(t, out, "Internet → svc-lb → svc → app-role")
	mustContain(t, out, "What This Means")
	mustContain(t, out, `"svc"`)
	mustContain(t, out, `"app-role"`)
	mustContain(t, out, "Why This Is Dangerous")
	mustContain(t, out, "Recommended Actions")
	mustContain(t, out, "IRSA")
}

// TestExplainRisk_CloudResource verifies the P3 explanation
// (Internet → LB → Workload → IAMRole → CloudResource, score 130, CRITICAL).
func TestExplainRisk_CloudResource(t *testing.T) {
	r := RiskFinding{
		Title:    "Internet → api → role → data-bucket",
		Path:     []string{"Internet", "api-lb", "api", "app-role", "data-bucket"},
		Score:    scoreInternet + scoreIAMRole + scoreCloudResource, // 130
		Severity: "CRITICAL",
	}
	out := ExplainRisk(r)

	mustContain(t, out, "AI SECURITY EXPLANATION")
	mustContain(t, out, "Severity: CRITICAL")
	mustContain(t, out, "Score: 130")
	mustContain(t, out, "Internet → api-lb → api → app-role → data-bucket")
	mustContain(t, out, "What This Means")
	mustContain(t, out, `"api"`)
	mustContain(t, out, `"app-role"`)
	mustContain(t, out, `"data-bucket"`)
	mustContain(t, out, "Why This Is Dangerous")
	mustContain(t, out, "data-exfiltration")
	mustContain(t, out, "Recommended Actions")
	mustContain(t, out, "server-side access logging")
}

// TestExplainRisk_WorkloadNodeIAMRole verifies the P4 explanation
// (Workload → Node → IAMRole, score 70, hasInternet=false).
func TestExplainRisk_WorkloadNodeIAMRole(t *testing.T) {
	r := RiskFinding{
		Title:    "batch → worker-2 → node-role",
		Path:     []string{"batch", "worker-2", "node-role"},
		Score:    scoreNode + scoreIAMRole, // 70
		Severity: "HIGH",
	}
	out := ExplainRisk(r)

	mustContain(t, out, "AI SECURITY EXPLANATION")
	mustContain(t, out, "Severity: HIGH")
	mustContain(t, out, "Score: 70")
	mustContain(t, out, "batch → worker-2 → node-role")
	mustContain(t, out, "What This Means")
	mustContain(t, out, `"batch"`)
	mustContain(t, out, `"worker-2"`)
	mustContain(t, out, `"node-role"`)
	mustContain(t, out, "Why This Is Dangerous")
	mustContain(t, out, "Recommended Actions")
	mustContain(t, out, "IRSA")
	mustContain(t, out, "IMDSv2")
}

// mustContain is a test helper that fails if substr is not found in s.
func mustContain(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("output missing %q\nfull output:\n%s", substr, s)
	}
}
