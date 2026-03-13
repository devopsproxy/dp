package risk

import (
	"fmt"
	"strings"
)

// ExplainRisk converts a RiskFinding into a structured, plain-English security
// explanation with four sections: Attack Path, What This Means, Why This Is
// Dangerous, and Recommended Actions.
//
// The explanation is generated deterministically from the finding's Path and
// Score — no external AI service is called.
func ExplainRisk(r RiskFinding) string {
	var b strings.Builder

	hasInternet := len(r.Path) > 0 && r.Path[0] == "Internet"

	// Determine which pattern fired based on score + internet presence.
	// Scores are additive:
	//   P3: internet(40) + iam(40) + cloud(50) = 130
	//   P2: internet(40) + iam(40)             =  80
	//   P1: internet(40) + node(30)            =  70  (hasInternet)
	//   P4: node(30)     + iam(40)             =  70  (!hasInternet)
	switch {
	case r.Score >= thresholdCritical:
		writeExplanationP3(&b, r, hasInternet)
	case r.Score == scoreInternet+scoreIAMRole && hasInternet:
		writeExplanationP2(&b, r)
	case r.Score == scoreInternet+scoreNode && hasInternet:
		writeExplanationP1(&b, r)
	default:
		// P4: Workload → Node → IAMRole (no Internet)
		writeExplanationP4(&b, r)
	}

	return b.String()
}

// ── Pattern writers ──────────────────────────────────────────────────────────

// writeExplanationP1 generates the explanation for:
// Internet → LB → Workload → Node  (score 70)
func writeExplanationP1(b *strings.Builder, r RiskFinding) {
	workload := safeIndex(r.Path, 2)
	node := safeIndex(r.Path, 3)

	writeHeader(b, r)

	fmt.Fprintf(b, "What This Means\n")
	fmt.Fprintf(b, "The workload %q is exposed to the internet through a LoadBalancer.\n", workload)
	fmt.Fprintf(b, "If the application is compromised, an attacker could gain access to the\n")
	fmt.Fprintf(b, "Kubernetes node %q where the pod runs.\n", node)
	b.WriteString("\n")

	fmt.Fprintf(b, "Why This Is Dangerous\n")
	fmt.Fprintf(b, "Internet exposure combined with node access significantly increases the blast\n")
	fmt.Fprintf(b, "radius of a compromise. An attacker who controls the node can affect every\n")
	fmt.Fprintf(b, "workload running on it, not just the originally compromised pod.\n")
	b.WriteString("\n")

	writeRecommendations(b,
		"Restrict the service from public internet exposure or add authentication",
		"Apply Kubernetes NetworkPolicy to limit pod-to-pod and pod-to-node traffic",
		"Run containers with a non-root user and a read-only root filesystem",
		"Use a PodDisruptionBudget and node isolation to limit blast radius",
	)
}

// writeExplanationP2 generates the explanation for:
// Internet → LB → Workload → IAMRole  (score 80)
func writeExplanationP2(b *strings.Builder, r RiskFinding) {
	workload := safeIndex(r.Path, 2)
	role := safeIndex(r.Path, 3)

	writeHeader(b, r)

	fmt.Fprintf(b, "What This Means\n")
	fmt.Fprintf(b, "The workload %q is exposed to the internet through a LoadBalancer.\n", workload)
	fmt.Fprintf(b, "The workload also has access to the AWS IAM role %q, either via IRSA\n", role)
	fmt.Fprintf(b, "(eks.amazonaws.com/role-arn annotation) or through the node instance-profile.\n")
	fmt.Fprintf(b, "If the container is compromised, the attacker inherits those cloud permissions.\n")
	b.WriteString("\n")

	fmt.Fprintf(b, "Why This Is Dangerous\n")
	fmt.Fprintf(b, "Public workloads with cloud credentials are a common initial-access vector.\n")
	fmt.Fprintf(b, "Even without cloud resource access today, the role may be expanded later or\n")
	fmt.Fprintf(b, "allow privilege escalation through sts:AssumeRole chaining.\n")
	b.WriteString("\n")

	writeRecommendations(b,
		"Restrict the service from public internet exposure or add authentication",
		"Use IRSA instead of node IAM roles to scope credentials per workload",
		"Apply least-privilege to the IAM role — remove unused actions and resources",
		"Enable AWS CloudTrail to detect unusual IAM API calls from this workload",
	)
}

// writeExplanationP3 generates the explanation for:
// Internet → LB → Workload → IAMRole → CloudResource  (score 130)
func writeExplanationP3(b *strings.Builder, r RiskFinding, hasInternet bool) {
	var workload, role, cloud string
	if hasInternet {
		workload = safeIndex(r.Path, 2)
		role = safeIndex(r.Path, 3)
		cloud = safeIndex(r.Path, 4)
	} else {
		// Defensive: unexpected topology — use what is available.
		workload = safeIndex(r.Path, 0)
		role = safeIndex(r.Path, 1)
		cloud = safeIndex(r.Path, 2)
	}

	writeHeader(b, r)

	fmt.Fprintf(b, "What This Means\n")
	fmt.Fprintf(b, "The workload %q is exposed to the internet through a LoadBalancer.\n", workload)
	fmt.Fprintf(b, "It can reach the AWS IAM role %q, which in turn grants access to the\n", role)
	fmt.Fprintf(b, "cloud resource %q.\n", cloud)
	fmt.Fprintf(b, "This creates a direct path from the public internet to sensitive cloud data.\n")
	b.WriteString("\n")

	fmt.Fprintf(b, "Why This Is Dangerous\n")
	fmt.Fprintf(b, "This is a complete data-exfiltration path. An attacker who exploits a\n")
	fmt.Fprintf(b, "vulnerability in %q can immediately read or write %q without any\n", workload, cloud)
	fmt.Fprintf(b, "additional lateral movement. This satisfies the attacker's primary goal in a\n")
	fmt.Fprintf(b, "single compromise step.\n")
	b.WriteString("\n")

	writeRecommendations(b,
		"Restrict the service from public internet exposure or add authentication",
		"Use IRSA to scope IAM credentials to individual workloads, not the whole node",
		fmt.Sprintf("Apply least-privilege to %q — restrict to the minimum required actions", role),
		fmt.Sprintf("Enable server-side access logging on %q to detect exfiltration", cloud),
		"Run containers with a non-root user and drop all Linux capabilities",
	)
}

// writeExplanationP4 generates the explanation for:
// Workload → Node → IAMRole  (score 70, no Internet)
func writeExplanationP4(b *strings.Builder, r RiskFinding) {
	workload := safeIndex(r.Path, 0)
	node := safeIndex(r.Path, 1)
	role := safeIndex(r.Path, 2)

	writeHeader(b, r)

	fmt.Fprintf(b, "What This Means\n")
	fmt.Fprintf(b, "The workload %q runs on node %q, which has the AWS IAM role %q attached\n", workload, node, role)
	fmt.Fprintf(b, "via its EC2 instance-profile. Because the role is applied at the node level,\n")
	fmt.Fprintf(b, "every pod on that node inherits the same cloud permissions — regardless of\n")
	fmt.Fprintf(b, "whether those pods are supposed to access cloud resources.\n")
	b.WriteString("\n")

	fmt.Fprintf(b, "Why This Is Dangerous\n")
	fmt.Fprintf(b, "Node-level IAM roles violate the principle of least privilege at the workload\n")
	fmt.Fprintf(b, "level. A compromised pod in any namespace on this node could exfiltrate data\n")
	fmt.Fprintf(b, "or perform cloud operations using the node role, making container escape the\n")
	fmt.Fprintf(b, "only step needed for cloud access.\n")
	b.WriteString("\n")

	writeRecommendations(b,
		"Migrate workloads from node IAM roles to IRSA (IAM Roles for Service Accounts)",
		fmt.Sprintf("Scope the permissions of %q to the minimum required by any workload on the node", role),
		"Block access to the EC2 instance metadata service (IMDSv2 with hop limit = 1)",
		"Use node taints and tolerations to isolate sensitive workloads onto dedicated nodes",
	)
}

// ── Shared helpers ───────────────────────────────────────────────────────────

// writeHeader writes the banner and Attack Path section.
func writeHeader(b *strings.Builder, r RiskFinding) {
	b.WriteString("AI SECURITY EXPLANATION\n")
	b.WriteString("\n")
	fmt.Fprintf(b, "Severity: %s  Score: %d\n", r.Severity, r.Score)
	b.WriteString("\n")
	b.WriteString("Attack Path\n")
	fmt.Fprintf(b, "%s\n", strings.Join(r.Path, " → "))
	b.WriteString("\n")
}

// writeRecommendations writes the "Recommended Actions" section.
func writeRecommendations(b *strings.Builder, actions ...string) {
	b.WriteString("Recommended Actions\n")
	for _, a := range actions {
		fmt.Fprintf(b, "• %s\n", a)
	}
}

// safeIndex returns r.Path[i] or "<unknown>" when i is out of range.
func safeIndex(path []string, i int) string {
	if i < len(path) {
		return path[i]
	}
	return "<unknown>"
}
