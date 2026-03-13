// Package risk implements a lightweight attack-path risk prioritization engine.
// It operates on the existing asset graph (internal/graph) without modifying
// any rule or correlation logic. The analyzer detects predefined toxic
// combinations and scores them using additive component weights.
package risk

import (
	"sort"

	"github.com/devopsproxy/dp/internal/graph"
)

// Score components. Scores are additive — each component present in a detected
// path contributes its weight to the total.
const (
	scoreInternet      = 40 // Internet exposure detected in the path
	scoreNode          = 30 // Kubernetes Node accessible from the workload
	scoreIAMRole       = 40 // IAM role reachable (via SA/IRSA or node instance-profile)
	scoreCloudResource = 50 // Cloud data resource (S3, Secrets Manager, …) reachable
)

// Severity thresholds.
const (
	thresholdCritical = 100
	thresholdHigh     = 70
	thresholdMedium   = 40
)

// RiskFinding is a single detected high-risk attack path in the asset graph.
type RiskFinding struct {
	Title       string   `json:"title"`
	Path        []string `json:"path"`
	Score       int      `json:"score"`
	Severity    string   `json:"severity"`
	Explanation string   `json:"explanation"`
}

// AnalyzeTopRisks walks g and returns one RiskFinding per detected toxic
// combination, ordered by score descending. Returns nil when g is nil.
//
// Detected patterns:
//
//	P1  Internet → LB → Workload → Node           score 70  HIGH
//	P2  Internet → LB → Workload → IAMRole         score 80  HIGH
//	P3  Internet → LB → Workload → IAMRole → Cloud score 130 CRITICAL
//	P4  Workload → Node → IAMRole                  score 70  HIGH
func AnalyzeTopRisks(g *graph.Graph) []RiskFinding {
	if g == nil {
		return nil
	}

	seen := make(map[string]bool)
	var results []RiskFinding

	// ── Internet-exposed paths (P1, P2, P3) ──────────────────────────────────
	for _, lb := range outNeighbors(g, "Internet", graph.EdgeTypeExposes) {
		for _, workload := range outNeighbors(g, lb.ID, graph.EdgeTypeRoutesTo) {
			if workload.Type != graph.NodeTypeWorkload {
				continue
			}

			nodes := outNeighbors(g, workload.ID, graph.EdgeTypeRunsOn)

			// IAMRoles reachable via ServiceAccount (IRSA).
			var rolesViaSA []*graph.Node
			for _, sa := range outNeighbors(g, workload.ID, graph.EdgeTypeRunsAs) {
				rolesViaSA = append(rolesViaSA, outNeighbors(g, sa.ID, graph.EdgeTypeAssumesRole)...)
			}
			// IAMRoles reachable via Node instance-profile.
			var rolesViaNode []*graph.Node
			for _, node := range nodes {
				rolesViaNode = append(rolesViaNode, outNeighbors(g, node.ID, graph.EdgeTypeAssumesRole)...)
			}
			allRoles := append(rolesViaSA, rolesViaNode...)

			// P1: Internet → LB → Workload → Node
			for _, node := range nodes {
				key := "p1:" + workload.ID + ":" + node.ID
				if seen[key] {
					continue
				}
				seen[key] = true
				score := scoreInternet + scoreNode
				results = append(results, RiskFinding{
					Title:    "Internet → " + workload.Name + " → " + node.Name,
					Path:     []string{"Internet", lb.Name, workload.Name, node.Name},
					Score:    score,
					Severity: severityFromScore(score),
					Explanation: "Internet exposed workload could allow an attacker to " +
						"access the Kubernetes node.",
				})
			}

			// P2 / P3: Internet → LB → Workload → IAMRole [→ CloudResource]
			for _, role := range allRoles {
				cloudResources := outNeighbors(g, role.ID, graph.EdgeTypeCanAccess)
				if len(cloudResources) > 0 {
					// P3: full data-exfiltration path.
					for _, cr := range cloudResources {
						key := "p3:" + workload.ID + ":" + role.ID + ":" + cr.ID
						if seen[key] {
							continue
						}
						seen[key] = true
						score := scoreInternet + scoreIAMRole + scoreCloudResource
						results = append(results, RiskFinding{
							Title: "Internet → " + workload.Name + " → " +
								role.Name + " → " + cr.Name,
							Path: []string{"Internet", lb.Name, workload.Name,
								role.Name, cr.Name},
							Score:    score,
							Severity: severityFromScore(score),
							Explanation: "Public service combined with cloud credentials may " +
								"allow direct access to cloud data.",
						})
					}
				} else {
					// P2: IAM role reachable but no cloud resource yet known.
					key := "p2:" + workload.ID + ":" + role.ID
					if seen[key] {
						continue
					}
					seen[key] = true
					score := scoreInternet + scoreIAMRole
					results = append(results, RiskFinding{
						Title: "Internet → " + workload.Name + " → " + role.Name,
						Path:  []string{"Internet", lb.Name, workload.Name, role.Name},
						Score: score,
						Severity: severityFromScore(score),
						Explanation: "Public workload with cloud credentials may allow cloud " +
							"access if the container is compromised.",
					})
				}
			}
		}
	}

	// ── P4: Workload → Node → IAMRole (not requiring Internet exposure) ───────
	for _, e := range g.Edges {
		if e.Type != graph.EdgeTypeRunsOn {
			continue
		}
		workload := g.GetNode(e.From)
		node := g.GetNode(e.To)
		if workload == nil || node == nil {
			continue
		}
		if workload.Type != graph.NodeTypeWorkload || node.Type != graph.NodeTypeNode {
			continue
		}
		for _, role := range outNeighbors(g, node.ID, graph.EdgeTypeAssumesRole) {
			key := "p4:" + workload.ID + ":" + node.ID + ":" + role.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			score := scoreNode + scoreIAMRole
			results = append(results, RiskFinding{
				Title: workload.Name + " → " + node.Name + " → " + role.Name,
				Path:  []string{workload.Name, node.Name, role.Name},
				Score: score,
				Severity: severityFromScore(score),
				Explanation: "Compromised workload could inherit node IAM permissions " +
					"via instance profile.",
			})
		}
	}

	// Sort by score descending; ties broken by title for determinism.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].Title < results[j].Title
	})

	return results
}

// severityFromScore maps a numeric score to a severity string.
func severityFromScore(score int) string {
	switch {
	case score >= thresholdCritical:
		return "CRITICAL"
	case score >= thresholdHigh:
		return "HIGH"
	case score >= thresholdMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// outNeighbors returns all destination nodes reachable from nodeID via edges
// of the given type. Returns nil when no such edges exist.
func outNeighbors(g *graph.Graph, nodeID string, edgeType graph.EdgeType) []*graph.Node {
	var result []*graph.Node
	for _, e := range g.Edges {
		if e.From != nodeID || e.Type != edgeType {
			continue
		}
		if n := g.GetNode(e.To); n != nil {
			result = append(result, n)
		}
	}
	return result
}
