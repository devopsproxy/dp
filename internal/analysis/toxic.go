// Package analysis implements high-level security analysis over the asset graph.
// It operates purely on the graph topology — it contains no rule logic and
// makes no AWS API calls.
package analysis

import (
	"sort"
	"strings"

	"github.com/devopsproxy/dp/internal/graph"
	"github.com/devopsproxy/dp/internal/graph/traversal"
	"github.com/devopsproxy/dp/internal/models"
)

// toxicEdgeTypes are the edge types followed when enumerating paths for toxic
// combination detection. They mirror attackPathEdges in the engine package and
// include AMPLIFIES so Misconfiguration nodes are traversed.
var toxicEdgeTypes = []graph.EdgeType{
	graph.EdgeTypeExposes,
	graph.EdgeTypeRoutesTo,
	graph.EdgeTypeRunsOn,
	graph.EdgeTypeRunsAs,
	graph.EdgeTypeAssumesRole,
	graph.EdgeTypeAssumeRole,
	graph.EdgeTypeCanAccess,
	graph.EdgeTypeAmplifies,
}

// toxicPattern defines a high-risk topology that, when present in the asset
// graph, constitutes a toxic combination.
type toxicPattern struct {
	severity  string
	reason    string
	sequence  []graph.NodeType // ordered type subsequence to match
	startType graph.NodeType   // node type to begin traversal from
}

// toxicPatterns lists the three predefined toxic combinations.
//
//   - Pattern 1 (CRITICAL): Internet → LoadBalancer → Workload → Node → IAMRole → S3Bucket
//     An Internet-exposed workload reaches an S3 bucket via the node's
//     instance-profile role rather than IRSA — every pod on that node inherits
//     the same cloud permissions, making lateral movement trivial.
//
//   - Pattern 2 (CRITICAL): Internet → LoadBalancer → Workload → Node → IAMRole → SecretsManager
//     Same topology as Pattern 1 but the target is a Secrets Manager secret,
//     potentially containing database passwords, API keys, or TLS certificates.
//
//   - Pattern 3 (HIGH): Workload → ServiceAccount → IAMRole → SecretsManager
//     A workload with IRSA access can read Secrets Manager directly. Severity
//     is HIGH rather than CRITICAL because the path does not require Internet
//     exposure — a compromised internal pod suffices.
var toxicPatterns = []toxicPattern{
	{
		severity: "CRITICAL",
		reason: "Internet-exposed workload reaches S3 bucket via node instance-profile role " +
			"(no IRSA isolation — all pods on the node share the same cloud permissions).",
		sequence: []graph.NodeType{
			graph.NodeTypeInternet,
			graph.NodeTypeLoadBalancer,
			graph.NodeTypeWorkload,
			graph.NodeTypeNode,
			graph.NodeTypeIAMRole,
			graph.NodeTypeS3Bucket,
		},
		startType: graph.NodeTypeInternet,
	},
	{
		severity: "CRITICAL",
		reason: "Internet-exposed workload reaches Secrets Manager via node instance-profile role " +
			"(no IRSA isolation — all pods on the node share the same cloud permissions).",
		sequence: []graph.NodeType{
			graph.NodeTypeInternet,
			graph.NodeTypeLoadBalancer,
			graph.NodeTypeWorkload,
			graph.NodeTypeNode,
			graph.NodeTypeIAMRole,
			graph.NodeTypeSecretsManagerSecret,
		},
		startType: graph.NodeTypeInternet,
	},
	{
		severity: "HIGH",
		reason: "Workload with IRSA-bound service account can read Secrets Manager directly " +
			"(compromised pod has immediate access to stored secrets).",
		sequence: []graph.NodeType{
			graph.NodeTypeWorkload,
			graph.NodeTypeServiceAccount,
			graph.NodeTypeIAMRole,
			graph.NodeTypeSecretsManagerSecret,
		},
		startType: graph.NodeTypeWorkload,
	},
}

// DetectToxicCombinations scans g for predefined high-risk topology patterns
// and returns one ToxicRisk entry per matched chain.
//
// Each pattern is tested by:
//  1. Enumerating all nodes of the pattern's start type.
//  2. Traversing all reachable paths from each start node using toxicEdgeTypes.
//  3. Checking whether the path's node type sequence contains the pattern's
//     type sequence as an ordered subsequence (gaps allowed for intermediate hops).
//  4. Collecting the matching node names as the Path field.
//
// Results are deduplicated (same matched node sequence + same pattern = one entry)
// and ordered CRITICAL first, then HIGH; within each severity, ordered by path
// string representation for deterministic output.
//
// Returns nil when g is nil or no patterns match.
func DetectToxicCombinations(g *graph.Graph) []models.ToxicRisk {
	if g == nil {
		return nil
	}

	seen := make(map[string]bool) // deduplication key: "severity\x00reason\x00path"
	var results []models.ToxicRisk

	opts := traversal.TraversalOptions{AllowedEdgeTypes: toxicEdgeTypes}

	for _, pat := range toxicPatterns {
		// Enumerate all nodes of the pattern's start type.
		for _, startNode := range nodesOfType(g, pat.startType) {
			paths := traversal.TraverseFromNode(g, startNode.ID, opts)
			for _, p := range paths {
				matched, ok := matchPattern(g, p.Nodes, pat.sequence)
				if !ok {
					continue
				}
				// Build human-readable path from matched node names.
				names := nodeNames(g, matched)
				dedup := pat.severity + "\x00" + pat.reason + "\x00" + strings.Join(matched, "|")
				if seen[dedup] {
					continue
				}
				seen[dedup] = true
				results = append(results, models.ToxicRisk{
					Severity: pat.severity,
					Reason:   pat.reason,
					Path:     names,
				})
			}
		}
	}

	// Sort: CRITICAL before HIGH; within severity, alphabetical by path join.
	sort.SliceStable(results, func(i, j int) bool {
		ri, rj := severityOrder(results[i].Severity), severityOrder(results[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return strings.Join(results[i].Path, "→") < strings.Join(results[j].Path, "→")
	})

	return results
}

// matchPattern checks whether the node type sequence of nodeSeq (node IDs)
// contains pat as an ordered subsequence. When the pattern matches, it returns
// the node IDs that matched each step of the pattern.
func matchPattern(g *graph.Graph, nodeSeq []string, pat []graph.NodeType) ([]string, bool) {
	matched := make([]string, 0, len(pat))
	pi := 0
	for _, nid := range nodeSeq {
		if pi >= len(pat) {
			break
		}
		node := g.GetNode(nid)
		if node == nil {
			continue
		}
		if node.Type == pat[pi] {
			matched = append(matched, nid)
			pi++
		}
	}
	return matched, pi == len(pat)
}

// nodeNames converts a slice of node IDs to their human-readable Names,
// falling back to the ID when the node is not found or has an empty Name.
func nodeNames(g *graph.Graph, nodeIDs []string) []string {
	names := make([]string, 0, len(nodeIDs))
	for _, nid := range nodeIDs {
		node := g.GetNode(nid)
		if node == nil || node.Name == "" {
			names = append(names, nid)
		} else {
			names = append(names, node.Name)
		}
	}
	return names
}

// nodesOfType returns all graph nodes whose Type equals nt.
func nodesOfType(g *graph.Graph, nt graph.NodeType) []*graph.Node {
	var out []*graph.Node
	for _, n := range g.Nodes {
		if n.Type == nt {
			out = append(out, n)
		}
	}
	return out
}

// severityOrder returns a sort key for severity strings (lower = higher priority).
func severityOrder(sev string) int {
	switch sev {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	default:
		return 2
	}
}
