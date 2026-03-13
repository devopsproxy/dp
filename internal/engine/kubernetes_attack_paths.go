// Package engine — kubernetes_attack_paths.go
//
// Phase 15.1: Graph-based attack path detection using the traversal engine.
// FindGraphAttackPaths discovers attack paths from Internet-exposed entry points
// through to sensitive cloud resources by traversing the asset graph.
//
// This module is independent of the rule-based correlation in
// kubernetes_correlation.go; it operates solely on the asset graph topology
// and cloud resource sensitivity metadata.
package engine

import (
	"sort"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/graph"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/graph/traversal"
)

// GraphAttackPath represents a single attack path discovered through graph
// traversal. Unlike the rule-based AttackPath model, this is derived
// purely from graph topology and sensitivity metadata.
type GraphAttackPath struct {
	// Nodes is the ordered sequence of node IDs from Internet to leaf.
	Nodes []string

	// Edges contains human-readable edge descriptors ("fromID→toID").
	Edges []string

	// Score is the computed risk score (0–100).
	Score int

	// Description is a human-readable summary of the path characteristics.
	Description string
}

// attackPathEdges are the edge types followed during graph-based attack path
// traversal. Structural containment edges (CONTAINS, PART_OF) are excluded;
// all attacker-movement edges are included.
var attackPathEdges = []graph.EdgeType{
	graph.EdgeTypeExposes,
	graph.EdgeTypeRoutesTo,
	graph.EdgeTypeRunsOn,
	graph.EdgeTypeRunsAs,
	graph.EdgeTypeAssumesRole,
	graph.EdgeTypeCanAccess,
}

// cloudResourceTypes is the set of NodeTypes that represent AWS cloud resources.
// Paths ending at these nodes are considered complete attack paths.
var cloudResourceTypes = map[graph.NodeType]struct{}{
	graph.NodeTypeS3Bucket:             {},
	graph.NodeTypeSecretsManagerSecret: {},
	graph.NodeTypeDynamoDBTable:        {},
	graph.NodeTypeKMSKey:               {},
	graph.NodeTypeSSMParameter:         {},
}

// isCloudResource reports whether nt is a cloud resource node type.
func isCloudResource(nt graph.NodeType) bool {
	_, ok := cloudResourceTypes[nt]
	return ok
}

// FindGraphAttackPaths discovers all attack paths from Internet-exposed entry
// points through to cloud resource leaf nodes in the asset graph.
//
// For each Internet node in the graph, the traversal engine enumerates all
// distinct paths using the attacker-movement edge set. Paths that do not
// terminate at a cloud resource node are discarded. Surviving paths are
// scored via ScorePath and returned sorted by score descending (highest
// risk first).
func FindGraphAttackPaths(g *graph.Graph) []GraphAttackPath {
	var results []GraphAttackPath

	// Find all Internet nodes — these are the attacker entry points.
	for _, node := range g.Nodes {
		if node.Type != graph.NodeTypeInternet {
			continue
		}

		paths := traversal.TraverseFromNode(g, node.ID, traversal.TraversalOptions{
			AllowedEdgeTypes: attackPathEdges,
		})

		for _, p := range paths {
			// Only keep paths that reach a cloud resource.
			if len(p.Nodes) == 0 {
				continue
			}
			lastNodeID := p.Nodes[len(p.Nodes)-1]
			lastNode := g.GetNode(lastNodeID)
			if lastNode == nil || !isCloudResource(lastNode.Type) {
				continue
			}

			score := ScorePath(g, p)
			results = append(results, GraphAttackPath{
				Nodes:       p.Nodes,
				Edges:       p.Edges,
				Score:       score,
				Description: describeAttackPath(g, p),
			})
		}
	}

	// Sort by score descending; stable within same score by first node ID.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		if len(results[i].Nodes) > 0 && len(results[j].Nodes) > 0 {
			return results[i].Nodes[0] < results[j].Nodes[0]
		}
		return false
	})

	return results
}

// ScorePath computes a risk score (0–100) for a traversal result based on
// the types of nodes present in the path.
//
// Scoring criteria (additive):
//
//	+40  if the path starts at (or contains) an Internet node
//	+20  if the path passes through a privileged workload (NodeTypeWorkload)
//	+20  if the path passes through an IAM role (NodeTypeIAMRole)
//	+20  if the path ends at a sensitive cloud resource (sensitivity == "high")
func ScorePath(g *graph.Graph, path traversal.TraversalResult) int {
	score := 0

	hasInternet := false
	hasWorkload := false
	hasIAMRole := false
	hasSensitiveResource := false

	for _, nid := range path.Nodes {
		node := g.GetNode(nid)
		if node == nil {
			continue
		}
		switch node.Type {
		case graph.NodeTypeInternet:
			hasInternet = true
		case graph.NodeTypeWorkload:
			hasWorkload = true
		case graph.NodeTypeIAMRole:
			hasIAMRole = true
		default:
			if isCloudResource(node.Type) && node.Metadata["sensitivity"] == "high" {
				hasSensitiveResource = true
			}
		}
	}

	if hasInternet {
		score += 40
	}
	if hasWorkload {
		score += 20
	}
	if hasIAMRole {
		score += 20
	}
	if hasSensitiveResource {
		score += 20
	}

	return score
}

// describeAttackPath produces a one-line human-readable description of a
// traversal path based on the node types it passes through.
func describeAttackPath(g *graph.Graph, path traversal.TraversalResult) string {
	hasInternet := false
	hasWorkload := false
	hasIAMRole := false
	hasNode := false
	hasSensitive := false

	for _, nid := range path.Nodes {
		node := g.GetNode(nid)
		if node == nil {
			continue
		}
		switch node.Type {
		case graph.NodeTypeInternet:
			hasInternet = true
		case graph.NodeTypeWorkload:
			hasWorkload = true
		case graph.NodeTypeIAMRole:
			hasIAMRole = true
		case graph.NodeTypeNode:
			hasNode = true
		}
		if isCloudResource(node.Type) && node.Metadata["sensitivity"] == "high" {
			hasSensitive = true
		}
	}

	switch {
	case hasInternet && hasWorkload && hasNode && hasIAMRole && hasSensitive:
		return "Internet-exposed workload reaches sensitive cloud data via node instance profile."
	case hasInternet && hasWorkload && hasIAMRole && hasSensitive:
		return "Internet-exposed workload reaches sensitive cloud data via IAM role (IRSA)."
	case hasInternet && hasWorkload && hasIAMRole:
		return "Internet-exposed workload has cloud IAM access via role assumption."
	case hasInternet && hasIAMRole && hasSensitive:
		return "Internet-exposed resource can access sensitive cloud data through IAM role."
	case hasIAMRole && hasSensitive:
		return "IAM role grants access to sensitive cloud resource."
	case hasSensitive:
		return "Path reaches sensitive cloud resource."
	default:
		return "Attack path detected through infrastructure graph."
	}
}
