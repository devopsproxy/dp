// Package traversal provides a reusable graph traversal engine for the
// DevOps-Proxy asset graph.  It is purely algorithmic — it contains no
// business logic, no rule matching, and no scoring.  Higher-level packages
// (internal/engine, internal/graph/blast) call it to discover paths and
// reachable nodes without implementing their own BFS/DFS loops.
//
// Circular-dependency note: this package imports internal/graph.  The parent
// package (internal/graph) does NOT import traversal; blast.go keeps its own
// BFS so the two can coexist without a cycle.
package traversal

import (
	"sort"

	"github.com/devopsproxy/dp/internal/graph"
)

// TraversalOptions configures a TraverseFromNode call.
type TraversalOptions struct {
	// AllowedEdgeTypes restricts which edge types are followed.
	// When empty (nil or zero-length) ALL edge types are followed.
	AllowedEdgeTypes []graph.EdgeType
}

// TraversalResult represents a single complete path discovered during
// traversal, from the start node to a leaf node (a node with no further
// allowed outgoing edges, or all outgoing neighbours already on this path).
type TraversalResult struct {
	// Nodes contains the ordered node IDs from start to leaf (inclusive).
	Nodes []string

	// Edges contains human-readable edge descriptors in the form "fromID→toID",
	// one entry per hop.  len(Edges) == len(Nodes)-1.
	Edges []string
}

// TraverseFromNode performs a depth-first enumeration of all distinct paths
// reachable from startNodeID in g.
//
// Behaviour:
//   - Only edges whose type is in opts.AllowedEdgeTypes are followed; when
//     AllowedEdgeTypes is empty every edge type is eligible.
//   - A node may not appear twice within the same path (cycle protection).
//   - Paths of length zero (start node with no eligible neighbours) are not
//     returned.
//   - The function returns nil when startNodeID does not exist in g.
func TraverseFromNode(g *graph.Graph, startNodeID string, opts TraversalOptions) []TraversalResult {
	if g.GetNode(startNodeID) == nil {
		return nil
	}

	// Build O(1) allowed-edge lookup.
	allowedSet := make(map[graph.EdgeType]bool, len(opts.AllowedEdgeTypes))
	for _, et := range opts.AllowedEdgeTypes {
		allowedSet[et] = true
	}

	var results []TraversalResult

	// DFS closure.  nodes/edges are grown via append-with-cap-trick so each
	// recursive branch gets its own slice without extra allocations.
	var dfs func(current string, nodes []string, edges []string, inPath map[string]bool)
	dfs = func(current string, nodes []string, edges []string, inPath map[string]bool) {
		// Append current to this branch's node list.
		nodes = append(nodes[:len(nodes):len(nodes)], current)

		moved := false
		for _, e := range g.EdgesFrom(current) {
			if len(allowedSet) > 0 && !allowedSet[e.Type] {
				continue
			}
			if inPath[e.To] {
				// Cycle — skip to prevent infinite loops.
				continue
			}
			moved = true
			inPath[e.To] = true
			dfs(e.To,
				nodes,
				append(edges[:len(edges):len(edges)], current+"→"+e.To),
				inPath,
			)
			delete(inPath, e.To) // backtrack
		}

		// If we couldn't move and the path has at least one edge, record it.
		if !moved && len(edges) > 0 {
			nodeCopy := make([]string, len(nodes))
			copy(nodeCopy, nodes)
			edgeCopy := make([]string, len(edges))
			copy(edgeCopy, edges)
			results = append(results, TraversalResult{Nodes: nodeCopy, Edges: edgeCopy})
		}
	}

	inPath := map[string]bool{startNodeID: true}
	dfs(startNodeID, nil, nil, inPath)
	return results
}

// GetNeighbors returns the IDs of all nodes directly reachable from nodeID
// via any outgoing edge.  The order follows the graph's edge insertion order.
func GetNeighbors(g *graph.Graph, nodeID string) []string {
	edges := g.EdgesFrom(nodeID)
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, e.To)
	}
	return out
}

// NodeType returns the string representation of the NodeType for nodeID, or
// an empty string when the node does not exist.
func NodeType(g *graph.Graph, nodeID string) string {
	n := g.GetNode(nodeID)
	if n == nil {
		return ""
	}
	return string(n.Type)
}

// ── Sensitive-resource reachability ──────────────────────────────────────────

// sensitiveEdgeTypes are the edge types that form an identity/access path in
// the asset graph.  This mirrors the traversalEdgeSet in internal/graph/blast.go
// but is defined here so the traversal package does not import blast internals.
var sensitiveEdgeTypes = []graph.EdgeType{
	graph.EdgeTypeRunsAs,
	graph.EdgeTypeRunsOn,
	graph.EdgeTypeAssumesRole,
	graph.EdgeTypeAssumeRole, // Phase 16.1: IAMRole → IAMRole cross-role escalation
	graph.EdgeTypeCanAccess,
}

// FindSensitiveResources enumerates all cloud resource nodes reachable from
// startNodeID via identity/access edges (RUNS_AS, RUNS_ON, ASSUMES_ROLE,
// CAN_ACCESS) whose sensitivity metadata is "high".
//
// This is the traversal-engine equivalent of the BFS performed by
// internal/graph.ComputeBlastRadius; both produce the same set of HIGH
// sensitive resources.  Results are sorted by Name ascending.
func FindSensitiveResources(g *graph.Graph, startNodeID string) []*graph.Node {
	paths := TraverseFromNode(g, startNodeID, TraversalOptions{
		AllowedEdgeTypes: sensitiveEdgeTypes,
	})

	seen := make(map[string]bool)
	var resources []*graph.Node

	for _, path := range paths {
		for _, nid := range path.Nodes {
			if seen[nid] {
				continue
			}
			node := g.GetNode(nid)
			if node == nil {
				continue
			}
			if node.Metadata["sensitivity"] == "high" {
				seen[nid] = true
				resources = append(resources, node)
			}
		}
	}

	sort.Slice(resources, func(i, j int) bool {
		return resources[i].Name < resources[j].Name
	})
	return resources
}
