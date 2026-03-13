package graph

import (
	"fmt"
	"sort"
	"strings"
)

// cloudResourceSet is the set of NodeTypes that represent AWS cloud resources.
// BFS traversal collects these nodes and does not traverse further through them
// (they are always leaf nodes in the current model).
var cloudResourceSet = map[NodeType]struct{}{
	NodeTypeS3Bucket:             {},
	NodeTypeSecretsManagerSecret: {},
	NodeTypeDynamoDBTable:        {},
	NodeTypeKMSKey:               {},
}

// traversalEdgeSet is the set of EdgeTypes followed during blast-radius BFS.
// Only identity/access edges are crossed; structural edges (EXPOSES, ROUTES_TO,
// CONTAINS) are intentionally excluded so traversal stays on the attack path.
//
// Phase 14 adds RUNS_ON so the instance-profile path
// (Workload → Node → IAMRole → Cloud Resource) is included in blast radius.
var traversalEdgeSet = map[EdgeType]struct{}{
	EdgeTypeRunsAs:      {},
	EdgeTypeRunsOn:      {},
	EdgeTypeAssumesRole: {},
	EdgeTypeCanAccess:   {},
}

// BlastResult holds the outcome of a blast-radius computation: the set of
// IAM identity nodes and cloud resource nodes reachable from a starting workload
// or service account node via RUNS_AS → ASSUMES_ROLE → CAN_ACCESS traversal.
type BlastResult struct {
	// StartNodeID is the graph node ID used as the traversal origin.
	StartNodeID string

	// StartNode is the Node corresponding to StartNodeID; never nil when
	// ComputeBlastRadius returns a non-error result.
	StartNode *Node

	// Identities contains all IAMRole nodes reachable from the start node.
	// Sorted by Name ascending for deterministic output.
	Identities []*Node

	// Resources maps each cloud resource NodeType to the nodes of that type
	// reachable from the start node. Only types with at least one reachable
	// node are present as keys. Slices are sorted by Name ascending.
	Resources map[NodeType][]*Node
}

// ComputeBlastRadius performs a BFS from startNodeID over RUNS_AS,
// ASSUMES_ROLE, and CAN_ACCESS edges.
//
// It collects:
//   - IAMRole nodes into BlastResult.Identities
//   - S3Bucket / SecretsManagerSecret / DynamoDBTable / KMSKey nodes into
//     BlastResult.Resources, keyed by NodeType
//
// Cloud resource nodes are treated as leaf nodes: once collected they are
// not enqueued for further traversal.
//
// Returns an error when startNodeID does not exist in g.
// Returns a non-nil BlastResult (with empty Identities/Resources) when the
// start node exists but no relevant nodes are reachable.
func ComputeBlastRadius(g *Graph, startNodeID string) (*BlastResult, error) {
	startNode := g.GetNode(startNodeID)
	if startNode == nil {
		return nil, fmt.Errorf("node %q not found in graph", startNodeID)
	}

	result := &BlastResult{
		StartNodeID: startNodeID,
		StartNode:   startNode,
		Resources:   make(map[NodeType][]*Node),
	}

	visited := make(map[string]bool)
	queue := []string{startNodeID}
	visited[startNodeID] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, edge := range g.EdgesFrom(current) {
			if _, allowed := traversalEdgeSet[edge.Type]; !allowed {
				continue
			}
			if visited[edge.To] {
				continue
			}
			visited[edge.To] = true

			node := g.GetNode(edge.To)
			if node == nil {
				continue
			}

			if _, isCloud := cloudResourceSet[node.Type]; isCloud {
				// Cloud resource — collect and do not traverse further.
				result.Resources[node.Type] = append(result.Resources[node.Type], node)
				continue
			}

			if node.Type == NodeTypeIAMRole {
				result.Identities = append(result.Identities, node)
			}

			// Continue BFS through non-cloud nodes (Workload, ServiceAccount,
			// IAMRole) so CAN_ACCESS edges on IAMRole nodes are followed.
			queue = append(queue, edge.To)
		}
	}

	// Sort for deterministic output.
	sort.Slice(result.Identities, func(i, j int) bool {
		return result.Identities[i].Name < result.Identities[j].Name
	})
	for nt, nodes := range result.Resources {
		sort.Slice(nodes, func(i, j int) bool {
			return nodes[i].Name < nodes[j].Name
		})
		result.Resources[nt] = nodes
	}

	return result, nil
}

// ResolveStartNode converts a user-facing resource reference of the form
// "kind/name" into a graph node ID using the same sanitizeID conventions as
// BuildAssetGraph.
//
// Supported kinds (case-insensitive):
//
//	deployment, statefulset, daemonset, job, cronjob, serviceaccount
//
// Returns (nodeID, true) on success, or ("", false) when the kind prefix is
// not recognised or the name is empty.
func ResolveStartNode(input string) (nodeID string, ok bool) {
	idx := strings.Index(input, "/")
	if idx < 0 || idx == len(input)-1 {
		return "", false
	}
	kind := strings.ToLower(input[:idx])
	name := input[idx+1:]

	var prefix string
	switch kind {
	case "deployment":
		prefix = "Deployment"
	case "statefulset":
		prefix = "StatefulSet"
	case "daemonset":
		prefix = "DaemonSet"
	case "job":
		prefix = "Job"
	case "cronjob":
		prefix = "CronJob"
	case "serviceaccount":
		prefix = "ServiceAccount"
	default:
		return "", false
	}
	return sanitizeID(prefix + "_" + name), true
}
