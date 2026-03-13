package graph

import (
	"strings"
	"unicode"

	"github.com/devopsproxy/dp/internal/models"
)

// BuildAssetGraph converts collected Kubernetes cluster inventory into an Asset
// Graph that encodes real infrastructure relationships. It does not consult
// rule findings or heuristics — every edge reflects an actual API-level
// relationship in the cluster.
//
// Node ID format (consistent with internal/render/graph.go):
//   - Internet:        "Internet"
//   - LoadBalancer:    sanitize("LoadBalancer_" + svc.Name)
//   - Workload:        sanitize(pod.WorkloadKind + "_" + pod.WorkloadName)
//   - ServiceAccount:  sanitize("ServiceAccount_" + sa.Name)
//   - IAMRole:         sanitize("IAMRole_" + roleName)
//   - Namespace:       sanitize("Namespace_" + ns.Name)
//
// Edges built:
//
//	Internet     → LoadBalancer   (EXPOSES)   — for every LB-type Service
//	LoadBalancer → Workload       (ROUTES_TO) — selector ∩ pod labels match
//	Workload     → ServiceAccount (RUNS_AS)   — pod.ServiceAccountName
//	ServiceAccount → IAMRole      (ASSUMES_ROLE) — eks.amazonaws.com/role-arn
//	Namespace    → Workload       (CONTAINS)
//	Namespace    → ServiceAccount (CONTAINS)
func BuildAssetGraph(cluster *models.KubernetesClusterData) (*Graph, error) {
	g := NewGraph()

	// ── Internet ─────────────────────────────────────────────────────────────
	g.AddNode(&Node{ID: "Internet", Type: NodeTypeInternet, Name: "Internet"})

	// ── Namespace nodes ───────────────────────────────────────────────────────
	for i := range cluster.Namespaces {
		ns := &cluster.Namespaces[i]
		nsID := sanitizeID("Namespace_" + ns.Name)
		g.AddNode(&Node{
			ID:   nsID,
			Type: NodeTypeNamespace,
			Name: ns.Name,
		})
	}

	// ── Kubernetes Node nodes (Phase 14) ──────────────────────────────────────
	// One graph node per Kubernetes worker node. ProviderID is stored in
	// Metadata so callers can later resolve the EC2 instance ID.
	for i := range cluster.Nodes {
		n := &cluster.Nodes[i]
		if n.Name == "" {
			continue
		}
		nodeID := sanitizeID("Node_" + n.Name)
		g.AddNode(&Node{
			ID:   nodeID,
			Type: NodeTypeNode,
			Name: n.Name,
			Metadata: map[string]string{
				"provider_id": n.ProviderID,
			},
		})
	}

	// ── ServiceAccount index: "namespace/name" → *KubernetesServiceAccountData
	saIndex := make(map[string]*models.KubernetesServiceAccountData, len(cluster.ServiceAccounts))
	for i := range cluster.ServiceAccounts {
		sa := &cluster.ServiceAccounts[i]
		saIndex[sa.Namespace+"/"+sa.Name] = sa
	}

	// ── Workload and ServiceAccount nodes (from pod records) ─────────────────
	// Each unique workload_kind+workload_name pair produces one Workload node.
	// Pod SA bindings produce ServiceAccount nodes and RUNS_AS edges.
	workloadSeen := make(map[string]bool)
	saSeen := make(map[string]bool)

	for i := range cluster.Pods {
		pod := &cluster.Pods[i]
		if pod.WorkloadKind == "" || pod.WorkloadName == "" {
			continue
		}
		wID := sanitizeID(pod.WorkloadKind + "_" + pod.WorkloadName)

		// Add Workload node (once per unique workload).
		if !workloadSeen[wID] {
			workloadSeen[wID] = true
			g.AddNode(&Node{
				ID:   wID,
				Type: NodeTypeWorkload,
				Name: pod.WorkloadName,
				Metadata: map[string]string{
					"kind":      pod.WorkloadKind,
					"namespace": pod.Namespace,
				},
			})
			// Namespace CONTAINS Workload.
			nsID := sanitizeID("Namespace_" + pod.Namespace)
			g.AddEdge(nsID, wID, EdgeTypeContains)
		}

		// Workload RUNS_ON Node (Phase 14 — instance-profile path).
		// Multiple pods of the same workload may run on different nodes;
		// AddEdge deduplicates identical (from, to, type) triples.
		if pod.NodeName != "" {
			nodeID := sanitizeID("Node_" + pod.NodeName)
			g.AddEdge(wID, nodeID, EdgeTypeRunsOn)
		}

		// ServiceAccount binding: Workload → ServiceAccount.
		if pod.ServiceAccountName == "" {
			continue
		}
		sa := saIndex[pod.Namespace+"/"+pod.ServiceAccountName]
		if sa == nil {
			continue
		}
		saID := sanitizeID("ServiceAccount_" + sa.Name)

		// Add ServiceAccount node (once per unique SA name).
		if !saSeen[saID] {
			saSeen[saID] = true
			g.AddNode(&Node{
				ID:   saID,
				Type: NodeTypeServiceAccount,
				Name: sa.Name,
				Metadata: map[string]string{
					"namespace": sa.Namespace,
				},
			})
			// Namespace CONTAINS ServiceAccount.
			nsID := sanitizeID("Namespace_" + sa.Namespace)
			g.AddEdge(nsID, saID, EdgeTypeContains)

			// ServiceAccount ASSUMES_ROLE IAMRole (Phase 11 IRSA bridge).
			if sa.IAMRoleArn != "" {
				roleName := extractRoleName(sa.IAMRoleArn)
				roleID := sanitizeID("IAMRole_" + roleName)
				g.AddNode(&Node{
					ID:   roleID,
					Type: NodeTypeIAMRole,
					Name: roleName,
					Metadata: map[string]string{
						"arn": sa.IAMRoleArn,
					},
				})
				g.AddEdge(saID, roleID, EdgeTypeAssumesRole)
			}
		}

		// Workload RUNS_AS ServiceAccount.
		g.AddEdge(wID, saID, EdgeTypeRunsAs)
	}

	// ── LoadBalancer Service nodes ────────────────────────────────────────────
	for i := range cluster.Services {
		svc := &cluster.Services[i]
		if svc.Type != "LoadBalancer" {
			continue
		}
		svcID := sanitizeID("LoadBalancer_" + svc.Name)
		g.AddNode(&Node{
			ID:   svcID,
			Type: NodeTypeLoadBalancer,
			Name: svc.Name,
			Metadata: map[string]string{
				"namespace": svc.Namespace,
			},
		})

		// Internet EXPOSES LoadBalancer.
		g.AddEdge("Internet", svcID, EdgeTypeExposes)

		// LoadBalancer ROUTES_TO Workload (selector matching).
		if len(svc.Selector) == 0 {
			continue
		}
		for j := range cluster.Pods {
			pod := &cluster.Pods[j]
			if pod.Namespace != svc.Namespace {
				continue
			}
			if pod.WorkloadKind == "" || pod.WorkloadName == "" {
				continue
			}
			if selectorMatches(svc.Selector, pod.Labels) {
				wID := sanitizeID(pod.WorkloadKind + "_" + pod.WorkloadName)
				g.AddEdge(svcID, wID, EdgeTypeRoutesTo)
			}
		}
	}

	return g, nil
}

// ── Cloud reachability enrichment ─────────────────────────────────────────────

// EnrichWithCloudAccess extends an existing Graph by adding cloud resource nodes
// (S3Bucket, SecretsManagerSecret, DynamoDBTable, KMSKey) and CAN_ACCESS edges
// from IAMRole nodes to those resources.
//
// roleAccess maps IAM role ARNs (e.g. "arn:aws:iam::123:role/app-role") to the
// set of AWS resources that role can access, as resolved by
// internal/providers/aws/iam.ResolveRoleResourceAccess.
//
// If the IAMRole node for a given ARN does not exist in g, that entry is silently
// skipped — enrichment never creates dangling edges.
// Duplicate cloud resource nodes and edges are deduplicated by the graph itself.
func EnrichWithCloudAccess(g *Graph, roleAccess map[string][]models.RoleCloudAccess) {
	for roleArn, accesses := range roleAccess {
		roleID := sanitizeID("IAMRole_" + extractRoleName(roleArn))
		if g.GetNode(roleID) == nil {
			continue
		}

		for _, access := range accesses {
			if access.ResourceName == "" {
				continue
			}
			nodeID := sanitizeID(string(access.ResourceType) + "_" + access.ResourceName)
			nt := cloudResourceNodeType(access.ResourceType)

			// Add cloud resource node (first-write-wins if already present).
			// Phase 15: stamp sensitivity metadata when a classification is set.
			meta := map[string]string{
				"arn": access.ARN,
			}
			if access.Sensitivity != "" {
				meta["sensitivity"] = string(access.Sensitivity)
			}
			g.AddNode(&Node{
				ID:       nodeID,
				Type:     nt,
				Name:     access.ResourceName,
				Metadata: meta,
			})

			g.AddEdge(roleID, nodeID, EdgeTypeCanAccess)
		}
	}
}

// ── Node IAM role enrichment (Phase 14) ──────────────────────────────────────

// EnrichWithNodeRoles extends an existing Graph by adding IAMRole nodes for
// AWS instance profile roles and ASSUMES_ROLE edges from the corresponding
// Node nodes to those IAMRole nodes.
//
// nodeRoles maps Kubernetes node names (e.g. "ip-10-0-1-1.ec2.internal") to
// the IAM role ARN attached to the node's EC2 instance profile
// (e.g. "arn:aws:iam::123456789012:role/eks-node-role").
//
// If the Node graph node for a given Kubernetes node name does not exist in g,
// that entry is silently skipped — enrichment never creates dangling edges.
// Duplicate IAMRole nodes and edges are deduplicated by the graph itself.
func EnrichWithNodeRoles(g *Graph, nodeRoles map[string]string) {
	for nodeName, roleARN := range nodeRoles {
		if roleARN == "" {
			continue
		}
		nodeID := sanitizeID("Node_" + nodeName)
		if g.GetNode(nodeID) == nil {
			continue
		}

		roleName := extractRoleName(roleARN)
		roleID := sanitizeID("IAMRole_" + roleName)

		// Add IAMRole node (first-write-wins when already present via IRSA).
		g.AddNode(&Node{
			ID:   roleID,
			Type: NodeTypeIAMRole,
			Name: roleName,
			Metadata: map[string]string{
				"arn": roleARN,
			},
		})

		g.AddEdge(nodeID, roleID, EdgeTypeAssumesRole)
	}
}

// cloudResourceNodeType maps a models.CloudResourceType to its graph NodeType.
func cloudResourceNodeType(rt models.CloudResourceType) NodeType {
	switch rt {
	case models.CloudResourceTypeS3Bucket:
		return NodeTypeS3Bucket
	case models.CloudResourceTypeSecretsManagerSecret:
		return NodeTypeSecretsManagerSecret
	case models.CloudResourceTypeDynamoDBTable:
		return NodeTypeDynamoDBTable
	case models.CloudResourceTypeKMSKey:
		return NodeTypeKMSKey
	case models.CloudResourceTypeSSMParameter:
		return NodeTypeSSMParameter
	default:
		return NodeType(rt) // passthrough for forward compatibility
	}
}

// selectorMatches reports whether all key-value pairs in selector are present
// in podLabels. An empty selector returns false.
func selectorMatches(selector, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

// extractRoleName returns the role name component from an IAM role ARN.
// For "arn:aws:iam::123456789012:role/app-role" it returns "app-role".
// Falls back to the full string when no slash is present.
func extractRoleName(arn string) string {
	if idx := strings.LastIndex(arn, "/"); idx >= 0 {
		return arn[idx+1:]
	}
	return arn
}

// sanitizeID replaces characters that are not alphanumeric or underscore with
// an underscore to produce valid Mermaid / Graphviz node identifiers.
// This function mirrors the sanitizeNodeID logic in internal/render/graph.go
// so that builder-produced node IDs are consistent with render-produced IDs.
func sanitizeID(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
