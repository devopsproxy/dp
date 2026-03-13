package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/devopsproxy/dp/internal/graph"
	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/policy"
	"github.com/devopsproxy/dp/internal/providers/aws/sensitivity"
	kube "github.com/devopsproxy/dp/internal/providers/kubernetes"
	"github.com/devopsproxy/dp/internal/rules"
)

// EngineContext holds ancillary data produced during a single RunAudit call.
// It is stored on the engine so callers can access it after RunAudit returns
// without changing the RunAudit return signature.
type EngineContext struct {
	// AssetGraph is the infrastructure relationship graph built from the
	// collected cluster inventory. It encodes Service→Workload routing,
	// Workload→ServiceAccount bindings, and ServiceAccount→IAMRole IRSA links.
	// Nil when no audit has been run yet or when graph construction failed.
	AssetGraph *graph.Graph
}

// EKSDataCollector collects EKS-specific cluster configuration from the AWS EKS API.
// The interface is defined here (engine layer) so the engine remains independent
// of any AWS provider implementation; callers inject the concrete collector.
// Nil means EKS data collection is disabled and EKS-specific rules are skipped.
type EKSDataCollector interface {
	CollectEKSData(ctx context.Context, clusterName, region string) (*models.KubernetesEKSData, error)
}

// IAMAccessResolver resolves the AWS cloud resources reachable by an IAM role.
// The interface is defined here (engine layer) for dependency inversion —
// the engine never imports the AWS IAM provider package directly.
// Nil disables cloud reachability enrichment on the asset graph.
type IAMAccessResolver interface {
	ResolveRoleResourceAccess(ctx context.Context, roleArn string) ([]models.RoleCloudAccess, error)
}

// NodeIAMRoleResolver resolves the AWS IAM instance-profile role for a
// Kubernetes worker node given its cloud ProviderID
// (e.g. "aws:///us-east-1a/i-0123456789abcdef0").
//
// The interface is defined here (engine layer) for dependency inversion —
// the engine never imports the AWS EC2 provider package directly.
// Nil disables instance-profile enrichment on the asset graph.
type NodeIAMRoleResolver interface {
	ResolveNodeIAMRole(ctx context.Context, providerID string) (string, error)
}

// KubernetesEngine orchestrates a Kubernetes governance audit.
// It supports provider-aware rule evaluation: core rules always run;
// EKS-specific rules run only when the cluster is detected as EKS.
type KubernetesEngine struct {
	provider         kube.KubeClientProvider
	coreRegistry     rules.RuleRegistry  // always evaluated
	eksRegistry      rules.RuleRegistry  // evaluated only for EKS clusters; may be nil
	eksCollector     EKSDataCollector    // optional; nil disables EKS data collection
	iamResolver      IAMAccessResolver   // optional; nil disables cloud reachability enrichment
	nodeRoleResolver NodeIAMRoleResolver // optional; nil disables instance-profile enrichment
	policy           *policy.PolicyConfig

	// lastCtx holds ancillary data from the most recent RunAudit call.
	// Callers access it via AssetGraph() after RunAudit returns.
	lastCtx EngineContext
}

// AssetGraph returns the infrastructure relationship graph built during the
// most recent RunAudit call. Returns nil when no audit has completed yet or
// when graph construction failed non-fatally.
func (e *KubernetesEngine) AssetGraph() *graph.Graph {
	return e.lastCtx.AssetGraph
}

// WithIAMResolver injects an optional IAM access resolver into the engine.
// When set, RunAudit will call ResolveRoleResourceAccess for each IAMRole node
// in the asset graph and enrich the graph with CAN_ACCESS edges to cloud resources.
// Returns the engine to allow fluent chaining.
func (e *KubernetesEngine) WithIAMResolver(resolver IAMAccessResolver) *KubernetesEngine {
	e.iamResolver = resolver
	return e
}

// WithNodeRoleResolver injects an optional node IAM role resolver into the engine.
// When set, RunAudit will resolve the EC2 instance-profile role for each cluster
// node and enrich the asset graph with Node → IAMRole (ASSUMES_ROLE) edges,
// enabling blast-radius traversal via the Workload → Node → IAMRole path.
// Returns the engine to allow fluent chaining.
func (e *KubernetesEngine) WithNodeRoleResolver(resolver NodeIAMRoleResolver) *KubernetesEngine {
	e.nodeRoleResolver = resolver
	return e
}

// NewKubernetesEngine constructs a KubernetesEngine with core rules only.
// EKS-specific rule evaluation and data collection are disabled.
// Use NewKubernetesEngineWithEKS to enable provider-aware governance.
func NewKubernetesEngine(
	provider kube.KubeClientProvider,
	registry rules.RuleRegistry,
	policyCfg *policy.PolicyConfig,
) *KubernetesEngine {
	return &KubernetesEngine{
		provider:     provider,
		coreRegistry: registry,
		policy:       policyCfg,
	}
}

// NewKubernetesEngineWithEKS constructs a KubernetesEngine with provider-aware
// governance. When the cluster is detected as EKS:
//   - eksCollector fetches control-plane configuration (endpoint, logging, OIDC)
//   - eksRegistry rules are evaluated in addition to coreRegistry rules
//
// eksRegistry and eksCollector may be nil (each is independently optional).
func NewKubernetesEngineWithEKS(
	provider kube.KubeClientProvider,
	coreRegistry rules.RuleRegistry,
	eksRegistry rules.RuleRegistry,
	eksCollector EKSDataCollector,
	policyCfg *policy.PolicyConfig,
) *KubernetesEngine {
	return &KubernetesEngine{
		provider:     provider,
		coreRegistry: coreRegistry,
		eksRegistry:  eksRegistry,
		eksCollector: eksCollector,
		policy:       policyCfg,
	}
}

// KubernetesAuditOptions carries the parameters for a single cluster audit.
type KubernetesAuditOptions struct {
	// ContextName is the kubeconfig context to connect to.
	// An empty string means use the current context.
	ContextName string

	// ReportFormat controls the output format selected by the CLI layer.
	ReportFormat ReportFormat

	// ExcludeSystem removes findings whose namespace_type metadata is "system"
	// (kube-system, kube-public, kube-node-lease) from the report.
	// Cluster-scoped findings (nodes, EKS-level) are always retained.
	// Default false — all findings are included.
	ExcludeSystem bool

	// MinRiskScore, when > 0, retains only findings whose risk_chain_score is
	// greater than or equal to this value. Findings with no chain score (0) are
	// excluded. Summary.RiskScore is computed before this filter so it always
	// reflects the full pre-filter risk picture.
	// Default 0 — all findings are included regardless of chain score.
	MinRiskScore int

	// ShowRiskChains, when true, groups the post-filter findings by their
	// risk_chain_score and populates Summary.RiskChains with one entry per
	// unique (score, reason) pair, ordered by descending score.
	// Used by the CLI --show-risk-chains flag and included in JSON output.
	// Default false — Summary.RiskChains is nil/empty.
	ShowRiskChains bool
}

// systemNamespaces is the canonical set of Kubernetes system namespaces.
// Findings for resources in these namespaces are tagged namespace_type="system".
var systemNamespaces = map[string]struct{}{
	"kube-system":     {},
	"kube-public":     {},
	"kube-node-lease": {},
}

// RunAudit connects to the cluster, collects inventory, detects the cloud
// provider, optionally collects EKS control-plane data, evaluates all
// registered rules, applies policy filtering, and returns a populated AuditReport.
func (e *KubernetesEngine) RunAudit(ctx context.Context, opts KubernetesAuditOptions) (*models.AuditReport, error) {
	clientset, info, err := e.provider.ClientsetForContext(opts.ContextName)
	if err != nil {
		return nil, fmt.Errorf("connect to cluster: %w", err)
	}

	clusterData, err := kube.CollectClusterData(ctx, clientset, info)
	if err != nil {
		return nil, fmt.Errorf("collect cluster data: %w", err)
	}

	k8sData := convertClusterData(clusterData)

	// ── Asset Graph (Phase 11.5) ──────────────────────────────────────────────
	// Build the internal infrastructure relationship graph from the collected
	// cluster inventory. Non-fatal: a graph build failure is ignored and the
	// engine continues with a nil AssetGraph. The graph is stored on the engine
	// so the CLI layer can retrieve it after RunAudit returns.
	if ag, agErr := graph.BuildAssetGraph(k8sData); agErr == nil {
		e.lastCtx.AssetGraph = ag
	}

	// ── Cloud Reachability Enrichment (Phase 12) ──────────────────────────────
	// When an IAMAccessResolver is configured, resolve the AWS resources each
	// IAM role can access and enrich the asset graph with CAN_ACCESS edges.
	// Non-fatal: resolution failures per role are silently ignored.
	if e.lastCtx.AssetGraph != nil && e.iamResolver != nil {
		roleAccess := make(map[string][]models.RoleCloudAccess)
		for _, node := range e.lastCtx.AssetGraph.Nodes {
			if node.Type == graph.NodeTypeIAMRole {
				arn, _ := node.Metadata["arn"]
				if arn == "" {
					continue
				}
				accesses, resolveErr := e.iamResolver.ResolveRoleResourceAccess(ctx, arn)
				if resolveErr == nil && len(accesses) > 0 {
					// Phase 15: classify sensitivity for each cloud resource.
					for i := range accesses {
						accesses[i].Sensitivity = sensitivity.ClassifyResource(
							accesses[i].ResourceType,
							accesses[i].ResourceName,
						)
					}
					roleAccess[arn] = accesses
				}
			}
		}
		if len(roleAccess) > 0 {
			graph.EnrichWithCloudAccess(e.lastCtx.AssetGraph, roleAccess)
		}
	}

	// ── Node IAM Role Enrichment (Phase 14) ──────────────────────────────────
	// When a NodeIAMRoleResolver is configured, resolve the EC2 instance-profile
	// role for each cluster node and enrich the asset graph with
	// Node → IAMRole (ASSUMES_ROLE) edges.
	// Non-fatal: resolution failures per node are silently ignored.
	if e.lastCtx.AssetGraph != nil && e.nodeRoleResolver != nil {
		nodeRoles := make(map[string]string)
		for _, n := range k8sData.Nodes {
			if n.ProviderID == "" {
				continue
			}
			roleARN, resolveErr := e.nodeRoleResolver.ResolveNodeIAMRole(ctx, n.ProviderID)
			if resolveErr == nil && roleARN != "" {
				nodeRoles[n.Name] = roleARN
			}
		}
		if len(nodeRoles) > 0 {
			graph.EnrichWithNodeRoles(e.lastCtx.AssetGraph, nodeRoles)
		}
	}

	// ── Provider detection ────────────────────────────────────────────────────
	k8sData.ClusterProvider = detectClusterProvider(k8sData.Nodes)

	// ── EKS-specific data collection (non-fatal) ─────────────────────────────
	if k8sData.ClusterProvider == "eks" && e.eksCollector != nil {
		clusterName, region := extractEKSInfo(k8sData.Nodes)
		if clusterName != "" && region != "" {
			eksData, eksErr := e.eksCollector.CollectEKSData(ctx, clusterName, region)
			if eksErr == nil {
				k8sData.EKSData = eksData
			}
			// EKS collection failure is non-fatal: EKS rules skip on nil check.
		}
	}

	// ── Rule evaluation ───────────────────────────────────────────────────────
	rctx := rules.RuleContext{ClusterData: k8sData}

	raw := e.coreRegistry.EvaluateAll(rctx)

	if k8sData.ClusterProvider == "eks" && e.eksRegistry != nil {
		eksRaw := e.eksRegistry.EvaluateAll(rctx)
		raw = append(raw, eksRaw...)
	}

	stampDomain(raw, "kubernetes")

	merged := mergeFindings(raw)
	annotateNamespaceType(merged)
	annotateStructuralTopology(merged, k8sData) // Phase 10.3: stamp pod labels, SA name, service selector
	if opts.ExcludeSystem {
		merged = excludeSystemFindings(merged)
	}
	correlateRiskChains(merged) // Phase 4A: compound risk pattern detection

	// Phase 6: detect multi-layer attack paths from the merged finding set.
	// Must run after correlateRiskChains so that all findings are fully annotated.
	attackPaths := buildAttackPaths(merged)

	// Compute the highest risk score before policy filtering so the summary
	// reflects the full pre-policy risk picture.
	// Attack path scores take precedence over chain scores when paths exist.
	maxRiskScore := 0
	if len(attackPaths) > 0 {
		for _, ap := range attackPaths {
			if ap.Score > maxRiskScore {
				maxRiskScore = ap.Score
			}
		}
	} else {
		for _, f := range merged {
			if s := getRiskScore(f); s > maxRiskScore {
				maxRiskScore = s
			}
		}
	}

	// Phase 4C: drop findings below the caller-requested minimum risk score.
	// Must happen after maxRiskScore is captured so Summary.RiskScore is unaffected.
	if opts.MinRiskScore > 0 {
		merged = filterByMinRiskScore(merged, opts.MinRiskScore)
	}

	filtered := policy.ApplyPolicy(merged, "kubernetes", e.policy)
	sortFindings(filtered)

	summary := computeSummary(filtered)
	summary.RiskScore = maxRiskScore

	// Phase 5D/6: populate risk chain and attack path groupings when requested.
	if opts.ShowRiskChains {
		summary.AttackPaths = attackPaths
		summary.RiskChains = buildRiskChains(filtered)
	}

	return &models.AuditReport{
		ReportID:    fmt.Sprintf("k8s-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
		AuditType:   "kubernetes",
		Profile:     info.ContextName,
		AccountID:   "",
		Regions:     []string{info.ContextName},
		Summary:     summary,
		Findings:    filtered,
		Metadata: map[string]any{
			"cluster_provider": k8sData.ClusterProvider,
		},
	}, nil
}

// detectClusterProvider inspects node ProviderID prefixes and well-known labels
// to determine the cloud provider. Returns "eks", "gke", "aks", or "unknown".
func detectClusterProvider(nodes []models.KubernetesNodeData) string {
	for _, n := range nodes {
		switch {
		case strings.HasPrefix(n.ProviderID, "aws://"):
			return "eks"
		case strings.HasPrefix(n.ProviderID, "gce://"):
			return "gke"
		case strings.HasPrefix(n.ProviderID, "azure://"):
			return "aks"
		}
		if _, ok := n.Labels["eks.amazonaws.com/nodegroup"]; ok {
			return "eks"
		}
		if _, ok := n.Labels["cloud.google.com/gke-nodepool"]; ok {
			return "gke"
		}
		if _, ok := n.Labels["kubernetes.azure.com/cluster"]; ok {
			return "aks"
		}
	}
	return "unknown"
}

// extractEKSInfo derives the EKS cluster name and AWS region from node labels.
// Preferred sources:
//   - cluster name: label "eks.amazonaws.com/cluster-name"
//   - region:       label "topology.kubernetes.io/region"
//
// Falls back to parsing the ProviderID AZ field for the region when the label
// is absent ("aws:///us-east-1a/i-xxx" → strip trailing AZ letter → "us-east-1").
func extractEKSInfo(nodes []models.KubernetesNodeData) (clusterName, region string) {
	for _, n := range nodes {
		if cn, ok := n.Labels["eks.amazonaws.com/cluster-name"]; ok && cn != "" {
			clusterName = cn
		}
		if r, ok := n.Labels["topology.kubernetes.io/region"]; ok && r != "" {
			region = r
		}
		// Fallback: derive region from ProviderID AZ ("aws:///us-east-1a/i-xxx").
		if region == "" && strings.HasPrefix(n.ProviderID, "aws://") {
			parts := strings.Split(n.ProviderID, "/")
			// parts: ["aws:", "", "", "us-east-1a", "i-xxx"]
			if len(parts) >= 4 && len(parts[3]) > 1 {
				az := parts[3]
				region = az[:len(az)-1] // strip trailing AZ letter
			}
		}
		if clusterName != "" && region != "" {
			return
		}
	}
	return
}

// annotateNamespaceType stamps each finding with Metadata["namespace_type"]:
//   - "system"   — finding belongs to a system namespace (kube-system, kube-public, kube-node-lease)
//   - "workload" — finding belongs to a user namespace
//   - "cluster"  — finding is cluster-scoped (nodes, cluster-level, EKS rules)
//
// Namespace is resolved in priority order:
//  1. ResourceType == K8S_NAMESPACE: ResourceID is the namespace name.
//  2. Otherwise: Metadata["namespace"] string, if present and non-empty.
//  3. Neither applies: cluster-scoped → tag "cluster".
//
// Must be called after mergeFindings (merged Metadata is available) and before
// policy.ApplyPolicy so policy rules can filter on namespace_type in future.
func annotateNamespaceType(findings []models.Finding) {
	for i := range findings {
		f := &findings[i]
		if f.Metadata == nil {
			f.Metadata = make(map[string]any)
		}
		ns := resolveNamespaceForFinding(f)
		if ns == "" {
			f.Metadata["namespace_type"] = "cluster"
			continue
		}
		if _, isSystem := systemNamespaces[ns]; isSystem {
			f.Metadata["namespace_type"] = "system"
		} else {
			f.Metadata["namespace_type"] = "workload"
		}
	}
}

// resolveNamespaceForFinding extracts the namespace string for a finding.
// Returns "" for cluster-scoped findings that have no namespace.
func resolveNamespaceForFinding(f *models.Finding) string {
	// Namespace findings: ResourceID is the namespace name itself.
	if f.ResourceType == models.ResourceK8sNamespace {
		return f.ResourceID
	}
	// Pod, Service, SA and other namespace-scoped resources store namespace
	// in Metadata["namespace"].
	if ns, ok := f.Metadata["namespace"].(string); ok && ns != "" {
		return ns
	}
	// No namespace available: cluster-scoped (K8S_CLUSTER, K8S_NODE, EKS rules).
	return ""
}

// excludeSystemFindings removes findings tagged namespace_type="system".
// Cluster-scoped ("cluster") and workload ("workload") findings are retained.
func excludeSystemFindings(findings []models.Finding) []models.Finding {
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if nst, ok := f.Metadata["namespace_type"].(string); ok && nst == "system" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// annotateStructuralTopology stamps structural Kubernetes relationship metadata
// onto findings so the graph builder can draw real infrastructure edges instead
// of heuristic ones. It must be called after annotateNamespaceType (so that
// Metadata["namespace"] is already set on namespace-scoped findings).
//
// Stamped keys (on K8S_POD findings):
//
//	"pod_service_account" (string)        — pod's declared serviceAccountName
//	"pod_labels"          (map[string]string) — pod's label map (for LB selector matching)
//	"workload_kind"       (string)        — top-level controller kind (Deployment, StatefulSet, …)
//	"workload_name"       (string)        — top-level controller name
//
// Stamped keys (on K8S_SERVICE findings):
//
//	"service_selector"    (map[string]string) — Service's spec.selector
//
// These keys are consumed exclusively by the rendering layer (render/graph.go)
// and never affect scoring, correlation, or policy enforcement.
func annotateStructuralTopology(findings []models.Finding, k8sData *models.KubernetesClusterData) {
	// Build lookup indexes: "namespace/name" → data.
	podIndex := make(map[string]*models.KubernetesPodData, len(k8sData.Pods))
	for i := range k8sData.Pods {
		p := &k8sData.Pods[i]
		podIndex[p.Namespace+"/"+p.Name] = p
	}
	svcIndex := make(map[string]*models.KubernetesServiceData, len(k8sData.Services))
	for i := range k8sData.Services {
		s := &k8sData.Services[i]
		svcIndex[s.Namespace+"/"+s.Name] = s
	}
	saIndex := make(map[string]*models.KubernetesServiceAccountData, len(k8sData.ServiceAccounts))
	for i := range k8sData.ServiceAccounts {
		sa := &k8sData.ServiceAccounts[i]
		saIndex[sa.Namespace+"/"+sa.Name] = sa
	}

	for i := range findings {
		f := &findings[i]
		if f.Metadata == nil {
			f.Metadata = make(map[string]any)
		}
		ns, _ := f.Metadata["namespace"].(string)

		switch f.ResourceType {
		case models.ResourceK8sPod:
			if pod, ok := podIndex[ns+"/"+f.ResourceID]; ok {
				f.Metadata["pod_service_account"] = pod.ServiceAccountName
				// Copy the label map so findings don't share the underlying map.
				labels := make(map[string]string, len(pod.Labels))
				for k, v := range pod.Labels {
					labels[k] = v
				}
				f.Metadata["pod_labels"] = labels
				// Phase 10.4: workload owner for graph node collapsing.
				f.Metadata["workload_kind"] = pod.WorkloadKind
				f.Metadata["workload_name"] = pod.WorkloadName
				// Phase 14: node name for instance-profile identity path.
				if pod.NodeName != "" {
					f.Metadata["node_name"] = pod.NodeName
				}
			}
		case models.ResourceK8sService:
			if svc, ok := svcIndex[ns+"/"+f.ResourceID]; ok {
				sel := make(map[string]string, len(svc.Selector))
				for k, v := range svc.Selector {
					sel[k] = v
				}
				f.Metadata["service_selector"] = sel
			}
		case models.ResourceK8sServiceAccount:
			if sa, ok := saIndex[ns+"/"+f.ResourceID]; ok {
				if sa.IAMRoleArn != "" {
					f.Metadata["iam_role_arn"] = sa.IAMRoleArn
				}
			}
		}
	}
}

// convertClusterData translates the provider-layer ClusterData into the
// engine-layer KubernetesClusterData used by rule evaluation.
func convertClusterData(data *kube.ClusterData) *models.KubernetesClusterData {
	k := &models.KubernetesClusterData{
		ContextName: data.ClusterInfo.ContextName,
		NodeCount:   len(data.Nodes),
	}
	for _, n := range data.Nodes {
		labels := make(map[string]string, len(n.Labels))
		for key, val := range n.Labels {
			labels[key] = val
		}
		k.Nodes = append(k.Nodes, models.KubernetesNodeData{
			Name:                 n.Name,
			CPUCapacityMillis:    n.CPUCapacityMillis,
			AllocatableCPUMillis: n.AllocatableCPUMillis,
			ProviderID:           n.ProviderID,
			Labels:               labels,
		})
	}
	for _, ns := range data.Namespaces {
		nsLabels := make(map[string]string, len(ns.Labels))
		for key, val := range ns.Labels {
			nsLabels[key] = val
		}
		k.Namespaces = append(k.Namespaces, models.KubernetesNamespaceData{
			Name:          ns.Name,
			HasLimitRange: ns.HasLimitRange,
			Labels:        nsLabels,
		})
	}
	for _, pod := range data.Pods {
		podLabels := make(map[string]string, len(pod.Labels))
		for key, val := range pod.Labels {
			podLabels[key] = val
		}
		pd := models.KubernetesPodData{
			Name:               pod.Name,
			Namespace:          pod.Namespace,
			HostNetwork:        pod.HostNetwork,
			HostPID:            pod.HostPID,
			HostIPC:            pod.HostIPC,
			ServiceAccountName: pod.ServiceAccountName,
			Labels:             podLabels,
			WorkloadKind:       pod.WorkloadKind,
			WorkloadName:       pod.WorkloadName,
			NodeName:           pod.NodeName,
		}
		for _, c := range pod.Containers {
			var addedCaps []string
			if len(c.AddedCapabilities) > 0 {
				addedCaps = append(addedCaps, c.AddedCapabilities...)
			}
			pd.Containers = append(pd.Containers, models.KubernetesContainerData{
				Name:               c.Name,
				Privileged:         c.Privileged,
				HasCPURequest:      c.HasCPURequest,
				HasMemoryRequest:   c.HasMemoryRequest,
				RunAsNonRoot:       c.RunAsNonRoot,
				RunAsUser:          c.RunAsUser,
				AddedCapabilities:  addedCaps,
				SeccompProfileType: c.SeccompProfileType,
			})
		}
		k.Pods = append(k.Pods, pd)
	}
	for _, svc := range data.Services {
		annotations := make(map[string]string, len(svc.Annotations))
		for key, val := range svc.Annotations {
			annotations[key] = val
		}
		selector := make(map[string]string, len(svc.Selector))
		for key, val := range svc.Selector {
			selector[key] = val
		}
		k.Services = append(k.Services, models.KubernetesServiceData{
			Name:        svc.Name,
			Namespace:   svc.Namespace,
			Type:        svc.Type,
			Annotations: annotations,
			Selector:    selector,
		})
	}
	for _, sa := range data.ServiceAccounts {
		saAnnotations := make(map[string]string, len(sa.Annotations))
		for key, val := range sa.Annotations {
			saAnnotations[key] = val
		}
		k.ServiceAccounts = append(k.ServiceAccounts, models.KubernetesServiceAccountData{
			Name:                         sa.Name,
			Namespace:                    sa.Namespace,
			AutomountServiceAccountToken: sa.AutomountServiceAccountToken,
			Annotations:                  saAnnotations,
			IAMRoleArn:                   sa.IAMRoleArn,
		})
	}
	return k
}
