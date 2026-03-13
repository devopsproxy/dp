package engine

import (
	"sort"

	"github.com/devopsproxy/dp/internal/models"
)

// ruleIDsForFinding returns all rule IDs associated with a finding.
// When multiple rules were merged by mergeFindings, the merged rule IDs are
// stored in Metadata["rules"]; these are included alongside the primary RuleID.
func ruleIDsForFinding(f *models.Finding) []string {
	ids := []string{f.RuleID}
	if f.Metadata != nil {
		if rr, ok := f.Metadata["rules"]; ok {
			if merged, ok := rr.([]string); ok {
				ids = append(ids, merged...)
			}
		}
	}
	return ids
}

// idsContain reports whether any element of ids equals target.
func idsContain(ids []string, target string) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

// nsIndexHas reports whether the namespace rule index entry for ns contains ruleID.
func nsIndexHas(index map[string]map[string]struct{}, ns, ruleID string) bool {
	if rules, ok := index[ns]; ok {
		_, found := rules[ruleID]
		return found
	}
	return false
}

// buildNamespaceRuleIndex constructs a map of namespace → set of rule IDs that
// have findings in that namespace. Used by the correlation pass to detect
// compound risk patterns across multiple findings in the same namespace.
//
// Only namespace-scoped findings contribute to the index; cluster-scoped
// findings (resolveNamespaceForFinding returns "") are skipped.
func buildNamespaceRuleIndex(findings []models.Finding) map[string]map[string]struct{} {
	index := make(map[string]map[string]struct{})
	for i := range findings {
		f := &findings[i]
		ns := resolveNamespaceForFinding(f)
		if ns == "" {
			continue
		}
		if index[ns] == nil {
			index[ns] = make(map[string]struct{})
		}
		for _, id := range ruleIDsForFinding(f) {
			index[ns][id] = struct{}{}
		}
	}
	return index
}

// filterByMinRiskScore returns a new slice containing only findings whose
// risk_chain_score is >= min. Findings with no chain score (score == 0) are
// excluded when min > 0. The original slice is not modified.
//
// This filter is applied after correlateRiskChains and after the maxRiskScore
// computation so that Summary.RiskScore reflects the full pre-filter picture.
func filterByMinRiskScore(findings []models.Finding, min int) []models.Finding {
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if getRiskScore(f) >= min {
			out = append(out, f)
		}
	}
	return out
}

// getRiskScore returns the risk_chain_score stored in f.Metadata, or 0 if the
// key is absent or not an int. Used to compute the report-level summary score.
func getRiskScore(f models.Finding) int {
	if f.Metadata == nil {
		return 0
	}
	if score, ok := f.Metadata["risk_chain_score"].(int); ok {
		return score
	}
	return 0
}

// correlateRiskChains annotates findings that participate in compound risk
// patterns with Metadata["risk_chain_score"] (int) and
// Metadata["risk_chain_reason"] (string).
//
// Six risk chains are detected:
//
//	Chain 1 (score 80): A public LoadBalancer service
//	  (K8S_SERVICE_PUBLIC_LOADBALANCER) and a pod with K8S_POD_RUN_AS_ROOT or
//	  K8S_POD_CAP_SYS_ADMIN co-exist in the same namespace.
//	  Reason: "Public service exposes privileged workload"
//
//	Chain 2 (score 60): A pod uses the default ServiceAccount
//	  (K8S_DEFAULT_SERVICEACCOUNT_USED) and the default ServiceAccount has
//	  automount enabled (K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT) in the same namespace.
//	  Reason: "Default service account with auto-mounted token"
//
//	Chain 3 (score 50): The cluster has a single node (K8S_CLUSTER_SINGLE_NODE)
//	  and at least one CRITICAL severity finding exists.
//	  Reason: "Single-node cluster with critical pod security violation"
//
//	Chain 4 (score 90): EKS node group IAM role is overpermissive
//	  (EKS_NODE_ROLE_OVERPERMISSIVE) and a public LoadBalancer service exists
//	  (K8S_SERVICE_PUBLIC_LOADBALANCER) anywhere in the cluster.
//	  Reason: "Public service exposed in cluster with over-permissive node IAM role."
//
//	Chain 5 (score 85): A ServiceAccount lacks IRSA annotation
//	  (EKS_SERVICEACCOUNT_NO_IRSA) and the default ServiceAccount is used
//	  (K8S_DEFAULT_SERVICEACCOUNT_USED) in the same namespace.
//	  Reason: "Default service account used without IRSA."
//
//	Chain 6 (score 95): The cluster lacks an IAM OIDC provider
//	  (EKS_OIDC_PROVIDER_NOT_ASSOCIATED) and at least one HIGH severity finding
//	  exists in the cluster.
//	  Reason: "Cluster lacks OIDC provider and has high-risk workload findings."
//
// When multiple chains apply to the same finding, the highest score is kept.
// Severity and sort order are not affected.
//
// Must be called after mergeFindings, annotateNamespaceType, and (optionally)
// excludeSystemFindings so that the correlation operates on the final finding set.
func correlateRiskChains(findings []models.Finding) {
	if len(findings) == 0 {
		return
	}

	// ── Phase 1: build lookup structures ──────────────────────────────────────

	nsIndex := buildNamespaceRuleIndex(findings)

	hasSingleNode := false
	hasCritical := false
	hasNodeRoleOverpermissive := false
	hasPublicLB := false
	hasOIDCNotAssociated := false
	hasHighSeverity := false

	for i := range findings {
		f := &findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_CLUSTER_SINGLE_NODE") {
			hasSingleNode = true
		}
		if f.Severity == models.SeverityCritical {
			hasCritical = true
		}
		if idsContain(ids, "EKS_NODE_ROLE_OVERPERMISSIVE") {
			hasNodeRoleOverpermissive = true
		}
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			hasPublicLB = true
		}
		if idsContain(ids, "EKS_OIDC_PROVIDER_NOT_ASSOCIATED") {
			hasOIDCNotAssociated = true
		}
		if f.Severity == models.SeverityHigh {
			hasHighSeverity = true
		}
	}

	// ── Phase 2: annotate participating findings ───────────────────────────────

	for i := range findings {
		f := &findings[i]
		ids := ruleIDsForFinding(f)
		ns := resolveNamespaceForFinding(f)

		bestScore := 0
		bestReason := ""

		// Chain 1: Public LB + K8S_POD_RUN_AS_ROOT or K8S_POD_CAP_SYS_ADMIN
		// in the same namespace.
		if ns != "" {
			isLB := idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER")
			isPriv := idsContain(ids, "K8S_POD_RUN_AS_ROOT") || idsContain(ids, "K8S_POD_CAP_SYS_ADMIN")
			nsHasLB := nsIndexHas(nsIndex, ns, "K8S_SERVICE_PUBLIC_LOADBALANCER")
			nsHasPriv := nsIndexHas(nsIndex, ns, "K8S_POD_RUN_AS_ROOT") ||
				nsIndexHas(nsIndex, ns, "K8S_POD_CAP_SYS_ADMIN")
			if (isLB && nsHasPriv) || (isPriv && nsHasLB) {
				if 80 > bestScore {
					bestScore = 80
					bestReason = "Public service exposes privileged workload"
				}
			}
		}

		// Chain 2: K8S_DEFAULT_SERVICEACCOUNT_USED + K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT
		// in the same namespace.
		if ns != "" {
			isDefaultSA := idsContain(ids, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			isAutomount := idsContain(ids, "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT")
			nsHasDefaultSA := nsIndexHas(nsIndex, ns, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			nsHasAutomount := nsIndexHas(nsIndex, ns, "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT")
			if (isDefaultSA && nsHasAutomount) || (isAutomount && nsHasDefaultSA) {
				if 60 > bestScore {
					bestScore = 60
					bestReason = "Default service account with auto-mounted token"
				}
			}
		}

		// Chain 3: K8S_CLUSTER_SINGLE_NODE + any CRITICAL severity finding.
		{
			isSingleNode := idsContain(ids, "K8S_CLUSTER_SINGLE_NODE")
			isCritical := f.Severity == models.SeverityCritical
			if (isSingleNode && hasCritical) || (isCritical && hasSingleNode) {
				if 50 > bestScore {
					bestScore = 50
					bestReason = "Single-node cluster with critical pod security violation"
				}
			}
		}

		// Chain 4 (EKS Phase 5C): EKS_NODE_ROLE_OVERPERMISSIVE + K8S_SERVICE_PUBLIC_LOADBALANCER
		// anywhere in the cluster (global scope). Score 90.
		{
			isNodeRole := idsContain(ids, "EKS_NODE_ROLE_OVERPERMISSIVE")
			isLB := idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER")
			if (isNodeRole || isLB) && hasNodeRoleOverpermissive && hasPublicLB {
				if 90 > bestScore {
					bestScore = 90
					bestReason = "Public service exposed in cluster with over-permissive node IAM role."
				}
			}
		}

		// Chain 5 (EKS Phase 5C): EKS_SERVICEACCOUNT_NO_IRSA + K8S_DEFAULT_SERVICEACCOUNT_USED
		// in the same namespace. Score 85.
		if ns != "" {
			isNoIRSA := idsContain(ids, "EKS_SERVICEACCOUNT_NO_IRSA")
			isDefaultSAUsed := idsContain(ids, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			nsHasNoIRSA := nsIndexHas(nsIndex, ns, "EKS_SERVICEACCOUNT_NO_IRSA")
			nsHasDefaultSAUsed := nsIndexHas(nsIndex, ns, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			if (isNoIRSA && nsHasDefaultSAUsed) || (isDefaultSAUsed && nsHasNoIRSA) {
				if 85 > bestScore {
					bestScore = 85
					bestReason = "Default service account used without IRSA."
				}
			}
		}

		// Chain 6 (EKS Phase 5C): EKS_OIDC_PROVIDER_NOT_ASSOCIATED + any HIGH severity finding
		// anywhere in the cluster (global scope). Score 95.
		{
			isOIDCNotAssociated := idsContain(ids, "EKS_OIDC_PROVIDER_NOT_ASSOCIATED")
			isHigh := f.Severity == models.SeverityHigh
			if (isOIDCNotAssociated || isHigh) && hasOIDCNotAssociated && hasHighSeverity {
				if 95 > bestScore {
					bestScore = 95
					bestReason = "Cluster lacks OIDC provider and has high-risk workload findings."
				}
			}
		}

		if bestScore > 0 {
			if f.Metadata == nil {
				f.Metadata = make(map[string]any)
			}
			f.Metadata["risk_chain_score"] = bestScore
			f.Metadata["risk_chain_reason"] = bestReason
		}
	}
}

// buildAttackPaths detects multi-layer compound attack paths across the full
// finding set and returns one models.AttackPath per triggered scenario, ordered
// by descending score.
//
// Five attack paths are defined:
//
//	PATH 1 (score 98) — External Compromise (per-namespace):
//	  Requires in the SAME namespace:
//	    K8S_SERVICE_PUBLIC_LOADBALANCER
//	  + (K8S_POD_RUN_AS_ROOT OR K8S_POD_CAP_SYS_ADMIN)
//	  + (EKS_SERVICEACCOUNT_NO_IRSA OR K8S_DEFAULT_SERVICEACCOUNT_USED)
//	  Optional 4th layer (cluster-scoped): EKS_NODE_ROLE_OVERPERMISSIVE
//	  One AttackPath entry is produced per qualifying namespace.
//	  Description: "Externally exposed privileged workload with weak identity isolation."
//
//	PATH 5 (score 96) — Cross-Cloud Identity Escalation (per-namespace):
//	  Requires in the SAME namespace:
//	    K8S_SERVICE_PUBLIC_LOADBALANCER
//	  + (K8S_POD_RUN_AS_ROOT OR K8S_POD_CAP_SYS_ADMIN)
//	  + (EKS_SERVICEACCOUNT_NO_IRSA OR K8S_DEFAULT_SERVICEACCOUNT_USED OR K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT)
//	  AND cluster-wide: (EKS_NODE_ROLE_OVERPERMISSIVE OR EKS_IAM_ROLE_WILDCARD)
//	  One AttackPath entry is produced per qualifying namespace.
//	  Description: "Externally reachable workload can assume over-permissive cloud IAM role (cross-plane privilege escalation)."
//
//	PATH 4 (score 94) — EKS Control Plane Exposure (cluster-scoped):
//	  Requires: EKS_PUBLIC_ENDPOINT_ENABLED
//	          + (EKS_NODE_ROLE_OVERPERMISSIVE OR EKS_IAM_ROLE_WILDCARD)
//	          + EKS_CONTROL_PLANE_LOGGING_DISABLED
//	  Description: "Public EKS control plane exposed with weak IAM and insufficient audit logging."
//
//	PATH 2 (score 92) — Identity Escalation (per-namespace):
//	  Requires in the SAME namespace:
//	    K8S_DEFAULT_SERVICEACCOUNT_USED
//	  + K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT
//	  + EKS_SERVICEACCOUNT_NO_IRSA
//	  AND cluster-wide: EKS_OIDC_PROVIDER_NOT_ASSOCIATED
//	  One AttackPath entry is produced per qualifying namespace.
//	  Description: "Service account token misuse combined with missing IRSA and OIDC."
//
//	PATH 3 (score 90) — Governance Collapse (cluster-scoped):
//	  Requires: EKS_ENCRYPTION_DISABLED
//	          + EKS_CONTROL_PLANE_LOGGING_DISABLED
//	          + K8S_CLUSTER_SINGLE_NODE
//	  Description: "Cluster governance protections disabled with no redundancy."
//
// When attack paths are present, the caller should use the highest path score as
// Summary.RiskScore (overriding the chain-based score). If no paths are detected,
// the chain-based score is used as the fallback.
//
// Strict rule filtering: only a finding whose PRIMARY RuleID (f.RuleID) is in
// a path's allowed rule set will be detected and collected. Merged rule IDs
// stored in Metadata["rules"] are not used. This guarantees that AttackPath
// FindingIDs contain only findings directly scoped to the path's definition.
func buildAttackPaths(findings []models.Finding) []models.AttackPath {
	if len(findings) == 0 {
		return nil
	}

	// Two separate index pairs — one for detection, one for collection.
	//
	// DETECTION (expanded): uses ruleIDsForFinding so that merged findings
	// (Metadata["rules"]) contribute to nsHas/clusterHas condition checks.
	// This ensures attack paths trigger correctly even when the engine has merged
	// same-resource findings and the relevant rule ID is not the primary.
	//
	// COLLECTION (primary-only): uses f.RuleID only.
	// Only findings whose PRIMARY rule ID is in a path's allowed set appear in
	// AttackPath.FindingIDs, preventing unrelated-primary findings (e.g. a finding
	// with primary K8S_POD_NO_SECCOMP that happened to be merged with
	// K8S_POD_RUN_AS_ROOT) from polluting the path's finding reference list.
	//
	// Allowed primary rule IDs per path:
	//   PATH 1: K8S_SERVICE_PUBLIC_LOADBALANCER, K8S_POD_RUN_AS_ROOT,
	//           K8S_POD_CAP_SYS_ADMIN, EKS_SERVICEACCOUNT_NO_IRSA,
	//           K8S_DEFAULT_SERVICEACCOUNT_USED, EKS_NODE_ROLE_OVERPERMISSIVE (optional)
	//   PATH 5: K8S_SERVICE_PUBLIC_LOADBALANCER, K8S_POD_RUN_AS_ROOT,
	//           K8S_POD_CAP_SYS_ADMIN, EKS_SERVICEACCOUNT_NO_IRSA,
	//           K8S_DEFAULT_SERVICEACCOUNT_USED, K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT,
	//           EKS_NODE_ROLE_OVERPERMISSIVE, EKS_IAM_ROLE_WILDCARD
	//   PATH 4: EKS_PUBLIC_ENDPOINT_ENABLED, EKS_NODE_ROLE_OVERPERMISSIVE,
	//           EKS_IAM_ROLE_WILDCARD, EKS_CONTROL_PLANE_LOGGING_DISABLED
	//   PATH 2: K8S_DEFAULT_SERVICEACCOUNT_USED, K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT,
	//           EKS_SERVICEACCOUNT_NO_IRSA, EKS_OIDC_PROVIDER_NOT_ASSOCIATED
	//   PATH 3: EKS_ENCRYPTION_DISABLED, EKS_CONTROL_PLANE_LOGGING_DISABLED,
	//           K8S_CLUSTER_SINGLE_NODE

	// Detection index — namespace-scoped (expanded via ruleIDsForFinding).
	detectNS := buildNamespaceRuleIndex(findings)

	// Detection index — cluster-scoped (expanded via ruleIDsForFinding).
	detectCluster := make(map[string]struct{})
	for i := range findings {
		f := &findings[i]
		if resolveNamespaceForFinding(f) == "" {
			for _, ruleID := range ruleIDsForFinding(f) {
				detectCluster[ruleID] = struct{}{}
			}
		}
	}

	// Collection index — namespace-scoped (primary f.RuleID only).
	collectNS := make(map[string]map[string][]string)
	// Collection index — cluster-scoped (primary f.RuleID only).
	collectCluster := make(map[string][]string)
	for i := range findings {
		f := &findings[i]
		ns := resolveNamespaceForFinding(f)
		if ns != "" {
			if collectNS[ns] == nil {
				collectNS[ns] = make(map[string][]string)
			}
			collectNS[ns][f.RuleID] = append(collectNS[ns][f.RuleID], f.ID)
		} else {
			collectCluster[f.RuleID] = append(collectCluster[f.RuleID], f.ID)
		}
	}

	// nsHas reports whether any finding in ns has ruleID (detection, expanded).
	nsHas := func(ns, ruleID string) bool {
		return nsIndexHas(detectNS, ns, ruleID)
	}

	// clusterHas reports whether any cluster-scoped finding has ruleID (detection, expanded).
	clusterHas := func(ruleID string) bool {
		_, ok := detectCluster[ruleID]
		return ok
	}

	// collectNSIDs returns deduplicated finding IDs from collectNS[ns] for the given
	// ruleIDs (primary-only collection).
	collectNSIDs := func(ns string, ruleIDs ...string) []string {
		seen := make(map[string]struct{})
		var ids []string
		for _, ruleID := range ruleIDs {
			for _, fid := range collectNS[ns][ruleID] {
				if _, already := seen[fid]; !already {
					seen[fid] = struct{}{}
					ids = append(ids, fid)
				}
			}
		}
		return ids
	}

	// appendClusterIDs appends finding IDs from collectCluster for the given ruleIDs,
	// deduplicating against the supplied seen set (primary-only collection).
	appendClusterIDs := func(seen map[string]struct{}, ids []string, ruleIDs ...string) []string {
		for _, ruleID := range ruleIDs {
			for _, fid := range collectCluster[ruleID] {
				if _, already := seen[fid]; !already {
					seen[fid] = struct{}{}
					ids = append(ids, fid)
				}
			}
		}
		return ids
	}

	var paths []models.AttackPath

	// ── PATH 1 (98): External Compromise — one entry per qualifying namespace ──
	// Conditions checked within the same namespace:
	//   - has K8S_SERVICE_PUBLIC_LOADBALANCER (network exposure)
	//   - has K8S_POD_RUN_AS_ROOT or K8S_POD_CAP_SYS_ADMIN (workload privilege)
	//   - has EKS_SERVICEACCOUNT_NO_IRSA or K8S_DEFAULT_SERVICEACCOUNT_USED (identity weakness)
	// Optional: EKS_NODE_ROLE_OVERPERMISSIVE (cluster-scoped) appended once per entry.
	nodeRolePresent := clusterHas("EKS_NODE_ROLE_OVERPERMISSIVE")
	for ns := range detectNS {
		hasLB := nsHas(ns, "K8S_SERVICE_PUBLIC_LOADBALANCER")
		hasPriv := nsHas(ns, "K8S_POD_RUN_AS_ROOT") || nsHas(ns, "K8S_POD_CAP_SYS_ADMIN")
		hasIdentityWeak := nsHas(ns, "EKS_SERVICEACCOUNT_NO_IRSA") || nsHas(ns, "K8S_DEFAULT_SERVICEACCOUNT_USED")
		if !hasLB || !hasPriv || !hasIdentityWeak {
			continue
		}

		layers := []string{"Network Exposure", "Workload Privilege", "Identity Weakness"}

		// Collect namespace-scoped finding IDs for contributing rules.
		nsRules := []string{"K8S_SERVICE_PUBLIC_LOADBALANCER"}
		for _, r := range []string{
			"K8S_POD_RUN_AS_ROOT", "K8S_POD_CAP_SYS_ADMIN",
			"EKS_SERVICEACCOUNT_NO_IRSA", "K8S_DEFAULT_SERVICEACCOUNT_USED",
		} {
			if nsHas(ns, r) {
				nsRules = append(nsRules, r)
			}
		}
		fids := collectNSIDs(ns, nsRules...)

		// Optional 4th layer: cluster-scoped node role finding.
		if nodeRolePresent {
			layers = append(layers, "IAM Over-permission")
			seen := make(map[string]struct{})
			for _, id := range fids {
				seen[id] = struct{}{}
			}
			fids = appendClusterIDs(seen, fids, "EKS_NODE_ROLE_OVERPERMISSIVE")
		}

		paths = append(paths, models.AttackPath{
			Score:       98,
			Layers:      layers,
			FindingIDs:  fids,
			Description: "Externally exposed privileged workload with weak identity isolation.",
		})
	}

	// ── PATH 2 (92): Identity Escalation — one entry per qualifying namespace ──
	// Conditions checked within the same namespace:
	//   - has K8S_DEFAULT_SERVICEACCOUNT_USED
	//   - has K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT
	//   - has EKS_SERVICEACCOUNT_NO_IRSA
	// AND cluster-wide: EKS_OIDC_PROVIDER_NOT_ASSOCIATED must be present.
	if clusterHas("EKS_OIDC_PROVIDER_NOT_ASSOCIATED") {
		for ns := range detectNS {
			hasDefaultSA := nsHas(ns, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			hasTokenAutomount := nsHas(ns, "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT")
			hasNoIRSA := nsHas(ns, "EKS_SERVICEACCOUNT_NO_IRSA")
			if !hasDefaultSA || !hasTokenAutomount || !hasNoIRSA {
				continue
			}

			fids := collectNSIDs(ns,
				"K8S_DEFAULT_SERVICEACCOUNT_USED",
				"K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT",
				"EKS_SERVICEACCOUNT_NO_IRSA",
			)
			// Append cluster-level OIDC finding IDs (deduplicated).
			seen := make(map[string]struct{})
			for _, id := range fids {
				seen[id] = struct{}{}
			}
			fids = appendClusterIDs(seen, fids, "EKS_OIDC_PROVIDER_NOT_ASSOCIATED")

			paths = append(paths, models.AttackPath{
				Score:       92,
				Layers:      []string{"Service Account Usage", "Token Exposure", "Identity Federation Missing"},
				FindingIDs:  fids,
				Description: "Service account token misuse combined with missing IRSA and OIDC.",
			})
		}
	}

	// ── PATH 3 (90): Governance Collapse — cluster-scoped ────────────────────
	// All three rules are cluster-scoped: no namespace dimension.
	if clusterHas("EKS_ENCRYPTION_DISABLED") &&
		clusterHas("EKS_CONTROL_PLANE_LOGGING_DISABLED") &&
		clusterHas("K8S_CLUSTER_SINGLE_NODE") {
		seen := make(map[string]struct{})
		var fids []string
		fids = appendClusterIDs(seen, fids,
			"EKS_ENCRYPTION_DISABLED",
			"EKS_CONTROL_PLANE_LOGGING_DISABLED",
			"K8S_CLUSTER_SINGLE_NODE",
		)
		paths = append(paths, models.AttackPath{
			Score:       90,
			Layers:      []string{"Encryption Disabled", "Logging Disabled", "No Redundancy"},
			FindingIDs:  fids,
			Description: "Cluster governance protections disabled with no redundancy.",
		})
	}

	// ── PATH 4 (94): EKS Control Plane Exposure — cluster-scoped ─────────────
	// All three conditions are cluster-scoped: no namespace dimension.
	// IAM condition is satisfied by either EKS_NODE_ROLE_OVERPERMISSIVE or EKS_IAM_ROLE_WILDCARD.
	// Strict filtering: FindingIDs contain only findings from the four allowed rule IDs.
	hasIAMOverpermissive := clusterHas("EKS_NODE_ROLE_OVERPERMISSIVE") || clusterHas("EKS_IAM_ROLE_WILDCARD")
	if clusterHas("EKS_PUBLIC_ENDPOINT_ENABLED") &&
		hasIAMOverpermissive &&
		clusterHas("EKS_CONTROL_PLANE_LOGGING_DISABLED") {
		seen := make(map[string]struct{})
		var fids []string
		fids = appendClusterIDs(seen, fids, "EKS_PUBLIC_ENDPOINT_ENABLED")
		// Collect whichever IAM rule(s) are present (both if both exist).
		fids = appendClusterIDs(seen, fids, "EKS_NODE_ROLE_OVERPERMISSIVE")
		fids = appendClusterIDs(seen, fids, "EKS_IAM_ROLE_WILDCARD")
		fids = appendClusterIDs(seen, fids, "EKS_CONTROL_PLANE_LOGGING_DISABLED")
		paths = append(paths, models.AttackPath{
			Score:       94,
			Layers:      []string{"Control Plane Exposure", "IAM Over-Permission", "Observability Gap"},
			FindingIDs:  fids,
			Description: "Public EKS control plane exposed with weak IAM and insufficient audit logging.",
		})
	}

	// ── PATH 5 (96): Cross-Cloud Identity Escalation — per-namespace ─────────
	// Conditions checked within the SAME namespace:
	//   - K8S_SERVICE_PUBLIC_LOADBALANCER (network exposure)
	//   - K8S_POD_RUN_AS_ROOT OR K8S_POD_CAP_SYS_ADMIN (workload privilege)
	//   - EKS_SERVICEACCOUNT_NO_IRSA OR K8S_DEFAULT_SERVICEACCOUNT_USED
	//     OR K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT (identity weakness)
	// AND cluster-wide:
	//   - EKS_NODE_ROLE_OVERPERMISSIVE OR EKS_IAM_ROLE_WILDCARD (IAM over-permission)
	// One AttackPath entry is produced per qualifying namespace.
	hasClusterIAM := clusterHas("EKS_NODE_ROLE_OVERPERMISSIVE") || clusterHas("EKS_IAM_ROLE_WILDCARD")
	if hasClusterIAM {
		for ns := range detectNS {
			hasLB5 := nsHas(ns, "K8S_SERVICE_PUBLIC_LOADBALANCER")
			hasPriv5 := nsHas(ns, "K8S_POD_RUN_AS_ROOT") || nsHas(ns, "K8S_POD_CAP_SYS_ADMIN")
			hasIdentity5 := nsHas(ns, "EKS_SERVICEACCOUNT_NO_IRSA") ||
				nsHas(ns, "K8S_DEFAULT_SERVICEACCOUNT_USED") ||
				nsHas(ns, "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT")
			if !hasLB5 || !hasPriv5 || !hasIdentity5 {
				continue
			}

			// Collect namespace-scoped finding IDs for all contributing rules
			// present in this namespace.
			nsRules5 := []string{"K8S_SERVICE_PUBLIC_LOADBALANCER"}
			for _, r := range []string{
				"K8S_POD_RUN_AS_ROOT", "K8S_POD_CAP_SYS_ADMIN",
				"EKS_SERVICEACCOUNT_NO_IRSA", "K8S_DEFAULT_SERVICEACCOUNT_USED",
				"K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT",
			} {
				if nsHas(ns, r) {
					nsRules5 = append(nsRules5, r)
				}
			}
			fids := collectNSIDs(ns, nsRules5...)

			// Append cluster IAM finding IDs (deduplicated).
			seen := make(map[string]struct{})
			for _, id := range fids {
				seen[id] = struct{}{}
			}
			fids = appendClusterIDs(seen, fids, "EKS_NODE_ROLE_OVERPERMISSIVE")
			fids = appendClusterIDs(seen, fids, "EKS_IAM_ROLE_WILDCARD")

			paths = append(paths, models.AttackPath{
				Score:       96,
				Layers:      []string{"Network Exposure", "Workload Compromise", "Cloud IAM Escalation"},
				FindingIDs:  fids,
				Description: "Externally reachable workload can assume over-permissive cloud IAM role (cross-plane privilege escalation).",
			})
		}
	}

	// Order by descending score.
	sort.Slice(paths, func(i, j int) bool {
		return paths[i].Score > paths[j].Score
	})
	return paths
}

// buildRiskChains groups findings by their (risk_chain_score, risk_chain_reason)
// pair and returns one models.RiskChain per unique pair, ordered by descending
// score. Only findings with risk_chain_score > 0 are included.
//
// Called by RunAudit when KubernetesAuditOptions.ShowRiskChains is true.
// Operates on the post-policy-filter sorted finding set so that FindingIDs
// match what appears in the report's Findings slice.
func buildRiskChains(findings []models.Finding) []models.RiskChain {
	type chainKey struct {
		score  int
		reason string
	}

	chainMap := make(map[chainKey][]string)
	for _, f := range findings {
		score := getRiskScore(f)
		if score == 0 {
			continue
		}
		reason, _ := f.Metadata["risk_chain_reason"].(string)
		k := chainKey{score: score, reason: reason}
		chainMap[k] = append(chainMap[k], f.ID)
	}

	chains := make([]models.RiskChain, 0, len(chainMap))
	for k, ids := range chainMap {
		chains = append(chains, models.RiskChain{
			Score:      k.score,
			Reason:     k.reason,
			FindingIDs: ids,
		})
	}

	// Order by descending score; break ties alphabetically by reason for stable output.
	sort.Slice(chains, func(i, j int) bool {
		if chains[i].Score != chains[j].Score {
			return chains[i].Score > chains[j].Score
		}
		return chains[i].Reason < chains[j].Reason
	})
	return chains
}
