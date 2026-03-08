# Architecture

`dp` is structured around three core principles:

1. **Offline-first** — the rule engine never requires an LLM or external API to produce findings
2. **Deterministic before AI** — rules run first; AI (when added) will only summarise, never control flow
3. **Engine independent from CLI** — the engine layer produces structured data; the CLI layer handles presentation

---

## Pipeline

```
┌─────────────┐     ┌──────────────┐     ┌──────────────────┐
│  Collectors │────▶│  Rule Engine │────▶│   Asset Graph    │
└─────────────┘     └──────────────┘     └──────────────────┘
                                                  │
                          ┌───────────────────────▼────────────────────┐
                          │   Correlation (risk chains + attack paths)  │
                          └───────────────────────┬────────────────────┘
                                                  │
                          ┌───────────────────────▼────────────────────┐
                          │    Policy filter (ApplyPolicy)              │
                          └───────────────────────┬────────────────────┘
                                                  │
                          ┌───────────────────────▼────────────────────┐
                          │    Output renderers (table/JSON/graph)      │
                          └────────────────────────────────────────────┘
```

### Step by step (Kubernetes audit)

1. **Collect** — `KubernetesProvider` calls the Kubernetes API and EKS API to collect nodes, namespaces, pods, services, service accounts, and EKS cluster metadata
2. **Convert** — raw provider data is mapped to `KubernetesClusterData` (engine-internal model); `annotateStructuralTopology` stamps pod labels, selectors, workload kind/name, and IRSA ARNs onto pod findings
3. **Evaluate** — the core rule registry (16 rules) and, when EKS is detected, the EKS rule registry (6 rules) run against `KubernetesClusterData`
4. **Asset Graph** — `BuildAssetGraph` converts the cluster inventory into a directed graph of real infrastructure relationships (Internet → LoadBalancer → Workload → ServiceAccount → IAMRole) using actual API-level data, not heuristics
5. **Correlate** — `correlateRiskChains` annotates findings that participate in compound risk chains; `buildAttackPaths` detects multi-layer attack paths using the dual detection/collection index
6. **Policy** — `ApplyPolicy` drops or re-severities findings per domain and rule config
7. **Sort** — findings sorted CRITICAL → HIGH → MEDIUM → LOW → INFO; ties by savings descending
8. **Render** — CLI dispatches to the appropriate renderer (table, JSON, risk chain table, explain, or graph)

---

## Package layout

```
cmd/dp/
  main.go          Entry point
  commands.go      Cobra commands, flag parsing, output dispatch

internal/engine/
  engine.go                  Engine interface, AuditOptions, AuditType
  kubernetes.go              KubernetesEngine: orchestration, convertClusterData,
                             annotateStructuralTopology, EngineContext, AssetGraph()
  kubernetes_correlation.go  correlateRiskChains, buildAttackPaths,
                             filterByMinRiskScore
  aws_cost.go                AWSCostEngine
  aws_security.go            AWSSecurityEngine
  aws_dataprotection.go      AWSDataProtectionEngine
  all_aws.go                 AllAWSDomainsEngine

internal/graph/
  types.go         NodeType, EdgeType, Node, Edge, Graph
  graph.go         NewGraph, AddNode, AddEdge, GetNode, Neighbors,
                   EdgesFrom, EdgesTo, HasEdge
  builder.go       BuildAssetGraph (cluster inventory → directed graph)

internal/providers/aws/
  common/          AWSClientProvider: profile loading, region discovery
  cost/            CostCollector: EC2, EBS, NAT, RDS, ELB, Savings Plan, Cost Explorer
  security/        SecurityCollector: S3, IAM, security groups, root account

internal/providers/kubernetes/
  models.go        PodInfo, ContainerInfo, NodeInfo, ServiceAccountInfo, …
  client.go        KubeClientProvider interface, DefaultKubeClientProvider
  collector.go     CollectClusterData, collectPods (resolves ownerReferences),
                   collectServiceAccounts (copies IRSA annotations)
  loader.go        LoadClientset: kubeconfig → clientset + ClusterInfo

internal/rules/
  rule.go                   Rule interface, RuleContext, RuleRegistry
  registry.go               DefaultRuleRegistry
  k8s_rules.go              Core Kubernetes rules
  k8s_pss_rules.go          Pod Security Standards rules (Phase 3A/3B)
  eks_rules.go              EKS governance rules (Phase 5A)
  eks_identity_rules.go     EKS identity rules (Phase 5B)
  aws_*.go                  AWS rules (cost, security, dataprotection)

internal/rulepacks/
  kubernetes_core/pack.go   16 core K8s rules
  kubernetes_eks/pack.go    6 EKS rules
  aws_cost/pack.go          8 cost rules
  aws_security/pack.go      8 security rules
  aws_dataprotection/pack.go 3 data protection rules

internal/render/
  explain.go             FindPathByScore, RenderAttackPathExplanation, WriteExplainJSON
  graph.go               BuildAttackGraph, RenderMermaidGraph, RenderGraphvizGraph
  min_attack_score.go    FilterAttackPaths

internal/models/
  findings.go      Severity, ResourceType, Finding, AuditSummary, AuditReport,
                   AttackPath, RiskChain
  aws.go           AWS raw data types
  aws_security.go  AWS security types
  kubernetes.go    KubernetesClusterData, KubernetesPodData, KubernetesServiceData, …

internal/policy/
  policy.go        PolicyConfig, DomainConfig, RuleConfig, EnforcementConfig, ApplyPolicy

internal/llm/
  (reserved for future AI summarisation)
```

---

## Asset Graph engine

The `internal/graph` package is an in-memory directed graph that models real infrastructure relationships — not findings or heuristics.

### Node types

| NodeType | Represents |
|----------|-----------|
| `Internet` | Conceptual external attacker entry point |
| `LoadBalancer` | Kubernetes Service of type LoadBalancer |
| `Workload` | Deployment, StatefulSet, DaemonSet, Job, CronJob, or ReplicaSet |
| `ServiceAccount` | Kubernetes ServiceAccount |
| `IAMRole` | AWS IAM role reachable via IRSA |
| `Namespace` | Kubernetes namespace (containment boundary) |
| `Cluster` | EKS cluster (control-plane resources) |
| `S3Bucket` | AWS S3 bucket accessible by an IAM role |
| `SecretsManagerSecret` | AWS Secrets Manager secret accessible by an IAM role |
| `DynamoDBTable` | AWS DynamoDB table accessible by an IAM role |
| `KMSKey` | AWS KMS key accessible by an IAM role |

### Edge types

| EdgeType | Meaning |
|----------|---------|
| `EXPOSES` | Internet → LoadBalancer (every LB-type Service) |
| `ROUTES_TO` | LoadBalancer → Workload (selector match) |
| `RUNS_AS` | Workload → ServiceAccount (pod.spec.serviceAccountName) |
| `ASSUMES_ROLE` | ServiceAccount → IAMRole (IRSA annotation) |
| `CONTAINS` | Namespace → Workload or Namespace → ServiceAccount |
| `CAN_ACCESS` | IAMRole → cloud resource (S3, Secrets Manager, DynamoDB, KMS) |

### Node ID format

IDs are consistent between `internal/graph/builder.go` and `internal/render/graph.go` so that asset graph edges can be used directly in attack graph rendering:

```
Internet            → "Internet"
LoadBalancer svc    → sanitize("LoadBalancer_" + svc.Name)
Deployment/app      → sanitize("Deployment_app")
ServiceAccount/sa   → sanitize("ServiceAccount_" + sa.Name)
IAMRole/app-role    → sanitize("IAMRole_app-role")
```

`sanitize` replaces any character that is not alphanumeric or `_` with `_`.

---

---

## Cloud Reachability (Phase 12)

The asset graph can be extended beyond Kubernetes topology into AWS cloud resources, enabling true end-to-end attack paths of the form:

```
Internet → LoadBalancer → Workload → ServiceAccount → IAMRole → S3Bucket / SecretsManagerSecret / …
```

### How it works

1. **IAM resolution** — `internal/providers/aws/iam.ResolveRoleResourceAccess` reads the attached managed policies and inline role policies for a given IAM role ARN using the AWS IAM API. It parses each `Allow` statement's `Action` and `Resource` fields, maps the service (s3, secretsmanager, dynamodb, kms) to a cloud resource type, extracts the resource name from the ARN, and returns a deduplicated `[]models.RoleCloudAccess`.

2. **Graph enrichment** — `graph.EnrichWithCloudAccess(g, roleAccess)` takes the resolved access map and, for each role ARN that has an `IAMRole` node in the graph, creates a resource node (`S3Bucket`, `SecretsManagerSecret`, etc.) and a `CAN_ACCESS` edge from the IAM role node to the resource node.

3. **Engine injection** — `KubernetesEngine.WithIAMResolver(resolver IAMAccessResolver)` injects the resolver. When set, `RunAudit` iterates every `IAMRole` node in the asset graph after graph construction, calls `ResolveRoleResourceAccess`, and enriches the graph. The resolver is optional; nil disables the feature.

### Wildcard handling

Policy resources containing `*` are skipped — it is not possible to enumerate actual resources from a wildcard grant without additional AWS API calls (e.g., `ListBuckets`). Only explicit ARNs are modelled as graph nodes.

### Non-fatal design

IAM resolution failures per role are silently ignored, consistent with the non-fatal pattern used for EKS data collection and asset graph construction. A single failing role never aborts the audit.

### Package structure

| Package | Responsibility |
|---------|---------------|
| `internal/providers/aws/iam` | `IAMAccessClient` interface, `DefaultIAMAccessClient`, `ResolveRoleResourceAccess` |
| `internal/models` | `CloudResourceType`, `RoleCloudAccess` (shared type between engine and provider) |
| `internal/graph` | `NodeTypeS3Bucket`, `NodeTypeSecretsManagerSecret`, `NodeTypeDynamoDBTable`, `NodeTypeKMSKey`, `EdgeTypeCanAccess`, `EnrichWithCloudAccess` |
| `internal/engine` | `IAMAccessResolver` interface, `iamResolver` field on `KubernetesEngine`, `WithIAMResolver` setter |

---

## EngineContext pattern

`KubernetesEngine` stores ancillary data produced during `RunAudit` in a `lastCtx EngineContext` field and exposes it via `AssetGraph() *graph.Graph`. This avoids changing the `RunAudit` return signature while making the asset graph available to the CLI for graph rendering.

```go
// In commands.go
ag := eng.AssetGraph()
g := render.BuildAttackGraph(report.Summary, report.Findings, ag)
```

When `assetGraph` is non-nil, `BuildAttackGraph` uses `HasEdge` / `EdgesFrom` for topology lookups. When nil, it falls back to finding metadata. The output is identical when both are built from the same cluster data.

---

## Design decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Offline-first | Rule engine has zero LLM dependency | Works in air-gapped clusters, CI, restricted environments |
| Deterministic before AI | Rules always run; AI never controls flow | Reproducible, auditable, testable findings |
| Engine independent from CLI | `RunAudit` returns `AuditReport`; CLI handles presentation | Engine can be embedded or called from a SaaS backend |
| Asset Graph separate from findings | `internal/graph` built from raw inventory, not findings | Graph is structurally accurate regardless of what rules fire |
| Dual detection/collection index | Detection expanded by merged rule IDs; collection primary-only | Merged findings trigger path conditions; finding_ids stay clean |
| Strict rule-scoped path filtering | Each path's finding_ids only contains allowed primary rule IDs | No contamination from co-located but unrelated findings |
| Workload-collapsed nodes | Pods resolved to parent workload via ownerReferences | Large clusters stay readable; N replicas → 1 node |
| Non-fatal asset graph build | `BuildAssetGraph` errors silently ignored in engine | Graph build failure never aborts the audit |

---

## See also

- [Kubernetes audit](kubernetes.md)
- [AWS audit](aws.md)
- [Troubleshooting](troubleshooting.md)
