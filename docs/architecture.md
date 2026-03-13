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
| `Node` | Kubernetes worker node (EC2 instance); carries `provider_id` metadata |
| `ServiceAccount` | Kubernetes ServiceAccount |
| `IAMRole` | AWS IAM role (via IRSA annotation or EC2 instance profile) |
| `Namespace` | Kubernetes namespace (containment boundary) |
| `S3Bucket` | AWS S3 bucket accessible by an IAM role |
| `SecretsManagerSecret` | AWS Secrets Manager secret accessible by an IAM role |
| `DynamoDBTable` | AWS DynamoDB table accessible by an IAM role |
| `KMSKey` | AWS KMS key accessible by an IAM role |
| `SSMParameter` | AWS Systems Manager Parameter Store entry accessible by an IAM role |

### Asset graph topology

```
Internet
  ↓ EXPOSES
LoadBalancer
  ↓ ROUTES_TO
Workload ──── RUNS_ON ────▶ Node
  ↓ RUNS_AS                   ↓ ASSUMES_ROLE
ServiceAccount              IAMRole_A ── ASSUME_ROLE ──▶ IAMRole_B
  ↓ ASSUMES_ROLE                          ↓ CAN_ACCESS
IAMRole                     S3Bucket / SecretsManagerSecret / SSMParameter
```

Both identity chains are supported:

| Identity path | Edge sequence | Used when |
|--------------|---------------|-----------|
| **IRSA** | Workload → ServiceAccount → IAMRole | SA has `eks.amazonaws.com/role-arn` annotation |
| **Instance profile** | Workload → Node → IAMRole | Pods inherit the EC2 node's IAM role |
| **Cross-role escalation** | IAMRole_A → IAMRole_B (ASSUME_ROLE) | Source role's policies grant `sts:AssumeRole` on target |

### Edge types

| EdgeType | Meaning |
|----------|---------|
| `EXPOSES` | Internet → LoadBalancer (every LB-type Service) |
| `ROUTES_TO` | LoadBalancer → Workload (selector match) |
| `RUNS_AS` | Workload → ServiceAccount (pod.spec.serviceAccountName) |
| `RUNS_ON` | Workload → Node (pod.spec.nodeName); Phase 14 |
| `ASSUMES_ROLE` | ServiceAccount or Node → IAMRole (IRSA annotation or instance profile) |
| `ASSUME_ROLE` | IAMRole → IAMRole (sts:AssumeRole permission); Phase 16.1 |
| `CONTAINS` | Namespace → Workload or Namespace → ServiceAccount |
| `CAN_ACCESS` | IAMRole → cloud resource (S3, Secrets Manager, DynamoDB, KMS, SSM) |

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

---

## Graph Traversal Queries

The `internal/graph` package exposes read-only traversal operations that consume the asset graph without modifying rule findings, scores, or any engine state.

### Identity paths

`dp` models two distinct paths by which a workload can reach AWS cloud resources:

| Path | Edges | Used when |
|------|-------|-----------|
| **IRSA** (per-pod identity) | Workload → ServiceAccount → IAMRole → Cloud Resource | SA has `eks.amazonaws.com/role-arn` annotation |
| **Node instance profile** | Workload → Node → IAMRole → Cloud Resource | Pods inherit the EC2 node's IAM role (no IRSA configured) |

Both paths are modelled in the asset graph and traversed by `ComputeBlastRadius`.

- `BuildAssetGraph` creates `NodeTypeNode` nodes from `KubernetesClusterData.Nodes` and adds `RUNS_ON` edges (Workload → Node) based on `pod.NodeName`.
- `EnrichWithNodeRoles(g, nodeRoles)` adds `IAMRole` nodes and `ASSUMES_ROLE` edges (Node → IAMRole) using a map of node name → role ARN resolved by `NodeIAMRoleResolver`.
- The concrete resolver (`internal/providers/aws/ec2.ResolveNodeIAMRole`) calls `EC2 DescribeInstances` to extract the instance profile ARN and converts it to a role ARN.
- `NodeIAMRoleResolver` is an interface in the engine layer — the engine never imports the EC2 provider directly; the CLI or test injects the concrete implementation via `WithNodeRoleResolver`.

### Blast Radius (`blast.go`)

`ComputeBlastRadius(g *Graph, startNodeID string) (*BlastResult, error)` performs a BFS from a starting node, following only the attack-relevant edge subset:

| Edge type | Meaning |
|-----------|---------|
| `RUNS_AS` | Workload is bound to a ServiceAccount |
| `RUNS_ON` | Workload is scheduled on a Kubernetes Node (Phase 14) |
| `ASSUMES_ROLE` | ServiceAccount or Node has an IAM role (IRSA or instance profile) |
| `CAN_ACCESS` | IAM role's policies grant access to a cloud resource |

All other edge types (`EXPOSES`, `ROUTES_TO`, `CONTAINS`) are ignored — the traversal stays on the identity/access path, not the network path.

**Collection rules:**

- `IAMRole` nodes → `BlastResult.Identities`
- `S3Bucket`, `SecretsManagerSecret`, `DynamoDBTable`, `KMSKey` nodes → `BlastResult.Resources[NodeType]`
- Cloud resource nodes are treated as leaves and not enqueued for further traversal

**Node resolution from user input:**

`ResolveStartNode("deployment/platform-api")` → `sanitizeID("Deployment_platform-api")`

Supported kind prefixes: `deployment`, `statefulset`, `daemonset`, `job`, `cronjob`, `serviceaccount`.

**CLI command:**

```bash
dp blast-radius deployment/platform-api
dp blast-radius serviceaccount/api-sa --output json
```

The command runs `RunAudit` to build the asset graph, then traverses it — it does not evaluate any rules or apply policy.

---

## Graph Traversal Engine (`internal/graph/traversal`) — Phase 15.1

The `internal/graph/traversal` package provides a **reusable, algorithmic traversal engine** for the asset graph. It contains no business logic, no rule matching, and no scoring. Higher-level packages (`internal/engine`, `internal/graph/blast`) call it to discover paths and reachable nodes without implementing their own BFS/DFS loops.

### Package boundary

```
internal/graph           ← imported by traversal (one-way)
internal/graph/traversal ← imported by internal/engine
internal/graph/blast.go  ← keeps its own BFS (no circular dependency)
```

`blast.go` lives in `package graph` and cannot import `internal/graph/traversal` without a cycle. It retains its own BFS implementation unchanged.

### Core API

```go
// TraversalOptions configures which edge types are followed.
type TraversalOptions struct {
    AllowedEdgeTypes []graph.EdgeType  // empty = follow all
}

// TraversalResult represents one complete path from start to a leaf node.
type TraversalResult struct {
    Nodes []string  // ordered node IDs (start → leaf, inclusive)
    Edges []string  // "fromID→toID" per hop; len(Edges) == len(Nodes)-1
}

// TraverseFromNode enumerates all distinct paths via DFS.
// Cycle protection: a node may not appear twice in the same path.
// Paths of length zero (start node, no eligible neighbours) are not returned.
// Returns nil when startNodeID does not exist.
func TraverseFromNode(g *graph.Graph, startNodeID string, opts TraversalOptions) []TraversalResult

func GetNeighbors(g *graph.Graph, nodeID string) []string
func NodeType(g *graph.Graph, nodeID string) string

// FindSensitiveResources returns cloud resource nodes reachable from
// startNodeID via identity/access edges with sensitivity == "high".
// Results are sorted by Name ascending.
func FindSensitiveResources(g *graph.Graph, startNodeID string) []*graph.Node
```

### Graph-Based Attack Path Detection (`internal/engine/kubernetes_attack_paths.go`)

`FindGraphAttackPaths(g *graph.Graph) []GraphAttackPath` uses the traversal engine to discover attack paths from Internet-exposed entry points to sensitive cloud resource leaf nodes. This replaces static rule-pattern matching with dynamic graph topology analysis.

**Algorithm:**
1. Find all `NodeTypeInternet` nodes (attacker entry points).
2. Call `TraverseFromNode` with the full attacker-movement edge set: `EXPOSES`, `ROUTES_TO`, `RUNS_ON`, `RUNS_AS`, `ASSUMES_ROLE`, `CAN_ACCESS`.
3. Discard paths whose last node is not a cloud resource type.
4. Score each surviving path via `ScorePath`.
5. Return paths sorted by score descending.

**Path scoring (`ScorePath`)** — see also Phase 16.1 for updated maximum:

| Criterion | Score |
|-----------|-------|
| Path starts at Internet node | +40 |
| Path passes through a Workload node | +20 |
| Path passes through an IAM role | +20 |
| Path ends at a high-sensitivity cloud resource | +20 |
| ≥2 IAMRole nodes (cross-role escalation, Phase 16.1) | +10 |
| **Maximum** | **110** |

---

## Internet → Sensitive Data Attack Path Detection (Phase 16)

`dp` automatically detects attack paths where Internet exposure can reach sensitive cloud data through identity permissions. These paths are derived purely from the asset graph — no rule patterns, no findings required.

### Example path

```
Internet
 ↓  (EXPOSES)
LoadBalancer
 ↓  (ROUTES_TO)
Workload (Deployment/platform-api)
 ↓  (RUNS_ON)
Node (ip-10-0-1-1)
 ↓  (ASSUMES_ROLE)
IAMRole (node-role)
 ↓  (CAN_ACCESS)
S3Bucket (customer-data) [HIGH]
```

### Detection flow

`DetectCloudAttackPaths(g *graph.Graph) []models.CloudAttackPath` (in `internal/engine/cloud_attack_paths.go`) bridges the traversal engine and the audit summary:

1. Calls `FindGraphAttackPaths(g)` (Phase 15.1) which uses `TraverseFromNode` on all `NodeTypeInternet` nodes.
2. Discards paths whose final node is not a cloud resource (S3Bucket, SecretsManagerSecret, DynamoDBTable, KMSKey, SSMParameter).
3. Converts surviving `GraphAttackPath` values to `models.CloudAttackPath{Score, Source, Target, Nodes}`.
4. Returns the converted slice; nil when no qualifying paths exist.

Both identity chains are supported:

| Chain | Edge sequence |
|-------|--------------|
| **IRSA** | Workload → ServiceAccount → IAMRole → Cloud Resource |
| **Instance profile** | Workload → Node → IAMRole → Cloud Resource |

### Integration in RunAudit

Detection runs after both cloud reachability enrichment (Phase 12) and node role enrichment (Phase 14) so all `CAN_ACCESS` and `ASSUMES_ROLE` edges are present. Results are attached unconditionally to `AuditSummary.CloudAttackPaths` — they are not gated on `--show-risk-chains`.

### CLI output

**Table mode** — `CRITICAL ATTACK PATH` section printed before the findings table:

```
CRITICAL ATTACK PATH

Internet → LB_web-svc → Workload_platform-api → Node_ip-10-0-1-1 → Role_node-role → S3_customer-data
```

**JSON output** — `cloud_attack_paths` array in the summary:

```json
"cloud_attack_paths": [
  {
    "score": 100,
    "source": "Internet",
    "target": "S3_customer-data",
    "nodes": ["Internet", "LB_web-svc", "Workload_platform-api", "Node_ip-10-0-1-1", "Role_node-role", "S3_customer-data"]
  }
]
```

---

## IAM Privilege Escalation Path Detection (Phase 16.1)

Phase 16.1 extends the asset graph with cross-role escalation edges and upgrades path scoring to detect IAMRole → IAMRole privilege escalation chains.

### New edge type

`ASSUME_ROLE` (`EdgeTypeAssumeRole`) — an IAMRole node's policies grant `sts:AssumeRole` on a second IAMRole. Distinct from `ASSUMES_ROLE` (`EdgeTypeAssumesRole`) which represents a ServiceAccount or Node assuming a role.

### Detection flow

1. After cloud reachability and node role enrichment, `ResolveAssumableRoles(ctx, roleArn)` is called for each IAMRole node in the graph.
2. The resolver inspects attached managed policies and inline role policies for `Allow` statements containing `sts:AssumeRole` with non-wildcard IAM role ARN resources.
3. `graph.EnrichWithAssumeRoleEdges` adds `ASSUME_ROLE` edges between IAMRole nodes and creates target role nodes when not already present.
4. Traversal follows `ASSUME_ROLE` edges alongside all other attacker-movement edges; per-path cycle protection prevents infinite loops.

### Updated scoring

| Criterion | Score |
|-----------|-------|
| Internet node in path | +40 |
| Workload node in path | +20 |
| At least one IAMRole in path | +20 |
| Sensitive cloud resource (sensitivity=high) | +20 |
| **≥2 IAMRole nodes (cross-role escalation)** | **+10** |
| **Maximum** | **110** |

### Example escalation path

```
Internet → LB → Workload → SA → IAMRole_app-role --ASSUME_ROLE--> IAMRole_admin-role → S3_prod-data(high)
Score: 110 (all criteria + escalation bonus)
```

### Cycle protection

The traversal engine's `inPath` map prevents a node from appearing twice in the same DFS path. Bidirectional `ASSUME_ROLE` edges (Role A ↔ Role B) cannot produce infinite loops.

---

## Recent major features

| Version | Feature |
|---------|---------|
| **v0.13** | **Blast Radius** — `ComputeBlastRadius` BFS from any workload/SA to reachable IAM roles and cloud resources; `dp blast-radius` CLI command |
| **v0.14** | **Node Role Identity Path** — Workload → Node → IAMRole chain modelled in asset graph; `EnrichWithNodeRoles`; `NodeIAMRoleResolver` interface |
| **v0.15** | **Graph Traversal Engine** — `internal/graph/traversal` package; DFS path enumeration with cycle protection; `FindSensitiveResources`; `FindGraphAttackPaths`; `ScorePath` |
| **v0.16** | **Internet → Sensitive Data Attack Paths** — `DetectCloudAttackPaths`; `CloudAttackPath{Score, Source, Target, Nodes}` in `AuditSummary`; automatic CRITICAL ATTACK PATH output |
| **v0.16.1** | **IAM Privilege Escalation Paths** — `ASSUME_ROLE` edge (IAMRole → IAMRole); `ResolveAssumableRoles`; `EnrichWithAssumeRoleEdges`; ScorePath +10 bonus; max score = 110 |

---

## Explain Engine (Phase 17)

`internal/explain` generates human-readable descriptions for `CloudAttackPath`
instances. Two modes are supported:

| Mode | Function | Requires | Offline? |
|------|----------|----------|---------|
| Deterministic | `ExplainAttackPath(path)` | Nothing | Yes |
| AI-generated | `ExplainAttackPathAI(ctx, path)` | `DP_ANTHROPIC_API_KEY` or `DP_OPENAI_API_KEY` | No |

### Deterministic explanation

`ExplainAttackPath` parses each node ID by prefix (`LoadBalancer_`, `Deployment_`,
`Node_`, `ServiceAccount_`, `IAMRole_`, `S3Bucket_`, etc.) and emits a
per-node security sentence. The sentences are joined with spaces to produce a
complete path description. No network calls are made; the function is pure and
works in air-gapped environments.

### AI explanation

`ExplainAttackPathAI` sends a prompt to Anthropic (preferred) or OpenAI using
plain `net/http` — no external SDK dependencies are added. The prompt asks the
model to explain the attack path in 2–3 sentences for a developer audience.
AI calls are optional: `dp` runs fully offline when no key is configured.
A failed AI call is silently ignored; `AIExplanation` remains empty.

### CLI integration

`--ai-explain` flag on `dp kubernetes audit` enables AI explanations. Both
`Explanation` (deterministic) and `AIExplanation` (AI) are populated before
`writeReportToFile`, so they appear in JSON file output. The `renderCloudAttackPaths`
renderer prints `Explanation (AI):` when an AI explanation is available, falling
back to `Explanation:` for the deterministic text.

### Provider selection

`IsAIAvailable()` returns the preferred provider name and a boolean. Anthropic
(`DP_ANTHROPIC_API_KEY`) is preferred when both keys are present; OpenAI
(`DP_OPENAI_API_KEY`) is the fallback.

---

## Attack Path Prioritization (Phase 17.1)

Every `CloudAttackPath` carries a `Severity` classification derived from its
numeric score and a `HasSensitiveData` flag for blast-radius context.

### Severity thresholds

| Score range | Severity | Meaning |
|-------------|----------|---------|
| ≥ 90 | **CRITICAL** | Internet-reachable path to sensitive data; immediate action required |
| 70 – 89 | **HIGH** | Significant risk; missing one or more amplifying factors |
| < 70 | **MEDIUM** | Partial attack chain; lower overall impact |

Derived by `models.AttackPathSeverityFromScore(score)` in `internal/models/attack_paths.go`.

### Sort order

Paths are ordered by:
1. **Severity** ascending rank (CRITICAL first)
2. **Score** descending within severity
3. **Path length** ascending (shorter = more direct = higher risk) within the same score

### Sensitive data flag

`HasSensitiveData` is `true` when the target cloud resource node carries
`Metadata["sensitivity"] == "high"`. Set in `DetectCloudAttackPaths` by
inspecting the asset graph. Rendered as `[SENSITIVE]` on the target node line
in table output.

### CLI rendering

```
ATTACK PATH SUMMARY

  CRITICAL: 1
  HIGH: 2

CRITICAL ATTACK PATH (Score: 100)

Internet
 → LoadBalancer_kafka-ui
 → Deployment_platform-api
 → Node_ip-10-3-23-253
 → IAMRole_admin
 → S3Bucket_customer-data [SENSITIVE]

Explanation: Traffic enters from the Internet. ...
```

### JSON fields

```json
{
  "severity": "CRITICAL",
  "score": 100,
  "has_sensitive_data": true,
  "nodes": ["Internet", "LoadBalancer_kafka-ui", "..."]
}
```

---

## Node Role Identity Bridge

Kubernetes pods on EKS can reach AWS cloud resources in two ways:

1. **IRSA** (IAM Roles for Service Accounts) — a ServiceAccount annotation grants the
   pod permission to assume a named IAM role via OIDC federation.

2. **Instance profile** — the pod inherits the IAM permissions of the EC2 node it runs
   on via the node's attached instance profile role. No per-pod annotation required.

The node role path is the less visible of the two: no IRSA annotation in the pod spec,
no `eks.amazonaws.com/role-arn` on the ServiceAccount. But the blast radius can be
identical or larger, since every pod on the node shares the same role.

### Attack path

```
Internet → LoadBalancer → Deployment → Node → IAMRole → CloudResource
```

The graph encodes this via two edge types:

| Edge | From | To | Meaning |
|------|------|----|---------|
| `RUNS_ON` | Workload | Node | Pod(s) in the workload are scheduled on this node |
| `ASSUMES_ROLE` | Node | IAMRole | The node's EC2 instance profile grants access to this role |

Both edges are included in `attackPathEdges` (traversal) and `traversalEdgeSet`
(blast radius).

### Concrete resolver (`DefaultNodeRoleResolver`)

File: `internal/providers/aws/ec2/resolver.go`

`DefaultNodeRoleResolver` implements `engine.NodeIAMRoleResolver` using two AWS API calls:

1. **EC2 `DescribeInstances`** — extracts the `IamInstanceProfile.Arn` from the EC2
   instance identified by the node's `ProviderID`
   (e.g. `aws:///us-east-1a/i-0123456789abcdef0`).

2. **IAM `GetInstanceProfile`** — resolves the profile name to the ARN of the first
   attached `Role`. This is more accurate than the string-substitution heuristic
   (`:instance-profile/` → `:role/`) used in Phase 14 helpers, handling cases where
   the profile name and role name differ.

```go
resolver := ec2.NewDefaultNodeRoleResolver(ec2Client, iamClient)
eng.WithNodeRoleResolver(resolver)
```

The resolver is injected via `WithNodeRoleResolver` on `KubernetesEngine` and is
optional — when nil, node-role enrichment is silently skipped and only IRSA paths
are detected.

### Blast radius

`ComputeBlastRadius(g, deploymentID)` traverses `RUNS_ON` → `ASSUMES_ROLE` →
`CAN_ACCESS` edges, so the blast radius of a Deployment correctly includes cloud
resources reachable via the node's instance-profile role, even when IRSA is not used.

---

## Misconfiguration Bridging (Phase 18)

Phase 18 connects the rule-based finding engine with the asset graph so that
detected security misconfigurations become first-class nodes in the graph topology.
This allows the graph traversal engine to surface misconfigurations inside attack
paths, making them visible alongside the infrastructure nodes they amplify.

### How it works

After rule evaluation and finding annotation (`annotateStructuralTopology`),
the engine calls `EnrichWithFindings(graph, findings)`. This function iterates
the merged findings and injects `Misconfiguration` nodes into the asset graph
for supported rule IDs:

| Rule ID | Misconfiguration type | Attachment |
|---------|----------------------|------------|
| `K8S_SERVICE_PUBLIC_LOADBALANCER` | `PublicLoadBalancer` | `Internet → Misconfig` (EXPOSES); `LBNode → Misconfig` (AMPLIFIES) |
| `EKS_NODE_ROLE_OVERPERMISSIVE` | `WildcardIAMRole` | `IAMRole → Misconfig` (AMPLIFIES) for all IAM role nodes |
| `K8S_POD_RUN_AS_ROOT` / `K8S_PRIVILEGED_CONTAINER` / `K8S_POD_CAP_SYS_ADMIN` | `PrivilegedContainer` | `WorkloadNode → Misconfig` (AMPLIFIES) |

`DetectCloudAttackPaths` runs after `EnrichWithFindings` so the traversal
engine sees all Misconfiguration nodes. The `AMPLIFIES` edge type is included
in `attackPathEdges`, enabling traversal through Misconfiguration nodes.

### CLI rendering

Misconfiguration nodes in attack paths are rendered in human-readable form:

```
Internet
 → LoadBalancer_kafka-ui
 → PublicLoadBalancer (kafka-ui)   ← Misconfiguration node
 → Deployment_api
 → IAMRole_admin
 → S3Bucket_data [SENSITIVE]
```

### Design constraints

- Rule detection logic is never modified — `EnrichWithFindings` only reads findings
- Node injection is idempotent (first-write-wins in `graph.AddNode`)
- Edge injection is idempotent (`graph.AddEdge` deduplicates)
- `EnrichWithFindings` is a no-op when the asset graph is nil (graph build failure)
- Unrecognised rule IDs are silently ignored

---

## Risk Prioritization Engine

**`dp risk top`** — `internal/risk/analyzer.go`

`dp risk top` is dp's attack-path risk prioritization engine, similar to how
commercial CNAPP tools highlight the most dangerous paths instead of listing
hundreds of raw findings.

### Command

```
dp risk top [--context <kubeconfig-context>] [--top <N>]
```

The command reuses the existing Kubernetes audit pipeline to build the asset
graph and passes it to `risk.AnalyzeTopRisks`. No new data collection and no
rule-engine changes are needed.

### Detected toxic combinations

| Pattern | Nodes traversed | Score | Severity |
|---------|----------------|-------|---------|
| P1 | Internet → LB → **Workload** → **Node** | 70 | HIGH |
| P2 | Internet → LB → **Workload** → **IAMRole** | 80 | HIGH |
| P3 | Internet → LB → **Workload** → **IAMRole** → **CloudResource** | 130 | CRITICAL |
| P4 | **Workload** → **Node** → **IAMRole** (no Internet required) | 70 | HIGH |

### Scoring model

Each component present in a detected path contributes an additive weight:

| Component | Score |
|-----------|-------|
| Internet exposure | +40 |
| Node access | +30 |
| IAM role reachable | +40 |
| Cloud resource reachable | +50 |

Severity thresholds: ≥ 100 → CRITICAL · ≥ 70 → HIGH · ≥ 40 → MEDIUM.

### Design constraints

- `internal/risk` is a pure analysis package — no AWS API calls, no rule logic
- Uses only edges already present in the asset graph (`EXPOSES`, `ROUTES_TO`,
  `RUNS_ON`, `RUNS_AS`, `ASSUMES_ROLE`, `CAN_ACCESS`)
- Deduplication ensures each unique path appears once; sorted by score descending
- Nil graph returns nil (safe when no Kubernetes connection is available)

---

## Toxic Combination Engine

**Phase 19** — `internal/analysis/toxic.go`

The Toxic Combination Engine scans the asset graph for predefined high-risk
topology patterns that represent real-world exploit chains. It is distinct
from the attack path correlation layer (`buildAttackPaths`) — it operates
on graph structure rather than rule findings, and requires the asset graph
to be populated with cloud resource nodes (S3, Secrets Manager) via the
cloud reachability enrichment step (Phase 12).

### Predefined patterns

| # | Severity | Pattern | Description |
|---|----------|---------|-------------|
| 1 | CRITICAL | Internet → LB → Workload → Node → IAMRole → S3Bucket | Internet-exposed workload reaches S3 via node instance-profile (no IRSA isolation) |
| 2 | CRITICAL | Internet → LB → Workload → Node → IAMRole → SecretsManager | Same topology; target is a Secrets Manager secret |
| 3 | HIGH | Workload → ServiceAccount → IAMRole → SecretsManager | IRSA-bound workload can read secrets directly |

### Matching algorithm

Each pattern specifies a `startType` node and a `sequence` of `NodeType` values.
For each start node the traversal package enumerates all reachable paths
(`traversal.TraverseFromNode`) using `toxicEdgeTypes` (all attack path edges plus
`AMPLIFIES`). A path matches when its node type sequence contains the pattern
sequence as an **ordered subsequence** (gaps allowed for intermediate topology hops).

Matched results are deduplicated (same node IDs + same pattern = one entry) and
sorted CRITICAL-first, then HIGH; within each severity, alphabetically by path.

### Output

Toxic combinations are attached to `AuditSummary.ToxicCombinations []ToxicRisk`
(JSON: `summary.toxic_combinations`) and are always surfaced — they are not gated
on `--show-risk-chains`. In table mode they appear in a **TOXIC COMBINATIONS**
section before the findings table. Each line shows the severity and the ordered
human-readable path of node names:

```
TOXIC COMBINATIONS

  CRITICAL  Internet → kafka-ui → platform-api → ip-10-0-1-5 → eks-node-role → customer-data
  HIGH      billing → billing-sa → billing-role → api-key
```

### Design constraints

- No rule logic, no AWS API calls — pure graph topology analysis
- `toxicEdgeTypes` mirrors `attackPathEdges` plus `EdgeTypeAmplifies` so
  Misconfiguration nodes (Phase 18) are traversed
- Nil graph returns nil (no-op when cloud enrichment is unavailable)
- Deduplication ensures each unique matched chain appears at most once
- Pattern sequence uses ordered-subsequence matching, not strict contiguous match,
  to tolerate intermediate hops in real topologies

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
