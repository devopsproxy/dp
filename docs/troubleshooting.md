# Troubleshooting

---

## Environment diagnostics

Always start with `dp doctor`:

```bash
dp doctor
dp doctor --profile staging
dp doctor --format json
```

This checks:
- AWS credentials and STS identity
- Kubernetes connectivity and current context
- Policy file presence and validity

Exit 0 = all checks passed (missing policy file is OK — it is optional).
Exit 1 = AWS credentials failed, Kubernetes API unreachable, or policy file invalid.

---

## AWS issues

### `NoCredentialProviders` / `unable to load credentials`

`dp` uses the standard AWS credential chain: environment variables → `~/.aws/credentials` → EC2 instance profile.

```bash
# Check which credentials are active
aws sts get-caller-identity

# Use a named profile
dp aws audit cost --profile staging

# Verify dp doctor sees credentials
dp doctor --profile staging
```

### `AccessDeniedException` on specific APIs

`dp` needs read-only access to CloudWatch, Cost Explorer, EC2, RDS, S3, IAM, and optionally EKS and GuardDuty. See [security-and-permissions.md](security-and-permissions.md#aws-iam) for the minimum IAM policy.

### EKS rules missing / not evaluated

EKS rules are only evaluated when:
1. The audit is `dp kubernetes audit` (not `dp aws audit`)
2. The cluster is an EKS cluster (detected by the Kubernetes API server URL)
3. The EKS API call succeeds (failure is non-fatal and silently skipped)

If EKS rules are missing, check:
- AWS credentials are configured and have `eks:DescribeCluster` permission
- `--profile` matches the profile that owns the EKS cluster
- `dp doctor` shows credentials OK

### Cost Explorer returns no data

Cost Explorer data has a 24-hour delay. If you just created resources, try again tomorrow. The `--days` flag controls the lookback window (default 30).

### All regions collected when I only want one

Pass `--region` explicitly:

```bash
dp aws audit cost --region us-east-1
```

Without `--region`, `dp` auto-discovers all active regions.

---

## Kubernetes issues

### `unable to connect to the server`

Kubernetes connectivity check:

```bash
kubectl cluster-info --context <context>
dp doctor
```

Common causes:
- VPN not connected
- kubeconfig expired (EKS token, GKE OIDC)
- Wrong context: `kubectl config get-contexts`

Refresh EKS credentials:
```bash
aws eks update-kubeconfig --region us-east-1 --name <cluster-name> --profile <profile>
```

### `--context` flag has no effect

The context name must match exactly what appears in `kubectl config get-contexts`. Context names are case-sensitive.

### Findings from `kube-system` polluting results

Use `--exclude-system`:

```bash
dp kubernetes audit --exclude-system
```

This drops all findings with `namespace_type=system`.

### Risk chains not shown

`--show-risk-chains` must be set explicitly:

```bash
dp kubernetes audit --show-risk-chains
```

Without this flag, `attack_paths` and `risk_chains` are absent from JSON output and the table shows flat findings only.

### Attack paths not detected

Attack paths require specific combinations of findings. Check:
1. `--show-risk-chains` is set
2. The required rule IDs have fired (visible in the flat findings table)
3. The findings are in the correct scope (same namespace for per-namespace paths)

Use `--explain-path <score>` to investigate a specific path. If it returns "not found", the conditions were not met.

### `--explain-path` error: requires `--show-risk-chains`

```bash
# Wrong
dp kubernetes audit --explain-path 96

# Correct
dp kubernetes audit --show-risk-chains --explain-path 96
```

### Graph output is empty

`--attack-graph` renders the attack graph from findings in the current report. If no attack paths are detected, no graph is produced. Verify attack paths appear first:

```bash
dp kubernetes audit --show-risk-chains
dp kubernetes audit --show-risk-chains --attack-graph
```

---

## Policy issues

### Policy file not loaded

`dp.yaml` is auto-detected only in the **current working directory**. If running from a different directory, use `--policy`:

```bash
dp kubernetes audit --policy /path/to/dp.yaml
```

Validate the file without running an audit:

```bash
dp policy validate --policy ./dp.yaml
```

### Findings not being dropped by `min_severity`

Severity override (`rules.<ID>.severity`) is applied **before** `min_severity` filtering. A finding overridden to CRITICAL survives `min_severity: HIGH`.

Check the effective severity in the JSON output:

```bash
dp kubernetes audit --output json | jq '.findings[] | {rule_id, severity}'
```

### `enforcement.fail_on_severity` not triggering exit 1

Enforcement fires based on findings **after** policy filtering. If `min_severity` drops all HIGH findings, the enforcement threshold won't trigger. Also verify the domain key matches exactly (`kubernetes`, not `k8s`).

---

## JSON output issues

### `jq` reports invalid JSON / `parse error`

In table mode (default), `dp` prints header lines before the JSON. Use `--output json` for pure JSON:

```bash
# Wrong — table mode with jq
dp kubernetes audit | jq .

# Correct — pure JSON
dp kubernetes audit --output json | jq .
```

### JSON file contains only part of the report

`--file` always writes the **full** JSON report regardless of `--output` or `--summary`. The file is written atomically before stdout rendering begins.

---

## Build / installation issues

### `go build` fails

Requires Go 1.22+:

```bash
go version
# go version go1.22.x ...
```

### Binary reports `dev / none / unknown` version

This is expected for local builds. The release pipeline injects version, commit, and build date via `-ldflags`.

---

## See also

- [Required permissions](security-and-permissions.md)
- [Policy file reference](policy.md)
- [Output modes and CI](outputs-and-ci.md)
