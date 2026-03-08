# Outputs and CI Integration

---

## Output modes

| Mode | How to invoke | What you get |
|------|--------------|--------------|
| Table (default) | *(no flag)* | Formatted table with header line |
| JSON | `--output json` | Pure JSON to stdout — no banners, no headers |
| Summary | `--summary` | Severity counts + top-5 findings by savings |
| File | `--file <path>` | Full JSON written to file; stdout output unchanged |

These flags are available on all audit commands.

---

## JSON mode

`--output json` produces **pure JSON to stdout** — safe to pipe directly to `jq`, `curl`, or a log aggregator.

```bash
dp aws audit cost --output json | jq '.summary'
dp kubernetes audit --output json | jq '.findings[] | select(.severity=="CRITICAL")'
```

**What JSON mode suppresses:**
- Table headers and column labels
- Summary lines and banner
- The stderr enforcement message `"audit completed with CRITICAL or HIGH findings"`

**What JSON mode does not suppress:**
- Exit code 1 (still raised unconditionally when CRITICAL or HIGH findings exist)

When `--summary` and `--output json` are both set, JSON mode takes priority.

---

## `--file` flag

Writes the full JSON report to a file **in addition to** the normal stdout output. The file always receives JSON regardless of `--output`.

```bash
# Table to stdout AND JSON saved to file
dp aws audit cost --file report.json

# JSON to stdout AND JSON saved to file (same content)
dp aws audit cost --output json --file report.json

# Summary to stdout AND JSON saved to file
dp aws audit cost --summary --file report.json
```

`--file` does not suppress stdout. Both destinations are always written.

---

## Summary mode

```bash
dp aws audit cost --summary
dp kubernetes audit --summary
```

Prints a compact block: total findings, severity breakdown, and top-5 findings by estimated savings. Suitable for quick terminal review without reading the full table.

Example:

```
Profile: default       Account: 123456789012  Regions: 3

Summary
  Total findings:    4
  CRITICAL:          0
  HIGH:              1
  MEDIUM:            2
  LOW:               1
  Est. savings:     $108.00/mo

Top findings (by savings):
  1. RDS_LOW_CPU — mydb-prod (us-east-1)  HIGH  $60.00/mo
  2. EC2_LOW_CPU — i-0a1b2c3d (us-east-1)  MEDIUM  $30.00/mo
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| **0** | Audit completed; no enforcement violation |
| **1** | CRITICAL or HIGH findings exist (unconditional), or policy `fail_on_severity` triggered |

Exit code 1 is raised **unconditionally** when CRITICAL or HIGH findings exist — regardless of whether a policy file is present. This is separate from policy enforcement.

When a policy file sets `fail_on_severity`, that threshold is also checked per domain. Multiple conditions can both independently produce exit code 1.

---

## CI enforcement

### Basic — fail on any HIGH+ finding

```bash
dp kubernetes audit
echo $?  # 1 if CRITICAL or HIGH findings exist
```

### With policy — domain-scoped thresholds

```bash
# dp.yaml:
# enforcement:
#   kubernetes:
#     fail_on_severity: HIGH

dp kubernetes audit --policy ./dp.yaml
echo $?  # 1 if kubernetes domain has HIGH+ findings
```

### JSON mode in CI — clean piping

```bash
dp aws audit security --policy ./dp.yaml --output json > report.json
# exit code still set; report.json contains clean JSON
```

### Kubernetes — exclude system namespace noise

```bash
dp kubernetes audit --exclude-system --policy ./dp.yaml
```

### Kubernetes — minimum attack score gate

```bash
# Fail only if an attack path with score >= 95 exists
# Note: exit code 1 fires on HIGH+; --min-attack-score only filters rendered paths
dp kubernetes audit --show-risk-chains --min-attack-score 95 --policy ./dp.yaml
```

---

## Enforcement timing

Policy enforcement fires **after all output is produced**:

1. Full report written to `--file` (if set)
2. stdout rendered (table, JSON, or summary)
3. Enforcement checked → exit code set

This means the report is always available even when the command exits 1.

**Enforcement is skipped entirely in these modes:**
- `--explain-path` — exits 0 after rendering the explanation
- `--attack-graph` — exits 0 after rendering the graph

---

## JSON report structure

```json
{
  "report_id": "audit-1740000000000000000",
  "audit_type": "kubernetes",
  "summary": {
    "total_findings": 4,
    "critical_findings": 1,
    "high_findings": 2,
    "medium_findings": 1,
    "low_findings": 0,
    "total_estimated_monthly_savings_usd": 0,
    "risk_score": 96,
    "attack_paths": [...],
    "risk_chains": [...]
  },
  "findings": [
    {
      "id": "K8S_SERVICE_PUBLIC_LOADBALANCER:web-svc",
      "rule_id": "K8S_SERVICE_PUBLIC_LOADBALANCER",
      "resource_id": "web-svc",
      "resource_type": "K8S_SERVICE",
      "severity": "HIGH",
      "explanation": "...",
      "recommendation": "...",
      "metadata": {
        "namespace": "prod",
        "namespace_type": "workload",
        "risk_chain_score": 80,
        "risk_chain_reason": "Public service exposes privileged workload"
      }
    }
  ]
}
```

`attack_paths` and `risk_chains` are present only when `--show-risk-chains` is set. Both use `omitempty` so they are absent from the JSON when empty.

---

## See also

- [Policy file reference](policy.md)
- [AWS audit](aws.md)
- [Kubernetes audit](kubernetes.md)
