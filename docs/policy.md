# Policy File Reference (`dp.yaml`)

The policy file lets you customize `dp` behaviour — suppressing noise, escalating severities, and enforcing CI exit codes — **without changing any rule logic**.

---

## How it works

The policy layer sits between rule evaluation and output:

```
Collect → Evaluate → Merge → ApplyPolicy → Sort → Summary → Output
```

Rules run first with their default severities. Policy then:
1. Drops findings below a per-domain `min_severity` threshold
2. Overrides severities for specific rules
3. Disables rules entirely
4. Adjusts rule thresholds via `params`
5. Enforces exit code 1 when findings at or above `fail_on_severity` are present

---

## File format

```yaml
version: 1

domains:
  cost:
    enabled: true        # set false to suppress ALL cost findings
    min_severity: HIGH   # drop findings with final severity below HIGH
  security:
    enabled: true
    min_severity: MEDIUM
  dataprotection:
    enabled: true
  kubernetes:
    enabled: true
    min_severity: HIGH

rules:
  EC2_LOW_CPU:
    enabled: false            # silence this rule entirely
    params:
      cpu_threshold: 15.0    # raise threshold from default 10% to 15%
  SG_OPEN_SSH:
    severity: CRITICAL        # escalate from HIGH to CRITICAL
  NAT_LOW_TRAFFIC:
    params:
      traffic_gb_threshold: 2.0  # raise threshold from default 1 GB

enforcement:
  cost:
    fail_on_severity: HIGH       # exit 1 if any cost finding is HIGH or above
  security:
    fail_on_severity: CRITICAL   # exit 1 only for CRITICAL security findings
  dataprotection:
    fail_on_severity: HIGH
  kubernetes:
    fail_on_severity: HIGH
```

---

## Domains

| Key | Available domains |
|-----|------------------|
| `domains.<name>.enabled` | `cost`, `security`, `dataprotection`, `kubernetes` |
| `domains.<name>.min_severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |

Setting `enabled: false` drops **all** findings for that domain, before any other processing.

`min_severity` drops findings whose **final** severity (after any severity override) is below the threshold. Severity ordering: `CRITICAL > HIGH > MEDIUM > LOW > INFO`.

---

## Rules

### `enabled: false`

Silences a specific rule. The rule still runs internally; its findings are dropped before output.

```yaml
rules:
  K8S_DEFAULT_SERVICEACCOUNT_USED:
    enabled: false
```

### `severity: <level>`

Overrides the finding's severity. The override is applied **before** `min_severity` filtering, so a MEDIUM finding overridden to CRITICAL will survive a `min_severity: HIGH` filter.

```yaml
rules:
  SG_OPEN_SSH:
    severity: CRITICAL
```

### `params`

Adjusts rule-specific numeric thresholds. Only the rules below support params:

| Rule ID | Param key | Default |
|---------|-----------|---------|
| `EC2_LOW_CPU` | `cpu_threshold` | `10.0` |
| `RDS_LOW_CPU` | `cpu_threshold` | `10.0` |
| `NAT_LOW_TRAFFIC` | `traffic_gb_threshold` | `1.0` |

```yaml
rules:
  EC2_LOW_CPU:
    params:
      cpu_threshold: 15.0
```

---

## Enforcement

```yaml
enforcement:
  cost:
    fail_on_severity: HIGH
```

When `fail_on_severity` is set for a domain, `dp` exits with code 1 if any finding in that domain has severity **at or above** the threshold.

**Output is always printed before enforcement fires.** JSON report is written, table/summary rendered, then the exit code is checked.

**In JSON mode (`--output json`)**, the stderr message `"audit completed with CRITICAL or HIGH findings"` is suppressed to keep stdout clean for piping. The exit code is still set.

**In explain mode (`--explain-path`) and graph mode (`--attack-graph`)**, policy enforcement is skipped entirely — these modes exit 0.

---

## Behaviour summary

| Scenario | Result |
|----------|--------|
| No policy file | Default behaviour — all findings, rule-defined severities |
| `domains.cost.enabled: false` | All cost findings dropped |
| `domains.cost.min_severity: HIGH` | MEDIUM/LOW/INFO cost findings dropped |
| `rules.EC2_LOW_CPU.enabled: false` | All `EC2_LOW_CPU` findings dropped |
| `rules.SG_OPEN_SSH.severity: CRITICAL` | Finding severity replaced with CRITICAL |
| Severity override + min_severity | Override applied first, then min_severity filter |
| `enforcement.cost.fail_on_severity: HIGH` | Exit 1 if any cost finding is HIGH or CRITICAL |
| Rule not listed in policy | Pass through unchanged |

---

## Auto-detection

Place `dp.yaml` in the working directory for automatic detection — no `--policy` flag needed:

```bash
# Auto-detected
dp kubernetes audit

# Explicit path
dp kubernetes audit --policy ./ci/dp-policy.yaml
```

---

## Integration status

| Engine | `--policy` flag | `ApplyPolicy` called | Domain key |
|--------|-----------------|---------------------|------------|
| `dp aws audit cost` | ✅ | ✅ | `"cost"` |
| `dp aws audit security` | ✅ | ✅ | `"security"` |
| `dp aws audit dataprotection` | ✅ | ✅ | `"dataprotection"` |
| `dp aws audit --all` | ✅ | ✅ per domain | `"cost"`, `"security"`, `"dataprotection"` |
| `dp kubernetes audit` | ✅ | ✅ | `"kubernetes"` |

---

## Validate without running an audit

```bash
dp policy validate --policy ./dp.yaml
```

Checks file syntax and field validity. Exits 0 on success, 1 on error.

---

## See also

- [Output modes and CI](outputs-and-ci.md)
- [AWS audit](aws.md)
- [Kubernetes audit](kubernetes.md)
