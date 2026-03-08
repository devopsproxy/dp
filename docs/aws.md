# AWS Audit Reference

`dp aws audit` runs deterministic rule-based audits against your AWS account(s). Three domains are available — cost, security, and dataprotection — plus a unified `--all` mode.

---

## Commands

| Command | What it checks |
|---------|---------------|
| `dp aws audit cost` | Idle/oversized EC2, RDS, EBS, NAT Gateways, ALBs; Savings Plan gaps |
| `dp aws audit security` | IAM, S3 public access, security groups, CloudTrail, GuardDuty, AWS Config |
| `dp aws audit dataprotection` | EBS, RDS, S3 encryption at rest |
| `dp aws audit --all` | All three domains in one command |

---

## Common flags (all audit commands)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Named AWS profile; omit for default credential chain |
| `--all-profiles` | bool | false | Audit every profile in `~/.aws/config` in parallel |
| `--region` | []string | nil | Explicit regions; omit to auto-discover active regions |
| `--output` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | false | Compact severity breakdown + top-5 findings |
| `--file` | string | `""` | Write full JSON report to this path (stdout unchanged) |
| `--policy` | string | `""` | Path to `dp.yaml`; auto-detected if `./dp.yaml` exists |

`--days` (lookback window, default 30) is available on `cost` and `--all`.

---

## `dp aws audit cost`

Checks for AWS spend waste using CloudWatch CPU metrics and Cost Explorer data.

```bash
# Default profile, table output
dp aws audit cost

# Named profile, JSON output
dp aws audit cost --profile staging --output json

# All profiles
dp aws audit cost --all-profiles

# Specific regions, 14-day lookback
dp aws audit cost --profile prod --region us-east-1 --region eu-west-1 --days 14

# Compact summary + save full JSON
dp aws audit cost --summary --file report.json
```

### Cost rules

| Rule ID | Trigger | Severity | Savings estimate |
|---------|---------|----------|-----------------|
| `EC2_LOW_CPU` | avg CPU > 0% and < 10% over lookback | MEDIUM | 30% of CE monthly cost |
| `EBS_UNATTACHED` | volume state == "available" | MEDIUM | SizeGB × $0.08/mo |
| `EBS_GP2_LEGACY` | volume type == "gp2" | LOW | SizeGB × $0.02/mo |
| `NAT_LOW_TRAFFIC` | BytesOutToDestination < 1 GB | HIGH | $32/mo (fixed) |
| `SAVINGS_PLAN_UNDERUTILIZED` | SP coverage < 60% and on-demand cost > $100 | HIGH/MEDIUM | 10% of on-demand cost |
| `RDS_LOW_CPU` | status == "available", avg CPU > 0% and < 10% | HIGH (< 5%) / MEDIUM | 30% of CE monthly cost |
| `ALB_IDLE` | active ALB with RequestCount == 0 over lookback | HIGH | ~$18/mo |
| `EC2_NO_SAVINGS_PLAN` | on-demand EC2 with zero SP coverage in region | HIGH | 20% of on-demand cost |

---

## `dp aws audit security`

```bash
dp aws audit security
dp aws audit security --profile staging --output json
dp aws audit security --all-profiles
dp aws audit security --region us-east-1 --summary
dp aws audit security --file security-report.json
```

### Security rules

| Rule ID | Trigger | Severity |
|---------|---------|----------|
| `ROOT_ACCESS_KEY` | Root account has ≥ 1 active access key | CRITICAL |
| `ROOT_ACCOUNT_MFA_DISABLED` | Root account MFA not enabled | CRITICAL |
| `CLOUDTRAIL_NOT_MULTI_REGION` | No multi-region CloudTrail trail | HIGH |
| `S3_PUBLIC_BUCKET` | `GetBucketPolicyStatus.IsPublic == true` | HIGH |
| `SG_OPEN_SSH` | Port 22 or 3389 open from 0.0.0.0/0 or ::/0 | HIGH |
| `GUARDDUTY_DISABLED` | GuardDuty detector not in ENABLED state | HIGH |
| `AWS_CONFIG_DISABLED` | AWS Config recorder not actively recording | HIGH |
| `IAM_USER_NO_MFA` | Console IAM user with no MFA device | MEDIUM |

---

## `dp aws audit dataprotection`

```bash
dp aws audit dataprotection
dp aws audit dataprotection --profile staging --output json
dp aws audit dataprotection --all-profiles
dp aws audit dataprotection --file dp-report.json
```

### Data protection rules

| Rule ID | Trigger | Severity |
|---------|---------|----------|
| `RDS_UNENCRYPTED` | `StorageEncrypted == false` | CRITICAL |
| `EBS_UNENCRYPTED` | `Encrypted == false` | HIGH |
| `S3_DEFAULT_ENCRYPTION_MISSING` | Bucket has no SSE configuration | HIGH |

---

## `dp aws audit --all`

Runs all three domains in one shot and returns a single merged report. Policy is applied per-domain before merge; findings for the same resource across domains are deduplicated (highest severity wins, savings summed).

```bash
dp aws audit --all
dp aws audit --all --profile staging --output json --file all-report.json
dp aws audit --all --all-profiles --summary
dp aws audit --all --region us-east-1 --region eu-west-1
dp aws audit --all --policy ./dp.yaml
```

**Additional flag for `--all`:**

| Flag | Default | Description |
|------|---------|-------------|
| `--all` | false | Enable unified mode (required) |
| `--days` | 30 | Lookback window for cost queries |

### Merging behaviour

| Scenario | Result |
|----------|--------|
| Same resource in cost and dataprotection | Single finding: highest severity, summed savings |
| Different resources across domains | Kept as separate findings |
| Policy per-domain | Applied inside each engine before global merge |
| Policy enforcement | Exit 1 if any domain triggers `fail_on_severity`; output printed first |
| `audit_type` in JSON | `"all"` |

### Example table output

```
Profile: default       Account: 123456789012  Regions: 3  Findings: 6  Est. Savings: $88.00/mo

RESOURCE ID                                REGION           SEVERITY    TYPE                  SAVINGS/MO
-------------------------------------------------------------------------------------------------------
123456789012                               global           CRITICAL    ROOT_ACCOUNT           $0.00
mydb-prod                                  us-east-1        CRITICAL    RDS_INSTANCE           $0.00
vol-0abc123                                us-east-1        HIGH        EBS_VOLUME             $8.00
my-public-bucket                           global           HIGH        S3_BUCKET              $0.00
```

---

## Multi-profile audits

When `--all-profiles` is set, `dp` reads every profile from `~/.aws/config` and fans out in parallel (up to 3 concurrent profiles). Each profile produces its own report section. Cost summaries are correctly aggregated across profiles.

```bash
dp aws audit cost --all-profiles --summary
dp aws audit --all --all-profiles --output json --file multi-profile.json
```

---

## See also

- [Policy file reference](policy.md)
- [Output modes and CI](outputs-and-ci.md)
- [Required AWS permissions](security-and-permissions.md#aws-iam)
