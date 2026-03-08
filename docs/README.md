# DevOps Proxy — Documentation Index

This folder contains the detailed reference documentation for `dp`. The root [README](../README.md) is the quickstart; come here for depth.

---

## Contents

| File | What it covers |
|------|---------------|
| [aws.md](aws.md) | All three AWS audit commands — cost, security, dataprotection, and `--all`; every flag; rule reference tables |
| [kubernetes.md](kubernetes.md) | Kubernetes audit: all flags, namespace classification, risk chains, attack paths, explain mode, graph export |
| [policy.md](policy.md) | `dp.yaml` policy file — domains, rules, enforcement, threshold params, severity ordering |
| [outputs-and-ci.md](outputs-and-ci.md) | Output modes (`table`, `json`, `--summary`, `--file`), CI pipeline patterns, exit codes |
| [architecture.md](architecture.md) | Engine pipeline, Asset Graph, package layout, design decisions |
| [troubleshooting.md](troubleshooting.md) | Common errors and how to fix them |
| [security-and-permissions.md](security-and-permissions.md) | Minimum AWS IAM permissions and Kubernetes RBAC required to run `dp` |

---

## Quick links

- [Install dp](../README.md#installation)
- [Run your first audit](../README.md#60-second-quickstart)
- [Kubernetes attack paths](kubernetes.md#attack-paths)
- [Graph visualization](kubernetes.md#attack-path-graph-visualization)
- [Policy enforcement in CI](outputs-and-ci.md#ci-enforcement)
- [Required AWS permissions](security-and-permissions.md#aws-iam)
