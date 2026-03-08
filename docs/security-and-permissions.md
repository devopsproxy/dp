# Security and Permissions

This document describes the minimum AWS IAM permissions and Kubernetes RBAC rules required to run `dp` audit commands.

---

## AWS IAM

`dp` makes read-only API calls. No resources are created, modified, or deleted.

### Minimum IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2ReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeNatGateways",
        "ec2:DescribeLoadBalancers",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRegions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:GetMetricData"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CostExplorerReadOnly",
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage",
        "ce:GetSavingsPlansCoverage",
        "ce:GetReservationCoverage"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ELBReadOnly",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeTargetGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "RDSReadOnly",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3ReadOnly",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketEncryption",
        "s3:GetBucketLocation"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IAMReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ListAttachedRolePolicies",
        "iam:GetAccountPasswordPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudTrailReadOnly",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GuardDutyReadOnly",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:GetDetector"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ConfigReadOnly",
      "Effect": "Allow",
      "Action": [
        "config:DescribeConfigurationRecorderStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EKSReadOnly",
      "Effect": "Allow",
      "Action": [
        "eks:DescribeCluster",
        "eks:ListNodegroups",
        "eks:DescribeNodegroup"
      ],
      "Resource": "*"
    }
  ]
}
```

### What each section covers

| IAM section | `dp` feature |
|-------------|-------------|
| `EC2ReadOnly` | EC2 low CPU, EBS unattached/gp2/unencrypted, NAT traffic, security groups, region discovery |
| `CloudWatchReadOnly` | EC2 and RDS CPU metrics, ALB request counts |
| `CostExplorerReadOnly` | Per-instance cost data for savings estimates, Savings Plan coverage |
| `ELBReadOnly` | ALB idle detection |
| `RDSReadOnly` | RDS low CPU, RDS unencrypted |
| `S3ReadOnly` | S3 public access, S3 encryption checks |
| `IAMReadOnly` | Root account, IAM users without MFA, node role policy checks |
| `CloudTrailReadOnly` | CloudTrail multi-region trail check |
| `GuardDutyReadOnly` | GuardDuty enabled check |
| `ConfigReadOnly` | AWS Config recorder check |
| `EKSReadOnly` | EKS encryption, endpoint, logging, nodegroup IAM role checks |

### Optional — Cost Explorer

Cost Explorer requires explicit opt-in in the AWS console. If Cost Explorer is not enabled, `dp` will still run but savings estimates for EC2 and RDS will be based on defaults rather than real CE cost data.

### Multi-profile (`--all-profiles`)

Each profile in `~/.aws/config` must have credentials and the IAM policy above. `dp` audits each profile independently using its own credential chain.

---

## Kubernetes RBAC

`dp kubernetes audit` reads-only from the Kubernetes API. No mutations are performed.

### Minimum ClusterRole

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: dp-auditor
rules:
  - apiGroups: [""]
    resources:
      - nodes
      - namespaces
      - pods
      - services
      - serviceaccounts
    verbs: ["get", "list"]
  - apiGroups: ["apps"]
    resources:
      - replicasets
      - deployments
      - statefulsets
      - daemonsets
    verbs: ["get", "list"]
  - apiGroups: ["batch"]
    resources:
      - jobs
      - cronjobs
    verbs: ["get", "list"]
  - apiGroups: ["admissionregistration.k8s.io"]
    resources:
      - validatingadmissionpolicies
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dp-auditor-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: dp-auditor
subjects:
  - kind: User
    name: <your-user>
    apiGroup: rbac.authorization.k8s.io
```

### What each resource covers

| Resource | `dp` feature |
|----------|-------------|
| `nodes` | Node count, overallocation check |
| `namespaces` | Namespace classification, LimitRange checks |
| `pods` | Pod security rules (privileged, root, capabilities, seccomp), workload discovery via ownerReferences |
| `services` | Public LoadBalancer detection, service selector for attack graph edges |
| `serviceaccounts` | Default SA usage, token automount, IRSA annotation |
| `replicasets` | ownerReference chain resolution (Pod → ReplicaSet → Deployment) for workload-collapsed graph nodes |
| `deployments`, `statefulsets`, `daemonsets` | Workload kind resolution |
| `jobs`, `cronjobs` | Workload kind resolution |

### EKS — additional AWS credentials needed

EKS-specific rules (`EKS_*`) require AWS credentials in addition to Kubernetes RBAC. The EKS API calls are made using the standard AWS credential chain, not the Kubernetes kubeconfig. See the IAM section above for the required `eks:*` permissions.

---

## Credential storage

`dp` never stores credentials. It reads them at runtime from:
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`)
- `~/.aws/credentials` and `~/.aws/config`
- EC2/ECS/EKS instance metadata (when running on AWS)
- Kubeconfig at `~/.kube/config` or `$KUBECONFIG`

No credentials are written to disk, logged, or transmitted outside of the standard AWS/Kubernetes SDK request path.

---

## See also

- [Troubleshooting](troubleshooting.md)
- [AWS audit](aws.md)
- [Kubernetes audit](kubernetes.md)
