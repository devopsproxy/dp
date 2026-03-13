package eks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/devopsproxy/dp/internal/models"
)

// DefaultEKSCollector implements EKSCollector using the AWS SDK v2.
// It loads AWS credentials from the default chain (env vars, ~/.aws/credentials,
// EC2 instance profile) — no explicit profile is needed because the EKS cluster
// name and region are derived from the nodes themselves.
type DefaultEKSCollector struct{}

// NewDefaultEKSCollector returns an EKSCollector backed by the real AWS SDK.
func NewDefaultEKSCollector() *DefaultEKSCollector {
	return &DefaultEKSCollector{}
}

// CollectEKSData calls eks.DescribeCluster and converts the response to
// models.KubernetesEKSData for rule evaluation.
func (d *DefaultEKSCollector) CollectEKSData(ctx context.Context, clusterName, region string) (*models.KubernetesEKSData, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("load AWS config for EKS region %q: %w", region, err)
	}
	return collectWithClient(ctx, awseks.NewFromConfig(cfg), awsiam.NewFromConfig(cfg), clusterName, region)
}

// collectWithClient is the testable core: it accepts injectable eksAPIClient and iamAPIClient.
func collectWithClient(ctx context.Context, eksClient eksAPIClient, iamClient iamAPIClient, clusterName, region string) (*models.KubernetesEKSData, error) {
	out, err := eksClient.DescribeCluster(ctx, &awseks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		return nil, fmt.Errorf("describe EKS cluster %q: %w", clusterName, err)
	}
	if out.Cluster == nil {
		return nil, fmt.Errorf("describe EKS cluster %q: empty response", clusterName)
	}

	data := &models.KubernetesEKSData{
		ClusterName: clusterName,
		Region:      region,
	}

	if out.Cluster.ResourcesVpcConfig != nil {
		data.EndpointPublicAccess = out.Cluster.ResourcesVpcConfig.EndpointPublicAccess
	}

	if out.Cluster.Logging != nil {
		for _, logConf := range out.Cluster.Logging.ClusterLogging {
			if logConf.Enabled != nil && *logConf.Enabled && len(logConf.Types) > 0 {
				data.LoggingEnabled = true
				for _, lt := range logConf.Types {
					data.LoggingTypes = append(data.LoggingTypes, string(lt))
				}
			}
		}
	}

	if len(out.Cluster.EncryptionConfig) > 0 {
		data.EncryptionEnabled = true
	}

	if out.Cluster.Identity != nil && out.Cluster.Identity.Oidc != nil {
		data.OIDCIssuer = aws.ToString(out.Cluster.Identity.Oidc.Issuer)
	}

	// Phase 5B: verify the IAM OIDC provider ARN (non-fatal; empty on failure).
	if iamClient != nil {
		data.OIDCProviderARN = collectOIDCProviderARN(ctx, iamClient, data.OIDCIssuer)
		data.NodeRolePolicies = collectNodeRoleOverpermissivePolicies(ctx, eksClient, iamClient, clusterName)
	}

	return data, nil
}

// ── Phase 5B helpers ──────────────────────────────────────────────────────────

// collectOIDCProviderARN looks up the IAM OIDC provider ARN matching the
// cluster's OIDC issuer URL. Returns empty string when the provider does not
// exist in IAM or the issuer URL is empty. All errors are treated as non-fatal.
func collectOIDCProviderARN(ctx context.Context, iamClient iamAPIClient, oidcIssuerURL string) string {
	if oidcIssuerURL == "" {
		return ""
	}
	// Strip https:// to get the bare URL embedded in the ARN.
	// ARN format: arn:aws:iam::{accountID}:oidc-provider/{providerURL}
	providerURL := strings.TrimPrefix(oidcIssuerURL, "https://")

	out, err := iamClient.ListOpenIDConnectProviders(ctx, &awsiam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return ""
	}
	for _, p := range out.OpenIDConnectProviderList {
		arn := aws.ToString(p.Arn)
		if strings.HasSuffix(arn, "/"+providerURL) {
			return arn
		}
	}
	return ""
}

// policyDocument is a minimal IAM policy document representation for
// wildcard-action detection.
type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Effect   string          `json:"Effect"`
	Action   json.RawMessage `json:"Action"`
	Resource json.RawMessage `json:"Resource"`
}

// hasWildcardAction returns true when the policy document contains at least one
// Allow statement where Action is "*" or includes "*".
func hasWildcardAction(doc policyDocument) bool {
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		// Try Action as a bare string.
		var actionStr string
		if err := json.Unmarshal(stmt.Action, &actionStr); err == nil {
			if actionStr == "*" {
				return true
			}
			continue
		}
		// Try Action as a string slice.
		var actionSlice []string
		if err := json.Unmarshal(stmt.Action, &actionSlice); err == nil {
			for _, a := range actionSlice {
				if a == "*" {
					return true
				}
			}
		}
	}
	return false
}

// collectNodeRoleOverpermissivePolicies iterates node groups for the cluster,
// resolves their IAM role, and returns the names of any overpermissive policies
// (AdministratorAccess attached policy, or inline policy with Action:"*").
// All errors are treated as non-fatal; an empty slice is returned on any failure.
func collectNodeRoleOverpermissivePolicies(ctx context.Context, eksClient eksAPIClient, iamClient iamAPIClient, clusterName string) []string {
	ngOut, err := eksClient.ListNodegroups(ctx, &awseks.ListNodegroupsInput{
		ClusterName: aws.String(clusterName),
	})
	if err != nil {
		return nil
	}

	seen := make(map[string]bool) // deduplicate by role name
	var overpermissive []string

	for _, ngName := range ngOut.Nodegroups {
		ngDesc, err := eksClient.DescribeNodegroup(ctx, &awseks.DescribeNodegroupInput{
			ClusterName:   aws.String(clusterName),
			NodegroupName: aws.String(ngName),
		})
		if err != nil || ngDesc.Nodegroup == nil {
			continue
		}

		roleARN := aws.ToString(ngDesc.Nodegroup.NodeRole)
		if roleARN == "" {
			continue
		}

		// Extract role name from ARN: arn:aws:iam::{accountID}:role/{roleName}
		parts := strings.Split(roleARN, "/")
		roleName := parts[len(parts)-1]
		if seen[roleName] {
			continue
		}
		seen[roleName] = true

		// Check attached managed policies for AdministratorAccess.
		attachedOut, err := iamClient.ListAttachedRolePolicies(ctx, &awsiam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(roleName),
		})
		if err == nil {
			for _, p := range attachedOut.AttachedPolicies {
				arn := aws.ToString(p.PolicyArn)
				name := aws.ToString(p.PolicyName)
				if strings.HasSuffix(arn, "/AdministratorAccess") {
					overpermissive = append(overpermissive, name)
				}
			}
		}

		// Check inline policies for wildcard actions.
		inlineOut, err := iamClient.ListRolePolicies(ctx, &awsiam.ListRolePoliciesInput{
			RoleName: aws.String(roleName),
		})
		if err != nil {
			continue
		}
		for _, policyName := range inlineOut.PolicyNames {
			getRoleOut, err := iamClient.GetRolePolicy(ctx, &awsiam.GetRolePolicyInput{
				RoleName:   aws.String(roleName),
				PolicyName: aws.String(policyName),
			})
			if err != nil {
				continue
			}
			// PolicyDocument is URL-encoded JSON.
			docJSON, err := url.QueryUnescape(aws.ToString(getRoleOut.PolicyDocument))
			if err != nil {
				continue
			}
			var doc policyDocument
			if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
				continue
			}
			if hasWildcardAction(doc) {
				overpermissive = append(overpermissive, policyName)
			}
		}
	}

	return overpermissive
}
