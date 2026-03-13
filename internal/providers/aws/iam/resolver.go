// Package iam provides a resolver that analyzes IAM role policies to determine
// which AWS cloud resources (S3, Secrets Manager, DynamoDB, KMS) a role can
// access. The resolved data is consumed by internal/graph.EnrichWithCloudAccess
// to extend the asset graph with cloud reachability edges (Phase 12).
package iam

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/devopsproxy/dp/internal/models"
)

// IAMAccessClient is the narrow AWS IAM API surface required by
// ResolveRoleResourceAccess. Implemented by DefaultIAMAccessClient (real AWS
// client) or a test double.
type IAMAccessClient interface {
	ListAttachedRolePolicies(ctx context.Context, params *awsiam.ListAttachedRolePoliciesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListAttachedRolePoliciesOutput, error)
	GetPolicy(ctx context.Context, params *awsiam.GetPolicyInput, optFns ...func(*awsiam.Options)) (*awsiam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *awsiam.GetPolicyVersionInput, optFns ...func(*awsiam.Options)) (*awsiam.GetPolicyVersionOutput, error)
	ListRolePolicies(ctx context.Context, params *awsiam.ListRolePoliciesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *awsiam.GetRolePolicyInput, optFns ...func(*awsiam.Options)) (*awsiam.GetRolePolicyOutput, error)
}

// DefaultIAMAccessClient wraps an *awsiam.Client to satisfy IAMAccessClient.
type DefaultIAMAccessClient struct {
	client *awsiam.Client
}

// NewDefaultIAMAccessClient constructs a DefaultIAMAccessClient from an AWS SDK
// IAM client. Callers obtain the *awsiam.Client from an aws.Config loaded via
// the common AWSClientProvider.
func NewDefaultIAMAccessClient(client *awsiam.Client) *DefaultIAMAccessClient {
	return &DefaultIAMAccessClient{client: client}
}

func (c *DefaultIAMAccessClient) ListAttachedRolePolicies(ctx context.Context, params *awsiam.ListAttachedRolePoliciesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListAttachedRolePoliciesOutput, error) {
	return c.client.ListAttachedRolePolicies(ctx, params, optFns...)
}
func (c *DefaultIAMAccessClient) GetPolicy(ctx context.Context, params *awsiam.GetPolicyInput, optFns ...func(*awsiam.Options)) (*awsiam.GetPolicyOutput, error) {
	return c.client.GetPolicy(ctx, params, optFns...)
}
func (c *DefaultIAMAccessClient) GetPolicyVersion(ctx context.Context, params *awsiam.GetPolicyVersionInput, optFns ...func(*awsiam.Options)) (*awsiam.GetPolicyVersionOutput, error) {
	return c.client.GetPolicyVersion(ctx, params, optFns...)
}
func (c *DefaultIAMAccessClient) ListRolePolicies(ctx context.Context, params *awsiam.ListRolePoliciesInput, optFns ...func(*awsiam.Options)) (*awsiam.ListRolePoliciesOutput, error) {
	return c.client.ListRolePolicies(ctx, params, optFns...)
}
func (c *DefaultIAMAccessClient) GetRolePolicy(ctx context.Context, params *awsiam.GetRolePolicyInput, optFns ...func(*awsiam.Options)) (*awsiam.GetRolePolicyOutput, error) {
	return c.client.GetRolePolicy(ctx, params, optFns...)
}

// ── Policy document parsing types ─────────────────────────────────────────────

// policyDocument is a decoded IAM policy JSON document.
type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

// policyStatement is a single statement in an IAM policy document.
// Action and Resource are each either a JSON string or a JSON array of strings.
type policyStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
}

// ── Service → resource type mapping ───────────────────────────────────────────

// serviceResourceType maps IAM action service prefixes (lowercase) to the
// corresponding CloudResourceType. Only the four supported services are listed.
var serviceResourceType = map[string]models.CloudResourceType{
	"s3":             models.CloudResourceTypeS3Bucket,
	"secretsmanager": models.CloudResourceTypeSecretsManagerSecret,
	"dynamodb":       models.CloudResourceTypeDynamoDBTable,
	"kms":            models.CloudResourceTypeKMSKey,
}

// ── ResolveRoleResourceAccess ──────────────────────────────────────────────────

// ResolveRoleResourceAccess analyzes the IAM policies attached to roleArn and
// returns the set of concrete AWS resources the role has permission to access.
//
// Both attached (managed) policies and inline role policies are inspected.
// Only Allow statements are considered; Deny statements are not modelled.
// Wildcard resource ARNs ("*" or "arn:aws:s3:::*") are skipped — individual
// resource names cannot be enumerated from a wildcard.
//
// Errors from individual policy API calls are silently ignored so that a single
// inaccessible policy does not abort the entire resolution. The function returns
// a non-nil slice (possibly empty) and a nil error in the normal case; a non-nil
// error only when roleArn is unparseable.
func ResolveRoleResourceAccess(ctx context.Context, roleArn string, client IAMAccessClient) ([]models.RoleCloudAccess, error) {
	roleName := extractRoleName(roleArn)
	if roleName == "" {
		return nil, nil
	}

	seen := make(map[string]bool)
	var accesses []models.RoleCloudAccess

	addAccess := func(a models.RoleCloudAccess) {
		key := string(a.ResourceType) + "/" + a.ResourceName
		if seen[key] {
			return
		}
		seen[key] = true
		accesses = append(accesses, a)
	}

	// ── Attached (managed) policies ───────────────────────────────────────────
	attachedOut, err := client.ListAttachedRolePolicies(ctx, &awsiam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err == nil {
		for _, p := range attachedOut.AttachedPolicies {
			if p.PolicyArn == nil {
				continue
			}
			// Get default version ID.
			policyOut, err := client.GetPolicy(ctx, &awsiam.GetPolicyInput{
				PolicyArn: p.PolicyArn,
			})
			if err != nil || policyOut.Policy == nil || policyOut.Policy.DefaultVersionId == nil {
				continue
			}
			// Get policy version document (URL-encoded JSON).
			versionOut, err := client.GetPolicyVersion(ctx, &awsiam.GetPolicyVersionInput{
				PolicyArn: p.PolicyArn,
				VersionId: policyOut.Policy.DefaultVersionId,
			})
			if err != nil || versionOut.PolicyVersion == nil || versionOut.PolicyVersion.Document == nil {
				continue
			}
			doc, err := url.QueryUnescape(*versionOut.PolicyVersion.Document)
			if err != nil {
				continue
			}
			for _, a := range parsePolicyDocument(doc) {
				addAccess(a)
			}
		}
	}

	// ── Inline policies ───────────────────────────────────────────────────────
	inlineOut, err := client.ListRolePolicies(ctx, &awsiam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err == nil {
		for _, pName := range inlineOut.PolicyNames {
			pNameCopy := pName
			getRoleOut, err := client.GetRolePolicy(ctx, &awsiam.GetRolePolicyInput{
				RoleName:   &roleName,
				PolicyName: &pNameCopy,
			})
			if err != nil || getRoleOut.PolicyDocument == nil {
				continue
			}
			doc, err := url.QueryUnescape(*getRoleOut.PolicyDocument)
			if err != nil {
				continue
			}
			for _, a := range parsePolicyDocument(doc) {
				addAccess(a)
			}
		}
	}

	return accesses, nil
}

// ── ResolveAssumableRoles ──────────────────────────────────────────────────────

// ResolveAssumableRoles analyzes the IAM policies attached to roleArn and
// returns the set of IAM roles the source role can assume via sts:AssumeRole.
//
// Both attached (managed) policies and inline role policies are inspected.
// Only Allow statements containing an sts:AssumeRole action are considered.
// Wildcard resource ARNs ("*") are skipped — individual target role ARNs cannot
// be enumerated from a wildcard. Policy API errors are silently ignored.
func ResolveAssumableRoles(ctx context.Context, roleArn string, client IAMAccessClient) ([]models.AssumableRole, error) {
	roleName := extractRoleName(roleArn)
	if roleName == "" {
		return nil, nil
	}

	seen := make(map[string]bool)
	var assumable []models.AssumableRole

	addRole := func(arn string) {
		if arn == "" || arn == "*" || seen[arn] {
			return
		}
		seen[arn] = true
		assumable = append(assumable, models.AssumableRole{
			ARN:      arn,
			RoleName: extractRoleName(arn),
		})
	}

	// ── Attached (managed) policies ───────────────────────────────────────────
	attachedOut, err := client.ListAttachedRolePolicies(ctx, &awsiam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err == nil {
		for _, p := range attachedOut.AttachedPolicies {
			if p.PolicyArn == nil {
				continue
			}
			policyOut, err := client.GetPolicy(ctx, &awsiam.GetPolicyInput{PolicyArn: p.PolicyArn})
			if err != nil || policyOut.Policy == nil || policyOut.Policy.DefaultVersionId == nil {
				continue
			}
			versionOut, err := client.GetPolicyVersion(ctx, &awsiam.GetPolicyVersionInput{
				PolicyArn: p.PolicyArn,
				VersionId: policyOut.Policy.DefaultVersionId,
			})
			if err != nil || versionOut.PolicyVersion == nil || versionOut.PolicyVersion.Document == nil {
				continue
			}
			doc, err := url.QueryUnescape(*versionOut.PolicyVersion.Document)
			if err != nil {
				continue
			}
			for _, arn := range parseAssumeRoleTargets(doc) {
				addRole(arn)
			}
		}
	}

	// ── Inline policies ───────────────────────────────────────────────────────
	inlineOut, err := client.ListRolePolicies(ctx, &awsiam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err == nil {
		for _, pName := range inlineOut.PolicyNames {
			pNameCopy := pName
			getRoleOut, err := client.GetRolePolicy(ctx, &awsiam.GetRolePolicyInput{
				RoleName:   &roleName,
				PolicyName: &pNameCopy,
			})
			if err != nil || getRoleOut.PolicyDocument == nil {
				continue
			}
			doc, err := url.QueryUnescape(*getRoleOut.PolicyDocument)
			if err != nil {
				continue
			}
			for _, arn := range parseAssumeRoleTargets(doc) {
				addRole(arn)
			}
		}
	}

	return assumable, nil
}

// parseAssumeRoleTargets extracts IAM role ARNs from Allow statements that
// contain an sts:AssumeRole action. Returns nil when no such statements exist.
func parseAssumeRoleTargets(doc string) []string {
	var pd policyDocument
	if err := json.Unmarshal([]byte(doc), &pd); err != nil {
		return nil
	}
	var arns []string
	for _, stmt := range pd.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		actions := toStringSlice(stmt.Action)
		hasAssumeRole := false
		for _, a := range actions {
			if strings.EqualFold(a, "sts:AssumeRole") || a == "*" {
				hasAssumeRole = true
				break
			}
		}
		if !hasAssumeRole {
			continue
		}
		for _, res := range toStringSlice(stmt.Resource) {
			if res != "" && res != "*" && strings.HasPrefix(res, "arn:aws:iam:") {
				arns = append(arns, res)
			}
		}
	}
	return arns
}

// ── Internal helpers ───────────────────────────────────────────────────────────

// parsePolicyDocument decodes a JSON IAM policy document and extracts concrete
// resource accesses from Allow statements. Returns nil when the document is
// unparseable or contains no supported resource entries.
func parsePolicyDocument(doc string) []models.RoleCloudAccess {
	var pd policyDocument
	if err := json.Unmarshal([]byte(doc), &pd); err != nil {
		return nil
	}
	var accesses []models.RoleCloudAccess
	for _, stmt := range pd.Statement {
		if !strings.EqualFold(stmt.Effect, "Allow") {
			continue
		}
		actions := toStringSlice(stmt.Action)
		resources := toStringSlice(stmt.Resource)
		for _, action := range actions {
			svc := actionService(action)
			if svc == "" {
				continue
			}
			rt, ok := serviceResourceType[svc]
			if !ok {
				continue
			}
			for _, res := range resources {
				name, arn := extractResourceInfo(svc, res)
				if name == "" || name == "*" {
					continue // skip wildcards
				}
				accesses = append(accesses, models.RoleCloudAccess{
					ResourceType: rt,
					ResourceName: name,
					ARN:          arn,
				})
			}
		}
	}
	return accesses
}

// actionService returns the lowercase service prefix of an IAM action string
// (e.g. "s3:GetObject" → "s3", "secretsmanager:GetSecretValue" → "secretsmanager").
// Returns "" for malformed or wildcard-only actions.
func actionService(action string) string {
	if action == "*" {
		return ""
	}
	idx := strings.IndexByte(action, ':')
	if idx < 0 {
		return ""
	}
	return strings.ToLower(action[:idx])
}

// extractResourceInfo parses a resource ARN for the given service and returns
// (resourceName, arn). Returns ("", "") when the ARN is a wildcard or empty.
//
// ARN formats handled:
//
//	s3             arn:aws:s3:::bucket-name[/...]
//	secretsmanager arn:aws:secretsmanager:region:account:secret:name[-suffix]
//	dynamodb       arn:aws:dynamodb:region:account:table/name
//	kms            arn:aws:kms:region:account:key/key-id
func extractResourceInfo(svc, arn string) (name, fullARN string) {
	if arn == "" || arn == "*" {
		return "", ""
	}
	switch svc {
	case "s3":
		// arn:aws:s3:::bucket-name  or  arn:aws:s3:::bucket-name/prefix
		const prefix = "arn:aws:s3:::"
		if !strings.HasPrefix(arn, prefix) {
			// bare bucket name without ARN prefix
			bucket := strings.SplitN(arn, "/", 2)[0]
			if bucket == "*" {
				return "", ""
			}
			return bucket, arn
		}
		rest := arn[len(prefix):]
		bucket := strings.SplitN(rest, "/", 2)[0]
		if bucket == "" || bucket == "*" {
			return "", ""
		}
		return bucket, "arn:aws:s3:::" + bucket
	case "secretsmanager":
		// last colon-separated segment: secret name may include a random suffix
		parts := strings.Split(arn, ":")
		if len(parts) < 7 {
			return "", ""
		}
		n := parts[len(parts)-1]
		if n == "" || n == "*" {
			return "", ""
		}
		return n, arn
	case "dynamodb":
		// arn:aws:dynamodb:...:table/name
		if idx := strings.LastIndex(arn, "/"); idx >= 0 {
			n := arn[idx+1:]
			if n == "" || n == "*" {
				return "", ""
			}
			return n, arn
		}
		return "", ""
	case "kms":
		// arn:aws:kms:...:key/key-id
		if idx := strings.LastIndex(arn, "/"); idx >= 0 {
			n := arn[idx+1:]
			if n == "" || n == "*" {
				return "", ""
			}
			return n, arn
		}
		return "", ""
	}
	return "", ""
}

// toStringSlice normalises an IAM policy Action or Resource field, which the
// AWS API may encode as either a JSON string or a JSON array of strings,
// into a []string.
func toStringSlice(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// extractRoleName returns the role name component from an IAM role ARN.
// For "arn:aws:iam::123456789012:role/app-role" it returns "app-role".
// Falls back to the full string when no slash is present.
func extractRoleName(arn string) string {
	if idx := strings.LastIndex(arn, "/"); idx >= 0 {
		return arn[idx+1:]
	}
	return arn
}
