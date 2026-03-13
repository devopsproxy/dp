// Package ec2 — resolver.go
//
// DefaultNodeRoleResolver is the concrete implementation of
// engine.NodeIAMRoleResolver. It resolves the IAM role attached to a
// Kubernetes worker node by combining two AWS API calls:
//
//  1. EC2 DescribeInstances — given the node's ProviderID it extracts the EC2
//     instance ID and retrieves the attached IamInstanceProfile.Arn.
//
//  2. IAM GetInstanceProfile — converts the instance profile name to the ARN
//     of the first attached IAM role, avoiding the brittle string substitution
//     used in Phase 14 helpers. GetInstanceProfile is authoritative: it returns
//     the actual role ARN regardless of naming conventions.
package ec2

import (
	"context"
	"fmt"

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
)

// InstanceProfileClient is the narrow AWS IAM API surface required to resolve
// the IAM role attached to an EC2 instance profile. Defined as an interface so
// callers can inject test doubles without a live AWS connection.
type InstanceProfileClient interface {
	GetInstanceProfile(
		ctx context.Context,
		params *awsiam.GetInstanceProfileInput,
		optFns ...func(*awsiam.Options),
	) (*awsiam.GetInstanceProfileOutput, error)
}

// DefaultNodeRoleResolver implements engine.NodeIAMRoleResolver using the EC2
// DescribeInstances API to look up the instance profile and the IAM
// GetInstanceProfile API to resolve the attached role ARN.
//
// Use NewDefaultNodeRoleResolver to construct an instance.
type DefaultNodeRoleResolver struct {
	ec2Client NodeIAMRoleClient   // for DescribeInstances (defined in node_role.go)
	iamClient InstanceProfileClient // for GetInstanceProfile
}

// NewDefaultNodeRoleResolver returns a DefaultNodeRoleResolver that uses the
// provided EC2 and IAM clients.
func NewDefaultNodeRoleResolver(ec2Client NodeIAMRoleClient, iamClient InstanceProfileClient) *DefaultNodeRoleResolver {
	return &DefaultNodeRoleResolver{
		ec2Client: ec2Client,
		iamClient: iamClient,
	}
}

// ResolveNodeIAMRole returns the IAM role ARN for the Kubernetes node
// identified by providerID (e.g. "aws:///us-east-1a/i-0123456789abcdef0").
//
// Flow:
//  1. Parse providerID → EC2 instance ID via ExtractInstanceID.
//  2. Call DescribeInstances to retrieve the IamInstanceProfile.Arn.
//  3. Extract the profile name from the ARN.
//  4. Call GetInstanceProfile to obtain the first attached Role.Arn.
//
// Returns ("", nil) when:
//   - providerID is not in AWS format (non-EKS node)
//   - the instance has no attached instance profile
//   - the instance profile has no attached roles
//
// Returns an error when any AWS API call fails.
func (r *DefaultNodeRoleResolver) ResolveNodeIAMRole(ctx context.Context, providerID string) (string, error) {
	instanceID := ExtractInstanceID(providerID)
	if instanceID == "" {
		// Not an AWS-format provider ID — skip silently.
		return "", nil
	}

	// Step 1: Retrieve the instance profile ARN from EC2.
	profileARN, err := instanceProfileARN(ctx, instanceID, r.ec2Client)
	if err != nil {
		return "", fmt.Errorf("get instance profile for %q: %w", instanceID, err)
	}
	if profileARN == "" {
		return "", nil
	}

	// Step 2: Extract the profile name from "arn:aws:iam::<acct>:instance-profile/<Name>".
	profileName := extractProfileName(profileARN)
	if profileName == "" {
		// Malformed ARN — fall back to string-substitution heuristic.
		return profileARNToRoleARN(profileARN), nil
	}

	// Step 3: Call IAM GetInstanceProfile to resolve the attached role ARN.
	out, err := r.iamClient.GetInstanceProfile(ctx, &awsiam.GetInstanceProfileInput{
		InstanceProfileName: &profileName,
	})
	if err != nil {
		return "", fmt.Errorf("get instance profile %q: %w", profileName, err)
	}
	if out.InstanceProfile == nil || len(out.InstanceProfile.Roles) == 0 {
		return "", nil
	}

	// Return the ARN of the first attached role (EKS nodes have exactly one).
	if arn := out.InstanceProfile.Roles[0].Arn; arn != nil {
		return *arn, nil
	}
	return "", nil
}

// instanceProfileARN returns the instance profile ARN for the given instanceID
// by calling DescribeInstances. Returns ("", nil) when the instance has no
// attached profile.
func instanceProfileARN(ctx context.Context, instanceID string, client NodeIAMRoleClient) (string, error) {
	roleARN, err := ResolveNodeIAMRole(ctx, instanceID, client)
	if err != nil {
		return "", err
	}
	// ResolveNodeIAMRole already converts the profile ARN via string substitution;
	// we need the raw profile ARN. Re-derive it from the returned role ARN by
	// reversing the substitution.
	if roleARN == "" {
		return "", nil
	}
	// Convert role ARN back to profile ARN for the GetInstanceProfile call.
	// roleARN: "arn:aws:iam::<acct>:role/<Name>"
	// profileARN: "arn:aws:iam::<acct>:instance-profile/<Name>"
	// Note: ResolveNodeIAMRole uses profileARNToRoleARN which only does this
	// substitution, so the round-trip is safe.
	return roleARNToProfileARN(roleARN), nil
}

// extractProfileName extracts the profile name from an instance profile ARN.
//
//	"arn:aws:iam::123:instance-profile/MyProfile" → "MyProfile"
func extractProfileName(profileARN string) string {
	const marker = ":instance-profile/"
	idx := -1
	for i := range profileARN {
		if profileARN[i] == ':' && len(profileARN)-i > len(marker) && profileARN[i:i+len(marker)] == marker {
			idx = i + len(marker)
			break
		}
	}
	if idx < 0 || idx >= len(profileARN) {
		return ""
	}
	return profileARN[idx:]
}

// roleARNToProfileARN converts an IAM role ARN to the corresponding instance
// profile ARN (inverse of profileARNToRoleARN).
//
//	"arn:aws:iam::123:role/MyRole" → "arn:aws:iam::123:instance-profile/MyRole"
func roleARNToProfileARN(roleARN string) string {
	const roleMarker = ":role/"
	const profMarker = ":instance-profile/"
	for i := 0; i < len(roleARN)-len(roleMarker); i++ {
		if roleARN[i:i+len(roleMarker)] == roleMarker {
			return roleARN[:i] + profMarker + roleARN[i+len(roleMarker):]
		}
	}
	return roleARN
}
