// Package ec2 provides AWS EC2 helper functions used by the DevOps-Proxy graph
// engine. It is intentionally minimal — only the operations needed for Phase 14
// (node IAM role resolution) live here.
package ec2

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// NodeIAMRoleClient is the minimal EC2 API surface required to resolve the IAM
// instance profile role attached to a specific EC2 instance. Defined as an
// interface so callers can inject test doubles without a live AWS connection.
type NodeIAMRoleClient interface {
	DescribeInstances(
		ctx context.Context,
		params *ec2svc.DescribeInstancesInput,
		optFns ...func(*ec2svc.Options),
	) (*ec2svc.DescribeInstancesOutput, error)
}

// ResolveNodeIAMRole returns the IAM role ARN for the EC2 instance with the
// given instanceID by examining its attached instance profile.
//
// The instance profile ARN returned by DescribeInstances has the form:
//
//	arn:aws:iam::<account>:instance-profile/<ProfileName>
//
// This is converted to the corresponding role ARN by replacing
// ":instance-profile/" with ":role/". On EKS nodes the profile name and role
// name are typically identical, making this conversion reliable in practice.
//
// Returns ("", nil) when the instance exists but has no instance profile.
// Returns an error when the DescribeInstances call fails or the instance is
// not found.
func ResolveNodeIAMRole(ctx context.Context, instanceID string, client NodeIAMRoleClient) (string, error) {
	out, err := client.DescribeInstances(ctx, &ec2svc.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return "", fmt.Errorf("describe instances %q: %w", instanceID, err)
	}

	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			if inst.IamInstanceProfile == nil || inst.IamInstanceProfile.Arn == nil {
				return "", nil
			}
			return profileARNToRoleARN(aws.ToString(inst.IamInstanceProfile.Arn)), nil
		}
	}

	return "", fmt.Errorf("instance %q not found", instanceID)
}

// ResolveNodeIAMRoleByDNS returns the IAM role ARN for the EC2 instance whose
// private DNS name matches privateDNSName (e.g. "ip-10-0-1-1.ec2.internal").
//
// The ".ec2.internal" suffix is stripped before the DescribeInstances call so
// that the filter value matches the hostname portion stored by EC2
// (e.g. "ip-10-0-1-1"). EC2 DescribeInstances is invoked with a
// "private-dns-name" filter, which is more reliable than the ProviderID-based
// approach when the node name IS the private DNS name.
//
// Returns ("", nil) when the instance exists but has no instance profile.
// Returns an error when the DescribeInstances call fails or no instance matches.
func ResolveNodeIAMRoleByDNS(ctx context.Context, privateDNSName string, client NodeIAMRoleClient) (string, error) {
	// Strip the ".ec2.internal" suffix if present so EC2 accepts the hostname.
	dnsFilter := strings.TrimSuffix(privateDNSName, ".ec2.internal")

	out, err := client.DescribeInstances(ctx, &ec2svc.DescribeInstancesInput{
		Filters: []ec2types.Filter{
			{Name: aws.String("private-dns-name"), Values: []string{dnsFilter + "*"}},
		},
	})
	if err != nil {
		return "", fmt.Errorf("describe instances by DNS %q: %w", privateDNSName, err)
	}

	for _, r := range out.Reservations {
		for _, inst := range r.Instances {
			if inst.IamInstanceProfile == nil || inst.IamInstanceProfile.Arn == nil {
				return "", nil
			}
			return profileARNToRoleARN(aws.ToString(inst.IamInstanceProfile.Arn)), nil
		}
	}

	return "", fmt.Errorf("no instance found with private DNS name %q", privateDNSName)
}

// ExtractInstanceID parses a Kubernetes node ProviderID and returns the EC2
// instance ID component.
//
// Expected format: "aws:///us-east-1a/i-0123456789abcdef0"
//
// Returns "" when the ProviderID is not in the expected AWS format or does not
// contain an instance ID beginning with "i-".
func ExtractInstanceID(providerID string) string {
	const prefix = "aws:///"
	if !strings.HasPrefix(providerID, prefix) {
		return ""
	}
	trimmed := providerID[len(prefix):]
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
		last := trimmed[idx+1:]
		if strings.HasPrefix(last, "i-") {
			return last
		}
	}
	return ""
}

// profileARNToRoleARN converts an IAM instance profile ARN to the
// corresponding IAM role ARN.
//
//	"arn:aws:iam::123:instance-profile/MyProfile"
//	→ "arn:aws:iam::123:role/MyProfile"
func profileARNToRoleARN(profileARN string) string {
	return strings.Replace(profileARN, ":instance-profile/", ":role/", 1)
}
