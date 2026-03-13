package ec2

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// ── fakeEC2Client ─────────────────────────────────────────────────────────────

type fakeEC2Client struct {
	profileARN string // instance profile ARN to return
	err        error
}

func (f *fakeEC2Client) DescribeInstances(
	_ context.Context,
	_ *ec2svc.DescribeInstancesInput,
	_ ...func(*ec2svc.Options),
) (*ec2svc.DescribeInstancesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	var profile *ec2types.IamInstanceProfile
	if f.profileARN != "" {
		profile = &ec2types.IamInstanceProfile{Arn: aws.String(f.profileARN)}
	}
	return &ec2svc.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{
			{
				Instances: []ec2types.Instance{
					{IamInstanceProfile: profile},
				},
			},
		},
	}, nil
}

// ── fakeIAMClient ─────────────────────────────────────────────────────────────

type fakeIAMClient struct {
	roleARN string // role ARN to return inside the profile
	err     error
}

func (f *fakeIAMClient) GetInstanceProfile(
	_ context.Context,
	_ *awsiam.GetInstanceProfileInput,
	_ ...func(*awsiam.Options),
) (*awsiam.GetInstanceProfileOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	var roles []iamtypes.Role
	if f.roleARN != "" {
		roles = []iamtypes.Role{{Arn: aws.String(f.roleARN)}}
	}
	return &awsiam.GetInstanceProfileOutput{
		InstanceProfile: &iamtypes.InstanceProfile{
			Roles: roles,
		},
	}, nil
}

// ── TestNodeToIAMRoleEdge ─────────────────────────────────────────────────────

// TestNodeToIAMRoleEdge verifies that DefaultNodeRoleResolver.ResolveNodeIAMRole
// correctly resolves a Kubernetes node's IAM role ARN from its ProviderID by
// calling DescribeInstances then GetInstanceProfile.
func TestNodeToIAMRoleEdge(t *testing.T) {
	const (
		providerID  = "aws:///us-east-1a/i-0abc123def456789"
		profileARN  = "arn:aws:iam::123456789012:instance-profile/eks-worker-profile"
		expectedARN = "arn:aws:iam::123456789012:role/eks-worker-role"
	)

	ec2Client := &fakeEC2Client{profileARN: profileARN}
	iamClient := &fakeIAMClient{roleARN: expectedARN}
	resolver := NewDefaultNodeRoleResolver(ec2Client, iamClient)

	got, err := resolver.ResolveNodeIAMRole(context.Background(), providerID)
	if err != nil {
		t.Fatalf("ResolveNodeIAMRole: unexpected error: %v", err)
	}
	if got != expectedARN {
		t.Errorf("expected role ARN %q; got %q", expectedARN, got)
	}
}

// TestNodeToIAMRoleEdge_NonAWSNode verifies that a non-AWS ProviderID returns
// ("", nil) without making any API calls.
func TestNodeToIAMRoleEdge_NonAWSNode(t *testing.T) {
	// GKE-style ProviderID — no AWS instance ID.
	ec2Client := &fakeEC2Client{err: errors.New("should not be called")}
	iamClient := &fakeIAMClient{err: errors.New("should not be called")}
	resolver := NewDefaultNodeRoleResolver(ec2Client, iamClient)

	got, err := resolver.ResolveNodeIAMRole(context.Background(), "gce://my-project/us-central1-a/node-1")
	if err != nil {
		t.Fatalf("expected no error for non-AWS node; got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty role ARN for non-AWS node; got %q", got)
	}
}

// TestNodeToIAMRoleEdge_NoProfile verifies that ("", nil) is returned when the
// EC2 instance has no attached instance profile.
func TestNodeToIAMRoleEdge_NoProfile(t *testing.T) {
	ec2Client := &fakeEC2Client{profileARN: ""} // no profile
	iamClient := &fakeIAMClient{}
	resolver := NewDefaultNodeRoleResolver(ec2Client, iamClient)

	got, err := resolver.ResolveNodeIAMRole(context.Background(), "aws:///us-east-1a/i-0abc123def456789")
	if err != nil {
		t.Fatalf("expected no error for instance without profile; got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty role ARN; got %q", got)
	}
}

// TestNodeToIAMRoleEdge_NoRoles verifies that ("", nil) is returned when the
// instance profile exists but has no attached roles.
func TestNodeToIAMRoleEdge_NoRoles(t *testing.T) {
	const profileARN = "arn:aws:iam::123456789012:instance-profile/empty-profile"
	ec2Client := &fakeEC2Client{profileARN: profileARN}
	iamClient := &fakeIAMClient{roleARN: ""} // no roles attached
	resolver := NewDefaultNodeRoleResolver(ec2Client, iamClient)

	got, err := resolver.ResolveNodeIAMRole(context.Background(), "aws:///us-east-1a/i-0abc123def456789")
	if err != nil {
		t.Fatalf("expected no error; got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty role ARN for profile with no roles; got %q", got)
	}
}

// TestNodeToIAMRoleEdge_EC2Error verifies that an EC2 API error is propagated.
func TestNodeToIAMRoleEdge_EC2Error(t *testing.T) {
	ec2Client := &fakeEC2Client{err: errors.New("ec2 API failure")}
	iamClient := &fakeIAMClient{}
	resolver := NewDefaultNodeRoleResolver(ec2Client, iamClient)

	_, err := resolver.ResolveNodeIAMRole(context.Background(), "aws:///us-east-1a/i-0abc123def456789")
	if err == nil {
		t.Error("expected error when EC2 API fails; got nil")
	}
}

// TestNodeToIAMRoleEdge_IAMError verifies that an IAM GetInstanceProfile error
// is propagated as a non-nil error.
func TestNodeToIAMRoleEdge_IAMError(t *testing.T) {
	const profileARN = "arn:aws:iam::123456789012:instance-profile/my-profile"
	ec2Client := &fakeEC2Client{profileARN: profileARN}
	iamClient := &fakeIAMClient{err: errors.New("iam API failure")}
	resolver := NewDefaultNodeRoleResolver(ec2Client, iamClient)

	_, err := resolver.ResolveNodeIAMRole(context.Background(), "aws:///us-east-1a/i-0abc123def456789")
	if err == nil {
		t.Error("expected error when IAM API fails; got nil")
	}
}

// ── extractProfileName helpers ────────────────────────────────────────────────

func TestExtractProfileName(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:iam::123:instance-profile/MyProfile", "MyProfile"},
		{"arn:aws:iam::123456789012:instance-profile/eks-worker-ng1", "eks-worker-ng1"},
		{"arn:aws:iam::123:role/SomeRole", ""},   // role ARN — no profile marker
		{"", ""},
	}
	for _, tc := range cases {
		got := extractProfileName(tc.arn)
		if got != tc.want {
			t.Errorf("extractProfileName(%q) = %q; want %q", tc.arn, got, tc.want)
		}
	}
}
