package awssecurity

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2svc "github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/devopsproxy/dp/internal/models"
)

// collectSecurityGroupRules lists all EC2 security groups in the given region
// and returns one SecurityGroupRule entry per inbound IP rule. Both IPv4 and
// IPv6 CIDR ranges are included. The Region field is set on every rule so that
// security rule findings can be attributed to the correct region.
func collectSecurityGroupRules(ctx context.Context, client ec2SecurityAPIClient, region string) ([]models.AWSSecurityGroupRule, error) {
	out, err := client.DescribeSecurityGroups(ctx, &ec2svc.DescribeSecurityGroupsInput{})
	if err != nil {
		return nil, fmt.Errorf("describe security groups in %s: %w", region, err)
	}

	var rules []models.AWSSecurityGroupRule
	for _, sg := range out.SecurityGroups {
		groupID := aws.ToString(sg.GroupId)
		for _, perm := range sg.IpPermissions {
			port := 0
			if perm.FromPort != nil {
				port = int(aws.ToInt32(perm.FromPort))
			}
			for _, ipRange := range perm.IpRanges {
				rules = append(rules, models.AWSSecurityGroupRule{
					GroupID: groupID,
					Port:    port,
					CIDR:    aws.ToString(ipRange.CidrIp),
					Region:  region,
				})
			}
			for _, ipv6Range := range perm.Ipv6Ranges {
				rules = append(rules, models.AWSSecurityGroupRule{
					GroupID: groupID,
					Port:    port,
					CIDR:    aws.ToString(ipv6Range.CidrIpv6),
					Region:  region,
				})
			}
		}
	}
	return rules, nil
}
