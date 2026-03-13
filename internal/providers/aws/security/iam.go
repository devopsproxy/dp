package awssecurity

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/devopsproxy/dp/internal/models"
)

// collectIAMUsers returns all IAM users in the account together with their
// relevant security attributes: whether MFA is enabled and whether the user
// has a console login profile (i.e. can sign in to the AWS console).
// The ListUsers paginator handles accounts with many users.
func collectIAMUsers(ctx context.Context, client iamAPIClient) ([]models.AWSIAMUser, error) {
	paginator := iamsvc.NewListUsersPaginator(client, &iamsvc.ListUsersInput{})
	var users []models.AWSIAMUser
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list IAM users: %w", err)
		}
		for _, u := range page.Users {
			userName := aws.ToString(u.UserName)
			users = append(users, models.AWSIAMUser{
				UserName:        userName,
				MFAEnabled:      userHasMFA(ctx, client, userName),
				HasLoginProfile: userHasLoginProfile(ctx, client, userName),
			})
		}
	}
	return users, nil
}

// userHasMFA returns true when the specified IAM user has at least one MFA
// device registered. Errors are treated as "no MFA" (conservative).
func userHasMFA(ctx context.Context, client iamAPIClient, userName string) bool {
	out, err := client.ListMFADevices(ctx, &iamsvc.ListMFADevicesInput{
		UserName: aws.String(userName),
	})
	if err != nil {
		return false
	}
	return len(out.MFADevices) > 0
}

// userHasLoginProfile returns true when the specified IAM user has a console
// login profile (password). GetLoginProfile returns an error (NoSuchEntityException)
// when no login profile exists, which is treated as false. API-only users
// typically have no login profile and should not be flagged for missing MFA.
func userHasLoginProfile(ctx context.Context, client iamAPIClient, userName string) bool {
	_, err := client.GetLoginProfile(ctx, &iamsvc.GetLoginProfileInput{
		UserName: aws.String(userName),
	})
	return err == nil
}
