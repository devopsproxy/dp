package awssecurity

import (
	"context"
	"fmt"

	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/devopsproxy/dp/internal/models"
)

// collectRootAccountInfo retrieves the IAM account summary and checks whether
// the root account has active access keys and whether MFA is enabled.
//
// AccountAccessKeysPresent in the summary map is the number of root access keys.
// AccountMFAEnabled is 1 when virtual or hardware MFA is enabled on root.
// DataAvailable is set to true on success so rules can distinguish "collection
// failed (zero value)" from "actually not enabled".
func collectRootAccountInfo(ctx context.Context, client iamAPIClient) (models.AWSRootAccountInfo, error) {
	out, err := client.GetAccountSummary(ctx, &iamsvc.GetAccountSummaryInput{})
	if err != nil {
		return models.AWSRootAccountInfo{}, fmt.Errorf("get IAM account summary: %w", err)
	}
	return models.AWSRootAccountInfo{
		HasAccessKeys: out.SummaryMap["AccountAccessKeysPresent"] > 0,
		MFAEnabled:    out.SummaryMap["AccountMFAEnabled"] > 0,
		DataAvailable: true,
	}, nil
}
