package awssecurity

import (
	"context"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/providers/aws/common"
)

// SecurityCollector collects raw security posture data from an AWS account.
// The returned SecurityData is account-level (aggregated across all audited
// regions). It is passed to the security rule engine for evaluation.
//
// Implementations must never apply business logic or produce findings.
// Non-fatal collection failures (e.g. a single region's SGs unreachable) must
// be silently skipped so the rest of the audit can complete.
type SecurityCollector interface {
	CollectAll(
		ctx context.Context,
		profile *common.ProfileConfig,
		provider common.AWSClientProvider,
		regions []string,
	) (*models.AWSSecurityData, error)
}
