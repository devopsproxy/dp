package cost

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/devopsproxy/dp/internal/models"
	"github.com/devopsproxy/dp/internal/providers/aws/common"
)

// CollectOptions carries per-region collection parameters.
type CollectOptions struct {
	// Region is the AWS region to collect from.
	Region string

	// AccountID is the resolved AWS account ID.
	AccountID string

	// Profile is the AWS profile name used for this collection run.
	Profile string

	// DaysBack is the lookback window in days for Cost Explorer and CloudWatch
	// metrics. Defaults to 30 when zero.
	DaysBack int
}

// CostCollector gathers raw cost-related resource data from AWS and converts
// it into internal models. It must not apply business rules or call the LLM.
//
// All implementations must use the AWS SDK v2 only.
type CostCollector interface {
	// CollectAll is the top-level entry point. It coordinates per-region
	// resource collection and account-level Cost Explorer data, returning the
	// complete dataset needed by the rule engine.
	//
	// For each region: a regional aws.Config is obtained via provider, and all
	// resource types are collected. Savings Plan coverage is fetched once
	// (account-level) and distributed to each RegionData.
	// Regions that fail are skipped; Cost Explorer failure returns nil CostSummary.
	CollectAll(
		ctx context.Context,
		profile *common.ProfileConfig,
		provider common.AWSClientProvider,
		regions []string,
		daysBack int,
	) ([]models.AWSRegionData, *models.AWSCostSummary, error)

	// CollectRegion gathers all cost-relevant resources within a single region:
	// EC2 instances, EBS volumes, NAT Gateways, RDS instances, and Load Balancers.
	// SavingsPlanCoverage is NOT populated here; CollectAll fills it centrally.
	CollectRegion(ctx context.Context, cfg aws.Config, opts CollectOptions) (*models.AWSRegionData, error)

	// CollectCostExplorer gathers account-level billing data from Cost Explorer.
	// This is a global (non-regional) call; the region in cfg is overridden to
	// us-east-1 internally. Returns a CostSummary covering the last opts.DaysBack days.
	CollectCostExplorer(ctx context.Context, cfg aws.Config, opts CollectOptions) (*models.AWSCostSummary, error)
}
