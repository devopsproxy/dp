package eks

import (
	"context"

	"github.com/devopsproxy/dp/internal/models"
)

// EKSCollector fetches EKS-specific cluster configuration from the AWS EKS API.
// Implementations must be stateless and safe to call concurrently.
// They must never apply business rules or produce findings.
type EKSCollector interface {
	// CollectEKSData queries the EKS API for the named cluster in the given region
	// and returns structured configuration consumed by EKS governance rules.
	// Returns a non-nil error only when the API call itself fails.
	CollectEKSData(ctx context.Context, clusterName, region string) (*models.KubernetesEKSData, error)
}
