package cost

import (
	"context"
	"fmt"
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	ce "github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/devopsproxy/dp/internal/models"
)

// collectCostSummary calls Cost Explorer GetCostAndUsage for [start, end) and
// returns an aggregated CostSummary with per-service cost breakdown.
//
// Granularity is MONTHLY; costs are summed across all returned time periods so
// the summary covers the full requested window (which may span two calendar months).
// Services are sorted descending by cost.
func collectCostSummary(
	ctx context.Context,
	client costCEClient,
	start, end string,
) (*models.AWSCostSummary, error) {
	// Per-service cost accumulator across all time periods.
	serviceTotals := make(map[string]float64)

	var nextToken *string
	for {
		out, err := client.GetCostAndUsage(ctx, &ce.GetCostAndUsageInput{
			TimePeriod: &cetypes.DateInterval{
				Start: aws.String(start),
				End:   aws.String(end),
			},
			Granularity: cetypes.GranularityMonthly,
			Metrics:     []string{"UnblendedCost"},
			GroupBy: []cetypes.GroupDefinition{
				{
					Key:  aws.String("SERVICE"),
					Type: cetypes.GroupDefinitionTypeDimension,
				},
			},
			NextPageToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("GetCostAndUsage: %w", err)
		}

		for _, result := range out.ResultsByTime {
			for _, group := range result.Groups {
				if len(group.Keys) == 0 {
					continue
				}
				service := group.Keys[0]
				metric, ok := group.Metrics["UnblendedCost"]
				if !ok {
					continue
				}
				serviceTotals[service] += parseCostFloat(metric.Amount)
			}
		}

		if out.NextPageToken == nil {
			break
		}
		nextToken = out.NextPageToken
	}

	// Compute grand total.
	var totalCost float64
	for _, v := range serviceTotals {
		totalCost += v
	}

	// Build breakdown sorted by cost descending (most expensive first).
	breakdown := make([]models.AWSServiceCost, 0, len(serviceTotals))
	for service, cost := range serviceTotals {
		if cost > 0 {
			breakdown = append(breakdown, models.AWSServiceCost{
				Service: service,
				CostUSD: cost,
			})
		}
	}
	sort.Slice(breakdown, func(i, j int) bool {
		return breakdown[i].CostUSD > breakdown[j].CostUSD
	})

	return &models.AWSCostSummary{
		PeriodStart:      start,
		PeriodEnd:        end,
		TotalCostUSD:     totalCost,
		ServiceBreakdown: breakdown,
	}, nil
}

// collectResourceCosts calls Cost Explorer GetCostAndUsage grouped by
// RESOURCE_ID, filtered to the given AWS service name, and returns a map of
// resourceID → aggregated monthly cost in USD across all returned time periods.
//
// Non-fatal: if the CE call fails, returns an empty map and the error.
// Callers must treat a missing entry (cost == 0) as "cost unknown" and skip
// any rules that depend on accurate cost data.
func collectResourceCosts(
	ctx context.Context,
	client costCEClient,
	serviceName, start, end string,
) (map[string]float64, error) {
	costs := make(map[string]float64)

	var nextToken *string
	for {
		out, err := client.GetCostAndUsage(ctx, &ce.GetCostAndUsageInput{
			TimePeriod: &cetypes.DateInterval{
				Start: aws.String(start),
				End:   aws.String(end),
			},
			Granularity: cetypes.GranularityMonthly,
			Metrics:     []string{"UnblendedCost"},
			Filter: &cetypes.Expression{
				Dimensions: &cetypes.DimensionValues{
					Key:    cetypes.DimensionService,
					Values: []string{serviceName},
				},
			},
			GroupBy: []cetypes.GroupDefinition{
				{
					Key:  aws.String("RESOURCE_ID"),
					Type: cetypes.GroupDefinitionTypeDimension,
				},
			},
			NextPageToken: nextToken,
		})
		if err != nil {
			return costs, fmt.Errorf("GetCostAndUsage (service=%q): %w", serviceName, err)
		}

		for _, result := range out.ResultsByTime {
			for _, group := range result.Groups {
				if len(group.Keys) == 0 {
					continue
				}
				resourceID := group.Keys[0]
				metric, ok := group.Metrics["UnblendedCost"]
				if !ok {
					continue
				}
				costs[resourceID] += parseCostFloat(metric.Amount)
			}
		}

		if out.NextPageToken == nil {
			break
		}
		nextToken = out.NextPageToken
	}

	return costs, nil
}

// collectEC2InstanceCosts returns a map of EC2 instanceID → monthly cost USD
// by calling the generic collectResourceCosts for the EC2 Compute service.
func collectEC2InstanceCosts(
	ctx context.Context,
	client costCEClient,
	start, end string,
) (map[string]float64, error) {
	return collectResourceCosts(ctx, client, "Amazon Elastic Compute Cloud - Compute", start, end)
}

// collectRDSInstanceCosts returns a map of RDS DBInstanceID → monthly cost USD
// by calling the generic collectResourceCosts for the RDS service.
func collectRDSInstanceCosts(
	ctx context.Context,
	client costCEClient,
	start, end string,
) (map[string]float64, error) {
	return collectResourceCosts(ctx, client, "Amazon Relational Database Service", start, end)
}
