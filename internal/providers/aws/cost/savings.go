package cost

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	ce "github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/devopsproxy/dp/internal/models"
)

// collectSavingsPlanCoverage fetches Savings Plan / Reserved Instance coverage
// for every region in the account, aggregated over the [start, end) period.
//
// A single account-level CE call with GroupBy REGION returns per-region data.
// Results are keyed by AWS region name (e.g. "us-east-1") so CollectAll can
// attach each entry to the corresponding RegionData.
//
// CoveragePercent is derived from the accumulated costs:
//
//	covered / (covered + on-demand) * 100
//
// Regions with zero spend (covered + on-demand == 0) receive 0% coverage.
func collectSavingsPlanCoverage(
	ctx context.Context,
	client costCEClient,
	start, end string,
) (map[string]models.AWSSavingsPlanCoverage, error) {
	// Accumulate per-region totals across all returned time periods.
	type regionTotals struct {
		onDemand float64
		covered  float64
	}
	totals := make(map[string]*regionTotals)

	var nextToken *string
	for {
		out, err := client.GetSavingsPlansCoverage(ctx, &ce.GetSavingsPlansCoverageInput{
			TimePeriod: &cetypes.DateInterval{
				Start: aws.String(start),
				End:   aws.String(end),
			},
			GroupBy: []cetypes.GroupDefinition{
				{
					Key:  aws.String("REGION"),
					Type: cetypes.GroupDefinitionTypeDimension,
				},
			},
			Granularity: cetypes.GranularityMonthly,
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("GetSavingsPlansCoverage: %w", err)
		}

		for _, cov := range out.SavingsPlansCoverages {
			// CE returns the region under "REGION" or "region" depending on
			// the API version; check both to be safe.
			region := cov.Attributes["REGION"]
			if region == "" {
				region = cov.Attributes["region"]
			}
			if region == "" {
				continue
			}

			if cov.Coverage == nil {
				continue
			}

			if totals[region] == nil {
				totals[region] = &regionTotals{}
			}
			totals[region].onDemand += parseCostFloat(cov.Coverage.OnDemandCost)
			totals[region].covered += parseCostFloat(cov.Coverage.SpendCoveredBySavingsPlans)
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}

	// Build the result map.
	result := make(map[string]models.AWSSavingsPlanCoverage, len(totals))
	for region, t := range totals {
		var pct float64
		total := t.onDemand + t.covered
		if total > 0 {
			pct = (t.covered / total) * 100
		}
		result[region] = models.AWSSavingsPlanCoverage{
			Region:          region,
			CoveragePercent: pct,
			OnDemandCostUSD: t.onDemand,
			CoveredCostUSD:  t.covered,
		}
	}
	return result, nil
}

// parseCostFloat parses a cost string returned by the Cost Explorer API
// (e.g. "1234.5678"). Returns 0 on parse failure — CE strings should always
// be valid decimals, so 0 is a safe sentinel.
func parseCostFloat(s *string) float64 {
	if s == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(*s, 64)
	return v
}
