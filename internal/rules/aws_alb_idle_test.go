package rules

import (
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

func TestAWSALBIdleRule_ID(t *testing.T) {
	r := AWSALBIdleRule{}
	if r.ID() != "ALB_IDLE" {
		t.Errorf("expected ALB_IDLE, got %s", r.ID())
	}
}

func TestAWSALBIdleRule_NilRegionData(t *testing.T) {
	r := AWSALBIdleRule{}
	findings := r.Evaluate(RuleContext{RegionData: nil})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil RegionData, got %d", len(findings))
	}
}

func TestAWSALBIdleRule_NoLBs(t *testing.T) {
	r := AWSALBIdleRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region:        "us-east-1",
			LoadBalancers: nil,
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings for no LBs, got %d", len(findings))
	}
}

func TestAWSALBIdleRule_ActiveALBWithTraffic_NotFlagged(t *testing.T) {
	r := AWSALBIdleRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			LoadBalancers: []models.AWSLoadBalancer{
				{
					LoadBalancerName: "my-alb",
					LoadBalancerARN:  "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc",
					Type:             "application",
					State:            "active",
					Region:           "us-east-1",
					RequestCount:     50000, // has traffic
				},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings for ALB with traffic, got %d", len(findings))
	}
}

func TestAWSALBIdleRule_ActiveALBNoTraffic_Flagged(t *testing.T) {
	r := AWSALBIdleRule{}
	ctx := RuleContext{
		AccountID: "123456789012",
		Profile:   "prod",
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			LoadBalancers: []models.AWSLoadBalancer{
				{
					LoadBalancerName: "idle-alb",
					LoadBalancerARN:  "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/idle-alb/abc",
					Type:             "application",
					State:            "active",
					Region:           "us-east-1",
					RequestCount:     0, // no traffic
				},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for idle ALB, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "ALB_IDLE" {
		t.Errorf("expected RuleID ALB_IDLE, got %s", f.RuleID)
	}
	if f.Severity != models.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.ResourceID != "idle-alb" {
		t.Errorf("expected ResourceID idle-alb, got %s", f.ResourceID)
	}
	if f.EstimatedMonthlySavings <= 0 {
		t.Errorf("expected positive savings, got %f", f.EstimatedMonthlySavings)
	}
}

func TestAWSALBIdleRule_NLBNotFlagged(t *testing.T) {
	r := AWSALBIdleRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			LoadBalancers: []models.AWSLoadBalancer{
				{
					LoadBalancerName: "my-nlb",
					Type:             "network",
					State:            "active",
					Region:           "us-east-1",
					RequestCount:     0, // NLB with no traffic — should NOT be flagged by this rule
				},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings for NLB (not ALB), got %d", len(findings))
	}
}

func TestAWSALBIdleRule_InactiveALBNotFlagged(t *testing.T) {
	r := AWSALBIdleRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			LoadBalancers: []models.AWSLoadBalancer{
				{
					LoadBalancerName: "provisioning-alb",
					Type:             "application",
					State:            "provisioning", // not active
					Region:           "us-east-1",
					RequestCount:     0,
				},
			},
		},
	}
	if findings := r.Evaluate(ctx); len(findings) != 0 {
		t.Errorf("expected 0 findings for non-active ALB, got %d", len(findings))
	}
}

func TestAWSALBIdleRule_MultipleALBs_OnlyIdleFlagged(t *testing.T) {
	r := AWSALBIdleRule{}
	ctx := RuleContext{
		RegionData: &models.AWSRegionData{
			Region: "us-east-1",
			LoadBalancers: []models.AWSLoadBalancer{
				{LoadBalancerName: "busy-alb", Type: "application", State: "active", Region: "us-east-1", RequestCount: 10000},
				{LoadBalancerName: "idle-alb-1", Type: "application", State: "active", Region: "us-east-1", RequestCount: 0},
				{LoadBalancerName: "idle-alb-2", Type: "application", State: "active", Region: "us-east-1", RequestCount: 0},
			},
		},
	}
	findings := r.Evaluate(ctx)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (2 idle ALBs), got %d", len(findings))
	}
}
