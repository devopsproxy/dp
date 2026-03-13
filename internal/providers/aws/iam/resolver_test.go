package iam

import (
	"testing"
)

// ── TestIAMAssumeRoleDetection ────────────────────────────────────────────────

// TestIAMAssumeRoleDetection verifies that parseAssumeRoleTargets correctly
// extracts IAM role ARNs from Allow statements with sts:AssumeRole actions
// and ignores wildcard resources and non-AssumeRole actions.
func TestIAMAssumeRoleDetection(t *testing.T) {
	t.Run("single_target_role", func(t *testing.T) {
		doc := `{
			"Statement": [{
				"Effect": "Allow",
				"Action": "sts:AssumeRole",
				"Resource": "arn:aws:iam::123456789012:role/admin-role"
			}]
		}`
		arns := parseAssumeRoleTargets(doc)
		if len(arns) != 1 {
			t.Fatalf("expected 1 ARN; got %d: %v", len(arns), arns)
		}
		if arns[0] != "arn:aws:iam::123456789012:role/admin-role" {
			t.Errorf("unexpected ARN %q", arns[0])
		}
	})

	t.Run("multiple_target_roles", func(t *testing.T) {
		doc := `{
			"Statement": [{
				"Effect": "Allow",
				"Action": ["sts:AssumeRole"],
				"Resource": [
					"arn:aws:iam::123456789012:role/role-a",
					"arn:aws:iam::123456789012:role/role-b"
				]
			}]
		}`
		arns := parseAssumeRoleTargets(doc)
		if len(arns) != 2 {
			t.Fatalf("expected 2 ARNs; got %d: %v", len(arns), arns)
		}
	})

	t.Run("wildcard_resource_skipped", func(t *testing.T) {
		doc := `{
			"Statement": [{
				"Effect": "Allow",
				"Action": "sts:AssumeRole",
				"Resource": "*"
			}]
		}`
		arns := parseAssumeRoleTargets(doc)
		if len(arns) != 0 {
			t.Errorf("expected 0 ARNs for wildcard resource; got %v", arns)
		}
	})

	t.Run("deny_statement_skipped", func(t *testing.T) {
		doc := `{
			"Statement": [{
				"Effect": "Deny",
				"Action": "sts:AssumeRole",
				"Resource": "arn:aws:iam::123456789012:role/restricted-role"
			}]
		}`
		arns := parseAssumeRoleTargets(doc)
		if len(arns) != 0 {
			t.Errorf("expected 0 ARNs for Deny statement; got %v", arns)
		}
	})

	t.Run("non_assumerole_action_skipped", func(t *testing.T) {
		doc := `{
			"Statement": [{
				"Effect": "Allow",
				"Action": "s3:GetObject",
				"Resource": "arn:aws:s3:::my-bucket/*"
			}]
		}`
		arns := parseAssumeRoleTargets(doc)
		if len(arns) != 0 {
			t.Errorf("expected 0 ARNs for non-sts action; got %v", arns)
		}
	})

	t.Run("invalid_json_returns_nil", func(t *testing.T) {
		arns := parseAssumeRoleTargets("not-valid-json")
		if arns != nil {
			t.Errorf("expected nil for invalid JSON; got %v", arns)
		}
	})
}
