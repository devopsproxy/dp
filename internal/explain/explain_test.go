package explain

import (
	"context"
	"strings"
	"testing"

	"github.com/devopsproxy/dp/internal/models"
)

// ── TestExplainAttackPath_Deterministic ──────────────────────────────────────

func TestExplainAttackPath_Deterministic(t *testing.T) {
	t.Run("internet_to_s3", func(t *testing.T) {
		path := models.CloudAttackPath{
			Nodes: []string{"Internet", "LoadBalancer_my-lb", "Deployment_api", "IAMRole_app-role", "S3Bucket_data-bucket"},
		}
		result := ExplainAttackPath(path)
		assertContains(t, result, "Internet")
		assertContains(t, result, "my-lb")
		assertContains(t, result, "api")
		assertContains(t, result, "app-role")
		assertContains(t, result, "data-bucket")
	})

	t.Run("node_instance_profile_path", func(t *testing.T) {
		path := models.CloudAttackPath{
			Nodes: []string{"Internet", "LoadBalancer_frontend", "Deployment_web", "Node_ip-10-0-1-1", "IAMRole_node-role", "SecretsManagerSecret_db-password"},
		}
		result := ExplainAttackPath(path)
		assertContains(t, result, "node-role")
		assertContains(t, result, "db-password")
		assertContains(t, result, "ip-10-0-1-1")
	})

	t.Run("service_account_irsa_path", func(t *testing.T) {
		path := models.CloudAttackPath{
			Nodes: []string{"Internet", "LoadBalancer_api-svc", "Deployment_backend", "ServiceAccount_backend-sa", "IAMRole_irsa-role", "DynamoDBTable_orders"},
		}
		result := ExplainAttackPath(path)
		assertContains(t, result, "backend-sa")
		assertContains(t, result, "irsa-role")
		assertContains(t, result, "orders")
	})

	t.Run("iam_cross_role_escalation", func(t *testing.T) {
		path := models.CloudAttackPath{
			Nodes: []string{"Internet", "IAMRole_role-a", "IAMRole_role-b", "S3Bucket_sensitive"},
		}
		result := ExplainAttackPath(path)
		assertContains(t, result, "role-a")
		assertContains(t, result, "role-b")
		assertContains(t, result, "sensitive")
	})

	t.Run("empty_nodes_returns_fallback", func(t *testing.T) {
		path := models.CloudAttackPath{Nodes: []string{}}
		result := ExplainAttackPath(path)
		if result == "" {
			t.Error("expected non-empty result for empty nodes")
		}
	})

	t.Run("unknown_prefix_nodes_fallback", func(t *testing.T) {
		path := models.CloudAttackPath{
			Nodes: []string{"UnknownType_foo", "AnotherUnknown_bar"},
		}
		result := ExplainAttackPath(path)
		// All unknown → falls back to the generic message
		assertContains(t, result, "Attack path")
	})
}

// ── TestSentenceForNode ───────────────────────────────────────────────────────

func TestSentenceForNode(t *testing.T) {
	cases := []struct {
		nodeID   string
		wantFrag string
	}{
		{"Internet", "Internet"},
		{"Internet_node", "Internet"},
		{"LoadBalancer_web-svc", "web-svc"},
		{"Deployment_api", "api"},
		{"StatefulSet_db", "db"},
		{"DaemonSet_fluentd", "fluentd"},
		{"Job_migrate", "migrate"},
		{"CronJob_cleanup", "cleanup"},
		{"Pod_my-pod", "my-pod"},
		{"Node_worker-1", "worker-1"},
		{"ServiceAccount_backend-sa", "backend-sa"},
		{"IAMRole_app-role", "app-role"},
		{"S3Bucket_data", "data"},
		{"SecretsManagerSecret_db-pass", "db-pass"},
		{"DynamoDBTable_orders", "orders"},
		{"KMSKey_master", "master"},
		{"SSMParameter_/prod/db/pass", "/prod/db/pass"},
	}

	for _, tc := range cases {
		t.Run(tc.nodeID, func(t *testing.T) {
			s := sentenceForNode(tc.nodeID)
			if !strings.Contains(s, tc.wantFrag) {
				t.Errorf("sentenceForNode(%q) = %q; want fragment %q", tc.nodeID, s, tc.wantFrag)
			}
		})
	}
}

// ── TestIsAIAvailable ─────────────────────────────────────────────────────────

func TestIsAIAvailable_NoKeys(t *testing.T) {
	t.Setenv(envAnthropicKey, "")
	t.Setenv(envOpenAIKey, "")
	provider, ok := IsAIAvailable()
	if ok {
		t.Errorf("expected IsAIAvailable=false when no keys set; got provider=%q", provider)
	}
}

func TestIsAIAvailable_AnthropicPreferred(t *testing.T) {
	t.Setenv(envAnthropicKey, "sk-ant-test")
	t.Setenv(envOpenAIKey, "sk-openai-test")
	provider, ok := IsAIAvailable()
	if !ok {
		t.Fatal("expected IsAIAvailable=true")
	}
	if provider != "anthropic" {
		t.Errorf("expected provider=anthropic when both keys set; got %q", provider)
	}
}

func TestIsAIAvailable_OpenAIFallback(t *testing.T) {
	t.Setenv(envAnthropicKey, "")
	t.Setenv(envOpenAIKey, "sk-openai-test")
	provider, ok := IsAIAvailable()
	if !ok {
		t.Fatal("expected IsAIAvailable=true")
	}
	if provider != "openai" {
		t.Errorf("expected provider=openai when only openai key set; got %q", provider)
	}
}

// ── TestExplainAttackPathAI_NoKeys ────────────────────────────────────────────

func TestExplainAttackPathAI_NoKeys(t *testing.T) {
	t.Setenv(envAnthropicKey, "")
	t.Setenv(envOpenAIKey, "")
	path := models.CloudAttackPath{
		Nodes: []string{"Internet", "IAMRole_test", "S3Bucket_data"},
	}
	_, err := ExplainAttackPathAI(context.Background(), path)
	if err == nil {
		t.Error("expected error when no AI keys are configured")
	}
}

// ── TestPopulateExplanations ──────────────────────────────────────────────────

func TestPopulateExplanations_DeterministicOnly(t *testing.T) {
	t.Setenv(envAnthropicKey, "")
	t.Setenv(envOpenAIKey, "")

	paths := []models.CloudAttackPath{
		{
			Score: 80,
			Nodes: []string{"Internet", "LoadBalancer_frontend", "Deployment_api", "IAMRole_app-role", "S3Bucket_data"},
		},
		{
			Score: 60,
			Nodes: []string{"Internet", "LoadBalancer_svc2", "IAMRole_role-b", "SecretsManagerSecret_pass"},
		},
	}

	result := PopulateExplanations(context.Background(), paths, false)

	if len(result) != 2 {
		t.Fatalf("expected 2 results; got %d", len(result))
	}
	for i, p := range result {
		if p.Explanation == "" {
			t.Errorf("path[%d]: expected non-empty Explanation", i)
		}
		if p.AIExplanation != "" {
			t.Errorf("path[%d]: expected empty AIExplanation when aiExplain=false; got %q", i, p.AIExplanation)
		}
	}
}

func TestPopulateExplanations_OriginalUnchanged(t *testing.T) {
	t.Setenv(envAnthropicKey, "")
	t.Setenv(envOpenAIKey, "")

	original := []models.CloudAttackPath{
		{Score: 80, Nodes: []string{"Internet", "S3Bucket_data"}},
	}

	_ = PopulateExplanations(context.Background(), original, false)

	// Original slice must not be mutated.
	if original[0].Explanation != "" {
		t.Error("PopulateExplanations must not mutate the original slice")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func assertContains(t *testing.T, s, fragment string) {
	t.Helper()
	if !strings.Contains(s, fragment) {
		t.Errorf("expected %q to contain %q", s, fragment)
	}
}
