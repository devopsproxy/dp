package explain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/devopsproxy/dp/internal/models"
)

const (
	envAnthropicKey = "DP_ANTHROPIC_API_KEY"
	envOpenAIKey    = "DP_OPENAI_API_KEY"

	anthropicURL   = "https://api.anthropic.com/v1/messages"
	anthropicModel = "claude-haiku-4-5-20251001"

	openaiURL   = "https://api.openai.com/v1/chat/completions"
	openaiModel = "gpt-4o-mini"
)

// IsAIAvailable reports whether an AI provider key is configured in the
// environment and returns the name of the preferred provider.
// Anthropic is preferred when both keys are set.
// Returns ("", false) when no key is present.
func IsAIAvailable() (provider string, available bool) {
	if os.Getenv(envAnthropicKey) != "" {
		return "anthropic", true
	}
	if os.Getenv(envOpenAIKey) != "" {
		return "openai", true
	}
	return "", false
}

// ExplainAttackPathAI generates a human-readable AI explanation for the
// given CloudAttackPath. It prefers the Anthropic API (DP_ANTHROPIC_API_KEY)
// and falls back to OpenAI (DP_OPENAI_API_KEY) when the Anthropic key is
// absent. Returns an error when neither key is configured or when the API
// call fails.
func ExplainAttackPathAI(ctx context.Context, path models.CloudAttackPath) (string, error) {
	prompt := buildPrompt(path)

	anthropicKey := os.Getenv(envAnthropicKey)
	if anthropicKey != "" {
		return callAnthropic(ctx, anthropicKey, prompt)
	}

	openaiKey := os.Getenv(envOpenAIKey)
	if openaiKey != "" {
		return callOpenAI(ctx, openaiKey, prompt)
	}

	return "", fmt.Errorf("no AI provider key configured (set %s or %s)", envAnthropicKey, envOpenAIKey)
}

// buildPrompt constructs the prompt string sent to the AI provider.
func buildPrompt(path models.CloudAttackPath) string {
	chain := strings.Join(path.Nodes, " → ")
	return fmt.Sprintf(
		"You are a cloud security expert. Explain the following attack path in simple terms for a developer audience. "+
			"Be concise (2-3 sentences). Describe what an attacker could do and what data or systems are at risk.\n\n"+
			"Attack path: %s",
		chain,
	)
}

// ── Anthropic ─────────────────────────────────────────────────────────────────

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func callAnthropic(ctx context.Context, apiKey, prompt string) (string, error) {
	reqBody := anthropicRequest{
		Model:     anthropicModel,
		MaxTokens: 256,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal anthropic request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create anthropic request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read anthropic response: %w", err)
	}

	var parsed anthropicResponse
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return "", fmt.Errorf("parse anthropic response: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("anthropic API error: %s: %s", parsed.Error.Type, parsed.Error.Message)
	}
	for _, c := range parsed.Content {
		if c.Type == "text" && c.Text != "" {
			return strings.TrimSpace(c.Text), nil
		}
	}
	return "", fmt.Errorf("anthropic returned empty response")
}

// ── OpenAI ────────────────────────────────────────────────────────────────────

type openaiRequest struct {
	Model    string          `json:"model"`
	Messages []openaiMessage `json:"messages"`
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func callOpenAI(ctx context.Context, apiKey, prompt string) (string, error) {
	reqBody := openaiRequest{
		Model: openaiModel,
		Messages: []openaiMessage{
			{Role: "user", Content: prompt},
		},
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal openai request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openaiURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create openai request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read openai response: %w", err)
	}

	var parsed openaiResponse
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return "", fmt.Errorf("parse openai response: %w", err)
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("openai API error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("openai returned no choices")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

// ── Population helper ─────────────────────────────────────────────────────────

// PopulateExplanations fills Explanation (deterministic) and, when useAI is
// true, AIExplanation (AI-generated) on each CloudAttackPath. AI failures are
// silently swallowed — a failed AI call leaves AIExplanation empty.
func PopulateExplanations(ctx context.Context, paths []models.CloudAttackPath, useAI bool) []models.CloudAttackPath {
	result := make([]models.CloudAttackPath, len(paths))
	for i, p := range paths {
		p.Explanation = ExplainAttackPath(p)
		if useAI {
			ai, err := ExplainAttackPathAI(ctx, p)
			if err == nil {
				p.AIExplanation = ai
			}
		}
		result[i] = p
	}
	return result
}
