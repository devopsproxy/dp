package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/devopsproxy/dp/internal/risk"
)

// ── renderRiskTop (table mode) ───────────────────────────────────────────────

func TestRenderRiskTop_TableFormat(t *testing.T) {
	findings := []risk.RiskFinding{
		{Title: "Internet → haproxy → node", Path: []string{"Internet", "haproxy", "ip-10-3-23-253.ec2.internal"}, Score: 70, Severity: "HIGH"},
		{Title: "Internet → kafka-ui → node", Path: []string{"Internet", "kafka-ui", "ip-10-3-23-253.ec2.internal"}, Score: 70, Severity: "HIGH"},
	}

	var buf bytes.Buffer
	renderRiskTop(&buf, findings)
	out := buf.String()

	if !strings.Contains(out, "TOP ATTACK PATH RISKS") {
		t.Error("table output missing header")
	}
	if !strings.Contains(out, "SEVERITY") {
		t.Error("table output missing column header SEVERITY")
	}
	if !strings.Contains(out, "SCORE") {
		t.Error("table output missing column header SCORE")
	}
	if !strings.Contains(out, "ATTACK PATH") {
		t.Error("table output missing column header ATTACK PATH")
	}
	if !strings.Contains(out, "Internet → haproxy → ip-10-3-23-253.ec2.internal") {
		t.Error("table output missing first path")
	}
	if !strings.Contains(out, "HIGH") {
		t.Error("table output missing severity HIGH")
	}
}

func TestRenderRiskTop_TableNumbering(t *testing.T) {
	findings := []risk.RiskFinding{
		{Title: "a", Path: []string{"Internet", "lb", "svc"}, Score: 80, Severity: "HIGH"},
		{Title: "b", Path: []string{"Internet", "lb2", "svc2"}, Score: 70, Severity: "HIGH"},
	}

	var buf bytes.Buffer
	renderRiskTop(&buf, findings)
	out := buf.String()

	if !strings.Contains(out, "1") {
		t.Error("table output missing row number 1")
	}
	if !strings.Contains(out, "2") {
		t.Error("table output missing row number 2")
	}
}

// ── encodeRiskJSON ───────────────────────────────────────────────────────────

func TestEncodeRiskJSON_ValidJSON(t *testing.T) {
	findings := []risk.RiskFinding{
		{Title: "Internet → svc → node", Path: []string{"Internet", "lb", "svc", "node"}, Score: 70, Severity: "HIGH", Explanation: "test"},
	}

	var buf bytes.Buffer
	if err := encodeRiskJSON(&buf, findings); err != nil {
		t.Fatalf("encodeRiskJSON returned error: %v", err)
	}

	var decoded []risk.RiskFinding
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
}

func TestEncodeRiskJSON_ContainsSeverityScorePath(t *testing.T) {
	findings := []risk.RiskFinding{
		{
			Title:    "Internet → haproxy → ip-10-3-23-253.ec2.internal",
			Path:     []string{"Internet", "haproxy", "ip-10-3-23-253.ec2.internal"},
			Score:    70,
			Severity: "HIGH",
		},
	}

	var buf bytes.Buffer
	if err := encodeRiskJSON(&buf, findings); err != nil {
		t.Fatalf("encodeRiskJSON: %v", err)
	}
	out := buf.String()

	if !strings.Contains(out, `"severity"`) {
		t.Error("JSON missing severity field")
	}
	if !strings.Contains(out, `"score"`) {
		t.Error("JSON missing score field")
	}
	if !strings.Contains(out, `"path"`) {
		t.Error("JSON missing path field")
	}
	if !strings.Contains(out, "HIGH") {
		t.Error("JSON missing HIGH value")
	}
	if !strings.Contains(out, "70") {
		t.Error("JSON missing score value 70")
	}
	if !strings.Contains(out, "haproxy") {
		t.Error("JSON missing path node haproxy")
	}
}

func TestEncodeRiskJSON_NoTableHeaders(t *testing.T) {
	findings := []risk.RiskFinding{
		{Title: "t", Path: []string{"Internet", "lb"}, Score: 40, Severity: "MEDIUM"},
	}

	var buf bytes.Buffer
	if err := encodeRiskJSON(&buf, findings); err != nil {
		t.Fatalf("encodeRiskJSON: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "TOP ATTACK PATH RISKS") {
		t.Error("JSON output must not contain table header")
	}
	if strings.Contains(out, "ATTACK PATH") {
		t.Error("JSON output must not contain column headers")
	}
}

// ── --output flag registration ───────────────────────────────────────────────

func TestRiskTopCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newRiskTopCmd()
	f := cmd.Flags().Lookup("output")
	if f == nil {
		t.Fatal("--output flag not registered on risk top")
	}
	if f.DefValue != "table" {
		t.Errorf("--output default: want %q, got %q", "table", f.DefValue)
	}
}

func TestRiskExplainCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newRiskExplainCmd()
	f := cmd.Flags().Lookup("output")
	if f == nil {
		t.Fatal("--output flag not registered on risk explain")
	}
	if f.DefValue != "table" {
		t.Errorf("--output default: want %q, got %q", "table", f.DefValue)
	}
}
