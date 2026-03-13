package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/devopsproxy/dp/internal/version"
)

func TestVersionCmd_Output(t *testing.T) {
	// Override the package-level version variables for this test.
	orig := version.Version
	origC := version.Commit
	origD := version.Date
	t.Cleanup(func() {
		version.Version = orig
		version.Commit = origC
		version.Date = origD
	})

	version.Version = "test"
	version.Commit = "abc123"
	version.Date = "2025-01-01"

	// Execute the version command and capture stdout.
	var buf bytes.Buffer
	root := newRootCmd()
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"version"})

	if err := root.Execute(); err != nil {
		t.Fatalf("version command returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"test", "abc123", "2025-01-01"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output missing %q; got:\n%s", want, out)
		}
	}
}

func TestVersionInfo_Format(t *testing.T) {
	orig := version.Version
	origC := version.Commit
	origD := version.Date
	t.Cleanup(func() {
		version.Version = orig
		version.Commit = origC
		version.Date = origD
	})

	version.Version = "v1.2.3"
	version.Commit = "deadbeef"
	version.Date = "2026-01-15"

	info := version.Info()

	if !strings.HasPrefix(info, "dp version v1.2.3\n") {
		t.Errorf("Info() first line wrong; got: %q", info)
	}
	if !strings.Contains(info, "commit: deadbeef") {
		t.Errorf("Info() missing commit line; got: %q", info)
	}
	if !strings.Contains(info, "built: 2026-01-15") {
		t.Errorf("Info() missing built line; got: %q", info)
	}
}

func TestVersionInfo_Defaults(t *testing.T) {
	orig := version.Version
	origC := version.Commit
	origD := version.Date
	t.Cleanup(func() {
		version.Version = orig
		version.Commit = origC
		version.Date = origD
	})

	version.Version = "dev"
	version.Commit = "none"
	version.Date = "unknown"

	info := version.Info()

	if !strings.Contains(info, "dev") {
		t.Errorf("Info() should contain default version 'dev'; got: %q", info)
	}
	if !strings.Contains(info, "none") {
		t.Errorf("Info() should contain default commit 'none'; got: %q", info)
	}
	if !strings.Contains(info, "unknown") {
		t.Errorf("Info() should contain default date 'unknown'; got: %q", info)
	}
}
