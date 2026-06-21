package cli

import (
	"bytes"
	"strings"
	"testing"

	"mcp-socd/internal/version"
)

func TestNewRootCmd_HasExpectedFlags(t *testing.T) {
	cmd := NewRootCmd()
	for _, name := range []string{"config", "audit-stdout"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is missing", name)
		}
	}
}

func TestNewRootCmd_HasExpectedSubcommandShape(t *testing.T) {
	cmd := NewRootCmd()
	if cmd.Use == "" {
		t.Error("Use string is empty")
	}
	if !strings.Contains(cmd.Use, "upstream-command") {
		t.Errorf("Use string should mention positional <upstream-command>: %q", cmd.Use)
	}
}

func TestNewRootCmd_VersionIsBuildInfo(t *testing.T) {
	cmd := NewRootCmd()
	if cmd.Version != version.String() {
		t.Errorf("Version = %q, want %q", cmd.Version, version.String())
	}
}

func TestRootCmd_VersionFlagPrintsBuildInfo(t *testing.T) {
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--version"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "mcp-socd") {
		t.Errorf("--version output missing program name: %q", out)
	}
	if !strings.Contains(out, "commit:") {
		t.Errorf("--version output missing commit: %q", out)
	}
	if !strings.Contains(out, "built:") {
		t.Errorf("--version output missing built: %q", out)
	}
}

func TestRootCmd_HelpFlagPrintsUsage(t *testing.T) {
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "stdio proxy") {
		t.Errorf("--help output missing description: %q", out)
	}
}

func TestRootCmd_UnknownFlagReturnsError(t *testing.T) {
	cmd := NewRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--no-such-flag"})

	if err := cmd.Execute(); err == nil {
		t.Error("expected error for unknown flag, got nil")
	}
}
