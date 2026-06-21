package config

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestLoad_SampleConfig(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "sample.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version != SchemaVersion {
		t.Errorf("Version = %d, want %d", cfg.Version, SchemaVersion)
	}
	if got, want := cfg.Upstream.Command[0], "npx"; got != want {
		t.Errorf("Upstream.Command[0] = %q, want %q", got, want)
	}
	if got, want := cfg.Policy.DefaultAction, "deny"; got != want {
		t.Errorf("Policy.DefaultAction = %q, want %q", got, want)
	}
	if got := len(cfg.Policy.Rules); got != 2 {
		t.Fatalf("len(Policy.Rules) = %d, want 2", got)
	}
	if got, want := cfg.Policy.Rules[0].ID, "allow-read-ioc"; got != want {
		t.Errorf("Rules[0].ID = %q, want %q", got, want)
	}
	if got, want := cfg.Approval.TimeoutSeconds, 300; got != want {
		t.Errorf("Approval.TimeoutSeconds = %d, want %d", got, want)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("testdata/does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !errors.Is(err, ErrFileNotFound) {
		t.Errorf("error is not ErrFileNotFound: %v", err)
	}
}

func TestValidate_SchemaMismatch(t *testing.T) {
	cfg := &Config{
		Version: SchemaVersion + 1,
		Upstream: Upstream{
			Command: []string{"echo"},
		},
		Policy: Policy{DefaultAction: "deny"},
	}
	if err := cfg.Validate(); !errors.Is(err, ErrSchemaMismatch) {
		t.Errorf("Validate() error = %v, want ErrSchemaMismatch", err)
	}
}

func TestValidate_EmptyUpstream(t *testing.T) {
	cfg := &Config{
		Version: SchemaVersion,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty upstream.command, got nil")
	}
}

func TestValidate_BlankArgInUpstream(t *testing.T) {
	cfg := &Config{
		Version: SchemaVersion,
		Upstream: Upstream{
			Command: []string{"echo", ""},
		},
		Policy: Policy{DefaultAction: "deny"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for blank upstream.command element, got nil")
	}
}

func TestValidate_InvalidDefaultAction(t *testing.T) {
	cfg := &Config{
		Version: SchemaVersion,
		Upstream: Upstream{
			Command: []string{"echo"},
		},
		Policy: Policy{DefaultAction: "maybe"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid default_action, got nil")
	}
}

func TestValidate_RuleMissingID(t *testing.T) {
	cfg := &Config{
		Version: SchemaVersion,
		Upstream: Upstream{
			Command: []string{"echo"},
		},
		Policy: Policy{
			DefaultAction: "deny",
			Rules: []Rule{
				{ID: "", Tool: "x", Action: "allow"},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for rule missing id, got nil")
	}
}

func TestValidate_RuleInvalidAction(t *testing.T) {
	cfg := &Config{
		Version: SchemaVersion,
		Upstream: Upstream{
			Command: []string{"echo"},
		},
		Policy: Policy{
			DefaultAction: "deny",
			Rules: []Rule{
				{ID: "r1", Tool: "x", Action: "wat"},
			},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid rule action, got nil")
	}
}

func TestValidate_SlackChannelMissingTokens(t *testing.T) {
	cfg := &Config{
		Version: SchemaVersion,
		Upstream: Upstream{
			Command: []string{"echo"},
		},
		Policy: Policy{DefaultAction: "deny"},
		Approval: Approval{
			Channels: []Channel{{Type: "slack"}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for slack channel missing tokens, got nil")
	}
}

func TestParse_RejectsMalformedYAML(t *testing.T) {
	_, err := Parse([]byte("this: is: not: valid: yaml: ["))
	if err == nil {
		t.Error("expected yaml parse error, got nil")
	}
}

func TestParse_AcceptsMinimalValidConfig(t *testing.T) {
	// Minimum valid config: no rules, no approval channels, no audit file.
	src := []byte(`version: 1
upstream:
  command: ["echo"]
policy:
  default_action: deny
`)
	cfg, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}
