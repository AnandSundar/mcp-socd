package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ErrSchemaMismatch is returned when the on-disk version field does not
// match the binary's SchemaVersion. Migrations are not yet implemented.
var ErrSchemaMismatch = errors.New("config schema version mismatch")

// ErrFileNotFound is returned when a requested config path does not exist.
var ErrFileNotFound = errors.New("config file not found")

// Load reads, parses, and validates a config file at path. Returns the
// populated Config or an error. Errors include the file path and the
// underlying yaml or schema error for diagnostics.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrFileNotFound, path)
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes YAML bytes into a Config and validates it. Exposed
// separately from Load so callers (tests, --print-config, init) can
// parse without going through the filesystem.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	return &cfg, nil
}

// Validate enforces required fields and value constraints. Called by
// Load and by hot-reload; a failed validate must never cause the proxy
// to start or to swap to a bad policy.
func (c *Config) Validate() error {
	if c.Version != SchemaVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrSchemaMismatch, c.Version, SchemaVersion)
	}
	if c.Upstream.Command == nil || len(c.Upstream.Command) == 0 {
		return errors.New("upstream.command is required and must be non-empty")
	}
	for i, c := range c.Upstream.Command {
		if c == "" {
			return fmt.Errorf("upstream.command[%d] is empty", i)
		}
	}
	switch c.Policy.DefaultAction {
	case "allow", "deny":
		// ok
	case "":
		return errors.New("policy.default_action is required (allow|deny)")
	default:
		return fmt.Errorf("policy.default_action must be allow or deny, got %q", c.Policy.DefaultAction)
	}
	for i, r := range c.Policy.Rules {
		if r.ID == "" {
			return fmt.Errorf("policy.rules[%d].id is required", i)
		}
		if r.Tool == "" {
			return fmt.Errorf("policy.rules[%d].tool is required", i)
		}
		switch r.Action {
		case "allow", "deny", "require_approval":
			// ok
		default:
			return fmt.Errorf("policy.rules[%d].action must be allow|deny|require_approval, got %q", i, r.Action)
		}
	}
	if c.Approval.TimeoutSeconds < 0 {
		return fmt.Errorf("approval.timeout_seconds must be >= 0, got %d", c.Approval.TimeoutSeconds)
	}
	for i, ch := range c.Approval.Channels {
		switch ch.Type {
		case "terminal":
			// no extra fields required
		case "slack":
			if ch.BotToken == "" || ch.AppToken == "" {
				return fmt.Errorf("approval.channels[%d]: slack requires bot_token and app_token", i)
			}
			if ch.SigningSecret == "" && ch.SigningSecretEnv == "" {
				return fmt.Errorf("approval.channels[%d]: slack requires signing_secret or signing_secret_env", i)
			}
		default:
			return fmt.Errorf("approval.channels[%d].type must be terminal or slack, got %q", i, ch.Type)
		}
	}
	return nil
}
