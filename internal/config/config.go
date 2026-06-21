// Package config defines the on-disk configuration schema for mcp-socd.
//
// The schema is versioned (SchemaVersion) so future versions can migrate
// without breaking existing installations. The current version is 1.
package config

import (
	"os"
)

// SchemaVersion is the config schema version this binary understands.
// Increment when introducing breaking changes to any struct below.
const SchemaVersion = 1

// Config is the root of the mcp-socd configuration file.
type Config struct {
	// Version is the schema version. Must match SchemaVersion or Load
	// returns an error.
	Version int `yaml:"version"`

	// Upstream describes the MCP server that mcp-socd wraps. The proxy
	// is a stdio wrapper; it spawns this command and forwards JSON-RPC
	// frames between the agent and the child process.
	Upstream Upstream `yaml:"upstream"`

	// Policy controls tool-call evaluation. See Plan §KTD3.
	Policy Policy `yaml:"policy"`

	// Approval configures the approval workflow. See Plan §KTD7-8.
	Approval Approval `yaml:"approval"`

	// Audit configures OCSF audit emission. See Plan §KTD5.
	Audit Audit `yaml:"audit"`

	// Backend declares the EDR / identity backend the proxy dispatches
	// actions to. See Plan §U8. Empty Name leaves the proxy in
	// "no-backend" mode where action dispatch is disabled (useful for
	// policy / catalog development without live API credentials).
	Backend Backend `yaml:"backend,omitempty"`
}

// Upstream describes the wrapped MCP server.
type Upstream struct {
	// Command is the executable and its arguments, in execvp(3) order.
	// Example: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
	Command []string `yaml:"command"`

	// Env holds additional environment variables to set on the child
	// process. Existing process env is preserved unless overridden here.
	Env map[string]string `yaml:"env,omitempty"`
}

// Policy is the allowlist + destructive-verb gate. See Plan §KTD3.
type Policy struct {
	// DefaultAction is what to do when no rule matches. Must be "allow"
	// or "deny". Per Plan R1, the proxy default-denies; "allow" is
	// available for homelab/testing only and emits a startup warning.
	DefaultAction string `yaml:"default_action"`

	// Rules is the ordered list of policy rules. First-match-wins;
	// rules are sorted by specificity at load time (exact > glob > catch-all).
	Rules []Rule `yaml:"rules"`
}

// Rule is a single allowlist entry. See Plan U3 for matching semantics.
type Rule struct {
	// ID is a stable identifier for this rule. Surfaced in audit events
	// as the Finding UID for post-hoc correlation.
	ID string `yaml:"id"`

	// Tool is the MCP tool name to match. Supports glob (`*`, `**`, `?`).
	Tool string `yaml:"tool"`

	// Targets is a list of argument-level target patterns. Empty means
	// "any target". Supports glob matching. Currently used for hostnames
	// in `isolate_endpoint` and usernames in `block_user_account`.
	Targets []string `yaml:"targets,omitempty"`

	// Action is one of: "allow", "deny", "require_approval".
	Action string `yaml:"action"`

	// ApprovalChannel overrides the default approval channel for this rule.
	// Empty means use the workflow's default channel list.
	ApprovalChannel string `yaml:"approval_channel,omitempty"`

	// ApprovalTimeoutSeconds overrides the default 300s timeout for this rule.
	ApprovalTimeoutSeconds int `yaml:"approval_timeout_seconds,omitempty"`
}

// Approval is the approval workflow config. See Plan §KTD7-8.
type Approval struct {
	// TimeoutSeconds is the default per-request timeout. Defaults to 300.
	TimeoutSeconds int `yaml:"timeout_seconds"`

	// Channels is the ordered list of approval channels to try. The
	// first channel that returns a definitive answer wins.
	Channels []Channel `yaml:"channels"`
}

// Channel is one approval channel. Type selects the implementation.
type Channel struct {
	// Type is "terminal" or "slack".
	Type string `yaml:"type"`

	// Slack-specific fields (ignored when Type != "slack").
	BotToken           string `yaml:"bot_token,omitempty"`
	AppToken           string `yaml:"app_token,omitempty"`
	ApproverUserID     string `yaml:"approver_user_id,omitempty"`
	FallbackChannelID  string `yaml:"fallback_channel_id,omitempty"`
	SigningSecretEnv   string `yaml:"signing_secret_env,omitempty"`
	SigningSecret      string `yaml:"signing_secret,omitempty"`
}

// Audit is the OCSF audit emission config. See Plan §KTD5.
type Audit struct {
	// Stdout, when true, emits OCSF records as JSON-lines to stdout.
	// Default is false (records go to stderr to preserve MCP stdout purity).
	// The flag is also exposed as --audit-stdout on the CLI for one-off use.
	Stdout bool `yaml:"stdout"`

	// File is an optional secondary sink. If set, records are appended
	// here as JSON-lines. The file is fsync'd after every event.
	File string `yaml:"file,omitempty"`

	// HeartbeatSeconds, if > 0, emits a heartbeat audit event every N
	// seconds when the proxy is idle. 0 disables heartbeats.
	// Default 60.
	HeartbeatSeconds int `yaml:"heartbeat_seconds"`
}

// Backend declares the EDR / identity backend the proxy dispatches
// actions to. See Plan §U8. Empty Name leaves the proxy in
// "no-backend" mode where action dispatch is disabled (useful for
// policy / catalog development without live API credentials).
//
// The struct is intentionally provider-agnostic at the top level: the
// registry in internal/backend dispatches on Name, while the concrete
// implementation (e.g. internal/backend/falcon) consumes the
// provider-specific fields (Type, Cloud, ClientID, ClientSecret).
type Backend struct {
	// Name is the registry key. Conventionally lowercase
	// ("falcon"); future entries include "sentinelone",
	// "carbonblack". See Plan §U8 and the "Deferred" list.
	Name string `yaml:"name"`

	// Type selects the concrete implementation. Mirrors Name today
	// (only "falcon" ships in v1) but is kept separate so a future
	// "falcon-federal" alias or "falcon-gov" type can share the
	// "falcon" implementation with a different cloud default.
	Type string `yaml:"type"`

	// Cloud is the CrowdStrike cloud region. One of "us-1", "us-2",
	// "eu-1", "us-gov-1". The Falcon implementation passes this
	// straight to gofalcon's ApiConfig.Cloud. Empty means
	// autodiscover via gofalcon.
	Cloud string `yaml:"cloud,omitempty"`

	// ClientID is the OAuth2 client ID for client-credentials
	// authentication. Required when Type is set. May reference an
	// env-var name via ClientIDEnv instead.
	ClientID string `yaml:"client_id,omitempty"`

	// ClientIDEnv, when set, makes ClientID resolved from
	// os.Getenv(ClientIDEnv) at NewClient time. Wins over ClientID
	// when both are present.
	ClientIDEnv string `yaml:"client_id_env,omitempty"`

	// ClientSecret mirrors ClientID/ClientIDEnv for the OAuth2 secret.
	ClientSecret string `yaml:"client_secret,omitempty"`

	// ClientSecretEnv, when set, resolves ClientSecret from
	// os.Getenv(ClientSecretEnv). Wins over ClientSecret.
	ClientSecretEnv string `yaml:"client_secret_env,omitempty"`

	// HostOverride replaces the SDK-computed host. Optional; mostly
	// for tests pointing at falcon/testing or a sandbox tenant.
	HostOverride string `yaml:"host_override,omitempty"`
}

// ResolvedClientID returns the OAuth2 client ID the backend should
// use, preferring ClientIDEnv when set. Returns the empty string when
// neither field is populated. The Backend struct does not hold a
// reference to the live environment, so callers that want env-var
// indirection must call this method (not read ClientID directly).
func (b Backend) ResolvedClientID() string {
	if b.ClientIDEnv != "" {
		return os.Getenv(b.ClientIDEnv)
	}
	return b.ClientID
}

// ResolvedClientSecret mirrors ResolvedClientID for the OAuth2 secret.
func (b Backend) ResolvedClientSecret() string {
	if b.ClientSecretEnv != "" {
		return os.Getenv(b.ClientSecretEnv)
	}
	return b.ClientSecret
}