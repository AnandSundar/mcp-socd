// Package config defines the on-disk configuration schema for mcp-socd.
//
// The schema is versioned (SchemaVersion) so future versions can migrate
// without breaking existing installations. The current version is 1.
package config

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
	BotToken         string `yaml:"bot_token,omitempty"`
	AppToken         string `yaml:"app_token,omitempty"`
	ApproverUserID   string `yaml:"approver_user_id,omitempty"`
	SigningSecretEnv string `yaml:"signing_secret_env,omitempty"`
	SigningSecret    string `yaml:"signing_secret,omitempty"`
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
