// Package policy implements the mcp-socd policy engine: an allowlist
// plus a destructive-verb gate. See Plan §U3 and §KTD3.
//
// The engine evaluates every intercepted tools/call against a compiled
// Policy. Rules are matched first-match-wins by specificity (exact
// tool > glob tool > catch-all). A last-resort catch-all rule
// intercepts any tool whose name contains a destructive verb
// (delete|drop|truncate|revoke|disable|wipe|purge) and requires
// out-of-band approval regardless of catalog membership.
//
// The compiled Policy is held behind an atomic.Pointer so in-flight
// Evaluate calls always see a single consistent snapshot; that same
// snapshot is what ends up in the audit event's policy_version.
//
// Cardinal rule from Plan R1/R3: a broken or missing policy must
// never result in tool calls being allowed by default. Compile errors
// surface here so the loader can refuse to start.
package policy

import (
	"sync/atomic"

	"mcp-socd/internal/config"

	"github.com/gobwas/glob"
)

// Decision is the outcome of an Evaluate call. It maps directly to
// the policy.actions enum (allow|deny|require_approval) and to the
// OCSF verdict_id values 5/6/7/8/9 documented in Plan §KTD4.
type Decision int

const (
	// DecisionUnset is the zero value. It must never be returned by
	// Evaluate; production code that sees it indicates a bug.
	DecisionUnset Decision = iota

	// DecisionAllow forwards the call to the upstream MCP server.
	// Maps to OCSF verdict_id 5 (Policy Allow).
	DecisionAllow

	// DecisionDeny blocks the call and returns a JSON-RPC error to
	// the agent. Maps to OCSF verdict_id 6 (Policy Deny).
	DecisionDeny

	// DecisionRequireApproval routes the call to the approval
	// workflow (U6). Maps to OCSF verdict_id 7 (Awaiting Approval)
	// before the user responds, then 8/9 based on outcome.
	DecisionRequireApproval
)

// String returns the canonical lowercase action name used in config
// and audit metadata.
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionDeny:
		return "deny"
	case DecisionRequireApproval:
		return "require_approval"
	default:
		return "unset"
	}
}

// ParseDecision converts a string action ("allow", "deny",
// "require_approval") into a Decision. Returns DecisionUnset and
// false for unknown values; callers should treat unknown actions as
// compile errors.
func ParseDecision(s string) (Decision, bool) {
	switch s {
	case "allow":
		return DecisionAllow, true
	case "deny":
		return DecisionDeny, true
	case "require_approval":
		return DecisionRequireApproval, true
	default:
		return DecisionUnset, false
	}
}

// Call is the input to Engine.Evaluate. It carries the fields the
// policy engine needs to make a decision; the rest of the JSON-RPC
// frame stays in the proxy layer.
//
// Tool is the MCP tool name (e.g. "isolate_endpoint",
// "truncate_table"). Target is the primary argument the rule matches
// against — typically a hostname for isolate_endpoint or a username
// for block_user_account — extracted by the proxy layer from the
// tools/call arguments. Empty Target means "any target".
type Call struct {
	// Tool is the MCP tool name as called by the agent.
	Tool string

	// Target is the primary argument the rule's Targets list matches
	// against. Empty means the rule's Targets must also be empty
	// (or the rule must explicitly allow any target).
	Target string

	// Arguments is the full decoded arguments map, preserved for
	// downstream consumers (audit, approval). The engine itself only
	// reads Tool and Target.
	Arguments map[string]any
}

// CompiledRule is the runtime form of a config.Rule. It embeds the
// raw config for stable IDs and the original action string, plus
// pre-parsed glob patterns for the tool name and each target.
//
// We compose rather than duplicate so a config reload that updates
// one field propagates the rest of the rule's metadata unchanged,
// and so the audit emitter can always reach back to the raw ID
// without an indirection.
type CompiledRule struct {
	// Raw is the original config.Rule. ID and the original Action
	// string are surfaced in audit events; ApprovalChannel and
	// ApprovalTimeoutSeconds are read by the approval workflow.
	Raw config.Rule

	// ToolGlob matches the MCP tool name. When the rule's tool field
	// contains no glob metacharacters, ToolGlob is nil and matches
	// are done by exact equality.
	ToolGlob glob.Glob

	// TargetGlobs is the compiled list of target patterns. A rule
	// with no targets matches any target (empty list). When the list
	// is non-empty, at least one target must match (OR semantics).
	TargetGlobs []glob.Glob

	// Decision is the parsed action. Pre-parsed so Evaluate does not
	// re-parse strings on the hot path.
	Decision Decision

	// Specificity is the rank used to sort rules at compile time.
	// Lower is more specific. See compileRule.
	Specificity int
}

// Policy is a compiled, immutable set of CompiledRules. Construct
// with Compile; mutate by handing a new Policy to Engine.Update.
//
// Rules are stored sorted by Specificity ascending (most specific
// first). Evaluate walks them in order; the first match wins. The
// destructive-verb catch-all is appended last with the highest
// specificity so it only fires when no explicit rule matched.
type Policy struct {
	// Version is a monotonically increasing identifier stamped into
	// every audit event. Incremented by the loader on hot-reload;
	// survives the atomic.Pointer swap so consumers can correlate
	// audit events with the policy that produced them.
	Version int

	// Rules is the sorted list of explicit rules. First match wins.
	Rules []CompiledRule

	// DefaultDecision is what to return when no explicit rule
	// matches AND the destructive-verb gate does not fire. Defaults
	// to DecisionDeny (per Plan R1: default-deny).
	DefaultDecision Decision

	// CatchAll is the synthetic destructive-verb catch-all rule. It
	// is the last rule Evaluate considers; it never replaces an
	// explicit rule's match.
	CatchAll CompiledRule
}

// Engine holds the active Policy behind an atomic.Pointer so
// concurrent Evaluate calls always read a single consistent
// snapshot. Engine is safe for concurrent use by multiple goroutines.
//
// The zero value is ready to use with a deny-by-default empty
// policy; production code should construct via New.
type Engine struct {
	current atomic.Pointer[Policy]
}

// globMetaChars is the set of characters that indicate a pattern is
// a glob rather than a literal string. Matches gobwas/glob's
// metacharacter set ('*', '?', '[', '{').
const globMetaChars = "*?[{"
