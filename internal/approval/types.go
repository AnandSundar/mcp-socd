// Package approval implements the mcp-socd approval workflow: when the
// policy engine returns DecisionRequireApproval, the proxy blocks the
// tool call here until an out-of-band human responder approves or
// denies, or the configured timeout elapses. See Plan §U6, §U7, and
// §KTD7-8.
//
// # Shape
//
// Request is the in-memory description of the tool call under review.
// It carries the fields the operator must see (tool name, target,
// arguments, requesting agent, timestamp, request id) plus an HMAC
// signature that binds the request id to a server-side secret. The
// signature prevents a malicious tool call from being approved by an
// unrelated prompt.
//
// Decision is the outcome of an approval attempt. Approve and Deny
// are the two definitive answers; Timeout and Error are non-definitive
// — Timeout is treated as Deny by the workflow (per Plan §KTD8:
// no answer means no destructive action) and Error is treated as
// "try next channel". A Channel returns Decision directly; the error
// return is reserved for transport-level failures (channel process
// crashed, network down).
//
// Channel is the abstraction over the supported transports. U6
// implements TerminalChannel; U7 will provide SlackChannel; future
// revisions may add PagerDuty or a webhook channel.
//
// Workflow orchestrates one approval request against the configured
// Channel list, in order, until one returns a definitive answer or
// the timeout elapses. Every decision fires the OnDecision audit hook
// so U5 (audit) can subscribe without an import cycle back to this
// package.
package approval

import (
	"context"
	"time"
)

// DefaultTimeoutSeconds is the Plan §KTD8 default: 300 seconds.
// Per-rule overrides via config.Rule.ApprovalTimeoutSeconds are
// honored by Workflow when the request carries them.
const DefaultTimeoutSeconds = 300

// Decision is the outcome of an approval attempt. It is the
// approval-package analog of policy.Decision but lives in this
// package because the two decisions have different surfaces:
// policy.Decision is one of {Allow,Deny,RequireApproval}, while
// approval.Decision is one of {Approve,Deny,Timeout,Error}.
type Decision int

const (
	// DecisionUnset is the zero value. It must never be returned by
	// a Channel or by Workflow.Approve; production code that sees
	// it indicates a bug.
	DecisionUnset Decision = iota

	// DecisionApprove grants the tool call. Workflow returns this
	// verbatim to the caller; the proxy then forwards the original
	// request to the upstream server.
	DecisionApprove

	// DecisionDeny blocks the tool call. The caller surfaces a
	// JSON-RPC error to the agent with reason "denied".
	DecisionDeny

	// DecisionTimeout means no human responded within the
	// configured window. Per Plan §KTD8 the default behavior is
	// deny; the proxy surfaces a JSON-RPC error with reason
	// "timeout".
	DecisionTimeout

	// DecisionError means the channel itself could not produce an
	// answer for a non-definitive reason (the channel's transport
	// failed, the channel returned an error from Request, etc.).
	// The workflow treats this as a request to try the next
	// configured channel; only after all channels have failed does
	// the workflow return DecisionTimeout.
	DecisionError
)

// String returns the canonical lowercase name used in audit metadata
// and logs. The zero value renders as "unset" so a missing decision is
// impossible to mistake for a real one.
func (d Decision) String() string {
	switch d {
	case DecisionApprove:
		return "approve"
	case DecisionDeny:
		return "deny"
	case DecisionTimeout:
		return "timeout"
	case DecisionError:
		return "error"
	default:
		return "unset"
	}
}

// IsDefinitive reports whether d is a final answer that stops the
// workflow from trying further channels. Approve and Deny are
// definitive; Timeout and Error are not.
func (d Decision) IsDefinitive() bool {
	return d == DecisionApprove || d == DecisionDeny
}

// Request is the description of one tool call under review. The
// workflow creates one Request per call to Approve; the proxy layer
// constructs it from the intercepted tools/call frame and the
// requesting agent's identity.
//
// RequestID is unique per tool call and is the input to the HMAC
// signature (see hmac.go). The same RequestID is surfaced in audit
// events so the proxy and the operator's audit tooling can correlate
// an approval prompt back to the tool call that triggered it.
type Request struct {
	// RequestID is a unique identifier for this approval request.
	// Format is implementation-defined (typically a UUIDv4 string).
	// Used as the HMAC input and surfaced in audit metadata.
	RequestID string

	// Tool is the MCP tool name (e.g. "isolate_endpoint",
	// "block_user_account"). Surfaced in the operator prompt and
	// the audit event's resources[].name field.
	Tool string

	// Target is the primary argument the rule matched against
	// (typically a hostname for isolate_endpoint or a username for
	// block_user_account). Empty when no specific target applies.
	// Surfaced in the operator prompt.
	Target string

	// Arguments is the full decoded arguments map from the agent's
	// tools/call frame. Preserved for the operator prompt and the
	// audit event. Channels typically render the most relevant
	// fields; the entire map is available for completeness.
	Arguments map[string]any

	// Agent is the requesting agent's identity. Format is the
	// MCP client identity string; the proxy layer populates this
	// from the agent's initialize handshake. Surfaced in the audit
	// event's actor field per Plan §KTD4.
	Agent string

	// CreatedAt is the moment the request entered the workflow.
	// Surfaced in the audit event's time field; also used by the
	// HMAC token's expiration logic.
	CreatedAt time.Time

	// Token is the HMAC-bound one-time token the operator must
	// present to approve. Filled in by Workflow.Approve (or by
	// the proxy before calling Approve) so the channel can verify
	// the response. Channels MUST verify the token before
	// accepting a response; see hmac.go.
	Token string

	// PolicyRuleID is the ID of the policy rule that produced
	// DecisionRequireApproval. Surfaced in audit metadata for
	// post-hoc correlation. Optional; empty is permitted when the
	// request comes from the destructive-verb catch-all.
	PolicyRuleID string

	// TimeoutSeconds overrides the workflow's default timeout for
	// this specific request. Zero means "use the workflow default".
	// The Plan §KTD8 default is 300 seconds; per-rule overrides
	// arrive via config.Rule.ApprovalTimeoutSeconds.
	TimeoutSeconds int
}

// Channel is the transport-agnostic abstraction for one approval
// channel. Implementations include TerminalChannel (U6) and
// SlackChannel (U7, future).
//
// Request blocks until the channel has either a definitive answer
// (Approve or Deny) or cannot produce one (timeout or transport
// failure). The error return is reserved for transport-level
// failures; a channel that needs to report "I cannot answer" should
// return (DecisionError, nil) so the workflow can try the next
// channel. A nil error paired with a non-definitive decision
// (Timeout or Error) is the normal signal to fan out.
type Channel interface {
	// Name returns a short stable identifier for this channel
	// ("terminal", "slack"). Surfaced in audit metadata so
	// post-hoc analysts know which transport produced the
	// decision.
	Name() string

	// Request blocks until the operator responds, the context is
	// cancelled, or the channel times out. The returned Decision
	// is the operator's answer (Approve or Deny) when definitive;
	// Timeout means the channel's own wait elapsed without a
	// response; Error means the channel failed in a way that the
	// workflow can recover from by trying the next channel.
	Request(ctx context.Context, req Request) (Decision, error)
}

// AuditHook is the callback Workflow fires for every decision. The
// proxy layer wires this in so U5 can subscribe to approval outcomes
// without this package importing the audit package (which would
// create an import cycle).
//
// Latency is the wall-clock time from Workflow.Approve entry to the
// decision (whether Approve, Deny, Timeout, or Error). Channel is
// the Name() of the channel that produced the decision; it is the
// empty string when no channel answered (i.e. the workflow itself
// timed out before any channel returned).
type AuditHook func(req Request, d Decision, channel string, latency time.Duration)

// Workflow orchestrates one approval request against the configured
// channels. It is constructed once per process (typically by the
// proxy layer at startup) and reused for every tool call that
// triggers DecisionRequireApproval.
//
// The zero value is not usable; construct via NewWorkflow so the
// secret can be loaded and validated up front.
type Workflow struct {
	// channels is the ordered list of transports to try. The first
	// channel that returns a definitive decision wins; non-definitive
	// results (Timeout, Error) cause the workflow to fall through to
	// the next channel.
	channels []Channel

	// defaultTimeout is the per-request timeout applied when the
	// request's TimeoutSeconds field is zero. Set from
	// config.Approval.TimeoutSeconds at construction time.
	defaultTimeout time.Duration

	// secret is the HMAC signing key. Required: Workflow refuses
	// to construct without one because a missing key would make
	// the approval token forgeable.
	secret []byte

	// onDecision is the audit hook. May be nil; the workflow guards
	// against nil at every call site.
	onDecision AuditHook
}

// Secret returns the HMAC signing key bytes. Exposed so callers
// (typically the proxy layer) can construct new HMAC tokens for
// sub-requests without re-reading the secret from disk.
//
// The returned slice aliases internal storage; do not mutate it.
func (w *Workflow) Secret() []byte {
	return w.secret
}
