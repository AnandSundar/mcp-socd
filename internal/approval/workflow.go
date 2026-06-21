// Workflow orchestration for the approval channel fan-out and
// timeout. See Plan §U6 and §KTD8.
//
// The workflow drives one approval request through its channels in
// order, taking the first definitive answer and skipping
// non-definitive ones (Timeout, Error). When the outer timeout
// elapses — either because the request's TimeoutSeconds is reached
// or ctx is cancelled — the workflow returns DecisionTimeout. Every
// decision fires the AuditHook exactly once.
//
// Fan-out semantics: each channel is invoked with the same Request
// (carrying the same HMAC token). Channels are tried sequentially,
// not concurrently, so a fast definitive answer from channel[0] does
// not get raced by a slow non-definitive answer from channel[1]. The
// outer deadline is the source of truth for the request as a whole.

package approval

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"mcp-socd/internal/config"
)

// WorkflowOption configures a Workflow at construction time. The
// functional-options pattern lets the call site stay readable as the
// set of optional dependencies grows (U5 will add WithAuditSink,
// tests will add WithClock, etc.) without breaking the constructor
// signature.
type WorkflowOption func(*Workflow)

// WithSecret overrides the HMAC signing key. Normally the secret is
// loaded by NewWorkflow from config (env first, then literal); this
// option exists for tests and for deployments that load the secret
// from a vault at runtime.
func WithSecret(secret []byte) WorkflowOption {
	return func(w *Workflow) {
		if len(secret) > 0 {
			// Copy to avoid the caller mutating their slice after
			// construction.
			w.secret = append([]byte(nil), secret...)
		}
	}
}

// WithAuditHook installs the callback fired for every decision. See
// the AuditHook type comment.
func WithAuditHook(fn AuditHook) WorkflowOption {
	return func(w *Workflow) {
		w.onDecision = fn
	}
}

// NewWorkflow constructs a Workflow from the proxy's approval
// configuration. Returns an error when the configuration is invalid:
//
//   - no channels configured
//   - no channel could be constructed (unknown type, missing
//     credentials)
//   - no signing secret available (neither env nor literal)
//
// The signing secret is loaded from Channel.SigningSecretEnv first,
// then Channel.SigningSecret as a literal fallback. A literal secret
// in config.yaml is a deployment smell (it ends up on disk in
// plaintext) but is supported for homelab use; production deployments
// should use the env path.
//
// When multiple channels are configured, only the FIRST channel's
// secret is consulted: the HMAC token is workflow-scoped, not
// channel-scoped, so all channels must share the same secret to
// verify each other's tokens.
func NewWorkflow(cfg config.Approval, opts ...WorkflowOption) (*Workflow, error) {
	if len(cfg.Channels) == 0 {
		return nil, errors.New("approval: at least one channel is required")
	}

	w := &Workflow{
		defaultTimeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
	}
	if w.defaultTimeout <= 0 {
		w.defaultTimeout = DefaultTimeoutSeconds * time.Second
	}

	for _, opt := range opts {
		opt(w)
	}

	// Resolve the HMAC secret. If WithSecret was supplied it
	// overrides; otherwise consult the first channel's config. The
	// explicit "no default secret" rule is enforced here: a missing
	// secret is a configuration error, not a permission to mint one
	// (that would defeat the security purpose).
	if len(w.secret) == 0 {
		secret, err := loadSecret(cfg.Channels[0])
		if err != nil {
			return nil, fmt.Errorf("approval: %w", err)
		}
		w.secret = secret
	}
	if len(w.secret) == 0 {
		return nil, errors.New("approval: signing secret is required (set SigningSecretEnv or SigningSecret on the first channel)")
	}

	// Build channels in order. Unknown channel types are an error:
	// silently dropping a misconfigured channel would let the
	// operator think Slack is configured when only Terminal is.
	for i, ch := range cfg.Channels {
		c, err := newChannel(ch, w.secret)
		if err != nil {
			return nil, fmt.Errorf("approval: channel[%d] (%s): %w", i, ch.Type, err)
		}
		w.channels = append(w.channels, c)
	}

	return w, nil
}

// loadSecret reads the HMAC signing secret from the channel config.
// SigningSecretEnv is checked first (then read from os.Getenv);
// SigningSecret is the literal fallback.
func loadSecret(ch config.Channel) ([]byte, error) {
	if ch.SigningSecretEnv != "" {
		v := os.Getenv(ch.SigningSecretEnv)
		if v == "" {
			return nil, fmt.Errorf("signing_secret_env %q is set but the variable is empty or unset",
				ch.SigningSecretEnv)
		}
		return []byte(v), nil
	}
	if ch.SigningSecret != "" {
		return []byte(ch.SigningSecret), nil
	}
	return nil, nil
}

// newChannel constructs the Channel implementation named by
// config.Channel.Type. Returns an error for unknown types; this is
// the boundary between "configured but not built" and "ready".
//
// secret is the workflow's HMAC signing key, threaded through to
// channels that need to verify operator responses (terminal does;
// the slack stub does not).
func newChannel(ch config.Channel, secret []byte) (Channel, error) {
	switch ch.Type {
	case "terminal", "":
		// Empty Type defaults to terminal so the minimal homelab
		// config (a single channel with no type field) just works.
		return NewTerminalChannel(TerminalChannelOptions{
			Reader: terminalReader(),
			Writer: os.Stderr,
			Secret: secret,
			Prompt: fmt.Sprintf("APPROVE %%s? [y/N] (token: %s): ", TokenPlaceholder),
		})
	case "slack":
		return NewSlackChannelStub(ch)
	default:
		return nil, fmt.Errorf("unknown channel type %q", ch.Type)
	}
}

// Approve runs one approval request through the workflow and returns
// the operator's decision. The function blocks until either:
//
//  1. a channel returns a definitive answer (Approve or Deny);
//  2. all channels have returned Timeout or Error;
//  3. the request's effective timeout (TimeoutSeconds or
//     workflow.defaultTimeout) elapses; or
//  4. ctx is cancelled.
//
// In case 3 the workflow returns DecisionTimeout (treated as deny by
// the proxy per Plan §KTD8). In case 4 the workflow returns
// DecisionTimeout as well: the distinction between "outer cancel" and
// "elapsed" is recorded in audit via the AuditHook's req.CreatedAt
// vs. the workflow's stop time.
//
// Every decision fires the AuditHook exactly once. The Channel
// argument is the Name() of the channel that produced the decision
// (or the empty string for the workflow-level timeout).
//
// Channels are tried sequentially: a definitive answer from
// channel[0] stops channel[1] from ever being called. The outer
// timeout is the wall-clock budget for the entire request, not per
// channel, so a single slow channel cannot exhaust the budget.
func (w *Workflow) Approve(ctx context.Context, req Request) Decision {
	if len(w.channels) == 0 {
		// Should be unreachable post-NewWorkflow, but the guard
		// keeps the method safe for callers that synthesize a
		// Workflow with options only.
		w.fireHook(req, DecisionError, "", 0)
		return DecisionError
	}

	// Mint the HMAC token for this request before any channel sees
	// it. The token is workflow-scoped (one secret across channels)
	// so all channels can verify it.
	req.Token = SignToken(req.RequestID, w.secret)
	if req.Token == "" {
		// SignToken returns "" for empty requestID. The workflow
		// cannot safely proceed without a token because channels
		// would not be able to verify responses.
		w.fireHook(req, DecisionError, "", 0)
		return DecisionError
	}

	timeout := w.defaultTimeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}

	start := time.Now()

	// Derive a per-request context with the timeout deadline so
	// each channel honors the request budget. We use the existing
	// ctx as the parent so callers can still cancel the whole
	// request externally (e.g. proxy shutdown).
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Sequential fan-out: try channel[0]; on non-definitive answer,
	// try channel[1]; and so on. The first definitive answer wins.
	//
	// We track the last channel name so that, if every channel
	// fails to produce a definitive answer, the audit hook still
	// has a useful channel label.
	var lastChannel string

	for _, ch := range w.channels {
		d, err := ch.Request(reqCtx, req)
		if err != nil {
			// Transport-level failure collapses to DecisionError
			// so the audit hook sees a uniform vocabulary. We
			// still continue to the next channel — a Slack
			// network blip should not prevent the operator from
			// approving at the terminal.
			d = DecisionError
		}
		lastChannel = ch.Name()
		if d.IsDefinitive() {
			w.fireHook(req, d, lastChannel, time.Since(start))
			return d
		}
	}

	// All channels answered without a definitive decision. Per
	// Plan §KTD8, this collapses to deny-via-timeout so the audit
	// shape is uniform. The channel name surfaces the most recent
	// non-definitive answer so operators can see which channel
	// gave up last (useful for diagnosing Slack-down scenarios).
	w.fireHook(req, DecisionTimeout, lastChannel, time.Since(start))
	return DecisionTimeout
}

// fireHook invokes the audit hook if one is installed. Centralized
// so nil-hook workflows do not need to guard at every call site.
func (w *Workflow) fireHook(req Request, d Decision, channel string, latency time.Duration) {
	if w.onDecision == nil {
		return
	}
	w.onDecision(req, d, channel, latency)
}
