package approval

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mcp-socd/internal/config"
)

// fakeChannel is a programmable Channel for workflow tests. Each
// test wires the closure that produces a Decision and an error
// given the Request the workflow hands it.
type fakeChannel struct {
	name string

	// requestFn is invoked when the workflow calls Request. It
	// receives the Request and returns (Decision, error). Tests
	// can inspect req.Token inside to assert HMAC binding.
	requestFn func(req Request) (Decision, error)

	// delay simulates a slow channel; the workflow must not be
	// blocked beyond this if a faster channel produces a
	// definitive answer.
	delay time.Duration

	// lastReq is captured for assertions about what the workflow
	// passed to the channel.
	lastReq atomic.Pointer[Request]
}

func (f *fakeChannel) Name() string { return f.name }

func (f *fakeChannel) Request(ctx context.Context, req Request) (Decision, error) {
	f.lastReq.Store(&req)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return DecisionTimeout, ctx.Err()
		}
	}
	if f.requestFn == nil {
		return DecisionTimeout, nil
	}
	return f.requestFn(req)
}

// TestWorkflow_TerminalApprove — Plan scenario #1: terminal channel
// returns Approve, workflow returns Approve.
func TestWorkflow_TerminalApprove(t *testing.T) {
	secret := []byte("workflow-secret-1")
	w := mustWorkflow(t, secret, []Channel{
		&fakeChannel{
			name: "terminal",
			requestFn: func(req Request) (Decision, error) {
				if req.Token == "" {
					return DecisionDeny, errors.New("no token on request")
				}
				if !strings.HasPrefix(req.Token, TokenPrefix(SignToken(req.RequestID, secret))) {
					return DecisionDeny, errors.New("token does not match expected prefix")
				}
				return DecisionApprove, nil
			},
		},
	})

	got := w.Approve(context.Background(), sampleRequest("req-1"))
	if got != DecisionApprove {
		t.Fatalf("decision = %v, want DecisionApprove", got)
	}
}

// TestWorkflow_TerminalDeny — Plan scenario #2: terminal channel
// returns Deny, workflow returns Deny.
func TestWorkflow_TerminalDeny(t *testing.T) {
	secret := []byte("workflow-secret-2")
	w := mustWorkflow(t, secret, []Channel{
		&fakeChannel{
			name: "terminal",
			requestFn: func(_ Request) (Decision, error) {
				return DecisionDeny, nil
			},
		},
	})

	got := w.Approve(context.Background(), sampleRequest("req-2"))
	if got != DecisionDeny {
		t.Fatalf("decision = %v, want DecisionDeny", got)
	}
}

// TestWorkflow_Timeout — Plan scenario #3: when no response arrives
// within the configured timeout, the workflow returns
// DecisionTimeout. We use a channel that honors ctx (via fakeChannel.delay)
// and never produces a definitive answer; the workflow must return
// DecisionTimeout promptly after the per-request deadline fires.
func TestWorkflow_Timeout(t *testing.T) {
	secret := []byte("workflow-secret-3")
	// delay=10s forces the channel to wait until ctx cancels; the
	// workflow's per-request context cancels after 1s, so the
	// channel returns DecisionTimeout + context.DeadlineExceeded.
	channel := &fakeChannel{
		name:  "slow",
		delay: 10 * time.Second,
		// requestFn is not invoked because delay's select returns
		// first when ctx fires.
	}
	w := mustWorkflow(t, secret, []Channel{channel})

	req := sampleRequest("req-3")
	req.TimeoutSeconds = 1 // 1s; tight enough for CI

	start := time.Now()
	got := w.Approve(context.Background(), req)
	elapsed := time.Since(start)

	if got != DecisionTimeout {
		t.Fatalf("decision = %v, want DecisionTimeout", got)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("workflow did not respect 1s timeout: elapsed %v", elapsed)
	}
}

// TestWorkflow_ChannelFanOut — Plan scenario #4: when channel[0]
// returns Timeout/Error, try channel[1]. When channel[1] returns a
// definitive answer, the workflow returns that answer.
func TestWorkflow_ChannelFanOut(t *testing.T) {
	secret := []byte("workflow-secret-4")

	terminal := &fakeChannel{
		name: "terminal",
		requestFn: func(_ Request) (Decision, error) {
			return DecisionTimeout, nil // first channel cannot answer
		},
	}
	slack := &fakeChannel{
		name: "slack",
		requestFn: func(_ Request) (Decision, error) {
			return DecisionApprove, nil // second channel answers
		},
	}

	w := mustWorkflow(t, secret, []Channel{terminal, slack})

	got := w.Approve(context.Background(), sampleRequest("req-4"))
	if got != DecisionApprove {
		t.Fatalf("decision = %v, want DecisionApprove (via fallback)", got)
	}
}

// TestWorkflow_ChannelFanOutError — companion to scenario #4: a
// transport-level error on channel[0] also causes a fallback to
// channel[1]. This is the "Slack network blip should not prevent
// the terminal from approving" property.
func TestWorkflow_ChannelFanOutError(t *testing.T) {
	secret := []byte("workflow-secret-4e")

	slack := &fakeChannel{
		name: "slack",
		requestFn: func(_ Request) (Decision, error) {
			return DecisionError, errors.New("network blip")
		},
	}
	terminal := &fakeChannel{
		name: "terminal",
		requestFn: func(_ Request) (Decision, error) {
			return DecisionApprove, nil
		},
	}

	w := mustWorkflow(t, secret, []Channel{slack, terminal})

	got := w.Approve(context.Background(), sampleRequest("req-4e"))
	if got != DecisionApprove {
		t.Fatalf("decision = %v, want DecisionApprove (via terminal fallback)", got)
	}
}

// TestWorkflow_HMACBindingAcrossChannels — every channel receives a
// Request with a non-empty Token that verifies against the
// workflow's secret. This is the core Plan §U6 property: the token
// is workflow-scoped, not channel-scoped.
func TestWorkflow_HMACBindingAcrossChannels(t *testing.T) {
	secret := []byte("workflow-secret-hmac")
	var tokensSeen sync.Map

	a := &fakeChannel{
		name: "terminal",
		requestFn: func(req Request) (Decision, error) {
			tokensSeen.Store("a", req.Token)
			return DecisionTimeout, nil
		},
	}
	b := &fakeChannel{
		name: "slack",
		requestFn: func(req Request) (Decision, error) {
			tokensSeen.Store("b", req.Token)
			return DecisionDeny, nil
		},
	}

	w := mustWorkflow(t, secret, []Channel{a, b})
	_ = w.Approve(context.Background(), sampleRequest("req-hmac"))

	ta, _ := tokensSeen.Load("a")
	tb, _ := tokensSeen.Load("b")
	if ta == nil || tb == nil {
		t.Fatalf("channels did not receive tokens: a=%v b=%v", ta, tb)
	}
	if ta != tb {
		t.Fatalf("channels received different tokens: a=%q b=%q", ta, tb)
	}
	// And the token must verify under the workflow's secret.
	if err := VerifyToken("req-hmac", ta.(string), secret); err != nil {
		t.Fatalf("channel token did not verify: %v", err)
	}
}

// TestWorkflow_AuditHookFires — Plan scenario #6: the OnDecision
// callback receives the right arguments for each decision type.
//
// The hook records every invocation; we then assert that one (and
// only one) hook fired per Approve call, and that the recorded
// arguments match the workflow's decision.
func TestWorkflow_AuditHookFires(t *testing.T) {
	secret := []byte("workflow-secret-audit")
	type hookEvent struct {
		reqID   string
		dec     Decision
		channel string
		latency time.Duration
	}
	var (
		mu     sync.Mutex
		events []hookEvent
	)
	hook := func(req Request, d Decision, channel string, latency time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, hookEvent{
			reqID:   req.RequestID,
			dec:     d,
			channel: channel,
			latency: latency,
		})
	}

	// Case A: Approve path.
	wApprove := mustWorkflow(t, secret, []Channel{
		&fakeChannel{
			name:      "terminal",
			requestFn: func(_ Request) (Decision, error) { return DecisionApprove, nil },
		},
	}, WithAuditHook(hook))
	events = events[:0]
	_ = wApprove.Approve(context.Background(), sampleRequest("req-a-audit"))
	if len(events) != 1 {
		t.Fatalf("Approve: hook fired %d times, want 1", len(events))
	}
	if events[0].dec != DecisionApprove {
		t.Fatalf("Approve: hook dec = %v, want DecisionApprove", events[0].dec)
	}
	if events[0].reqID != "req-a-audit" {
		t.Fatalf("Approve: hook reqID = %q, want req-a-audit", events[0].reqID)
	}
	if events[0].channel != "terminal" {
		t.Fatalf("Approve: hook channel = %q, want terminal", events[0].channel)
	}

	// Case B: Deny path.
	wDeny := mustWorkflow(t, secret, []Channel{
		&fakeChannel{
			name:      "terminal",
			requestFn: func(_ Request) (Decision, error) { return DecisionDeny, nil },
		},
	}, WithAuditHook(hook))
	events = events[:0]
	_ = wDeny.Approve(context.Background(), sampleRequest("req-b-audit"))
	if len(events) != 1 || events[0].dec != DecisionDeny {
		t.Fatalf("Deny: hook events = %+v, want one DecisionDeny", events)
	}

	// Case C: Timeout path (channel returns Timeout; workflow
	// collapses to DecisionTimeout).
	wTimeout := mustWorkflow(t, secret, []Channel{
		&fakeChannel{
			name:      "terminal",
			requestFn: func(_ Request) (Decision, error) { return DecisionTimeout, nil },
		},
	}, WithAuditHook(hook))
	events = events[:0]
	_ = wTimeout.Approve(context.Background(), sampleRequest("req-c-audit"))
	if len(events) != 1 || events[0].dec != DecisionTimeout {
		t.Fatalf("Timeout: hook events = %+v, want one DecisionTimeout", events)
	}
}

// TestWorkflow_NewWorkflowRequiresSecret — Plan §KTD8: a missing
// signing secret is a configuration error, not a permission to
// generate one. Construction must fail loud.
func TestWorkflow_NewWorkflowRequiresSecret(t *testing.T) {
	cfg := config.Approval{
		TimeoutSeconds: 5,
		Channels: []config.Channel{
			{Type: "terminal"},
		},
	}
	if _, err := NewWorkflow(cfg); err == nil {
		t.Fatal("NewWorkflow accepted config without signing secret")
	}
}

// TestWorkflow_NewWorkflowRequiresChannel — a workflow with zero
// channels is a configuration error (the proxy would silently deny
// every tool call without an audit-trail-bearing operator decision).
func TestWorkflow_NewWorkflowRequiresChannel(t *testing.T) {
	cfg := config.Approval{
		TimeoutSeconds: 5,
		Channels:       nil,
	}
	if _, err := NewWorkflow(cfg, WithSecret([]byte("s"))); err == nil {
		t.Fatal("NewWorkflow accepted config without channels")
	}
}

// TestWorkflow_SecretFromEnv — when only SigningSecretEnv is set,
// NewWorkflow reads the env var. We use t.Setenv for isolation.
func TestWorkflow_SecretFromEnv(t *testing.T) {
	t.Setenv("MCP_SOCD_TEST_SIGNING_SECRET", "env-loaded-secret")

	cfg := config.Approval{
		TimeoutSeconds: 5,
		Channels: []config.Channel{
			{Type: "terminal", SigningSecretEnv: "MCP_SOCD_TEST_SIGNING_SECRET"},
		},
	}
	w, err := NewWorkflow(cfg)
	if err != nil {
		t.Fatalf("NewWorkflow: %v", err)
	}
	if string(w.Secret()) != "env-loaded-secret" {
		t.Fatalf("Secret() = %q, want env-loaded-secret", string(w.Secret()))
	}
}

// TestWorkflow_UnknownChannelType — a config typo (Type="slak") must
// be rejected at construction, not silently dropped.
func TestWorkflow_UnknownChannelType(t *testing.T) {
	cfg := config.Approval{
		TimeoutSeconds: 5,
		Channels: []config.Channel{
			{Type: "terminal", SigningSecret: "s"},
			{Type: "slak"}, // typo
		},
	}
	if _, err := NewWorkflow(cfg); err == nil {
		t.Fatal("NewWorkflow accepted unknown channel type")
	}
}

// mustWorkflow builds a Workflow for tests. It uses the test's
// channel list directly (bypassing config.Channel parsing) so the
// test body can focus on scenario semantics.
func mustWorkflow(t *testing.T, secret []byte, channels []Channel, opts ...WorkflowOption) *Workflow {
	t.Helper()
	w := &Workflow{
		channels:       channels,
		defaultTimeout: 300 * time.Second,
		secret:         append([]byte(nil), secret...),
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}
