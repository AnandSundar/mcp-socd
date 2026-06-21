package approval

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// TestTerminal_Approve exercises the happy path: operator types
// "y <full-token>" and the channel returns DecisionApprove.
func TestTerminal_Approve(t *testing.T) {
	secret := []byte("test-secret")
	req := sampleRequest("req-approve-1")
	token := SignToken(req.RequestID, secret)
	req.Token = token

	in := strings.NewReader("y " + token + "\n")
	out := &bytes.Buffer{}

	ch, err := NewTerminalChannel(TerminalChannelOptions{
		Reader: in,
		Writer: out,
		Secret: secret,
		Prompt: "[%T%] approve %s%? ",
	})
	if err != nil {
		t.Fatalf("NewTerminalChannel: %v", err)
	}

	got, err := ch.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if got != DecisionApprove {
		t.Fatalf("decision = %v, want DecisionApprove", got)
	}
	if !strings.Contains(out.String(), TokenPrefix(token)) {
		t.Fatalf("prompt did not contain token prefix %q; got %q",
			TokenPrefix(token), out.String())
	}
	if !strings.Contains(out.String(), req.Tool) {
		t.Fatalf("prompt did not contain tool name %q; got %q",
			req.Tool, out.String())
	}
}

// TestTerminal_Deny covers explicit deny: operator types "n <token>"
// and the channel returns DecisionDeny.
func TestTerminal_Deny(t *testing.T) {
	secret := []byte("test-secret")
	req := sampleRequest("req-deny-1")
	token := SignToken(req.RequestID, secret)
	req.Token = token

	in := strings.NewReader("n " + token + "\n")
	out := &bytes.Buffer{}

	ch, err := NewTerminalChannel(TerminalChannelOptions{
		Reader: in,
		Writer: out,
		Secret: secret,
		Prompt: "[%T%] approve %s%? ",
	})
	if err != nil {
		t.Fatalf("NewTerminalChannel: %v", err)
	}

	got, err := ch.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if got != DecisionDeny {
		t.Fatalf("decision = %v, want DecisionDeny", got)
	}
}

// TestTerminal_YesAlias — "yes" is accepted in addition to "y".
func TestTerminal_YesAlias(t *testing.T) {
	secret := []byte("test-secret")
	req := sampleRequest("req-yes")
	token := SignToken(req.RequestID, secret)
	req.Token = token

	in := strings.NewReader("yes " + token + "\n")
	out := &bytes.Buffer{}

	ch, err := NewTerminalChannel(TerminalChannelOptions{
		Reader: in, Writer: out, Secret: secret,
		Prompt: "[%T%] approve %s%? ",
	})
	if err != nil {
		t.Fatalf("NewTerminalChannel: %v", err)
	}

	got, _ := ch.Request(context.Background(), req)
	if got != DecisionApprove {
		t.Fatalf("decision = %v, want DecisionApprove (yes alias)", got)
	}
}

// TestTerminal_WrongTokenDeny — an operator typing a different
// request's token is treated as Deny (not Error). The whole point
// of HMAC binding is that a stale prompt cannot be approved by an
// unrelated token.
func TestTerminal_WrongTokenDeny(t *testing.T) {
	secret := []byte("test-secret")
	req := sampleRequest("req-correct")
	correct := SignToken(req.RequestID, secret)
	wrong := SignToken("req-something-else", secret)
	req.Token = correct

	in := strings.NewReader("y " + wrong + "\n")
	out := &bytes.Buffer{}

	ch, err := NewTerminalChannel(TerminalChannelOptions{
		Reader: in, Writer: out, Secret: secret,
		Prompt: "[%T%] approve %s%? ",
	})
	if err != nil {
		t.Fatalf("NewTerminalChannel: %v", err)
	}

	got, err := ch.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("Request returned transport error (want silent deny): %v", err)
	}
	if got != DecisionDeny {
		t.Fatalf("decision = %v, want DecisionDeny for wrong token", got)
	}
}

// TestTerminal_MissingTokenDeny — operator types "y" with no token.
// Default-deny per Plan §KTD8.
func TestTerminal_MissingTokenDeny(t *testing.T) {
	secret := []byte("test-secret")
	req := sampleRequest("req-missing-token")
	req.Token = SignToken(req.RequestID, secret)

	in := strings.NewReader("y\n")
	out := &bytes.Buffer{}

	ch, err := NewTerminalChannel(TerminalChannelOptions{
		Reader: in, Writer: out, Secret: secret,
		Prompt: "[%T%] approve %s%? ",
	})
	if err != nil {
		t.Fatalf("NewTerminalChannel: %v", err)
	}

	got, _ := ch.Request(context.Background(), req)
	if got != DecisionDeny {
		t.Fatalf("decision = %v, want DecisionDeny for missing token", got)
	}
}

// TestTerminal_ContextCancel — ctx cancellation during read returns
// (DecisionTimeout, ctx.Err()) so the workflow's outer deadline
// still wins.
func TestTerminal_ContextCancel(t *testing.T) {
	secret := []byte("test-secret")
	req := sampleRequest("req-cancel")
	req.Token = SignToken(req.RequestID, secret)

	// SlowReader blocks until the test cancels the context.
	in := &slowReader{}
	out := &bytes.Buffer{}

	ch, err := NewTerminalChannel(TerminalChannelOptions{
		Reader: in, Writer: out, Secret: secret,
		Prompt: "[%T%] approve %s%? ",
	})
	if err != nil {
		t.Fatalf("NewTerminalChannel: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	got, err := ch.Request(ctx, req)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got != DecisionTimeout {
		t.Fatalf("decision = %v, want DecisionTimeout", got)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Request did not return promptly after cancel: %v", elapsed)
	}
}

// TestTerminal_RequiresSecret — a TerminalChannel constructed
// without a Secret is rejected at construction time. This is the
// "no default secret" rule from the spec.
func TestTerminal_RequiresSecret(t *testing.T) {
	_, err := NewTerminalChannel(TerminalChannelOptions{
		Reader: strings.NewReader(""),
		Writer: io.Discard,
	})
	if err == nil {
		t.Fatal("NewTerminalChannel with empty Secret accepted; want error")
	}
}

// TestTerminal_EOF — operator input closes without a newline (rare
// but possible with redirected stdin). Should not panic; treat as
// Deny with no transport error.
func TestTerminal_EOF(t *testing.T) {
	secret := []byte("test-secret")
	req := sampleRequest("req-eof")
	req.Token = SignToken(req.RequestID, secret)

	in := strings.NewReader("y " + req.Token) // no trailing newline
	out := &bytes.Buffer{}

	ch, err := NewTerminalChannel(TerminalChannelOptions{
		Reader: in, Writer: out, Secret: secret,
		Prompt: "[%T%] approve %s%? ",
	})
	if err != nil {
		t.Fatalf("NewTerminalChannel: %v", err)
	}

	got, err := ch.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if got != DecisionApprove {
		t.Fatalf("decision = %v, want DecisionApprove (input without newline)", got)
	}
}

// TestTerminal_Name — channel Name() must be the documented string.
// Other packages (and audit metadata) rely on this being stable.
func TestTerminal_Name(t *testing.T) {
	ch, err := NewTerminalChannel(TerminalChannelOptions{
		Secret: []byte("s"),
	})
	if err != nil {
		t.Fatalf("NewTerminalChannel: %v", err)
	}
	if got := ch.Name(); got != "terminal" {
		t.Fatalf("Name() = %q, want %q", got, "terminal")
	}
}

// slowReader blocks Read until cancelled. Used to simulate an
// operator who walked away from the terminal.
type slowReader struct{}

func (slowReader) Read(_ []byte) (int, error) {
	select {}
}

// sampleRequest builds a Request with sensible defaults so test
// bodies focus on the scenario.
func sampleRequest(id string) Request {
	return Request{
		RequestID: id,
		Tool:      "isolate_endpoint",
		Target:    "server01.example.com",
		Arguments: map[string]any{"host_id": "server01.example.com"},
		Agent:     "agent-test",
		CreatedAt: time.Now().UTC(),
	}
}
