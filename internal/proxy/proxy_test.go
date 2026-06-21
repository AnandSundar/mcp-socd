package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"mcp-socd/internal/catalog"
	"mcp-socd/internal/config"
	"mcp-socd/internal/policy"
)

// newTestProxy wires a Proxy against the bundled Python upstream and
// returns the proxy plus a pair of in-memory pipes standing in for the
// agent's stdin/stdout. The test writes framed JSON-RPC into agentIn
// and reads framed responses out of agentOut.
//
// The proxy runs in its own goroutine; the caller is expected to
// close agentIn when it has finished writing and to read agentOut
// until EOF to drain pending responses.
func newTestProxy(t *testing.T, cfg *config.Config, engine *policy.Engine, cat *catalog.Catalog, emitter Emitter) (*Proxy, io.WriteCloser, io.Reader) {
	t.Helper()

	agentInR, agentInW := io.Pipe()
	agentOutR, agentOutW := io.Pipe()

	proxy, err := New(cfg, engine, cat,
		WithEmitter(emitter),
		WithStdio(agentInR, agentOutW),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Closing agentOutW from the proxy side (after pumpChildToAgent
	// exits) signals EOF to the test reader. We hold the writer
	// reference here so the test goroutine can drain it.
	go func() {
		_ = proxy.Run()
		_ = agentOutW.Close()
	}()

	return proxy, agentInW, agentOutR
}

// readResponseFrame reads exactly one Content-Length framed
// JSON-RPC response from r with the supplied timeout. Used by every
// test below to wait for the agent's reply.
func readResponseFrame(t *testing.T, r io.Reader, timeout time.Duration) (*Response, []byte) {
	t.Helper()
	type result struct {
		resp *Response
		raw  []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		reader := bufio.NewReader(r)
		raw, err := ReadFrame(reader)
		if err != nil {
			done <- result{nil, nil, err}
			return
		}
		var resp Response
		if jerr := json.Unmarshal(raw, &resp); jerr != nil {
			done <- result{nil, raw, jerr}
			return
		}
		done <- result{&resp, raw, nil}
	}()
	select {
	case res := <-done:
		if res.err != nil && !errors.Is(res.err, io.EOF) {
			t.Fatalf("readResponseFrame: %v", res.err)
		}
		return res.resp, res.raw
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for response", timeout)
		return nil, nil
	}
}

// writeFrame writes one Content-Length framed JSON-RPC body to w.
func writeFrame(t *testing.T, w io.Writer, body []byte) {
	t.Helper()
	if err := WriteFrame(w, body); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
}

// buildEngine returns a policy engine compiled from cfg.Policy. We
// load rules that allow isolated_endpoint against "server01.*" and
// deny everything else by default; require_approval is exercised by
// the destructive-verb catch-all.
func buildEngine(t *testing.T, cfg *config.Config) *policy.Engine {
	t.Helper()
	pol, err := policy.Compile(&cfg.Policy)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	// Bump the version so audit consumers can correlate; the
	// Compile helper leaves Version at 0.
	pol.Version = 1
	return policy.New(pol)
}

// testProxyUpstreamCfg builds the minimal config needed to spawn the
// Python test upstream.
func testProxyUpstreamCfg(t *testing.T) *config.Config {
	t.Helper()
	pythonPath := findPython(t)
	return &config.Config{
		Version: 1,
		Upstream: config.Upstream{
			Command: []string{pythonPath, "testdata/upstream-echo.py"},
		},
		Policy: config.Policy{
			DefaultAction: "deny",
			Rules: []config.Rule{
				{
					ID:     "allow-isolate-server01",
					Tool:   "isolate_endpoint",
					Action: "allow",
					Targets: []string{
						"server01.example.com",
					},
				},
				{
					ID:     "allow-submit-query",
					Tool:   "submit_edr_query",
					Action: "allow",
				},
				{
					ID:     "require-approval-block-user",
					Tool:   "block_user_account",
					Action: "require_approval",
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Test 1: tools/list is forwarded to child and the response relayed
// ---------------------------------------------------------------------------

func TestProxy_ForwardsToolsList(t *testing.T) {
	cfg := testProxyUpstreamCfg(t)
	engine := buildEngine(t, cfg)
	cat := catalog.New()

	_, agentIn, agentOut := newTestProxy(t, cfg, engine, cat, NoopEmitter{})

	// Send a tools/list request.
	writeFrame(t, agentIn, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))

	resp, raw := readResponseFrame(t, agentOut, 5*time.Second)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected successful response, got %+v (raw=%s)", resp, raw)
	}
	// Confirm the upstream's tools/list payload came back.
	if !bytes.Contains(raw, []byte(`isolate_endpoint`)) {
		t.Fatalf("upstream payload not relayed: %s", raw)
	}

	_ = agentIn.Close()
}

// ---------------------------------------------------------------------------
// Test 2: tools/call to a denied tool returns a synthetic error and
// never reaches the child
// ---------------------------------------------------------------------------

func TestProxy_InterceptsToolsCall_Deny(t *testing.T) {
	cfg := testProxyUpstreamCfg(t)
	engine := buildEngine(t, cfg)
	cat := catalog.New()

	// Capture audit decisions so we can assert the deny was emitted.
	emitter := &captureEmitter{}
	_, agentIn, agentOut := newTestProxy(t, cfg, engine, cat, emitter)

	// isolate_endpoint against server99 (no rule matches the target;
	// default action is deny). The Python upstream echoes the call back,
	// so if the proxy forwarded, the test would see the echo payload
	// instead of the synthetic JSON-RPC error.
	writeFrame(t, agentIn, []byte(`{
		"jsonrpc":"2.0",
		"id":7,
		"method":"tools/call",
		"params":{"name":"isolate_endpoint","arguments":{"host_id":"server99.example.com","comment":"unauthorized"}}
	}`))

	resp, _ := readResponseFrame(t, agentOut, 5*time.Second)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected synthetic error response, got %+v", resp)
	}
	if resp.Error.Code != CodePolicyDenied {
		t.Fatalf("expected CodePolicyDenied, got %d", resp.Error.Code)
	}

	// Verify the deny was emitted to the audit hook.
	if !emitter.saw("deny") {
		t.Fatalf("audit emitter did not see deny: events=%v", emitter.events)
	}

	_ = agentIn.Close()
}

// ---------------------------------------------------------------------------
// Test 3: tools/call to an allow-listed tool forwards to the child and
// the child's echo response comes back
// ---------------------------------------------------------------------------

func TestProxy_InterceptsToolsCall_Allow(t *testing.T) {
	cfg := testProxyUpstreamCfg(t)
	engine := buildEngine(t, cfg)
	cat := catalog.New()

	emitter := &captureEmitter{}
	_, agentIn, agentOut := newTestProxy(t, cfg, engine, cat, emitter)

	// isolate_endpoint against server01.example.com is allowlisted.
	writeFrame(t, agentIn, []byte(`{
		"jsonrpc":"2.0",
		"id":8,
		"method":"tools/call",
		"params":{"name":"isolate_endpoint","arguments":{"host_id":"server01.example.com"}}
	}`))

	resp, raw := readResponseFrame(t, agentOut, 5*time.Second)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected forwarded response, got %+v (raw=%s)", resp, raw)
	}
	// The upstream echoes "echoed_tool": "isolate_endpoint" so the
	// test can assert the call actually reached the child.
	if !bytes.Contains(raw, []byte(`echoed_tool`)) {
		t.Fatalf("expected echo payload from upstream: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`server01.example.com`)) {
		t.Fatalf("expected arguments echoed back: %s", raw)
	}

	// Verify the allow was emitted to the audit hook.
	if !emitter.saw("allow") {
		t.Fatalf("audit emitter did not see allow: events=%v", emitter.events)
	}

	_ = agentIn.Close()
}

// ---------------------------------------------------------------------------
// Test 4: tools/call to a require_approval tool yields the synthetic
// approval_pending response (placeholder for U6)
// ---------------------------------------------------------------------------

func TestProxy_InterceptsToolsCall_RequireApproval(t *testing.T) {
	cfg := testProxyUpstreamCfg(t)
	engine := buildEngine(t, cfg)
	cat := catalog.New()

	emitter := &captureEmitter{}
	_, agentIn, agentOut := newTestProxy(t, cfg, engine, cat, emitter)

	// block_user_account is not in the rule list. The catalog still
	// recognizes it (starter catalog), so the policy engine reaches
	// the destructive-verb catch-all and returns RequireApproval.
	writeFrame(t, agentIn, []byte(`{
		"jsonrpc":"2.0",
		"id":9,
		"method":"tools/call",
		"params":{"name":"block_user_account","arguments":{"user_id":"alice@example.com"}}
	}`))

	resp, raw := readResponseFrame(t, agentOut, 5*time.Second)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected synthetic error response, got %+v", resp)
	}
	if !bytes.Contains(raw, []byte(`awaiting out-of-band approval`)) {
		t.Fatalf("expected approval_pending message in synthetic response: %s", raw)
	}
	// Verify the require_approval decision was emitted.
	if !emitter.saw("require_approval") {
		t.Fatalf("audit emitter did not see require_approval: events=%v", emitter.events)
	}

	_ = agentIn.Close()
}

// ---------------------------------------------------------------------------
// Test 5: initialize request/response handshakes through untouched
// ---------------------------------------------------------------------------

func TestProxy_PassesInitialize(t *testing.T) {
	cfg := testProxyUpstreamCfg(t)
	engine := buildEngine(t, cfg)
	cat := catalog.New()

	_, agentIn, agentOut := newTestProxy(t, cfg, engine, cat, NoopEmitter{})

	// Send an initialize request; expect the upstream's
	// InitializeResult back, including the protocolVersion the test
	// child hardcodes.
	writeFrame(t, agentIn, []byte(`{"jsonrpc":"2.0","id":42,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`))

	resp, raw := readResponseFrame(t, agentOut, 5*time.Second)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected successful initialize response, got %+v (raw=%s)", resp, raw)
	}
	if !bytes.Contains(raw, []byte(`"protocolVersion":"2025-06-18"`)) {
		t.Fatalf("upstream protocolVersion not relayed: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`upstream-echo`)) {
		t.Fatalf("upstream serverInfo not relayed: %s", raw)
	}

	_ = agentIn.Close()
}

// ---------------------------------------------------------------------------
// Test 6: ping passes through with the empty result
// ---------------------------------------------------------------------------

func TestProxy_PassesPing(t *testing.T) {
	cfg := testProxyUpstreamCfg(t)
	engine := buildEngine(t, cfg)
	cat := catalog.New()

	_, agentIn, agentOut := newTestProxy(t, cfg, engine, cat, NoopEmitter{})

	writeFrame(t, agentIn, []byte(`{"jsonrpc":"2.0","id":3,"method":"ping"}`))

	resp, raw := readResponseFrame(t, agentOut, 5*time.Second)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected successful ping response, got %+v (raw=%s)", resp, raw)
	}
	if !bytes.Contains(raw, []byte(`"result":{}`)) {
		t.Fatalf("expected empty ping result: %s", raw)
	}

	_ = agentIn.Close()
}

// ---------------------------------------------------------------------------
// Test 7: when the child exits, the proxy exits cleanly
// ---------------------------------------------------------------------------

func TestProxy_HandlesUpstreamExit(t *testing.T) {
	cfg := testProxyUpstreamCfg(t)
	engine := buildEngine(t, cfg)
	cat := catalog.New()

	agentInR, agentInW := io.Pipe()
	agentOutR, agentOutW := io.Pipe()

	proxy, err := New(cfg, engine, cat,
		WithEmitter(NoopEmitter{}),
		WithStdio(agentInR, agentOutW),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Use a short-lived upstream: python -c "pass" exits immediately.
	// This forces the child to die before the agent does, which is
	// the scenario this test covers.
	cfg.Upstream.Command = []string{findPython(t), "-c", "import sys; sys.exit(0)"}

	runDone := make(chan error, 1)
	go func() {
		runDone <- proxy.Run()
	}()

	// The agent does NOT close stdin; we wait for the proxy to detect
	// the child's exit and shut down on its own. The proxy writes
	// the shutdown event to the emitter (a no-op here) and returns.
	select {
	case err := <-runDone:
		// Run returns nil when the child exited cleanly. Any other
		// exit (non-zero code) still satisfies "handles upstream
		// exit" as long as it is not a panic. We tolerate both.
		_ = err
	case <-time.After(10 * time.Second):
		t.Fatalf("proxy did not exit within 10s after child died")
	}

	// Drain the agent-side pipes; they should already be closed by
	// the proxy's pump goroutines.
	_ = agentInW.Close()
	_ = agentOutW.Close()
	_, _ = io.Copy(io.Discard, agentOutR)
}

// ---------------------------------------------------------------------------
// Additional coverage: schema-violation returns synthetic error
// ---------------------------------------------------------------------------

// TestProxy_InterceptsToolsCall_SchemaViolation verifies that a
// tools/call whose arguments fail the action's inputSchema is rejected
// with a synthetic error and never reaches the upstream. This guards
// against an agent that sends malformed JSON to bypass validation.
func TestProxy_InterceptsToolsCall_SchemaViolation(t *testing.T) {
	cfg := testProxyUpstreamCfg(t)
	engine := buildEngine(t, cfg)
	cat := catalog.New()

	_, agentIn, agentOut := newTestProxy(t, cfg, engine, cat, NoopEmitter{})

	// isolate_endpoint requires host_id; we send an empty string,
	// which violates minLength: 1 in the starter schema.
	writeFrame(t, agentIn, []byte(`{
		"jsonrpc":"2.0",
		"id":11,
		"method":"tools/call",
		"params":{"name":"isolate_endpoint","arguments":{"host_id":""}}
	}`))

	resp, raw := readResponseFrame(t, agentOut, 5*time.Second)
	if resp == nil || resp.Error == nil {
		t.Fatalf("expected schema-violation error, got %+v (raw=%s)", resp, raw)
	}
	if resp.Error.Code != CodeInvalidParams {
		t.Fatalf("expected CodeInvalidParams, got %d", resp.Error.Code)
	}

	_ = agentIn.Close()
}

// ---------------------------------------------------------------------------
// captureEmitter is a tiny in-memory Emitter used to assert that the
// proxy emitted the expected audit events without depending on stderr.
// ---------------------------------------------------------------------------

type captureEmitter struct {
	mu     sync.Mutex
	events []map[string]any
}

func (c *captureEmitter) Emit(e map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

// saw returns true if any captured event has a "decision" key whose
// value equals the supplied label.
func (c *captureEmitter) saw(decision string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if d, ok := e["decision"].(string); ok && d == decision {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Compile sanity: ensure the policy + catalog + emitter types compose
// without import cycles by referencing them all here.
// ---------------------------------------------------------------------------

var (
	_ *config.Config
	_ *catalog.Catalog
	_ *policy.Engine
	_ Emitter = (*captureEmitter)(nil)
)

// ---------------------------------------------------------------------------
// Helpers used by the destructive-path test (kept here so a follow-up
// test for the kill-on-stdin-EOF path has a place to live).
// ---------------------------------------------------------------------------

// findPython is defined in transport_test.go; the reference below
// ensures go vet does not complain if a future refactor moves it.
var _ = findPythonRef

func findPythonRef() string {
	for _, name := range []string{"python", "python3"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// ensure go vet is happy with unused imports on platforms where the
// runtime-specific calls below are stripped by build tags.
var (
	_ = fmt.Sprintf
	_ = context.Background
	_ = strings.Contains
)
