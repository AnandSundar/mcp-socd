package integration

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"mcp-socd/internal/catalog"
	"mcp-socd/test/integration/mockupstream"
)

// yamlMarshal encodes v as YAML bytes. Pulled out of the integration
// tests so the build-tagged framework tests (langgraph_test.go,
// claude_code_test.go, openai_agents_test.go) share one
// serialization helper instead of each re-importing gopkg.in/yaml.
func yamlMarshal(v any) ([]byte, error) {
	return yaml.Marshal(v)
}

// expectedProtocolVersion is the value the mock returns in
// initialize. Pinned so the test can compare against an exact
// string without importing the mock package's internal constant.
const expectedProtocolVersion = "2025-06-18"

// writeMockRequest serializes a JSON-RPC body and writes it as a
// Content-Length framed message to w. Used by every
// TestMockUpstream_* test below to drive the mock with hand-built
// requests.
func writeMockRequest(t *testing.T, w io.Writer, body []byte) {
	t.Helper()
	if err := mockupstream.WriteFrame(w, body); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
}

// readMockResponse reads one framed JSON-RPC response with a
// bounded timeout. Returns the parsed Response struct so tests can
// branch on error/result without re-decoding the raw bytes.
func readMockResponse(t *testing.T, r io.Reader, timeout time.Duration) (*jsonResponse, []byte) {
	t.Helper()
	type result struct {
		resp *jsonResponse
		raw  []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		reader := bufio.NewReader(r)
		raw, err := mockupstream.ReadFrame(reader)
		if err != nil {
			done <- result{nil, nil, err}
			return
		}
		var resp jsonResponse
		if jerr := json.Unmarshal(raw, &resp); jerr != nil {
			done <- result{nil, raw, jerr}
			return
		}
		done <- result{&resp, raw, nil}
	}()
	select {
	case res := <-done:
		if res.err != nil && !errors.Is(res.err, io.EOF) {
			t.Fatalf("readMockResponse: %v", res.err)
		}
		return res.resp, res.raw
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for response", timeout)
		return nil, nil
	}
}

// jsonResponse is the minimal envelope the tests need: id, result,
// and error. Matches the proxy package's Response struct but lives
// here so the integration test code does not have to import
// internal/proxy (which would create a cycle: the proxy tests in
// U4 do not import the mock).
type jsonResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonError      `json:"error,omitempty"`
}

// jsonError is the JSON-RPC error block; only Code and Message are
// inspected by the tests.
type jsonError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// TestMockUpstream_HandlesInitialize verifies the mock responds to
// an initialize request with a fixed protocolVersion, serverInfo,
// and capabilities.tools block. The protocolVersion assertion
// pins the wire contract: any change to MCP-Protocol-Version here
// is a deliberate version bump and must be flagged in the test.
func TestMockUpstream_HandlesInitialize(t *testing.T) {
	stdin, stdout, errCh := mockupstream.StartMockUpstream()
	defer stdin.Close()

	writeMockRequest(t, stdin, []byte(`{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "initialize",
		"params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}
	}`))

	resp, raw := readMockResponse(t, stdout, 5*time.Second)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected successful response, got %+v (raw=%s)", resp, raw)
	}
	if !bytesContains(raw, []byte(`"protocolVersion":"`+expectedProtocolVersion+`"`)) {
		t.Fatalf("protocolVersion not relayed correctly: %s", raw)
	}
	if !bytesContains(raw, []byte(`mcp-socd-mock-upstream`)) {
		t.Fatalf("serverInfo.name not relayed: %s", raw)
	}
	if !bytesContains(raw, []byte(`"capabilities"`)) {
		t.Fatalf("capabilities block missing: %s", raw)
	}

	// The mock should not have errored.
	select {
	case err := <-errCh:
		t.Fatalf("mock upstream errored: %v", err)
	default:
	}
}

// TestMockUpstream_ToolsListReturnsFiveActions verifies the
// tools/list response returns the five starter actions declared in
// catalog.Starter() and that each entry carries a name,
// description, and inputSchema. This is the wire-contract test
// for the catalog/mock alignment: any drift between the catalog
// and the mock would surface here rather than at framework-test
// time.
func TestMockUpstream_ToolsListReturnsFiveActions(t *testing.T) {
	stdin, stdout, errCh := mockupstream.StartMockUpstream()
	defer stdin.Close()

	writeMockRequest(t, stdin, []byte(`{
		"jsonrpc": "2.0",
		"id": 2,
		"method": "tools/list"
	}`))

	resp, raw := readMockResponse(t, stdout, 5*time.Second)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected successful response, got %+v (raw=%s)", resp, raw)
	}

	// Decode the result.tools list so we can assert exactly five
	// entries by name. The proxy's tools/list filter (U4) operates
	// on this shape; a regression in the mock's shape would break
	// every framework test.
	var result struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("decode tools/list result: %v", err)
	}
	if got := len(result.Tools); got != 5 {
		t.Fatalf("tools/list returned %d tools, want 5", got)
	}

	// Build a set of names so the test is order-independent.
	gotNames := make(map[string]bool, 5)
	wantNames := make(map[string]bool, 5)
	for _, a := range catalog.Starter() {
		wantNames[a.Name] = true
	}
	for _, tool := range result.Tools {
		gotNames[tool.Name] = true
		if tool.Description == "" {
			t.Errorf("tool %q has empty description", tool.Name)
		}
		if len(tool.InputSchema) == 0 {
			t.Errorf("tool %q has empty inputSchema", tool.Name)
		}
	}
	for name := range wantNames {
		if !gotNames[name] {
			t.Errorf("tools/list missing starter action %q", name)
		}
	}
	for name := range gotNames {
		if !wantNames[name] {
			t.Errorf("tools/list returned unknown tool %q", name)
		}
	}

	// The mock should not have errored.
	select {
	case err := <-errCh:
		t.Fatalf("mock upstream errored: %v", err)
	default:
	}
}

// TestMockUpstream_ToolsCallEchoesArguments exercises the canned
// tools/call response path: a forwarded call must produce a result
// payload that round-trips the tool name and arguments. This is
// the assertion the framework tests rely on to confirm "the call
// went through to the mock and back".
func TestMockUpstream_ToolsCallEchoesArguments(t *testing.T) {
	stdin, stdout, _ := mockupstream.StartMockUpstream()
	defer stdin.Close()

	writeMockRequest(t, stdin, []byte(`{
		"jsonrpc": "2.0",
		"id": 7,
		"method": "tools/call",
		"params": {"name": "submit_edr_query", "arguments": {"query": "event_simpleName=ProcessRollup2"}}
	}`))

	resp, raw := readMockResponse(t, stdout, 5*time.Second)
	if resp == nil || resp.Error != nil {
		t.Fatalf("expected successful response, got %+v (raw=%s)", resp, raw)
	}
	if !bytesContains(raw, []byte(`echoed_tool`)) {
		t.Fatalf("expected echo payload, got: %s", raw)
	}
	if !bytesContains(raw, []byte(`submit_edr_query`)) {
		t.Fatalf("tool name not echoed: %s", raw)
	}
	if !bytesContains(raw, []byte(`event_simpleName=ProcessRollup2`)) {
		t.Fatalf("arguments not echoed: %s", raw)
	}
}

// TestMockUpstream_NotificationDoesNotRespond — the MCP
// "initialized" notification has no id; the mock must consume it
// silently (no response frame). This is the spec compliance test
// that catches a regression to "always respond".
func TestMockUpstream_NotificationDoesNotRespond(t *testing.T) {
	stdin, stdout, _ := mockupstream.StartMockUpstream()
	defer stdin.Close()

	// Send a notification: no id field. The mock must NOT write
	// any response frame.
	writeMockRequest(t, stdin, []byte(`{
		"jsonrpc": "2.0",
		"method": "notifications/initialized"
	}`))

	// A subsequent ping forces the mock to write at least one
	// response frame. We read that and assert the buffered
	// reader didn't see anything before it.
	writeMockRequest(t, stdin, []byte(`{
		"jsonrpc": "2.0",
		"id": 99,
		"method": "ping"
	}`))

	resp, _ := readMockResponse(t, stdout, 5*time.Second)
	if resp == nil {
		t.Fatal("expected ping response, got nil")
	}
	// The response must be the ping (id 99), not a phantom reply
	// to the notification. If the mock were echoing notifications,
	// the first response frame would have no id or a different id.
	if !bytesContains([]byte(string(resp.ID)), []byte(`99`)) {
		t.Fatalf("unexpected first response id %q; expected 99", resp.ID)
	}
}

// bytesContains is a tiny helper kept here so the test file does
// not pull in the bytes package solely for one call.
func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
