// Package mockupstream implements a minimal MCP-over-stdio server
// used by the mcp-socd integration test suite (Plan U10).
//
// The mock speaks just enough of the MCP protocol to be
// indistinguishable from a "real" SOC backend as far as the proxy
// is concerned: it answers initialize, tools/list, and tools/call
// with canned responses whose shape matches the catalog.Starter()
// set declared in internal/catalog. The proxy's catalog validation
// path reads from internal/catalog directly; the mock just needs
// to keep its declared tools in sync so that, if the proxy's
// tools/list filter (U4) ever inspects the upstream payload, it
// sees the same five tools the catalog knows about.
//
// The package is NOT build-tagged: the integration-tagged
// framework tests (langgraph_test.go, claude_code_test.go,
// openai_agents_test.go) import the mock via its public API. The
// mock itself has no _test.go files and lives in its own
// subpackage so it can be imported by both test code and the
// mock-upstream-runner command (test/integration/cmd/
// mock_upstream_runner), which the proxy spawns as a subprocess
// in place of a real upstream MCP server.
package mockupstream

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"mcp-socd/internal/catalog"
)

// protocolVersion is the MCP protocol version this mock speaks. It is
// a recent stable revision of the MCP spec; agents and the proxy
// negotiate this value during the initialize handshake. Hard-coded
// here so the mock is a known, fixed target.
const mockProtocolVersion = "2025-06-18"

// MockUpstream is a minimal MCP-over-stdio server used by the
// integration tests. It speaks the Content-Length framed JSON-RPC
// protocol on the agent-facing side and implements:
//
//   - initialize        -> protocolVersion + serverInfo
//   - tools/list        -> the five catalog.Starter() tools with their
//     compiled inputSchema (re-rendered as the catalog's RawSchema
//     so the wire shape is stable across starter refactors).
//   - tools/call        -> canned result content keyed by tool name
//     and arguments, so the test can assert that a forwarded call
//     round-tripped end-to-end.
//
// MockUpstream is NOT safe for concurrent use from outside the
// StartMockUpstream goroutine. It owns a single request loop reading
// from a pipe.
type MockUpstream struct {
	// ProtocolVersion is the value returned in the initialize result.
	// Exposed so tests can assert it without hard-coding the constant
	// twice (and so a future revision bump is a one-line change).
	ProtocolVersion string

	// ServerInfo is surfaced in the initialize result's serverInfo
	// block. Tests assert it to verify the upstream was the mock and
	// not the agent's own MCP transport.
	ServerInfo map[string]any

	// Calls is an in-memory log of every tools/call the mock has
	// processed (method, name, arguments). Tests inspect this to
	// assert that an action actually reached the mock upstream,
	// independent of the JSON-RPC response. Append-only; no locking
	// because the upstream runs single-threaded.
	mu    sync.Mutex
	Calls []MockCall
}

// MockCall is one entry in MockUpstream.Calls.
type MockCall struct {
	// ID is the JSON-RPC request id of the original tools/call.
	// String form so the test can match by id regardless of whether
	// the wire encoded it as a string or number.
	ID string

	// Name is the MCP tool name the agent called.
	Name string

	// Arguments is the decoded arguments map. nil when the agent
	// supplied no arguments field.
	Arguments map[string]any
}

// NewMockMCPServer returns a MockUpstream with sensible defaults.
// The constructor is exposed separately from StartMockUpstream so a
// test that wants to drive the mock directly (without the proxy in
// the loop) can construct one and use Serve against its own io.Pipe.
func NewMockMCPServer() *MockUpstream {
	return &MockUpstream{
		ProtocolVersion: mockProtocolVersion,
		ServerInfo: map[string]any{
			"name":    "mcp-socd-mock-upstream",
			"version": "0.0.0-test",
		},
	}
}

// StartMockUpstream spawns the mock upstream as a goroutine using
// two io.Pipes wired as agent-facing stdio. The returned writer is
// what the agent (or the proxy) writes framed JSON-RPC requests to;
// the returned reader is what the agent reads framed JSON-RPC
// responses from. errCh receives a non-nil error when the mock's
// read loop exits (e.g. on malformed framing); the channel is not
// closed so the caller can detect the goroutine's exit without
// ranging over the channel.
//
// The pipes are io.Pipe-based (not os.Pipe) because the mock runs
// in-process — there is no real subprocess — and io.Pipe gives us
// synchronous, blocking reads/writes without depending on the OS
// filesystem. Close discipline: the caller MUST close stdin when
// done writing; the mock's read loop will then exit cleanly and
// stdout will be closed (returning io.EOF on the next read).
func StartMockUpstream() (stdin io.WriteCloser, stdout io.ReadCloser, errCh chan error) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()

	mock := NewMockMCPServer()
	errCh = make(chan error, 1)

	go func() {
		// Capture the first non-clean exit so the test can fail loud
		// on a malformed frame or read error instead of hanging.
		defer func() { _ = outW.Close() }()
		if err := mock.serve(inR, outW); err != nil && err != io.EOF {
			errCh <- err
		}
	}()

	return inW, outR, errCh
}

// serve is the mock's main read loop. It reads Content-Length
// framed JSON-RPC requests, dispatches by method, and writes the
// response. Exposed at package level (rather than only via the
// goroutine above) so tests can drive the mock with a custom reader
// and writer pair.
//
// serve returns nil on clean EOF (the caller closed stdin) and a
// non-nil error for malformed frames or transport failures.
func (m *MockUpstream) serve(r io.Reader, w io.Writer) error {
	reader := bufio.NewReader(r)
	for {
		body, err := ReadFrame(reader)
		if err != nil {
			return err
		}

		var req map[string]any
		if jerr := json.Unmarshal(body, &req); jerr != nil {
			return fmt.Errorf("mock_upstream: decode frame: %w", jerr)
		}

		id, _ := req["id"].(string)
		if id == "" {
			// Numeric ids come back as float64 from the generic
			// map[string]any decode; round-trip them through JSON
			// to recover the canonical wire form. This keeps the
			// recorded call id stable across the test.
			id = formatJSONID(req["id"])
		}
		method, _ := req["method"].(string)

		if id == "" {
			// Notification (no id): no response. This covers the
			// "initialized" notification the agent sends after the
			// handshake per MCP spec.
			continue
		}

		resp := m.dispatch(id, method, req)
		if err := WriteFrame(w, resp); err != nil {
			return fmt.Errorf("mock_upstream: write frame: %w", err)
		}
	}
}

// dispatch routes a single request to its handler and returns the
// response envelope. Unrecognized methods get a standard JSON-RPC
// method-not-found error; the proxy and the agent SDKs both
// tolerate this surface for tool names they don't understand.
func (m *MockUpstream) dispatch(id, method string, req map[string]any) []byte {
	switch method {
	case "initialize":
		return m.handleInitialize(id)
	case "tools/list":
		return m.handleToolsList(id)
	case "tools/call":
		return m.handleToolsCall(id, req)
	case "ping":
		return mustMarshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"result":  map[string]any{},
		})
	default:
		return mustMarshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"error": map[string]any{
				"code":    -32601,
				"message": fmt.Sprintf("method not found: %s", method),
			},
		})
	}
}

// handleInitialize returns the MCP InitializeResult. serverInfo is
// fixed so tests can detect the mock from the agent side.
func (m *MockUpstream) handleInitialize(id string) []byte {
	return mustMarshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"protocolVersion": m.ProtocolVersion,
			"serverInfo":      m.ServerInfo,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		},
	})
}

// handleToolsList returns the five starter actions with their
// compiled input schemas re-rendered as the canonical JSON-Schema
// bytes. The wire shape mirrors what a real MCP server would emit
// (MCP 2025-06-18 tools/list result).
//
// The schemas are intentionally the same ones declared in
// catalog.starter.go (and validated against by the proxy at
// runtime). We duplicate the literal here rather than relying on
// catalog.Action.RawSchema because the starter catalog does not
// populate RawSchema (only custom YAML-loaded actions do). The
// catalog's package-init guard already pins the starter blast-radius
// mapping, so any drift here would surface as a test failure on
// either side rather than as a silent schema mismatch.
func (m *MockUpstream) handleToolsList(id string) []byte {
	tools := make([]map[string]any, 0, len(catalog.Starter()))
	for _, a := range catalog.Starter() {
		tools = append(tools, map[string]any{
			"name":        a.Name,
			"description": a.Description,
			"inputSchema": json.RawMessage(starterSchemaFor(a.Name)),
		})
	}
	return mustMarshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"tools":      tools,
			"nextCursor": nil,
		},
	})
}

// handleToolsCall decodes the params and returns a canned response
// whose content includes the tool name and arguments so the test
// can assert the call round-tripped end-to-end. The mock also
// records the call in MockUpstream.Calls for inspection.
func (m *MockUpstream) handleToolsCall(id string, req map[string]any) []byte {
	params, _ := req["params"].(map[string]any)
	name, _ := params["name"].(string)
	var args map[string]any
	if raw, ok := params["arguments"].(map[string]any); ok {
		args = raw
	}

	m.mu.Lock()
	m.Calls = append(m.Calls, MockCall{ID: id, Name: name, Arguments: args})
	m.mu.Unlock()

	result := map[string]any{
		"echoed_tool": name,
		"arguments":   args,
	}
	body, _ := json.Marshal(result)
	return mustMarshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": string(body)},
			},
			"isError": false,
		},
	})
}

// ReadFrame reads one Content-Length framed JSON-RPC message from r.
// The framing is identical to internal/proxy.ReadFrame but exposed
// here so the integration tests (which live in the parent
// test/integration package) can drive the mock without re-implementing
// the framing protocol. Tolerates unknown headers so a future MCP
// revision can add Content-Type without breaking this fixture.
//
// Exported at package level (capitalized) so the framework_test.go
// helpers can use it; the mock's own serve loop is the primary caller.
func ReadFrame(r *bufio.Reader) ([]byte, error) {
	var length int
	found := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return nil, fmt.Errorf("mock_upstream: missing colon in header %q", line)
		}
		name := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		if strings.EqualFold(name, "Content-Length") {
			n, perr := parseInt(value)
			if perr != nil {
				return nil, fmt.Errorf("mock_upstream: bad Content-Length %q: %w", value, perr)
			}
			length = n
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("mock_upstream: missing Content-Length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("mock_upstream: read body: %w", err)
	}
	return body, nil
}

// WriteFrame serializes body as a single Content-Length framed
// JSON-RPC message and writes it to w. Mirrors
// internal/proxy.WriteFrame; inlined for the same cycle-avoidance
// reason as ReadFrame.
//
// Exported so framework_test.go can drive the mock with hand-built
// requests without re-implementing the framing protocol.
func WriteFrame(w io.Writer, body []byte) error {
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// formatJSONID renders a decoded JSON id value back into its
// canonical wire form (string with quotes, or decimal integer).
// The generic map[string]any decode produces float64 for numeric
// ids; without this normalization, the recorded call id would
// always be a string for string ids but a Go-formatted float for
// numeric ids, which is brittle for test assertions.
func formatJSONID(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		// json.Number would preserve the wire form; for the test's
		// purposes an integer-only decimal string is enough.
		return fmt.Sprintf("%d", int64(x))
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// parseInt is a tiny strconv.Atoi wrapper. Pulled out so ReadFrame
// stays readable.
func parseInt(s string) (int, error) {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a digit: %q", string(c))
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// mustMarshal encodes v as JSON or panics. Marshalling errors here
// are programmer errors (a known-good response shape that the
// package cannot encode), not runtime failures.
func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mock_upstream: marshal: %v", err))
	}
	return b
}

// starterSchemaFor returns the canonical JSON-Schema text for the
// given starter action. Schemas mirror those declared in
// catalog.starter.go so the proxy's catalog validation passes for
// forwarded calls. Unknown names return an empty object schema
// (accepts anything) — the catalog will reject unknown actions
// anyway before the proxy ever lets a tools/call through.
func starterSchemaFor(name string) string {
	switch name {
	case "isolate_endpoint":
		return `{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"host_id": {"type": "string", "minLength": 1},
				"comment": {"type": "string"}
			},
			"required": ["host_id"]
		}`
	case "block_user_account":
		return `{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"user_id": {"type": "string", "minLength": 1},
				"comment": {"type": "string"}
			},
			"required": ["user_id"]
		}`
	case "rotate_api_key":
		return `{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"key_id": {"type": "string", "minLength": 1},
				"reason": {"type": "string"}
			},
			"required": ["key_id"]
		}`
	case "submit_edr_query":
		return `{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"query":      {"type": "string", "minLength": 1},
				"host_id":    {"type": "string"},
				"time_range": {"type": "string", "description": "ISO 8601 duration, e.g. PT1H"}
			},
			"required": ["query"]
		}`
	case "enrich_ioc":
		return `{
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "object",
			"additionalProperties": false,
			"properties": {
				"indicator":      {"type": "string", "minLength": 1},
				"indicator_type": {"type": "string", "enum": ["ipv4", "ipv6", "domain", "url", "sha256", "md5", "email"]}
			},
			"required": ["indicator", "indicator_type"]
		}`
	default:
		return `{"type": "object"}`
	}
}
