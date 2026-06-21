// Package proxy implements the mcp-socd stdio wrapper that mediates
// JSON-RPC traffic between an AI agent and an upstream MCP server.
//
// The proxy speaks the MCP stdio transport (Plan §KTD2): each frame
// is `Content-Length: N\r\n\r\n<json bytes>`. Frames are read from
// os.Stdin (the agent) and written to the child MCP server's Stdin;
// responses flow back from the child's Stdout to os.Stdout. tools/call
// frames are intercepted and evaluated against the policy engine
// (internal/policy) before being forwarded or short-circuited with a
// synthetic JSON-RPC error.
//
// Files in this package:
//
//	jsonrpc.go    -- Content-Length framed I/O and minimal JSON-RPC 2.0 types
//	intercept.go  -- tools/call evaluation pipeline (catalog + policy + emitter)
//	transport.go  -- child-process lifecycle, stdio plumbing
//	proxy.go      -- main loop wiring stdin/child/stdout goroutines
//
// The Emitter interface (defined below) is satisfied by a no-op default
// now and will be implemented by the OCSF audit emitter (U5) without
// U4 having to change.
package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxFrameBytes caps a single JSON-RPC frame at 1 MiB. Agents can pass
// arbitrarily large arguments (e.g. base64-encoded blobs in tools/call)
// and the limit has to be comfortably above the typical agent payload
// while still being a bounded guardrail against a runaway producer.
//
// Plan §KTD2 recommends an explicit byte-count read rather than
// bufio.Scanner, which would silently truncate at its default 64 KiB
// max-token size and would emit an ErrTooLong without forwarding the
// message.
const MaxFrameBytes = 1 << 20 // 1 MiB

// ErrFrameTooLarge is returned by ReadFrame when a Content-Length header
// exceeds MaxFrameBytes. The frame is not consumed; the caller decides
// whether to close the connection or attempt recovery.
var ErrFrameTooLarge = errors.New("proxy: frame exceeds max bytes")

// ErrBadHeader is returned by ReadFrame when the framing header is
// malformed (missing Content-Length, non-numeric length, unknown header,
// etc.). The frame is not consumed.
var ErrBadHeader = errors.New("proxy: malformed framing header")

// Request is a minimal JSON-RPC 2.0 request envelope. We deliberately
// keep the struct permissive (Params is raw JSON) because the proxy
// only inspects the method and a small subset of params for the
// well-known methods (initialize, tools/list, tools/call, ping); the
// rest of the params ride through unchanged.
type Request struct {
	// JSONRPC is the protocol version. Always "2.0" for MCP. We do not
	// reject "1.0" here because the proxy is meant to be liberal in
	// what it accepts; the upstream server will reject if it cares.
	JSONRPC string `json:"jsonrpc"`

	// ID correlates requests and responses. May be a string, number,
	// or null for notifications (no response expected). json.RawMessage
	// preserves the on-wire form.
	ID json.RawMessage `json:"id,omitempty"`

	// Method is the JSON-RPC method name. For MCP: "initialize",
	// "initialized", "tools/list", "tools/call", "ping", plus
	// notifications/list_changed variants.
	Method string `json:"method"`

	// Params are the method-specific parameters. We decode lazily:
	// the intercept path needs Params for tools/call; the rest of the
	// code passes them through as raw JSON bytes.
	Params json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the request has no ID. JSON-RPC
// notifications receive no response from the server.
func (r *Request) IsNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// Response is a minimal JSON-RPC 2.0 response envelope. Either Result
// or Error is populated; the wire protocol forbids both.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is the JSON-RPC 2.0 error object. Code follows the JSON-RPC
// spec; Message is human-readable; Data is optional structured detail.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes plus the MCP-recommended -32000
// application-error range. We use the -32000 slot for policy denials
// so the agent's diagnostic UI surfaces a distinct class of error
// from transport failures.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	// CodePolicyDenied is in the MCP server-error range (-32000 to
	// -32099). The exact code is not standardized by MCP yet; the
	// proxy emits -32000 with a descriptive message so future spec
	// alignment is a one-line change.
	CodePolicyDenied = -32000
)

// Message is a wire-level envelope. It can be either a Request or a
// Response; the JSON-RPC 2.0 spec requires the receiver to dispatch
// based on whether an "id" field is present and whether the object
// looks like a response (has "result" or "error") or a request (has
// "method").
type Message struct {
	// Raw is the original JSON bytes for the frame. We retain it so
	// pass-through forwarding does not lose any fields the proxy did
	// not decode into the typed view.
	Raw []byte

	// Request is populated when the frame decodes as a request.
	Request *Request

	// Response is populated when the frame decodes as a response.
	Response *Response

	// IsResponse is true when the wire object has an "id" plus either
	// "result" or "error" (and no "method"). Used for dispatch.
	IsResponse bool
}

// ReadFrame reads one Content-Length framed JSON-RPC message from r.
// Returns the raw bytes (after the headers) and the size announced by
// the header. The caller is responsible for unmarshalling the bytes.
//
// ReadFrame supports the Content-Length framing defined by the MCP
// spec. Unknown headers are tolerated (preserved but ignored) so the
// proxy does not break against an upstream that adds e.g.
// Content-Type. A missing Content-Length is an error: we do not
// auto-fallback to newline-delimited because MCP requires the header.
func ReadFrame(r *bufio.Reader) ([]byte, error) {
	contentLength, err := readContentLength(r)
	if err != nil {
		return nil, err
	}
	if contentLength > MaxFrameBytes {
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, contentLength, MaxFrameBytes)
	}

	// Use io.ReadFull so a short read is reported as such rather than
	// silently producing a truncated JSON object.
	buf := make([]byte, contentLength)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("proxy: read frame body: %w", err)
	}
	return buf, nil
}

// readContentLength walks the header lines until the blank-line
// separator and returns the Content-Length value. Unknown headers are
// skipped; the spec requires exactly Content-Length but we tolerate
// extras for forward compatibility.
func readContentLength(r *bufio.Reader) (int, error) {
	var contentLength int
	found := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("proxy: read header line: %w", err)
		}
		// Trim trailing \r\n or \n.
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			// Blank line marks end of headers.
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return 0, fmt.Errorf("%w: missing colon in %q", ErrBadHeader, line)
		}
		name := strings.TrimSpace(line[:colon])
		value := strings.TrimSpace(line[colon+1:])
		if strings.EqualFold(name, "Content-Length") {
			n, err := strconv.Atoi(value)
			if err != nil {
				return 0, fmt.Errorf("%w: Content-Length %q: %v", ErrBadHeader, value, err)
			}
			if n < 0 {
				return 0, fmt.Errorf("%w: negative Content-Length %d", ErrBadHeader, n)
			}
			contentLength = n
			found = true
		}
	}
	if !found {
		return 0, fmt.Errorf("%w: missing Content-Length", ErrBadHeader)
	}
	return contentLength, nil
}

// WriteFrame writes a single Content-Length framed JSON-RPC message to
// w. The body is written verbatim (no transformation), preserving any
// fields the proxy did not decode.
//
// WriteFrame does not flush w; callers that need line-buffered output
// (e.g. the audit sink) must Flush themselves.
func WriteFrame(w io.Writer, body []byte) error {
	// MCP framing: "Content-Length: N\r\n\r\n<body>". We use \r\n for
	// the header line ending because the spec mandates CRLF, but the
	// content itself is raw bytes and may contain newlines.
	header := "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n"
	if _, err := io.WriteString(w, header); err != nil {
		return fmt.Errorf("proxy: write frame header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("proxy: write frame body: %w", err)
	}
	return nil
}

// EncodeResponse serializes a Response into JSON bytes suitable for
// WriteFrame. The ID is taken from req so the agent can correlate.
func EncodeResponse(req *Request, resp *Response) ([]byte, error) {
	if resp.JSONRPC == "" {
		resp.JSONRPC = "2.0"
	}
	if len(resp.ID) == 0 && len(req.ID) > 0 {
		resp.ID = req.ID
	}
	return json.Marshal(resp)
}

// EncodeErrorResponse builds a synthetic Response carrying err. Used by
// the intercept path to short-circuit a denied or approval-pending
// tools/call back to the agent without forwarding to the upstream.
func EncodeErrorResponse(req *Request, code int, message string, data any) ([]byte, error) {
	return EncodeResponse(req, &Response{
		JSONRPC: "2.0",
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
	})
}

// DecodeMessage classifies raw JSON bytes as a request or a response
// based on the presence of the "method" field. We deliberately decode
// the full envelope because both arms of the dispatch need the typed
// view, and the MCP frames we expect are small (well under the
// MaxFrameBytes cap).
//
// DecodeMessage tolerates a missing JSON-RPC version field for
// forwarding purposes. The decode uses json.Unmarshal which accepts
// unknown fields by default; we never panic on extra fields the
// upstream server emits.
func DecodeMessage(raw []byte) (*Message, error) {
	// First peek: does the object carry a "method" key? We do a
	// partial decode so we don't allocate a Response for a Request
	// (and vice versa).
	var probe struct {
		Method *string         `json:"method"`
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("proxy: decode message probe: %w", err)
	}

	msg := &Message{Raw: raw}
	if probe.Method != nil {
		var req Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, fmt.Errorf("proxy: decode request: %w", err)
		}
		msg.Request = &req
	} else {
		var resp Response
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("proxy: decode response: %w", err)
		}
		msg.Response = &resp
		msg.IsResponse = true
	}
	return msg, nil
}
