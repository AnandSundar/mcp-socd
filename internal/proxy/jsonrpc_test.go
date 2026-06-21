package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestReadFrame_RoundTrip exercises the basic Content-Length framed
// I/O path: a small message goes through WriteFrame and comes back
// via ReadFrame with the same bytes.
func TestReadFrame_RoundTrip(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, body); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	got, err := ReadFrame(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch: got %s, want %s", got, body)
	}
}

// TestReadFrame_MultiFrame writes two frames back to back and asserts
// the reader yields them in order without losing bytes between frames.
func TestReadFrame_MultiFrame(t *testing.T) {
	a := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	b := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, a); err != nil {
		t.Fatalf("WriteFrame a: %v", err)
	}
	if err := WriteFrame(&buf, b); err != nil {
		t.Fatalf("WriteFrame b: %v", err)
	}

	r := bufio.NewReader(&buf)
	ga, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame a: %v", err)
	}
	gb, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame b: %v", err)
	}
	if !bytes.Equal(ga, a) || !bytes.Equal(gb, b) {
		t.Fatalf("frame order or content mismatch")
	}
}

// TestReadFrame_TooLarge asserts that a Content-Length above
// MaxFrameBytes is rejected before any body bytes are consumed. The
// caller can then decide whether to close the connection.
func TestReadFrame_TooLarge(t *testing.T) {
	// Build a header that announces a body larger than MaxFrameBytes
	// but supply no body. ReadFrame must reject on the header.
	header := "Content-Length: 2097152\r\n\r\n"
	r := bufio.NewReader(strings.NewReader(header))
	_, err := ReadFrame(r)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got err=%v, want ErrFrameTooLarge", err)
	}
}

// TestReadFrame_BadHeader_MissingLength asserts that a header without
// a Content-Length field is rejected.
func TestReadFrame_BadHeader_MissingLength(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("Content-Type: application/json\r\n\r\n"))
	_, err := ReadFrame(r)
	if !errors.Is(err, ErrBadHeader) {
		t.Fatalf("got err=%v, want ErrBadHeader", err)
	}
}

// TestReadFrame_BadHeader_NonNumeric asserts that a non-numeric
// Content-Length value is rejected.
func TestReadFrame_BadHeader_NonNumeric(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("Content-Length: notanumber\r\n\r\n"))
	_, err := ReadFrame(r)
	if !errors.Is(err, ErrBadHeader) {
		t.Fatalf("got err=%v, want ErrBadHeader", err)
	}
}

// TestReadFrame_UnknownHeadersIgnored asserts the parser tolerates
// header lines other than Content-Length. Future MCP revisions may add
// Content-Type or other metadata; the proxy must not break.
func TestReadFrame_UnknownHeadersIgnored(t *testing.T) {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	var buf bytes.Buffer
	buf.WriteString("Content-Type: application/json\r\n")
	WriteFrame(&buf, body)

	got, err := ReadFrame(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch: got %s, want %s", got, body)
	}
}

// TestReadFrame_EOFOnEmptyStream asserts the reader returns io.EOF
// (wrapped) when the stream is closed mid-header.
func TestReadFrame_EOFOnEmptyStream(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(""))
	_, err := ReadFrame(r)
	if err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("got err=%v, want io.EOF", err)
	}
}

// TestEncodeErrorResponse_IncludesID asserts that the synthetic
// error response preserves the request's ID so the agent can
// correlate the rejection with its pending call.
func TestEncodeErrorResponse_IncludesID(t *testing.T) {
	req := &Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`42`),
		Method:  "tools/call",
	}
	body, err := EncodeErrorResponse(req, CodePolicyDenied, "denied", map[string]any{"reason": "policy_deny"})
	if err != nil {
		t.Fatalf("EncodeErrorResponse: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode synthetic: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != CodePolicyDenied {
		t.Fatalf("missing or wrong error code: %+v", resp.Error)
	}
	if string(resp.ID) != "42" {
		t.Fatalf("ID not preserved: got %s, want 42", resp.ID)
	}
}

// TestDecodeMessage_Request verifies the dispatching decoder
// classifies a request-shaped object correctly.
func TestDecodeMessage_Request(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"isolate_endpoint","arguments":{"host_id":"h1"}}}`)
	msg, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if msg.IsResponse {
		t.Fatalf("classified as response; want request")
	}
	if msg.Request == nil || msg.Request.Method != "tools/call" {
		t.Fatalf("request not decoded correctly: %+v", msg.Request)
	}
}

// TestDecodeMessage_Response verifies the dispatching decoder
// classifies a response-shaped object correctly.
func TestDecodeMessage_Response(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":7,"result":{"ok":true}}`)
	msg, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("DecodeMessage: %v", err)
	}
	if !msg.IsResponse {
		t.Fatalf("classified as request; want response")
	}
	if msg.Response == nil || msg.Response.Result == nil {
		t.Fatalf("response not decoded correctly: %+v", msg.Response)
	}
}

// TestRequest_IsNotification verifies the notification detection
// distinguishes between absent ID, null ID, and a real ID.
func TestRequest_IsNotification(t *testing.T) {
	cases := []struct {
		name string
		id   json.RawMessage
		want bool
	}{
		{"missing", nil, true},
		{"explicit null", json.RawMessage(`null`), true},
		{"number", json.RawMessage(`42`), false},
		{"string", json.RawMessage(`"abc"`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Request{ID: tc.id}
			if got := r.IsNotification(); got != tc.want {
				t.Fatalf("IsNotification()=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestWriteFrame_HeaderFormat asserts the exact byte layout: CRLF
// separators, no trailing newline before the body, and the body
// appended verbatim. Some MCP clients are strict about the header
// byte sequence.
func TestWriteFrame_HeaderFormat(t *testing.T) {
	body := []byte("{\"id\":1}")
	var buf bytes.Buffer
	if err := WriteFrame(&buf, body); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	want := "Content-Length: 8\r\n\r\n{\"id\":1}"
	if got := buf.String(); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
