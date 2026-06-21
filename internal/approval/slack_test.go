package approval

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slack-go/slack"

	"mcp-socd/internal/config"
)

// TestSlack_OpensDMChannel — Plan U7 scenario #1: a SlackChannel
// with a working Web API backend can open a 1:1 DM with the
// configured approver and surface the channel id to the caller.
//
// We stand up an httptest.Server that mimics Slack's Web API
// just enough to serve a conversations.list response containing
// an IM channel for the approver, then point slack-go at it via
// OptionAPIURL.
func TestSlack_OpensDMChannel(t *testing.T) {
	const approverID = "U_APPROVER_42"

	var conversationsCalled atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/conversations.list"):
			conversationsCalled.Add(1)
			w.Header().Set("Content-Type", "application/json")
			// conversations.list returns ok=true plus the
			// list of channels. We return one IM channel
			// belonging to the approver.
			_, _ = io.WriteString(w, `{
				"ok": true,
				"channels": [
					{"id": "D_DM_42", "is_im": true, "user": "`+approverID+`"}
				]
			}`)
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	ch := mustTestChannel(t, server.URL, approverID)

	dmID, err := ch.openDM(context.Background(), approverID)
	if err != nil {
		t.Fatalf("openDM: %v", err)
	}
	if dmID != "D_DM_42" {
		t.Fatalf("openDM id = %q, want %q", dmID, "D_DM_42")
	}
	if got := conversationsCalled.Load(); got != 1 {
		t.Fatalf("conversations.list called %d times, want 1", got)
	}
}

// TestSlack_PostsBlockKitMessage — Plan U7 scenario #2: the
// Block Kit message posted to Slack contains action buttons
// with action_id mcp-socd.approve and mcp-socd.deny.
//
// We capture the POST body to chat.postMessage, then assert it
// contains the action block with the expected action ids and
// the request id encoded in the button value field.
func TestSlack_PostsBlockKitMessage(t *testing.T) {
	const approverID = "U_APPROVER_42"
	const requestID = "req-blockkit-1"

	var posted atomic.Pointer[map[string]any]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/conversations.list"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok": true, "channels": [{"id": "D_DM_42", "is_im": true, "user": "`+approverID+`"}]}`)
		case strings.HasSuffix(r.URL.Path, "/chat.postMessage"):
			// slack-go POSTs chat.postMessage as
			// application/x-www-form-urlencoded. We
			// capture the form so the test can assert on
			// the parsed block fields.
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form: "+err.Error(), http.StatusBadRequest)
				return
			}
			// slack-go serialises the `blocks` field as a
			// JSON-encoded string under the form key, so
			// we decode that and stash the parsed slice
			// under decoded["blocks"] for the test's
			// structural assertions.
			decoded := map[string]any{}
			if blocksJSON := r.FormValue("blocks"); blocksJSON != "" {
				var blocks []any
				if err := json.Unmarshal([]byte(blocksJSON), &blocks); err == nil {
					decoded["blocks"] = blocks
				}
			}
			if channel := r.FormValue("channel"); channel != "" {
				decoded["channel"] = channel
			}
			posted.Store(&decoded)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ok": true, "channel": "D_DM_42", "ts": "1700000000.000100"}`)
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer server.Close()

	ch := mustTestChannel(t, server.URL, approverID)
	req := sampleRequest(requestID)
	req.Token = SignToken(req.RequestID, ch.secret)

	_, err := ch.postApprovalMessage(context.Background(), "D_DM_42", req)
	if err != nil {
		t.Fatalf("postApprovalMessage: %v", err)
	}
	captured := posted.Load()
	if captured == nil {
		t.Fatal("chat.postMessage was never called")
	}
	if !containsActionID(*captured, slackActionApprove) {
		t.Fatalf("posted payload missing action_id %q; payload=%v", slackActionApprove, *captured)
	}
	if !containsActionID(*captured, slackActionDeny) {
		t.Fatalf("posted payload missing action_id %q; payload=%v", slackActionDeny, *captured)
	}
	if !containsRequestID(*captured, requestID) {
		t.Fatalf("posted payload missing request id %q in button value; payload=%v", requestID, *captured)
	}
}

// TestSlack_ReceivesApproval — Plan U7 scenario #3: a recorded
// block_actions payload produces the expected Decision.
//
// We feed the golden fixtures from testdata/ directly into the
// SlackChannel.handleInteraction method (the one called by the
// socket-mode event loop), bypassing the WebSocket entirely.
// The handler is the production code path; only the
// transport has been substituted for a fixture, which is the
// right boundary for unit testing a Socket Mode client.
func TestSlack_ReceivesApproval(t *testing.T) {
	secret := []byte("slack-approval-secret")
	ch := &SlackChannel{
		cfg: config.Channel{
			Type:           "slack",
			ApproverUserID: "U_APPROVER_123",
		},
		secret:             append([]byte(nil), secret...),
		approverCache:      make(map[string]string),
		pendingInteractions: make(map[string]chan slack.InteractionCallback),
	}
	// We intentionally do not call NewSlackChannel here because
	// it would require a real Slack API client. The handler
	// path under test does not use ch.api.

	t.Run("approve payload yields DecisionApprove", func(t *testing.T) {
		req := sampleRequest("req-approve-test")
		req.Token = SignToken(req.RequestID, secret)

		cb := loadFixture(t, "testdata/golden-payload-approve.json")
		// Stub out api-dependent user lookup; handleInteraction
		// best-effort on error so an unset api is fine for this
		// path (the lookup is wrapped in `err == nil`).
		got := ch.handleInteraction(context.Background(), "D_DM_CHANNEL", "1700000000.000100", req, cb)
		if got != DecisionApprove {
			t.Fatalf("decision = %v, want DecisionApprove", got)
		}
	})

	t.Run("deny payload yields DecisionDeny", func(t *testing.T) {
		req := sampleRequest("req-deny-test")
		req.Token = SignToken(req.RequestID, secret)

		cb := loadFixture(t, "testdata/golden-payload-deny.json")
		got := ch.handleInteraction(context.Background(), "D_DM_CHANNEL", "1700000000.000200", req, cb)
		if got != DecisionDeny {
			t.Fatalf("decision = %v, want DecisionDeny", got)
		}
	})
}

// TestSlack_RejectsUnsignedPayload — Plan U7 scenario #4:
// verifySlackSignature rejects an unsigned (or
// wrongly-signed) payload with ErrSlackSignatureMismatch.
func TestSlack_RejectsUnsignedPayload(t *testing.T) {
	const secret = "test-signing-secret"
	body := []byte(`{"type":"block_actions","actions":[{"action_id":"mcp-socd.approve","value":"req-x"}]}`)

	// No signature headers at all.
	err := verifySlackSignature(secret, http.Header{}, body)
	if !errors.Is(err, ErrSlackSignatureMismatch) {
		t.Fatalf("missing headers err = %v, want ErrSlackSignatureMismatch", err)
	}

	// Wrong prefix.
	headers := http.Header{}
	headers.Set("X-Slack-Signature", "v1=deadbeef")
	headers.Set("X-Slack-Request-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	if err := verifySlackSignature(secret, headers, body); !errors.Is(err, ErrSlackSignatureMismatch) {
		t.Fatalf("wrong prefix err = %v, want ErrSlackSignatureMismatch", err)
	}

	// Correct prefix, wrong MAC.
	headers.Set("X-Slack-Signature", "v0=deadbeef")
	if err := verifySlackSignature(secret, headers, body); !errors.Is(err, ErrSlackSignatureMismatch) {
		t.Fatalf("bad MAC err = %v, want ErrSlackSignatureMismatch", err)
	}

	// Tampered body — the same signature should NOT verify
	// against a different body.
	goodSig := computeSlackSignature(t, secret, headers.Get("X-Slack-Request-Timestamp"), body)
	headers.Set("X-Slack-Signature", goodSig)
	if err := verifySlackSignature(secret, headers, []byte(`{"tampered":true}`)); !errors.Is(err, ErrSlackSignatureMismatch) {
		t.Fatalf("tampered body err = %v, want ErrSlackSignatureMismatch", err)
	}
}

// TestSlack_RejectsExpiredTimestamp — Plan U7 scenario #5:
// verifySlackSignature rejects a payload whose
// X-Slack-Request-Timestamp is older than 5 minutes.
func TestSlack_RejectsExpiredTimestamp(t *testing.T) {
	const secret = "test-signing-secret"
	body := []byte(`{"type":"block_actions"}`)

	headers := http.Header{}
	// 6 minutes ago — outside the 5-minute replay window.
	stale := time.Now().Add(-6 * time.Minute).Unix()
	headers.Set("X-Slack-Request-Timestamp", strconv.FormatInt(stale, 10))
	headers.Set("X-Slack-Signature", computeSlackSignature(t, secret, headers.Get("X-Slack-Request-Timestamp"), body))

	err := verifySlackSignature(secret, headers, body)
	if !errors.Is(err, ErrSlackTimestampSkew) {
		t.Fatalf("stale timestamp err = %v, want ErrSlackTimestampSkew", err)
	}

	// A timestamp well in the future is also a rejection:
	// forward-skewed timestamps protect against an attacker
	// who tries to game the window.
	future := time.Now().Add(10 * time.Minute).Unix()
	headers.Set("X-Slack-Request-Timestamp", strconv.FormatInt(future, 10))
	headers.Set("X-Slack-Signature", computeSlackSignature(t, secret, headers.Get("X-Slack-Request-Timestamp"), body))
	if err := verifySlackSignature(secret, headers, body); !errors.Is(err, ErrSlackTimestampSkew) {
		t.Fatalf("future timestamp err = %v, want ErrSlackTimestampSkew", err)
	}

	// A timestamp inside the window, with the matching MAC,
	// must verify cleanly.
	fresh := time.Now().Add(-30 * time.Second).Unix()
	headers.Set("X-Slack-Request-Timestamp", strconv.FormatInt(fresh, 10))
	headers.Set("X-Slack-Signature", computeSlackSignature(t, secret, headers.Get("X-Slack-Request-Timestamp"), body))
	if err := verifySlackSignature(secret, headers, body); err != nil {
		t.Fatalf("fresh signature err = %v, want nil", err)
	}
}

// mustTestChannel builds a SlackChannel backed by an
// httptest.Server's URL (passed through OptionAPIURL). The
// server is expected to be left running by the caller (we do
// not Close it from inside this helper).
func mustTestChannel(t *testing.T, serverURL, approverID string) *SlackChannel {
	t.Helper()
	// slack-go's OptionAPIURL concatenates the API method name
	// directly onto the configured endpoint, so the URL must
	// end with a single slash for path separation to work.
	if !strings.HasSuffix(serverURL, "/") {
		serverURL += "/"
	}
	cfg := config.Channel{
		Type:           "slack",
		BotToken:       "xoxb-test",
		AppToken:       "xapp-test",
		ApproverUserID: approverID,
	}
	ch, err := NewSlackChannel(cfg)
	if err != nil {
		t.Fatalf("NewSlackChannel: %v", err)
	}
	// Replace the api with one pointed at the fake server.
	ch.api = slack.New("xoxb-test",
		slack.OptionAPIURL(serverURL),
		slack.OptionAppLevelToken("xapp-test"),
	)
	ch.secret = []byte("slack-approval-secret")
	ch.approverCache = make(map[string]string)
	ch.pendingInteractions = make(map[string]chan slack.InteractionCallback)
	ch.done = make(chan struct{})
	return ch
}

// loadFixture reads a JSON file from the package directory and
// unmarshals it into a slack.InteractionCallback. Tests pass
// the relative path from the test's working directory
// (which Go sets to the package directory).
func loadFixture(t *testing.T, relPath string) slack.InteractionCallback {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(".", relPath))
	if err != nil {
		t.Fatalf("read fixture %s: %v", relPath, err)
	}
	var cb slack.InteractionCallback
	if err := json.Unmarshal(data, &cb); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", relPath, err)
	}
	return cb
}

// containsActionID returns true when the Block Kit payload
// contains an `actions` block whose action_id matches want.
// We descend into the JSON structure rather than regexing the
// raw bytes so a missing field produces a clean test failure
// instead of a false negative on a renamed key.
func containsActionID(payload map[string]any, want string) bool {
	blocks, ok := payload["blocks"].([]any)
	if !ok {
		return false
	}
	for _, raw := range blocks {
		block, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if block["type"] != "actions" {
			continue
		}
		elements, ok := block["elements"].([]any)
		if !ok {
			continue
		}
		for _, e := range elements {
			btn, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if btn["action_id"] == want {
				return true
			}
		}
	}
	return false
}

// containsRequestID checks whether the button value (which
// carries the request id) appears anywhere in the payload.
func containsRequestID(payload map[string]any, requestID string) bool {
	blocks, ok := payload["blocks"].([]any)
	if !ok {
		return false
	}
	for _, raw := range blocks {
		block, ok := raw.(map[string]any)
		if !ok || block["type"] != "actions" {
			continue
		}
		elements, ok := block["elements"].([]any)
		if !ok {
			continue
		}
		for _, e := range elements {
			btn, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if btn["value"] == requestID {
				return true
			}
		}
	}
	return false
}

// computeSlackSignature computes the v0 HMAC-SHA256 that
// Slack would produce for body under secret and timestamp.
// Used by signature tests so the test is checking the verify
// path against known-good input rather than against a
// pre-computed magic string.
func computeSlackSignature(t *testing.T, secret, timestamp string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:"))
	mac.Write([]byte(timestamp))
	mac.Write([]byte(":"))
	mac.Write(body)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}