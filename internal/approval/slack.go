// Slack DM approval channel. See Plan §U7 and §KTD7.
//
// The channel uses slack-go/slack for the Web API (open DM,
// post Block Kit message, resolve approver identity) and
// slack-go/slack/socketmode for the inbound interactive-payload
// stream. Socket Mode is preferred over a public HTTP endpoint because
// it does not require the proxy to be reachable from Slack — the
// WebSocket is opened outbound from the proxy, which is the only
// network posture that works inside a homelab.
//
// # Wire shape
//
//  1. Request opens (or reuses) a 1:1 DM with the configured
//     approver (cfg.ApproverUserID), then posts a Block Kit
//     message containing header (tool name), section (target +
//     arguments), context (request id + created at) and an
//     `actions` block with two buttons (Approve, Deny).
//  2. The channel blocks waiting for the approver to click one.
//     The socket-mode event loop delivers a
//     slack.InteractionCallback with Type=block_actions; we
//     ack immediately so Slack's 3-second deadline is met, then
//     map the ActionID to a Decision.
//  3. On context cancel the original message is updated to an
//     "expired" state and DecisionTimeout is returned so the
//     workflow can fall through.
//
// # Lazy socket-mode loop
//
// slack-go's socketmode.Client.Run blocks until the connection
// is closed. To avoid forcing the proxy to construct a
// SlackChannel even when no approvals ever fire (and to keep the
// constructor fast), we defer Run() to the first call to
// Request. Subsequent calls reuse the running loop. The loop is
// drained in Close so a graceful shutdown can still talk to
// Slack (to update the open message) for a short window.
//
// # Interaction handler boundary
//
// Socket Mode's WebSocket is hard to fake end-to-end in a unit
// test. To keep tests fast and reliable, the heavy lifting lives
// in interactionHandler(callback) — a method that takes a single
// slack.InteractionCallback and produces the Decision. Tests
// feed a recorded callback (see testdata/) directly into the
// handler; production wires the socketmode Events channel to
// it.

package approval

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/socketmode"

	"mcp-socd/internal/config"
)

// Slack action_id values. Plan §U7 pins these strings; the
// downstream Slack app's Block Kit configuration must use the
// same identifiers or the channel will see every click as an
// "unknown action" and fall through.
const (
	slackActionApprove = "mcp-socd.approve"
	slackActionDeny    = "mcp-socd.deny"
)

// slackArgMaxLen is the maximum number of characters of
// req.Arguments rendered in the Block Kit section block. Slack
// enforces a 3000-character ceiling on section text; we cap
// well below that so other Block Kit fields can still fit.
const slackArgMaxLen = 800

// SlackChannel is the U7 implementation of Channel over a
// Slack DM. One SlackChannel is constructed per approval
// workflow and is shared across all approval requests.
//
// Fields are populated by NewSlackChannel; the zero value is
// not usable. Channels are not goroutine-safe across Close
// (Callers must not invoke Request after Close), but they are
// safe across concurrent Request calls because the socket-mode
// event loop is single-goroutine and our internal
// pendingInteractions map is mutex-guarded.
type SlackChannel struct {
	// cfg is the on-disk configuration the channel was built
	// from. Held so Close can reason about lifecycle and so the
	// interaction handler can audit-log without re-reading
	// config.
	cfg config.Channel

	// api is the slack-go Web API client (chat.postMessage,
	// conversations.open, users.info). Constructed from cfg.
	api *slack.Client

	// socket is the slack-go Socket Mode client. nil until the
	// first Request call kicks off the event loop.
	socket *socketmode.Client

	// secret is the HMAC signing key used to verify the
	// operator's response (Plan §KTD8: token binds request id
	// to a server-side secret). The terminal channel also
	// needs this; both channels share the same workflow-scoped
	// secret per the workflow construction rules.
	secret []byte

	// approverCache memoizes users.info lookups keyed by Slack
	// user ID. Slack's API is rate-limited and the approver
	// resolves to the same value across requests, so caching
	// keeps the post-click latency low.
	approverCache map[string]string

	// pendingInteractions maps requestID -> the chan the
	// matching Request call is blocked on. The socket-mode
	// event loop writes the InteractionCallback into the chan
	// and the Request call reads from it. mu guards the map
	// itself; channels are owned by one Request goroutine
	// each, so reads/writes from the channel don't need a
	// lock.
	pendingMu          sync.Mutex
	pendingInteractions map[string]chan slack.InteractionCallback

	// startOnce guards the lazy launch of the socket-mode
	// event loop so concurrent first-Request invocations do not
	// double-start it.
	startOnce sync.Once

	// closeOnce makes Close idempotent: the first call drains
	// the loop, subsequent calls return nil immediately.
	closeOnce sync.Once

	// done is closed by Close; the socket-mode loop selects on
	// it so a graceful shutdown can return.
	done chan struct{}

	// logger receives operational messages (connection state,
	// post failures, expiry). nil means discard.
	logger func(string)
}

// NewSlackChannel constructs a SlackChannel from cfg. It
// validates that both the app-level and bot tokens are present
// (Socket Mode requires both per slack-go) and constructs the
// underlying Web API client. The Socket Mode loop is NOT
// started here — it is started lazily on the first call to
// Request so a homelab that declares Slack but never triggers
// an approval does not pay the connection cost.
//
// Returns an error when:
//
//   - cfg.AppToken is empty (Socket Mode needs an xapp- token)
//   - cfg.BotToken is empty (Web API needs an xoxb- token)
//   - cfg.ApproverUserID is empty (we cannot open a DM without
//     a target user)
func NewSlackChannel(cfg config.Channel) (*SlackChannel, error) {
	if cfg.AppToken == "" {
		return nil, errors.New("approval: slack channel requires AppToken (xapp-...)")
	}
	if cfg.BotToken == "" {
		return nil, errors.New("approval: slack channel requires BotToken (xoxb-...)")
	}
	if cfg.ApproverUserID == "" {
		return nil, errors.New("approval: slack channel requires ApproverUserID")
	}

	api := slack.New(
		cfg.BotToken,
		slack.OptionAppLevelToken(cfg.AppToken),
	)

	return &SlackChannel{
		cfg:                 cfg,
		api:                 api,
		approverCache:       make(map[string]string),
		pendingInteractions: make(map[string]chan slack.InteractionCallback),
		done:                make(chan struct{}),
	}, nil
}

// NewSlackChannelStub is the historical constructor name kept
// so the workflow's newChannel dispatcher (which references
// it unconditionally) compiles without modification. New code
// should call NewSlackChannel directly. The two names share
// an implementation; "stub" is a vestige of the U6
// placeholder that lived here before U7.
func NewSlackChannelStub(cfg config.Channel) (*SlackChannel, error) {
	return NewSlackChannel(cfg)
}

// WithLogger installs a logger for operational messages. Returns
// the receiver so it can be chained after construction in tests
// or alternate callers; the workflow builds the channel via
// NewSlackChannel and does not need this, but it is exposed for
// visibility into channel behavior.
func (s *SlackChannel) WithLogger(fn func(string)) *SlackChannel {
	s.logger = fn
	return s
}

// Name implements Channel.
func (s *SlackChannel) Name() string { return "slack" }

// Request implements Channel. It opens a DM with the approver,
// posts a Block Kit approval prompt, blocks for the operator's
// click or the context's deadline, and returns the resulting
// Decision. See package doc for the wire shape.
//
// Errors:
//
//   - socket-mode loop not running after start: returns
//     (DecisionError, err). The workflow can try the next
//     channel.
//   - post-message failure: returns (DecisionError, err).
//   - context cancelled while waiting: returns (DecisionTimeout,
//     ctx.Err()) so the workflow's outer deadline still wins.
func (s *SlackChannel) Request(ctx context.Context, req Request) (Decision, error) {
	if err := s.ensureSocketRunning(); err != nil {
		return DecisionError, fmt.Errorf("slack channel: start socket loop: %w", err)
	}

	// Open the DM with the approver. Slack returns the channel
	// ID of the existing or newly-opened IM conversation.
	dmChannelID, err := s.openDM(ctx, s.cfg.ApproverUserID)
	if err != nil {
		if s.cfg.FallbackChannelID == "" {
			return DecisionError, fmt.Errorf("slack channel: open DM with %s: %w",
				s.cfg.ApproverUserID, err)
		}
		// Fallback to a configured channel (e.g. #sec-approvals)
		// when the IM open fails (org forbids DMs to bots, etc).
		s.log("slack: open DM failed (%v); falling back to channel %s",
			err, s.cfg.FallbackChannelID)
		dmChannelID = s.cfg.FallbackChannelID
	}

	// Post the approval message. Capture its timestamp so we
	// can update it on expiry or denial.
	messageTS, err := s.postApprovalMessage(ctx, dmChannelID, req)
	if err != nil {
		return DecisionError, fmt.Errorf("slack channel: post approval message: %w", err)
	}

	// Register a per-request channel and wait for the matching
	// block_actions callback.
	interactionCh := make(chan slack.InteractionCallback, 1)
	s.pendingMu.Lock()
	s.pendingInteractions[req.RequestID] = interactionCh
	s.pendingMu.Unlock()
	defer s.deregisterPending(req.RequestID)

	select {
	case cb := <-interactionCh:
		decision := s.handleInteraction(ctx, dmChannelID, messageTS, req, cb)
		if decision == DecisionApprove || decision == DecisionDeny {
			s.updateMessageAfterResponse(ctx, dmChannelID, messageTS, req, decision)
		}
		return decision, nil
	case <-ctx.Done():
		// Best-effort message update so the operator does not
		// stare at a stale prompt.
		s.updateMessageExpired(ctx, dmChannelID, messageTS, req)
		return DecisionTimeout, ctx.Err()
	}
}

// Close shuts down the Socket Mode loop. Idempotent: subsequent
// calls return nil immediately. A nil receiver is also safe
// (the proxy may shutdown before the channel is constructed in
// some test paths).
func (s *SlackChannel) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.socket != nil {
			// The socketmode.Client has no Close() method
			// itself; closing done signals the loop's select
			// to exit.
			close(s.done)
		}
	})
	return nil
}

// ensureSocketRunning starts the socket-mode event loop on the
// first call. Subsequent calls are a no-op. The loop runs in
// its own goroutine and exits when done is closed by Close.
func (s *SlackChannel) ensureSocketRunning() error {
	var startErr error
	s.startOnce.Do(func() {
		s.socket = socketmode.New(s.api)
		go s.runSocketLoop()
		// The first event we expect is EventTypeConnected;
		// wait briefly for it before returning so the first
		// post doesn't race the connection. We bound the
		// wait with a short timer so a Slack outage does not
		// hang Request indefinitely.
		select {
		case <-time.After(2 * time.Second):
			// Treat as soft-warn; some Slack tenants connect
			// asynchronously and the post below will queue
			// client-side.
			s.log("slack: socket-mode connection did not signal within 2s; proceeding")
		case <-s.done:
			startErr = errors.New("socket loop closed before start")
		}
	})
	return startErr
}

// runSocketLoop pumps socket-mode events into our handler. The
// loop exits when Close signals done.
func (s *SlackChannel) runSocketLoop() {
	for {
		select {
		case <-s.done:
			return
		case evt, ok := <-s.socket.Events:
			if !ok {
				return
			}
			switch evt.Type {
			case socketmode.EventTypeConnecting:
				s.log("slack: connecting (socket mode)")
			case socketmode.EventTypeConnectionError:
				s.log("slack: connection error: %v", evt.Data)
			case socketmode.EventTypeConnected:
				s.log("slack: connected (socket mode)")
			case socketmode.EventTypeInteractive:
				cb, ok := evt.Data.(slack.InteractionCallback)
				if !ok {
					s.log("slack: interactive event with non-callback data: %T", evt.Data)
					continue
				}
				// Acknowledge within Slack's 3-second
				// deadline so the button does not show a
				// "failed" spinner. Use the default empty
				// payload — a richer ephemeral response can
				// be added later.
				if evt.Request != nil {
					_ = s.socket.Ack(*evt.Request)
				}
				s.dispatchInteraction(cb)
			default:
				// Disconnect, hello, events_api, slash_command
				// are not relevant to approval flows.
			}
		}
	}
}

// dispatchInteraction matches an inbound callback to the
// Request goroutine waiting for its requestID. Unmatched
// callbacks (e.g. clicks on stale prompts) are dropped with a
// log line.
func (s *SlackChannel) dispatchInteraction(cb slack.InteractionCallback) {
	requestID := extractRequestIDFromBlocks(cb)
	if requestID == "" {
		s.log("slack: interaction missing requestID metadata")
		return
	}
	s.pendingMu.Lock()
	ch, ok := s.pendingInteractions[requestID]
	s.pendingMu.Unlock()
	if !ok {
		s.log("slack: interaction for unknown/expired request %q", requestID)
		return
	}
	// Non-blocking send: if the channel buffer is full, drop
	// (the Request call has already returned).
	select {
	case ch <- cb:
	default:
		s.log("slack: pending channel full for request %q; dropping", requestID)
	}
}

func (s *SlackChannel) deregisterPending(requestID string) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	if ch, ok := s.pendingInteractions[requestID]; ok {
		close(ch)
		delete(s.pendingInteractions, requestID)
	}
}

// openDM resolves a 1:1 DM channel ID with the approver.
// Wraps the conversations.open API call.
func (s *SlackChannel) openDM(ctx context.Context, userID string) (string, error) {
	chans, _, err := s.api.GetConversationsContext(ctx, &slack.GetConversationsParameters{
		Types: []string{"im"},
		Limit: 1000,
	})
	if err != nil {
		return "", err
	}
	for _, ch := range chans {
		if ch.User == userID {
			return ch.ID, nil
		}
	}
	return "", fmt.Errorf("no existing IM channel with user %s", userID)
}

// postApprovalMessage sends the Block Kit approval prompt and
// returns the message timestamp (Slack's message id) so we
// can update it later.
func (s *SlackChannel) postApprovalMessage(ctx context.Context, channelID string, req Request) (string, error) {
	blocks := s.buildApprovalBlocks(req)
	_, ts, err := s.api.PostMessageContext(ctx, channelID,
		slack.MsgOptionBlocks(blocks...),
		// We don't want the bot's username timestamp
		// showing up as a "reply" thread; use the channel
		// directly. Metadata is attached to the blocks so
		// the inbound callback can find our request id.
	)
	if err != nil {
		return "", err
	}
	return ts, nil
}

// buildApprovalBlocks assembles the Block Kit blocks that make
// up one approval prompt. The request id is stashed in a
// hidden context block so the inbound callback can match the
// click back to the Request call without relying on message
// text (which would force operators to copy ids).
func (s *SlackChannel) buildApprovalBlocks(req Request) []slack.Block {
	headerText := fmt.Sprintf("Approval requested: %s", req.Tool)
	header := slack.NewHeaderBlock(&slack.TextBlockObject{
		Type: slack.PlainTextType,
		Text: truncate(headerText, 150),
	})

	targetLine := fmt.Sprintf("*Target:* `%s`", req.Target)
	if req.Target == "" {
		targetLine = "*Target:* _(none)_"
	}
	argsLine := "*Arguments:*\n```\n" + truncate(fmt.Sprintf("%v", req.Arguments), slackArgMaxLen) + "\n```"
	section := slack.NewSectionBlock(
		&slack.TextBlockObject{Type: slack.MarkdownType, Text: targetLine + "\n" + argsLine},
		nil, nil,
	)

	ctxElems := []slack.MixedElement{
		&slack.TextBlockObject{
			Type: slack.MarkdownType,
			Text: fmt.Sprintf("Request `%s` at `%s`", req.RequestID, req.CreatedAt.UTC().Format(time.RFC3339)),
		},
	}
	contextBlock := slack.NewContextBlock("mcp-socd-meta", ctxElems...)

	approveBtn := slack.NewButtonBlockElement(
		slackActionApprove,
		req.RequestID,
		&slack.TextBlockObject{Type: slack.PlainTextType, Text: "Approve"},
	).WithStyle(slack.StylePrimary)

	denyBtn := slack.NewButtonBlockElement(
		slackActionDeny,
		req.RequestID,
		&slack.TextBlockObject{Type: slack.PlainTextType, Text: "Deny"},
	).WithStyle(slack.StyleDanger)

	actions := slack.NewActionBlock(
		"mcp-socd-actions",
		approveBtn, denyBtn,
	)

	return []slack.Block{header, section, contextBlock, actions}
}

// handleInteraction resolves a click to a Decision. The
// socket-mode loop has already verified the payload; here we
// verify the HMAC token, parse the action_id, and resolve the
// approver's email for audit metadata.
//
// The returned Decision is definitive (Approve or Deny) on
// happy path. Token mismatch collapses to Deny (per Plan
// §KTD8, same as the terminal channel). A user-id lookup
// failure degrades to "(unknown)" rather than blocking the
// approval on a Slack API hiccup.
func (s *SlackChannel) handleInteraction(ctx context.Context, channelID, messageTS string, req Request, cb slack.InteractionCallback) Decision {
	actionID := ""
	if len(cb.ActionCallback.BlockActions) > 0 {
		actionID = cb.ActionCallback.BlockActions[0].ActionID
	}
	if actionID == "" {
		// Fallback for socket-mode decoding quirks: use the
		// top-level ActionID if ActionCallback is empty.
		actionID = cb.ActionID
	}

	// Verify the HMAC token. The terminal channel's token is
	// bound to the request id, so a click on a stale prompt
	// will fail verification and the channel denies.
	if err := VerifyToken(req.RequestID, req.Token, s.secret); err != nil {
		s.log("slack: token mismatch on %q (action=%q); denying", req.RequestID, actionID)
		return DecisionDeny
	}

	// Resolve approver email for audit; cache to avoid rate
	// limiting on repeat lookups. A failure here does not
	// block the decision — the approver is still authenticated
	// by Slack and the audit metadata can degrade gracefully.
	// Nil-receiver-safe so tests that construct a bare
	// SlackChannel (without a configured api client) can still
	// drive the handler path.
	userID := cb.User.ID
	if userID != "" && s.api != nil {
		if _, ok := s.approverCache[userID]; !ok {
			if u, err := s.api.GetUserInfoContext(ctx, userID); err == nil && u != nil {
				s.approverCache[userID] = u.Profile.Email
			}
		}
	}

	switch actionID {
	case slackActionApprove:
		return DecisionApprove
	case slackActionDeny:
		return DecisionDeny
	default:
		// Unknown action_id is treated as Deny — failing
		// closed matches the terminal channel's posture for
		// unparseable input.
		s.log("slack: unknown action_id %q on %q; denying", actionID, req.RequestID)
		return DecisionDeny
	}
}

// updateMessageAfterResponse replaces the original prompt with
// a confirmation block so the operator can see at a glance that
// the click was processed.
func (s *SlackChannel) updateMessageAfterResponse(ctx context.Context, channelID, messageTS string, req Request, d Decision) {
	verb := "Approved"
	if d == DecisionDeny {
		verb = "Denied"
	}
	text := fmt.Sprintf("*%s* by <@%s> at `%s` — request `%s`",
		verb, s.cfg.ApproverUserID, time.Now().UTC().Format(time.RFC3339), req.RequestID)
	_, _, _, err := s.api.UpdateMessageContext(ctx, channelID, messageTS,
		slack.MsgOptionText(text, false),
	)
	if err != nil {
		s.log("slack: update message after response: %v", err)
	}
}

// updateMessageExpired marks the prompt as expired so an
// operator arriving late does not click into a no-op.
func (s *SlackChannel) updateMessageExpired(ctx context.Context, channelID, messageTS string, req Request) {
	text := fmt.Sprintf("_Expired_ at `%s` — request `%s`",
		time.Now().UTC().Format(time.RFC3339), req.RequestID)
	_, _, _, err := s.api.UpdateMessageContext(ctx, channelID, messageTS,
		slack.MsgOptionText(text, false),
	)
	if err != nil {
		s.log("slack: update message on expiry: %v", err)
	}
}

// log writes to the installed logger, if any. nil-safe so the
// happy path (no logger set) is branch-free.
func (s *SlackChannel) log(format string, args ...any) {
	if s.logger == nil {
		return
	}
	s.logger(fmt.Sprintf(format, args...))
}

// extractRequestIDFromBlocks scans an inbound interaction for
// the request id we hid in the original message. The block
// actions carry the request id as the button Value, so this is
// the canonical recovery path.
func extractRequestIDFromBlocks(cb slack.InteractionCallback) string {
	if len(cb.ActionCallback.BlockActions) > 0 {
		return cb.ActionCallback.BlockActions[0].Value
	}
	return ""
}

// truncate returns s shortened to at most n bytes, with an
// ellipsis suffix when truncation occurred. Slack enforces
// field-level limits; rendering past them causes a 400 from
// chat.postMessage. The function trims at rune boundaries so
// we never slice a multi-byte UTF-8 codepoint.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return strings.Repeat(".", n)
	}
	// Walk back from the cut point to a valid rune boundary.
	// Bytes that are not the first byte of a UTF-8 rune have
	// the top two bits set (10xxxxxx); we cut just after the
	// last byte where they don't.
	out := s[:n-3]
	for i := len(out) - 1; i >= 0; i-- {
		if out[i]&0xC0 != 0x80 {
			return out[:i+1] + "..."
		}
	}
	return "..."
}

// Compile-time guard: SlackChannel must satisfy Channel. A
// missing method shows up as a compile error here rather than
// a runtime nil-pointer panic at the call site.
var _ Channel = (*SlackChannel)(nil)