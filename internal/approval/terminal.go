// Terminal approval channel. See Plan §U6 and §KTD7.
//
// Reads a single y/N line from stdin (or /dev/tty when available),
// verifies the HMAC token, and returns the operator's answer. The
// channel is intentionally synchronous: it owns the terminal while
// the operator is reading the prompt, and yields back when the
// operator has typed their answer or the context is cancelled.
//
// # Prompt format
//
// "APPROVE tool=isolate_endpoint target=server01.example.com? [y/N] (token: a1b2c3d4): "
//
// The token prefix is shown for visual confirmation; the full token
// must be typed for the response to be accepted. A "y" without the
// token (or with the wrong token) is treated as Deny with audit.

package approval

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// TokenPlaceholder is the printf verb in TerminalChannelOptions.Prompt
// that is replaced with TokenPrefix(req.Token) before display. Tests
// override the prompt format with a simpler shape; production callers
// use the default.
const TokenPlaceholder = "%T%"

// TerminalChannelOptions configures TerminalChannel. Most callers
// use the defaults (stdin/stderr, 30s read timeout) and only override
// the prompt format for tests.
type TerminalChannelOptions struct {
	// Reader is the source of operator input. Defaults to
	// terminalReader() which prefers /dev/tty and falls back to
	// os.Stdin. Tests pass an io.Pipe.
	Reader io.Reader

	// Writer is where the prompt is written. Defaults to
	// os.Stderr so the prompt does not leak onto the agent's
	// stdout (which must remain valid MCP frames).
	Writer io.Writer

	// Prompt is the format string for the operator prompt. The
	// verbs are substituted at render time:
	//
	//   %T% — TokenPrefix(req.Token) — short prefix shown to the operator
	//   %s% — req.Tool                — MCP tool name under review
	//   %t% — req.Target              — primary target (hostname, user)
	//
	// The default is "APPROVE %s% target=%t%? [y/N] (token: %T%): ".
	// Tests override this with a simpler shape.
	Prompt string

	// ReadTimeout is the per-line read deadline. Defaults to 30s
	// so an operator who walked away from the terminal does not
	// hold the workflow forever. The workflow's outer timeout is
	// the source of truth for the request as a whole; this is
	// just a per-channel wait ceiling.
	ReadTimeout time.Duration

	// Secret is the HMAC signing key. The terminal channel needs
	// it to verify the operator's response. Normally it is loaded
	// by NewWorkflow and threaded through; tests pass it
	// explicitly when constructing the channel directly.
	Secret []byte
}

// TerminalChannel prompts the operator on a terminal and verifies
// the HMAC token before accepting the response. Constructed via
// NewTerminalChannel so the defaults are applied consistently.
type TerminalChannel struct {
	reader io.Reader
	writer io.Writer
	prompt string
	readTO time.Duration
	secret []byte
}

// NewTerminalChannel constructs a TerminalChannel with the supplied
// options. Zero-value fields fall back to the documented defaults
// (terminalReader(), os.Stderr, default prompt, 30s read timeout).
//
// A nil or empty Secret is an error: without a key the channel
// cannot verify operator responses and would silently accept any
// token, defeating the security purpose of HMAC binding.
func NewTerminalChannel(opts TerminalChannelOptions) (*TerminalChannel, error) {
	if len(opts.Secret) == 0 {
		return nil, errors.New("approval: terminal channel requires a non-empty Secret")
	}
	c := &TerminalChannel{
		reader: opts.Reader,
		writer: opts.Writer,
		prompt: opts.Prompt,
		readTO: opts.ReadTimeout,
		secret: append([]byte(nil), opts.Secret...),
	}
	if c.reader == nil {
		c.reader = terminalReader()
	}
	if c.writer == nil {
		c.writer = os.Stderr
	}
	if c.prompt == "" {
		c.prompt = "APPROVE %s% target=%t%? [y/N] (token: %T%): "
	}
	if c.readTO <= 0 {
		c.readTO = 30 * time.Second
	}
	return c, nil
}

// Name implements Channel.
func (c *TerminalChannel) Name() string { return "terminal" }

// Request implements Channel. It writes the prompt to c.writer,
// reads one line from c.reader, verifies the HMAC token, and returns
// Approve on "y <token>" or Deny on "n <token>" / unrecognized input.
//
// Errors:
//
//   - ctx cancelled during read: returns (DecisionTimeout, ctx.Err())
//     so the workflow's outer deadline still wins.
//   - read timeout: returns (DecisionTimeout, nil) so the workflow
//     can try the next channel.
//   - bad response format or token mismatch: returns (DecisionDeny,
//     nil). The operator's answer was processable, just wrong; this
//     is not a transport-level failure.
func (c *TerminalChannel) Request(ctx context.Context, req Request) (Decision, error) {
	if err := c.writePrompt(req); err != nil {
		return DecisionError, fmt.Errorf("terminal channel: write prompt: %w", err)
	}

	line, err := c.readLine(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return DecisionTimeout, err
		}
		// Per-line read timeout collapses to DecisionTimeout so the
		// workflow can fall through to the next channel.
		if isTimeout(err) {
			return DecisionTimeout, nil
		}
		return DecisionError, fmt.Errorf("terminal channel: read response: %w", err)
	}

	return parseTerminalResponse(line, req.RequestID, c.secret), nil
}

// writePrompt renders the prompt to c.writer. The format string
// supports three verbs (see TerminalChannelOptions.Prompt).
func (c *TerminalChannel) writePrompt(req Request) error {
	prefix := TokenPrefix(req.Token)
	msg := c.prompt
	msg = strings.ReplaceAll(msg, "%T%", prefix)
	msg = strings.ReplaceAll(msg, "%s%", req.Tool)
	msg = strings.ReplaceAll(msg, "%t%", req.Target)
	if _, err := io.WriteString(c.writer, msg); err != nil {
		return err
	}
	// Flush if writer is buffered (bufio.Writer, test sinks).
	if f, ok := c.writer.(interface{ Flush() error }); ok {
		_ = f.Flush()
	}
	return nil
}

// readLine returns the next newline-terminated line from c.reader,
// stripped of the trailing newline. Honours ctx for cancellation
// and the channel's readTO for the per-line ceiling.
//
// A clean EOF (no trailing newline) is treated as a successful read
// of the trailing partial line. This is the right behavior for
// redirected stdin where the operator's "y <token>" is followed
// by EOF rather than Enter.
func (c *TerminalChannel) readLine(ctx context.Context) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		reader := bufio.NewReader(c.reader)
		line, err := reader.ReadString('\n')
		ch <- result{line: line, err: err}
	}()

	var timer *time.Timer
	var timerC <-chan time.Time
	if c.readTO > 0 {
		timer = time.NewTimer(c.readTO)
		defer timer.Stop()
		timerC = timer.C
	}

	select {
	case r := <-ch:
		if r.err != nil && !errors.Is(r.err, io.EOF) {
			return "", r.err
		}
		return strings.TrimRight(r.line, "\r\n"), nil
	case <-timerC:
		return "", os.ErrDeadlineExceeded
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// parseTerminalResponse interprets one line of operator input. The
// expected shape is "<y|n> <full-token>" with optional whitespace
// between the verb and the token. The token is verified against the
// requestID using the HMAC secret; a mismatch collapses to Deny
// because the operator was presumably answering a different prompt.
//
// We accept the verb "yes" as well as "y"; anything else is Deny.
// This matches Plan §KTD8: explicit deny is the safe default.
func parseTerminalResponse(line, requestID string, secret []byte) Decision {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		// Without a token the operator cannot have meant to approve.
		// Default-deny.
		return DecisionDeny
	}
	verb := strings.ToLower(fields[0])
	presented := fields[1]

	if err := VerifyToken(requestID, presented, secret); err != nil {
		// Token mismatch is treated as Deny, not Error. The
		// operator is reading a different prompt; failing
		// closed is the safe response.
		return DecisionDeny
	}

	switch verb {
	case "y", "yes":
		return DecisionApprove
	default:
		return DecisionDeny
	}
}

// isTimeout reports whether err indicates a per-line timeout that
// should be treated as DecisionTimeout rather than DecisionError.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	type timeoutErr interface{ Timeout() bool }
	var te timeoutErr
	if errors.As(err, &te) {
		return te.Timeout()
	}
	return false
}

// terminalReader prefers /dev/tty (which works under nohup and tmux)
// and falls back to os.Stdin. Tests pass their own reader via
// TerminalChannelOptions.Reader so this default does not run.
func terminalReader() io.Reader {
	if f, err := os.Open("/dev/tty"); err == nil {
		return f
	}
	return os.Stdin
}
