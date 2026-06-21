// Slack DM approval channel. U7 will provide the real implementation;
// for U6 this is a stub that returns DecisionError so the workflow
// can still build when Slack is configured but not yet implemented.
//
// The stub exists for two reasons:
//
//  1. Compile-time check that the Channel interface and the
//     newChannel dispatcher handle the slack type without a runtime
//     panic. The U7 implementation replaces this file directly;
//     the interface and workflow code do not change.
//  2. Operational diagnostic: if a homelab operator misconfigures
//     Slack and runs U6, the audit record's channel="slack" with
//     DecisionError tells them exactly what is missing instead of
//     silently falling through to terminal.

package approval

import (
	"context"
	"errors"

	"mcp-socd/internal/config"
)

// SlackChannel is the U7 placeholder. U7 will replace it with the
// real Slack-DM-based implementation that uses slack-go/slack with
// Socket Mode and Block Kit interactive buttons per Plan §KTD7.
type SlackChannel struct {
	// cfg is preserved so U7's implementation has the original
	// configuration to work from without re-parsing config.
	cfg config.Channel
}

// NewSlackChannelStub returns a Channel implementation that always
// returns DecisionError. U7 will swap this for a real implementation
// without changing the Channel interface or workflow code.
func NewSlackChannelStub(cfg config.Channel) (*SlackChannel, error) {
	// We do not enforce token presence here: the workflow can
	// still build when Slack is declared but credentials are
	// missing (the operator may add them later via hot-reload,
	// which is a U1+ follow-up). U7 will tighten this.
	return &SlackChannel{cfg: cfg}, nil
}

// Name implements Channel.
func (s *SlackChannel) Name() string { return "slack" }

// Request implements Channel. The stub always returns
// DecisionError so the workflow can try the next channel (typically
// terminal) and surface a clear "slack not implemented" message via
// the audit hook.
func (s *SlackChannel) Request(_ context.Context, _ Request) (Decision, error) {
	return DecisionError, errors.New("slack channel not implemented in U6")
}
