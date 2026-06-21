// Package errsposture decides what the proxy does when something goes
// wrong mid-evaluation. It exports one type, Posture, that classifies
// every tools/call as either fail-closed or fail-open. The proxy (U4)
// consults the classification to choose between returning an error to
// the agent (fail-closed) and attempting the action in degraded mode
// (fail-open). See Plan §U9 and acceptance examples AE5/AE6.
//
// The classification rule, per Plan R3 and §U9:
//
//   - Destructive: the tool name contains a destructive verb (delete,
//     drop, truncate, revoke, disable, wipe, purge) OR the catalog
//     action's blast radius is at least 3. Fails closed.
//   - Read-only: blast radius under 3 AND no destructive verb. Fails
//     open.
//   - Unknown action (not in the catalog) defaults to fail-closed so
//     a misconfigured catalog never widens the trust surface.
//
// The package is deliberately import-isolated: it pulls in only
// internal/catalog and internal/policy, never internal/proxy or
// internal/audit. That keeps the dependency graph one-directional
// (proxy -> posture -> catalog/policy) and lets tests run without
// spinning up the audit emitter.
package errsposture

import (
	"mcp-socd/internal/catalog"
	"mcp-socd/internal/policy"
)

// Mode is the error-handling posture for a single tools/call. The
// zero value is ModeFailClosed: a Posture that has not yet been
// asked to classify anything should not silently become permissive.
type Mode int

const (
	// ModeFailClosed returns an error to the agent and stops the
	// action. Used for destructive actions: the cost of a false
	// negative (refusing a legitimate call during an outage) is
	// acceptable; the cost of a false positive (executing an
	// isolation against an unrelated host) is not. Maps to the
	// audit reason "fail_closed".
	ModeFailClosed Mode = iota

	// ModeFailOpen attempts the action in degraded mode. Used for
	// read-only actions: the worst case is a missed observation,
	// which the operator can repeat manually. Maps to the audit
	// reason "fail_open".
	ModeFailOpen
)

// String returns the canonical lowercase posture name used in audit
// metadata. The empty string is reserved for an unclassified mode;
// callers should never emit an audit event without a posture stamp.
func (m Mode) String() string {
	switch m {
	case ModeFailClosed:
		return "fail_closed"
	case ModeFailOpen:
		return "fail_open"
	default:
		return ""
	}
}

// Posture classifies MCP tool calls as fail-closed or fail-open. It
// is constructed with NewPosture and held by the proxy layer for the
// lifetime of the process. Posture is safe for concurrent use; it
// holds only references (no mutable state of its own).
type Posture struct {
	cat    *catalog.Catalog
	engine *policy.Engine
}

// NewPosture returns a Posture that classifies calls using the given
// catalog and policy engine. The engine reference is retained for
// symmetry with future classifications that may need to consult
// policy context; today's Classify uses only the catalog and the
// static destructive-verb list, so callers may pass nil for engine
// if they only intend to use Classify. We accept it now so the
// signature does not need to change when richer posture rules land.
//
// A nil catalog is treated as empty: every lookup fails closed.
// This is the safe direction; an empty catalog must never make the
// proxy more permissive.
func NewPosture(cat *catalog.Catalog, engine *policy.Engine) *Posture {
	return &Posture{cat: cat, engine: engine}
}

// Classify returns the posture for a given MCP tool call. The
// decision is made once per tools/call evaluation (Plan §U9) and
// stamped into the OCSF audit event's metadata so post-hoc analysis
// can correlate failures with posture.
//
// Classification rules, in order:
//
//  1. If the tool name contains a destructive verb (per
//     policy.IsDestructiveTool), return ModeFailClosed. The
//     destructive-verb gate is the safety net and wins regardless
//     of catalog membership; this catches AE4 (destructive-verb gate
//     triggered outside catalog).
//  2. Look up the tool in the catalog. If the action is unknown,
//     return ModeFailClosed. An action outside the catalog is
//     by definition ungoverned; failing open would be a policy
//     violation.
//  3. If the catalog action's blast radius is at least 3
//     (catalog.BlastRadiusSoftAction), return ModeFailClosed. This
//     covers every starter action whose execution changes state
//     (isolate_endpoint, block_user_account, rotate_api_key).
//  4. Otherwise (blast radius 1 or 2 and no destructive verb),
//     return ModeFailOpen.
func (p *Posture) Classify(call policy.Call) Mode {
	if policy.IsDestructiveTool(call.Tool) {
		return ModeFailClosed
	}
	if p == nil || p.cat == nil {
		return ModeFailClosed
	}
	action, ok := p.cat.Get(call.Tool)
	if !ok {
		return ModeFailClosed
	}
	if action.BlastRadius >= catalog.BlastRadiusSoftAction {
		return ModeFailClosed
	}
	return ModeFailOpen
}

// ModeName returns the canonical lowercase name of m ("fail_closed"
// or "fail_open"). Provided as a method on Posture so callers can
// stamp the posture into audit metadata with one expression:
//
//	posture.ModeName(posture.Classify(call))
//
// The method does not consult the catalog; it is purely a string
// conversion for an already-classified Mode.
func (p *Posture) ModeName(m Mode) string {
	return m.String()
}
