package errsposture

import (
	"testing"

	"mcp-socd/internal/catalog"
	"mcp-socd/internal/policy"
)

// newTestPosture returns a Posture backed by the starter catalog. The
// policy engine is nil because today's Classify does not consult it;
// passing nil matches what NewPosture accepts and pins the contract
// that an engine-less Posture is still usable.
func newTestPosture(t *testing.T) *Posture {
	t.Helper()
	return NewPosture(catalog.New(), nil)
}

// TestPosture_DestructiveFailsClosed — isolate_endpoint (blast 5,
// system-impact) must fail closed. AE5 pins this contract: a proxy
// failure during evaluation of a destructive action blocks the call
// rather than executing it. The audit reason in the production
// stack would be "fail_closed"; we assert it here via ModeName.
func TestPosture_DestructiveFailsClosed(t *testing.T) {
	p := newTestPosture(t)

	// The call Tool is the only field Classify reads.
	call := policy.Call{Tool: "isolate_endpoint"}

	got := p.Classify(call)
	if got != ModeFailClosed {
		t.Fatalf("Classify(%q) = %v, want ModeFailClosed", call.Tool, got)
	}
	// The proxy stamps the posture into the audit event's metadata.
	// Pin the string here so a future rename of ModeFailClosed breaks
	// the test loudly instead of silently corrupting audit correlation.
	if name := p.ModeName(got); name != "fail_closed" {
		t.Errorf("ModeName(ModeFailClosed) = %q, want %q", name, "fail_closed")
	}
}

// TestPosture_ReadFailsOpen — submit_edr_query (blast 1, read) must
// fail open. AE6 pins this contract: a proxy failure during
// evaluation of a read action attempts the action in degraded mode
// rather than blocking the agent. The audit reason is "fail_open".
func TestPosture_ReadFailsOpen(t *testing.T) {
	p := newTestPosture(t)

	call := policy.Call{Tool: "submit_edr_query"}

	got := p.Classify(call)
	if got != ModeFailOpen {
		t.Fatalf("Classify(%q) = %v, want ModeFailOpen", call.Tool, got)
	}
	if name := p.ModeName(got); name != "fail_open" {
		t.Errorf("ModeName(ModeFailOpen) = %q, want %q", name, "fail_open")
	}
}

// TestPosture_ModeStampedInAudit — every error audit event includes
// the posture mode string. We exercise this by walking the full
// starter catalog and asserting each classification maps to one of
// the two canonical strings. A future Mode value that lacks a
// non-empty String would slip through a Classify-only check but
// fail here, which is exactly the audit-trail invariant we want to
// protect.
func TestPosture_ModeStampedInAudit(t *testing.T) {
	p := newTestPosture(t)

	for _, a := range catalog.Starter() {
		call := policy.Call{Tool: a.Name}
		mode := p.Classify(call)
		name := p.ModeName(mode)
		if name != "fail_closed" && name != "fail_open" {
			t.Errorf("ModeName(Classify(%q)) = %q, want fail_closed or fail_open",
				a.Name, name)
		}
	}
}

// TestPosture_UnknownActionFailsClosed — an action not in the
// catalog must fail closed even when the tool name carries no
// destructive verb. Defaulting to fail-open here would let a
// misconfigured catalog widen the trust surface; a missing or
// unknown action is ungoverned by definition, so the safe posture
// is to refuse.
func TestPosture_UnknownActionFailsClosed(t *testing.T) {
	p := newTestPosture(t)

	cases := []string{
		"some_unknown_action",
		"submit_unrelated_query",
		"refresh_token", // no destructive verb, no catalog entry
	}
	for _, tool := range cases {
		t.Run(tool, func(t *testing.T) {
			got := p.Classify(policy.Call{Tool: tool})
			if got != ModeFailClosed {
				t.Errorf("Classify(%q) = %v, want ModeFailClosed", tool, got)
			}
		})
	}
}

// TestPosture_DestructiveVerbWins — a destructive verb in the tool
// name forces fail-closed regardless of the action's catalog blast
// radius. This is the safety-net behavior of Plan R7 / §U9: even if
// someone added a low-blast-radius action with a verb like "delete"
// to the catalog, the gate would still trip.
//
// We synthesize two cases that have no catalog entry (so the
// blast-radius lookup cannot accidentally steer the result) and
// verify both classify as fail-closed purely because of the verb.
func TestPosture_DestructiveVerbWins(t *testing.T) {
	p := newTestPosture(t)

	cases := []struct {
		tool string
	}{
		{"delete_low_risk_thing"},
		{"truncate_cache"},
		{"disable_metric"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			got := p.Classify(policy.Call{Tool: tc.tool})
			if got != ModeFailClosed {
				t.Errorf("Classify(%q) = %v, want ModeFailClosed (destructive verb)",
					tc.tool, got)
			}
		})
	}
}

// TestPosture_BlastRadiusThreshold — every catalog action with
// blast radius >= 3 fails closed; every action with blast radius
// < 3 fails open (provided no destructive verb in the name, which
// the starter catalog guarantees). Pinning the threshold here means
// a future catalog addition that crosses the line will break this
// test unless the operator also confirms the posture change.
func TestPosture_BlastRadiusThreshold(t *testing.T) {
	p := newTestPosture(t)

	for _, a := range catalog.Starter() {
		call := policy.Call{Tool: a.Name}
		mode := p.Classify(call)
		want := ModeFailOpen
		if a.BlastRadius >= catalog.BlastRadiusSoftAction {
			want = ModeFailClosed
		}
		if mode != want {
			t.Errorf("Classify(%q) = %v, want %v (blast radius %d)",
				a.Name, mode, want, a.BlastRadius)
		}
	}
}

// TestPosture_NilCatalogFailsClosed — a Posture constructed with a
// nil catalog must classify every call as fail-closed. This guards
// against a future refactor that assumes the catalog is non-nil;
// without this guard, an uninitialized Posture could become
// permissive by accident.
func TestPosture_NilCatalogFailsClosed(t *testing.T) {
	p := NewPosture(nil, nil)

	call := policy.Call{Tool: "submit_edr_query"} // would be fail-open with a real catalog
	if got := p.Classify(call); got != ModeFailClosed {
		t.Errorf("Classify with nil catalog = %v, want ModeFailClosed", got)
	}
}

// TestModeString — defensive coverage of the Mode.String switch
// so an unhandled Mode value (e.g. introduced by future expansion)
// surfaces as an empty string rather than a silent default.
func TestModeString(t *testing.T) {
	cases := []struct {
		mode Mode
		want string
	}{
		{ModeFailClosed, "fail_closed"},
		{ModeFailOpen, "fail_open"},
		{Mode(99), ""}, // unknown future value
	}
	for _, tc := range cases {
		if got := tc.mode.String(); got != tc.want {
			t.Errorf("Mode(%d).String() = %q, want %q", tc.mode, got, tc.want)
		}
	}
}
