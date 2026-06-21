package catalog

import (
	"testing"
)

// TestStarter_BlastRadiusMapping pins the blast-radius score of each
// starter action so the documented mapping in starter.go cannot drift
// without a test failure. Complements the range check in
// TestBlastRadius_ScoresAllInRange by asserting the exact values.
func TestStarter_BlastRadiusMapping(t *testing.T) {
	want := map[string]int{
		"isolate_endpoint":   BlastRadiusSystemImpact,
		"block_user_account": BlastRadiusUserImpact,
		"rotate_api_key":     BlastRadiusSoftAction,
		"submit_edr_query":   BlastRadiusRead,
		"enrich_ioc":         BlastRadiusRead,
	}
	for _, a := range Starter() {
		w, ok := want[a.Name]
		if !ok {
			t.Errorf("unexpected starter action %q", a.Name)
			continue
		}
		if a.BlastRadius != w {
			t.Errorf("%s: BlastRadius = %d, want %d", a.Name, a.BlastRadius, w)
		}
	}
	if got := len(Starter()); got != len(want) {
		t.Errorf("Starter() returned %d actions, want %d", got, len(want))
	}
}

// TestStarter_AllCompileAsserts the starter Action values exposed
// through Starter() are independently validated (the package init
// already validates, but this guards against future refactors that
// might skip the init-time check).
func TestStarter_AllCompile(t *testing.T) {
	for _, a := range Starter() {
		if err := a.Validate(); err != nil {
			t.Errorf("starter action %q fails Validate: %v", a.Name, err)
		}
	}
}

// TestStarter_FreshCopyOnEachCall ensures Starter returns a freshly
// allocated slice so callers cannot mutate the package-level state by
// appending to the result.
func TestStarter_FreshCopyOnEachCall(t *testing.T) {
	a := Starter()
	b := Starter()
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("Starter() returned empty slice")
	}
	if &a[0] == &b[0] {
		t.Error("Starter() returned the same underlying array across calls; expected a fresh copy")
	}
}

// TestStarter_SchemasValidateAccepts asserts each starter action's
// compiled JSON-Schema accepts a minimal valid arguments object. This
// is the positive counterpart to TestCatalog_RejectsInvalidParams.
func TestStarter_SchemasValidateAccepts(t *testing.T) {
	cases := map[string]map[string]any{
		"isolate_endpoint": {
			"host_id": "abc-123",
		},
		"block_user_account": {
			"user_id": "alice@example.com",
		},
		"rotate_api_key": {
			"key_id": "key-42",
		},
		"submit_edr_query": {
			"query": "event_simpleName=ProcessRollup2",
		},
		"enrich_ioc": {
			"indicator":      "1.2.3.4",
			"indicator_type": "ipv4",
		},
	}
	c := New()
	for name, args := range cases {
		if err := c.Validate(name, args); err != nil {
			t.Errorf("Validate(%s, %v) = %v, want nil", name, args, err)
		}
	}
}

// TestNew_SeedsStarterActions confirms New() returns a Catalog
// containing exactly the five starter actions, keyed by name.
func TestNew_SeedsStarterActions(t *testing.T) {
	c := New()
	if got := len(c.Actions); got != 5 {
		t.Fatalf("New().Actions has %d entries, want 5", got)
	}
	for _, name := range starterNames() {
		if _, ok := c.Actions[name]; !ok {
			t.Errorf("New() catalog missing starter %q", name)
		}
	}
}
