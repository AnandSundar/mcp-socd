package catalog

import (
	"errors"
	"strings"
	"testing"
)

// TestStarterCatalog_HasFiveActions asserts the starter catalog ships
// exactly the five actions required by R4 and that each is fully typed
// (non-empty Description, non-empty Params documentation, compiled
// InputSchema, non-empty AuditShape). Per the task brief this is
// scenario 1 of 4.
func TestStarterCatalog_HasFiveActions(t *testing.T) {
	actions := Starter()
	if got, want := len(actions), 5; got != want {
		t.Fatalf("Starter() returned %d actions, want %d", got, want)
	}

	wantNames := map[string]struct {
		params int
		radius int
	}{
		"isolate_endpoint":   {params: 2, radius: BlastRadiusSystemImpact},
		"block_user_account": {params: 2, radius: BlastRadiusUserImpact},
		"rotate_api_key":     {params: 2, radius: BlastRadiusSoftAction},
		"submit_edr_query":   {params: 3, radius: BlastRadiusRead},
		"enrich_ioc":         {params: 2, radius: BlastRadiusRead},
	}

	gotNames := map[string]bool{}
	for _, a := range actions {
		gotNames[a.Name] = true
		if a.Description == "" {
			t.Errorf("action %q has empty description", a.Name)
		}
		if len(a.Params) == 0 {
			t.Errorf("action %q has no params documented", a.Name)
		}
		if a.InputSchema == nil {
			t.Errorf("action %q has no compiled InputSchema", a.Name)
		}
		if a.OCSFAuditShape.Title == "" {
			t.Errorf("action %q has empty audit title", a.Name)
		}
		if len(a.OCSFAuditShape.Types) == 0 {
			t.Errorf("action %q has no audit types", a.Name)
		}
	}

	for name, want := range wantNames {
		if !gotNames[name] {
			t.Errorf("starter catalog missing action %q", name)
			continue
		}
		// Find the action and check its typed shape.
		var found Action
		for _, a := range actions {
			if a.Name == name {
				found = a
				break
			}
		}
		if got, wantParams := len(found.Params), want.params; got != wantParams {
			t.Errorf("%s: len(Params) = %d, want %d", name, got, wantParams)
		}
		if got, wantRadius := found.BlastRadius, want.radius; got != wantRadius {
			t.Errorf("%s: BlastRadius = %d, want %d", name, got, wantRadius)
		}
	}
}

// TestBlastRadius_ScoresAllInRange asserts every starter action's
// blast-radius falls within the documented 1..5 scale. Scenario 4 of 4
// per the task brief.
func TestBlastRadius_ScoresAllInRange(t *testing.T) {
	for _, a := range Starter() {
		if a.BlastRadius < BlastRadiusRead || a.BlastRadius > BlastRadiusSystemImpact {
			t.Errorf("action %q: blast_radius %d outside [%d,%d]",
				a.Name, a.BlastRadius, BlastRadiusRead, BlastRadiusSystemImpact)
		}
	}
}

// TestCatalog_RejectsInvalidParams asserts Validate returns a
// schema-violation error when the agent supplies arguments that fail
// the action's JSON-Schema. Scenario 3 of 4 per the task brief.
func TestCatalog_RejectsInvalidParams(t *testing.T) {
	c := New()

	// isolate_endpoint requires a non-empty host_id. Missing host_id
	// violates the schema's required list.
	err := c.Validate("isolate_endpoint", map[string]any{
		"comment": "no host supplied",
	})
	if err == nil {
		t.Fatal("expected schema violation for missing host_id, got nil")
	}
	if !errors.Is(err, ErrSchemaViolation) {
		t.Errorf("expected ErrSchemaViolation, got: %v", err)
	}
	// Error message should mention the offending field so operators
	// can diagnose. The library formats as "/host_id: ...".
	if !strings.Contains(err.Error(), "host_id") {
		t.Errorf("error %q should mention offending field host_id", err)
	}

	// submit_edr_query requires query; passing wrong type also fails.
	err = c.Validate("submit_edr_query", map[string]any{
		"query": 42, // should be string
	})
	if err == nil {
		t.Fatal("expected schema violation for wrong query type, got nil")
	}
	if !errors.Is(err, ErrSchemaViolation) {
		t.Errorf("expected ErrSchemaViolation, got: %v", err)
	}

	// enrich_ioc requires indicator_type to be in the enum.
	err = c.Validate("enrich_ioc", map[string]any{
		"indicator":      "1.2.3.4",
		"indicator_type": "garbage",
	})
	if err == nil {
		t.Fatal("expected schema violation for bad enum value, got nil")
	}
	if !errors.Is(err, ErrSchemaViolation) {
		t.Errorf("expected ErrSchemaViolation, got: %v", err)
	}

	// Unknown action returns ErrActionNotFound, not a schema violation.
	err = c.Validate("does_not_exist", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown action, got nil")
	}
	if errors.Is(err, ErrSchemaViolation) {
		t.Errorf("unknown action should not surface as schema violation: %v", err)
	}
	if !errors.Is(err, ErrActionNotFound) {
		t.Errorf("unknown action should wrap ErrActionNotFound, got: %v", err)
	}
}
