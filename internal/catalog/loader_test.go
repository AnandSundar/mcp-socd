package catalog

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// TestCatalog_LoadsCustomAction loads the custom-action fixture and
// asserts the resulting catalog entry is fully typed and validates.
// Scenario 2 of 4 per the task brief.
func TestCatalog_LoadsCustomAction(t *testing.T) {
	c := New()
	if err := c.LoadCustomFile(filepath.Join("testdata", "custom-action.yaml")); err != nil {
		t.Fatalf("LoadCustomFile: %v", err)
	}

	a, ok := c.Get("quarantine_mailbox")
	if !ok {
		t.Fatal("catalog missing quarantine_mailbox after load")
	}
	if a.Description == "" {
		t.Error("custom action has empty description")
	}
	if a.BlastRadius != 4 {
		t.Errorf("BlastRadius = %d, want 4", a.BlastRadius)
	}
	if len(a.Params) != 2 {
		t.Errorf("len(Params) = %d, want 2", len(a.Params))
	}
	if a.InputSchema == nil {
		t.Error("custom action has nil InputSchema")
	}
	if a.OCSFAuditShape.Title == "" {
		t.Error("custom action has empty audit title")
	}
	if len(a.OCSFAuditShape.Types) == 0 {
		t.Error("custom action has no audit types")
	}
	if !containsString(a.OCSFAuditShape.Types, "soc-action") {
		t.Errorf("audit types missing soc-action: %v", a.OCSFAuditShape.Types)
	}

	// Schema must accept valid input.
	if err := c.Validate("quarantine_mailbox", map[string]any{
		"user_email":     "alice@example.com",
		"duration_hours": 24,
	}); err != nil {
		t.Errorf("valid custom args rejected: %v", err)
	}

	// Schema must reject invalid input (bad duration).
	err := c.Validate("quarantine_mailbox", map[string]any{
		"user_email":     "alice@example.com",
		"duration_hours": 0,
	})
	if err == nil {
		t.Error("expected schema violation for duration_hours=0, got nil")
	} else if !errors.Is(err, ErrSchemaViolation) {
		t.Errorf("expected ErrSchemaViolation, got: %v", err)
	}
}

// TestLoadCustom_MultiActionDocument asserts the loader handles the
// multi-action YAML shape (`actions:` list at top level).
func TestLoadCustom_MultiActionDocument(t *testing.T) {
	doc := []byte(`
actions:
  - name: action_alpha
    description: First custom action.
    params:
      - name: target
        type: string
        description: Target.
        required: true
    blast_radius: 3
    ocsf_audit_shape:
      title: action_alpha against {{.target}}
      severity_id: 3
      types: [soc-action]
    input_schema: |
      {"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}
  - name: action_beta
    description: Second custom action.
    params:
      - name: target
        type: string
        description: Target.
        required: true
    blast_radius: 1
    ocsf_audit_shape:
      title: action_beta
      severity_id: 1
      types: [soc-action]
    input_schema: |
      {"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}
`)
	c := New()
	if err := c.LoadCustomBytes(doc); err != nil {
		t.Fatalf("LoadCustomBytes: %v", err)
	}
	if _, ok := c.Get("action_alpha"); !ok {
		t.Error("catalog missing action_alpha after multi-action load")
	}
	if _, ok := c.Get("action_beta"); !ok {
		t.Error("catalog missing action_beta after multi-action load")
	}
	if got := len(c.Actions); got != 7 { // 5 starter + 2 custom
		t.Errorf("len(Actions) = %d, want 7", got)
	}
}

// TestLoadCustom_RejectsCollision asserts that loading a custom action
// whose name matches an existing one fails with ErrActionExists rather
// than silently overwriting.
func TestLoadCustom_RejectsCollision(t *testing.T) {
	doc := []byte(`
name: isolate_endpoint
description: Custom override that should be rejected.
blast_radius: 5
ocsf_audit_shape:
  title: x
  severity_id: 5
  types: [soc-action]
input_schema: |
  {"type":"object"}
`)
	c := New()
	err := c.LoadCustomBytes(doc)
	if err == nil {
		t.Fatal("expected collision error, got nil")
	}
	if !errors.Is(err, ErrActionExists) {
		t.Errorf("expected ErrActionExists, got: %v", err)
	}
}

// TestLoadCustom_RejectsInvalidSchema asserts a malformed JSON-Schema
// is reported as a clear load error rather than a runtime panic.
func TestLoadCustom_RejectsInvalidSchema(t *testing.T) {
	doc := []byte(`
name: bad_schema_action
description: An action with a broken schema.
blast_radius: 3
ocsf_audit_shape:
  title: x
  severity_id: 3
  types: [soc-action]
input_schema: |
  {"type":"not-a-real-type"}
`)
	c := New()
	err := c.LoadCustomBytes(doc)
	if err == nil {
		t.Fatal("expected error for invalid JSON-Schema, got nil")
	}
	if !strings.Contains(err.Error(), "bad_schema_action") {
		t.Errorf("error %q should mention the offending action name", err)
	}
}

// TestLoadCustom_RejectsMissingInputSchema asserts an action without
// input_schema is rejected (cannot validate arguments at runtime).
func TestLoadCustom_RejectsMissingInputSchema(t *testing.T) {
	doc := []byte(`
name: schemaless_action
description: Missing input_schema.
blast_radius: 3
ocsf_audit_shape:
  title: x
  severity_id: 3
  types: [soc-action]
`)
	c := New()
	err := c.LoadCustomBytes(doc)
	if err == nil {
		t.Fatal("expected error for missing input_schema, got nil")
	}
	if !strings.Contains(err.Error(), "input_schema") {
		t.Errorf("error %q should mention input_schema", err)
	}
}

// TestLoadCustom_RejectsOutOfRangeBlastRadius asserts an action with
// blast_radius outside [1,5] is rejected.
func TestLoadCustom_RejectsOutOfRangeBlastRadius(t *testing.T) {
	doc := []byte(`
name: out_of_range
description: blast_radius too high.
blast_radius: 9
ocsf_audit_shape:
  title: x
  severity_id: 5
  types: [soc-action]
input_schema: |
  {"type":"object"}
`)
	c := New()
	err := c.LoadCustomBytes(doc)
	if err == nil {
		t.Fatal("expected error for blast_radius=9, got nil")
	}
	if !strings.Contains(err.Error(), "blast_radius") {
		t.Errorf("error %q should mention blast_radius", err)
	}
}

// TestLoadCustom_EmptyDocument asserts a custom document declaring no
// actions yields a clear error rather than silent success.
func TestLoadCustom_EmptyDocument(t *testing.T) {
	c := New()
	if err := c.LoadCustomBytes([]byte("---\n")); err == nil {
		t.Fatal("expected error for empty document, got nil")
	}
}

// TestRemove_RemovesAction asserts Remove deletes the entry and
// returns ErrActionNotFound when the name is unknown.
func TestRemove_RemovesAction(t *testing.T) {
	c := New()
	if err := c.Remove("quarantine_mailbox_does_not_exist"); err == nil {
		t.Fatal("expected error for unknown action, got nil")
	} else if !errors.Is(err, ErrActionNotFound) {
		t.Errorf("expected ErrActionNotFound, got: %v", err)
	}

	// Load a custom action and remove it.
	if err := c.LoadCustomFile(filepath.Join("testdata", "custom-action.yaml")); err != nil {
		t.Fatalf("LoadCustomFile: %v", err)
	}
	if _, ok := c.Get("quarantine_mailbox"); !ok {
		t.Fatal("custom action did not load")
	}
	if err := c.Remove("quarantine_mailbox"); err != nil {
		t.Errorf("Remove: %v", err)
	}
	if _, ok := c.Get("quarantine_mailbox"); ok {
		t.Error("Remove did not delete the action")
	}
}

// TestLoadCustom_FileNotFound asserts the file path error wraps the
// underlying os.ReadFile error and is surfaced verbatim.
func TestLoadCustom_FileNotFound(t *testing.T) {
	c := New()
	err := c.LoadCustomFile(filepath.Join("testdata", "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "does-not-exist.yaml") {
		t.Errorf("error %q should include the missing path", err)
	}
}

// containsString is a tiny helper to keep the test file free of the
// slices.Contains import.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
