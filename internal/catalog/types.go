// Package catalog defines the typed SOC-action catalog consumed by the
// policy engine (U3) and the audit emitter (U5).
//
// A catalog entry describes one action the proxy understands: a stable
// name, human-readable description, JSON-schema for its input arguments,
// blast-radius score, and the OCSF Detection Finding audit shape the
// emitter (U5) will use when recording a policy decision about it.
//
// The starter catalog (R4) ships five built-in actions. Operators extend
// the catalog with custom actions via YAML (R6); the loader (loader.go)
// validates each custom action against the same JSON-schema contract
// before merging it with the starter set.
package catalog

import (
	"errors"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Blast-radius scoring is 1 (read) through 5 (system-impact). The score
// drives fail-closed vs. fail-open posture in U9 and surfaces in the
// OCSF audit record's severity_id (U5).
const (
	// BlastRadiusRead is a read-only action. No state change. Fails open
	// (per Plan R3 and AE6).
	BlastRadiusRead = 1
	// BlastRadiusMetadata modifies annotations only (tags, labels).
	// Reversible by definition.
	BlastRadiusMetadata = 2
	// BlastRadiusSoftAction is reversible state change (token rotation,
	// session revoke). Fails closed (per AE5).
	BlastRadiusSoftAction = 3
	// BlastRadiusUserImpact affects a user account or user-visible
	// resource (block, suspend). Fails closed.
	BlastRadiusUserImpact = 4
	// BlastRadiusSystemImpact affects a host, network segment, or
	// service-level resource (isolate, quarantine). Fails closed.
	BlastRadiusSystemImpact = 5
)

// Param describes one named input argument of a catalog Action. The
// Name and Type are what the agent sees; the JSON Schema (on the parent
// Action.InputSchema) is what the runtime validates arguments against.
type Param struct {
	// Name is the argument key the agent supplies in the JSON-RPC
	// arguments object. Must be a non-empty valid Go identifier-style
	// token because it is used as the JSON-Schema property key.
	Name string `yaml:"name"`

	// Type is the JSON-Schema type for this argument: "string",
	// "integer", "number", "boolean", "object", "array", or "null".
	// Surfaced for human readers; not consumed at runtime (the
	// JSON-Schema is the source of truth).
	Type string `yaml:"type"`

	// Description is one short sentence describing what the argument
	// is for. Surfaced in tools/list responses so agents can self-document.
	Description string `yaml:"description"`

	// Required, when true, marks the argument as required in the
	// generated JSON-Schema. Convenience over hand-writing the schema.
	Required bool `yaml:"required"`
}

// AuditShape is metadata describing the OCSF Detection Finding (UID
// 2004) record the audit emitter (U5) will produce for decisions about
// this action. It is intentionally a typed struct (not an any) so the
// catalog compiler can enforce that every action declares a complete
// audit shape and U5 can rely on the field set.
//
// The fields here are the OCSF attributes that vary per action; the
// common envelope (metadata, class_uid, activity_id, time) is stamped
// at emit time and does not need to be declared per action.
type AuditShape struct {
	// Title is a short human label used as the OCSF finding_info.title.
	// Example: "isolate_endpoint against {{.target}}". May reference
	// catalog placeholders; U5 expands them at emit time.
	Title string `yaml:"title"`

	// SeverityID is the OCSF severity_id (0=Unknown, 1=Informational,
	// 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal, 99=Other). The
	// starter catalog maps blast-radius 1->2, 2->2, 3->3, 4->4, 5->5;
	// U5 may override per policy decision.
	SeverityID int `yaml:"severity_id"`

	// Types are OCSF finding_info.types values. Conventionally
	// include "soc-action" plus action-class tags ("isolation",
	// "credential-rotation", etc.) for SIEM-side correlation.
	Types []string `yaml:"types"`
}

// Action is one entry in the SOC-action catalog. Five starter actions
// are defined in starter.go; operators may add more via loader.go.
//
// The InputSchema field is a compiled *jsonschema.Schema; callers use
// Validate to check an arguments object against it. The loader is
// responsible for compiling the user-supplied JSON-Schema text.
type Action struct {
	// Name is the stable identifier matched against MCP tool names.
	// Convention: snake_case verb_object. Used as the OCSF
	// resources[].name value at emit time.
	Name string `yaml:"name"`

	// Description is one or two sentences explaining what the action
	// does and when it should be used. Surfaced in tools/list and the
	// starter catalog doc.
	Description string `yaml:"description"`

	// Params documents the action's input arguments. The schema
	// compiler in loader.go converts this into the JSON-Schema's
	// properties and required lists.
	Params []Param `yaml:"params"`

	// BlastRadius is the 1-5 score driving posture (U9) and audit
	// severity. Validated by Validate against the BlastRadius*
	// constants above.
	BlastRadius int `yaml:"blast_radius"`

	// OCSFAuditShape declares the per-action OCSF fields. Required;
	// the catalog rejects actions that leave it empty.
	OCSFAuditShape AuditShape `yaml:"ocsf_audit_shape"`

	// PrimaryArg is the name of the argument that carries the
	// action's "target" — the high-cardinality identifier the policy
	// engine matches against Rule.Targets (host_id for
	// isolate_endpoint, user_id for block_user_account, etc.).
	//
	// When set, the proxy extracts args[PrimaryArg] as the policy
	// engine's Target field. When unset (empty string), the proxy
	// falls back to its name-based heuristic AND emits a startup
	// warning so operators know the action is ungoverned.
	//
	// This per-action declaration defends against bypass attacks
	// where a malicious agent puts the actual target in a
	// non-canonical argument name (e.g. `subject` instead of
	// `host_id`) to evade target-restricted allow rules. With
	// PrimaryArg declared in the catalog, the proxy looks at exactly
	// the right argument and cannot be steered.
	PrimaryArg string `yaml:"primary_arg,omitempty"`

	// InputSchema is the compiled JSON-Schema used at runtime to
	// validate an agent's arguments object. Loaded by loader.go from
	// the RawSchema bytes; starter actions populate it directly in
	// starter.go. May be nil if Validate is not called; Validate itself
	// will fail.
	InputSchema *jsonschema.Schema `yaml:"-"`

	// RawSchema is the original JSON-Schema text (for diagnostics and
	// re-loading). nil for starter actions whose schema is compiled
	// inline.
	RawSchema []byte `yaml:"-"`
}

// Validate enforces field-level constraints on an Action. Called by
// loader.go for custom actions and by starter.go at init time as a
// guard against accidental drift.
//
// Blast radius must be in 1..5; Name must be non-empty; SeverityID must
// be in the OCSF-defined set; at least one Type must be declared; and
// InputSchema must be non-nil so the runtime validator has something
// to validate against.
func (a *Action) Validate() error {
	if a.Name == "" {
		return errors.New("action.name is required")
	}
	if a.BlastRadius < BlastRadiusRead || a.BlastRadius > BlastRadiusSystemImpact {
		return fmt.Errorf("action %q: blast_radius %d outside [%d,%d]",
			a.Name, a.BlastRadius, BlastRadiusRead, BlastRadiusSystemImpact)
	}
	if a.InputSchema == nil {
		return fmt.Errorf("action %q: input_schema is required", a.Name)
	}
	if a.OCSFAuditShape.Title == "" {
		return fmt.Errorf("action %q: ocsf_audit_shape.title is required", a.Name)
	}
	if !validSeverity(a.OCSFAuditShape.SeverityID) {
		return fmt.Errorf("action %q: ocsf_audit_shape.severity_id %d is not a valid OCSF severity",
			a.Name, a.OCSFAuditShape.SeverityID)
	}
	if len(a.OCSFAuditShape.Types) == 0 {
		return fmt.Errorf("action %q: ocsf_audit_shape.types must list at least one tag", a.Name)
	}
	if a.PrimaryArg != "" {
		// PrimaryArg must reference a declared Param so the
		// proxy can extract the target reliably. A typo
		// (e.g. "hostid" vs "host_id") would silently fall
		// through to the name-based heuristic and defeat the
		// per-action target declaration.
		found := false
		for _, p := range a.Params {
			if p.Name == a.PrimaryArg {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("action %q: primary_arg %q does not reference a declared param",
				a.Name, a.PrimaryArg)
		}
	}
	return nil
}

// validSeverity returns true for OCSF-defined severity_id values
// (0=Unknown, 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical,
// 6=Fatal, 99=Other).
func validSeverity(id int) bool {
	switch id {
	case 0, 1, 2, 3, 4, 5, 6, 99:
		return true
	default:
		return false
	}
}
