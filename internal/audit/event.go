// Package audit implements the OCSF Detection Finding (UID 2004)
// audit emitter for mcp-socd. See Plan §U5 and §KTD4.
//
// The emitter writes one JSON object per line (JSON-lines) to a
// configurable set of sinks: stderr (the default, so MCP stdout stays
// pure), opt-in stdout, and an optional file with fsync-after-every-
// write semantics per Plan R11.
//
// Records are hand-rolled with encoding/json (no OCSF library) per
// Plan KTD5: the records are well-defined, the Go OCSF ecosystem is
// immature, and explicit struct fields let us control which optional
// attributes appear in the wire format.
package audit

import (
	"fmt"
	"time"
)

// OCSF class and activity identifiers used by this package. They are
// defined as constants so tests and external callers (the proxy in U4,
// the approval workflow in U6) can reference them by name instead of
// repeating magic numbers.
const (
	// ClassUIDDetectionFinding is the OCSF class UID for a Detection
	// Finding record (OCSF v1.2+).
	ClassUIDDetectionFinding = 2004

	// ClassNameDetectionFinding is the human-readable class name
	// matching ClassUIDDetectionFinding.
	ClassNameDetectionFinding = "Detection Finding"

	// ActivityIDOther is the OCSF activity_id used for heartbeat
	// events (no decision was made, just a liveness signal).
	ActivityIDOther = 0

	// ActivityIDCreate is the OCSF activity_id used for a policy
	// decision on a tool call: a new detection finding is being
	// recorded.
	ActivityIDCreate = 1

	// SeverityIDUnknown marks a finding whose severity is not yet
	// classified (OCSF value 99).
	SeverityIDUnknown = 99
)

// Severity is the OCSF severity_id (0..6 plus 99 for Unknown).
// Values map directly to the OCSF Detection Finding severity_id enum:
//
//	0 = Unknown, 1 = Informational, 2 = Low, 3 = Medium, 4 = High,
//	5 = Critical, 6 = Fatal, 99 = Other.
//
// The catalog (U2) is responsible for translating blast-radius scores
// into one of these values; the audit emitter passes the chosen value
// through unchanged.
type Severity int

// Severity constants for the well-known OCSF severity levels. Use
// these instead of raw integers at call sites.
const (
	Severity0Unknown       Severity = 0
	Severity1Informational Severity = 1
	Severity2Low           Severity = 2
	Severity3Medium        Severity = 3
	Severity4High          Severity = 4
	Severity5Critical      Severity = 5
	Severity6Fatal         Severity = 6
	Severity99Other        Severity = 99
)

// Verdict is the outcome of a policy decision as recorded in the
// audit record. Values are vendored extensions of the OCSF Detection
// Finding verdict_id enum (see Plan §KTD4):
//
//	1 = Allow           — the call was forwarded to the upstream MCP server.
//	2 = Deny            — the call was blocked before reaching the upstream.
//	3 = RequireApproval — the call is awaiting out-of-band approval.
//
// The numeric verdict_id values are stable wire format and must not be
// renumbered; downstream SIEM rules key off them.
type Verdict int

// Verdict constants. Use these instead of raw integers at call sites.
const (
	// VerdictAllow maps to verdict_id 1 ("Allow"). The call was
	// forwarded to the upstream MCP server.
	VerdictAllow Verdict = 1

	// VerdictDeny maps to verdict_id 2 ("Deny"). The call was blocked
	// before reaching the upstream.
	VerdictDeny Verdict = 2

	// VerdictRequireApproval maps to verdict_id 3 ("RequireApproval").
	// The call is held pending out-of-band approval; a follow-up
	// audit event will record the final disposition.
	VerdictRequireApproval Verdict = 3
)

// String returns the canonical verdict label used in the OCSF verdict
// field. Stable wire format; do not rename.
func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "Allow"
	case VerdictDeny:
		return "Deny"
	case VerdictRequireApproval:
		return "RequireApproval"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

// Event is a single OCSF Detection Finding (UID 2004) audit record.
// Field tags use omitempty for optional attributes so the wire format
// stays compact when callers do not populate them; the required
// fields (class_uid, class_name, activity_id, time, severity_id,
// message, metadata.product, verdict, verdict_id) are always emitted.
//
// The struct is intentionally flat for the required OCSF fields and
// embeds typed sub-objects for the richer OCSF groupings
// (finding_info, metadata, resources). Callers build events via
// EventBuilder rather than constructing Event literals directly so
// the required fields cannot be forgotten.
type Event struct {
	// class_uid — OCSF class identifier. Always 2004 (Detection
	// Finding). Emitted as "class_uid" in the JSON record.
	ClassUID int `json:"class_uid"`

	// class_name — human-readable class name. Always "Detection
	// Finding". Emitted as "class_name".
	ClassName string `json:"class_name"`

	// activity_id — OCSF activity identifier within the class.
	// 1 (Create) for tool-call decisions, 0 (Other) for heartbeats.
	ActivityID int `json:"activity_id"`

	// time — event timestamp in RFC3339 UTC. Stamp at build time via
	// EventBuilder.Now; the emitter does not overwrite it.
	Time time.Time `json:"time"`

	// metadata — OCSF envelope. The product block identifies the
	// emitter so SIEM-side rules can route on it.
	Metadata Metadata `json:"metadata"`

	// severity_id — OCSF severity (0..6, 99). Sourced from the
	// catalog's AuditShape.SeverityID or overridden by policy.
	SeverityID int `json:"severity_id"`

	// message — short human label, typically the OCSF finding_info.title
	// from the catalog with placeholders expanded.
	Message string `json:"message"`

	// finding_info — OCSF finding_info block. UID is the policy rule
	// ID; types are the action-class tags from the catalog.
	FindingInfo FindingInfo `json:"finding_info"`

	// verdict — human-readable verdict label ("Allow", "Deny",
	// "RequireApproval"). Mirrors verdict_id for human readers.
	Verdict string `json:"verdict"`

	// verdict_id — numeric verdict. Stable wire format; SIEM rules
	// key off this field.
	VerdictID int `json:"verdict_id"`

	// policy_version — version of the policy that produced this
	// decision. Optional; omitted when the caller did not supply it.
	PolicyVersion int `json:"policy_version,omitempty"`

	// request_id — JSON-RPC request id, when available. Optional;
	// omitted for heartbeat events.
	RequestID string `json:"request_id,omitempty"`

	// resources — list of resources involved in the decision
	// (typically the MCP tool name). Optional.
	Resources []Resource `json:"resources,omitempty"`

	// actor — who triggered the call (typically the agent identity).
	// Optional.
	Actor *Actor `json:"actor,omitempty"`

	// approver — populated when an approval workflow recorded who
	// approved/denied the request. Optional.
	Approver string `json:"approver,omitempty"`

	// error_reason — populated when this event records a failure
	// (e.g. fsync failure, schema rejection). Optional.
	ErrorReason string `json:"error_reason,omitempty"`
}

// Metadata is the OCSF metadata envelope. The product block is the
// only required sub-object per the OCSF spec; the version string is
// the schema version this record conforms to.
type Metadata struct {
	// Version is the OCSF schema version this record conforms to.
	// Hard-coded to "1.2.0" until we move to a newer OCSF release.
	Version string `json:"version"`

	// Product identifies the emitting software. The audit emitter
	// fills Name and VendorName with "mcp-socd" and Version with the
	// value from internal/version.
	Product Product `json:"product"`
}

// Product identifies the emitting software in the OCSF metadata
// envelope. VendorName is required by OCSF even though it duplicates
// Name for our project.
type Product struct {
	// Name is the short product name. Always "mcp-socd".
	Name string `json:"name"`

	// VendorName is the vendor / maintainer. Always "mcp-socd"
	// (single-vendor project).
	VendorName string `json:"vendor_name"`

	// Version is the build-time version string from internal/version.
	Version string `json:"version"`
}

// FindingInfo is the OCSF finding_info block. UID is the policy rule
// ID (or a synthetic heartbeat ID for liveness events); types are
// the action-class tags.
type FindingInfo struct {
	// UID is a stable identifier for the finding. For policy
	// decisions this is the rule ID; for heartbeats it is a
	// synthetic "heartbeat-<unix>" string.
	UID string `json:"uid"`

	// Title is the human-readable finding title. Mirrors the Event
	// Message field for convenience.
	Title string `json:"title"`

	// Types are OCSF finding_info.types values. Conventionally
	// include "soc-action" plus action-class tags.
	Types []string `json:"types"`
}

// Resource describes one resource involved in the policy decision.
// The OCSF spec allows several type values; "MCP Tool" is the
// vendor-specific value used here.
type Resource struct {
	// Type is the OCSF resource type. Always "MCP Tool" for now.
	Type string `json:"type"`

	// Name is the resource name (MCP tool name).
	Name string `json:"name"`
}

// Actor identifies who triggered the policy decision. Only the User
// sub-field is populated; group/role attributes can be added when
// the catalog/agent-identity work lands.
type Actor struct {
	// User is the user (agent) identity. May be empty for heartbeat
	// events.
	User User `json:"user"`
}

// User is the OCSF user object nested under Actor. Name is the
// free-form identifier; UID is reserved for future stable IDs.
type User struct {
	// Name is the agent's human-readable identity string.
	Name string `json:"name,omitempty"`

	// UID is reserved for a future stable identifier (e.g. SPIFFE).
	// Omitted from the wire format until populated.
	UID string `json:"uid,omitempty"`
}

// EventBuilder constructs Event values fluently. Use NewBuilder for
// a minimal event (class_uid, class_name, time, metadata.product
// pre-populated) and chain the typed setters to fill in the rest.
//
// The builder pattern exists so call sites cannot forget the
// required fields and so the wire format stays stable across the
// project — every emitter path goes through this single
// construction site.
type EventBuilder struct {
	// now is the timestamp stamped into the event. Set by Now(); the
	// builder does not overwrite it if the caller already set Time
	// explicitly via the WithTime setter.
	now time.Time

	// ev is the working event. Built up by the setters; Build
	// performs the final validation.
	ev Event
}

// NewBuilder returns an EventBuilder pre-populated with the required
// envelope fields: class_uid=2004, class_name="Detection Finding",
// metadata.version="1.2.0", metadata.product populated from the
// static emitter identity. Callers chain setters to add the
// per-decision fields and then call Build.
func NewBuilder() *EventBuilder {
	b := &EventBuilder{
		ev: Event{
			ClassUID:  ClassUIDDetectionFinding,
			ClassName: ClassNameDetectionFinding,
			Metadata: Metadata{
				Version: "1.2.0",
				Product: Product{
					Name:       "mcp-socd",
					VendorName: "mcp-socd",
					Version:    "dev",
				},
			},
		},
	}
	return b
}

// Now stamps the event with the current time in UTC. Returns the
// builder so callers can chain setters and finish with Build.
//
// Callers that need a deterministic timestamp (tests, replays) should
// use WithTime instead.
func (b *EventBuilder) Now() *EventBuilder {
	b.now = time.Now().UTC()
	return b
}

// WithTime stamps the event with the given timestamp. Returns the
// builder for chaining. The time is stored as-supplied; the emitter
// does not convert time zones.
func (b *EventBuilder) WithTime(t time.Time) *EventBuilder {
	b.now = t
	return b
}

// WithActivity sets activity_id. Use ActivityIDCreate (1) for policy
// decisions and ActivityIDOther (0) for heartbeats.
func (b *EventBuilder) WithActivity(id int) *EventBuilder {
	b.ev.ActivityID = id
	return b
}

// WithSeverity sets severity_id from the OCSF severity enum.
// Accepts the named Severity constants or a raw int that has already
// been validated by the catalog.
func (b *EventBuilder) WithSeverity(s Severity) *EventBuilder {
	b.ev.SeverityID = int(s)
	return b
}

// WithSeverityID sets severity_id from a raw int. Provided so
// callers that already have a validated int (the catalog stamps
// AuditShape.SeverityID as int) do not have to cast.
func (b *EventBuilder) WithSeverityID(id int) *EventBuilder {
	b.ev.SeverityID = id
	return b
}

// WithMessage sets the short human-readable message. Typically
// populated from the catalog's AuditShape.Title with any
// placeholders expanded.
func (b *EventBuilder) WithMessage(msg string) *EventBuilder {
	b.ev.Message = msg
	return b
}

// WithFindingUID sets the finding UID (typically the policy rule
// ID; for heartbeats a synthetic "heartbeat-<unix>" string).
func (b *EventBuilder) WithFindingUID(uid string) *EventBuilder {
	b.ev.FindingInfo.UID = uid
	return b
}

// WithFindingTitle sets the finding_info.title. Usually mirrors the
// message; the OCSF spec allows them to diverge.
func (b *EventBuilder) WithFindingTitle(title string) *EventBuilder {
	b.ev.FindingInfo.Title = title
	return b
}

// WithFindingTypes sets finding_info.types. The slice is stored as
// supplied; the emitter does not deduplicate.
func (b *EventBuilder) WithFindingTypes(types []string) *EventBuilder {
	b.ev.FindingInfo.Types = types
	return b
}

// WithVerdict stamps the verdict label and verdict_id. The string
// label is derived from the enum so it cannot drift from the int.
func (b *EventBuilder) WithVerdict(v Verdict) *EventBuilder {
	b.ev.Verdict = v.String()
	b.ev.VerdictID = int(v)
	return b
}

// WithPolicyVersion stamps the policy version that produced this
// decision. 0 is omitted from the wire format.
func (b *EventBuilder) WithPolicyVersion(v int) *EventBuilder {
	b.ev.PolicyVersion = v
	return b
}

// WithRequestID stamps the JSON-RPC request id. Heartbeat events
// leave this empty.
func (b *EventBuilder) WithRequestID(id string) *EventBuilder {
	b.ev.RequestID = id
	return b
}

// WithResource appends one MCP tool reference to the resources
// block. Call once per tool involved in the decision.
func (b *EventBuilder) WithResource(toolName string) *EventBuilder {
	b.ev.Resources = append(b.ev.Resources, Resource{
		Type: "MCP Tool",
		Name: toolName,
	})
	return b
}

// WithActor sets the actor (agent identity). Pass an empty string
// for heartbeat events.
func (b *EventBuilder) WithActor(agentID string) *EventBuilder {
	b.ev.Actor = &Actor{User: User{Name: agentID}}
	return b
}

// WithApprover stamps the approver identity recorded by the
// approval workflow.
func (b *EventBuilder) WithApprover(id string) *EventBuilder {
	b.ev.Approver = id
	return b
}

// WithErrorReason stamps a structured error reason, used when this
// event records a failure rather than a clean policy decision.
func (b *EventBuilder) WithErrorReason(reason string) *EventBuilder {
	b.ev.ErrorReason = reason
	return b
}

// WithProductVersion overrides metadata.product.version. The audit
// emitter calls this from Emitter.Emit with internal/version.String()
// so the version stamped at emit time reflects the build.
func (b *EventBuilder) WithProductVersion(v string) *EventBuilder {
	b.ev.Metadata.Product.Version = v
	return b
}

// Build finalizes the event. It stamps the time recorded by Now or
// WithTime (falling back to time.Now().UTC() if neither was called)
// and returns the populated Event value. Build does not mutate the
// builder so a single builder can be reused for multiple events if
// the caller really wants to — but the common pattern is one
// builder per Emit call.
func (b *EventBuilder) Build() Event {
	ev := b.ev
	if b.now.IsZero() {
		ev.Time = time.Now().UTC()
	} else {
		ev.Time = b.now
	}
	return ev
}
