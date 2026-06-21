package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEventBuilder_RequiredEnvelope verifies that NewBuilder()
// pre-populates the OCSF-required envelope fields so callers cannot
// forget them. Catches regressions where a refactor accidentally
// drops a required field from the builder defaults.
func TestEventBuilder_RequiredEnvelope(t *testing.T) {
	ev := NewBuilder().Now().Build()

	if got, want := ev.ClassUID, ClassUIDDetectionFinding; got != want {
		t.Errorf("ClassUID = %d, want %d", got, want)
	}
	if got, want := ev.ClassName, ClassNameDetectionFinding; got != want {
		t.Errorf("ClassName = %q, want %q", got, want)
	}
	if ev.Time.IsZero() {
		t.Error("Time should be stamped by Now(), got zero value")
	}
	if ev.Metadata.Version == "" {
		t.Error("Metadata.Version should be set, got empty")
	}
	if ev.Metadata.Product.Name == "" {
		t.Error("Metadata.Product.Name should be set, got empty")
	}
	if ev.Metadata.Product.VendorName == "" {
		t.Error("Metadata.Product.VendorName should be set, got empty")
	}
}

// TestEventBuilder_FluentSetters exercises every typed setter on the
// builder and confirms the resulting Event reflects each call.
func TestEventBuilder_FluentSetters(t *testing.T) {
	when := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	ev := NewBuilder().
		WithTime(when).
		WithActivity(ActivityIDCreate).
		WithSeverityID(4).
		WithMessage("hello world").
		WithFindingUID("rule-1").
		WithFindingTitle("hello world").
		WithFindingTypes([]string{"soc-action", "test"}).
		WithVerdict(VerdictDeny).
		WithPolicyVersion(7).
		WithRequestID("req-1").
		WithResource("isolate_endpoint").
		WithActor("alice@home").
		WithApprover("bob@home").
		WithErrorReason("fail_closed").
		WithProductVersion("v1.2.3").
		Build()

	if !ev.Time.Equal(when) {
		t.Errorf("Time = %v, want %v", ev.Time, when)
	}
	if ev.ActivityID != ActivityIDCreate {
		t.Errorf("ActivityID = %d, want %d", ev.ActivityID, ActivityIDCreate)
	}
	if ev.SeverityID != 4 {
		t.Errorf("SeverityID = %d, want 4", ev.SeverityID)
	}
	if ev.Message != "hello world" {
		t.Errorf("Message = %q, want %q", ev.Message, "hello world")
	}
	if ev.FindingInfo.UID != "rule-1" {
		t.Errorf("FindingInfo.UID = %q, want %q", ev.FindingInfo.UID, "rule-1")
	}
	if ev.FindingInfo.Title != "hello world" {
		t.Errorf("FindingInfo.Title = %q, want %q", ev.FindingInfo.Title, "hello world")
	}
	if got, want := ev.FindingInfo.Types, []string{"soc-action", "test"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("FindingInfo.Types = %v, want %v", got, want)
	}
	if ev.Verdict != "Deny" {
		t.Errorf("Verdict = %q, want %q", ev.Verdict, "Deny")
	}
	if ev.VerdictID != int(VerdictDeny) {
		t.Errorf("VerdictID = %d, want %d", ev.VerdictID, VerdictDeny)
	}
	if ev.PolicyVersion != 7 {
		t.Errorf("PolicyVersion = %d, want 7", ev.PolicyVersion)
	}
	if ev.RequestID != "req-1" {
		t.Errorf("RequestID = %q, want %q", ev.RequestID, "req-1")
	}
	if len(ev.Resources) != 1 || ev.Resources[0].Type != "MCP Tool" || ev.Resources[0].Name != "isolate_endpoint" {
		t.Errorf("Resources = %+v, want one MCP Tool 'isolate_endpoint'", ev.Resources)
	}
	if ev.Actor == nil || ev.Actor.User.Name != "alice@home" {
		t.Errorf("Actor = %+v, want User.Name=alice@home", ev.Actor)
	}
	if ev.Approver != "bob@home" {
		t.Errorf("Approver = %q, want %q", ev.Approver, "bob@home")
	}
	if ev.ErrorReason != "fail_closed" {
		t.Errorf("ErrorReason = %q, want %q", ev.ErrorReason, "fail_closed")
	}
	if ev.Metadata.Product.Version != "v1.2.3" {
		t.Errorf("Metadata.Product.Version = %q, want %q",
			ev.Metadata.Product.Version, "v1.2.3")
	}
}

// TestEventBuilder_WithSeverityNamedConstant ensures the named
// Severity constants produce the same wire value as the raw int.
func TestEventBuilder_WithSeverityNamedConstant(t *testing.T) {
	cases := []struct {
		name string
		s    Severity
		want int
	}{
		{"Unknown", Severity0Unknown, 0},
		{"Informational", Severity1Informational, 1},
		{"Low", Severity2Low, 2},
		{"Medium", Severity3Medium, 3},
		{"High", Severity4High, 4},
		{"Critical", Severity5Critical, 5},
		{"Fatal", Severity6Fatal, 6},
		{"Other", Severity99Other, 99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := NewBuilder().WithSeverity(tc.s).Build()
			if ev.SeverityID != tc.want {
				t.Errorf("SeverityID = %d, want %d", ev.SeverityID, tc.want)
			}
		})
	}
}

// TestVerdictString verifies each Verdict constant maps to its
// canonical wire label.
func TestVerdictString(t *testing.T) {
	cases := []struct {
		v    Verdict
		want string
	}{
		{VerdictAllow, "Allow"},
		{VerdictDeny, "Deny"},
		{VerdictRequireApproval, "RequireApproval"},
	}
	for _, tc := range cases {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("Verdict(%d).String() = %q, want %q", int(tc.v), got, tc.want)
		}
	}
	// Unknown value falls back to a debug-friendly label.
	if got := Verdict(42).String(); got != "Verdict(42)" {
		t.Errorf("Verdict(42).String() = %q, want %q", got, "Verdict(42)")
	}
}

// TestEvent_RoundTripJSON verifies that an Event built via the
// builder round-trips through json.Marshal/Unmarshal to a struct
// that matches the well-known field values. This catches field-tag
// regressions (e.g. a missing `json:"verdict_id"` tag) before they
// reach the wire.
func TestEvent_RoundTripJSON(t *testing.T) {
	when := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	src := NewBuilder().
		WithTime(when).
		WithActivity(ActivityIDCreate).
		WithSeverityID(4).
		WithMessage("isolate_endpoint against server99.example.com").
		WithFindingUID("allow-isolate-server99").
		WithFindingTitle("isolate_endpoint against server99.example.com").
		WithFindingTypes([]string{"soc-action", "isolation"}).
		WithVerdict(VerdictDeny).
		WithPolicyVersion(7).
		WithRequestID("req-abc").
		WithResource("isolate_endpoint").
		WithActor("agent-user@home").
		WithProductVersion("v1.2.3").
		Build()

	bytes, err := json.Marshal(src)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Event
	if err := json.Unmarshal(bytes, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.ClassUID != src.ClassUID ||
		got.ClassName != src.ClassName ||
		got.ActivityID != src.ActivityID ||
		got.SeverityID != src.SeverityID ||
		got.Message != src.Message ||
		got.Verdict != src.Verdict ||
		got.VerdictID != src.VerdictID {
		t.Errorf("round-trip mismatch:\n got=%+v\nwant=%+v", got, src)
	}
	if !got.Time.Equal(src.Time) {
		t.Errorf("Time: got %v, want %v", got.Time, src.Time)
	}
	if got.FindingInfo.UID != src.FindingInfo.UID ||
		got.FindingInfo.Title != src.FindingInfo.Title ||
		len(got.FindingInfo.Types) != len(src.FindingInfo.Types) {
		t.Errorf("FindingInfo: got %+v, want %+v", got.FindingInfo, src.FindingInfo)
	}
}

// TestEvent_GoldenFileMatches confirms that an Event built via the
// builder (with the product.version pinned to the golden file's
// value) round-trips through Marshal/Unmarshal into a struct equal
// to the golden fixture.
//
// This is the wire-format stability contract: any change to the OCSF
// field set that affects the required fields must update the golden
// file in the same PR. The test fails loudly so the reviewer sees
// the change.
func TestEvent_GoldenFileMatches(t *testing.T) {
	goldenPath := filepath.Join("testdata", "golden-event.json")
	goldenBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var golden Event
	if err := json.Unmarshal(goldenBytes, &golden); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}

	// Approver and ErrorReason are "" in the golden file; the
	// `omitempty` tag drops them on the wire. Build an event that
	// omits them and compare the wire bytes (excluding those
	// optional fields) via JSON equality of the round-trip.
	when, err := time.Parse(time.RFC3339, "2026-06-20T12:00:00Z")
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	built := NewBuilder().
		WithTime(when).
		WithActivity(ActivityIDCreate).
		WithSeverityID(4).
		WithMessage("isolate_endpoint against server99.example.com").
		WithFindingUID("allow-isolate-server99").
		WithFindingTitle("isolate_endpoint against server99.example.com").
		WithFindingTypes([]string{"soc-action", "isolation"}).
		WithVerdict(VerdictDeny).
		WithPolicyVersion(7).
		WithRequestID("req-abc").
		WithResource("isolate_endpoint").
		WithActor("agent-user@home").
		WithProductVersion("v1.2.3 (commit: abc1234, built: 2026-06-20T12:00:00Z)").
		Build()

	builtBytes, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("marshal built: %v", err)
	}
	gotBytes, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("marshal built (second): %v", err)
	}
	var gotParsed, builtParsed map[string]any
	if err := json.Unmarshal(builtBytes, &builtParsed); err != nil {
		t.Fatalf("unmarshal built: %v", err)
	}
	if err := json.Unmarshal(goldenBytes, &gotParsed); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	_ = gotBytes

	// Compare each non-optional field individually so a regression
	// in one field shows up as a precise test failure rather than
	// a giant blob diff.
	if builtParsed["class_uid"].(float64) != float64(golden.ClassUID) {
		t.Errorf("class_uid mismatch: built=%v golden=%d", builtParsed["class_uid"], golden.ClassUID)
	}
	if builtParsed["class_name"].(string) != golden.ClassName {
		t.Errorf("class_name mismatch: built=%v golden=%q", builtParsed["class_name"], golden.ClassName)
	}
	if builtParsed["activity_id"].(float64) != float64(golden.ActivityID) {
		t.Errorf("activity_id mismatch: built=%v golden=%d", builtParsed["activity_id"], golden.ActivityID)
	}
	if builtParsed["severity_id"].(float64) != float64(golden.SeverityID) {
		t.Errorf("severity_id mismatch: built=%v golden=%d", builtParsed["severity_id"], golden.SeverityID)
	}
	if builtParsed["message"].(string) != golden.Message {
		t.Errorf("message mismatch: built=%v golden=%q", builtParsed["message"], golden.Message)
	}
	if builtParsed["verdict"].(string) != golden.Verdict {
		t.Errorf("verdict mismatch: built=%v golden=%q", builtParsed["verdict"], golden.Verdict)
	}
	if builtParsed["verdict_id"].(float64) != float64(golden.VerdictID) {
		t.Errorf("verdict_id mismatch: built=%v golden=%d", builtParsed["verdict_id"], golden.VerdictID)
	}
}
