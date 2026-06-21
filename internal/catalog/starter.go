package catalog

import (
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// schemaCompiler is the shared JSON-Schema compiler used to turn
// in-line schemas (for starter actions) and user-supplied schemas (for
// custom actions) into compiled *jsonschema.Schema values. It is
// package-private because callers should not need to compile their own
// schemas; loader.go and starter.go own the compile step.
//
// santhosh-tekuri/jsonschema/v5 was chosen over gojsonschema for two
// reasons: it supports draft 2020-12 (the latest stable JSON-Schema
// version), and per its README benchmarks it compiles and validates
// noticeably faster on the kind of small per-action schemas we use.
var schemaCompiler = jsonschema.NewCompiler()

// Starter returns the five starter SOC actions required by R4. The
// returned slice is freshly allocated on each call so callers may
// safely mutate it without affecting subsequent calls. The Action
// values themselves share their compiled InputSchema across calls so
// the per-call cost is the slice and struct copies only.
//
// The blast-radius mapping is fixed per the task brief:
//   - submit_edr_query   -> 1 (read)
//   - enrich_ioc         -> 1 (read)
//   - rotate_api_key     -> 3 (soft-action, reversible)
//   - block_user_account -> 4 (user-impact)
//   - isolate_endpoint   -> 5 (system-impact)
func Starter() []Action {
	srcs := []Action{
		starterIsolateEndpoint(),
		starterBlockUserAccount(),
		starterRotateAPIKey(),
		starterSubmitEDRQuery(),
		starterEnrichIOC(),
	}
	out := make([]Action, len(srcs))
	copy(out, srcs)
	return out
}

// starterIsolateEndpoint describes host isolation against the EDR
// backend. Highest blast-radius (5, system-impact): disconnects a host
// from the network. Always fails closed; require_approval is the only
// sane posture.
func starterIsolateEndpoint() Action {
	schema := mustCompileSchema("isolate_endpoint", `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"host_id": {"type": "string", "minLength": 1},
			"comment": {"type": "string"}
		},
		"required": ["host_id"]
	}`)
	return Action{
		Name:        "isolate_endpoint",
		Description: "Disconnect a host from the network via the EDR backend. Highest blast-radius: disconnects a host from the network.",
		Params: []Param{
			{Name: "host_id", Type: "string", Description: "EDR host identifier (e.g. CrowdStrike device ID).", Required: true},
			{Name: "comment", Type: "string", Description: "Free-text justification recorded in the audit event."},
		},
		BlastRadius: BlastRadiusSystemImpact,
		OCSFAuditShape: AuditShape{
			Title:      "isolate_endpoint against {{.target}}",
			SeverityID: 5, // Critical
			Types:      []string{"soc-action", "isolation"},
		},
		InputSchema: schema,
		PrimaryArg: "host_id",
	}
}

// starterBlockUserAccount describes identity-level user blocking. Blast
// radius 4 (user-impact): a blocked user cannot authenticate. Reversible
// via the unblock action (separate action, not in the starter set).
func starterBlockUserAccount() Action {
	schema := mustCompileSchema("block_user_account", `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"user_id": {"type": "string", "minLength": 1},
			"comment": {"type": "string"}
		},
		"required": ["user_id"]
	}`)
	return Action{
		Name:        "block_user_account",
		Description: "Block a user account in the identity provider. Reversible only via an unblock action.",
		Params: []Param{
			{Name: "user_id", Type: "string", Description: "Identity provider user ID (e.g. email or UPN).", Required: true},
			{Name: "comment", Type: "string", Description: "Free-text justification recorded in the audit event."},
		},
		BlastRadius: BlastRadiusUserImpact,
		OCSFAuditShape: AuditShape{
			Title:      "block_user_account against {{.target}}",
			SeverityID: 4, // High
			Types:      []string{"soc-action", "identity"},
		},
		InputSchema: schema,
		PrimaryArg: "user_id",
	}
}

// starterRotateAPIKey describes API key rotation. Blast radius 3
// (soft-action): the rotation is reversible by re-issuing the prior key
// during a grace window, but services using the old key will start
// failing as soon as it expires.
func starterRotateAPIKey() Action {
	schema := mustCompileSchema("rotate_api_key", `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"key_id": {"type": "string", "minLength": 1},
			"reason": {"type": "string"}
		},
		"required": ["key_id"]
	}`)
	return Action{
		Name:        "rotate_api_key",
		Description: "Rotate an API key in the EDR backend. Reversible during a short grace window; downstream services may fail after expiry.",
		Params: []Param{
			{Name: "key_id", Type: "string", Description: "API key identifier in the backend.", Required: true},
			{Name: "reason", Type: "string", Description: "Free-text reason recorded in the audit event."},
		},
		BlastRadius: BlastRadiusSoftAction,
		OCSFAuditShape: AuditShape{
			Title:      "rotate_api_key {{.target}}",
			SeverityID: 3, // Medium
			Types:      []string{"soc-action", "credential-rotation"},
		},
		InputSchema: schema,
		PrimaryArg: "key_id",
	}
}

// starterSubmitEDRQuery describes a read-only EDR query. Blast radius 1
// (read): no state change. Fails open per AE6.
func starterSubmitEDRQuery() Action {
	schema := mustCompileSchema("submit_edr_query", `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"query":      {"type": "string", "minLength": 1},
			"host_id":    {"type": "string"},
			"time_range": {"type": "string", "description": "ISO 8601 duration, e.g. PT1H"}
		},
		"required": ["query"]
	}`)
	return Action{
		Name:        "submit_edr_query",
		Description: "Submit a read-only query to the EDR backend (RTR, search, IOC lookup). No state change.",
		Params: []Param{
			{Name: "query", Type: "string", Description: "Query string in the backend's DSL (e.g. RTR command, FQL filter).", Required: true},
			{Name: "host_id", Type: "string", Description: "Optional host scope; omit for tenant-wide queries."},
			{Name: "time_range", Type: "string", Description: "Optional ISO 8601 duration limiting the query window."},
		},
		BlastRadius: BlastRadiusRead,
		OCSFAuditShape: AuditShape{
			Title:      "submit_edr_query",
			SeverityID: 2, // Low
			Types:      []string{"soc-action", "edr-query"},
		},
		InputSchema: schema,
		// No PrimaryArg: submit_edr_query's "target" is the
		// query DSL itself, not a single high-cardinality
		// identifier. The proxy leaves Target empty for
		// read-only actions so target-restricted allow
		// rules don't accidentally scope to one host.
	}
}

// starterEnrichIOC describes IOC enrichment. Blast radius 1 (read):
// fetches reputation and context for an indicator. No state change.
func starterEnrichIOC() Action {
	schema := mustCompileSchema("enrich_ioc", `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"additionalProperties": false,
		"properties": {
			"indicator":      {"type": "string", "minLength": 1},
			"indicator_type": {"type": "string", "enum": ["ipv4", "ipv6", "domain", "url", "sha256", "md5", "email"]}
		},
		"required": ["indicator", "indicator_type"]
	}`)
	return Action{
		Name:        "enrich_ioc",
		Description: "Enrich an indicator of compromise (IP, domain, hash, URL, email) with reputation and context. No state change.",
		Params: []Param{
			{Name: "indicator", Type: "string", Description: "The indicator value.", Required: true},
			{Name: "indicator_type", Type: "string", Description: "Indicator type; one of ipv4, ipv6, domain, url, sha256, md5, email.", Required: true},
		},
		BlastRadius: BlastRadiusRead,
		OCSFAuditShape: AuditShape{
			Title:      "enrich_ioc {{.target}}",
			SeverityID: 2, // Low
			Types:      []string{"soc-action", "enrichment"},
		},
		InputSchema: schema,
		PrimaryArg: "indicator",
	}
}

// mustCompileSchema registers and compiles a JSON-Schema text under the
// given action name. The action name doubles as the schema URL fragment
// to keep the compiler's URL space clean across calls.
//
// Panics on compilation failure because a starter schema is part of the
// binary's contract; a compile error here is a programmer error and
// must fail loudly at init time, not at runtime.
func mustCompileSchema(action, schemaText string) *jsonschema.Schema {
	url := schemaURL(action)
	if err := schemaCompiler.AddResource(url, strings.NewReader(schemaText)); err != nil {
		panic(fmt.Sprintf("catalog: register schema for %q: %v", action, err))
	}
	compiled, err := schemaCompiler.Compile(url)
	if err != nil {
		panic(fmt.Sprintf("catalog: compile schema for %q: %v", action, err))
	}
	return compiled
}

// schemaURL produces a stable in-binary URL for the JSON-Schema compiler.
// Using a fragment-style URL avoids any chance of colliding with a real
// fetchable URL if the compiler ever evolves to lazy-load.
func schemaURL(action string) string {
	return "mem://catalog/" + action + ".json"
}

// Sanity check at package init: starter actions must validate and their
// blast-radius scores must match the documented mapping. This guard
// runs once at process start and panics if a future change accidentally
// drifts a starter action's contract.
func init() {
	want := map[string]int{
		"isolate_endpoint":   BlastRadiusSystemImpact,
		"block_user_account": BlastRadiusUserImpact,
		"rotate_api_key":     BlastRadiusSoftAction,
		"submit_edr_query":   BlastRadiusRead,
		"enrich_ioc":         BlastRadiusRead,
	}
	got := map[string]int{}
	for _, a := range Starter() {
		if err := a.Validate(); err != nil {
			panic(fmt.Sprintf("catalog: starter action %q fails validation: %v", a.Name, err))
		}
		got[a.Name] = a.BlastRadius
	}
	if len(got) != len(want) {
		panic(fmt.Sprintf("catalog: starter count mismatch: got %d actions, want %d", len(got), len(want)))
	}
	for name, score := range want {
		if got[name] != score {
			panic(fmt.Sprintf("catalog: starter %q blast_radius = %d, want %d", name, got[name], score))
		}
	}
}
