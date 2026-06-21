// Package backend defines the contract every SOC backend (Falcon,
// future SentinelOne / Carbon Black, ...) must satisfy, plus the
// shared sentinel errors callers map to posture decisions.
//
// The interface is intentionally narrow: one method per starter
// catalog action (see Plan §U2 / starter.go) and no shared client
// handle. Each implementation owns its own connection pool, OAuth
// token cache, and SDK retry logic; this package only describes
// what callers (the proxy in U4, future tests in U10) consume.
//
// Sentinel errors are package-level vars so callers can match with
// errors.Is. Each error type corresponds to a posture decision in
// the proxy:
//
//   - ErrNotFound         - host_id / user_id / key_id does not exist.
//     Usually not retryable; surfaced as a deny.
//   - ErrPermissionDenied - caller lacks OAuth scope or RBAC. Not
//     retryable; surfaced as a deny (audit shows why).
//   - ErrRateLimited      - upstream returned 429. Caller (U9) decides
//     whether to retry or fail closed.
//   - ErrTimeout          - SDK context deadline elapsed. Caller
//     decides retry vs. posture.
//   - ErrUnavailable      - the backend does not implement this
//     action (e.g. Falcon does not have a native user-block API).
//     Surfaced as a deny with an explanatory audit reason.
//
// Implementations must return one of these errors unwrapped when the
// underlying SDK error falls into that bucket. Wrapping with %w is
// allowed so callers can still introspect the original SDK error.
package backend

import (
	"context"
	"errors"
)

// Sentinel errors. Use errors.Is at call sites; do not compare to nil
// pointers. Wrapping with fmt.Errorf("%w: ...", ErrX) is encouraged
// when a more specific diagnostic is helpful.
var (
	// ErrNotFound is returned when the target of an action (host_id,
	// user_id, key_id) does not exist on the backend.
	ErrNotFound = errors.New("backend: resource not found")

	// ErrPermissionDenied is returned when the caller's OAuth scope
	// or RBAC does not permit the requested action.
	ErrPermissionDenied = errors.New("backend: permission denied")

	// ErrRateLimited is returned when the backend signals a
	// rate-limit response (HTTP 429). The SDK's RetryConfig may
	// have already absorbed some retries; this is the last-resort
	// signal that the caller (U9) should back off and retry, or
	// fail closed if retries are exhausted.
	ErrRateLimited = errors.New("backend: rate limited")

	// ErrTimeout is returned when the SDK context deadline elapsed
	// before the backend responded. Long-running operations (RTR
	// sessions, batch IOC enrichment) commonly surface this.
	ErrTimeout = errors.New("backend: timeout")

	// ErrUnavailable is returned when the backend has no
	// implementation for the requested action. Used for stubs
	// (e.g. Falcon identity-block in v1) so the proxy surfaces a
	// honest deny rather than a fake success.
	ErrUnavailable = errors.New("backend: action unavailable")

	// ErrUnknownAction is returned by Registry.Execute when the
	// action name does not map to a method on the named backend.
	// Distinct from ErrUnavailable: the backend may exist and
	// implement other actions; this one is just not wired.
	ErrUnknownAction = errors.New("backend: unknown action")
)

// SubmitEDRQueryInput is the typed argument list for
// Backend.SubmitEDRQuery. Mirrors the catalog action schema for
// "submit_edr_query" (see starter.go) so the proxy can decode the
// JSON-RPC arguments without depending on the catalog package.
type SubmitEDRQueryInput struct {
	// Query is the backend-native DSL (RTR command, FQL filter,
	// search expression). Required.
	Query string

	// HostID scopes the query to a single host (the host's agent
	// ID on Falcon). Empty means tenant-wide.
	HostID string

	// TimeRange is an optional ISO 8601 duration limiting the query
	// window (e.g. "PT1H"). Implementations are free to ignore the
	// value if their SDK does not surface it.
	TimeRange string
}

// SubmitEDRQueryResult is the structured result of a successful
// EDR query. The Rows/Stats shape is intentionally untyped so
// implementations can pass through whatever the upstream SDK
// returns; the proxy marshals it back to the agent as JSON-RPC
// content.
type SubmitEDRQueryResult struct {
	// Rows is one entry per result record. The map shape is
	// backend-specific (e.g. RTR returns {"stdout": "...",
	// "stderr": "...", "base_command": "..."}).
	Rows []map[string]any

	// Stats is backend-specific aggregate counters (commands run,
	// hosts matched, etc.). Optional; may be nil.
	Stats map[string]int64
}

// EnrichIOCInput is the typed argument list for Backend.EnrichIOC.
// Mirrors the catalog action schema for "enrich_ioc" (see
// starter.go).
type EnrichIOCInput struct {
	// Indicator is the IOC value itself (IP, domain, hash, URL,
	// email). Required.
	Indicator string

	// IndicatorType narrows the indicator kind. One of ipv4,
	// ipv6, domain, url, sha256, md5, email.
	IndicatorType string
}

// EnrichIOCResult is the structured result of a successful IOC
// enrichment. The Reputation/Score pair is the minimal signal the
// proxy needs to record an audit event; Sources carries the
// per-backend evidence trail for SIEM correlation.
type EnrichIOCResult struct {
	// Reputation is the backend's verdict ("malicious",
	// "suspicious", "neutral", "unknown", ...). Exact strings are
	// backend-specific.
	Reputation string

	// Score is a numeric severity (0..100 typical). Higher is
	// worse. The proxy surfaces this in the audit metadata so
	// downstream consumers can apply their own threshold logic
	// without re-parsing Sources.
	Score int

	// Sources is the per-source evidence: list of matched rules,
	// related campaigns, kill-chain stages, etc. Optional; may be
	// nil. The map shape is backend-specific.
	Sources map[string]any
}

// Backend is the contract every SOC backend must satisfy. Each
// method corresponds to one starter catalog action; the proxy
// dispatches by action name via Registry.Execute.
//
// All methods take a context.Context so callers can apply
// per-request timeouts / cancellation. All methods return one of
// the sentinel errors above (or another wrapped error) on failure.
//
// Implementations must not panic on bad input — they must return
// ErrNotFound for missing targets and ErrPermissionDenied for
// scope failures so the proxy can distinguish "user error" from
// "infrastructure error" in the audit trail.
type Backend interface {
	// IsolateEndpoint places hostID into network containment
	// (Falcon: action=contain). Reversible via LiftIsolation.
	IsolateEndpoint(ctx context.Context, hostID string) error

	// LiftIsolation removes network containment from hostID
	// (Falcon: action=lift_containment). The matching counter-
	// action to IsolateEndpoint; the proxy dispatches it from
	// the "unisolate" tool when the agent unwinds an isolation.
	LiftIsolation(ctx context.Context, hostID string) error

	// BlockUserAccount blocks userID at the identity provider.
	// Not every backend implements this — Falcon returns
	// ErrUnavailable in v1 because there is no native user-block
	// endpoint; the proxy surfaces an explanatory deny.
	BlockUserAccount(ctx context.Context, userID string) error

	// UnblockUserAccount reverses BlockUserAccount. Same
	// availability caveats apply.
	UnblockUserAccount(ctx context.Context, userID string) error

	// RotateAPIKey rotates keyID on the backend. Reversible
	// during a short grace window; downstream services may start
	// failing once the prior key expires.
	RotateAPIKey(ctx context.Context, keyID string) error

	// SubmitEDRQuery runs a read-only EDR query and returns the
	// structured result. The only non-error-returning starter
	// action; readers should expect Rows to be non-nil on success
	// even if empty.
	SubmitEDRQuery(ctx context.Context, query SubmitEDRQueryInput) (*SubmitEDRQueryResult, error)

	// EnrichIOC fetches reputation and context for an indicator.
	// Like SubmitEDRQuery, this is the other reader in the
	// starter set.
	EnrichIOC(ctx context.Context, ioc EnrichIOCInput) (*EnrichIOCResult, error)
}