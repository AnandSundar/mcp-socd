package falcon

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	falcontesting "github.com/crowdstrike/gofalcon/falcon/testing"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"mcp-socd/internal/backend"
	"mcp-socd/internal/config"
)

// newTestClient wires a Client around a falcon/testing FakeClient
// so the production SDK handle points at our mock transport.
// Returns both the wrapped Client and the underlying FakeClient so
// tests can register per-operation mock handlers and inspect
// captured requests.
func newTestClient(t *testing.T) (*Client, *falcontesting.FakeClient) {
	t.Helper()
	fake := falcontesting.NewFakeClient()
	c := newClientFromSDK(fake.GetClient(), falcon.Cloud("us-1"))
	return c, fake
}

// stringPtr returns &s. Mirrors the SDK's pointer-to-string field
// convention so test scaffolding stays terse.
func stringPtr(s string) *string {
	return &s
}

// TestFalcon_IsolateEndpoint_Success is the happy-path isolate
// test: the fake client's PerformActionV2 handler returns a
// successful 202 response and the SDK call returns nil.
func TestFalcon_IsolateEndpoint_Success(t *testing.T) {
	c, fake := newTestClient(t)
	fake.AddStaticMockHandler("PerformActionV2", &hosts.PerformActionV2Accepted{
		XCSTRACEID: "trace-isolate-ok",
	})

	if err := c.IsolateEndpoint(context.Background(), "agent-123"); err != nil {
		t.Fatalf("IsolateEndpoint returned error: %v", err)
	}
	if got := fake.CountRequests("PerformActionV2"); got != 1 {
		t.Errorf("PerformActionV2 call count = %d, want 1", got)
	}
}

// TestFalcon_LiftIsolation_Success mirrors the contain test for
// the lift direction. Same SDK operation, different action name
// in the request body.
func TestFalcon_LiftIsolation_Success(t *testing.T) {
	c, fake := newTestClient(t)
	fake.AddStaticMockHandler("PerformActionV2", &hosts.PerformActionV2Accepted{
		XCSTRACEID: "trace-lift-ok",
	})

	if err := c.LiftIsolation(context.Background(), "agent-456"); err != nil {
		t.Fatalf("LiftIsolation returned error: %v", err)
	}
	if got := fake.CountRequests("PerformActionV2"); got != 1 {
		t.Errorf("PerformActionV2 call count = %d, want 1", got)
	}
}

// TestFalcon_IsolateEndpoint_AuthFailure drives the SDK to return
// a 401 via the fake client's error-handler chain and asserts
// the resulting error is recognized as ErrPermissionDenied via
// errors.Is.
func TestFalcon_IsolateEndpoint_AuthFailure(t *testing.T) {
	c, fake := newTestClient(t)
	fake.AddErrorMockHandler("PerformActionV2", errors.New("401 Unauthorized: client credentials rejected"))

	err := c.IsolateEndpoint(context.Background(), "agent-bad")
	if err == nil {
		t.Fatal("expected error from IsolateEndpoint, got nil")
	}
	if !errors.Is(err, backend.ErrPermissionDenied) {
		t.Errorf("error is not ErrPermissionDenied: %v", err)
	}
}

// TestFalcon_RateLimited verifies that an SDK error containing the
// 429 marker surfaces as backend.ErrRateLimited. The SDK's own
// RetryConfig is nil on the fake client (it has no roundTripper
// to wrap), so this test exercises our mapSDKError behavior in
// isolation.
func TestFalcon_RateLimited(t *testing.T) {
	c, fake := newTestClient(t)
	fake.AddErrorMockHandler("PerformActionV2", errors.New("429 Too Many Requests: retry-after 60"))

	err := c.IsolateEndpoint(context.Background(), "agent-busy")
	if err == nil {
		t.Fatal("expected error from IsolateEndpoint, got nil")
	}
	if !errors.Is(err, backend.ErrRateLimited) {
		t.Errorf("error is not ErrRateLimited: %v", err)
	}
}

// TestFalcon_RTRTimeout exercises the context-deadline path:
// SubmitEDRQuery gets a context that has already expired; the
// SDK call propagates the deadline-exceeded error; mapSDKError
// surfaces it as backend.ErrTimeout.
func TestFalcon_RTRTimeout(t *testing.T) {
	c, fake := newTestClient(t)
	fake.AddErrorMockHandler("GetDeviceDetailsV2", fmt.Errorf("GetDeviceDetailsV2: %w", context.DeadlineExceeded))

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	_, err := c.SubmitEDRQuery(ctx, backend.SubmitEDRQueryInput{
		Query:  "device.os:linux",
		HostID: "agent-timeout",
	})
	if err == nil {
		t.Fatal("expected error from SubmitEDRQuery with expired context, got nil")
	}
	if !errors.Is(err, backend.ErrTimeout) {
		t.Errorf("error is not ErrTimeout: %v", err)
	}
}

// TestFalcon_EnrichIOC_OK feeds a synthesized intel response and
// asserts the normalized result has Reputation populated from
// MaliciousConfidence and Score 0 (we never synthesize a number
// from a string).
func TestFalcon_EnrichIOC_OK(t *testing.T) {
	c, fake := newTestClient(t)
	confidence := "high"
	falconType := "domain"
	last := int64(1700000000)
	fake.AddStaticMockHandler("GetIntelIndicatorEntities", &intel.GetIntelIndicatorEntitiesOK{
		XCSTRACEID: "trace-ioc-ok",
		Payload: &models.DomainPublicIndicatorsV3Response{
			Resources: []*models.DomainPublicIndicatorV3{
				{
					Indicator:           stringPtr("evil.example.com"),
					Type:                &falconType,
					MaliciousConfidence: &confidence,
					LastUpdated:         &last,
				},
			},
		},
	})

	res, err := c.EnrichIOC(context.Background(), backend.EnrichIOCInput{
		Indicator:     "evil.example.com",
		IndicatorType: "domain",
	})
	if err != nil {
		t.Fatalf("EnrichIOC returned error: %v", err)
	}
	if res == nil {
		t.Fatal("EnrichIOC returned nil result")
	}
	if res.Reputation != "high" {
		t.Errorf("Reputation = %q, want %q", res.Reputation, "high")
	}
	if res.Score != 0 {
		t.Errorf("Score = %d, want 0", res.Score)
	}
	if got, ok := res.Sources["falcon_type"]; !ok || got != "domain" {
		t.Errorf("Sources[falcon_type] = %v, want %q", got, "domain")
	}
}

// TestFalcon_EnrichIOC_NotFound drives a 404 from the SDK and
// asserts ErrNotFound surfaces. Mirrors TestFalcon_IsolateEndpoint_
// AuthFailure's structure for the other HTTP-status branch.
func TestFalcon_EnrichIOC_NotFound(t *testing.T) {
	c, fake := newTestClient(t)
	fake.AddErrorMockHandler("GetIntelIndicatorEntities", errors.New("404 Not Found: indicator entity not present"))

	_, err := c.EnrichIOC(context.Background(), backend.EnrichIOCInput{
		Indicator:     "missing.example.com",
		IndicatorType: "domain",
	})
	if err == nil {
		t.Fatal("expected error from EnrichIOC, got nil")
	}
	if !errors.Is(err, backend.ErrNotFound) {
		t.Errorf("error is not ErrNotFound: %v", err)
	}
}

// TestFalcon_BlockUserAccount_Unavailable asserts the stub
// behavior: Falcon returns ErrUnavailable with a wrapped message
// explaining why. The test exists so the wiring (registry -> client
// -> backend.Backend) is verified end-to-end even though the
// underlying SDK call is never made.
func TestFalcon_BlockUserAccount_Unavailable(t *testing.T) {
	c, _ := newTestClient(t)
	err := c.BlockUserAccount(context.Background(), "alice@example.com")
	if err == nil {
		t.Fatal("expected ErrUnavailable from BlockUserAccount, got nil")
	}
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("error is not ErrUnavailable: %v", err)
	}
	if !strings.Contains(err.Error(), "user-block") {
		t.Errorf("error message lacks 'user-block' explanation: %v", err)
	}
}

// TestFalcon_RotateAPIKey_Unavailable mirrors the block-user test
// for the API key stub.
func TestFalcon_RotateAPIKey_Unavailable(t *testing.T) {
	c, _ := newTestClient(t)
	err := c.RotateAPIKey(context.Background(), "key-abc")
	if err == nil {
		t.Fatal("expected ErrUnavailable from RotateAPIKey, got nil")
	}
	if !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("error is not ErrUnavailable: %v", err)
	}
}

// TestFalcon_AllFiveActionsRegistered verifies that every
// starter-catalog action has a working wiring through the
// Registry. This is the "five-action guard": if a future refactor
// drops one of the arms from Registry.Execute, this test fails
// loudly.
//
// ErrUnavailable is acceptable for the stubbed actions
// (block_user_account, unblock_user_account, rotate_api_key).
// Any other error means wiring broke.
func TestFalcon_AllFiveActionsRegistered(t *testing.T) {
	c, fake := newTestClient(t)

	// Register handlers for every operation we expect the
	// five starter actions to touch. Anything left
	// unhandled here would surface as a fake-client error
	// ("no mock handler found") rather than a typed
	// backend.Backend sentinel; that error would then fail
	// the per-action subtest below.
	fake.AddStaticMockHandler("PerformActionV2", &hosts.PerformActionV2Accepted{XCSTRACEID: "trace"})
	fake.AddStaticMockHandler("QueryDevicesByFilter", &hosts.QueryDevicesByFilterOK{
		Payload: &models.MsaQueryResponse{Resources: []string{}},
	})
	fake.AddStaticMockHandler("GetDeviceDetailsV2", &hosts.GetDeviceDetailsV2OK{
		Payload: &models.DeviceapiDeviceDetailsResponseSwagger{},
	})
	fake.AddStaticMockHandler("GetIntelIndicatorEntities", &intel.GetIntelIndicatorEntitiesOK{
		Payload: &models.DomainPublicIndicatorsV3Response{},
	})

	reg := backend.NewRegistry()
	reg.Register("falcon", c)

	cases := []struct {
		action string
		args   map[string]any
	}{
		{"isolate_endpoint", map[string]any{"host_id": "agent-1"}},
		{"lift_isolation", map[string]any{"host_id": "agent-1"}},
		{"block_user_account", map[string]any{"user_id": "alice@example.com"}},
		{"unblock_user_account", map[string]any{"user_id": "alice@example.com"}},
		{"rotate_api_key", map[string]any{"key_id": "key-1"}},
		{"submit_edr_query", map[string]any{"query": "device.os:linux", "host_id": "agent-1"}},
		{"enrich_ioc", map[string]any{"indicator": "evil.example.com", "indicator_type": "domain"}},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			err := reg.Execute(context.Background(), "falcon", tc.action, tc.args)
			if err == nil {
				return
			}
			if errors.Is(err, backend.ErrUnavailable) {
				return
			}
			t.Errorf("Execute(%q) returned unexpected error: %v", tc.action, err)
		})
	}
}

// TestFalcon_Registry_UnknownAction asserts the registry's
// out-of-band guard: an action name not in the dispatch table
// returns ErrUnknownAction (not the typed ErrUnavailable). This
// protects against typos in the catalog or future arms added to
// one backend but not another.
func TestFalcon_Registry_UnknownAction(t *testing.T) {
	c, _ := newTestClient(t)
	reg := backend.NewRegistry()
	reg.Register("falcon", c)

	err := reg.Execute(context.Background(), "falcon", "delete_database", nil)
	if err == nil {
		t.Fatal("expected ErrUnknownAction, got nil")
	}
	if !errors.Is(err, backend.ErrUnknownAction) {
		t.Errorf("error is not ErrUnknownAction: %v", err)
	}
}

// TestFalcon_NewClient_MissingCreds asserts the constructor's
// guard against empty credentials. We never reach the SDK call so
// no fake client is needed.
func TestFalcon_NewClient_MissingCreds(t *testing.T) {
	_, err := NewClient(config.Backend{Cloud: "us-1"})
	if err == nil {
		t.Fatal("expected error from NewClient with empty credentials, got nil")
	}
	if !strings.Contains(err.Error(), "client credentials") {
		t.Errorf("error message lacks 'client credentials': %v", err)
	}
}

// TestNormalizeIntelResult_Empty drives the nil-payload branch of
// normalizeIntelResult directly so the table is reachable even
// without an SDK round trip.
func TestNormalizeIntelResult_Empty(t *testing.T) {
	got := normalizeIntelResult(nil, backend.EnrichIOCInput{
		Indicator:     "x.example.com",
		IndicatorType: "domain",
	})
	if got == nil {
		t.Fatal("normalizeIntelResult returned nil")
	}
	if got.Reputation != "unknown" {
		t.Errorf("Reputation = %q, want %q", got.Reputation, "unknown")
	}
	if got.Score != 0 {
		t.Errorf("Score = %d, want 0", got.Score)
	}
	if got.Sources["indicator"] != "x.example.com" {
		t.Errorf("Sources[indicator] = %v, want x.example.com", got.Sources["indicator"])
	}
}

// TestFalcon_Cloud asserts the Cloud() accessor returns the
// canonical short form ("us-1") regardless of how the underlying
// SDK was constructed.
func TestFalcon_Cloud(t *testing.T) {
	c := newClientFromSDK(falcontesting.NewFakeClient().GetClient(), falcon.Cloud("eu-1"))
	if got, want := c.Cloud(), "eu-1"; got != want {
		t.Errorf("Cloud() = %q, want %q", got, want)
	}
}