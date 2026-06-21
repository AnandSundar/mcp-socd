// Package falcon implements backend.Backend against the CrowdStrike
// Falcon platform via github.com/crowdstrike/gofalcon.
//
// The package groups one file per resource surface (hosts, users,
// api_keys, rtr, iocs) so each set of related methods lives next to
// its SDK callsite. client.go owns only the connection: it performs
// the OAuth2 client-credentials handshake via the gofalcon SDK and
// caches the token there (we deliberately do not implement our own
// token cache; see Plan R1).
//
// Token refresh, rate-limit backoff, and HTTP retries are owned by
// the SDK's roundTripper. This package only surfaces the sentinel
// errors from internal/backend when the SDK has finally given up.
package falcon

import (
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	gofalcon "github.com/crowdstrike/gofalcon/falcon/client"

	"mcp-socd/internal/backend"
	"mcp-socd/internal/config"
)

// Client is the concrete *Backend for the CrowdStrike Falcon
// platform. It owns the gofalcon SDK client (which in turn owns the
// OAuth2 token cache, HTTP round tripper, and retry layer) and
// exposes the starter-catalog actions as backend.Backend methods.
//
// The struct is hidden behind the package-level New function (in
// falcon.go) so the registry can hand out a value that satisfies
// backend.Backend without exposing internal SDK fields.
type Client struct {
	// client is the gofalcon *CrowdStrikeAPISpecification. We hold a
	// pointer (not a copy) because every method call mutates the
	// underlying transport when tokens refresh; copying the struct
	// would split the token cache between callers.
	client *gofalcon.CrowdStrikeAPISpecification

	// cloud is the resolved CloudType (e.g. CloudUs1). Stored
	// alongside client so the test in Cloud() does not have to
	// reach back through the SDK to recover the region string.
	cloud falcon.CloudType
}

// NewClient performs the OAuth2 client-credentials handshake against
// the configured Falcon cloud and returns a *Client wrapping the
// resulting SDK handle.
//
// cfg.Cloud must be one of the canonical values accepted by
// gofalcon.CloudValidate ("us-1", "us-2", "eu-1", "us-gov-1"). The
// empty string means autodiscover (the SDK does a probe and picks
// the correct region from the client ID); we pass it through
// unchanged.
//
// cfg.ClientID and cfg.ClientSecret are the OAuth2 client
// credentials. The struct's ResolvedClientID / ResolvedClientSecret
// helpers resolve the *Env forms when set so callers can keep
// secrets out of the on-disk YAML.
//
// We do not implement our own token cache: gofalcon's
// clientCredentialsHTTPClient wraps golang.org/x/oauth2's
// clientcredentials.Config which refreshes proactively, and the
// SDK's roundTripper tracks remaining quota for proactive
// throttling. Re-implementing either here would be redundant and
// risky.
func NewClient(cfg config.Backend) (*Client, error) {
	clientID := cfg.ResolvedClientID()
	clientSecret := cfg.ResolvedClientSecret()
	if clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("falcon: client credentials required (set ClientID/ClientSecret or ClientIDEnv/ClientSecretEnv)")
	}

	cloud, err := falcon.CloudValidate(cfg.Cloud)
	if err != nil {
		return nil, fmt.Errorf("falcon: %w", err)
	}

	sdk, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     clientID,
		ClientSecret: clientSecret,
		Cloud:        cloud,
		// We deliberately leave Context nil: the SDK uses it
		// only for the initial OAuth handshake, and we have no
		// startup-wide context to hand it. The SDK then uses
		// per-call contexts for everything else.
	})
	if err != nil {
		return nil, fmt.Errorf("falcon: handshake: %w", err)
	}

	return &Client{client: sdk, cloud: cloud}, nil
}

// newClientFromSDK builds a *Client from an already-constructed
// gofalcon handle. Tests use this path to inject
// falcon/testing.NewFakeClient without going through the real OAuth
// handshake; production code must use NewClient.
func newClientFromSDK(sdk *gofalcon.CrowdStrikeAPISpecification, cloud falcon.CloudType) *Client {
	return &Client{client: sdk, cloud: cloud}
}

// Cloud returns the canonical Falcon cloud string ("us-1", "us-2",
// "eu-1", "us-gov-1", or "autodiscover" for the autodiscover
// probe). Surfaced in the OCSF audit metadata so SIEM-side rules
// can route on tenant region without parsing the request URL.
func (c *Client) Cloud() string {
	return c.cloud.String()
}

// mapSDKError maps a gofalcon SDK error to the closest
// internal/backend sentinel. The SDK returns a mix of go-openapi
// runtime errors and HTTP status codes; we coarse-grain to keep
// the proxy's posture mapping stable.
//
// Returns the original error wrapped with %w when no sentinel
// matches so callers still get the SDK's diagnostic via
// errors.Unwrap.
func mapSDKError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "401"), strings.Contains(msg, "403"):
		return fmt.Errorf("%w: %v", backend.ErrPermissionDenied, err)
	case strings.Contains(msg, "404"):
		return fmt.Errorf("%w: %v", backend.ErrNotFound, err)
	case strings.Contains(msg, "429"):
		return fmt.Errorf("%w: %v", backend.ErrRateLimited, err)
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return fmt.Errorf("%w: %v", backend.ErrTimeout, err)
	case strings.Contains(msg, "context canceled"):
		return fmt.Errorf("%w: %v", backend.ErrTimeout, err)
	default:
		return err
	}
}