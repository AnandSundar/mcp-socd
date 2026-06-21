package falcon

import (
	"context"
	"fmt"

	"mcp-socd/internal/backend"
)

// RotateAPIKey is currently a stub: the gofalcon SDK exposes API
// client lifecycle endpoints (create, delete, list, rotate-secrets)
// under falcon/client/api_clients, but a true "rotate" of an
// arbitrary keyID passed in by the caller is not a single-call
// operation — it is a delete-then-recreate flow whose semantics
// depend on whether the caller wants the old secret to remain
// valid for a grace window. The right wiring also depends on
// whether keyID refers to a Falcon API client (rotation lives in
// this SDK) or to a downstream service's key (rotation lives in
// that service).
//
// We return backend.ErrUnavailable so the proxy surfaces an honest
// deny rather than a fake success. Once the catalog's
// rotate_api_key action grows a "scope" parameter (e.g.
// scope=falcon_api_client vs scope=downstream), this method will
// dispatch to the right backend.
//
// Track gofalcon's api_clients.UpdateAPIClient for progress on
// in-place secret rotation.
func (c *Client) RotateAPIKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("falcon: rotate_api_key requires non-empty key_id")
	}
	return fmt.Errorf("%w: %s", backend.ErrUnavailable,
		"Falcon API key rotation is a delete-then-recreate flow; see api_clients.UpdateAPIClient / DeleteAPIClients")
}