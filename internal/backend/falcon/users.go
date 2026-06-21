package falcon

import (
	"context"
	"fmt"

	"mcp-socd/internal/backend"
)

// BlockUserAccount is currently a stub: CrowdStrike Falcon does not
// expose a native "block this user" endpoint. The Identity
// Protection product (c.client.IdentityProtection in gofalcon)
// operates on policy rules that block authentication flows, not on
// direct user suspensions, and the right wiring depends on the
// operator's identity provider (Azure AD, Okta, Ping, ...) rather
// than on Falcon itself.
//
// We return backend.ErrUnavailable so the proxy surfaces an honest
// deny with an explanatory audit reason (Plan §U9 / §U5), rather
// than pretending success. Once we land an IDP-aware block path,
// this method will translate the userID into the provider's
// native suspension call.
//
// Track https://github.com/CrowdStrike/gofalcon for any future
// user-suspension endpoints before re-implementing.
func (c *Client) BlockUserAccount(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("falcon: block_user_account requires non-empty user_id")
	}
	return fmt.Errorf("%w: %s", backend.ErrUnavailable,
		"Falcon does not expose a native user-block endpoint; integrate with the identity provider (Azure AD / Okta / Ping) instead")
}

// UnblockUserAccount mirrors BlockUserAccount: same stub for the
// same reason. Splitting the two keeps the registry's action
// dispatch one-action-per-method even though both return
// ErrUnavailable today.
func (c *Client) UnblockUserAccount(ctx context.Context, userID string) error {
	if userID == "" {
		return fmt.Errorf("falcon: unblock_user_account requires non-empty user_id")
	}
	return fmt.Errorf("%w: %s", backend.ErrUnavailable,
		"Falcon does not expose a native user-unblock endpoint; integrate with the identity provider (Azure AD / Okta / Ping) instead")
}

// compile-time assertion that *Client satisfies backend.Backend.
// If a future refactor changes the interface, this line breaks
// the build before tests run.
var _ backend.Backend = (*Client)(nil)