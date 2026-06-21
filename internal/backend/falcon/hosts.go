package falcon

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

// IsolateEndpoint places hostID into network containment on Falcon
// (Hosts API action=contain). The agent ID (AID) must be the
// internal device identifier — get it from a detection, the
// Falcon console, or the Streaming API.
//
// On success the SDK returns a 202 Accepted with a CSA trace ID;
// we treat that as success because the contain action itself is
// asynchronous on the Falcon side. Mapping to
// backend.ErrPermissionDenied / ErrNotFound / ErrTimeout happens
// in mapSDKError based on the HTTP status.
func (c *Client) IsolateEndpoint(ctx context.Context, hostID string) error {
	return c.performHostAction(ctx, "contain", hostID)
}

// LiftIsolation removes network containment from hostID
// (Hosts API action=lift_containment). The matching counter-action
// to IsolateEndpoint; the proxy dispatches it from the
// "lift_isolation" tool (and the corresponding "unisolate" alias
// in future catalog versions).
func (c *Client) LiftIsolation(ctx context.Context, hostID string) error {
	return c.performHostAction(ctx, "lift_containment", hostID)
}

// performHostAction is the shared body of the four Hosts-action
// methods (contain, lift_containment, hide_host, unhide_host) so
// the dispatch logic lives in one place. hostID is the agent ID
// (AID); action is one of the documented Falcon action strings.
//
// We deliberately build the request body by hand rather than via
// the SDK's *Params.WithBody fluent chain because the SDK's
// generated builder does nothing interesting here — Ids is the
// only required field, and keeping the call site explicit makes
// the audit trail easier to reason about.
func (c *Client) performHostAction(ctx context.Context, action, hostID string) error {
	if hostID == "" {
		return fmt.Errorf("falcon: %s requires non-empty host_id", action)
	}

	params := hosts.NewPerformActionV2Params().
		WithContext(ctx).
		WithActionName(action).
		WithBody(&models.MsaEntityActionRequestV2{
			Ids: []string{hostID},
		})

	_, err := c.client.Hosts.PerformActionV2(params)
	return mapSDKError(err)
}