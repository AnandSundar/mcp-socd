package falcon

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/hosts"

	"mcp-socd/internal/backend"
)

// SubmitEDRQuery runs a read-only EDR query against Falcon and
// returns the aggregated result. v1 implementation maps the
// starter-catalog schema (see starter.go) onto the Hosts API:
//
//   - When HostID is set: calls Hosts.GetDeviceDetailsV2 with the
//     host's agent ID and synthesizes one Row per device in the
//     response. The Query string is treated as a free-text
//     assertion (logged but not forwarded) because the Hosts
//     detail endpoint has no FQL field for it.
//   - When HostID is empty: calls Hosts.QueryDevicesByFilter with
//     Query as the Filter expression and synthesizes one Row per
//     device ID in the Resources slice.
//
// This is the simplest "real SDK call" mapping that honors ctx
// timeouts, so the Plan §U8 timeout test scenario
// (TestFalcon_RTRTimeout) can drive a real context deadline and
// observe backend.ErrTimeout surfacing from mapSDKError.
//
// Future versions will route through the RTR session APIs
// (gofalcon/falcon/client/rtr_real_time_response) and the Falcon
// Search / Streaming endpoints; the surface here stays stable so
// the registry and proxy do not change.
func (c *Client) SubmitEDRQuery(ctx context.Context, in backend.SubmitEDRQueryInput) (*backend.SubmitEDRQueryResult, error) {
	if in.Query == "" {
		return nil, fmt.Errorf("falcon: submit_edr_query requires non-empty query")
	}

	if in.HostID != "" {
		return c.submitEDRQueryForHost(ctx, in)
	}
	return c.submitEDRQueryByFilter(ctx, in)
}

// submitEDRQueryForHost calls Hosts.GetDeviceDetailsV2 with one
// agent ID and turns the response into one Row. ctx is forwarded
// so a caller-imposed deadline surfaces as backend.ErrTimeout.
func (c *Client) submitEDRQueryForHost(ctx context.Context, in backend.SubmitEDRQueryInput) (*backend.SubmitEDRQueryResult, error) {
	params := hosts.NewGetDeviceDetailsV2Params().
		WithContext(ctx).
		WithIds([]string{in.HostID})

	resp, err := c.client.Hosts.GetDeviceDetailsV2(params)
	if err != nil {
		return nil, mapSDKError(err)
	}

	rows := make([]map[string]any, 0)
	if resp != nil && resp.Payload != nil {
		for _, dev := range resp.Payload.Resources {
			if dev == nil {
				continue
			}
			row := map[string]any{
				"device_id":      stringFromPtr(dev.DeviceID),
				"hostname":       dev.Hostname,
				"agent_version":  dev.AgentVersion,
				"os_version":     dev.OsVersion,
				"local_ip":       dev.LocalIP,
				"mac_address":    dev.MacAddress,
				"first_seen":     dev.FirstSeen,
				"last_seen":      dev.LastSeen,
				"query":          in.Query,
				"time_range":     in.TimeRange,
			}
			rows = append(rows, row)
		}
	}

	return &backend.SubmitEDRQueryResult{
		Rows: rows,
		Stats: map[string]int64{
			"matched": int64(len(rows)),
		},
	}, nil
}

// submitEDRQueryByFilter calls Hosts.QueryDevicesByFilter with
// in.Query as the FQL filter expression and turns the returned
// device IDs into one Row per ID. The "query" string is
// round-tripped into each Row's "filter" field so the caller can
// confirm what filter the server actually saw.
func (c *Client) submitEDRQueryByFilter(ctx context.Context, in backend.SubmitEDRQueryInput) (*backend.SubmitEDRQueryResult, error) {
	filter := in.Query
	params := hosts.NewQueryDevicesByFilterParams().
		WithContext(ctx).
		WithFilter(&filter)

	resp, err := c.client.Hosts.QueryDevicesByFilter(params)
	if err != nil {
		return nil, mapSDKError(err)
	}

	rows := make([]map[string]any, 0)
	if resp != nil && resp.Payload != nil {
		for _, devID := range resp.Payload.Resources {
			rows = append(rows, map[string]any{
				"device_id":  devID,
				"filter":    filter,
				"time_range": in.TimeRange,
			})
		}
	}

	return &backend.SubmitEDRQueryResult{
		Rows: rows,
		Stats: map[string]int64{
			"matched": int64(len(rows)),
		},
	}, nil
}

// stringFromPtr is a small helper that dereferences a *string
// (the shape of most SDK model fields), returning the empty
// string when the pointer is nil. Keeps the row-building loop
// readable.
func stringFromPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}