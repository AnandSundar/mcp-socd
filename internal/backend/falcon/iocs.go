package falcon

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon/client/intel"
	"github.com/crowdstrike/gofalcon/falcon/models"

	"mcp-socd/internal/backend"
)

// EnrichIOC fetches reputation and context for an indicator from
// CrowdStrike Falcon Intelligence. v1 wires through
// intel.GetIntelIndicatorEntities, which returns one entity per
// requested indicator with type, malicious-confidence, kill-chain,
// malware-family, and related-report fields. We normalize those
// into the backend.EnrichIOCResult shape the proxy and audit
// emitter consume.
//
// IndicatorType narrows which Falcon indicator kinds we ask for.
// The starter catalog enumerates ipv4 / ipv6 / domain / url /
// sha256 / md5 / email; Falcon's Type field is one of a similar
// set ("ipv4", "ipv6", "domain", "url", "sha256", "md5"). The
// proxy maps indicator_type -> Falcon Type, but we pass through
// unknown values so a future indicator kind added to the catalog
// reaches the SDK without a code change here.
//
// Mapping notes:
//
//   - Reputation is sourced from the SDK's MaliciousConfidence
//     string ("high" / "medium" / "low" / "unknown"). We surface
//     that verbatim because SIEM rules key off the literal
//     string.
//   - Score is the OCSF-friendly severity. Falcon returns no
//     numeric score; we synthesize 0 (unknown) on the wire and
//     stash the underlying confidence in Sources so consumers
//     can apply their own threshold logic.
func (c *Client) EnrichIOC(ctx context.Context, in backend.EnrichIOCInput) (*backend.EnrichIOCResult, error) {
	if in.Indicator == "" {
		return nil, fmt.Errorf("falcon: enrich_ioc requires non-empty indicator")
	}
	if in.IndicatorType == "" {
		return nil, fmt.Errorf("falcon: enrich_ioc requires non-empty indicator_type")
	}

	params := intel.NewGetIntelIndicatorEntitiesParams().
		WithContext(ctx).
		WithBody(&models.MsaIdsRequest{
			Ids: []string{in.Indicator},
		})

	resp, err := c.client.Intel.GetIntelIndicatorEntities(params)
	if err != nil {
		return nil, mapSDKError(err)
	}

	return normalizeIntelResult(resp, in), nil
}

// normalizeIntelResult turns the SDK's typed response into the
// untyped backend.EnrichIOCResult shape. Kept in a free function
// rather than a method so the table test in falcon_test.go can
// drive it directly without spinning up a Client.
func normalizeIntelResult(resp *intel.GetIntelIndicatorEntitiesOK, in backend.EnrichIOCInput) *backend.EnrichIOCResult {
	out := &backend.EnrichIOCResult{
		Reputation: "unknown",
		Score:      0,
		Sources:    map[string]any{},
	}
	out.Sources["indicator"] = in.Indicator
	out.Sources["indicator_type"] = in.IndicatorType

	if resp == nil || resp.Payload == nil {
		return out
	}
	out.Sources["trace_id"] = resp.XCSTRACEID

	resources := resp.Payload.Resources
	if len(resources) == 0 {
		return out
	}

	// Pick the first matching entity. The SDK returns one
	// entity per requested indicator, so for a single
	// indicator the first is the only match.
	entity := resources[0]
	if entity == nil {
		return out
	}

	if entity.Type != nil {
		out.Sources["falcon_type"] = *entity.Type
	}
	if entity.MaliciousConfidence != nil {
		out.Reputation = *entity.MaliciousConfidence
		out.Sources["malicious_confidence"] = *entity.MaliciousConfidence
	}
	if entity.LastUpdated != nil {
		out.Sources["last_updated"] = *entity.LastUpdated
	}
	if entity.KillChains != nil {
		out.Sources["kill_chains"] = entity.KillChains
	}
	if entity.ThreatTypes != nil {
		out.Sources["threat_types"] = entity.ThreatTypes
	}
	if entity.MalwareFamilies != nil {
		out.Sources["malware_families"] = entity.MalwareFamilies
	}
	return out
}