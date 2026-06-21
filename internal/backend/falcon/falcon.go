// Package falcon — see client.go for the package overview. This
// file is the aggregator: the only entry point the rest of the
// project uses to construct a Falcon backend.
package falcon

import (
	"fmt"

	"mcp-socd/internal/backend"
	"mcp-socd/internal/config"
)

// New constructs a backend.Backend backed by CrowdStrike Falcon
// from the provider-agnostic config.Backend. The returned value is
// the *falcon.Client type (defined in client.go) which already
// satisfies backend.Backend — see the compile-time assertion in
// users.go.
//
// On construction failure (missing credentials, bad cloud
// string, OAuth handshake error), New returns a non-nil error and
// a nil backend. Callers should treat any error as fatal for
// proxy startup: there is no useful degraded mode for a backend
// that cannot authenticate.
func New(cfg config.Backend) (backend.Backend, error) {
	if cfg.Name != "" && cfg.Name != "falcon" {
		return nil, fmt.Errorf("falcon: backend name %q does not match implementation", cfg.Name)
	}
	return NewClient(cfg)
}