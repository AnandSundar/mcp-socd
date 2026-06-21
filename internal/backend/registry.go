package backend

import (
	"context"
	"fmt"
	"sync"
)

// Registry holds the set of registered Backend implementations
// keyed by name ("falcon", future "sentinelone", "carbonblack").
//
// The registry is the only dispatch surface the proxy uses. Adding
// a new provider is a two-step process: implement the Backend
// interface, then call Register from the provider's package init
// (or from the CLI's startup wiring). The registry itself does not
// know about provider-specific configuration — that is the
// provider's New(cfg) constructor's responsibility.
//
// Registry is safe for concurrent reads after construction. The
// proxy typically builds the full set once at startup and never
// mutates it afterwards; Register is therefore safe under the
// usual "configure before serve" pattern but is not optimized for
// hot reload.
type Registry struct {
	mu       sync.RWMutex
	backends map[string]Backend
}

// NewRegistry returns an empty Registry. Callers should
// immediately Register one or more backends before handing the
// Registry to the proxy.
func NewRegistry() *Registry {
	return &Registry{
		backends: make(map[string]Backend),
	}
}

// Register adds b under name. Re-registering an existing name
// overwrites the previous backend; this is intentional so test
// setups can swap a fake in for a real backend without restarting.
//
// Names are conventionally lowercase ("falcon") to match the
// config-side config.Backend.Name field. The Registry does not
// enforce case so callers are free to use whatever convention
// their config schema dictates.
func (r *Registry) Register(name string, b Backend) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.backends[name] = b
}

// Get returns the Backend registered under name. The second return
// is false when no backend is registered under that name; callers
// must check it before calling methods on the returned value.
func (r *Registry) Get(name string) (Backend, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.backends[name]
	return b, ok
}

// Names returns the sorted set of registered backend names. Useful
// for startup diagnostics and for the proxy's --list-backends CLI
// flag (planned for a later unit). The slice is freshly allocated;
// callers may mutate it.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.backends))
	for name := range r.backends {
		out = append(out, name)
	}
	return out
}

// Execute dispatches a single tool-call to the named backend by
// action name. args is the JSON-RPC arguments map; concrete
// methods decode the keys they care about.
//
// The action-to-method mapping is hard-coded here so the registry
// stays the single place that names the dispatch contract. Adding
// a new starter action means (1) adding a Backend interface
// method, (2) adding the corresponding case here, (3) implementing
// it on every backend that supports it. Backends that do not
// support a given action should return ErrUnavailable from the
// interface method so callers can distinguish "missing method"
// (ErrUnknownAction) from "method exists but unsupported on this
// backend" (ErrUnavailable).
//
// Returns ErrUnknownAction when the action does not map to any
// method. Returns a wrapped error when the named backend is not
// registered.
func (r *Registry) Execute(ctx context.Context, backendName, action string, args map[string]any) error {
	b, ok := r.Get(backendName)
	if !ok {
		return fmt.Errorf("backend %q: %w", backendName, ErrUnknownAction)
	}
	switch action {
	case "isolate_endpoint":
		hostID, _ := args["host_id"].(string)
		return b.IsolateEndpoint(ctx, hostID)
	case "lift_isolation":
		hostID, _ := args["host_id"].(string)
		return b.LiftIsolation(ctx, hostID)
	case "block_user_account":
		userID, _ := args["user_id"].(string)
		return b.BlockUserAccount(ctx, userID)
	case "unblock_user_account":
		userID, _ := args["user_id"].(string)
		return b.UnblockUserAccount(ctx, userID)
	case "rotate_api_key":
		keyID, _ := args["key_id"].(string)
		return b.RotateAPIKey(ctx, keyID)
	case "submit_edr_query":
		in := SubmitEDRQueryInput{
			Query:     stringArg(args, "query"),
			HostID:    stringArg(args, "host_id"),
			TimeRange: stringArg(args, "time_range"),
		}
		_, err := b.SubmitEDRQuery(ctx, in)
		return err
	case "enrich_ioc":
		in := EnrichIOCInput{
			Indicator:     stringArg(args, "indicator"),
			IndicatorType: stringArg(args, "indicator_type"),
		}
		_, err := b.EnrichIOC(ctx, in)
		return err
	default:
		return fmt.Errorf("%w: %q on %q", ErrUnknownAction, action, backendName)
	}
}

// stringArg fetches a string value from a map[string]any,
// returning the empty string when the key is missing or the value
// is not a string. Centralized here so each Execute arm stays a
// one-liner.
func stringArg(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}