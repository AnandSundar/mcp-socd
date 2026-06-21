// Package version exposes build-time version metadata injected via -ldflags.
//
// At build time the Makefile overrides these values:
//
//	-ldflags "-X mcp-socd/internal/version.Version=v0.1.0 \
//	          -X mcp-socd/internal/version.Commit=$(git rev-parse HEAD) \
//	          -X mcp-socd/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
package version

import "fmt"

// These vars are set via -ldflags at build time. Defaults are used for
// `go run` and untagged development builds.
var (
	// Version is the semantic version, e.g. "0.1.0". "dev" for untagged.
	Version = "dev"
	// Commit is the short git SHA. "none" outside a git checkout.
	Commit = "none"
	// BuildDate is the ISO 8601 UTC timestamp. "unknown" when not injected.
	BuildDate = "unknown"
)

// String returns a one-line version string suitable for --version output.
func String() string {
	return fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildDate)
}
