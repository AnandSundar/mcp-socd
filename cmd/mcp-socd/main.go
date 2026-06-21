// Command mcp-socd is the entry point for the MCP-aware security proxy.
//
// The CLI tree lives in internal/cli. main() is intentionally minimal:
// all logic is in packages so it can be unit-tested without spawning a
// process.
package main

import (
	"fmt"
	"os"

	"mcp-socd/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
