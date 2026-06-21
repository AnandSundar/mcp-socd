// mock_upstream_runner is a tiny CLI wrapper that bridges
// mockupstream.MockUpstream's in-process pipes to the host's stdio.
//
// The proxy (mcp-socd) spawns its upstream via os/exec, so the
// upstream must be a real subprocess. This binary is that
// subprocess: it calls StartMockUpstream() and pumps bytes
// between the mock's agent-facing pipes and os.Stdin /
// os.Stdout.
//
// Build:
//
//	go build -o test/integration/bin/mock-upstream-runner \
//	    ./test/integration/cmd/mock_upstream_runner
//
// The integration test suite builds it on demand before each
// run; the resulting binary lives under test/integration/bin/
// which is gitignored.
package main

import (
	"io"
	"log"
	"os"

	"mcp-socd/test/integration/mockupstream"
)

func main() {
	stdin, stdout, errCh := mockupstream.StartMockUpstream()

	// Pump bytes bidirectionally: host-stdin -> mock-stdin (the
	// upstream's agent-facing input) and mock-stdout -> host-stdout
	// (the upstream's agent-facing output). Two goroutines so a
	// slow read on one side does not block the other.
	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(stdin, os.Stdin)
		_ = stdin.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, stdout)
		_ = stdout.Close()
		done <- struct{}{}
	}()

	// Wait for both pumps to exit. A non-clean exit on the mock's
	// read loop (e.g. malformed frame) shows up on errCh; we log
	// it so the test's stderr captures the failure mode.
	select {
	case err := <-errCh:
		log.Printf("mock_upstream_runner: %v", err)
	case <-done:
	}
	<-done
}
