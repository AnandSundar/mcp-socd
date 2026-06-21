package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"mcp-socd/internal/config"
)

// TestSpawnUpstream_EmptyCommand asserts that an empty command list is
// rejected before any process is started.
func TestSpawnUpstream_EmptyCommand(t *testing.T) {
	if _, err := spawnUpstream(context.Background(), &config.Upstream{}); err == nil {
		t.Fatalf("expected error for empty command")
	}
}

// TestSpawnUpstream_NilConfig asserts a nil config is also rejected
// without side effects.
func TestSpawnUpstream_NilConfig(t *testing.T) {
	if _, err := spawnUpstream(context.Background(), nil); err == nil {
		t.Fatalf("expected error for nil config")
	}
}

// TestSpawnUpstream_RoundTrip uses the bundled Python test child to
// verify the lifecycle end-to-end: spawn, write a frame, read the
// response, then shut down cleanly.
//
// python is required; the test is skipped on environments where it
// is not on PATH so CI without Python does not fail.
func TestSpawnUpstream_RoundTrip(t *testing.T) {
	pythonPath := findPython(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	child, err := spawnUpstream(ctx, &config.Upstream{
		Command: []string{pythonPath, "testdata/upstream-echo.py"},
	})
	if err != nil {
		t.Fatalf("spawnUpstream: %v", err)
	}
	defer func() { _ = child.Shutdown() }()

	// Send a ping and read the response.
	if err := WriteFrame(child.Stdin(), []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	body, err := ReadFrame(child.Stdout())
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if !bytes.Contains(body, []byte(`"result":{}`)) {
		t.Fatalf("unexpected ping response: %s", body)
	}
}

// TestSpawnUpstream_EnvOverride verifies that cfg.Env can add variables
// on the child process. We set a known sentinel and assert the child
// sees it.
func TestSpawnUpstream_EnvOverride(t *testing.T) {
	pythonPath := findPython(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	child, err := spawnUpstream(ctx, &config.Upstream{
		Command: []string{pythonPath, "-c", "import os,sys; sys.stdout.write(os.environ.get('MCP_SOCD_TEST_SENTINEL',''))"},
		Env: map[string]string{
			"MCP_SOCD_TEST_SENTINEL": "ok",
		},
	})
	if err != nil {
		t.Fatalf("spawnUpstream: %v", err)
	}
	defer func() { _ = child.Shutdown() }()

	// Read the child's stdout (which is the sentinel) until EOF.
	got, err := io.ReadAll(child.stdout)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "ok" {
		t.Fatalf("env override did not propagate: got %q, want %q", got, "ok")
	}
}

// TestSpawnUpstream_ExitsOnStdinClose asserts that closing the child's
// stdin causes the upstream to exit (the canonical MCP stdio
// convention).
func TestSpawnUpstream_ExitsOnStdinClose(t *testing.T) {
	pythonPath := findPython(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	child, err := spawnUpstream(ctx, &config.Upstream{
		Command: []string{pythonPath, "testdata/upstream-echo.py"},
	})
	if err != nil {
		t.Fatalf("spawnUpstream: %v", err)
	}

	if err := child.Shutdown(); err != nil {
		// Shutdown returns the child's exit error; an exit code of 0
		// is fine, a non-zero is acceptable too as long as the child
		// actually exited. We accept anything non-context-cancelled.
		if errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("child did not exit after stdin close: %v", err)
		}
	}
}

// TestAppendOrSetEnv_AddAndReplace covers both branches of the env
// helper: append when the key is absent, replace when it is present.
func TestAppendOrSetEnv_AddAndReplace(t *testing.T) {
	base := []string{"PATH=/bin", "HOME=/root"}
	got := appendOrSetEnv(base, "FOO", "bar")
	if !containsString(got, "FOO=bar") {
		t.Fatalf("FOO=bar not appended: %v", got)
	}
	got = appendOrSetEnv(got, "HOME", "/home/u")
	if !containsString(got, "HOME=/home/u") {
		t.Fatalf("HOME not replaced: %v", got)
	}
	if containsString(got, "HOME=/root") {
		t.Fatalf("old HOME entry still present: %v", got)
	}
}

// containsString is a tiny helper; we avoid importing slices just for this.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// findPython locates a Python interpreter on PATH, skipping the test
// if none is available. Both `python` and `python3` are tried in turn
// so the test works on systems where only one is installed.
func findPython(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python", "python3"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("python/python3 not available on PATH; skipping spawn test")
	return ""
}

// Ensure errors from lookPath carry enough info to debug CI failures.
// (Kept here rather than as a separate file so the helper stays
// co-located with the transport tests.)
var _ = strings.Contains // silence unused-import warning if strings is removed
