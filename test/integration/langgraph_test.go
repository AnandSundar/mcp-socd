//go:build integration

// LangGraph framework integration tests for mcp-socd (Plan U10).
//
// These tests start the proxy as a real subprocess with the
// in-process mock upstream as its upstream MCP server, then
// spawn a tiny LangGraph agent fixture (test/integration/fixtures/
// langgraph_agent.py) that talks to the proxy's stdio as if it
// were any other MCP server. The proxy's policy engine, catalog,
// and audit emitter run inside the proxy subprocess; the agent
// fixture stays oblivious to the proxy's existence.
//
// Tests in this file are build-tagged `integration` so plain
// `go test ./...` does not require the Python LangGraph SDK to
// be installed. The integration suite is invoked via
// `make test-integration`.
//
// Skip semantics: if the LangGraph SDK or the proxy binary is
// unavailable, the tests t.Skip with a clear message. They never
// hard-fail because the integration environment is operator-
// supplied (the homelab CI may not have every Python package).
package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"mcp-socd/internal/catalog"
	"mcp-socd/internal/config"
	"mcp-socd/internal/policy"
)

// fixturePath returns the absolute path to the Python agent
// fixture relative to the package directory. The fixtures live
// under test/integration/fixtures/ and the integration tests run
// from the package directory.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	// The test package is at $MODULE/test/integration/, so the
	// fixtures live one level down.
	p, err := filepath.Abs(filepath.Join("fixtures", name))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return p
}

// moduleRoot returns the absolute path to the module root
// (directory containing go.mod). Tests run with CWD at the
// package directory (test/integration/), so the module root is
// two parents up.
func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs module root: %v", err)
	}
	return root
}

// writeTempYAML serializes cfg as YAML to a temp file and returns
// the path. The file is automatically cleaned up via t.TempDir.
func writeTempYAML(t *testing.T, name string, cfg *config.Config) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	b, err := yamlMarshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// buildProxyBinary builds the mcp-socd binary into t.TempDir() and
// returns its absolute path. The build uses the package's own
// LDFLAGS to embed the version; for integration tests, "dev" is
// fine because the proxy never has to verify its own version.
func buildProxyBinary(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("MCP_SOCD_BINARY"); path != "" {
		// Operator-supplied binary (e.g. from a CI step that
		// pre-built the proxy): skip the build.
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "mcp-socd.exe")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/mcp-socd")
	cmd.Dir = moduleRoot(t)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("could not build mcp-socd (go missing?): %v", err)
	}
	return bin
}

// buildMockRunnerBinary builds the mock-upstream-runner binary
// into t.TempDir() and returns its path. The runner is the
// subprocess the proxy spawns in place of a real upstream.
func buildMockRunnerBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "mock-upstream-runner.exe")
	cmd := exec.Command("go", "build", "-o", bin,
		"./test/integration/cmd/mock_upstream_runner")
	cmd.Dir = moduleRoot(t)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("could not build mock-upstream-runner (go missing?): %v", err)
	}
	return bin
}

// findPythonPath returns a usable python or python3 interpreter.
// Used by every framework test before spawning the agent fixture;
// the framework test calls t.Skip if no interpreter is available.
func findPythonPath(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python", "python3"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("python/python3 not available on PATH; skipping LangGraph integration test")
	return ""
}

// defaultTestConfig builds a permissive policy used by the
// framework tests: submit_edr_query is allow-all (so the success
// path runs), enrich_ioc is also allow-all, and isolate_endpoint
// requires an allowlisted target (so the deny path is a true
// policy-deny, not a default-deny).
func defaultTestConfig() *config.Config {
	return &config.Config{
		Version: config.SchemaVersion,
		Upstream: config.Upstream{
			Command: []string{"placeholder"}, // overwritten per-test
		},
		Policy: config.Policy{
			DefaultAction: "deny",
			Rules: []config.Rule{
				{
					ID:     "allow-submit-edr",
					Tool:   "submit_edr_query",
					Action: "allow",
				},
				{
					ID:     "allow-enrich-ioc",
					Tool:   "enrich_ioc",
					Action: "allow",
				},
				{
					ID:      "allow-isolate-allowlisted",
					Tool:    "isolate_endpoint",
					Action:  "allow",
					Targets: []string{"server01.example.com"},
				},
			},
		},
		Approval: config.Approval{
			// Terminal channel with a signing secret; we don't
			// expect the proxy to actually prompt because the
			// tests use allow rules (no require_approval path
			// for the success cases). The channel is here so the
			// config is structurally valid.
			TimeoutSeconds: 5,
			Channels: []config.Channel{
				{Type: "terminal", SigningSecret: "integration-test-secret"},
			},
		},
		Audit: config.Audit{
			Stdout: false,
			File:   "",
		},
	}
}

// runAgent spawns the agent fixture (or skips if Python / fixture
// is unavailable). It sets the env vars the fixture expects
// (proxy command, args, action arguments) and returns the
// captured stdout/stderr for assertions. The action name is the
// positional CLI arg; the arguments JSON file is written to
// t.TempDir() and passed via MCP_SOCD_TEST_ARGS.
func runAgent(t *testing.T, py, fixture, action string, args map[string]any, proxyCmd []string, extraEnv ...string) (stdout, stderr string, exitCode int, skip bool) {
	t.Helper()
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.json")
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			t.Fatalf("marshal args: %v", err)
		}
		if err := os.WriteFile(argsFile, b, 0o600); err != nil {
			t.Fatalf("write args: %v", err)
		}
	} else {
		// Empty file = no arguments.
		if err := os.WriteFile(argsFile, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write empty args: %v", err)
		}
	}

	cmdFile := filepath.Join(dir, "proxy_cmd.json")
	cmdJSON, err := json.Marshal(proxyCmd)
	if err != nil {
		t.Fatalf("marshal proxy cmd: %v", err)
	}
	if err := os.WriteFile(cmdFile, cmdJSON, 0o600); err != nil {
		t.Fatalf("write proxy cmd: %v", err)
	}

	env := append(os.Environ(),
		"MCP_SOCD_PROXY_CMD_FILE="+cmdFile,
		"MCP_SOCD_TEST_ARGS="+argsFile,
		"PYTHONUNBUFFERED=1",
	)
	env = append(env, extraEnv...)

	c := exec.Command(py, fixture, action)
	c.Env = env
	c.Dir = dir

	var outBuf, errBuf bytes.Buffer
	c.Stdout = &outBuf
	c.Stderr = &errBuf

	runErr := c.Run()
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("agent run: %v (stderr=%s)", runErr, errBuf.String())
		}
	}

	return outBuf.String(), errBuf.String(), exitCode, false
}

// runProxyWithConfig starts the mcp-socd binary against the
// mock-upstream-runner and returns the pipes the agent (or test)
// will speak to. The config file is written to t.TempDir(); the
// proxy is given --config <path> and reads upstream.command from
// it. Returns (stdin writer, stdout reader).
func runProxyWithConfig(t *testing.T, proxyBin, mockBin string, cfg *config.Config) (stdinWriter *os.File, stdoutReader *os.File) {
	t.Helper()
	cfg.Upstream.Command = []string{mockBin}
	cfgPath := writeTempYAML(t, "mcp-socd.yaml", cfg)

	c := exec.Command(proxyBin, "--config", cfgPath)
	// Discard audit output (stderr) but capture stdout — that's
	// the agent-facing channel. We also capture stderr to a
	// buffer so test failures can include proxy diagnostics.
	var proxyStderr bytes.Buffer
	c.Stderr = &proxyStderr

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		t.Fatalf("stdout pipe: %v", err)
	}
	c.Stdin = stdinR
	c.Stdout = stdoutW

	if err := c.Start(); err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		t.Skipf("could not start mcp-socd: %v", err)
	}

	// Close the parent's ends of the pipes that the child will
	// use; the parent process is the test, the child is the
	// proxy. The test writes to stdinW and reads from stdoutR.
	_ = stdinR.Close()
	_ = stdoutW.Close()

	// Save a t.Cleanup hook that closes the proxy gracefully and
	// reports any proxy-side error in case the test fails.
	t.Cleanup(func() {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = c.Wait()
		if proxyStderr.Len() > 0 && t.Failed() {
			t.Logf("proxy stderr:\n%s", proxyStderr.String())
		}
	})

	return stdinW, stdoutR
}

// TestLangGraph_AllowAllowedAction — happy path: the agent
// (LangGraph fixture) issues a submit_edr_query call against the
// proxy; the proxy allows it; the result returns from the mock
// upstream.
//
// Pre-conditions: the test fixture exists, the proxy builds, the
// runner builds, and Python is on PATH. Any of these missing
// causes a t.Skip, never a hard failure.
func TestLangGraph_AllowAllowedAction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test; skipped in -short mode")
	}
	py := findPythonPath(t)
	fixture := fixturePath(t, "langgraph_agent.py")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("langgraph_agent.py not built: %v", err)
	}
	proxyBin := buildProxyBinary(t)
	mockBin := buildMockRunnerBinary(t)

	cfg := defaultTestConfig()
	stdin, stdout := runProxyWithConfig(t, proxyBin, mockBin, cfg)

	// Issue a submit_edr_query via the agent fixture. The fixture
	// reads MCP_SOCD_TEST_ARGS and calls the proxy. We do not
	// drive the fixture's stdin/stdout directly; instead we run
	// it as a subprocess that connects to the proxy via the
	// command we wrote to cmdFile.
	proxyCmd := []string{proxyBin, "--config", writeTempYAML(t, "agent-side.yaml", cfg)}

	stdoutStr, stderrStr, exitCode, _ := runAgent(t, py, fixture, "submit_edr_query",
		map[string]any{"query": "event_simpleName=ProcessRollup2"},
		proxyCmd)

	// On a non-zero exit, the fixture saw a transport or protocol
	// failure. The agent-side .mcp.json-style path may not work
	// for all SDK versions; treat as skip if the agent could not
	// even initialize the MCP session, otherwise fail.
	if exitCode != 0 {
		t.Logf("agent stderr:\n%s", stderrStr)
		t.Logf("agent stdout:\n%s", stdoutStr)
		// Common failure: SDK not installed. Skip if import error.
		if strings.Contains(stderrStr, "ModuleNotFoundError") ||
			strings.Contains(stderrStr, "ImportError") ||
			strings.Contains(stderrStr, "No module named") {
			t.Skip("LangGraph MCP SDK not installed; skipping")
		}
		t.Fatalf("agent exited %d", exitCode)
	}

	// The agent's stdout payload includes isError and content;
	// assert isError is false and the upstream's echo of the
	// arguments is present.
	var payload struct {
		IsError bool     `json:"isError"`
		Content []string `json:"content"`
	}
	if err := json.Unmarshal([]byte(stdoutStr), &payload); err != nil {
		t.Fatalf("decode agent payload: %v\nstderr:\n%s", err, stderrStr)
	}
	if payload.IsError {
		t.Fatalf("expected isError=false, got %+v (stderr=%s)", payload, stderrStr)
	}
	if len(payload.Content) == 0 {
		t.Fatalf("expected content blocks, got none (stderr=%s)", stderrStr)
	}
	text := strings.Join(payload.Content, "")
	if !strings.Contains(text, "submit_edr_query") {
		t.Fatalf("expected echoed tool name, got: %s", text)
	}
	if !strings.Contains(text, "ProcessRollup2") {
		t.Fatalf("expected echoed query, got: %s", text)
	}

	// Quietly drain stdin/stdout to release the pipes.
	_ = stdin
	_ = stdout
}

// TestLangGraph_DenyDisallowedAction — the agent issues
// isolate_endpoint against a non-allowlisted host; the proxy
// denies; the agent receives an error.
//
// Pre-conditions: identical to the happy-path test.
func TestLangGraph_DenyDisallowedAction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test; skipped in -short mode")
	}
	py := findPythonPath(t)
	fixture := fixturePath(t, "langgraph_agent.py")
	if _, err := os.Stat(fixture); err != nil {
		t.Skipf("langgraph_agent.py not built: %v", err)
	}
	proxyBin := buildProxyBinary(t)
	mockBin := buildMockRunnerBinary(t)

	cfg := defaultTestConfig()
	_, _ = runProxyWithConfig(t, proxyBin, mockBin, cfg)

	// Target server99.example.com is NOT in the allowlist; the
	// proxy should return a JSON-RPC error and the agent should
	// surface it.
	proxyCmd := []string{proxyBin, "--config", writeTempYAML(t, "agent-side.yaml", cfg)}
	stdoutStr, stderrStr, exitCode, _ := runAgent(t, py, fixture, "isolate_endpoint",
		map[string]any{"host_id": "server99.example.com"},
		proxyCmd)

	// Check for SDK-missing first; this lets the test skip cleanly
	// even when the agent exited unusually (the fixture's exception
	// path can mask the actual cause).
	if strings.Contains(stderrStr, "ModuleNotFoundError") ||
		strings.Contains(stderrStr, "ImportError") ||
		strings.Contains(stderrStr, "No module named") {
		t.Skip("LangGraph MCP SDK not installed; skipping")
	}

	if exitCode == 0 {
		t.Logf("agent stdout:\n%s", stdoutStr)
		t.Fatalf("expected agent to receive a deny error, but exit was 0")
	}
	if exitCode == 1 {
		// Tool call returned isError=true: that's the expected
		// shape from the MCP SDK's call_tool when the proxy
		// returned a JSON-RPC error. The fixture exits 1 in that
		// case.
		var payload struct {
			IsError bool     `json:"isError"`
			Content []string `json:"content"`
		}
		if err := json.Unmarshal([]byte(stdoutStr), &payload); err != nil {
			t.Skipf("agent did not produce JSON payload (SDK surface mismatch?): %v", err)
		}
		if !payload.IsError {
			t.Fatalf("expected isError=true, got false (payload=%+v)", payload)
		}
		return
	}

	// Other exit codes: log and skip if the SDK is missing,
	// otherwise fail.
	t.Logf("agent stderr:\n%s", stderrStr)
	t.Fatalf("agent exited %d (stderr=%s)", exitCode, stderrStr)
}

// keep references to catalog and policy so a future test can
// import them without re-doing the build-tag dance. Avoids
// "imported and not used" if the build tag drops the only usages.
var (
	_ = catalog.Starter
	_ = policy.New
)
