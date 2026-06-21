//go:build integration

// OpenAI Agents SDK framework integration tests for mcp-socd (Plan
// U10).
//
// These tests start the proxy with the mock upstream and then
// invoke the OpenAI Agents SDK fixture (test/integration/fixtures/
// openai_agents_agent.py) which uses MCPServerStdio to talk to the
// proxy. The fixture issues one tools/call and exits, so the
// test loop is bounded.
//
// Tests in this file are build-tagged `integration` so plain
// `go test ./...` does not require the OpenAI Agents SDK to be
// installed. The integration suite is invoked via
// `make test-integration`.
//
// Skip semantics: if the `openai-agents` Python package is not
// installed (ModuleNotFoundError on import), the tests t.Skip
// with a clear message. They never hard-fail because the
// integration environment is operator-supplied.
package integration

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"mcp-socd/internal/config"
)

// TestOpenAIAgents_AllowAllowedAction — happy path: the OpenAI
// Agents SDK fixture issues submit_edr_query against the proxy;
// the proxy allows it; the result returns from the mock upstream.
//
// Pre-conditions: Python on PATH; the openai-agents package
// installed; the proxy + mock-upstream-runner binaries build.
// Any missing pre-condition causes a t.Skip.
func TestOpenAIAgents_AllowAllowedAction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test; skipped in -short mode")
	}
	py := findPythonPath(t)
	fixture := fixturePath(t, "openai_agents_agent.py")
	proxyBin := buildProxyBinary(t)
	mockBin := buildMockRunnerBinary(t)

	cfg := defaultTestConfig()
	_, _ = runProxyWithConfig(t, proxyBin, mockBin, cfg)

	// Drive the agent fixture. It opens an MCPServerStdio
	// connection to the proxy and issues submit_edr_query.
	proxyCmd := []string{proxyBin, "--config", writeTempYAML(t, "agent-side.yaml", cfg)}
	stdoutStr, stderrStr, exitCode, _ := runAgent(t, py, fixture, "submit_edr_query",
		map[string]any{"query": "event_simpleName=ProcessRollup2"},
		proxyCmd)

	// Skip cleanly when the SDK is missing. The fixture catches
	// the ImportError and re-raises as "tool call failed: <msg>";
	// we accept either shape so the skip is robust across SDK
	// versions.
	if exitCode != 0 {
		if strings.Contains(stderrStr, "ModuleNotFoundError") ||
			strings.Contains(stderrStr, "ImportError") ||
			strings.Contains(stderrStr, "No module named") {
			t.Skip("openai-agents SDK not installed; skipping")
		}
		t.Logf("agent stderr:\n%s", stderrStr)
		t.Logf("agent stdout:\n%s", stdoutStr)
		t.Fatalf("agent exited %d", exitCode)
	}

	// Decode the agent's JSON payload and assert success.
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
}

// keep the imports tidy and avoid "imported and not used" if a
// follow-up test trims dependencies.
var (
	_ = bytes.Buffer{}
	_ = config.SchemaVersion
)
