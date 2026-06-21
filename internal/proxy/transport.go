package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"mcp-socd/internal/config"
)

// childProcess bundles an os/exec.Cmd with its connected stdio pipes
// and a once-protected shutdown path. The proxy uses one childProcess
// per Run; the parent goroutine owns the lifecycle (start, wait,
// shutdown).
//
// All public methods are safe for concurrent use. Wait and Shutdown
// coordinate via a sync.Once so double-close of the pipes is
// impossible.
type childProcess struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	stdout   io.ReadCloser
	waitOnce sync.Once
	waitErr  error
}

// spawnUpstream starts the configured upstream MCP server and wires
// its stdio to the returned childProcess. The command is taken from
// cfg.Command; if the list is empty (or has only one element, which is
// an invalid exec form), spawnUpstream returns an error so the proxy
// exits cleanly instead of trying to spawn nothing.
//
// The returned childProcess owns the *exec.Cmd; callers MUST call
// Shutdown to release the resources. spawnUpstream does NOT install
// signal handlers; the proxy.Run loop is responsible for forwarding
// os.Stdin EOF into a child shutdown.
func spawnUpstream(ctx context.Context, cfg *config.Upstream) (*childProcess, error) {
	if cfg == nil || len(cfg.Command) == 0 {
		return nil, errors.New("proxy: upstream command is empty")
	}

	cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...)
	// Inherit the proxy's own environment by default; overlay the
	// operator's overrides from cfg.Env so a config can add or replace
	// specific variables without rewriting the whole environment.
	cmd.Env = append([]string(nil), os.Environ()...)
	for k, v := range cfg.Env {
		cmd.Env = appendOrSetEnv(cmd.Env, k, v)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("proxy: upstream stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, fmt.Errorf("proxy: upstream stdout pipe: %w", err)
	}
	// Discard the upstream's stderr so its diagnostic output does not
	// pollute the proxy's stdout (MCP stdio transport: stdout purity
	// is a spec-compliance requirement). Operators that want to see
	// upstream diagnostics can run the proxy with stderr captured
	// separately and inspect the upstream's own logs.
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("proxy: start upstream %v: %w", cfg.Command, err)
	}

	return &childProcess{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
	}, nil
}

// Wait blocks until the child exits and returns its exit error. Safe
// to call multiple times; only the first call invokes cmd.Wait.
func (c *childProcess) Wait() error {
	c.waitOnce.Do(func() {
		c.waitErr = c.cmd.Wait()
	})
	return c.waitErr
}

// Shutdown closes the child's stdin (signalling EOF to the upstream
// server), waits for it to exit, and closes the stdout pipe. It is
// idempotent; subsequent calls return the result of the first Wait.
//
// Shutdown does not kill the process forcibly. The MCP stdio wrapper
// convention is that the upstream server exits when its stdin closes;
// if the server does not honour that, the caller's context will
// eventually cancel and os/exec will SIGKILL via CommandContext.
func (c *childProcess) Shutdown() error {
	// Closing stdin is best-effort; an already-closed pipe returns an
	// error we deliberately swallow because the Wait path is the
	// authoritative exit source.
	_ = c.stdin.Close()
	waitErr := c.Wait()
	_ = c.stdout.Close()
	return waitErr
}

// Stdin returns the upstream server's stdin pipe. The proxy writes
// framed JSON-RPC requests here.
func (c *childProcess) Stdin() io.Writer { return c.stdin }

// Stdout returns the upstream server's stdout pipe wrapped in a
// buffered reader. The proxy reads framed JSON-RPC responses from
// here.
func (c *childProcess) Stdout() *bufio.Reader { return bufio.NewReader(c.stdout) }

// appendOrSetEnv returns env with key=value appended if key is not
// already present, or with the existing entry replaced otherwise.
// Used to apply cfg.Upstream.Env overrides without losing the
// inherited process environment.
func appendOrSetEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}
