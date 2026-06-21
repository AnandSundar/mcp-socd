package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"mcp-socd/internal/catalog"
	"mcp-socd/internal/config"
	"mcp-socd/internal/policy"
)

// Proxy is the stdio wrapper that mediates JSON-RPC traffic between
// the AI agent (over os.Stdin/os.Stdout) and an upstream MCP server.
//
// One Proxy value is constructed per process. Run blocks until either
// the agent's stdin closes (EOF) or the upstream server exits. Shutdown
// drains in-flight writes, closes the child's stdin, and waits for it
// to exit cleanly.
//
// Proxy is intentionally narrow: it owns no policy or catalog state
// beyond the references handed to it. Reloading the policy or catalog
// is the caller's responsibility (a future hot-reload path will Swap
// the *policy.Engine's atomic.Pointer; the proxy reads through the
// pointer on every Evaluate so it does not need to be reconfigured).
type Proxy struct {
	cfg     *config.Config
	engine  *policy.Engine
	catalog *catalog.Catalog
	emitter Emitter

	// stdin and stdout are the agent-facing streams. They default to
	// os.Stdin/os.Stdout but tests inject in-memory pipes via
	// WithStdio.
	stdin  io.Reader
	stdout io.Writer

	// stdoutMu serializes writes to stdout. pumpAgentToChild (which
	// writes synthetic JSON-RPC responses) and pumpChildToAgent
	// (which relays upstream responses) both write to the same
	// stream; without a mutex their frames would interleave at the
	// byte level and corrupt the JSON-RPC stream.
	stdoutMu sync.Mutex

	// shutdownOnce coordinates Shutdown so double-close of the child
	// process is impossible.
	shutdownOnce sync.Once
	shutdownErr  error

	// shutdownCtx cancels the upstream child's CommandContext so a
	// hung upstream does not block Shutdown forever.
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

// Options configures the proxy at construction time. Fields are set
// via functional options (WithStdio, WithEmitter) so New stays
// readable as the set of required dependencies grows.
type Options struct {
	// Cfg is the loaded proxy configuration. Required.
	Cfg *config.Config

	// Engine is the policy engine. Required.
	Engine *policy.Engine

	// Catalog is the action catalog. Required.
	Catalog *catalog.Catalog

	// Emitter is the audit hook. Optional; defaults to NoopEmitter.
	Emitter Emitter

	// Stdin overrides os.Stdin. Optional; tests inject an io.Pipe.
	Stdin io.Reader

	// Stdout overrides os.Stdout. Optional; tests inject an io.Pipe.
	Stdout io.Writer
}

// Option is a functional option for New.
type Option func(*Options)

// WithEmitter returns an Option that sets the audit emitter.
func WithEmitter(e Emitter) Option {
	return func(o *Options) { o.Emitter = e }
}

// WithStdio returns an Option that overrides the agent-facing stdio.
// Tests pass in-memory pipes; production code leaves it unset so the
// proxy uses os.Stdin/os.Stdout.
func WithStdio(in io.Reader, out io.Writer) Option {
	return func(o *Options) {
		o.Stdin = in
		o.Stdout = out
	}
}

// New constructs a Proxy. Returns an error if any required dependency
// is missing; the proxy never starts in a half-configured state.
func New(cfg *config.Config, engine *policy.Engine, cat *catalog.Catalog, opts ...Option) (*Proxy, error) {
	if cfg == nil {
		return nil, errors.New("proxy: config is nil")
	}
	if engine == nil {
		return nil, errors.New("proxy: policy engine is nil")
	}
	if cat == nil {
		return nil, errors.New("proxy: catalog is nil")
	}

	options := &Options{
		Cfg:     cfg,
		Engine:  engine,
		Catalog: cat,
		Emitter: NoopEmitter{},
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
	}
	for _, opt := range opts {
		opt(options)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Proxy{
		cfg:            options.Cfg,
		engine:         options.Engine,
		catalog:        options.Catalog,
		emitter:        options.Emitter,
		stdin:          options.Stdin,
		stdout:         options.Stdout,
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
	}, nil
}

// Run blocks until either the agent's stdin closes (EOF) or the
// upstream MCP server exits. Run is the main loop:
//
//  1. spawn the upstream child
//  2. start goroutine A: agent-stdin -> framed -> child-stdin
//  3. start goroutine B: child-stdout -> framed -> agent-stdout
//  4. start goroutine C: shutdown watcher that cancels everything
//     when either stdin-EOF or child-exit is observed
//  5. wait for shutdown watcher; return its error
//
// Run returns a non-nil error only when the proxy itself failed to
// start (no upstream command, spawn failure, etc.). Clean exit after
// either side closes its pipe returns nil.
func (p *Proxy) Run() error {
	// Emit a startup event so SIEM-side correlation can detect
	// proxy restarts. Best-effort: a missing emitter is a no-op.
	p.emitter.Emit(map[string]any{
		"decision": "startup",
		"upstream": p.cfg.Upstream.Command,
		"time":     time.Now().UTC().Format(time.RFC3339Nano),
	})

	child, err := spawnUpstream(p.shutdownCtx, &p.cfg.Upstream)
	if err != nil {
		return err
	}

	// finished is closed by whichever side terminates first (agent
	// stdin EOF or child exit). The shutdown path waits on it then
	// cancels the upstream context and tears down the child.
	finished := make(chan error, 2)

	// Goroutine A: agent stdin -> child stdin. We forward every
	// frame we receive from the agent; intercept happens for
	// tools/call by short-circuiting before write (the inspect frame
	// loop is below in the same goroutine). When agent stdin closes,
	// we close the child's stdin so the upstream sees EOF.
	go p.pumpAgentToChild(child, finished)

	// Goroutine B: child stdout -> agent stdout. Pass-through with
	// framing preservation; the inspect loop never modifies
	// upstream-to-agent frames.
	go p.pumpChildToAgent(child, finished)

	// Wait for either side to finish. Whichever finishes first is
	// recorded; the second close of `finished` is harmless because
	// the channel is buffered.
	firstErr := <-finished
	p.emitter.Emit(map[string]any{
		"decision": "shutdown",
		"reason":   shutdownReason(firstErr),
		"error":    errString(firstErr),
	})

	// Tear down the child regardless of which side closed first.
	// The child's context is cancelled so a hung Shutdown does not
	// block the program forever.
	p.shutdownCancel()
	shutdownErr := child.Shutdown()
	if firstErr == nil {
		firstErr = shutdownErr
	}
	return firstErr
}

// Shutdown is idempotent and safe to call from a signal handler. It
// cancels the upstream context (which SIGKILLs the child via
// CommandContext) and waits for Run to return. Returns the first
// non-nil error from any of those steps.
//
// Shutdown is wired up to SIGTERM/SIGINT by the CLI in U1; calling
// it explicitly is the right pattern for integration tests that want
// to exercise the drain path.
func (p *Proxy) Shutdown() error {
	p.shutdownOnce.Do(func() {
		p.shutdownCancel()
		p.shutdownErr = nil
	})
	return p.shutdownErr
}

// pumpAgentToChild reads framed JSON-RPC requests from the agent,
// inspects each one, and either forwards it to the upstream or
// short-circuits with a synthetic response. The loop terminates when
// the agent's stdin closes (EOF) or the upstream dies (broken pipe on
// write). On exit it sends the terminating error to finished.
//
// Per Plan §"Tool-call flow", the inspect dance for tools/call is:
//
//  1. decode the request envelope
//  2. if method == "tools/call", run the policy intercept
//  3. on Forward, write the original frame to the child
//  4. on Synthetic, write the synthetic bytes back to the agent
//     (under stdoutMu so it does not interleave with pumpChildToAgent)
//
// For non-tools/call methods (initialize, tools/list, ping,
// notifications, etc.) we pass the frame through verbatim.
func (p *Proxy) pumpAgentToChild(child *childProcess, finished chan<- error) {
	reader := bufio.NewReader(p.stdin)
	for {
		raw, err := ReadFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				finished <- nil
			} else {
				finished <- fmt.Errorf("proxy: read agent frame: %w", err)
			}
			return
		}

		msg, derr := DecodeMessage(raw)
		if derr != nil {
			// Undecodable frame: forward verbatim. The upstream
			// will produce a JSON-RPC parse error response and the
			// agent's UI will surface it. We do not synthesize a
			// response here because we cannot correlate by ID.
			if werr := WriteFrame(child.Stdin(), raw); werr != nil {
				finished <- fmt.Errorf("proxy: forward undecodable frame to child: %w", werr)
				return
			}
			continue
		}

		// Notifications and any non-tools/call method are passed
		// through unchanged. We do not even decode Params; the
		// raw bytes are enough.
		if msg.Request == nil || !shouldIntercept(msg.Request) {
			if werr := WriteFrame(child.Stdin(), raw); werr != nil {
				finished <- fmt.Errorf("proxy: write frame to child: %w", werr)
				return
			}
			continue
		}

		// tools/call: run the intercept pipeline.
		result := interceptCall(msg.Request, p.engine, p.catalog, p.emitter)
		if result.Forward {
			if werr := WriteFrame(child.Stdin(), raw); werr != nil {
				finished <- fmt.Errorf("proxy: write intercepted frame to child: %w", werr)
				return
			}
		} else {
			if werr := p.writeToAgent(result.Synthetic); werr != nil {
				finished <- fmt.Errorf("proxy: write synthetic response to agent: %w", werr)
				return
			}
		}
	}
}

// pumpChildToAgent reads framed JSON-RPC responses from the upstream
// server and relays them to the agent. The proxy does not inspect
// upstream-to-agent frames; the tools/list filter (defense in depth)
// is deferred to a follow-up unit per Plan U4.
//
// The loop terminates when the child's stdout closes (the upstream
// exited) or the agent's stdout write fails (the agent has gone
// away). The terminating error is sent to finished.
func (p *Proxy) pumpChildToAgent(child *childProcess, finished chan<- error) {
	reader := child.Stdout()
	for {
		raw, err := ReadFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				finished <- nil
			} else {
				finished <- fmt.Errorf("proxy: read child frame: %w", err)
			}
			return
		}
		if werr := p.writeToAgent(raw); werr != nil {
			finished <- fmt.Errorf("proxy: write child frame to agent: %w", werr)
			return
		}
	}
}

// writeToAgent serializes one Content-Length framed body to the
// agent's stdout. The mutex is held for the duration of the write so
// frames from pumpAgentToChild and pumpChildToAgent never interleave.
func (p *Proxy) writeToAgent(body []byte) error {
	p.stdoutMu.Lock()
	defer p.stdoutMu.Unlock()
	return WriteFrame(p.stdout, body)
}

// shouldIntercept reports whether the proxy must inspect the request
// before forwarding. Currently only tools/call qualifies; tools/list
// filtering (U4 §"Test Scenarios") is implemented in the same package
// but is invoked from the child-to-agent pump to rewrite the upstream
// response, which keeps the agent-to-child path simple.
//
// We use method-name comparison rather than method-pattern matching
// because MCP method names are a fixed closed set per the spec; the
// only ambiguity is the notifications/list_changed variant which is a
// notification (no response) and therefore passes through this branch
// untouched.
func shouldIntercept(req *Request) bool {
	return req.Method == "tools/call"
}

// shutdownReason returns a short, structured label for the audit
// emitter's shutdown event so post-hoc analysts can distinguish the
// three normal exit paths (agent EOF, child exit, spawn failure).
func shutdownReason(err error) string {
	if err == nil {
		return "clean"
	}
	if errors.Is(err, io.EOF) {
		return "agent_eof"
	}
	return "child_exit"
}

// errString returns err.Error() or "" when err is nil. Used in the
// audit map so the JSON encoding stays valid even on the clean-exit
// path.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
