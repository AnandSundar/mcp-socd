// Package cli implements the mcp-socd cobra command tree.
//
// Usage:
//
//	mcp-socd [flags] [--] <upstream-command> [args...]
//
// If positional args are provided, they override the upstream.command
// list from the config file. The config file is the recommended source
// for the upstream command in production.
package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"mcp-socd/internal/catalog"
	"mcp-socd/internal/config"
	"mcp-socd/internal/policy"
	"mcp-socd/internal/proxy"
	"mcp-socd/internal/version"
)

// Options carries the resolved runtime configuration from flags, config
// file, and positional args. Built by Execute and consumed by main.
type Options struct {
	// ConfigPath is the path to the YAML config. Empty means XDG default.
	ConfigPath string

	// AuditStdout, when true, emits OCSF records to stdout instead of
	// stderr. CLI override for config.audit.stdout.
	AuditStdout bool

	// UpstreamOverride, when non-empty, replaces config.upstream.command.
	// Populated from positional args.
	UpstreamOverride []string
}

// NewRootCmd builds the cobra root command.
func NewRootCmd() *cobra.Command {
	opts := &Options{}

	cmd := &cobra.Command{
		Use:   "mcp-socd [flags] [--] <upstream-command> [args...]",
		Short: "MCP-aware security proxy for SOC teams",
		Long: `mcp-socd is a stdio proxy that mediates AI agent MCP tool calls against
a SOC-action catalog. Default-denies destructive actions, requires out-of-band
approval for high-blast-radius operations, and emits OCSF audit records.

The upstream MCP server is normally configured via the config file's
upstream.command. Positional args after -- override the config value,
which is useful for quick testing.

Hot-reload: send SIGHUP to reload the config file. Send SIGTERM/SIGINT
to drain in-flight requests and exit cleanly.`,
		Version:           version.String(),
		SilenceUsage:      true,
		SilenceErrors:     true,
		DisableAutoGenTag: true,
		Args:              cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.UpstreamOverride = args
			return runRoot(opts)
		},
	}

	cmd.Flags().StringVar(&opts.ConfigPath, "config", "",
		"path to config file (default: XDG-resolved config.yaml)")
	cmd.Flags().BoolVar(&opts.AuditStdout, "audit-stdout", false,
		"emit OCSF audit records to stdout instead of stderr")

	return cmd
}

// Execute is the entry point called by main.
func Execute() error {
	return NewRootCmd().Execute()
}

// runRoot loads the config, applies CLI overrides, compiles the policy
// engine and catalog, then starts the proxy loop. The stdio wrapper
// and tools/call interception live in internal/proxy (U4). U5 will
// replace proxy.NoopEmitter with the OCSF audit emitter without
// changing this wiring.
func runRoot(opts *Options) error {
	cfgPath, err := resolveConfigPath(opts.ConfigPath)
	if err != nil {
		return err
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	if len(opts.UpstreamOverride) > 0 {
		cfg.Upstream.Command = opts.UpstreamOverride
	}
	if opts.AuditStdout {
		cfg.Audit.Stdout = true
	}

	fmt.Fprintf(os.Stderr,
		"mcp-socd %s\n  config:        %s\n  upstream:      %v\n  audit.stdout:  %v\n  audit.file:    %q\n",
		version.String(), cfgPath, cfg.Upstream.Command, cfg.Audit.Stdout, cfg.Audit.File)

	// Loud warning if the operator has weakened the proxy to
	// default-allow. Plan R1: the proxy default-denies; "allow" is
	// available for homelab/testing only and must emit a loud
	// startup warning. The DestructiveVerb gate still fires (it is
	// an invariant, not a config), so destructive tools are still
	// intercepted even with default_action: allow.
	if cfg.Policy.DefaultAction == "allow" {
		warnDefaultAllow(os.Stderr)
	}

	// Compile the policy engine from the loaded config. We do this
	// before spawning any goroutines so a policy compile failure
	// surfaces immediately as a startup error.
	pol, err := policy.Compile(&cfg.Policy)
	if err != nil {
		return fmt.Errorf("compile policy: %w", err)
	}
	// Stamp the initial policy version; the loader will eventually
	// own this increment during hot-reload.
	pol.Version = 1
	engine := policy.New(pol)

	// Seed the catalog with the five starter actions. Custom action
	// loading happens elsewhere (SIGHUP reload path).
	cat := catalog.New()

	// Wire the proxy. U5 will replace NoopEmitter with the OCSF
	// emitter; the Emitter interface boundary in internal/proxy keeps
	// U4 decoupled from U5.
	p, err := proxy.New(cfg, engine, cat, proxy.WithEmitter(proxy.NoopEmitter{}))
	if err != nil {
		return fmt.Errorf("init proxy: %w", err)
	}

	// Install signal handlers. SIGHUP is reserved for the future
	// hot-reload path; SIGTERM and SIGINT trigger a clean shutdown.
	// Buffered so a signal that arrives mid-shutdown does not get
	// dropped.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	// Run the proxy in a goroutine so the signal handler can trigger
	// Shutdown from another goroutine.
	runDone := make(chan error, 1)
	go func() {
		runDone <- p.Run()
	}()

	select {
	case sig := <-sigCh:
		fmt.Fprintf(os.Stderr, "mcp-socd: received signal %s, shutting down\n", sig)
		_ = p.Shutdown()
	case err := <-runDone:
		if err != nil {
			fmt.Fprintf(os.Stderr, "mcp-socd: proxy exited with error: %v\n", err)
		}
		return err
	}

	// After a signal, wait for the proxy to finish draining.
	if err := <-runDone; err != nil {
		fmt.Fprintf(os.Stderr, "mcp-socd: proxy exited with error: %v\n", err)
		return err
	}
	return nil
}

// resolveConfigPath returns the explicit path if provided, otherwise
// the XDG-resolved default. Reports a clear error when XDG resolution
// fails (e.g. no home directory on a system user).
func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	p, err := config.DefaultConfigPath()
	if err != nil {
		return "", fmt.Errorf("resolve default config path: %w", err)
	}
	return p, nil
}

// warnDefaultAllow prints a loud, multi-line warning to w when the
// operator has set policy.default_action to "allow". Plan R1: the
// proxy default-denies; "allow" is for homelab/testing only and
// must emit a startup warning. The destructive-verb gate is an
// invariant and still fires, so destructive tools are still
// intercepted even with default_action: allow.
//
// Exposed as a package-level function (not just inlined into
// runRoot) so the test can verify the exact text without spinning
// up the full proxy loop.
func warnDefaultAllow(w io.Writer) {
	fmt.Fprint(w,
		"\n"+
			"  ▓▓▓ WARNING: policy.default_action = \"allow\"\n"+
			"  ▓▓▓ The proxy will default-PERMIT any tool call that does not match a rule.\n"+
			"  ▓▓▓ This is for homelab/testing only. Set default_action: deny in production.\n"+
			"  ▓▓▓ (Destructive-verb tools still require out-of-band approval.)\n\n")
}
