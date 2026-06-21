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
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"mcp-socd/internal/config"
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

// runRoot loads the config, applies CLI overrides, installs signal
// handlers, and starts the proxy loop. The actual proxy loop is
// implemented in U4; U1 wires up the scaffolding only.
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

	// Install signal handlers. SIGHUP triggers config reload; SIGTERM
	// and SIGINT trigger graceful drain. The proxy loop (U4) will
	// register the actual handler callbacks; for U1 we just confirm
	// the signals are observable.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for s := range sigCh {
			fmt.Fprintf(os.Stderr, "mcp-socd: received signal %s (handlers wired in U4+)\n", s)
		}
	}()

	// U1 placeholder: the proxy loop is implemented in U4. We block
	// here so the binary stays up, observing signals, until the user
	// kills it.
	select {}
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
