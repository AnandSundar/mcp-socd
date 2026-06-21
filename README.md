# mcp-socd

MCP-aware security proxy that mediates AI agent tool calls against a SOC-action catalog. Default-denies destructive actions, requires out-of-band approval for high-blast-radius operations, and emits OCSF audit records to a SIEM.

> Status: pre-1.0, under active development. See `docs/plans/2026-06-20-001-feat-mcp-socd-plan.md` for the implementation plan and `docs/brainstorms/2026-06-20-ai-agent-containment-soc-requirements.md` for the requirements.

## Quickstart

Documentation lands with the v1 release (U11). For now:

- Requirements: Go 1.23+ (tested on 1.25)
- Build: `make build`
- Run: `./bin/mcp-socd --help`
- Test: `make test`

## Configuration

Configuration lives at the XDG-resolved path (`$XDG_CONFIG_HOME/mcp-socd/config.yaml` on Linux, `~/Library/Application Support/mcp-socd/config.yaml` on macOS, `%LOCALAPPDATA%\mcp-socd\config.yaml` on Windows). Override with `--config /path/to/config.yaml`.

## License

Apache-2.0. See `LICENSE`.
