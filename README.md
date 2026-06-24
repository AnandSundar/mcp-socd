# mcp-socd

**Default-deny for AI agents in production.**

mcp-socd is a stdio proxy that sits between an AI agent and its MCP server. Every tool call is intercepted, classified against a typed action catalog, and gated by a default-deny policy before it reaches the upstream. High-blast-radius actions get routed to a human via terminal prompt or Slack DM. Every decision lands as an OCSF Detection Finding in your SIEM.

## The problem

You have AI agents deployed in production. They act on credentials. They make real tool calls — isolate endpoints, rotate keys, block users — and you have no action-layer enforcement.

> "Management bought the marketing hype, threw it at us, and now we're stuck trying to figure out how to stop an LLM from accidentally isolating our own domain controllers."
> — r/cybersecurity

Output guardrails don't stop the tool call. Observability is post-hoc. The gap is at the **action layer**, where credentials meet capability.

## What mcp-socd does

A small, static Go binary. One config file. No sidecars, no daemons, no language runtime.

```
┌──────────┐    stdio     ┌──────────┐    stdio     ┌─────────────────┐
│  agent   │ ───JSON-RPC──▶  mcp-socd │ ───JSON-RPC──▶  upstream MCP   │
│ (Claude, │              │  (proxy) │              │  (falcon, splunk │
│  Codex…) │ ◀──JSON-RPC───│          │ ◀──JSON-RPC───│   edr, custom)  │
└──────────┘              └─────┬────┘              └─────────────────┘
                                 │
                                 ▼
                        catalog → policy → audit → approval
```

**Four primitives:**

| | |
|---|---|
| **catalog** | Typed actions with blast radius (1–5) and OCSF audit shape |
| **policy** | Allowlist, default-deny, destructive-verb gate |
| **audit** | OCSF Detection Finding (UID 2004) → JSON-lines to stderr or stdout |
| **approval** | Out-of-band human gate: terminal prompt or Slack DM with HMAC-signed token |

When the agent asks `isolate_endpoint host=dc01.corp`, the proxy:

1. Looks the action up in the catalog. Blast radius is 5. Target is `dc01.corp`.
2. Checks the policy. `dc01.corp` is on no allowlist → `require_approval`.
3. Opens a Slack DM to `@secops` with a one-tap approve/deny block.
4. Emits an OCSF record: `verdict=awaiting_approval actor=agent:v1`.
5. When secops approves, the HMAC-signed token is verified, the action is forwarded, the audit record is updated with the verdict, and the upstream's response is returned to the agent.

The agent never sees a silent failure. The proxy never holds credentials it doesn't need.

## Install

**From source** (works today)

```bash
git clone https://github.com/AnandSundar/mcp-socd.git
cd mcp-socd
make build
./bin/mcp-socd --help
```

**curl-pipe-sh** (lands with v1 release; the script in `scripts/install.sh` is ready)

```bash
curl -fsSL https://raw.githubusercontent.com/AnandSundar/mcp-socd/main/scripts/install.sh | bash
```

**Homebrew / Scoop** — generated automatically by GoReleaser at first tagged release. Requires the [`AnandSundar/homebrew-tap`](https://github.com/AnandSundar/homebrew-tap) and [`AnandSundar/scoop-bucket`](https://github.com/AnandSundar/scoop-bucket) repos to exist; the goreleaser config in `.goreleaser.yaml` is wired to push to them.

**Requirements:** Go 1.23+ (built and tested on 1.25) for source builds. Pre-built binaries have no runtime deps.

## Quickstart

Copy the example config and edit it for your upstream:

```bash
mkdir -p ~/.config/mcp-socd
curl -fsSL https://raw.githubusercontent.com/AnandSundar/mcp-socd/main/config.example.yaml \
  -o ~/.config/mcp-socd/config.yaml
$EDITOR ~/.config/mcp-socd/config.yaml
```

Then point your agent's MCP client at `mcp-socd` instead of the upstream directly. The proxy spawns the upstream on first use and proxies stdio.

For Claude Code (`~/.claude/mcp.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "soc": {
      "command": "mcp-socd",
      "args": []
    }
  }
}
```

For one-off testing without a config file, pass the upstream as positional args:

```bash
mcp-socd -- npx -y @modelcontextprotocol/server-filesystem /var/soc/readonly
```

You should see the proxy start, print the upstream and audit destinations, and wait for the agent to send a `tools/call`. Try a destructive call (`isolate_endpoint host=dc01.corp`) — the proxy will hold it, emit the audit record, and open the approval channel.

## Configuration

The config file is the only place upstream commands, policy rules, and audit destinations live. See [`config.example.yaml`](config.example.yaml) for a complete example. Schema docs land with the v1 release; the file is well-commented and self-explanatory.

Hot-reload: send `SIGHUP` to reload the config without dropping in-flight requests. `SIGTERM` / `SIGINT` drains cleanly.

## What's in the box

- **Single static binary.** No glibc version pinning hell, no shared libraries.
- **One config file.** No database, no migrations, no cluster.
- **OCSF-native audit.** Records are valid `Detection Finding` (UID 2004). Drop them into Splunk, Elastic, Panther, or any JSON-lines consumer.
- **Framework-agnostic.** Works with anything that speaks MCP: Claude Code, Codex, LangGraph, OpenAI Agents SDK, custom.
- **Catalog of starter actions** for CrowdStrike Falcon (isolate endpoint, block user, rotate API key, enrich IOC, submit EDR query). Custom actions are just YAML.
- **Pluggable approval channels.** Terminal is built-in. Slack is a first-class citizen. Adding Mattermost, PagerDuty, or a custom webhook is a 100-line PR.

## Status

Pre-1.0. The `main` branch is what's shipping; the work is in the `feat/u1-foundation` branch and the [implementation plan](docs/plans/2026-06-20-001-feat-mcp-socd-plan.md). The v1 release comes when:

- Slack approval channel ships (in review)
- CrowdStrike Falcon backend ships (in review)
- Distribution pipeline lands (in review)
- Framework integration tests pass (in review)

For background on the design, see the [requirements doc](docs/brainstorms/2026-06-20-ai-agent-containment-soc-requirements.md).

## Security

mcp-socd sits between an agent and credentials it shouldn't see. The threat model:

- **Action-layer enforcement, not output filtering.** The tool call is intercepted before the upstream ever sees it. Prompt injection that produces a `function_call` payload still goes through the policy gate.
- **Per-action primary-arg target extraction.** Targets aren't parsed from arbitrary `args` keys; the catalog declares which argument is the target. Bypasses via arg renaming don't work.
- **HMAC-signed approval tokens.** Approval requests and responses are bound to the action and target. Tokens are single-use and have a 5-minute replay window.
- **Default-deny.** No rule match → deny. The audit record carries the verdict and reason.
- **Pinned dependencies and SHA-pinned CI actions.** Supply chain attacks against the build or release pipeline fail loudly.

Found a vulnerability? Open an issue or email the address in `SECURITY.md` (lands with v1).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
