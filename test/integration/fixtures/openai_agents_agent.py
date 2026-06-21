#!/usr/bin/env python3
"""openai_agents_agent.py — minimal OpenAI Agents SDK fixture for mcp-socd U10.

Reads a single CLI argument naming the SOC action to invoke (one of
the five starter actions) and calls it through an OpenAI Agents SDK
MCPServerStdio connection. The SDK speaks MCP stdio transport on
its stdin/stdout; the proxy is that transport on its agent-facing
side.

Like langgraph_agent.py, this fixture is intentionally minimal: no
LLM, no tool selection, no multi-agent orchestration. Its purpose
is to prove that the OpenAI Agents SDK can drive mcp-socd as an
MCP server transport without proxy-aware code in the agent.

Protocol: the fixture speaks MCP stdio (Content-Length framed
JSON-RPC) on its stdin/stdout. The proxy is wired up to be that
transport on its agent-facing side.

Usage:

    openai_agents_agent.py <action_name>

Action arguments are passed through the MCP_SOCD_TEST_ARGS env var
as a path to a JSON file (one-shot) so the fixture doesn't have to
parse per-action flags.

Exit semantics:

  - exit 0: the agent received a successful JSON-RPC response
  - exit 2: the proxy returned an error (JSON-RPC error.code != null)
  - exit 3: timeout or transport-level failure
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any


def load_proxy_command() -> list[str]:
    """Resolve the proxy command from MCP_SOCD_PROXY_CMD_FILE or
    MCP_SOCD_PROXY_CMD_JSON. Both shapes are supported so a
    developer can override from a shell.
    """
    cmd_path = os.environ.get("MCP_SOCD_PROXY_CMD_FILE", "")
    cmd_env = os.environ.get("MCP_SOCD_PROXY_CMD_JSON", "")
    if cmd_path:
        with open(cmd_path, "r", encoding="utf-8") as f:
            return json.load(f)
    if cmd_env:
        return json.loads(cmd_env)
    print(
        "openai_agents_agent: MCP_SOCD_PROXY_CMD_FILE (or _JSON) is required",
        file=sys.stderr,
    )
    sys.exit(2)


def load_arguments() -> dict[str, Any]:
    """Read action arguments from the MCP_SOCD_TEST_ARGS path.
    Empty file or missing variable = no arguments.
    """
    path = os.environ.get("MCP_SOCD_TEST_ARGS", "")
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError) as exc:
        print(f"openai_agents_agent: bad MCP_SOCD_TEST_ARGS: {exc}", file=sys.stderr)
        sys.exit(2)
    return {}


async def main_async() -> int:
    # Imported lazily so the module's import-error path is reported
    # with the right exit code (the openai-agents SDK is optional).
    from agents.mcp import MCPServerStdio

    if len(sys.argv) < 2:
        print("usage: openai_agents_agent.py <action_name>", file=sys.stderr)
        return 2
    action_name = sys.argv[1]
    arguments = load_arguments()
    command = load_proxy_command()

    # MCPServerStdio spawns the proxy as a child and routes the
    # call_tool request through MCP stdio transport.
    async with MCPServerStdio(
        name="mcp-socd-proxy",
        params={
            "command": command[0],
            "args": command[1:],
        },
    ) as server:
        # List tools so we can confirm the SDK saw the proxy's
        # tools/list response (proves the stdio transport is wired).
        tools = await server.list_tools()
        tool_names = [t.name for t in tools]
        sys.stderr.write(f"tools={tool_names}\n")

        # Drive the tool call. The SDK handles JSON-RPC framing on
        # top of the proxy's stdio; we get back a CallToolResult.
        result = await server.call_tool(action_name, arguments)
        payload = {
            "isError": bool(getattr(result, "isError", False)),
            "content": [
                getattr(block, "text", str(block))
                for block in (result.content or [])
            ],
        }
        sys.stdout.write(json.dumps(payload))
        sys.stdout.flush()
        return 0


def main() -> int:
    try:
        return asyncio.run(main_async())
    except Exception as exc:  # noqa: BLE001
        print(f"openai_agents_agent: tool call failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())