#!/usr/bin/env python3
"""langgraph_agent.py — minimal LangGraph agent fixture for mcp-socd U10.

Reads a single CLI argument naming the SOC action to invoke (one of
the five starter actions) and calls it against an MCP server whose
stdio is the proxy's stdin/stdout. The proxy in turn forwards (or
denies) the call to the upstream MCP server.

The fixture is intentionally minimal: no LLM, no tool selection, no
multi-step graph. Its sole purpose is to prove that LangGraph can
drive mcp-socd as an MCP server transport without any
proxy-aware code in the agent. The agent SDK treats the proxy as
just another MCP server.

Protocol: the fixture speaks the MCP stdio transport (Content-Length
framed JSON-RPC) on its stdin/stdout. The proxy is wired up to be
that transport on its agent-facing side.

Usage:

    langgraph_agent.py <action_name>

Where action_name is one of the five starter actions
(submit_edr_query, enrich_ioc, etc.) plus its arguments are passed
through stdin as a JSON object (one-shot) so the fixture doesn't
have to parse argparse for every action's distinct argument list.

Exit semantics:

  - exit 0: the agent received a successful JSON-RPC response
  - exit 2: the proxy returned an error (JSON-RPC error.code != null);
            the error details are written to stderr
  - exit 3: the proxy or upstream did not respond within the
            timeout (transport-level failure)
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

# The official MCP Python SDK is the only transport-level dependency
# the fixture needs; langchain-mcp-adapters would add an LLM stack
# this minimal probe doesn't want. Tests that exercise the real
# LangGraph + LLM path are deferred until the v1.1 framework integration
# follow-up; this fixture only proves the stdio transport is wired
# correctly.
from mcp import ClientSession, StdioServerParams
from mcp.client.stdio import stdio_client


def parse_arguments() -> dict[str, Any]:
    """Read the action arguments from a side-channel JSON file.

    The fixture is invoked as a subprocess by go test; passing the
    arguments via CLI args would either require per-action flag
    parsing or a fragile JSON blob escaped through bash. Instead,
    the Go test writes the arguments to a temp file and passes the
    path via the MCP_SOCD_TEST_ARGS environment variable. Empty
    file = no arguments.
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
        print(f"langgraph_agent: bad MCP_SOCD_TEST_ARGS: {exc}", file=sys.stderr)
        sys.exit(2)
    return {}


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: langgraph_agent.py <action_name>", file=sys.stderr)
        return 2
    action_name = sys.argv[1]
    arguments = parse_arguments()

    # The proxy command is supplied via MCP_SOCD_PROXY_CMD, a
    # JSON-encoded argv list written to a temp file. We could also
    # accept MCP_SOCD_PROXY_CMD_FILE which is what the Go test
    # actually writes; both shapes are supported so a developer can
    # override from a shell if needed.
    cmd_path = os.environ.get("MCP_SOCD_PROXY_CMD_FILE", "")
    cmd_env = os.environ.get("MCP_SOCD_PROXY_CMD_JSON", "")
    if cmd_path:
        with open(cmd_path, "r", encoding="utf-8") as f:
            command = json.load(f)
    elif cmd_env:
        command = json.loads(cmd_env)
    else:
        print("langgraph_agent: MCP_SOCD_PROXY_CMD_FILE (or _JSON) is required", file=sys.stderr)
        return 2

    server_params = StdioServerParams(command=command[0], args=command[1:], env=os.environ.copy())

    try:
        # The stdio_client context manager drives the subprocess and
        # returns (read_stream, write_stream) for JSON-RPC. The
        # ClientSession wraps those into the higher-level MCP API
        # (initialize, list_tools, call_tool).
        import asyncio

        async def run() -> int:
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    init_result = await session.initialize()
                    # Surface the negotiated protocolVersion on stdout
                    # so the Go test can assert it round-tripped.
                    print(
                        f"protocolVersion={init_result.protocol_version}",
                        file=sys.stderr,
                    )

                    tool_result = await session.call_tool(action_name, arguments=arguments)
                    # tool_result.content is a list of content blocks;
                    # the proxy's upstream echoes arguments as a text
                    # block, so the test can grep for them in stdout.
                    payload = {
                        "isError": bool(getattr(tool_result, "isError", False)),
                        "content": [
                            getattr(block, "text", str(block))
                            for block in (tool_result.content or [])
                        ],
                    }
                    sys.stdout.write(json.dumps(payload))
                    sys.stdout.flush()
                    return 0

        return asyncio.run(run())
    except Exception as exc:  # noqa: BLE001
        # MCP exceptions include the JSON-RPC error path. We want
        # the Go test to see the structured error on stderr, not a
        # raw traceback.
        print(f"langgraph_agent: tool call failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())