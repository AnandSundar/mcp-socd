#!/usr/bin/env python3
"""upstream-echo.py -- minimal MCP stdio test fixture.

Reads Content-Length-framed JSON-RPC messages from stdin and replies with
hardcoded responses for the methods that the proxy test suite exercises:

  - initialize         -> InitializeResult with serverInfo and capabilities
  - initialized        -> no response (notification)
  - tools/list         -> one tool: "isolate_endpoint"
  - tools/call         -> echoes the call name and arguments back as the
                          result content so the test can assert the proxy
                          forwarded the call to the child
  - ping               -> empty result

The fixture is intentionally simple: it does not validate inputs and does
not implement state. Its sole purpose is to give the proxy a real
upstream process to drive during tests.

Exit semantics:

  - the script exits 0 on EOF (clean agent-side close)
  - the script exits 1 on a malformed frame, writing the error to stderr
    so the Go test can see it without polluting stdout
"""
from __future__ import annotations

import json
import sys


def read_frame(stream):
    """Read one Content-Length framed JSON-RPC message and return the
    decoded object plus the raw bytes. Raises ValueError on malformed
    framing and EOFError on stdin close.

    stream is expected to be a binary stream (e.g. sys.stdin.buffer);
    line/header parsing is therefore in bytes throughout.
    """
    headers = {}
    while True:
        line = stream.readline()
        if line == b"":
            raise EOFError("stdin closed during header read")
        line = line.rstrip(b"\r\n")
        if line == b"":
            break
        if b":" not in line:
            raise ValueError(f"malformed header line: {line!r}")
        name, _, value = line.partition(b":")
        headers[name.strip().lower().decode("ascii")] = value.strip().decode("ascii")
    if "content-length" not in headers:
        raise ValueError("missing Content-Length header")
    n = int(headers["content-length"])
    body = stream.read(n)
    if len(body) != n:
        raise EOFError(f"short read: wanted {n} bytes, got {len(body)}")
    return json.loads(body.decode("utf-8")), body


def write_frame(stream, obj):
    """Serialize obj as JSON and write it as one Content-Length frame."""
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    stream.write(header)
    stream.write(body)
    stream.flush()


def handle(req):
    """Produce a response for req (returns None for notifications)."""
    method = req.get("method")
    req_id = req.get("id")
    if req_id is None:
        # Notification: no response.
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "upstream-echo", "version": "0.0.0-test"},
                "capabilities": {"tools": {"listChanged": False}},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "isolate_endpoint",
                        "description": "Disconnect a host from the network.",
                        "inputSchema": {
                            "$schema": "https://json-schema.org/draft/2020-12/schema",
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "host_id": {"type": "string", "minLength": 1},
                                "comment": {"type": "string"},
                            },
                            "required": ["host_id"],
                        },
                    },
                ],
                "nextCursor": None,
            },
        }

    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        # Echo the call back as the tool result so the test can assert
        # the proxy forwarded the call unmodified.
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({"echoed_tool": name, "arguments": arguments}),
                    },
                ],
                "isError": False,
            },
        }

    # Unknown method: standard JSON-RPC method-not-found error.
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"method not found: {method}"},
    }


def main():
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        try:
            req, _ = read_frame(stdin)
        except EOFError:
            return 0
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"upstream-echo: malformed frame: {exc}", file=sys.stderr)
            return 1
        resp = handle(req)
        if resp is not None:
            write_frame(stdout, resp)


if __name__ == "__main__":
    sys.exit(main())