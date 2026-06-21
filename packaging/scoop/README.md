# Scoop manifest (generated; do not hand-edit)

`mcp-socd.json` is generated at release time by GoReleaser from the
`scoops:` block of `.goreleaser.yaml`. The generated manifest lands in
the [`mcp-socd/scoop-bucket`](https://github.com/mcp-socd/scoop-bucket)
repository under `bucket/mcp-socd.json`.

## What the generated manifest looks like

The structure below mirrors what goreleaser will produce (see
[goreleaser.com/customization/scoop](https://goreleaser.com/customization/scoop/)):

```json
{
  "version": "0.1.0",
  "description": "MCP-aware security proxy for SOC teams",
  "homepage": "https://github.com/mcp-socd/mcp-socd",
  "license": "Apache-2.0",
  "url": "https://github.com/mcp-socd/mcp-socd/releases/download/v0.1.0/mcp-socd_v0.1.0_windows_amd64.zip",
  "hash": "<generated sha256>",
  "bin": "mcp-socd.exe",
  "checkver": "github",
  "autoupdate": {
    "url": "https://github.com/mcp-socd/mcp-socd/releases/download/v$version/mcp-socd_v$version_windows_amd64.zip"
  }
}
```

The `hash` value comes from the SHA256SUMS file goreleaser writes
alongside the release artifacts.

## Operator install

```pwsh
scoop bucket add mcp-socd https://github.com/mcp-socd/scoop-bucket
scoop install mcp-socd
```

## Verifying a generated manifest locally

```pwsh
scoop install https://raw.githubusercontent.com/mcp-socd/scoop-bucket/main/bucket/mcp-socd.json
mcp-socd --version
```

The `--version` invocation must exit 0 before promoting the
goreleaser-generated PR on the `scoop-bucket` repo.