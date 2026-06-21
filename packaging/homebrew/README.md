# Homebrew formula (generated; do not hand-edit)

`mcp-socd.rb` is generated at release time by GoReleaser from the
`brews:` block of `.goreleaser.yaml`. The generated formula lands in
the [`mcp-socd/homebrew-tap`](https://github.com/mcp-socd/homebrew-tap)
repository under `Formula/mcp-socd.rb`.

## What the generated formula looks like

The structure below mirrors what goreleaser will produce (see
[goreleaser.com/customization/homebrew](https://goreleaser.com/customization/homebrew/)):

```ruby
class McpSocd < Formula
  desc      "MCP-aware security proxy for SOC teams"
  homepage  "https://github.com/mcp-socd/mcp-socd"
  version   "v0.1.0"
  license   "Apache-2.0"

  on_macos do
    on_intel do
      url     "https://github.com/mcp-socd/mcp-socd/releases/download/v0.1.0/mcp-socd_v0.1.0_darwin_amd64.tar.gz"
      sha256  "<generated>"
    end
    on_arm do
      url     "https://github.com/mcp-socd/mcp-socd/releases/download/v0.1.0/mcp-socd_v0.1.0_darwin_arm64.tar.gz"
      sha256  "<generated>"
    end
  end

  on_linux do
    on_intel do
      url     "https://github.com/mcp-socd/mcp-socd/releases/download/v0.1.0/mcp-socd_v0.1.0_linux_amd64.tar.gz"
      sha256  "<generated>"
    end
    on_arm do
      url     "https://github.com/mcp-socd/mcp-socd/releases/download/v0.1.0/mcp-socd_v0.1.0_linux_arm64.tar.gz"
      sha256  "<generated>"
    end
  end

  def install
    bin.install "mcp-socd"
  end

  test do
    system "#{bin}/mcp-socd --version"
  end
end
```

The `sha256` values come from the SHA256SUMS file goreleaser writes
alongside the release artifacts.

## Operator install

```sh
brew tap mcp-socd/tap
brew install mcp-socd
```

## Verifying a generated formula locally

```sh
brew audit --strict --new mcp-socd
brew install --build-from-source mcp-socd
```

Both must succeed before promoting the goreleaser-generated PR on the
`homebrew-tap` repo.