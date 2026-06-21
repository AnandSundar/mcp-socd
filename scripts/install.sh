#!/usr/bin/env bash
# curl-pipe-sh installer for mcp-socd.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mcp-socd/mcp-socd/main/scripts/install.sh | bash
#
# Environment overrides:
#   MCPSOCD_VERSION   - explicit version tag (e.g. v0.1.0); otherwise latest release
#   MCPSOCD_REPO      - override owner/repo (default: mcp-socd/mcp-socd)
#   MCPSOCD_INSTALL_DIR - override install dir; default ~/.local/bin (or /usr/local/bin if writable)
#
# Exits non-zero on any failure (set -e, set -u, pipefail). No silent fallbacks.

set -euo pipefail

REPO="${MCPSOCD_REPO:-mcp-socd/mcp-socd}"
VERSION="${MCPSOCD_VERSION:-}"

# --- OS detection -------------------------------------------------------------
uname_s=$(uname -s)
case "$uname_s" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *)
    echo "error: unsupported OS: $uname_s (only linux and darwin)" >&2
    exit 1
    ;;
esac

# --- Arch detection -----------------------------------------------------------
uname_m=$(uname -m)
case "$uname_m" in
  x86_64)          arch=amd64 ;;
  amd64)            arch=amd64 ;;
  arm64)            arch=arm64 ;;
  aarch64)          arch=arm64 ;;
  *)
    echo "error: unsupported architecture: $uname_m (only amd64 and arm64)" >&2
    exit 1
    ;;
esac

# --- Version resolution -------------------------------------------------------
if [ -z "$VERSION" ]; then
  if ! command -v gh >/dev/null 2>&1; then
    echo "error: gh CLI is required to resolve the latest release (or set MCPSOCD_VERSION)" >&2
    exit 1
  fi
  VERSION=$(gh api "repos/${REPO}/releases/latest" | jq -r .tag_name)
  if [ -z "$VERSION" ] || [ "$VERSION" = "null" ]; then
    echo "error: could not determine latest release for ${REPO}" >&2
    exit 1
  fi
fi

# --- Asset name ----------------------------------------------------------------
asset="mcp-socd_${VERSION}_${os}_${arch}.tar.gz"
checksum_asset="mcp-socd_${VERSION}_SHA256SUMS"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"

# --- Working dir --------------------------------------------------------------
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# --- Download -----------------------------------------------------------------
echo "==> Downloading ${asset}"
curl -fsSL -o "${workdir}/${asset}" "${base_url}/${asset}"
curl -fsSL -o "${workdir}/${checksum_asset}" "${base_url}/${checksum_asset}"

# --- Verify -------------------------------------------------------------------
expected_sha=$(grep -F "  ${asset}" "${workdir}/${checksum_asset}" | awk '{print $1}')
if [ -z "$expected_sha" ]; then
  echo "error: no checksum found for ${asset}" >&2
  exit 1
fi
actual_sha=$(sha256sum "${workdir}/${asset}" | awk '{print $1}')
if [ "$expected_sha" != "$actual_sha" ]; then
  echo "error: checksum mismatch for ${asset}" >&2
  echo "  expected: $expected_sha" >&2
  echo "  actual:   $actual_sha" >&2
  exit 1
fi
echo "==> Checksum verified"

# --- Install ------------------------------------------------------------------
if [ -n "${MCPSOCD_INSTALL_DIR:-}" ]; then
  install_dir="$MCPSOCD_INSTALL_DIR"
elif [ -w "/usr/local/bin" ]; then
  install_dir="/usr/local/bin"
else
  install_dir="${HOME}/.local/bin"
  mkdir -p "$install_dir"
fi

tar -xzf "${workdir}/${asset}" -C "$workdir"
install -m 0755 "${workdir}/mcp-socd" "${install_dir}/mcp-socd"

echo "==> Installed mcp-socd ${VERSION} to ${install_dir}/mcp-socd"
case ":$PATH:" in
  *":${install_dir}:"*) ;;
  *)
    echo "    (note: ${install_dir} is not on your PATH; add it or call the binary directly)"
    ;;
esac