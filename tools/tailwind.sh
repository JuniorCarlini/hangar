#!/usr/bin/env bash
# Runs the Tailwind CSS standalone CLI (no Node, no npm), pinned by version
# and SHA-256. The binary is downloaded once into bin/ and checked every time.
set -euo pipefail

VERSION=4.3.3
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  ASSET=tailwindcss-macos-arm64; SUM=cdf646702987a743464dff4d9c60fd4480d1c1e73dd819a9a67f1078815dce9d ;;
  Darwin-x86_64) ASSET=tailwindcss-macos-x64;   SUM=7922e0953f2110c05976e3bf58f14e643d90427575e766b7d433f5f80cbee7e1 ;;
  Linux-x86_64)  ASSET=tailwindcss-linux-x64;   SUM=dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a ;;
  Linux-aarch64) ASSET=tailwindcss-linux-arm64; SUM=55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195 ;;
  *) echo "tailwind: unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/tailwindcss-$VERSION"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

if [[ ! -x "$BIN" ]] || [[ "$(sha "$BIN")" != "$SUM" ]]; then
  mkdir -p "$ROOT/bin"
  tmp="$(mktemp)"
  curl -sSfL -o "$tmp" "https://github.com/tailwindlabs/tailwindcss/releases/download/v$VERSION/$ASSET"
  if [[ "$(sha "$tmp")" != "$SUM" ]]; then
    echo "tailwind: checksum mismatch for $ASSET v$VERSION" >&2
    exit 1
  fi
  chmod +x "$tmp"
  mv "$tmp" "$BIN"
fi

exec "$BIN" "$@"
