#!/usr/bin/env bash
# 生成 CredPivot Rust workspace 的 CycloneDX SBOM（M4-6）。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT/dist/sbom}"
mkdir -p "$OUT_DIR"
cd "$ROOT"
if ! cargo cyclonedx --version >/dev/null 2>&1; then
  echo "请先安装: cargo install cargo-cyclonedx" >&2
  exit 1
fi
cargo cyclonedx --all --format json --output-file "$OUT_DIR/credpivot-rust.cdx.json"
echo "SBOM: $OUT_DIR/credpivot-rust.cdx.json"
if command -v flutter >/dev/null 2>&1 && [ -f "$ROOT/apps/macos/pubspec.lock" ]; then
  cp "$ROOT/apps/macos/pubspec.lock" "$OUT_DIR/flutter-macos-pubspec.lock"
  echo "锁定文件副本: $OUT_DIR/flutter-macos-pubspec.lock"
fi
