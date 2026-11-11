#!/usr/bin/env bash
# 退出 CredPivot 后执行。默认只检查；追加 --apply 才迁移。
# bash scripts/upgrade-legacy-data.sh [保险库目录] [--apply]
# 只构建独立 CLI，不构建、安装或启动 App；不下载依赖。
set -euo pipefail
umask 077
SCRIPT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec cargo run --offline --locked --manifest-path "$SCRIPT_ROOT/Cargo.toml" \
  -p credpivot-cli -- upgrade-legacy "$@"
