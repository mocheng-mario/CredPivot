#!/usr/bin/env bash
# 只替换应用包；保险库、钥匙串、浏览器配置由 App 原有逻辑管理。
set -euo pipefail
SOURCE="${1:?用法: install-macos.sh app-path [install-directory]}"
INSTALL_DIR="${2:-/Applications}"
[[ -d "$SOURCE/Contents" ]] || { echo "App 构建产物不存在" >&2; exit 1; }
BUNDLE_ID="$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$SOURCE/Contents/Info.plist")"
EXECUTABLE="$(/usr/bin/plutil -extract CFBundleExecutable raw -o - "$SOURCE/Contents/Info.plist")"
[[ "$EXECUTABLE" == credpivot_macos && -n "$BUNDLE_ID" ]] || { echo "不是 CredPivot App" >&2; exit 1; }
codesign --verify --deep --strict "$SOURCE"

require_stopped() {
  if pgrep -x "$EXECUTABLE" >/dev/null; then
    echo "CredPivot 仍在运行，请先用 Cmd+Q 完全退出，再执行安装。" >&2
    exit 1
  fi
}
require_stopped
mkdir -p "$INSTALL_DIR"
INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd -P)"
TARGET="$INSTALL_DIR/CredPivot.app"
[[ -w "$INSTALL_DIR" ]] || {
  echo '安装目录不可写，可使用 make macos-install MACOS_INSTALL_DIR="$HOME/Applications"。' >&2
  exit 1
}
[[ ! -L "$TARGET" ]] || { echo "目标是符号链接，已停止安装: $TARGET" >&2; exit 1; }
if [[ -e "$TARGET" ]]; then
  [[ "$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "$TARGET/Contents/Info.plist")" == "$BUNDLE_ID" ]] || {
    echo "目标不是同一应用，已停止安装: $TARGET" >&2
    exit 1
  }
fi

# 同一目录暂存，复制或校验失败时不改动旧包；避免两个安装进程互相覆盖。
LOCK="$INSTALL_DIR/.credpivot-install.lock"
mkdir "$LOCK" 2>/dev/null || { echo "安装目录已被占用: $LOCK；若无其他安装进程，请移除遗留锁目录后重试。" >&2; exit 1; }
STAGING=""
cleanup() {
  local result=$?
  trap - EXIT
  if [[ -n "$STAGING" && -e "$STAGING/previous.app" && ! -e "$TARGET" ]]; then
    if ! mv "$STAGING/previous.app" "$TARGET"; then
      echo "恢复旧版本失败，旧包保留在: $STAGING/previous.app" >&2
      rmdir "$LOCK"
      exit 1
    fi
  fi
  if [[ -n "$STAGING" ]]; then rm -rf "$STAGING"; fi
  rmdir "$LOCK"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
STAGING="$(mktemp -d "$INSTALL_DIR/.credpivot-install.XXXXXXXX")"
ditto "$SOURCE" "$STAGING/CredPivot.app"
codesign --verify --deep --strict "$STAGING/CredPivot.app"
require_stopped
if [[ -e "$TARGET" ]]; then
  mv "$TARGET" "$STAGING/previous.app"
fi
mv "$STAGING/CredPivot.app" "$TARGET"
printf '已安装到: %s\n启动命令: open "%s"\n' "$TARGET" "$TARGET"
