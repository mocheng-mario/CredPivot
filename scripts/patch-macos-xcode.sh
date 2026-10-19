#!/usr/bin/env bash
# flutter create 之后：链接 Rust 静态库、避免自定义 Swift 被默认模板覆盖。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR="$ROOT/apps/macos"
CONFIG_DIR="$APP_DIR/macos/Runner/Configs"
PBX="$APP_DIR/macos/Runner.xcodeproj/project.pbxproj"

if [[ ! -f "$PBX" ]]; then
  echo "未找到 $PBX，请先运行: cd apps/macos && flutter create . --platforms=macos --org com.credpivot" >&2
  exit 1
fi

for cfg in Debug.xcconfig Release.xcconfig; do
  f="$CONFIG_DIR/$cfg"
  if [[ -f "$f" ]] && ! grep -q 'RustFFI.xcconfig' "$f"; then
    echo '#include "RustFFI.xcconfig"' >> "$f"
  fi
done

# 将自定义 Swift 编进 Runner target（若 pbxproj 里还没有）
SWIFT_FILES=(
  CredPivotPlatform.swift
  MenuBarController.swift
  LifecycleBridge.swift
)
for name in "${SWIFT_FILES[@]}"; do
  if ! grep -q "$name" "$PBX"; then
    echo "警告: $name 未在 Xcode 工程中，请在 Xcode 中 Add Files to Runner 或重新合并 pbxproj" >&2
  fi
done

# 开发期 Bundle ID，与 native-host launch 一致
if grep -q 'MACOSX_DEPLOYMENT_TARGET = 10.15' "$PBX" 2>/dev/null; then
  sed -i '' 's/MACOSX_DEPLOYMENT_TARGET = 10.15/MACOSX_DEPLOYMENT_TARGET = 15.0/g' "$PBX" 2>/dev/null || \
    sed -i 's/MACOSX_DEPLOYMENT_TARGET = 10.15/MACOSX_DEPLOYMENT_TARGET = 15.0/g' "$PBX"
fi

echo "patch-macos-xcode: xcconfig / 部署目标 15.0 / Bundle ID 见 AppInfo.xcconfig"
