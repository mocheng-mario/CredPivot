#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo >/dev/null; then
  echo "需要 Rust toolchain: https://rustup.rs" >&2
  exit 1
fi
if ! command -v flutter >/dev/null; then
  echo "需要 Flutter SDK: https://docs.flutter.dev/get-started/install/macos" >&2
  exit 1
fi

cargo build --release -p credpivot-ffi -p credpivot-native-host -p credpivot-askpass

APP_DIR="$ROOT/apps/macos"
if [[ ! -f "$APP_DIR/macos/Runner.xcodeproj/project.pbxproj" ]]; then
  cd "$APP_DIR"
  flutter create . --platforms=macos --org com.credpivot
fi
"$ROOT/scripts/patch-macos-xcode.sh"

LIB="$ROOT/target/release/libcredpivot_ffi.a"
HOST_BIN="$ROOT/target/release/credpivot-native-host"
ASKPASS_BIN="$ROOT/target/release/credpivot-askpass"
RUNNER="$APP_DIR/macos/Runner"

cp "$LIB" "$RUNNER/"
cp "$HOST_BIN" "$RUNNER/credpivot-native-host"
chmod +x "$RUNNER/credpivot-native-host"
cp "$ASKPASS_BIN" "$RUNNER/credpivot-askpass"
cp "$ROOT/target/release/credpivot-git-ssh" "$RUNNER/credpivot-git-ssh"
chmod +x "$RUNNER/credpivot-git-ssh"
chmod +x "$RUNNER/credpivot-askpass"
rm -rf "$RUNNER/credpivot-chrome-extension"
cp -R "$ROOT/apps/chrome-extension" "$RUNNER/credpivot-chrome-extension"

# 自定义 Swift 已在 apps/macos/macos/Runner/ 下；flutter create 后请确认 AppDelegate 等未被覆盖。

cd "$APP_DIR"
flutter pub get
flutter build macos --debug

echo "构建完成。开发期签名后若被 Gatekeeper 拦截，可对产物执行: xattr -cr <app path>"
