#!/usr/bin/env bash
# 不安装 SDK、NDK 或 Rust target；缺少工具链时明确停止，由开发者安装。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
# make 不一定经由 mise exec 启动；未显式配置 SDK 时，复用仓库锁定的 mise 安装。
if [[ -z "$SDK" ]] && command -v mise >/dev/null 2>&1; then
  SDK="$(cd "$ROOT" && mise where android-sdk 2>/dev/null || true)"
fi
SDK="${SDK:-$HOME/Library/Android/sdk}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-$SDK/ndk/28.2.13676358}}"
[[ -d "$NDK/toolchains/llvm/prebuilt" ]] || {
  echo "未找到 Android NDK 28.2.13676358，检查路径：$NDK" >&2
  echo "请确认 SDK/NDK 路径；确实未安装时，再安装 ndk;28.2.13676358。SDK：$SDK" >&2
  exit 1
}
case "$(uname -s)" in
  Darwin) HOST_TAG=darwin-x86_64 ;;
  Linux) HOST_TAG=linux-x86_64 ;;
  *) echo "Android Rust 构建脚本目前支持 macOS / Linux" >&2; exit 1 ;;
esac
BIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
PROFILE="${CARGO_PROFILE:-release}"
# 默认 Debug 构建对应 Cargo 的 dev profile；避免 Bash 3.2 在 set -u 下展开空数组时报错。
if [[ "$PROFILE" == debug ]]; then FLAGS=(--profile dev); else FLAGS=(--profile "$PROFILE"); fi
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
TARGETS="$(rustup target list --installed)"
for ABI in arm64-v8a x86_64; do
  case "$ABI" in
    arm64-v8a) TARGET=aarch64-linux-android; LINKER=AARCH64_LINUX_ANDROID ;;
    x86_64) TARGET=x86_64-linux-android; LINKER=X86_64_LINUX_ANDROID ;;
  esac
  [[ "$TARGETS" == *"$TARGET"* ]] || { echo "缺少 Rust target，请执行: rustup target add aarch64-linux-android x86_64-linux-android" >&2; exit 1; }
  COMPILER="$BIN/${TARGET}28-clang"
  [[ -x "$COMPILER" ]] || { echo "NDK 编译器不存在: $COMPILER" >&2; exit 1; }
  # 与桌面 CommonCrypto 分开，SQLCipher 的 Android OpenSSL 由 Cargo vendored feature 静态构建。
  env -u MACOSX_DEPLOYMENT_TARGET -u OPENSSL_DIR -u OPENSSL_LIB_DIR -u OPENSSL_INCLUDE_DIR \
    PATH="$BIN:$PATH" ANDROID_NDK_HOME="$NDK" ANDROID_NDK_ROOT="$NDK" \
    "CARGO_TARGET_${LINKER}_LINKER=$COMPILER" CC="$COMPILER" AR="$BIN/llvm-ar" RANLIB="$BIN/llvm-ranlib" \
    CARGO_TARGET_DIR="$TARGET_DIR" RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-soname,libcredpivot_ffi.so" \
    "${CARGO:-cargo}" build --manifest-path "$ROOT/apps/macos/android/rust/Cargo.toml" --target "$TARGET" "${FLAGS[@]}"
  DESTINATION="$ROOT/apps/macos/android/app/src/main/rustLibs/$ABI"
  mkdir -p "$DESTINATION"
  cp "$TARGET_DIR/$TARGET/$PROFILE/libcredpivot_ffi.so" "$DESTINATION/libcredpivot_ffi.so"
done
