#!/usr/bin/env bash
# 只打包显式传入的构建产物，不访问用户保险库、钥匙串或同步配置。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIND="${1:?用法: package-release.sh app|cli|extension path}"
SOURCE="${2:?请传入构建产物路径}"
VERSION="$(awk '/^version: / {print $2; exit}' "$ROOT/apps/macos/pubspec.yaml")"
VERSION="${VERSION%%+*}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || { echo "无效的发布版本" >&2; exit 1; }
mkdir -p "$ROOT/dist"
TEMP_DIR="$(mktemp -d -t credpivot-package)"
trap 'rm -rf "$TEMP_DIR"' EXIT
case "$KIND" in
  cli)
    [[ -x "$SOURCE" ]] || { echo "CLI 构建产物不存在" >&2; exit 1; }
    ARCH="$(lipo -archs "$SOURCE")"
    [[ "$ARCH" == arm64 || "$ARCH" == x86_64 ]] || { echo "当前只打包单架构 CLI" >&2; exit 1; }
    NAME="credpivot-cli-$VERSION-macos-$ARCH"
    mkdir "$TEMP_DIR/$NAME"
    cp "$SOURCE" "$TEMP_DIR/$NAME/credpivot-cli"
    codesign --force --sign - "$TEMP_DIR/$NAME/credpivot-cli"
    "$TEMP_DIR/$NAME/credpivot-cli" --version
    cp "$ROOT/README.md" "$TEMP_DIR/$NAME/README.md"
    ARCHIVE="$ROOT/dist/$NAME.tar.gz"
    tar -czf "$TEMP_DIR/archive.tar.gz" -C "$TEMP_DIR" "$NAME"
    mv "$TEMP_DIR/archive.tar.gz" "$ARCHIVE"
    ;;
  app)
    [[ -d "$SOURCE/Contents" ]] || { echo "App 构建产物不存在" >&2; exit 1; }
    [[ "$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$SOURCE/Contents/Info.plist")" == "${VERSION%%-*}" ]] || { echo "App 版本与发布版本不一致" >&2; exit 1; }
    # 独立发包必须携带 SSH 运行依赖，不能靠开发机 ~/.credpivot 中的旧文件兜底。
    for item in credpivot-native-host credpivot-askpass ssh-expect-pass.exp credpivot-chrome-extension/manifest.json; do
      [[ -f "$SOURCE/Contents/Resources/$item" ]] || { echo "App 缺少资源: $item" >&2; exit 1; }
    done
    [[ ! -e "$SOURCE/Contents/Resources/credpivot-cli" ]] || { echo "CLI 应独立分发" >&2; exit 1; }
    codesign --verify --deep --strict "$SOURCE"
    ARCH="$(lipo -archs "$SOURCE/Contents/MacOS/credpivot_macos")"
    [[ "$ARCH" == arm64 || "$ARCH" == x86_64 || "$ARCH" == 'x86_64 arm64' || "$ARCH" == 'arm64 x86_64' ]] || exit 1
    ARCH="${ARCH// /-}"
    ARCHIVE="$ROOT/dist/CredPivot-$VERSION-macos-$ARCH.zip"
    ditto -c -k --keepParent "$SOURCE" "$TEMP_DIR/archive.zip"
    mv "$TEMP_DIR/archive.zip" "$ARCHIVE"
    ;;
  extension)
    [[ -f "$SOURCE/manifest.json" ]] || { echo "扩展清单不存在" >&2; exit 1; }
    EXT_VERSION="$(/usr/bin/plutil -extract version raw -o - "$SOURCE/manifest.json")"
    ARCHIVE="$ROOT/dist/CredPivot-Chrome-$EXT_VERSION.zip"
    ditto -c -k --keepParent "$SOURCE" "$TEMP_DIR/archive.zip"
    mv "$TEMP_DIR/archive.zip" "$ARCHIVE"
    ;;
  *) echo "未知产物类型: $KIND" >&2; exit 1 ;;
esac
shasum -a 256 "$ARCHIVE" | sed "s|  .*/|  |" > "$ARCHIVE.sha256"
printf '已生成 %s\n' "$ARCHIVE" "$ARCHIVE.sha256"
