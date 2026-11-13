#!/usr/bin/env bash
# 只打包显式传入的构建产物，不访问用户保险库、钥匙串或同步配置。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIND="${1:?用法: package-release.sh app|cli|chrome|firefox|extension path}"
SOURCE="${2:?请传入构建产物路径}"
VERSION="$(awk '/^version: / {print $2; exit}' "$ROOT/apps/macos/pubspec.yaml")"
BUILD_NUMBER="${VERSION##*+}"
VERSION="${VERSION%%+*}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || { echo "无效的发布版本" >&2; exit 1; }
mkdir -p "$ROOT/dist"
TEMP_DIR="$(mktemp -d -t credpivot-package)"
trap 'rm -rf "$TEMP_DIR"' EXIT
publish() {
  local archive="$1"
  shasum -a 256 "$archive" | sed "s|  .*/|  |" > "$archive.sha256"
  printf '已生成 %s\n' "$archive" "$archive.sha256"
}
# 源目录是 Chrome 清单加共用文件。Firefox 清单单独存放，临时加载目录只复制共用文件。
package_browser() {
  local browser="$1"
  [[ -f "$SOURCE/manifest.json" ]] || { echo "扩展清单不存在" >&2; exit 1; }
  local ext_version stage archive
  ext_version="$(/usr/bin/plutil -extract version raw -o - "$SOURCE/manifest.json")"
  stage="$TEMP_DIR/stage-$browser"
  rm -rf "$stage"
  mkdir -p "$stage"
  COPYFILE_DISABLE=1 cp -R "$SOURCE/." "$stage/"
  find "$stage" -name '.DS_Store' -delete
  find "$stage" -name '._*' -delete
  rm -f "$stage/native-messaging-host-m0.json"
  case "$browser" in
    chrome)
      if /usr/bin/plutil -extract browser_specific_settings json -o /dev/null "$stage/manifest.json" 2>/dev/null; then
        /usr/bin/plutil -remove browser_specific_settings "$stage/manifest.json"
      fi
      archive="$ROOT/dist/CredPivot-Chrome-$ext_version.zip"
      rm -f "$archive" "$archive.sha256"
      # 解压后目录名保持 chrome-extension，便于按原说明加载未打包扩展。
      mkdir -p "$TEMP_DIR/chrome-root"
      rm -rf "$TEMP_DIR/chrome-root/chrome-extension"
      mv "$stage" "$TEMP_DIR/chrome-root/chrome-extension"
      (cd "$TEMP_DIR/chrome-root" && zip -r -X "$TEMP_DIR/chrome.zip" chrome-extension -x '*.DS_Store' -x '__MACOSX/*' -x '*/._*' -x '._*')
      mv "$TEMP_DIR/chrome.zip" "$archive"
      ;;
    firefox)
      archive="$ROOT/dist/CredPivot-Firefox-$ext_version.xpi"
      rm -f "$archive" "$archive.sha256"
      # xpi 根目录必须是 manifest.json，Firefox 才能从文件安装。
      (cd "$stage" && zip -r -X "$TEMP_DIR/firefox.zip" . -x '*.DS_Store' -x '__MACOSX/*')
      mv "$TEMP_DIR/firefox.zip" "$archive"
      ;;
    *) echo "未知浏览器: $browser" >&2; exit 1 ;;
  esac
  publish "$archive"
}
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
    publish "$ARCHIVE"
    ;;
  app)
    [[ -d "$SOURCE/Contents" ]] || { echo "App 构建产物不存在" >&2; exit 1; }
    [[ "$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "$SOURCE/Contents/Info.plist")" == "${VERSION%%-*}" ]] || { echo "App 版本与发布版本不一致" >&2; exit 1; }
    [[ "$(/usr/bin/plutil -extract CFBundleVersion raw -o - "$SOURCE/Contents/Info.plist")" == "$BUILD_NUMBER" ]] || { echo "App 构建号不一致" >&2; exit 1; }
    # 独立发包必须携带 SSH 运行依赖，不能靠开发机 ~/.credpivot 中的旧文件兜底。
    for item in credpivot-native-host credpivot-askpass credpivot-git-ssh ssh-expect-pass.exp credpivot-chrome-extension/manifest.json credpivot-firefox-manifest.json; do
      [[ -f "$SOURCE/Contents/Resources/$item" ]] || { echo "App 缺少资源: $item" >&2; exit 1; }
    done
    [[ ! -e "$SOURCE/Contents/Resources/credpivot-cli" ]] || { echo "CLI 应独立分发" >&2; exit 1; }
    codesign --verify --deep --strict "$SOURCE"
    # 签名检查通过并不代表动态库能加载；受控模式在启动 Agent 前退出，不访问用户保险库。
    CHECK_OUTPUT="$(/usr/bin/perl -e 'alarm 25; exec @ARGV or die "startup check exec failed"' "$SOURCE/Contents/MacOS/credpivot_macos" --credpivot-startup-check)"
    [[ "$CHECK_OUTPUT" == *"CredPivot startup check passed"* ]] || { echo "App 启动检查未通过" >&2; exit 1; }
    ARCH="$(lipo -archs "$SOURCE/Contents/MacOS/credpivot_macos")"
    [[ "$ARCH" == arm64 || "$ARCH" == x86_64 || "$ARCH" == 'x86_64 arm64' || "$ARCH" == 'arm64 x86_64' ]] || exit 1
    ARCH="${ARCH// /-}"
    ARCHIVE="$ROOT/dist/CredPivot-$VERSION-macos-$ARCH.dmg"
    mkdir "$TEMP_DIR/dmg"
    # 只重命名包目录，保留签名和包内可执行文件名称。
    ditto "$SOURCE" "$TEMP_DIR/dmg/CredPivot.app"
    codesign --verify --deep --strict "$TEMP_DIR/dmg/CredPivot.app"
    ln -s /Applications "$TEMP_DIR/dmg/Applications"
    hdiutil create -volname CredPivot -srcfolder "$TEMP_DIR/dmg" -fs HFS+ -format UDZO "$TEMP_DIR/archive.dmg"
    hdiutil verify "$TEMP_DIR/archive.dmg"
    mv "$TEMP_DIR/archive.dmg" "$ARCHIVE"
    publish "$ARCHIVE"
    ;;
  chrome|firefox)
    package_browser "$KIND"
    ;;
  extension)
    package_browser chrome
    package_browser firefox
    ;;
  *) echo "未知产物类型: $KIND" >&2; exit 1 ;;
esac
