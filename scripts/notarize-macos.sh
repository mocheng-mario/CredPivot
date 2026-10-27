#!/usr/bin/env bash
# Release 签名与公证（M4-2）。需 Apple Developer 账号与本机 notarytool 凭据。
# 用法: DEVELOPER_ID="Developer ID Application: …" TEAM_ID=… APPLE_ID=… NOTARY_PASSWORD=… ./scripts/notarize-macos.sh path/to/CredPivot.app
set -euo pipefail
APP="${1:?用法: notarize-macos.sh path/to/CredPivot.app}"
DEVELOPER_ID="${DEVELOPER_ID:?请设置 DEVELOPER_ID}"
TEAM_ID="${TEAM_ID:?请设置 TEAM_ID}"
: "${APPLE_ID:?请设置 APPLE_ID}" "${NOTARY_PASSWORD:?请设置 NOTARY_PASSWORD}"
[[ -d "$APP/Contents" ]] || { echo "不是有效的 App 包: $APP" >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# 先签内部 Mach-O 和嵌套包，最后签主包；--deep 仅用于验证，不掩盖缺失的签名步骤。
while IFS= read -r -d '' item; do
  if file -b "$item" | grep -q 'Mach-O'; then
    codesign --force --timestamp --options runtime --sign "$DEVELOPER_ID" "$item"
  fi
done < <(find "$APP" -type f -print0)
while IFS= read -r -d '' item; do
  [[ "$item" == "$APP" ]] && continue
  codesign --force --timestamp --options runtime --sign "$DEVELOPER_ID" "$item"
done < <(find "$APP" -depth -type d \( -name '*.framework' -o -name '*.bundle' -o -name '*.app' \) -print0)
codesign --force --timestamp --options runtime --entitlements "$ROOT/apps/macos/macos/Runner/Release.entitlements" --sign "$DEVELOPER_ID" "$APP"
codesign --verify --deep --strict "$APP"
TEMP_DIR="$(mktemp -d -t credpivot-notarize)"
ZIP="$TEMP_DIR/app.zip"
trap 'rm -rf "$TEMP_DIR"' EXIT
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --wait --apple-id "$APPLE_ID" --team-id "$TEAM_ID" --password "$NOTARY_PASSWORD"
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"
spctl --assess --type execute "$APP"
echo "公证完成: $APP"
