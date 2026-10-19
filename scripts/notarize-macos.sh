#!/usr/bin/env bash
# Release 签名与公证（M4-2）。需 Apple Developer 账号与本机 notarytool 凭据。
# 用法: DEVELOPER_ID="Developer ID Application: …" ./scripts/notarize-macos.sh path/to/CredPivot.app
set -euo pipefail
APP="${1:?用法: notarize-macos.sh path/to/CredPivot.app}"
DEVELOPER_ID="${DEVELOPER_ID:?请设置 DEVELOPER_ID}"
TEAM_ID="${TEAM_ID:?请设置 TEAM_ID}"
ZIP="$(mktemp -t credpivot-notarize).zip"
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --wait --apple-id "${APPLE_ID:?}" --team-id "$TEAM_ID" --password "${NOTARY_PASSWORD:?}"
xcrun stapler staple "$APP"
rm -f "$ZIP"
echo "公证完成: $APP"
