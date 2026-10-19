# M4 首发发布 Runbook

对照 `Implementation_Checklist_v1.1.md` 中 M4 条目，本文件记录可执行步骤与仓库内工具。

## M4-1 本地化 / 主题 / 键盘 / 无障碍

- macOS 客户端使用 Flutter Material 3 深浅色（跟随系统 `ThemeMode.system`）。
- 凭据 Tab 支持键盘焦点与 Tab 导航（`TabBar` + 列表 `ListTile`）。
- 发布前在「系统设置 → 辅助功能」中抽查 VoiceOver 朗读列表标题。

## M4-2 Mac 签名与公证

1. `make macos-build-release`
2. 在 Xcode 中配置 `DEVELOPMENT_TEAM` 与 Release 证书，或使用 ad-hoc 开发包（见 `M0_Platform_Findings.md`）。
3. 公证：`DEVELOPER_ID=… TEAM_ID=… APPLE_ID=… NOTARY_PASSWORD=… ./scripts/notarize-macos.sh build/macos/Build/Products/Release/credpivot_macos.app`

## M4-3 Chrome Web Store

- 扩展目录：`apps/chrome-extension/`
- 在应用内「Chrome Host」安装并固定扩展 ID；商店包须与 `native-host` 注册一致。

## M4-4 真机安装与升级

- 最低与最新 macOS（Apple Silicon）各一台：全新安装、覆盖升级、Vault 解锁与恢复点恢复各走一遍。

## M4-5 验收 AC-01～AC-32

- 设计文档 `CredPivot_V1.1_Design.md` 第 15 章；高危问题阻止发布。

## M4-6 SBOM 与依赖锁定

- Rust：`Cargo.lock` 已提交；生成 SBOM：`./scripts/generate-sbom.sh`
- Flutter：`apps/macos/pubspec.lock` 已提交。
