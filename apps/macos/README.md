# CredPivot macOS

Flutter UI、Swift 平台集成及进程内 Rust Agent。支持 macOS 15+，版本和发布目标以仓库根目录 README 为准。

在仓库根目录执行 `make macos-build-debug` 或 `make release-app`。独立恢复 CLI 使用 `make release-cli` 单独打包，不进入 App 包。发布资源必须包含 native-host、askpass、expect 脚本和 Chrome 扩展。

安装、备份恢复、已知限制和发布验收见根目录 README 及 `docs/specs/Personal_Edition_Acceptance.md`。
