# CredPivot

离线优先的 macOS / Android 凭据管理器，macOS 可配合 Chrome 扩展使用。当前 App 为 **0.1.0-beta.5+6**，仍需真实设备和网站兼容性验收。

## 支持范围

- macOS 15+，当前发布验证目标为 Apple Silicon。
- Android 9+；系统通行密钥提供程序需要 Android 14+，具体网站与应用兼容性需真机验收。
- 登录密码、候选和历史、MFA/TOTP、Ed25519 SSH、服务器连接、恢复码及安全笔记。
- 分区、分组与折叠、回收站、应用内快捷键、深浅色及语言包导入导出。
- 实时搜索、按模块记忆排序、固定批量操作栏、Shift 连选、批量恢复及携带选择的分区迁移。
- 重复网站账密对比与确认合并，合并前生成恢复点，原记录进入回收站。
- 本地加密备份、恢复密钥、独立恢复 CLI；WebDAV 加密同步与冲突预览。
- Chrome 顶层页面的手动保存/更新与填充；通行密钥为逐站启用的预览功能。

S3 只有占位入口；HOTP、其他 SSH 私钥算法和 Chrome iframe 登录填充尚不支持。内置语言为简体中文。Chrome 通行密钥目前限制为顶层 HTTPS、同主机 RP ID 和 ES256，条件式自动填充仍由浏览器处理。

## 下载与安装

发布产物分别提供，**CLI 不在 App 包内**：

1. `CredPivot-<版本>-macos-<架构>.zip`：解压后将 App 放入 Applications 再运行。无付费开发者证书的 Beta 为本地签名包，未公证；首次打开可能需要在系统安全设置中明确允许。
2. `CredPivot-Chrome-<插件版本>.zip`：解压，在 `chrome://extensions` 开启开发者模式并加载目录。在 App 的浏览器设置填写扩展 ID、更新 Native Host，然后在插件重试连接。移动 App 后应重新更新 Host。
3. `credpivot-cli-<版本>-macos-<架构>.tar.gz`：独立恢复工具，无须先安装 App。解压后可直接执行；恢复目标必须是空目录。

每个归档附带 `.sha256`。在归档所在目录执行 `shasum -a 256 -c <归档名>.sha256` 校验传输完整性；校验和不能代替发行方身份验证。

App 版本以 `apps/macos/pubspec.yaml` 为准，当前为 `0.1.0-beta.5+6`；Rust Agent、Native Host 与 CLI 的包版本为 `0.1.0-beta.2`，配套 Chrome 扩展为 `0.9.12`。App 诊断页集中展示版本、构建标识、协议、Schema 和 Native Host 安装状态；插件弹窗显示浏览器实际加载的插件版本及本机组件版本，版本不一致时提供更新步骤。不同组件不要求版本号相同。当前没有应用自动更新器，升级采用手动替换。

## 开始使用与备份

创建保险库时设置自己的主密码并离线保存恢复密钥；没有内置演示密码。按策略使用主密码或本机身份验证解锁。

添加真实凭据前，先导出 OVB，并在空目录分别演练主密码恢复和恢复密钥恢复。恢复密钥遗失且主密码不可用时，不能承诺找回数据。本地工作库不要放进实时云盘同步目录，跨设备使用 App 的加密同步功能。

分区不提供独立密码或加密边界，所有分区共用保险库授权、备份和同步。迁移时关联记录必须一起迁移。

WebDAV 接入应先测试，再选择远端、本地或合并策略并核对预览。当前为 Schema 14；不同 Schema 的客户端不能互相同步。开发期旧远端需保留备份后改用新的同步目录，App 不会自动删除旧远端。公开版本后续结构变更须提供明确迁移方案，不以清空用户数据作为常规升级方式。

## 独立 CLI

```bash
./credpivot-cli --version
./credpivot-cli inspect backup.ovb
./credpivot-cli verify backup.ovb
./credpivot-cli recover backup.ovb /path/to/empty-directory
./credpivot-cli recover backup.ovb /path/to/another-empty-directory --recovery
```

密码与恢复密钥在终端交互输入，不通过命令行参数传递。`export-json` 导出包含全部秘密的明文文件，仅在明确需要时使用并妥善保管。CLI 尚无 `ssh` 子命令。

## 从源码构建

需要 Rust stable、Flutter macOS SDK 与 Xcode，依赖由开发者预先安装。

```bash
make macos-build-debug
make release-app
make release-cli
make release-extension
# 或一次生成三个独立下载项
make release
```

产物与校验和输出到 `dist/`，只生成本地文件，不上传。Release 构建不覆盖开发机 `~/.credpivot` 中已安装的辅助程序；Debug 默认保留开发期同步行为，可用 `INSTALL_DEV_ARTIFACTS=0` 关闭。

`CREDPIVOT_DEV_SKIP_PEER_CHECK=1` 仅在 Debug 中跳过本机 IPC 对端路径、签名及摘要校验；不会直接解锁保险库。Release 忽略该开关。不要向普通用户推荐启用它。

具备 Apple Developer ID 后，可用 `scripts/notarize-macos.sh` 对构建结果签名、公证，再重新打包。Beta 的本地签名不能被描述为 Apple 公证。发布验收见 `docs/specs/Personal_Edition_Acceptance.md`。
