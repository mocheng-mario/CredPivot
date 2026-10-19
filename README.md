# CredPivot

离线优先的统一凭据管理器（设计见 `docs/Plans/CredPivot_V1.1_Design.md`）。

## M0 平台可行性（当前仓库）

Monorepo 布局：

```text
crates/agent/           # 进程内 Agent（假数据、IPC、SSH agent）
crates/native-host/     # Chrome Native Messaging 中继
crates/credpivot-ffi/   # Flutter macOS 宿主 FFI
apps/macos/             # Flutter UI + Swift 平台层
apps/chrome-extension/  # Chrome MV3 原型
specs/ipc_m0.md         # M0 IPC 说明
docs/specs/M0_Platform_Findings.md
```

### 构建前提

- macOS 15+（建议 M 系列真机）
- [Rust](https://rustup.rs) stable
- [Flutter](https://docs.flutter.dev/get-started/install/macos)（macOS 桌面）
- Xcode 命令行工具

### Make（推荐）

```bash
make help              # 列出全部目标
make macos-bootstrap   # 首次：Flutter 工程 + Rust + debug 构建
```

日常分步：

```bash
make rust-ffi rust-host
make macos-sync-artifacts
make macos-build
make chrome-host-manifest   # 写入 Chrome Host 清单后改扩展 ID
```

亦可直接：`chmod +x scripts/bootstrap-macos.sh && ./scripts/bootstrap-macos.sh`

Chrome 扩展：在 `chrome://extensions` 加载 `apps/chrome-extension`（开发者模式），将 `native-messaging-host-m0.json` 中的 `allowed_origins` 替换为实际扩展 ID。

### M0 演示解锁

- 主密码：`credpivot-m0`（仅假数据阶段）

### 开发调试

- 跳过 socket 对端校验：`CREDPIVOT_DEV_SKIP_PEER_CHECK=1`
- Gatekeeper quarantine：`xattr -cr /path/to/CredPivot.app`
