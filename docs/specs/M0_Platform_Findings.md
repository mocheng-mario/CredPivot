# M0 平台可行性结论（实施记录）

> 状态：代码骨架已落地；下列“真机测量”项需在 macOS 15+ M 系列机器上按清单自检后填写数值。

## M0-1 Mac App 骨架

| 项 | 结论 |
|:---|:---|
| Flutter + Swift 分层 | `apps/macos`（UI）+ `macos/Runner/*.swift`（平台）+ `crates/credpivot-ffi`（Rust Agent FFI） |
| Hardened Runtime | Release entitlements 已预留；正式签名在 M4，开发期可用 ad-hoc 签名 + `xattr -cr` 去除 quarantine |
| 本地证书 | `scripts/bootstrap-macos.sh` 走 `flutter build macos`；Team ID 写入后用于 Host/socket 校验 |

## M0-2 登录常驻与菜单栏

| 项 | 结论 |
|:---|:---|
| `SMAppService` | `LoginItemRegistrar`（macOS 13+ `SMAppService.mainApp`） |
| 关窗不退出 | `applicationShouldTerminateAfterLastWindowClosed = false`；`MainFlutterWindow.close()` 仅 `orderOut` |
| 菜单栏 | `MenuBarController`：显示/锁定/退出 |

## M0-3 进程内 Rust Agent + 单写入者

| 项 | 结论 |
|:---|:---|
| Agent | `credpivot-agent`：`~/.credpivot/agent.sock` JSON IPC + `vault.runtime.lock` 排他锁 |
| Flutter 调用 | Swift `credpivot_agent_*` FFI，不经 Dart 直接持密钥 |
| 假数据 | 演示主密码 `credpivot-m0`；内存 Map 凭据，无 SQLCipher |

## M0-4 Touch ID 方案 A / 方案 B 可行性

| 方案 | M0 实现 | 结论 |
|:---|:---|:---|
| **A（首版）** | `LAContext` 生物识别门槛通过后，读取/创建登录 Keychain 中的本地令牌，再 `unlock_touch_id_token` | 已接线；UI 文案应避免“指纹保护密钥” |
| **B（后续）** | 需 Apple Developer 账号、`keychain-access-group`、Provisioning Profile 与 `SecAccessControl` 生物绑定 | **未在本仓库实现**；预期指纹变更可使旧包装失效，防护强于 A，但依赖付费账号与签名体系 |

## M0-5 Native Host 中继

| 项 | 结论 |
|:---|:---|
| Chrome 父进程 | `verify_chrome_parent()`：父进程可执行文件名为 `Google Chrome` / Canary |
| Team ID / 对端校验 | Agent 对 Unix 连接做 `getpeereid` + 可执行路径校验；开发可设 `CREDPIVOT_DEV_SKIP_PEER_CHECK=1` |
| 拉起 App | socket 不存在时 `open -b com.credpivot.macos` + 8s 等待 |
| Host 注册 | `ChromeHostInstaller` 写入 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |

## M0-6 Chrome MV3 原型

| 项 | 结论 |
|:---|:---|
| Native Host 名 | `com.credpivot.chrome.m0` |
| SW 回收 | `background.js`：`onDisconnect` 清空 `inflight`，不续期 |
| 秘密投递 | `chrome.tabs.sendMessage` + `frameId`；Agent 侧 `fill_consume` 校验 `frame_id` / `document_id` |

## M0-7 SSH Agent 原型

| 项 | 结论 |
|:---|:---|
| Socket | `~/.credpivot/ssh.sock`（路径长度 << 104） |
| `IdentityAgent` | `SshIdentityAgentHelper` 接入/撤销标记块（设计「一键撤销」）；接入需 Vault 解锁 |
| 算法 | Ed25519（`ed25519-dalek`）；OpenSSH agent 消息子集 |

## M0-8 锁定与内存（待真机填写）

| 场景 | 预期行为 | 实测 |
|:---|:---|:---|
| 空闲 5 分钟 | Agent `idle_expired` 自动锁定 | 待测 |
| 锁屏 / 会话失效 | `LifecycleBridge` → `lock` | 待测 |
| 睡眠 | `willSleepNotification` → `lock` | 待测 |
| 关窗后 Flutter 内存 | 菜单栏常驻 | UI 展示本进程 resident（MB/GB）；关窗对比仍建议活动监视器复测 |

## M0-9 回写设计文档的条款（摘要）

以下与 `docs/Plans/CredPivot_V1.1_Design.md` 一致，M0 原型已按此实现边界：

1. **进程模型**：Agent 在 App 进程内；Host 仅中继。
2. **Touch ID 首版**：方案 A 为操作门槛 + 登录 Keychain 包装，非密码学绑定。
3. **扩展生命周期**：授权与秘密在 App；SW 回收作废未完成 `request_id`。
4. **SSH**：独立短路径 socket + `IdentityAgent`，不替换系统 `SSH_AUTH_SOCK`。
5. **锁定**：锁屏/睡眠立即失效；空闲 5 分钟（活动 = 与 Agent 交互）。

## 完成标准自检清单

- [ ] Chrome 保存/填充（假数据）走通 Host → Agent
- [ ] 终端 `ssh-add -l` 经 IdentityAgent 可见 Ed25519 密钥（解锁后）
- [ ] 关主窗口后菜单栏仍可服务 / 锁定后拒绝填充与签名
- [ ] 取消/超时/`request_id` 作废
- [ ] 双开 App 触发单写入者锁冲突或唤起已有实例
