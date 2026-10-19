# M0 IPC（假数据原型）

## Agent Unix Socket

- 路径：`~/.credpivot/agent.sock`（目录 `0700`）
- 帧格式：4 字节 little-endian 长度 + UTF-8 JSON
- 请求：`{ "type": "<snake_case>", ... }`（见 `crates/agent/src/protocol.rs`）

## SSH Agent Socket

- 路径：`~/.credpivot/ssh.sock`
- 协议：OpenSSH ssh-agent 二进制消息（仅 `request identities` / `sign request`，Ed25519）

## Native Messaging

Host 与 Chrome 扩展使用 Chrome 标准 4 字节 little-endian JSON；Host 将 `action` 字段映射为 Agent 请求。

## 单写入者

- 锁文件：`~/.credpivot/vault.runtime.lock`（`flock` 排他锁）
- 第二个 App 实例应检测到锁冲突并转为唤起已运行实例（M0：返回错误码，由 Swift 层 `NSRunningApplication` 激活）
