# 个人版验收清单（非商店 / 无 Apple 付费开发者）

适用：本机或小范围自用；Chrome 开发者模式；Mac 本地/ad-hoc 签名。

## Mac App

1. `make macos-build-debug`（或 release）成功；应用可启动，Agent 就绪。
2. 创建或打开 Vault，主密码解锁；锁定后凭据 Tab 不可泄露缓存。
3. 导出 OVB、从 OVB/恢复点恢复；切换工作库后须重新解锁。
4. 菜单栏锁定与 App 内锁定一致。

## Chrome

1. 打开 **Chrome** 标签：扩展目录存在；Finder 可打开；可跳转 `chrome://extensions`。
2. 开发者模式 → **加载已解压的扩展**（选 App 同步的目录或 `~/.credpivot/chrome-extension`）。
3. 复制扩展 ID → 粘贴 → **更新 Native Host**；完全退出 Chrome 后重开。
4. Vault 主密码解锁后，扩展 popup 可连接 App；保存/填充走通一条站点。
5. **ID 变更**：删除并重新加载扩展后 ID 变化 → 仅更新 ID 并重装 Host，无需改仓库。

## 已知非目标

- 无公证 / 无 Chrome 商店；Gatekeeper 与扩展加载步骤由用户自行完成。
- Touch ID 为操作门槛，不等于 Vault 解锁（须主密码挂载库）。
