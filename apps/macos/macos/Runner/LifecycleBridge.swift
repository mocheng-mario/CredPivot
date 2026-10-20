import Cocoa

/// 锁屏 / 睡眠时通知 Agent 锁定。勿用 sessionDidResignActive（Touch ID / 文件面板也会触发）。
final class LifecycleBridge {
  static let shared = LifecycleBridge()

  func start() {
    let workspace = NSWorkspace.shared.notificationCenter
    workspace.addObserver(
      self,
      selector: #selector(systemWillSleep),
      name: NSWorkspace.willSleepNotification,
      object: nil
    )
    workspace.addObserver(
      self,
      selector: #selector(screensDidSleep),
      name: NSWorkspace.screensDidSleepNotification,
      object: nil
    )

    DistributedNotificationCenter.default().addObserver(
      self,
      selector: #selector(screenLocked),
      name: NSNotification.Name("com.apple.screenIsLocked"),
      object: nil
    )
  }

  @objc private func screenLocked() {
    lockAgentUnlessTouchId()
  }

  @objc private func screensDidSleep() {
    lockAgentUnlessTouchId()
  }

  @objc private func systemWillSleep() {
    lockAgentUnlessTouchId()
  }

  private func lockAgentUnlessTouchId() {
    if TouchIdGate.isAuthenticating {
      return
    }
    _ = credpivotAgentRequestJsonString(#"{"type":"lock"}"#)
    CredPivotPlatform.publishVaultLocked()
  }
}
