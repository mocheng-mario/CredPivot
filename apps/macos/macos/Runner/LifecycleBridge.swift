import Cocoa

/// 锁屏 / 睡眠 / 空闲时通知 Agent 锁定（M0 验证入口）。
final class LifecycleBridge {
  static let shared = LifecycleBridge()

  func start() {
    let center = NSWorkspace.shared.notificationCenter
    center.addObserver(self, selector: #selector(screenLocked), name: NSWorkspace.screensDidSleepNotification, object: nil)
    center.addObserver(self, selector: #selector(screenLocked), name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
    NotificationCenter.default.addObserver(self, selector: #selector(systemWillSleep), name: NSWorkspace.willSleepNotification, object: nil)
  }

  @objc private func screenLocked() {
    lockAgent()
  }

  @objc private func systemWillSleep() {
    lockAgent()
  }

  private func lockAgent() {
    _ = credpivotAgentRequestJsonString(#"{"type":"lock"}"#)
  }
}
