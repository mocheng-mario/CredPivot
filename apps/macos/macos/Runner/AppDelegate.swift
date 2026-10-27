import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  static let launchedForBrowser = ProcessInfo.processInfo.arguments.contains("--credpivot-browser-background")
  private var menuBar: MenuBarController?
  private var platform: CredPivotPlatform?

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    true
  }

  override func applicationDidFinishLaunching(_ notification: Notification) {
    // 发包时实际验证 dyld/Flutter 可启动，且不启动 Agent、不触碰用户保险库或集成配置。
    if ProcessInfo.processInfo.arguments.contains("--credpivot-startup-check") {
      mainFlutterWindow?.orderOut(nil)
      print("CredPivot startup check passed")
      NSApp.terminate(nil)
      return
    }
    if Self.launchedForBrowser {
      mainFlutterWindow?.orderOut(nil)
      NSApp.setActivationPolicy(.accessory)
    }
    menuBar = MenuBarController(appDelegate: self)
    LifecycleBridge.shared.start()

    if let controller = mainFlutterWindow?.contentViewController as? FlutterViewController {
      ChromeHostInstaller.applyTrustedNativeHostEnv()
      SshAskpassLauncher.applyTrustedAskpassEnv()
      platform = CredPivotPlatform(messenger: controller.engine.binaryMessenger)
      let code = CredPivotRustFFI.start()
      if code == 0 {
        // 只有持有 Agent 单写锁的实例才能更新共享集成，避免第二个 Debug/Release 实例覆盖它。
        _ = try? SshAskpassLauncher.materializeInstalledBinary()
        _ = try? SshAskpassLauncher.materializeExpectScript()
        TerminalLauncher.purgeTerminalLaunchScripts()
        _ = ChromeHostInstaller.applyPreference()
        _ = LoginItemRegistrar.applyPreference()
        ExtensionGateCoordinator.start()
      }
      if code != 0 {
        NSLog("CredPivot: agent start failed at launch (code \(code))")
      }
    }

    if !Self.launchedForBrowser {
      showMainWindow()
    }
  }

  @objc func showMainWindow() {
    NSApp.setActivationPolicy(.regular)
    mainFlutterWindow?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  @objc func lockFromMenu() {
    TouchIdGate.invalidateInFlightAuthentication()
    _ = credpivotAgentRequestJsonString(#"{"type":"lock"}"#)
    CredPivotPlatform.publishVaultLocked()
  }

  @objc func quitApp() {
    _ = CredPivotRustFFI.stop()
    NSApp.terminate(nil)
  }
}
