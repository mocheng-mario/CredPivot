import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  private var menuBar: MenuBarController?
  private var platform: CredPivotPlatform?

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    true
  }

  override func applicationDidFinishLaunching(_ notification: Notification) {
    menuBar = MenuBarController(appDelegate: self)
    LifecycleBridge.shared.start()

    if let controller = mainFlutterWindow?.contentViewController as? FlutterViewController {
      ChromeHostInstaller.applyTrustedNativeHostEnv()
      SshAskpassLauncher.applyTrustedAskpassEnv()
      ExtensionGateCoordinator.start()
      _ = try? SshAskpassLauncher.materializeInstalledBinary()
      _ = try? SshAskpassLauncher.materializeExpectScript()
      TerminalLauncher.purgeTerminalLaunchScripts()
      platform = CredPivotPlatform(messenger: controller.engine.binaryMessenger)
      let code = CredPivotRustFFI.start()
      if code != 0 {
        NSLog("CredPivot: agent start failed at launch (code \(code))")
      }
    }

    showMainWindow()
  }

  @objc func showMainWindow() {
    NSApp.setActivationPolicy(.regular)
    mainFlutterWindow?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  @objc func lockFromMenu() {
    _ = credpivotAgentRequestJsonString(#"{"type":"lock"}"#)
    CredPivotPlatform.publishVaultLocked()
  }

  @objc func quitApp() {
    _ = CredPivotRustFFI.stop()
    NSApp.terminate(nil)
  }
}
