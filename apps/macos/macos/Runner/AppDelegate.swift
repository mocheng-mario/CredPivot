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
    if Self.launchedForBrowser {
      mainFlutterWindow?.orderOut(nil)
      NSApp.setActivationPolicy(.accessory)
    }
    menuBar = MenuBarController(appDelegate: self)
    LifecycleBridge.shared.start()

    if let controller = mainFlutterWindow?.contentViewController as? FlutterViewController {
      ChromeHostInstaller.applyTrustedNativeHostEnv()
      SshAskpassLauncher.applyTrustedAskpassEnv()
      _ = try? SshAskpassLauncher.materializeInstalledBinary()
      _ = try? SshAskpassLauncher.materializeExpectScript()
      TerminalLauncher.purgeTerminalLaunchScripts()
      platform = CredPivotPlatform(messenger: controller.engine.binaryMessenger)
      let code = CredPivotRustFFI.start()
      if code == 0 {
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
