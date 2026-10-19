import Cocoa
import FlutterMacOS
import LocalAuthentication
import Security
import ServiceManagement

final class CredPivotPlatform: NSObject {
  private let channel: FlutterMethodChannel

  init(messenger: FlutterBinaryMessenger) {
    channel = FlutterMethodChannel(name: "credpivot/agent", binaryMessenger: messenger)
    super.init()
    channel.setMethodCallHandler(handle)
  }

  private func agentIsUnlocked() -> Bool {
    let resp = credpivotAgentRequestJsonString(#"{"type":"status"}"#)
    return resp.contains("\"unlocked\":true")
  }

  private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "startAgent":
      let code = CredPivotRustFFI.start()
      result(code == 0 ? nil : FlutterError(code: "agent", message: "start failed", details: code))
    case "agentRequest":
      guard let json = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "expected json string", details: nil))
        return
      }
      result(credpivotAgentRequestJsonString(json))
    case "lockVault":
      _ = credpivotAgentRequestJsonString(#"{"type":"lock"}"#)
      result(nil)
    case "unlockPassword":
      guard let password = call.arguments as? String else {
        result(false)
        return
      }
      let escaped = password.replacingOccurrences(of: "\"", with: "\\\"")
      let body = #"{"type":"unlock_password","password":"\#(escaped)"}"#
      let resp = credpivotAgentRequestJsonString(body)
      result(resp.contains("\"unlocked\":true"))
    case "unlockTouchId":
      TouchIdGate.shared.authenticate { ok, token in
        DispatchQueue.main.async {
          guard ok, let token else {
            result(false)
            return
          }
          let escaped = token.replacingOccurrences(of: "\"", with: "\\\"")
          let body = #"{"type":"unlock_touch_id_token","token":"\#(escaped)"}"#
          let unlocked = credpivotAgentRequestJsonString(body).contains("\"unlocked\":true")
          if unlocked {
            (NSApp.delegate as? AppDelegate)?.showMainWindow()
          }
          result(unlocked)
        }
      }
    case "registerLoginItem":
      let enabled = (call.arguments as? Bool) ?? true
      LoginItemRegistrar.setEnabled(enabled, result: result)
    case "installChromeHost":
      ChromeHostInstaller.install()
      result(nil)
    case "appendSshIdentityAgent":
      if !agentIsUnlocked() {
        result([
          "ok": false,
          "message": "Vault 已锁定：请先解锁后再配置 SSH IdentityAgent（签名仍依赖解锁后的 Agent）",
        ])
        return
      }
      result(SshIdentityAgentHelper.appendSnippet())
    case "removeSshIdentityAgent":
      result(SshIdentityAgentHelper.removeSnippet())
    case "residentMemoryBytes":
      result(ProcessMemory.residentBytes())
    case "pickDirectory":
      DispatchQueue.main.async {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "选择"
        result(panel.runModal() == .OK ? panel.url?.path : nil)
      }
    case "pickOpenFile":
      DispatchQueue.main.async {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.data]
        panel.prompt = "打开"
        result(panel.runModal() == .OK ? panel.url?.path : nil)
      }
    case "pickSaveFile":
      let defaultName = (call.arguments as? String) ?? "backup.ovb"
      DispatchQueue.main.async {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = defaultName
        panel.allowedContentTypes = [.data]
        panel.prompt = "保存"
        result(panel.runModal() == .OK ? panel.url?.path : nil)
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }

}

// MARK: - Touch ID scheme A (LAContext gate + login keychain wrapper)

final class TouchIdGate {
  static let shared = TouchIdGate()
  /// 生物识别弹窗期间勿因 resign-active 误锁 Agent。
  static var isAuthenticating = false

  private let keychainService = "com.credpivot.macos.touchid.m0"
  private let keychainAccount = "vmk-wrapper-token"

  func authenticate(completion: @escaping (Bool, String?) -> Void) {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
      completion(false, nil)
      return
    }
    TouchIdGate.isAuthenticating = true
    context.evaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: "CredPivot：Touch ID 操作门槛（非 VMK 绑定）"
    ) { success, _ in
      TouchIdGate.isAuthenticating = false
      guard success else {
        completion(false, nil)
        return
      }
      let token = self.loadOrCreateToken()
      completion(true, token)
    }
  }

  private func loadOrCreateToken() -> String {
    if let existing = KeychainLoginStore.read(service: keychainService, account: keychainAccount) {
      return existing
    }
    let token = UUID().uuidString
    KeychainLoginStore.write(service: keychainService, account: keychainAccount, value: token)
    _ = agentConfigureTouchIdToken(token)
    return token
  }

  private func agentConfigureTouchIdToken(_ token: String) -> Bool {
    let escaped = token.replacingOccurrences(of: "\"", with: "\\\"")
    let body = #"{"type":"set_touch_id_token","token":"\#(escaped)"}"#
    return credpivotAgentRequestJsonString(body).contains("\"configured\":true")
  }
}

enum KeychainLoginStore {
  static func write(service: String, account: String, value: String) {
    let data = value.data(using: .utf8) ?? Data()
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecValueData as String: data,
      kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ]
    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
  }

  static func read(service: String, account: String) -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else { return nil }
    return String(data: data, encoding: .utf8)
  }
}

enum LoginItemRegistrar {
  static func setEnabled(_ enabled: Bool, result: @escaping FlutterResult) {
    if #available(macOS 13.0, *) {
      let service = SMAppService.mainApp
      do {
        if enabled {
          try service.register()
        } else {
          try service.unregister()
        }
        result(nil)
      } catch {
        result(FlutterError(code: "login_item", message: error.localizedDescription, details: nil))
      }
    } else {
      result(FlutterError(code: "login_item", message: "requires macOS 13+", details: nil))
    }
  }
}

enum ChromeHostInstaller {
  static func install() {
    guard let host = Bundle.main.path(forResource: "credpivot-native-host", ofType: nil) else {
      NSLog("CredPivot: native host binary missing from bundle")
      return
    }
    let manifest: [String: Any] = [
      "name": "com.credpivot.chrome.m0",
      "description": "CredPivot M0 Native Messaging Host",
      "path": host,
      "type": "stdio",
      "allowed_origins": ["chrome-extension://REPLACE_WITH_EXTENSION_ID/"],
    ]
    let dir = FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent("Library/Application Support/Google/Chrome/NativeMessagingHosts", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let url = dir.appendingPathComponent("com.credpivot.chrome.m0.json")
    if let data = try? JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted]) {
      try? data.write(to: url)
    }
  }
}

enum SshIdentityAgentHelper {
  private static let markerStart = "# >>> CredPivot M0 IdentityAgent"
  private static let markerEnd = "# <<< CredPivot M0"

  /// 写入 ~/.ssh/config；返回给 Flutter 展示结果（M0 无静默成功）。
  static func appendSnippet() -> [String: Any] {
    let home = FileManager.default.homeDirectoryForCurrentUser
    let credDir = home.appendingPathComponent(".credpivot", isDirectory: true)
    try? FileManager.default.createDirectory(at: credDir, withIntermediateDirectories: true)
    let socket = credDir.appendingPathComponent("ssh.sock").path
    let block = """
\(markerStart)
Host *
  IdentityAgent \(socket)
\(markerEnd)
"""
    let sshDir = home.appendingPathComponent(".ssh", isDirectory: true)
    let config = sshDir.appendingPathComponent("config")

    do {
      try FileManager.default.createDirectory(at: sshDir, withIntermediateDirectories: true)
      var text = (try? String(contentsOf: config, encoding: .utf8)) ?? ""

      if text.contains(markerStart) {
        if text.contains("IdentityAgent") && !text.contains("    Host *") {
          return [
            "ok": true,
            "already": true,
            "message": "已配置 IdentityAgent，无需重复写入",
            "configPath": config.path,
            "socketPath": socket,
          ]
        }
        text = replaceCredPivotBlock(in: text, with: block)
      } else {
        if !text.isEmpty && !text.hasSuffix("\n") {
          text += "\n"
        }
        text += "\n" + block + "\n"
      }

      try text.write(to: config, atomically: true, encoding: .utf8)
      return [
        "ok": true,
        "already": false,
        "message": "已写入 ~/.ssh/config。请先解锁 Vault，再在终端执行: ssh-add -l",
        "configPath": config.path,
        "socketPath": socket,
      ]
    } catch {
      return [
        "ok": false,
        "message": "写入失败: \(error.localizedDescription)",
        "configPath": config.path,
        "socketPath": socket,
      ]
    }
  }

  /// 从 ~/.ssh/config 移除 CredPivot 标记块（设计文档「一键撤销」）。
  static func removeSnippet() -> [String: Any] {
    let home = FileManager.default.homeDirectoryForCurrentUser
    let config = home.appendingPathComponent(".ssh/config")
    guard FileManager.default.fileExists(atPath: config.path) else {
      return [
        "ok": false,
        "message": "未找到 ~/.ssh/config",
        "configPath": config.path,
      ]
    }
    do {
      var text = try String(contentsOf: config, encoding: .utf8)
      guard text.contains(markerStart) else {
        return [
          "ok": false,
          "message": "配置中无 CredPivot IdentityAgent 标记块",
          "configPath": config.path,
        ]
      }
      text = removeCredPivotBlock(from: text)
      try text.write(to: config, atomically: true, encoding: .utf8)
      return [
        "ok": true,
        "message": "已从 ~/.ssh/config 移除 CredPivot IdentityAgent 片段",
        "configPath": config.path,
      ]
    } catch {
      return [
        "ok": false,
        "message": "移除失败: \(error.localizedDescription)",
        "configPath": config.path,
      ]
    }
  }

  private static func replaceCredPivotBlock(in text: String, with block: String) -> String {
    guard let start = text.range(of: markerStart),
          let end = text.range(of: markerEnd) else {
      return text
    }
    let afterEnd = text[end.upperBound...]
    let before = text[..<start.lowerBound]
    return String(before) + block + "\n" + String(afterEnd)
  }

  private static func removeCredPivotBlock(from text: String) -> String {
    guard let start = text.range(of: markerStart),
          let end = text.range(of: markerEnd) else {
      return text
    }
    var before = String(text[..<start.lowerBound])
    var after = String(text[end.upperBound...])
    while before.hasSuffix("\n") && before.count > 1 {
      before.removeLast()
    }
    while after.hasPrefix("\n") {
      after.removeFirst()
    }
    if before.isEmpty {
      return after
    }
    if after.isEmpty {
      return before + "\n"
    }
    return before + "\n" + after
  }
}
