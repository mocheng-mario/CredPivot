import Cocoa
import FlutterMacOS
import UniformTypeIdentifiers
import LocalAuthentication
import Security
import ServiceManagement

extension Notification.Name {
  static let credPivotVaultLocked = Notification.Name("CredPivotVaultLocked")
}

final class CredPivotPlatform: NSObject {
  private let channel: FlutterMethodChannel

  init(messenger: FlutterBinaryMessenger) {
    channel = FlutterMethodChannel(name: "credpivot/agent", binaryMessenger: messenger)
    super.init()
    channel.setMethodCallHandler(handle)
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(vaultLockedExternally),
      name: .credPivotVaultLocked,
      object: nil
    )
  }

  @objc private func vaultLockedExternally() {
    DispatchQueue.main.async {
      self.channel.invokeMethod("onVaultLocked", arguments: nil)
    }
  }

  static func publishVaultLocked() {
    NotificationCenter.default.post(name: .credPivotVaultLocked, object: nil)
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
    case "restartAgent":
      let code = CredPivotRustFFI.restart()
      result(code == 0)
    case "agentIsRunning":
      result(CredPivotRustFFI.isRunning())
    case "relaunchApp":
      AppRelauncher.relaunch()
      result(nil)
    case "agentRequest":
      guard let json = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "expected json string", details: nil))
        return
      }
      result(credpivotAgentRequestJsonString(json))
    case "lockVault":
      _ = credpivotAgentRequestJsonString(#"{"type":"lock"}"#)
      CredPivotPlatform.publishVaultLocked()
      result(nil)
    case "unlockPassword":
      guard let password = call.arguments as? String else {
        result(false)
        return
      }
      guard
        let data = try? JSONSerialization.data(withJSONObject: [
          "type": "unlock_password",
          "password": password,
        ]),
        let body = String(data: data, encoding: .utf8)
      else {
        result(false)
        return
      }
      let resp = credpivotAgentRequestJsonString(body)
      result(resp.contains("\"unlocked\":true"))
    case "authenticateTouchId":
      let reason = (call.arguments as? String) ?? "CredPivot 需要验证您的身份"
      TouchIdGate.shared.authenticateBiometricOnly(reason: reason) { ok in
        DispatchQueue.main.async {
          result(ok)
        }
      }
    case "unlockTouchId":
      TouchIdGate.shared.authenticateForUnlock { ok, token in
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
    case "getChromeExtensionId":
      result(ChromeHostInstaller.storedExtensionId() ?? "")
    case "chromeHostStatus":
      result(ChromeHostInstaller.status())
    case "installChromeHost":
      let extId = call.arguments as? String
      result(ChromeHostInstaller.install(extensionId: extId))
    case "revealChromeExtensionDir":
      result(ChromeHostInstaller.revealExtensionDirectory())
    case "openChromeExtensionsPage":
      result(ChromeHostInstaller.openChromeExtensionsPage())
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
    case "readTextFile":
      guard let path = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "path required", details: nil))
        return
      }
      do {
        result(try String(contentsOfFile: path, encoding: .utf8))
      } catch {
        result(FlutterError(code: "io", message: error.localizedDescription, details: nil))
      }
    case "copyConcealed":
      guard let secret = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "secret required", details: nil))
        return
      }
      ConcealedPasteboard.copyConcealed(secret, clearAfterSeconds: 30)
      result(nil)
    case "getTerminalPreference":
      result(TerminalLauncher.preferencePayload())
    case "pickTerminalApplication":
      if let picked = TerminalLauncher.pickApplication() {
        result(picked)
      } else {
        result(nil)
      }
    case "setTerminalPreference":
      guard let id = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "terminal id required", details: nil))
        return
      }
      TerminalLauncher.setLegacyPreset(id)
      result(nil)
    case "openSshInTerminal":
      guard let args = call.arguments as? [String: Any],
            let host = args["host"] as? String,
            let username = args["username"] as? String else {
        result(FlutterError(code: "bad_args", message: "host/username required", details: nil))
        return
      }
      let port = args["port"] as? Int ?? 22
      if let err = TerminalLauncher.openSsh(host: host, port: port, user: username) {
        result(err)
      } else {
        result(nil)
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

  /// 敏感操作门槛：仅 Touch ID，不访问钥匙串（避免二次输入登录密码）。
  func authenticateBiometricOnly(reason: String, completion: @escaping (Bool) -> Void) {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
      completion(false)
      return
    }
    TouchIdGate.isAuthenticating = true
    context.evaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: reason
    ) { success, _ in
      TouchIdGate.isAuthenticating = false
      completion(success)
    }
  }

  /// Touch ID 解锁 Agent 门槛：指纹通过后读取/创建钥匙串中的门槛令牌。
  func authenticateForUnlock(completion: @escaping (Bool, String?) -> Void) {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
      completion(false, nil)
      return
    }
    TouchIdGate.isAuthenticating = true
    context.evaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: "CredPivot：Touch ID 解锁"
    ) { success, _ in
      TouchIdGate.isAuthenticating = false
      guard success else {
        completion(false, nil)
        return
      }
      let token = self.loadOrCreateToken(context: context)
      completion(true, token)
    }
  }

  private func loadOrCreateToken(context: LAContext) -> String {
    if let existing = KeychainLoginStore.read(
      service: keychainService,
      account: keychainAccount,
      context: context
    ) {
      return existing
    }
    if let legacy = KeychainLoginStore.read(
      service: keychainService,
      account: keychainAccount,
      context: nil
    ) {
      return legacy
    }
    let token = UUID().uuidString
    _ = KeychainLoginStore.writeBiometricProtected(
      service: keychainService,
      account: keychainAccount,
      value: token
    )
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
  static func writeBiometricProtected(service: String, account: String, value: String) -> Bool {
    let data = value.data(using: .utf8) ?? Data()
    var createError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .biometryCurrentSet,
      &createError
    ) else {
      return false
    }
    let deleteQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
    SecItemDelete(deleteQuery as CFDictionary)
    let addQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrAccessControl as String: access,
      kSecValueData as String: data,
    ]
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    return status == errSecSuccess
  }

  static func read(service: String, account: String, context: LAContext?) -> String? {
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    if let context {
      query[kSecUseAuthenticationContext as String] = context
    }
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
  private static let hostName = "com.credpivot.chrome.m0"
  private static let credPivotDir: URL = {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot", isDirectory: true)
  }()
  private static let configPath: URL = credPivotDir.appendingPathComponent("chrome_extension_id")
  private static let installedHostPath: URL = credPivotDir.appendingPathComponent("credpivot-native-host")
  private static let manifestURL: URL = {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(
        "Library/Application Support/Google/Chrome/NativeMessagingHosts/\(hostName).json",
        isDirectory: false
      )
  }()

  static func status() -> [String: Any] {
    let stored = storedExtensionId() ?? ""
    let manifestId = manifestExtensionId()
    var out: [String: Any] = [
      "host_name": hostName,
      "manifest_path": manifestURL.path,
      "manifest_exists": FileManager.default.fileExists(atPath: manifestURL.path),
      "installed_host_path": installedHostPath.path,
      "installed_host_exists": FileManager.default.fileExists(atPath: installedHostPath.path),
      "stored_extension_id": stored,
      "manifest_extension_id": manifestId ?? "",
      "host_id_matches_manifest": manifestId == nil || stored.isEmpty || manifestId == stored,
      "extension_dir_path": extensionDirectoryPath() ?? "",
      "extension_dir_exists": extensionDirectoryPath() != nil,
    ]
    if let data = try? Data(contentsOf: manifestURL),
       let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
      out["manifest_allowed_origins"] = json["allowed_origins"]
      out["manifest_host_binary"] = json["path"]
    }
    return out
  }

  /// 供「加载已解压的扩展」使用；不固定扩展 ID，仅提供当前构建附带的目录。
  static func extensionDirectoryPath() -> String? {
    let manifestName = "manifest.json"
    if let bundled = Bundle.main.resourceURL?.appendingPathComponent("credpivot-chrome-extension", isDirectory: true) {
      if FileManager.default.fileExists(atPath: bundled.appendingPathComponent(manifestName).path) {
        return bundled.path
      }
    }
    let cached = credPivotDir.appendingPathComponent("chrome-extension", isDirectory: true)
    if FileManager.default.fileExists(atPath: cached.appendingPathComponent(manifestName).path) {
      return cached.path
    }
    let pathFile = credPivotDir.appendingPathComponent("chrome_extension_dir.path")
    if let raw = try? String(contentsOf: pathFile, encoding: .utf8) {
      let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
      if FileManager.default.fileExists(atPath: URL(fileURLWithPath: p).appendingPathComponent(manifestName).path) {
        return p
      }
    }
    return nil
  }

  static func manifestExtensionId() -> String? {
    guard let data = try? Data(contentsOf: manifestURL),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          let origins = json["allowed_origins"] as? [String],
          let first = origins.first
    else { return nil }
    return extensionIdFromOrigin(first)
  }

  private static func extensionIdFromOrigin(_ origin: String) -> String? {
    let prefix = "chrome-extension://"
    guard origin.hasPrefix(prefix) else { return nil }
    var s = String(origin.dropFirst(prefix.count))
    if s.hasSuffix("/") {
      s = String(s.dropLast())
    }
    return s.isEmpty ? nil : s
  }

  static func revealExtensionDirectory() -> [String: Any] {
    guard let path = extensionDirectoryPath() else {
      return [
        "ok": false,
        "message": "未找到扩展目录。请先在本机执行 make macos-sync-artifacts 或 make macos-build。",
      ]
    }
    NSWorkspace.shared.selectFile(
      URL(fileURLWithPath: path).appendingPathComponent("manifest.json").path,
      inFileViewerRootedAtPath: path
    )
    return ["ok": true, "message": "已在 Finder 中显示扩展目录", "path": path]
  }

  static func openChromeExtensionsPage() -> [String: Any] {
    guard let url = URL(string: "chrome://extensions") else {
      return ["ok": false, "message": "无法构造 chrome://extensions"]
    }
    NSWorkspace.shared.open(url)
    return [
      "ok": true,
      "message": "已尝试打开 Chrome 扩展页。若未跳转，请在 Chrome 地址栏手动输入 chrome://extensions",
    ]
  }

  private static func resolveSourceHostBinary() -> String? {
    if let bundled = Bundle.main.path(forResource: "credpivot-native-host", ofType: nil) {
      return bundled
    }
    let pathFile = credPivotDir.appendingPathComponent("native_host_binary.path")
    if let raw = try? String(contentsOf: pathFile, encoding: .utf8) {
      let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
      if FileManager.default.fileExists(atPath: p) {
        return p
      }
    }
    if FileManager.default.fileExists(atPath: installedHostPath.path) {
      return installedHostPath.path
    }
    return nil
  }

  private static func materializeHostBinary() throws -> String {
    guard let src = resolveSourceHostBinary() else {
      throw NSError(
        domain: "CredPivot",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "找不到 native-host，请先 make macos-build"]
      )
    }
    try FileManager.default.createDirectory(at: credPivotDir, withIntermediateDirectories: true)
    if FileManager.default.fileExists(atPath: installedHostPath.path) {
      try FileManager.default.removeItem(at: installedHostPath)
    }
    try FileManager.default.copyItem(atPath: src, toPath: installedHostPath.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installedHostPath.path)
    return installedHostPath.path
  }

  static func storedExtensionId() -> String? {
    guard let raw = try? String(contentsOf: configPath, encoding: .utf8) else { return nil }
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
  }

  private static func normalizeExtensionId(_ input: String) -> String {
    var s = input.trimmingCharacters(in: .whitespacesAndNewlines)
    if s.hasPrefix("chrome-extension://") {
      s = String(s.dropFirst("chrome-extension://".count))
    }
    if s.hasSuffix("/") {
      s = String(s.dropLast())
    }
    return s
  }

  /// Agent 对端校验与 Chrome 清单中的 host 路径一致（优先 ~/.credpivot 副本）。
  static func applyTrustedNativeHostEnv() {
    let path = FileManager.default.fileExists(atPath: installedHostPath.path)
      ? installedHostPath.path
      : Bundle.main.path(forResource: "credpivot-native-host", ofType: nil)
    if let path, !path.isEmpty {
      setenv("CREDPIVOT_TRUSTED_NATIVE_HOST", path, 1)
    }
  }

  static func install(extensionId: String?) -> [String: Any] {
    let candidate = extensionId ?? storedExtensionId() ?? ""
    let extId = normalizeExtensionId(candidate)
    if extId.isEmpty || extId.contains("REPLACE") {
      return [
        "ok": false,
        "message": "请填写 Chrome 扩展 ID（在 chrome://extensions 打开开发者模式后复制）",
      ]
    }
    do {
      try FileManager.default.createDirectory(
        at: configPath.deletingLastPathComponent(),
        withIntermediateDirectories: true
      )
      try extId.write(to: configPath, atomically: true, encoding: .utf8)
    } catch {
      return ["ok": false, "message": "无法保存扩展 ID: \(error.localizedDescription)"]
    }

    do {
      let host = try materializeHostBinary()
      let manifest: [String: Any] = [
        "name": hostName,
        "description": "CredPivot Native Messaging Host",
        "path": host,
        "type": "stdio",
        "allowed_origins": ["chrome-extension://\(extId)/"],
      ]
      let dir = manifestURL.deletingLastPathComponent()
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
      let data = try JSONSerialization.data(withJSONObject: manifest, options: [.prettyPrinted])
      try data.write(to: manifestURL)
      applyTrustedNativeHostEnv()
      return [
        "ok": true,
        "message": "已安装 Native Host。请完全退出 Chrome 后重开，再在扩展里点「连接 App」。",
        "manifest_path": manifestURL.path,
        "extension_id": extId,
        "host_binary": host,
      ]
    } catch {
      return ["ok": false, "message": error.localizedDescription]
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

enum AppRelauncher {
  static func relaunch() {
    let path = Bundle.main.bundlePath
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
    task.arguments = ["-n", path]
    try? task.run()
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
      NSApp.terminate(nil)
    }
  }
}

// MARK: - M2-11 剪贴板：ConcealedType + changeCount 清理

enum ConcealedPasteboard {
  private static let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
  private static var clearWorkItem: DispatchWorkItem?

  static func copyConcealed(_ secret: String, clearAfterSeconds: TimeInterval) {
    let pb = NSPasteboard.general
    let baseline = pb.changeCount
    pb.clearContents()
    pb.setString(secret, forType: .string)
    pb.setString("", forType: concealed)
    clearWorkItem?.cancel()
    let work = DispatchWorkItem {
      let current = NSPasteboard.general
      if current.changeCount == baseline + 1 || current.string(forType: .string) == secret {
        current.clearContents()
      }
    }
    clearWorkItem = work
    DispatchQueue.main.asyncAfter(deadline: .now() + clearAfterSeconds, execute: work)
  }
}

enum TerminalLauncher {
  private static let appPathKey = "credpivot.terminal.app_path"
  private static let legacyIdKey = "credpivot.terminal.app"

  static func preferencePayload() -> [String: String] {
    if let path = currentAppPath(), !path.isEmpty {
      let name = FileManager.default.displayName(atPath: path)
      return ["path": path, "name": name]
    }
    return ["path": "", "name": ""]
  }

  static func currentAppPath() -> String? {
    UserDefaults.standard.string(forKey: appPathKey)
  }

  /// 旧版预设 id（terminal/iterm/warp），首次选择 .app 后不再使用。
  static func setLegacyPreset(_ id: String) {
    UserDefaults.standard.set(id, forKey: legacyIdKey)
    if id == "terminal" {
      setAppPath("/System/Applications/Utilities/Terminal.app")
    } else if id == "iterm" {
      setAppPath("/Applications/iTerm.app")
    } else if id == "warp" {
      setAppPath("/Applications/Warp.app")
    }
  }

  static func setAppPath(_ path: String) {
    UserDefaults.standard.set(path, forKey: appPathKey)
    UserDefaults.standard.removeObject(forKey: legacyIdKey)
  }

  static func pickApplication() -> [String: String]? {
    let panel = NSOpenPanel()
    panel.canChooseFiles = true
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.allowedContentTypes = [UTType.application]
    panel.message = "选择用于 SSH 连接的终端应用（如 Terminal、iTerm、Tabby、Warp 等）"
    panel.prompt = "选择"
    guard panel.runModal() == .OK, let url = panel.url else {
      return nil
    }
    let path = url.path
    setAppPath(path)
    return ["path": path, "name": url.deletingPathExtension().lastPathComponent]
  }

  /// 成功返回 nil；失败返回错误文案。
  static func openSsh(host: String, port: Int, user: String) -> String? {
    guard let appPath = currentAppPath(), !appPath.isEmpty else {
      return "未选择终端应用：请在「凭据 → 服务器」点「终端设置」选择 .app"
    }
    if !FileManager.default.fileExists(atPath: appPath) {
      return "终端应用不存在：\(appPath)"
    }
    let portArg = port == 22 ? "" : " -p \(port)"
    let sshCmd = "ssh\(portArg) \(shellQuote(user))@\(shellQuote(host))"
    let bundleId = Bundle(path: appPath)?.bundleIdentifier ?? ""
    let appFile = (appPath as NSString).lastPathComponent.lowercased()

    switch bundleId {
    case "com.apple.Terminal":
      let script = "tell application \"Terminal\" to do script \"\(escapeAppleScript(sshCmd))\""
      return runOsascript(script)
    case "com.googlecode.iterm2":
      let script =
        "tell application \"iTerm\" to create window with default profile command \"\(escapeAppleScript(sshCmd))\""
      return runOsascript(script)
    case "dev.warp.Warp-Stable", "dev.warp.Warp":
      let enc = sshCmd.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? sshCmd
      let url = "warp://action/new_tab?command=\(enc)"
      NSWorkspace.shared.open(URL(string: url)!)
      return nil
    default:
      break
    }

    if appFile.contains("tabby") || bundleId.lowercased().contains("tabby") {
      if let err = launchTabby(appPath: appPath, user: user, host: host, port: port) {
        return err
      }
      return nil
    }

    return launchGenericApp(appPath: appPath, sshCmd: sshCmd)
  }

  private static func launchTabby(appPath: String, user: String, host: String, port: Int) -> String? {
    let cli = "\(appPath)/Contents/MacOS/Tabby"
    let sshTarget = port == 22 ? "\(user)@\(host)" : "\(user)@\(host):\(port)"
    if FileManager.default.fileExists(atPath: cli) {
      return runProcess(executable: cli, arguments: ["run", "ssh", sshTarget])
    }
    let uri = port == 22 ? "ssh://\(user)@\(host)" : "ssh://\(user)@\(host):\(port)"
    return runProcess(executable: "/usr/bin/open", arguments: ["-a", appPath, "--args", uri])
  }

  private static func launchGenericApp(appPath: String, sshCmd: String) -> String? {
    // 多数终端接受：open -na App.app --args $SHELL -lic "ssh ..."
    return runProcess(
      executable: "/usr/bin/open",
      arguments: ["-na", appPath, "--args", "/bin/zsh", "-lic", sshCmd]
    )
  }

  private static func runProcess(executable: String, arguments: [String]) -> String? {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: executable)
    proc.arguments = arguments
    do {
      try proc.run()
      proc.waitUntilExit()
      if proc.terminationStatus != 0 {
        return "启动终端失败（退出码 \(proc.terminationStatus)）"
      }
      return nil
    } catch {
      return error.localizedDescription
    }
  }

  private static func runOsascript(_ source: String) -> String? {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    proc.arguments = ["-e", source]
    do {
      try proc.run()
      proc.waitUntilExit()
      if proc.terminationStatus != 0 {
        return "无法启动终端（osascript 退出码 \(proc.terminationStatus)）"
      }
      return nil
    } catch {
      return error.localizedDescription
    }
  }

  private static func shellQuote(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }

  private static func escapeAppleScript(_ s: String) -> String {
    s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
  }
}
