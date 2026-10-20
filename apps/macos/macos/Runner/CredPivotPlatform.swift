import Cocoa
import CryptoKit
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
      TouchIdGate.shared.authenticateSensitiveOperation(reason: reason) { ok in
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
    case "setTerminalLaunchConfig":
      guard let args = call.arguments as? [String: Any] else {
        result(FlutterError(code: "bad_args", message: "map required", details: nil))
        return
      }
      TerminalLauncher.applyLaunchConfig(args)
      result(nil)
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
    case "materializeSshAskpass":
      do {
        let path = try SshAskpassLauncher.materializeInstalledBinary()
        result(path)
      } catch {
        result(FlutterError(code: "ssh_askpass", message: error.localizedDescription, details: nil))
      }
    case "openSshWithAskpass":
      guard let args = call.arguments as? [String: Any],
            let host = args["host"] as? String,
            let username = args["username"] as? String,
            let sessionId = args["sessionId"] as? String else {
        result(FlutterError(code: "bad_args", message: "host/username/sessionId required", details: nil))
        return
      }
      let port = args["port"] as? Int ?? 22
      if let err = SshAskpassLauncher.openInTerminal(
        host: host,
        port: port,
        user: username,
        sessionId: sessionId
      ) {
        result(err)
      } else {
        result(nil)
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }

}

// MARK: - Chrome 扩展指纹门槛

enum ExtensionGateCoordinator {
  private static var started = false
  private static var pending = false
  /// 用户取消指纹/密码后短暂不再自动弹窗（毫秒时间戳）。
  private static var snoozeUntilMs: TimeInterval = 0

  static func start() {
    guard !started else { return }
    started = true
    NotificationCenter.default.addObserver(
      forName: NSApplication.didBecomeActiveNotification,
      object: nil,
      queue: .main
    ) { _ in
      consumePendingIfNeeded()
    }
    Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
      consumePendingIfNeeded()
    }
    consumePendingIfNeeded()
  }

  private static var pendingPath: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot/extension_gate.pending")
  }

  private static func consumePendingIfNeeded() {
    let nowMs = Date().timeIntervalSince1970 * 1000
    if nowMs < snoozeUntilMs {
      return
    }
    if !FileManager.default.fileExists(atPath: pendingPath.path) {
      return
    }
    if pending {
      return
    }
    // 门槛仍有效时清掉陈旧 pending，避免重复弹指纹。
    let status = credpivotAgentRequestJsonString(#"{"type":"status"}"#)
    if status.contains("\"extension_gate_active\":true") {
      try? FileManager.default.removeItem(at: pendingPath)
      return
    }
    pending = true
    NSApp.activate(ignoringOtherApps: true)
    let epoch = TouchIdGate.beginAuthentication()
    TouchIdGate.shared.authenticateForExtensionGate(reason: "允许 Chrome 扩展访问已解锁凭据") { ok in
      defer {
        pending = false
      }
      let valid = TouchIdGate.endAuthentication(epoch)
      if valid && ok {
        _ = credpivotAgentRequestJsonString(
          #"{"type":"extension_gate_grant","ttl_secs":0}"#
        )
        try? FileManager.default.removeItem(at: pendingPath)
      } else {
        try? FileManager.default.removeItem(at: pendingPath)
        snoozeUntilMs = Date().timeIntervalSince1970 * 1000 + 30_000
      }
    }
  }
}

// MARK: - Touch ID scheme A (LAContext gate + login keychain wrapper)

final class TouchIdGate {
  static let shared = TouchIdGate()
  /// 生物识别弹窗期间勿因 resign-active 误锁 Agent。
  static var isAuthenticating = false
  /// 锁屏/睡眠时递增，使在途认证结果失效。
  private(set) static var authenticationEpoch: UInt64 = 0

  static func invalidateInFlightAuthentication() {
    authenticationEpoch += 1
    isAuthenticating = false
  }

  static func beginAuthentication() -> UInt64 {
    isAuthenticating = true
    return authenticationEpoch
  }

  static func endAuthentication(_ epoch: UInt64) -> Bool {
    isAuthenticating = false
    return epoch == authenticationEpoch
  }

  private let keychainService = "com.credpivot.macos.touchid.m0"
  private let keychainAccount = "vmk-wrapper-token"

  /// Chrome 扩展与 App 敏感操作使用相同的系统身份验证，避免手动切换认证上下文。
  func authenticateForExtensionGate(reason: String, completion: @escaping (Bool) -> Void) {
    authenticateSensitiveOperation(reason: reason, completion: completion)
  }

  /// 敏感操作门槛：由系统处理 Touch ID 与 Mac 登录密码回退，不访问钥匙串。
  func authenticateSensitiveOperation(reason: String, completion: @escaping (Bool) -> Void) {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
      completion(false)
      return
    }
    let epoch = TouchIdGate.beginAuthentication()
    context.evaluatePolicy(
      .deviceOwnerAuthentication,
      localizedReason: reason
    ) { success, _ in
      DispatchQueue.main.async {
        let valid = TouchIdGate.endAuthentication(epoch)
        completion(valid && success)
      }
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
    let epoch = TouchIdGate.beginAuthentication()
    context.evaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: "CredPivot：Touch ID 解锁"
    ) { success, _ in
      guard TouchIdGate.endAuthentication(epoch), success else {
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
    try writeNativeHostDigest(sourcePath: src)
    return installedHostPath.path
  }

  private static func writeNativeHostDigest(sourcePath: String) throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: sourcePath))
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    let out = credPivotDir.appendingPathComponent("native_host.sha256")
    try digest.write(to: out, atomically: true, encoding: .utf8)
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
    guard let bundled = Bundle.main.path(forResource: "credpivot-native-host", ofType: nil),
          !bundled.isEmpty else {
      return
    }
    setenv("CREDPIVOT_TRUSTED_NATIVE_HOST", bundled, 1)
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
  /// 旧版自定义启动项，已不再使用。
  private static let legacyLaunchModeKey = "credpivot.terminal.launch_mode"
  private static let legacyLauncherPathKey = "credpivot.terminal.launcher_path"
  private static let legacyArgvTemplateKey = "credpivot.terminal.argv_template"
  private static let legacyCwdKey = "credpivot.terminal.cwd"

  private static let launchScriptName = "terminal_launch.sh"

  static func preferencePayload() -> [String: String] {
    clearLegacyLaunchExtras()
    if let path = currentAppPath(), !path.isEmpty {
      let name = FileManager.default.displayName(atPath: path)
      return ["path": path, "name": name]
    }
    return ["path": "", "name": ""]
  }

  static func applyLaunchConfig(_ map: [String: Any]) {
    if let appPath = map["path"] as? String, !appPath.isEmpty {
      setAppPath(appPath)
    }
    clearLegacyLaunchExtras()
  }

  private static func clearLegacyLaunchExtras() {
    UserDefaults.standard.removeObject(forKey: legacyLaunchModeKey)
    UserDefaults.standard.removeObject(forKey: legacyLauncherPathKey)
    UserDefaults.standard.removeObject(forKey: legacyArgvTemplateKey)
    UserDefaults.standard.removeObject(forKey: legacyCwdKey)
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
    clearLegacyLaunchExtras()
    return ["path": path, "name": url.deletingPathExtension().lastPathComponent]
  }

  private static var lastLaunchPlanURL: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot/last_terminal_launch.txt", isDirectory: false)
  }

  /// 供用户核对：一键连接实际执行的启动方式（不含真实密码）。
  static func describeLaunchPlan(appPath: String, shellCommand: String) -> String {
    let scriptPath = launchScriptURL(sessionId: nil).path
    _ = writeLaunchScript(shellCommand: shellCommand)
    var lines: [String] = []
    lines.append("=== CredPivot 终端启动计划 ===")
    lines.append("")
    lines.append("【1】写入 ~/.credpivot/terminal_launch.sh ：")
    lines.append(shellCommand)
    lines.append("")
    if let cli = tabbyCliPath(appPath: appPath) ?? inferredTabbyCli(appPath: appPath) {
      lines.append("【2】Tabby CLI：")
      lines.append("\(cli) run /bin/zsh \(scriptPath)")
    } else {
      lines.append("【2】open 回退：")
      lines.append("/usr/bin/open -na \(shellQuote(appPath)) --args /bin/zsh \(scriptPath)")
    }
    lines.append("")
    lines.append("说明：zsh -c 后面若跟多个参数（如 expect、脚本、--user 分开写），")
    lines.append("zsh 会把它们当成多个「脚本文件」，出现 can't open input file。")
    let text = lines.joined(separator: "\n")
    persistLaunchPlan(text)
    return text
  }

  private static func inferredTabbyCli(appPath: String) -> String? {
    let lower = appPath.lowercased()
    if lower.contains("tabby") {
      return tabbyCliPath(appPath: appPath)
    }
    return nil
  }

  private static func persistLaunchPlan(_ text: String) {
    let dir = lastLaunchPlanURL.deletingLastPathComponent()
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    try? text.write(to: lastLaunchPlanURL, atomically: true, encoding: .utf8)
  }

  static func sshShellCommand(host: String, port: Int, user: String) -> String {
    let target = shellQuote("\(user)@\(host)")
    if port == 22 {
      return "ssh \(target)"
    }
    return "ssh -p \(port) \(target)"
  }

  /// 成功返回 nil；失败返回错误文案。
  static func openSsh(host: String, port: Int, user: String) -> String? {
    guard let appPath = currentAppPath(), !appPath.isEmpty else {
      return "未选择终端应用：请在「凭据 → 服务器」点「终端设置」选择 .app"
    }
    if !FileManager.default.fileExists(atPath: appPath) {
      return "终端应用不存在：\(appPath)"
    }
    let sshCmd = sshShellCommand(host: host, port: port, user: user)
    if let err = launchShellCommand(appPath: appPath, command: sshCmd) {
      let plan = describeLaunchPlan(appPath: appPath, shellCommand: sshCmd)
      return "\(err)\n\n\(plan)"
    }
    return nil
  }

  /// 在指定终端里执行一条 shell 命令（expect / ssh 等）。
  static func launchShellCommand(
    appPath: String,
    command: String,
    launchSessionId: String? = nil
  ) -> String? {
    if !FileManager.default.fileExists(atPath: appPath) {
      return "终端应用不存在：\(appPath)"
    }
    let bundleId = Bundle(path: appPath)?.bundleIdentifier ?? ""
    let appFile = (appPath as NSString).lastPathComponent.lowercased()

    switch bundleId {
    case "com.apple.Terminal":
      let script = "tell application \"Terminal\" to do script \"\(escapeAppleScript(command))\""
      return runOsascript(script)
    case "com.googlecode.iterm2":
      let script =
        "tell application \"iTerm\" to create window with default profile command \"\(escapeAppleScript(command))\""
      return runOsascript(script)
    case "dev.warp.Warp-Stable", "dev.warp.Warp":
      let enc = command.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? command
      let url = "warp://action/new_tab?command=\(enc)"
      NSWorkspace.shared.open(URL(string: url)!)
      return nil
    default:
      break
    }

    if appFile.contains("tabby") || bundleId.lowercased().contains("tabby") || tabbyCliPath(appPath: appPath) != nil {
      if let err = launchTabbyShellCommand(
        appPath: appPath,
        command: command,
        launchSessionId: launchSessionId
      ) {
        return err
      }
      return nil
    }

    if let script = writeLaunchScript(shellCommand: command, sessionId: launchSessionId) {
      return runProcess(
        executable: "/usr/bin/open",
        arguments: ["-na", appPath, "--args", "/bin/zsh", script],
        waitForExit: false
      )
    }
    return "无法写入启动脚本 ~/.credpivot/terminal_launch.sh"
  }

  private static func launchScriptURL(sessionId: String?) -> URL {
    let name = sessionId.map { "terminal_launch_\($0).sh" } ?? launchScriptName
    return FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot", isDirectory: true)
      .appendingPathComponent(name)
  }

  /// 将整条 shell 命令写入 `~/.credpivot/terminal_launch*.sh`，供 `zsh <path>` 执行。
  private static func writeLaunchScript(shellCommand: String, sessionId: String? = nil) -> String? {
    let url = launchScriptURL(sessionId: sessionId)
    let dir = url.deletingLastPathComponent()
    do {
      try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
      let body = "#!/bin/zsh\n\(shellCommand)\n"
      try body.write(to: url, atomically: true, encoding: .utf8)
      try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
      return url.path
    } catch {
      return nil
    }
  }

  /// Tabby：`run [command...]`；`-c` 后仅传脚本路径，避免长命令被拆成多个「脚本文件」参数。
  private static func launchTabbyShellCommand(
    appPath: String,
    command: String,
    launchSessionId: String? = nil
  ) -> String? {
    let cli = "\(appPath)/Contents/MacOS/Tabby"
    guard FileManager.default.fileExists(atPath: cli) else {
      return "找不到 Tabby CLI：\(cli)"
    }
    guard let script = writeLaunchScript(shellCommand: command, sessionId: launchSessionId) else {
      return "无法写入 ~/.credpivot/terminal_launch.sh"
    }
    return runProcess(executable: cli, arguments: ["run", "/bin/zsh", script], waitForExit: false)
  }

  private static func tabbyCliPath(appPath: String) -> String? {
    let cli = "\(appPath)/Contents/MacOS/Tabby"
    return FileManager.default.fileExists(atPath: cli) ? cli : nil
  }

  /// expect 等：拼成一条 shell 命令后走统一启动逻辑。
  static func launchShellCommandLine(
    appPath: String,
    executable: String,
    arguments: [String],
    launchSessionId: String? = nil
  ) -> String? {
    let shellCmd = ([executable] + arguments).map { shellQuote($0) }.joined(separator: " ")
    return launchShellCommand(
      appPath: appPath,
      command: shellCmd,
      launchSessionId: launchSessionId
    )
  }

  private static func runProcess(
    executable: String,
    arguments: [String],
    waitForExit: Bool = true
  ) -> String? {
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: executable)
    proc.arguments = arguments
    do {
      try proc.run()
      if waitForExit {
        proc.waitUntilExit()
        if proc.terminationStatus != 0 {
          return "启动终端失败（退出码 \(proc.terminationStatus)）"
        }
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

enum SshAskpassLauncher {
  private static let installedName = "credpivot-askpass"
  private static var credPivotDir: URL {
    FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".credpivot", isDirectory: true)
  }

  private static var installedURL: URL {
    credPivotDir.appendingPathComponent(installedName)
  }

  /// Agent 校验 askpass 副本时读取包内二进制路径。
  static func applyTrustedAskpassEnv() {
    guard let bundled = Bundle.main.path(forResource: installedName, ofType: nil),
          !bundled.isEmpty else {
      return
    }
    setenv("CREDPIVOT_TRUSTED_ASKPASS", bundled, 1)
  }

  private static func resolveSourceBinary() -> String? {
    if let bundled = Bundle.main.path(forResource: installedName, ofType: nil) {
      return bundled
    }
    let pathFile = credPivotDir.appendingPathComponent("askpass_binary.path")
    if let raw = try? String(contentsOf: pathFile, encoding: .utf8) {
      let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
      if FileManager.default.fileExists(atPath: p) {
        return p
      }
    }
    if FileManager.default.fileExists(atPath: installedURL.path) {
      return installedURL.path
    }
    return nil
  }

  /// 从 App 包复制到 ~/.credpivot/credpivot-askpass（与 native-host 相同策略）。
  static func materializeInstalledBinary() throws -> String {
    guard let src = resolveSourceBinary() else {
      throw NSError(
        domain: "CredPivot",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "找不到 credpivot-askpass，请先 make macos-build"]
      )
    }
    try FileManager.default.createDirectory(at: credPivotDir, withIntermediateDirectories: true)
    if FileManager.default.fileExists(atPath: installedURL.path) {
      try FileManager.default.removeItem(at: installedURL)
    }
    try FileManager.default.copyItem(atPath: src, toPath: installedURL.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installedURL.path)
    return installedURL.path
  }

  static func openInTerminal(
    host: String,
    port: Int,
    user: String,
    sessionId: String
  ) -> String? {
    let askpassPath: String
    do {
      askpassPath = try materializeInstalledBinary()
    } catch {
      return error.localizedDescription
    }
    guard let appPath = TerminalLauncher.currentAppPath(), !appPath.isEmpty else {
      return "未选择终端应用：请在「服务器」页配置终端"
    }
    let sshTarget = TerminalLauncher.sshShellCommand(host: host, port: port, user: user)
    let qAskpass = TerminalLauncher.shellQuoteForPlan(askpassPath)
    let qSession = TerminalLauncher.shellQuoteForPlan(sessionId)
    let shellCmd = """
    export SSH_ASKPASS=\(qAskpass)
    export SSH_ASKPASS_REQUIRE=force
    export CREDPIVOT_SESSION_ID=\(qSession)
    exec \(sshTarget)
    """
    if let err = TerminalLauncher.launchShellCommand(
      appPath: appPath,
      command: shellCmd,
      launchSessionId: sessionId
    ) {
      let plan = TerminalLauncher.describeLaunchPlan(appPath: appPath, shellCommand: shellCmd)
      return "\(err)\n\n\(plan)"
    }
    return nil
  }
}

extension TerminalLauncher {
  fileprivate static func shellQuoteForPlan(_ s: String) -> String {
    "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}
