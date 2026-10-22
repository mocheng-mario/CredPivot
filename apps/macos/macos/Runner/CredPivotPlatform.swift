import Cocoa
import Vision
import Darwin
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
  private var sshAuthorizationTimer: Timer?
  private var showingSshAuthorization = false
  private var showingPasskeyAuthorization = false
  private var shortcutController: CredPivotShortcuts?

  init(messenger: FlutterBinaryMessenger) {
    channel = FlutterMethodChannel(name: "credpivot/agent", binaryMessenger: messenger)
    super.init()
    channel.setMethodCallHandler(handle)
    DispatchQueue.main.async { [weak self] in self?.startInteractionServices() }
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(vaultLockedExternally),
      name: .credPivotVaultLocked,
      object: nil
    )
  }

  private func startInteractionServices() {
    NativePresentation.reload()
    shortcutController = CredPivotShortcuts { [weak self] action in
      if action == "lock" {
        (NSApp.delegate as? AppDelegate)?.lockFromMenu()
      } else {
        self?.channel.invokeMethod("onShortcut", arguments: action)
      }
    }
    shortcutController?.apply(AppPreferences.settings())
    sshAuthorizationTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
      self?.consumePasskeyAuthorization()
      self?.consumeSshAuthorization()
    }
  }

  private func consumeSshAuthorization() {
    guard !showingSshAuthorization, !showingPasskeyAuthorization, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil,
          let requests = LocalVaultUnlock.request(["type": "ssh_authorizations_pending"])?["requests"] as? [[String: Any]],
          let request = requests.first, let id = request["id"] as? String else { return }
    showingSshAuthorization = true
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    let policy = request["policy"] as? String ?? "confirm"
    alert.messageText = policy == "unlock" ? NativePresentation.tr("解锁保险库以使用 SSH 密钥？") : NativePresentation.tr("允许 SSH 密钥签名？")
    let scope = policy == "session" ? NativePresentation.tr("允许后，仅同一连接在敏感授权期限内可复用。") : NativePresentation.tr("仅允许这一次签名。")
    let caller = request["caller"] as? String ?? NativePresentation.tr("未知进程")
    alert.informativeText = policy == "unlock"
      ? NativePresentation.tr("调用：{0}\n\n验证后提供 SSH 公钥，实际签名仍需另行授权。", caller)
      : NativePresentation.tr("密钥：{0}\n{1}\n调用：{2}\n\n无法从 SSH Agent 协议可靠确认最终目标主机。\n{3}", request["key_label"] as? String ?? NativePresentation.tr("未知"), request["fingerprint"] as? String ?? "", caller, scope)
    alert.addButton(withTitle: NativePresentation.tr("允许"))
    alert.addButton(withTitle: NativePresentation.tr("拒绝"))
    // runModal 使用独立运行循环；请求已断开或过期时主动关闭，避免留下失效弹窗。
    let expiry = Timer(timeInterval: 0.5, repeats: true) { _ in
      guard let pending = LocalVaultUnlock.request(["type": "ssh_authorizations_pending"])?["requests"] as? [[String: Any]],
            pending.contains(where: { $0["id"] as? String == id }) else {
        NSApp.abortModal()
        alert.window.orderOut(nil)
        return
      }
    }
    RunLoop.main.add(expiry, forMode: .modalPanel)
    let response = alert.runModal()
    expiry.invalidate()
    guard response == .alertFirstButtonReturn else {
      _ = LocalVaultUnlock.request(["type": "ssh_authorization_resolve", "request_id": id, "approved": false])
      showingSshAuthorization = false
      return
    }
    let complete: (Bool) -> Void = { [weak self] ok in
      _ = LocalVaultUnlock.request(["type": "ssh_authorization_resolve", "request_id": id, "approved": ok])
      self?.showingSshAuthorization = false
    }
    if policy == "biometric" {
      TouchIdGate.shared.authenticateForExtensionGate(reason: NativePresentation.tr("允许本次 SSH 密钥签名"), completion: complete)
    } else {
      TouchIdGate.shared.authenticateSensitiveOperation(reason: policy == "unlock" ? NativePresentation.tr("解锁保险库以使用 SSH 密钥") : NativePresentation.tr("允许 SSH 密钥签名"), completion: complete)
    }
  }

  private func consumePasskeyAuthorization() {
    guard !showingPasskeyAuthorization, !showingSshAuthorization, !TouchIdGate.isAuthenticating, NSApp.modalWindow == nil,
          let requests = LocalVaultUnlock.request(["type": "passkey_requests_pending"])?["requests"] as? [[String: Any]],
          let request = requests.first, let id = request["id"] as? String else { return }
    showingPasskeyAuthorization = true
    let create = request["create"] as? Bool == true
    let origin = request["origin"] as? String ?? ""
    let candidates = request["candidates"] as? [[String: Any]] ?? []
    let alert = NSAlert()
    alert.messageText = NativePresentation.tr(create ? "保存通行密钥到 CredPivot？" : "使用 CredPivot 通行密钥登录？")
    let website = NativePresentation.tr("网站：{0}", origin)
    let account = passkeyAccountLabel(request["username"] as? String ?? "", request["display_name"] as? String ?? "")
    alert.informativeText = create
      ? website + "\n" + NativePresentation.tr("账号：{0}\n\n私钥保存在加密保险库中，随 CredPivot 加密备份迁移和恢复。", account)
      : website + "\n\n" + NativePresentation.tr("选择用于本次登录的账号，确认后验证身份。")
    let picker = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 380, height: 28), pullsDown: false)
    if !create {
      for (index, candidate) in candidates.enumerated() {
        let label = passkeyAccountLabel(candidate["username"] as? String ?? "", candidate["display_name"] as? String ?? "")
        picker.addItem(withTitle: "\(index + 1). \(label)")
        picker.lastItem?.representedObject = candidate["credential_id"] as? String
      }
      alert.accessoryView = picker
    }
    alert.addButton(withTitle: NativePresentation.tr(create ? "保存到 CredPivot" : "允许登录"))
    alert.addButton(withTitle: NativePresentation.tr("使用浏览器方式"))
    alert.addButton(withTitle: NativePresentation.tr("取消"))
    // 取消、跳转、锁库后关闭失效确认窗；实际签名前 Agent 还会再次校验请求。
    let expiry = Timer(timeInterval: 0.5, repeats: true) { _ in
      guard let pending = LocalVaultUnlock.request(["type": "passkey_requests_pending"])?["requests"] as? [[String: Any]],
            pending.contains(where: { $0["id"] as? String == id }) else {
        NSApp.abortModal()
        alert.window.orderOut(nil)
        return
      }
    }
    RunLoop.main.add(expiry, forMode: .modalPanel)
    NSApp.activate(ignoringOtherApps: true)
    let decision = alert.runModal()
    expiry.invalidate()
    let selected = picker.selectedItem?.representedObject as? String ?? ""
    let complete: (Bool) -> Void = { [weak self] approved in
      let result = LocalVaultUnlock.request(["type": "passkey_resolve", "request_id": id,
        "approved": approved, "credential_id": selected, "use_browser": decision == .alertSecondButtonReturn])
      if approved && result?["resolved"] as? Bool == true { self?.channel.invokeMethod("onVaultChanged", arguments: nil) }
      self?.showingPasskeyAuthorization = false
    }
    guard decision == .alertFirstButtonReturn else { complete(false); return }
    // WebAuthn 的 UV 标志对应本次真实验证，不借用浏览器会话或敏感操作宽限期。
    TouchIdGate.shared.authenticateForExtensionGate(
      reason: NativePresentation.tr(create ? "创建网站通行密钥" : "使用网站通行密钥登录"), completion: complete)
  }

  private func passkeyAccountLabel(_ username: String, _ displayName: String) -> String {
    // 网站提供的名称只作标签，移除控制/方向字符，避免伪造弹窗中的网站说明。
    let raw = displayName.isEmpty || displayName == username ? username : "\(username) · \(displayName)"
    let safe = raw.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) &&
      ![0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069].contains(Int($0.value)) }
    return String(String.UnicodeScalarView(safe)).prefix(160).description
  }

  deinit { sshAuthorizationTimer?.invalidate() }

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
      if code == 0 { NativePresentation.reload(); shortcutController?.apply(AppPreferences.settings()) }
      result(code == 0 ? nil : FlutterError(code: "agent", message: "start failed", details: code))
    case "restartAgent":
      let code = CredPivotRustFFI.restart()
      if code == 0 { NativePresentation.reload(); shortcutController?.apply(AppPreferences.settings()) }
      result(code == 0)
    case "agentIsRunning":
      result(CredPivotRustFFI.isRunning())
    case "relaunchApp":
      AppRelauncher.relaunch()
      result(nil)
    case "recordShortcut":
      guard let args = call.arguments as? [String: Any],
            let name = args["name"] as? String,
            let bindings = args["bindings"] as? [String: String],
            ["search", "lock", "new"].contains(name), let controller = shortcutController else {
        result(FlutterError(code: "bad_args", message: "无法开始快捷键录入", details: nil))
        return
      }
      result(controller.record(name: name, bindings: bindings))
    case "agentRequest":
      guard let json = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "expected json string", details: nil))
        return
      }
      var requestObject: [String: Any]?
      if let data = json.data(using: .utf8) {
        requestObject = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
      }
      let previousSettings = requestObject?["type"] as? String == "app_settings_set" ? AppPreferences.settings() : nil
      var response = credpivotAgentRequestJsonString(json)
      if let requestData = json.data(using: .utf8),
         let request = try? JSONSerialization.jsonObject(with: requestData) as? [String: Any],
         request["type"] as? String == "status",
         let responseData = response.data(using: .utf8),
         var object = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
         var payload = object["payload"] as? [String: Any] {
        payload["local_unlock_configured"] = LocalVaultUnlock.configured
        payload["local_unlock_notice"] = LocalVaultUnlock.setupNotice
        payload["browser_background_launch"] = AppDelegate.launchedForBrowser
        object["payload"] = payload
        if let data = try? JSONSerialization.data(withJSONObject: object),
           let updated = String(data: data, encoding: .utf8) { response = updated }
      }
      if let data = json.data(using: .utf8),
         let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
         response.contains("\"type\":\"ok\"") {
        switch request["type"] as? String {
        case "vault_create", "vault_change_password", "vault_security_rebuild":
          LocalVaultUnlock.enroll()
        case "vault_export_ovb": _ = LocalVaultUnlock.persist(enroll: false)
        case "vault_open_dir": LocalVaultUnlock.invalidate()
        case "app_settings_set":
          var notices: [String] = []
          let next = AppPreferences.settings()
          NativePresentation.reload()
          shortcutController?.apply(next)
          // 显式保存时也重试应用系统偏好，避免上次注册失败后只能反复切换开关。
          if let notice = LoginItemRegistrar.applyPreference() { notices.append(notice) }
          if (previousSettings?["chrome_extension_id"] as? String) != (next["chrome_extension_id"] as? String) {
            let installation = ChromeHostInstaller.applyPreference()
            if installation["ok"] as? Bool != true {
              notices.append("配置已保存，但浏览器连接尚未更新，请在「浏览器连接」页修复。")
            } else {
              notices.append((next["chrome_extension_id"] as? String ?? "").isEmpty ? "本机浏览器连接已停用。" : "浏览器连接已更新，请完全退出 Chrome 后重开。")
            }
          }
          if let data = response.data(using: .utf8),
             var object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
             var payload = object["payload"] as? [String: Any] {
            payload["platform_notice"] = notices.joined(separator: "\n")
            object["payload"] = payload
            if let updated = try? JSONSerialization.data(withJSONObject: object),
               let text = String(data: updated, encoding: .utf8) { response = text }
          }
        default: break
        }
      }
      result(response)
    case "lockVault":
      TouchIdGate.invalidateInFlightAuthentication()
      _ = credpivotAgentRequestJsonString(#"{"type":"lock"}"#)
      CredPivotPlatform.publishVaultLocked()
      result(nil)
    case "unlockPassword":
      guard let password = call.arguments as? String else {
        result(false)
        return
      }
      result(LocalVaultUnlock.unlockPassword(password))
    case "authenticateTouchId":
      let reason = (call.arguments as? String) ?? "CredPivot 需要验证您的身份"
      TouchIdGate.shared.authenticateSensitiveOperation(reason: reason) { ok in
        DispatchQueue.main.async {
          result(ok)
        }
      }
    case "unlockTouchId":
      LocalVaultUnlock.unlockBiometric { ok in result(ok) }
    case "registerLoginItem":
      let enabled = (call.arguments as? Bool) ?? true
      LoginItemRegistrar.setEnabled(enabled, result: result)
    case "loginItemStatus":
      result(LoginItemRegistrar.status())
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
    case "sshIdentityAgentStatus":
      result(SshIdentityAgentHelper.status())
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
        let url = URL(fileURLWithPath: path)
        guard try url.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile == true else {
          throw CocoaError(.fileReadUnknown)
        }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: 4 * 1024 * 1024 + 1) ?? Data()
        guard data.count <= 4 * 1024 * 1024, let text = String(data: data, encoding: .utf8) else {
          throw CocoaError(.fileReadCorruptFile)
        }
        result(text)
      } catch {
        result(FlutterError(code: "io", message: "请选择 4MB 以内的 UTF-8 文本文件", details: nil))
      }
    case "scanQrImage":
      DispatchQueue.main.async {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { result([]); return }
        DispatchQueue.global(qos: .userInitiated).async {
          do {
            let request = VNDetectBarcodesRequest()
            request.symbologies = [.qr]
            try VNImageRequestHandler(url: url).perform([request])
            let uris = (request.results ?? []).compactMap { $0.payloadStringValue }
              .filter { $0.lowercased().hasPrefix("otpauth://totp/") }
            DispatchQueue.main.async { result(uris) }
          } catch {
            DispatchQueue.main.async { result(FlutterError(code: "qr", message: "二维码识别失败", details: nil)) }
          }
        }
      }
    case "writeTextFile":
      guard let args = call.arguments as? [String: String], let path = args["path"],
            let text = args["text"], let data = text.data(using: .utf8) else {
        result(FlutterError(code: "bad_args", message: "path and text required", details: nil)); return
      }
      // 明文私钥和语言文件均使用私有临时文件，原子替换，避免短暂的宽权限文件。
      let temporary = path + "." + UUID().uuidString + ".tmp"
      let fd = Darwin.open(temporary, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
      guard fd >= 0 else { result(FlutterError(code: "io", message: "文件创建失败", details: nil)); return }
      do {
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try handle.write(contentsOf: data)
        try handle.synchronize()
        try handle.close()
        guard Darwin.rename(temporary, path) == 0 else { throw CocoaError(.fileWriteUnknown) }
        result(nil)
      } catch {
        try? FileManager.default.removeItem(atPath: temporary)
        result(FlutterError(code: "io", message: "文件保存失败", details: nil))
      }
    case "copyConcealed":
      guard let secret = call.arguments as? String else {
        result(FlutterError(code: "bad_args", message: "secret required", details: nil))
        return
      }
      let seconds = (AppPreferences.settings()["clipboard_clear_seconds"] as? NSNumber)?.doubleValue ?? 5
      ConcealedPasteboard.copyConcealed(secret, clearAfterSeconds: seconds)
      result(nil)
    case "getTerminalPreference":
      result(TerminalLauncher.preferencePayload())
    case "setTerminalLaunchConfig":
      guard let args = call.arguments as? [String: Any] else {
        result(FlutterError(code: "bad_args", message: "map required", details: nil))
        return
      }
      result(TerminalLauncher.applyLaunchConfig(args) ? nil : FlutterError(code: "settings_write", message: "终端配置保存失败", details: nil))
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
    guard !TouchIdGate.isAuthenticating,
          let session = try? String(contentsOf: pendingPath, encoding: .utf8),
          UUID(uuidString: session) != nil else { return }
    pending = true
    // LocalAuthentication 自行展示系统弹窗，不激活 App，避免打断 Chrome。
    TouchIdGate.shared.authenticateForExtensionGate(reason: "允许当前 Chrome 会话访问保险库") { ok in
      pending = false
      let current = try? String(contentsOf: pendingPath, encoding: .utf8)
      guard current == session else { return }
      if ok {
        _ = LocalVaultUnlock.request(["type": "extension_gate_grant", "session_id": session, "ttl_secs": 0])
      } else {
        snoozeUntilMs = Date().timeIntervalSince1970 * 1000 + 30_000
      }
      // 取消后不自动重弹；用户重新点扩展连接时再生成请求。
      if (try? String(contentsOf: pendingPath, encoding: .utf8)) == session {
        try? FileManager.default.removeItem(at: pendingPath)
      }
    }
  }
}

// MARK: - 用户偏好统一由 Rust 校验和原子写入 settings.json

enum AppPreferences {
  static func settings() -> [String: Any] {
    LocalVaultUnlock.request(["type": "app_settings_get"])?["settings"] as? [String: Any] ?? [:]
  }

  @discardableResult
  static func update(_ changes: [String: Any]) -> Bool {
    guard let payload = LocalVaultUnlock.request(["type": "app_settings_get"]),
          (payload["warning"] as? String ?? "").isEmpty,
          var current = payload["settings"] as? [String: Any] else { return false }
    current.merge(changes) { _, new in new }
    return LocalVaultUnlock.request(["type": "app_settings_set", "settings": current]) != nil
  }

  static func migrateLegacyPreferences() {
    let current = settings()
    guard !current.isEmpty else { return }
    var changes: [String: Any] = [:]
    let legacyChrome = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".credpivot/chrome_extension_id")
    if current["terminal_app_path"] as? String == nil {
      changes["terminal_app_path"] = UserDefaults.standard.string(forKey: "credpivot.terminal.app_path") ?? ""
    }
    if current["chrome_extension_id"] as? String == nil {
      let old = (try? String(contentsOf: legacyChrome, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
      changes["chrome_extension_id"] = old.range(of: "^[a-p]{32}$", options: .regularExpression) != nil ? old : ""
    }
    if current["launch_at_login"] as? Bool == nil {
      let login = LoginItemRegistrar.status()
      changes["launch_at_login"] = login["enabled"] as? Bool == true || login["requires_approval"] as? Bool == true
    }
    guard !changes.isEmpty, update(changes) else { return }
    // 只有统一配置写入成功后才移除旧存储，防止迁移失败丢失偏好。
    UserDefaults.standard.removeObject(forKey: "credpivot.terminal.app_path")
    UserDefaults.standard.removeObject(forKey: "credpivot.terminal.app")
    try? FileManager.default.removeItem(at: legacyChrome)
  }
}

// MARK: - 本机解锁（Secure Enclave + 登录钥匙串，不依赖共享钥匙串 entitlement）

enum LocalVaultUnlock {
  private static let service = "com.credpivot.macos.local-unlock.v1"
  private static let materialAccount = "encrypted-vmk"
  private static let policyAccount = "verification-policy"
  private(set) static var setupNotice = ""

  static func enroll() {
    if persist(enroll: true) {
      setupNotice = ""
    } else {
      _ = SecItemDelete(query(materialAccount) as CFDictionary)
      _ = SecItemDelete(query(policyAccount) as CFDictionary)
      setupNotice = "本机指纹解锁材料保存失败，当前已通过主密码解锁；下次请使用主密码。请检查 Touch ID 和钥匙串访问权限。"
    }
  }

  static func request(_ body: [String: Any]) -> [String: Any]? {
    guard let data = try? JSONSerialization.data(withJSONObject: body),
          let json = String(data: data, encoding: .utf8),
          let response = credpivotAgentRequestJsonString(json).data(using: .utf8),
          let result = try? JSONSerialization.jsonObject(with: response) as? [String: Any],
          result["type"] as? String == "ok" else { return nil }
    return result["payload"] as? [String: Any]
  }

  private static func query(_ account: String) -> [String: Any] {
    // 临时签名不能假定具有 Data Protection Keychain 的访问组权限。
    // 登录钥匙串中只保存 Secure Enclave 加密材料，绝不保存主密码或明文 VMK。
    [kSecClass as String: kSecClassGenericPassword,
     kSecAttrService as String: service, kSecAttrAccount as String: account,
     kSecUseDataProtectionKeychain as String: false]
  }

  private static func read(_ account: String, allowPrompt: Bool = true) -> Data? {
    var q = query(account)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    if !allowPrompt {
      let context = LAContext()
      context.interactionNotAllowed = true
      q[kSecUseAuthenticationContext as String] = context
    }
    var item: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess else { return nil }
    return item as? Data
  }

  private static func write(_ account: String, data: Data) -> Bool {
    let q = query(account)
    let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if status == errSecSuccess { return true }
    guard status == errSecItemNotFound else { return false }
    var add = q
    add[kSecValueData as String] = data
    return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
  }

  static var configured: Bool { read(materialAccount, allowPrompt: false) != nil }

  static func restorePolicy() {
    if request(["type": "status"])?["unlocked"] as? Bool == true { return }
    guard let data = read(policyAccount, allowPrompt: false),
          let policy = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
    _ = request(["type": "local_unlock_policy_set", "policy": policy])
  }

  static func invalidate() {
    _ = SecItemDelete(query(materialAccount) as CFDictionary)
    _ = SecItemDelete(query(policyAccount) as CFDictionary)
    _ = request(["type": "local_unlock_policy_set", "policy": ["binding": "", "last_master_ms": 0, "last_unlock_ms": 0]])
  }

  @discardableResult
  static func persist(enroll: Bool) -> Bool {
    guard let material = request(["type": "local_unlock_material"])?["material"] as? [String: Any],
          let policy = material["policy"] as? [String: Any],
          let binding = policy["binding"] as? String,
          let policyData = try? JSONSerialization.data(withJSONObject: policy) else { return false }
    if enroll {
      guard SecureEnclave.isAvailable,
            let encoded = material["vmk"] as? String,
            var vmk = Data(base64Encoded: encoded),
            let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                        [.privateKeyUsage, .biometryCurrentSet], nil) else { return false }
      defer { vmk.resetBytes(in: 0..<vmk.count) }
      do {
        // 临时 Secure Enclave 密钥的 dataRepresentation 是硬件封装数据，不是私钥。
        // 加密只用其公钥；解密必须由同一设备、同一指纹集合完成私钥运算。
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: enclave.publicKey)
        let aad = Data(binding.utf8)
        let key = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: aad,
                                                sharedInfo: Data("CredPivot local unlock v1".utf8), outputByteCount: 32)
        let sealed = try AES.GCM.seal(vmk, using: key, authenticating: aad)
        guard let combined = sealed.combined else { return false }
        let record: [String: Any] = ["enclave_key": enclave.dataRepresentation.base64EncodedString(),
                                    "ephemeral_public_key": ephemeral.publicKey.x963Representation.base64EncodedString(),
                                    "sealed_vmk": combined.base64EncodedString(), "binding": binding]
        let recordData = try JSONSerialization.data(withJSONObject: record)
        guard write(materialAccount, data: recordData) else { return false }
      } catch { return false }
    }
    return write(policyAccount, data: policyData)
  }

  static func unlockPassword(_ password: String) -> Bool {
    TouchIdGate.invalidateInFlightAuthentication()
    guard request(["type": "unlock_password", "password": password])?["unlocked"] as? Bool == true else { return false }
    enroll()
    return true
  }

  static func verifyPassword(_ password: String) -> Bool {
    TouchIdGate.invalidateInFlightAuthentication()
    let unlocked = request(["type": "status"])?["unlocked"] as? Bool == true
    if !unlocked { return unlockPassword(password) }
    guard request(["type": "verify_master_password", "password": password])?["verified"] as? Bool == true else { return false }
    enroll()
    return true
  }

  static func unlockBiometric(completion: @escaping (Bool) -> Void) {
    guard !TouchIdGate.isAuthenticating,
          request(["type": "status"])?["master_password_required"] as? Bool == false,
          let data = read(materialAccount),
          let record = try? JSONSerialization.jsonObject(with: data) as? [String: String],
          let binding = record["binding"],
          let policyData = read(policyAccount),
          let storedPolicy = try? JSONSerialization.jsonObject(with: policyData) as? [String: Any],
          storedPolicy["binding"] as? String == binding,
          let enclaveData = record["enclave_key"].flatMap({ Data(base64Encoded: $0) }),
          let publicData = record["ephemeral_public_key"].flatMap({ Data(base64Encoded: $0) }),
          let sealedData = record["sealed_vmk"].flatMap({ Data(base64Encoded: $0) }) else { completion(false); return }
    let context = LAContext()
    context.localizedReason = NativePresentation.tr("解锁 CredPivot 保险库")
    context.localizedFallbackTitle = ""
    let epoch = TouchIdGate.beginAuthentication(context: context)
    DispatchQueue.global(qos: .userInitiated).async {
      let decrypted: Data?
      do {
        let enclave = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: enclaveData,
                                                                    authenticationContext: context)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: publicData)
        let secret = try enclave.sharedSecretFromKeyAgreement(with: publicKey)
        let aad = Data(binding.utf8)
        let key = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: aad,
                                                sharedInfo: Data("CredPivot local unlock v1".utf8), outputByteCount: 32)
        decrypted = try AES.GCM.open(AES.GCM.SealedBox(combined: sealedData), using: key, authenticating: aad)
      } catch { decrypted = nil }
      DispatchQueue.main.async {
        var vmk = decrypted
        defer { if let count = vmk?.count { vmk?.resetBytes(in: 0..<count) } }
        guard TouchIdGate.endAuthentication(epoch), let key = vmk else { completion(false); return }
        let material: [String: Any] = ["vmk": key.base64EncodedString(), "policy": storedPolicy]
        let ok = request(["type": "unlock_local", "material": material])?["unlocked"] as? Bool == true
        if ok { _ = persist(enroll: false) }
        completion(ok)
      }
    }
  }
}

final class TouchIdGate {
  static let shared = TouchIdGate()
  static var isAuthenticating = false
  private(set) static var authenticationEpoch: UInt64 = 0
  private static var activeContext: LAContext?

  static func invalidateInFlightAuthentication() {
    authenticationEpoch &+= 1
    activeContext?.invalidate()
    activeContext = nil
    isAuthenticating = false
  }

  static func beginAuthentication(context: LAContext? = nil) -> UInt64 {
    authenticationEpoch &+= 1
    activeContext?.invalidate()
    activeContext = context
    isAuthenticating = true
    return authenticationEpoch
  }

  static func endAuthentication(_ epoch: UInt64) -> Bool {
    guard epoch == authenticationEpoch else { return false }
    isAuthenticating = false
    activeContext = nil
    return true
  }

  private func askMasterPassword(reason: String, completion: @escaping (Bool) -> Void) {
    let epoch = TouchIdGate.beginAuthentication()
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = NativePresentation.tr("验证保险库主密码")
    alert.informativeText = reason
    let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 24))
    field.placeholderString = NativePresentation.tr("保险库主密码（不是 Mac 登录密码）")
    alert.accessoryView = field
    alert.addButton(withTitle: NativePresentation.tr("验证"))
    alert.addButton(withTitle: NativePresentation.tr("取消"))
    alert.window.initialFirstResponder = field
    let accepted = alert.runModal() == .alertFirstButtonReturn
    defer { field.stringValue = "" }
    guard TouchIdGate.endAuthentication(epoch), accepted else { completion(false); return }
    completion(LocalVaultUnlock.verifyPassword(field.stringValue))
  }

  func authenticateForExtensionGate(reason: String, completion: @escaping (Bool) -> Void) {
    authenticate(reason: reason, allowReuse: false, completion: completion)
  }

  func authenticateSensitiveOperation(reason: String, completion: @escaping (Bool) -> Void) {
    authenticate(reason: reason, allowReuse: true, completion: completion)
  }

  private func authenticate(reason: String, allowReuse: Bool, completion: @escaping (Bool) -> Void) {
    let localizedReason = NativePresentation.tr(reason)
    guard !TouchIdGate.isAuthenticating else { completion(false); return }
    let status = LocalVaultUnlock.request(["type": "status"]) ?? [:]
    if allowReuse && status["sensitive_auth_active"] as? Bool == true { completion(true); return }
    if status["master_password_required"] as? Bool != false {
      askMasterPassword(reason: localizedReason, completion: completion)
      return
    }
    if status["unlocked"] as? Bool != true {
      let context = LAContext()
      var error: NSError?
      if !LocalVaultUnlock.configured || !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
        askMasterPassword(reason: localizedReason, completion: completion)
      } else {
        LocalVaultUnlock.unlockBiometric(completion: completion)
      }
      return
    }
    let context = LAContext()
    context.localizedFallbackTitle = NativePresentation.tr("使用主密码")
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
      askMasterPassword(reason: localizedReason, completion: completion)
      return
    }
    let epoch = TouchIdGate.beginAuthentication(context: context)
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: localizedReason) { success, error in
      DispatchQueue.main.async {
        guard TouchIdGate.endAuthentication(epoch) else { completion(false); return }
        if success {
          completion(LocalVaultUnlock.request(["type": "sensitive_auth_grant"])?["verified"] as? Bool == true)
        } else if let error = error as? LAError, error.code == .userFallback || error.code == .biometryLockout {
          self.askMasterPassword(reason: localizedReason, completion: completion)
        } else { completion(false) }
      }
    }
  }
}

enum LoginItemRegistrar {
  static func status() -> [String: Any] {
    if #available(macOS 13.0, *) {
      return ["supported": true, "enabled": SMAppService.mainApp.status == .enabled,
              "requires_approval": SMAppService.mainApp.status == .requiresApproval]
    }
    return ["supported": false, "enabled": false, "requires_approval": false]
  }

  /// JSON 保存用户意图，系统实际状态另行展示；注册失败不能伪装成已启用。
  static func applyPreference() -> String? {
    guard let desired = AppPreferences.settings()["launch_at_login"] as? Bool else { return nil }
    if #available(macOS 13.0, *) {
      let service = SMAppService.mainApp
      if desired && service.status == .requiresApproval { return "登录启动等待批准，请在系统设置的「登录项」中允许 CredPivot。" }
      if desired && service.status == .enabled { return nil }
      if !desired && service.status != .enabled && service.status != .requiresApproval { return nil }
      do {
        if desired { try service.register() } else { try service.unregister() }
        if service.status == .requiresApproval { return "登录启动等待系统批准，请检查系统设置的「登录项」。" }
        return (service.status == .enabled) == desired ? nil : "配置已保存，但登录项状态尚未同步，请重试或检查系统设置。"
      } catch { return "配置已保存，但登录项注册未生效，请检查系统设置。" }
    }
    return desired ? "当前系统不支持登录项注册，需要 macOS 13 或更新版本。" : nil
  }

  static func setEnabled(_ enabled: Bool, result: @escaping FlutterResult) {
    guard AppPreferences.update(["launch_at_login": enabled]) else {
      result(FlutterError(code: "settings_write", message: "登录启动配置保存失败", details: nil)); return
    }
    if let notice = applyPreference() { result(FlutterError(code: "login_item", message: notice, details: nil)) }
    else { result(nil) }
  }
}

enum ChromeHostInstaller {
  private static let hostName = "com.credpivot.chrome.m0"
  private static let credPivotDir: URL = {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot", isDirectory: true)
  }()
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
    let bundledHost = resolveSourceHostBinary()
    var trustedHostConfigured = false
    var installedHostCurrent = false
    if let bundledHost {
      if let trusted = getenv("CREDPIVOT_TRUSTED_NATIVE_HOST") {
        trustedHostConfigured = URL(fileURLWithPath: String(cString: trusted)).resolvingSymlinksInPath()
          == URL(fileURLWithPath: bundledHost).resolvingSymlinksInPath()
      }
      if let source = try? Data(contentsOf: URL(fileURLWithPath: bundledHost)),
         let installed = try? Data(contentsOf: installedHostPath) {
        installedHostCurrent = SHA256.hash(data: source) == SHA256.hash(data: installed)
      }
    }
    var out: [String: Any] = [
      "host_name": hostName,
      "manifest_path": manifestURL.path,
      "manifest_exists": FileManager.default.fileExists(atPath: manifestURL.path),
      "installed_host_path": installedHostPath.path,
      "installed_host_exists": FileManager.default.fileExists(atPath: installedHostPath.path),
      "trusted_host_configured": trustedHostConfigured,
      "installed_host_current": installedHostCurrent,
      "manifest_host_matches_installed": false,
      "stored_extension_id": stored,
      "manifest_extension_id": manifestId ?? "",
      "host_id_matches_manifest": !stored.isEmpty && manifestId == stored,
      "extension_dir_path": extensionDirectoryPath() ?? "",
      "extension_dir_exists": extensionDirectoryPath() != nil,
    ]
    if let data = try? Data(contentsOf: manifestURL),
       let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
      out["manifest_allowed_origins"] = json["allowed_origins"]
      out["manifest_host_binary"] = json["path"]
      out["manifest_host_matches_installed"] = (json["path"] as? String) == installedHostPath.path
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
    // 校验基准必须来自当前 App，不能把待校验的安装副本作为可信源。
    if let bundled = Bundle.main.path(forResource: "credpivot-native-host", ofType: nil) {
      return bundled
    }
    return nil
  }

  private static func materializeHostBinary() throws -> String {
    guard let src = resolveSourceHostBinary() else {
      throw NSError(
        domain: "CredPivot",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "App 包内缺少 native-host，请执行 make macos-build-debug 后完全退出并重新打开 App"]
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
    guard let raw = AppPreferences.settings()["chrome_extension_id"] as? String else { return nil }
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

  /// Agent 使用 App 包内原件校验 Chrome 启动的安装副本。
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
    if extId.range(of: "^[a-p]{32}$", options: .regularExpression) == nil {
      return [
        "ok": false,
        "message": "请填写 Chrome 扩展 ID（在 chrome://extensions 打开开发者模式后复制）",
      ]
    }
    guard AppPreferences.update(["chrome_extension_id": extId]) else { return ["ok": false, "message": "扩展 ID 保存失败"] }

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

  static func applyPreference() -> [String: Any] {
    if let id = storedExtensionId() { return install(extensionId: id) }
    do {
      if FileManager.default.fileExists(atPath: manifestURL.path) { try FileManager.default.removeItem(at: manifestURL) }
      return ["ok": true]
    } catch { return ["ok": false, "message": "浏览器连接配置清理失败"] }
  }
}

enum SshIdentityAgentHelper {
  private static let markerStart = "# >>> CredPivot M0 IdentityAgent"
  private static let markerEnd = "# <<< CredPivot M0"

  static func status() -> [String: Any] {
    let config = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh/config")
    guard FileManager.default.fileExists(atPath: config.path) else {
      return ["ok": true, "configured": false]
    }
    do {
      let text = try String(contentsOf: config, encoding: .utf8)
      // 只识别本应用管理的片段，不将用户自己的 IdentityAgent 配置视为已接入。
      if let start = text.range(of: markerStart),
         text.range(of: markerEnd, range: start.upperBound..<text.endIndex) == nil {
        return ["ok": false, "message": "CredPivot SSH 配置片段不完整，请检查 ~/.ssh/config"]
      }
      return ["ok": true, "configured": text.contains(markerStart)]
    } catch {
      return ["ok": false, "message": "无法读取 ~/.ssh/config，请检查文件权限后刷新状态"]
    }
  }

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

  static func applyLaunchConfig(_ map: [String: Any]) -> Bool {
    if let appPath = map["path"] as? String, !appPath.isEmpty {
      guard setAppPath(appPath) else { return false }
    }
    clearLegacyLaunchExtras()
    return true
  }

  private static func clearLegacyLaunchExtras() {
    UserDefaults.standard.removeObject(forKey: legacyLaunchModeKey)
    UserDefaults.standard.removeObject(forKey: legacyLauncherPathKey)
    UserDefaults.standard.removeObject(forKey: legacyArgvTemplateKey)
    UserDefaults.standard.removeObject(forKey: legacyCwdKey)
  }

  static func currentAppPath() -> String? {
    let path = AppPreferences.settings()["terminal_app_path"] as? String ?? ""
    return path.isEmpty ? nil : path
  }

  /// 旧版预设 id（terminal/iterm/warp），首次选择 .app 后不再使用。
  static func setLegacyPreset(_ id: String) {
    if id == "terminal" {
      setAppPath("/System/Applications/Utilities/Terminal.app")
    } else if id == "iterm" {
      setAppPath("/Applications/iTerm.app")
    } else if id == "warp" {
      setAppPath("/Applications/Warp.app")
    }
  }

  @discardableResult
  static func setAppPath(_ path: String) -> Bool {
    guard AppPreferences.update(["terminal_app_path": path]) else { return false }
    UserDefaults.standard.removeObject(forKey: legacyIdKey)
    return true
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
    // 选择只修改页面草稿，用户点击保存后才写统一配置。
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

    let err: String?
    switch bundleId {
    case "com.apple.Terminal":
      let script = "tell application \"Terminal\" to do script \"\(escapeAppleScript(command))\""
      err = runOsascript(script)
    case "com.googlecode.iterm2":
      let script =
        "tell application \"iTerm\" to create window with default profile command \"\(escapeAppleScript(command))\""
      err = runOsascript(script)
    case "dev.warp.Warp-Stable", "dev.warp.Warp":
      let enc = command.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? command
      let url = "warp://action/new_tab?command=\(enc)"
      NSWorkspace.shared.open(URL(string: url)!)
      err = nil
    default:
      if appFile.contains("tabby") || bundleId.lowercased().contains("tabby") || tabbyCliPath(appPath: appPath) != nil {
        err = launchTabbyShellCommand(
          appPath: appPath,
          command: command,
          launchSessionId: launchSessionId
        )
      } else if let script = writeLaunchScript(shellCommand: command, sessionId: launchSessionId) {
        err = runProcess(
          executable: "/usr/bin/open",
          arguments: ["-na", appPath, "--args", "/bin/zsh", script],
          waitForExit: false
        )
      } else {
        err = "无法写入启动脚本 ~/.credpivot/terminal_launch.sh"
      }
    }

    if err == nil {
      schedulePurgeTerminalLaunchScripts(sessionId: launchSessionId)
    }
    return err
  }

  private static func launchScriptURL(sessionId: String?) -> URL {
    let name = sessionId.map { "terminal_launch_\($0).sh" } ?? launchScriptName
    return FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot", isDirectory: true)
      .appendingPathComponent(name)
  }

  private static var credPivotRuntimeDir: URL {
    FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".credpivot", isDirectory: true)
  }

  private static func launchScriptContainsLegacySecrets(_ url: URL) -> Bool {
    guard let text = try? String(contentsOf: url, encoding: .utf8) else {
      return false
    }
    return text.contains("password-file")
      || text.contains("--password-file")
      || text.contains("--otp '")
      || text.contains("--otp \"")
  }

  /// 旧版一键 SSH 会把密码/MFA 写进 `~/.credpivot/*.sh` 或诊断文件，启动时清掉。
  static func purgeLegacySensitiveLaunchScripts() {
    let dir = credPivotRuntimeDir
    guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
      return
    }
    for name in names where name.hasSuffix(".sh") {
      let url = dir.appendingPathComponent(name)
      if launchScriptContainsLegacySecrets(url) {
        try? FileManager.default.removeItem(at: url)
      }
    }
    let diag = lastLaunchPlanURL
    if launchScriptContainsLegacySecrets(diag) {
      try? FileManager.default.removeItem(at: diag)
    }
  }

  /// 启动脚本仅用于 Tabby/open 拉起 zsh，读后无保留价值。
  static func purgeTerminalLaunchScripts() {
    let dir = credPivotRuntimeDir
    guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir.path) else {
      return
    }
    for name in names {
      let isLaunchScript =
        name == launchScriptName
        || (name.hasPrefix("terminal_launch_") && name.hasSuffix(".sh"))
      if isLaunchScript {
        try? FileManager.default.removeItem(at: dir.appendingPathComponent(name))
      }
    }
    purgeLegacySensitiveLaunchScripts()
  }

  /// 终端进程启动后再删当次脚本，避免 Tabby/open 尚未 open(2) 文件。
  private static func schedulePurgeTerminalLaunchScripts(sessionId: String?) {
    DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) {
      if let sessionId {
        try? FileManager.default.removeItem(at: launchScriptURL(sessionId: sessionId))
      }
      purgeTerminalLaunchScripts()
    }
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
    try writeAskpassTrustArtifacts(sourcePath: src)
    return installedURL.path
  }

  private static func writeAskpassTrustArtifacts(sourcePath: String) throws {
    let data = try Data(contentsOf: URL(fileURLWithPath: sourcePath))
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    try digest.write(
      to: credPivotDir.appendingPathComponent("askpass.sha256"),
      atomically: true,
      encoding: .utf8
    )
    try sourcePath.write(
      to: credPivotDir.appendingPathComponent("askpass_trusted.path"),
      atomically: true,
      encoding: .utf8
    )
  }

  private static let expectScriptName = "ssh-expect-pass.exp"

  private static var expectScriptURL: URL {
    credPivotDir.appendingPathComponent(expectScriptName)
  }

  private static func resolveSourceExpectScript() -> String? {
    if let bundled = Bundle.main.path(forResource: "ssh-expect-pass", ofType: "exp") {
      return bundled
    }
    let pathFile = credPivotDir.appendingPathComponent("expect_script.source.path")
    if let raw = try? String(contentsOf: pathFile, encoding: .utf8) {
      let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
      if FileManager.default.fileExists(atPath: p) {
        return p
      }
    }
    if FileManager.default.fileExists(atPath: expectScriptURL.path) {
      return expectScriptURL.path
    }
    return nil
  }

  /// 每次从 App 包（或开发期源路径）覆盖 `~/.credpivot/ssh-expect-pass.exp`。
  static func materializeExpectScript() throws -> String {
    guard let src = resolveSourceExpectScript() else {
      throw NSError(
        domain: "CredPivot",
        code: 2,
        userInfo: [NSLocalizedDescriptionKey: "内置 SSH expect 脚本缺失，请先 make macos-build"]
      )
    }
    let srcData = try Data(contentsOf: URL(fileURLWithPath: src))
    let srcText = String(data: srcData, encoding: .utf8) ?? ""
    if !srcText.contains("credpivot-expect-version: 2") {
      throw NSError(
        domain: "CredPivot",
        code: 3,
        userInfo: [NSLocalizedDescriptionKey: "SSH expect 脚本版本过旧，请 make macos-sync-artifacts 后重开 App"]
      )
    }
    try FileManager.default.createDirectory(at: credPivotDir, withIntermediateDirectories: true)
    let dst = expectScriptURL
    if FileManager.default.fileExists(atPath: dst.path) {
      try FileManager.default.removeItem(at: dst)
    }
    try FileManager.default.copyItem(atPath: src, toPath: dst.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dst.path)
    return dst.path
  }

  /// 一键连接：PTY + expect 处理 keyboard-interactive MFA；密码/OTP 经 askpass 向 Agent 领取。
  static func openInTerminal(
    host: String,
    port: Int,
    user: String,
    sessionId: String
  ) -> String? {
    let askpassPath: String
    let expectPath: String
    do {
      askpassPath = try materializeInstalledBinary()
      expectPath = try materializeExpectScript()
    } catch {
      return error.localizedDescription
    }
    if !FileManager.default.fileExists(atPath: "/usr/bin/expect") {
      return "系统缺少 /usr/bin/expect，无法自动认证 SSH（含 MFA）"
    }
    guard let appPath = TerminalLauncher.currentAppPath(), !appPath.isEmpty else {
      return "未选择终端应用：请在「服务器」页配置终端"
    }
    var args = [
      expectPath,
      "--user", user,
      "--host", host,
      "--session-id", sessionId,
      "--askpass", askpassPath,
    ]
    if port != 22 {
      args.append(contentsOf: ["--port", String(port)])
    }
    if let err = TerminalLauncher.launchShellCommandLine(
      appPath: appPath,
      executable: "/usr/bin/expect",
      arguments: args,
      launchSessionId: sessionId
    ) {
      let shellCmd = (["/usr/bin/expect"] + args).map { TerminalLauncher.shellQuoteForPlan($0) }.joined(separator: " ")
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

// 只监听主窗口事件，不注册系统全局热键；原生录入期间暂停业务快捷键。
final class CredPivotShortcuts {
  private var localMonitor: Any?
  private var localBindings: [String: (UInt16, NSEvent.ModifierFlags)] = [:]
  private var recording = false
  private let action: (String) -> Void
  private let keys: [String: UInt16] = ["a":0,"s":1,"d":2,"f":3,"h":4,"g":5,"z":6,"x":7,"c":8,"v":9,"b":11,"q":12,"w":13,"e":14,"r":15,"y":16,"t":17,"1":18,"2":19,"3":20,"4":21,"6":22,"5":23,"9":25,"7":26,"8":28,"0":29,"o":31,"u":32,"i":34,"p":35,"l":37,"j":38,"k":40,"n":45,"m":46,"space":49]
  private let modifiers: NSEvent.ModifierFlags = [.command, .control, .option, .shift]
  private let labels = ["search": "搜索凭据", "lock": "锁定保险库", "new": "新建记录"]
  private let reserved = ["command+c", "command+v", "command+x", "command+a", "command+z", "command+shift+z", "command+w", "command+q", "command+h", "command+m"]

  init(action: @escaping (String) -> Void) {
    self.action = action
    localMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      guard let self = self, !self.recording, NSApp.modalWindow == nil,
            let window = (NSApp.delegate as? AppDelegate)?.mainFlutterWindow,
            NSApp.isActive, event.window === window, window.isKeyWindow else { return event }
      let flags = event.modifierFlags.intersection(self.modifiers)
      for (name, binding) in self.localBindings where binding.0 == event.keyCode && binding.1 == flags {
        if !event.isARepeat { self.action(name) }
        return nil
      }
      return event
    }
  }

  private func parse(_ text: String) -> (UInt16, NSEvent.ModifierFlags)? {
    let parts = text.split(separator: "+").map(String.init)
    guard let last = parts.last, let key = keys[last], (2...5).contains(parts.count) else { return nil }
    var flags: NSEvent.ModifierFlags = []
    for part in parts.dropLast() {
      switch part {
      case "command": flags.insert(.command)
      case "control": flags.insert(.control)
      case "option": flags.insert(.option)
      case "shift": flags.insert(.shift)
      default: return nil
      }
    }
    guard flags.contains(.command) || flags.contains(.control) else { return nil }
    return (key, flags)
  }

  func apply(_ settings: [String: Any]) {
    localBindings.removeAll()
    for name in ["search", "lock", "new"] {
      if let text = settings["shortcut_" + name] as? String, let binding = parse(text) {
        localBindings[name] = binding
      }
    }
  }

  func record(name: String, bindings: [String: String]) -> String? {
    guard !recording, NSApp.modalWindow == nil else { return nil }
    recording = true
    defer { recording = false }
    let alert = NSAlert()
    alert.messageText = NativePresentation.tr("设置快捷键 · {0}", NativePresentation.tr(labels[name] ?? name))
    alert.informativeText = NativePresentation.tr("请直接按下组合键，包含 ⌘ 或 ⌃，搭配字母、数字或空格。按 Esc 取消。")
    let preview = NSTextField(wrappingLabelWithString: NativePresentation.tr("等待按键…"))
    preview.frame = NSRect(x: 0, y: 0, width: 380, height: 60)
    alert.accessoryView = preview
    alert.addButton(withTitle: NativePresentation.tr("使用此组合"))
    alert.addButton(withTitle: NativePresentation.tr("取消"))
    alert.buttons.first?.isEnabled = false
    var chosen: String?
    let monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
      guard let self = self, event.window === alert.window else { return event }
      let flags = event.modifierFlags.intersection(self.modifiers)
      if event.keyCode == 53 && flags.isEmpty {
        NSApp.abortModal()
        alert.window.orderOut(nil)
        return nil
      }
      if event.keyCode == 36 && flags.isEmpty && chosen != nil { return event }
      if event.isARepeat { return nil }
      chosen = nil
      alert.buttons.first?.isEnabled = false
      guard let key = self.keys.first(where: { $0.value == event.keyCode })?.key,
            flags.contains(.command) || flags.contains(.control) else {
        preview.stringValue = NativePresentation.tr("请使用 ⌘ 或 ⌃ 搭配字母、数字或空格。")
        return nil
      }
      if self.reserved.contains(where: { self.parse($0).map { $0.0 == event.keyCode && $0.1 == flags } ?? false }) {
        preview.stringValue = NativePresentation.tr("此组合保留给系统编辑或窗口操作，请换一个组合。")
        return nil
      }
      if let duplicate = bindings.first(where: { entry in
        entry.key != name && (self.parse(entry.value).map { $0.0 == event.keyCode && $0.1 == flags } ?? false)
      }) {
        preview.stringValue = NativePresentation.tr("与「{0}」重复，请换一个组合。", NativePresentation.tr(self.labels[duplicate.key] ?? duplicate.key))
        return nil
      }
      var parts: [String] = []
      if flags.contains(.control) { parts.append("control") }
      if flags.contains(.option) { parts.append("option") }
      if flags.contains(.shift) { parts.append("shift") }
      if flags.contains(.command) { parts.append("command") }
      chosen = (parts + [key]).joined(separator: "+")
      preview.stringValue = (flags.contains(.control) ? "⌃" : "") + (flags.contains(.option) ? "⌥" : "") + (flags.contains(.shift) ? "⇧" : "") + (flags.contains(.command) ? "⌘" : "") + (key == "space" ? "Space" : key.uppercased())
      alert.buttons.first?.isEnabled = true
      return nil
    }
    defer { if let monitor = monitor { NSEvent.removeMonitor(monitor) } }
    return alert.runModal() == .alertFirstButtonReturn ? chosen : nil
  }

  deinit {
    if let localMonitor = localMonitor { NSEvent.removeMonitor(localMonitor) }
  }
}

// 与 Flutter 共用用户导入的 JSON 语言包；这里只处理 UI 文案，不读取保险库内容。
enum NativePresentation {
  private static var messages: [String: String] = [:]
  static func reload() {
    messages = [:]
    guard let locale = AppPreferences.settings()["language"] as? String, locale != "zh-CN",
          locale.range(of: "^[a-zA-Z0-9_-]{1,64}$", options: .regularExpression) != nil else { return }
    let path = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".credpivot/languages/\(locale).json")
    guard let handle = try? FileHandle(forReadingFrom: path) else { return }
    defer { try? handle.close() }
    guard let data = try? handle.read(upToCount: 4 * 1024 * 1024 + 1), data.count <= 4 * 1024 * 1024,
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          value["version"] as? Int == 1, value["locale"] as? String == locale,
          let translated = value["messages"] as? [String: String], translated.count <= 10000,
          translated.allSatisfy({ $0.key.count <= 4096 && $0.value.count <= 8192 }) else { return }
    messages = translated
  }

  static func tr(_ source: String, _ arguments: String...) -> String {
    let template = messages[source] ?? source
    guard !arguments.isEmpty, let pattern = try? NSRegularExpression(pattern: "\\{([0-9]+)\\}") else { return template }
    var result = template
    for match in pattern.matches(in: template, range: NSRange(location: 0, length: (template as NSString).length)).reversed() {
      guard let token = Range(match.range(at: 1), in: template), let index = Int(template[token]),
            arguments.indices.contains(index), let range = Range(match.range, in: result) else { continue }
      result.replaceSubrange(range, with: arguments[index])
    }
    return result
  }
}
