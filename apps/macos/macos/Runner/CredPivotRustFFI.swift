import Foundation

@_silgen_name("credpivot_agent_start")
private func credpivot_agent_start() -> Int32

@_silgen_name("credpivot_agent_stop")
private func credpivot_agent_stop() -> Int32

@_silgen_name("credpivot_agent_is_running")
private func credpivot_agent_is_running() -> Int32

@_silgen_name("credpivot_agent_restart")
private func credpivot_agent_restart() -> Int32

@_silgen_name("credpivot_agent_request_json")
private func credpivot_agent_request_json(_ request: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?

@_silgen_name("credpivot_string_free")
private func credpivot_string_free(_ ptr: UnsafeMutablePointer<CChar>)

@_silgen_name("credpivot_browser_auth_event")
private func credpivot_browser_auth_event(_ stage: UInt32, _ elapsedMs: UInt64)

@_silgen_name("credpivot_webdav_error")
private func credpivot_webdav_error(_ operation: UInt32, _ phase: UInt32, _ directory: UInt32, _ status: UInt32, _ reason: UInt32)

enum CredPivotRustFFI {
  private static let webDAVLogQueue = DispatchQueue(label: "credpivot.webdav.cleanup-log", qos: .utility)
  static func logWebDAVCleanup(_ phase: UInt32, status: Int = 0, reason: UInt32 = 5, gate: Bool = false) {
    let code = UInt32((100...599).contains(status) ? status : 0)
    // 固定阶段/原因编码，不记录 URL、目录名、认证信息或服务端正文；串行写入保留事件顺序。
    webDAVLogQueue.async { credpivot_webdav_error(6, phase, gate ? 6 : 5, code, reason) }
  }
  static func logBrowserAuth(_ stage: UInt32, since started: TimeInterval) {
    let elapsed = UInt64(max(0, (ProcessInfo.processInfo.systemUptime - started) * 1000))
    // 日志文件锁和磁盘写入也不能占用负责展示/关闭系统验证窗口的主线程。
    DispatchQueue.global(qos: .utility).async { credpivot_browser_auth_event(stage, elapsed) }
  }
  static func start() -> Int32 {
    let code = credpivot_agent_start()
    if code == 0 {
      LocalVaultUnlock.restorePolicy()
      AppPreferences.migrateLegacyPreferences()
    }
    return code
  }
  static func stop() -> Int32 { credpivot_agent_stop() }
  static func isRunning() -> Bool { credpivot_agent_is_running() == 1 }
  static func restart() -> Int32 {
    TouchIdGate.invalidateInFlightAuthentication()
    let code = credpivot_agent_restart()
    if code == 0 {
      LocalVaultUnlock.restorePolicy()
      AppPreferences.migrateLegacyPreferences()
    }
    return code
  }
}

func credpivotAgentRequestJsonString(_ body: String) -> String {
  body.withCString { ptr -> String in
    guard let out = credpivot_agent_request_json(ptr) else { return "" }
    let s = String(cString: out)
    credpivot_string_free(out)
    return s
  }
}
