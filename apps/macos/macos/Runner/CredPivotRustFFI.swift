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

enum CredPivotRustFFI {
  static func start() -> Int32 { credpivot_agent_start() }
  static func stop() -> Int32 { credpivot_agent_stop() }
  static func isRunning() -> Bool { credpivot_agent_is_running() == 1 }
  static func restart() -> Int32 { credpivot_agent_restart() }
}

func credpivotAgentRequestJsonString(_ body: String) -> String {
  body.withCString { ptr -> String in
    guard let out = credpivot_agent_request_json(ptr) else { return "" }
    let s = String(cString: out)
    credpivot_string_free(out)
    return s
  }
}
