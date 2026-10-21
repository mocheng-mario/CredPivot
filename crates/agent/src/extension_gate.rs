use crate::paths::runtime_dir;
use std::fs;

pub fn extension_gate_until_path() -> std::path::PathBuf {
    runtime_dir().join("extension_gate_until_ms")
}

/// 浏览器空闲授权与 App 设置使用同一配置，锁库仍会立即撤销授权。
pub fn extension_gate_idle_secs() -> u64 {
    credpivot_core::effective_app_settings().browser_idle_seconds
}

pub fn clear_persisted_extension_gate() {
    let _ = fs::remove_file(extension_gate_until_path());
}
