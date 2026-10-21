use crate::paths::runtime_dir;
use std::fs;

const DEFAULT_IDLE_SECS: u64 = 300;

pub fn extension_gate_until_path() -> std::path::PathBuf {
    runtime_dir().join("extension_gate_until_ms")
}

pub fn extension_gate_idle_config_path() -> std::path::PathBuf {
    runtime_dir().join("extension_gate_idle_secs")
}

/// 扩展授权后，无 Native 活动超过该秒数需重新验证（可用环境变量或配置文件覆盖）。
pub fn extension_gate_idle_secs() -> u64 {
    if let Ok(v) = std::env::var("CREDPIVOT_EXTENSION_GATE_IDLE_SECS") {
        if let Ok(n) = v.trim().parse::<u64>() {
            if n > 0 {
                return n;
            }
        }
    }
    if let Ok(body) = fs::read_to_string(extension_gate_idle_config_path()) {
        if let Ok(n) = body.trim().parse::<u64>() {
            if n > 0 {
                return n;
            }
        }
    }
    DEFAULT_IDLE_SECS
}

pub fn clear_persisted_extension_gate() {
    let _ = fs::remove_file(extension_gate_until_path());
}
