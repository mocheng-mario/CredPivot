use std::fs;
use std::path::{Path, PathBuf};

/// Default runtime paths under `~/.credpivot` (0700). Socket path kept short for AF_UNIX limits.
pub fn runtime_dir() -> PathBuf {
    dirs_home().join(".credpivot")
}

pub fn agent_socket_path() -> PathBuf {
    runtime_dir().join("agent.sock")
}

/// Chrome Native Messaging 清单默认指向的 host 副本（与 App 包内二进制一致）。
pub fn materialized_native_host_path() -> PathBuf {
    runtime_dir().join("credpivot-native-host")
}

/// `SSH_ASKPASS` 默认指向的副本（须与 App 包内 credpivot-askpass 摘要一致）。
pub fn materialized_askpass_path() -> PathBuf {
    runtime_dir().join("credpivot-askpass")
}

pub fn materialized_askpass_digest_path() -> PathBuf {
    runtime_dir().join("askpass.sha256")
}

pub fn materialized_askpass_trusted_ref_path() -> PathBuf {
    runtime_dir().join("askpass_trusted.path")
}

/// Agent 写入浏览器验证请求标识，App 消费后唤起身份验证。
pub fn extension_gate_pending_path() -> PathBuf {
    runtime_dir().join("extension_gate.pending")
}

pub fn touch_extension_gate_pending() -> std::io::Result<()> {
    ensure_runtime_dir()?;
    let path = extension_gate_pending_path();
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    fs::write(path, ms.to_string())?;
    Ok(())
}

/// 已有 pending 时不重复写入，避免扩展轮询导致指纹弹窗关不掉。
pub fn touch_extension_gate_pending_if_absent() -> std::io::Result<bool> {
    let path = extension_gate_pending_path();
    if path.exists() {
        return Ok(false);
    }
    touch_extension_gate_pending()?;
    Ok(true)
}

pub fn clear_extension_gate_pending() -> std::io::Result<()> {
    let path = extension_gate_pending_path();
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn ssh_agent_socket_path() -> PathBuf {
    runtime_dir().join("ssh.sock")
}

pub fn single_writer_lock_path() -> PathBuf {
    runtime_dir().join("vault.runtime.lock")
}

pub fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn read_persisted_vault_dir() -> Option<PathBuf> {
    credpivot_core::effective_app_settings().vault_directory.map(PathBuf::from)
}

/// 迁移或切换工作库后写入指针，下次启动沿用（仍可用 `CREDPIVOT_VAULT_DIR` 覆盖）。
pub fn persist_active_vault_dir(dir: &Path) -> std::io::Result<()> {
    ensure_runtime_dir()?;
    let mut settings = credpivot_core::read_app_settings()?;
    settings.vault_directory = Some(dir.to_string_lossy().into_owned());
    credpivot_core::write_app_settings(&settings)
}

pub fn vault_data_dir() -> PathBuf {
    std::env::var_os("CREDPIVOT_VAULT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| read_persisted_vault_dir().unwrap_or_else(|| runtime_dir().join("vault")))
}

/// 每次 Vault 锁定递增；App 轮询以同步空闲锁等 UI。
pub fn vault_lock_generation_path() -> PathBuf {
    runtime_dir().join("vault_lock.generation")
}

pub fn bump_vault_lock_generation() {
    let _ = ensure_runtime_dir();
    let path = vault_lock_generation_path();
    let next = fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(|n| n + 1)
        .unwrap_or(1);
    let _ = fs::write(path, next.to_string());
}

pub fn read_vault_lock_generation() -> u64 {
    fs::read_to_string(vault_lock_generation_path())
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub fn ensure_runtime_dir() -> std::io::Result<()> {
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
