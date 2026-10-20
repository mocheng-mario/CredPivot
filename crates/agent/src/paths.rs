use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Default runtime paths under `~/.credpivot` (0700). Socket path kept short for AF_UNIX limits.
pub fn runtime_dir() -> PathBuf {
    dirs_home().join(".credpivot")
}

pub fn agent_socket_path() -> PathBuf {
    runtime_dir().join("agent.sock")
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

pub fn active_vault_pointer_path() -> PathBuf {
    runtime_dir().join("active_vault_dir")
}

fn read_persisted_vault_dir() -> Option<PathBuf> {
    let body = fs::read_to_string(active_vault_pointer_path()).ok()?;
    let path = PathBuf::from(body.trim());
    if path.join("vault.json").exists() {
        Some(path)
    } else {
        None
    }
}

/// 迁移或切换工作库后写入指针，下次启动沿用（仍可用 `CREDPIVOT_VAULT_DIR` 覆盖）。
pub fn persist_active_vault_dir(dir: &Path) -> std::io::Result<()> {
    ensure_runtime_dir()?;
    let pointer = active_vault_pointer_path();
    let next = runtime_dir().join("active_vault_dir.next");
    let mut f = fs::File::create(&next)?;
    f.write_all(dir.to_string_lossy().as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    fs::rename(next, pointer)?;
    Ok(())
}

pub fn vault_data_dir() -> PathBuf {
    std::env::var_os("CREDPIVOT_VAULT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| read_persisted_vault_dir().unwrap_or_else(|| runtime_dir().join("vault")))
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
