//! 本机重置。只删除本机文件和本机配置，不连接远端，也不修改远端已有备份。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn reset_vault(active: &Path) -> io::Result<()> {
    let default_dir = crate::paths::runtime_dir().join("vault");
    let mut settings = credpivot_core::read_app_settings()?;
    let previous = settings
        .vault_directory
        .clone()
        .map(PathBuf::from);
    ensure_deletable(active)?;
    if let Some(dir) = &previous {
        ensure_deletable(dir)?;
    }
    ensure_deletable(&default_dir)?;
    // 先改本机配置。写入失败时保险库文件保持不动。
    settings.webdav = None;
    settings.sync_host_names.clear();
    settings.vault_directory = None;
    credpivot_core::write_app_settings(&settings)?;
    remove_vault_files(active)?;
    if let Some(dir) = previous {
        if dir != active {
            remove_vault_files(&dir)?;
        }
    }
    if default_dir != active {
        remove_vault_files(&default_dir)?;
    }
    Ok(())
}

pub fn reset_app() -> io::Result<()> {
    let dir = crate::paths::runtime_dir();
    if !dir.exists() {
        return Ok(());
    }
    let canon = dir.canonicalize()?;
    let home = crate::paths::dirs_home();
    let home = home.canonicalize().unwrap_or(home);
    if canon == home || !canon.starts_with(&home) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "运行目录不在本机用户目录内",
        ));
    }
    fs::remove_dir_all(canon)
}

fn ensure_deletable(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let canon = dir.canonicalize()?;
    let home = crate::paths::dirs_home();
    let home = home.canonicalize().unwrap_or(home);
    if canon == home || canon.parent().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "不能清除用户主目录",
        ));
    }
    Ok(())
}

fn remove_vault_files(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let canon = dir.canonicalize()?;
    for name in ["vault.json", "vault.json.next", "vault.json.bak", "vault.db"] {
        let path = canon.join(name);
        if path.is_file() {
            fs::remove_file(path)?;
        }
    }
    for path in credpivot_core::sqlcipher_sidecar_paths(&canon) {
        if path.is_file() {
            fs::remove_file(path)?;
        }
    }
    for name in ["restore-points", "upgrade-backups"] {
        let path = canon.join(name);
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}
