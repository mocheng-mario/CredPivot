//! 本机重置。只删除本机文件和本机配置，不连接远端，也不修改远端已有备份。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn reset_vault(active: &Path) -> io::Result<()> {
    let current = current_vault(active)?;
    ensure_deletable(&current)?;
    let mut settings = credpivot_core::read_app_settings()?;
    // 先改本机配置。写入失败时保险库文件保持不动。
    settings.webdav = None;
    settings.sync_host_names.clear();
    settings.vault_directory = None;
    credpivot_core::write_app_settings(&settings)?;
    remove_vault_files(&current)?;
    Ok(())
}

pub fn reset_app(active: &Path) -> io::Result<()> {
    let current = current_vault(active)?;
    ensure_deletable(&current)?;
    let runtime = crate::paths::runtime_dir();
    // 自定义目录不在运行目录里，删除运行目录不会带走当前库。
    let outside = !path_within(&current, &runtime);
    if outside {
        remove_vault_files(&current)?;
    }
    remove_runtime(&runtime)
}

fn current_vault(active: &Path) -> io::Result<PathBuf> {
    if active.as_os_str().is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "当前保险库路径无效"));
    }
    Ok(active.to_path_buf())
}

fn path_within(path: &Path, parent: &Path) -> bool {
    let Ok(path) = normalize(path) else { return false };
    let Ok(parent) = normalize(parent) else { return false };
    path.starts_with(parent)
}

fn normalize(path: &Path) -> io::Result<PathBuf> {
    if path.exists() { path.canonicalize() } else { Ok(path.to_path_buf()) }
}

fn remove_runtime(dir: &Path) -> io::Result<()> {
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
