use crate::cpvc1::{parse_config, serialize_config, CpvcConfig};
use crate::error::{CoreError, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// 原子写入 vault.json（M1-4 / M1-7 共用）。
pub fn write_vault_json_atomic(dir: &Path, config: &CpvcConfig) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| CoreError::io(e.to_string()))?;
    let target = dir.join("vault.json");
    let next = dir.join("vault.json.next");
    let bak = dir.join("vault.json.bak");

    let body = serialize_config(config)?;
    let mut file = fs::File::create(&next).map_err(|e| CoreError::io(e.to_string()))?;
    file.write_all(body.as_bytes()).and_then(|_| file.sync_all())
        .map_err(|e| CoreError::io(e.to_string()))?;
    if target.exists() {
        fs::copy(&target, &bak).map_err(|e| CoreError::io(e.to_string()))?;
        fs::File::open(&bak).and_then(|file| file.sync_all())
            .map_err(|e| CoreError::io(e.to_string()))?;
    }
    // 先持久化 .next 和回退副本的目录项，再替换；返回成功前也要持久化 rename。
    let directory = fs::File::open(dir).map_err(|e| CoreError::io(e.to_string()))?;
    directory.sync_all().map_err(|e| CoreError::io(e.to_string()))?;
    fs::rename(&next, &target).map_err(|e| CoreError::io(e.to_string()))?;
    directory.sync_all().map_err(|e| CoreError::io(e.to_string()))?;
    Ok(())
}

pub fn read_vault_json(dir: &Path) -> Result<CpvcConfig> {
    let path = dir.join("vault.json");
    let body = fs::read_to_string(&path).map_err(|e| CoreError::io(e.to_string()))?;
    parse_config(&body)
}

/// 同目录临时文件 + rename，避免覆盖写入时截断破坏已有文件。
pub fn write_file_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| CoreError::io("output path has no parent"))?;
    fs::create_dir_all(parent).map_err(|e| CoreError::io(e.to_string()))?;
    let name = path
        .file_name()
        .ok_or_else(|| CoreError::io("output path has no file name"))?;
    let next = parent.join(format!("{}.next", name.to_string_lossy()));
    let bak = parent.join(format!("{}.bak", name.to_string_lossy()));
    let mut file = fs::File::create(&next).map_err(|e| CoreError::io(e.to_string()))?;
    file.write_all(contents).and_then(|_| file.sync_all())
        .map_err(|e| CoreError::io(e.to_string()))?;
    if path.exists() {
        fs::copy(path, &bak).map_err(|e| CoreError::io(e.to_string()))?;
        fs::File::open(&bak).and_then(|file| file.sync_all())
            .map_err(|e| CoreError::io(e.to_string()))?;
    }
    let directory = fs::File::open(parent).map_err(|e| CoreError::io(e.to_string()))?;
    directory.sync_all().map_err(|e| CoreError::io(e.to_string()))?;
    fs::rename(&next, path).map_err(|e| CoreError::io(e.to_string()))?;
    directory.sync_all().map_err(|e| CoreError::io(e.to_string()))?;
    Ok(())
}

pub fn recover_pending_next(dir: &Path) -> Result<Option<PathBuf>> {
    let next = dir.join("vault.json.next");
    if !next.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&next).map_err(|e| CoreError::io(e.to_string()))?;
    let _cfg = parse_config(&body)?;
    let target = dir.join("vault.json");
    fs::File::open(&next).and_then(|file| file.sync_all())
        .map_err(|e| CoreError::io(e.to_string()))?;
    fs::rename(&next, &target).map_err(|e| CoreError::io(e.to_string()))?;
    fs::File::open(dir).and_then(|file| file.sync_all())
        .map_err(|e| CoreError::io(e.to_string()))?;
    Ok(Some(target))
}
