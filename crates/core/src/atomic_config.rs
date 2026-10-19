use crate::cpvc1::{parse_config, serialize_config, CpvcConfig};
use crate::error::{CoreError, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// 原子写入 vault.json（M1-4 / M1-7 共用）。
pub fn write_vault_json_atomic(dir: &Path, config: &CpvcConfig) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| CoreError::io(e.to_string()))?;
    let target = dir.join("vault.json");
    let next = dir.join("vault.json.next");
    let bak = dir.join("vault.json.bak");

    let body = serialize_config(config)?;
    fs::write(&next, body).map_err(|e| CoreError::io(e.to_string()))?;
    if target.exists() {
        fs::copy(&target, &bak).map_err(|e| CoreError::io(e.to_string()))?;
    }
    fs::rename(&next, &target).map_err(|e| CoreError::io(e.to_string()))?;
    Ok(())
}

pub fn read_vault_json(dir: &Path) -> Result<CpvcConfig> {
    let path = dir.join("vault.json");
    let body = fs::read_to_string(&path).map_err(|e| CoreError::io(e.to_string()))?;
    parse_config(&body)
}

pub fn recover_pending_next(dir: &Path) -> Result<Option<PathBuf>> {
    let next = dir.join("vault.json.next");
    if !next.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&next).map_err(|e| CoreError::io(e.to_string()))?;
    let _cfg = parse_config(&body)?;
    let target = dir.join("vault.json");
    fs::rename(&next, &target).map_err(|e| CoreError::io(e.to_string()))?;
    Ok(Some(target))
}
