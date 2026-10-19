//! M3-1：自动本地恢复点（`restore-points/` 目录，非 OVB）。

use crate::error::{CoreError, Result};
use crate::local_db::{export_database_bytes, verify_database, DB_FILENAME};
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SETTINGS_RESTORE_DIRTY: &str = "restore_dirty";
pub const SETTINGS_LAST_RESTORE_MS: &str = "restore_last_created_ms";
pub const RESTORE_POINTS_DIR: &str = "restore-points";
pub const MAX_RESTORE_POINTS: usize = 10;
const MS_PER_DAY: i64 = 86_400_000;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn get_setting(conn: &Connection, key: &str) -> Result<Option<String>> {
    let row = conn.query_row(
        "SELECT value FROM vault_settings WHERE key = ?1",
        params![key],
        |r| r.get::<_, String>(0),
    );
    match row {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(CoreError::format(e.to_string())),
    }
}

fn set_setting(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_settings(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    Ok(())
}

/// 业务写入后标记「尚未纳入恢复点」。
pub fn mark_restore_dirty(conn: &Connection) -> Result<()> {
    set_setting(conn, SETTINGS_RESTORE_DIRTY, "1")
}

fn clear_restore_dirty(conn: &Connection) -> Result<()> {
    set_setting(conn, SETTINGS_RESTORE_DIRTY, "0")
}

fn last_restore_ms(conn: &Connection) -> i64 {
    get_setting(conn, SETTINGS_LAST_RESTORE_MS)
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// 已解锁且脏、且距上次恢复点超过 24 小时。
pub fn should_create_restore_point(conn: &Connection) -> bool {
    let dirty = get_setting(conn, SETTINGS_RESTORE_DIRTY)
        .ok()
        .flatten()
        .map(|v| v == "1")
        .unwrap_or(false);
    if !dirty {
        return false;
    }
    let last = last_restore_ms(conn);
    now_ms() - last >= MS_PER_DAY
}

/// 创建一份恢复点并裁剪旧副本；成功则清除 dirty 并更新 last 时间。
pub fn create_restore_point_if_due(
    vault_dir: &Path,
    vmk: &[u8; 32],
    conn: &Connection,
) -> Result<Option<PathBuf>> {
    if !should_create_restore_point(conn) {
        return Ok(None);
    }
    let created = create_restore_point(vault_dir, vmk, conn)?;
    Ok(Some(created))
}

pub fn create_restore_point(
    vault_dir: &Path,
    vmk: &[u8; 32],
    conn: &Connection,
) -> Result<PathBuf> {
    let ts = now_ms();
    let point_dir = vault_dir
        .join(RESTORE_POINTS_DIR)
        .join(ts.to_string());
    fs::create_dir_all(&point_dir).map_err(|e| CoreError::io(e.to_string()))?;

    let db_bytes = export_database_bytes(vault_dir, vmk)?;
    fs::write(point_dir.join(DB_FILENAME), &db_bytes)
        .map_err(|e| CoreError::io(e.to_string()))?;

    let vault_json = vault_dir.join("vault.json");
    fs::copy(&vault_json, point_dir.join("vault.json"))
        .map_err(|e| CoreError::io(e.to_string()))?;

    // 校验副本可打开
    let tmp_vault = tempfile::tempdir().map_err(|e| CoreError::io(e.to_string()))?;
    fs::copy(&vault_json, tmp_vault.path().join("vault.json"))
        .map_err(|e| CoreError::io(e.to_string()))?;
    fs::write(tmp_vault.path().join(DB_FILENAME), &db_bytes)
        .map_err(|e| CoreError::io(e.to_string()))?;
    verify_database(tmp_vault.path(), vmk)?;

    set_setting(conn, SETTINGS_LAST_RESTORE_MS, &ts.to_string())?;
    clear_restore_dirty(conn)?;
    prune_restore_points(vault_dir)?;
    Ok(point_dir)
}

pub fn prune_restore_points(vault_dir: &Path) -> Result<()> {
    let root = vault_dir.join(RESTORE_POINTS_DIR);
    if !root.is_dir() {
        return Ok(());
    }
    let mut dirs: Vec<(i64, PathBuf)> = Vec::new();
    for ent in fs::read_dir(&root).map_err(|e| CoreError::io(e.to_string()))? {
        let ent = ent.map_err(|e| CoreError::io(e.to_string()))?;
        if !ent.file_type().map_err(|e| CoreError::io(e.to_string()))?.is_dir() {
            continue;
        }
        let name = ent.file_name().to_string_lossy().to_string();
        if let Ok(ts) = name.parse::<i64>() {
            dirs.push((ts, ent.path()));
        }
    }
    dirs.sort_by(|a, b| b.0.cmp(&a.0));
    if dirs.len() <= MAX_RESTORE_POINTS {
        return Ok(());
    }
    for (_, path) in dirs.into_iter().skip(MAX_RESTORE_POINTS) {
        fs::remove_dir_all(&path).map_err(|e| CoreError::io(e.to_string()))?;
    }
    Ok(())
}
