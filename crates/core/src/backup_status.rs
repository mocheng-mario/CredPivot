//! M3-2：四种备份/验证状态（时间戳存 vault_settings）。

use crate::error::{CoreError, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const KEY_LOCAL_RESTORE_OK: &str = "backup_verify_local_restore_ms";
pub const KEY_OVB_EXPORT_OK: &str = "backup_verify_ovb_export_ms";
pub const KEY_OVB_DECRYPT_OK: &str = "backup_verify_ovb_decrypt_ms";
pub const KEY_RECOVERY_KEY_OK: &str = "backup_verify_recovery_key_ms";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BackupVerificationStatus {
    pub local_restore_verified_ms: Option<i64>,
    pub ovb_export_verified_ms: Option<i64>,
    pub ovb_decrypt_verified_ms: Option<i64>,
    pub recovery_key_verified_ms: Option<i64>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn get_i64(conn: &Connection, key: &str) -> Result<Option<i64>> {
    let row = conn.query_row(
        "SELECT value FROM vault_settings WHERE key = ?1",
        params![key],
        |r| r.get::<_, String>(0),
    );
    match row {
        Ok(v) => Ok(v.parse().ok()),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(CoreError::format(e.to_string())),
    }
}

fn set_i64(conn: &Connection, key: &str, value: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO vault_settings(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value.to_string()],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    Ok(())
}

pub fn read_backup_status(conn: &Connection) -> Result<BackupVerificationStatus> {
    Ok(BackupVerificationStatus {
        local_restore_verified_ms: get_i64(conn, KEY_LOCAL_RESTORE_OK)?,
        ovb_export_verified_ms: get_i64(conn, KEY_OVB_EXPORT_OK)?,
        ovb_decrypt_verified_ms: get_i64(conn, KEY_OVB_DECRYPT_OK)?,
        recovery_key_verified_ms: get_i64(conn, KEY_RECOVERY_KEY_OK)?,
    })
}

pub fn mark_local_restore_verified(conn: &Connection) -> Result<()> {
    set_i64(conn, KEY_LOCAL_RESTORE_OK, now_ms())
}

pub fn mark_ovb_export_verified(conn: &Connection) -> Result<()> {
    set_i64(conn, KEY_OVB_EXPORT_OK, now_ms())
}

pub fn mark_ovb_decrypt_verified(conn: &Connection) -> Result<()> {
    set_i64(conn, KEY_OVB_DECRYPT_OK, now_ms())
}

pub fn mark_recovery_key_verified(conn: &Connection) -> Result<()> {
    set_i64(conn, KEY_RECOVERY_KEY_OK, now_ms())
}
