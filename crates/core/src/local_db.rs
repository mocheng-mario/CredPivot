//! M1-5：SQLCipher 本地库（固定 bundled 版本、原始密钥模式）。

use crate::crypto::derive_sqlcipher_key;
use crate::error::{CoreError, Result};
use crate::limits::MAX_OVB_FILE_BYTES;
use hex::encode;
use rusqlite::{backup::Backup, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

pub const DB_FILENAME: &str = "vault.db";
/// 与 rusqlite `bundled-sqlcipher` 绑定的发行版本（M1 冻结，升级须回归）。
pub const SQLCIPHER_M1_LABEL: &str = "sqlcipher-bundled-m1";

const M1_SCHEMA: &str = "
PRAGMA user_version = 1;
CREATE TABLE IF NOT EXISTS vault_meta (
  key TEXT PRIMARY KEY NOT NULL,
  value BLOB NOT NULL
);
INSERT OR REPLACE INTO vault_meta(key, value) VALUES ('m1_marker', X'01');
";

fn db_path(dir: &Path) -> PathBuf {
    dir.join(DB_FILENAME)
}

fn apply_cipher_key(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    let pragma = format!("PRAGMA key = \"x'{}'\";", encode(key));
    conn.execute_batch(&pragma)
        .map_err(|e| CoreError::format(e.to_string()))?;
    conn.execute_batch(
        "PRAGMA cipher_page_size = 4096;
         PRAGMA kdf_iter = 256000;
         PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
         PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;",
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    Ok(())
}

fn open_connection(path: &Path, key: &[u8; 32], create: bool) -> Result<Connection> {
    if create {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| CoreError::io(e.to_string()))?;
        }
    }
    let conn = Connection::open(path).map_err(|e| CoreError::io(e.to_string()))?;
    apply_cipher_key(&conn, key)?;
    if create {
        conn.execute_batch(M1_SCHEMA)
            .map_err(|e| CoreError::format(e.to_string()))?;
    } else {
        conn.query_row("SELECT count(*) FROM vault_meta", [], |_| Ok(()))
            .map_err(|_| CoreError::Auth)?;
    }
    Ok(conn)
}

pub fn init_database(vault_dir: &Path, vmk: &[u8; 32], vault_id: &Uuid) -> Result<()> {
    let path = db_path(vault_dir);
    if path.exists() {
        return Err(CoreError::format("vault.db already exists"));
    }
    let key = derive_sqlcipher_key(vmk, vault_id.as_bytes());
    let _conn = open_connection(&path, &key, true)?;
    Ok(())
}

pub fn verify_database(vault_dir: &Path, vmk: &[u8; 32]) -> Result<()> {
    let path = db_path(vault_dir);
    if !path.exists() {
        return Err(CoreError::format("missing vault.db"));
    }
    let vault_id = read_vault_uuid_from_dir(vault_dir)?;
    let key = derive_sqlcipher_key(vmk, vault_id.as_bytes());
    let conn = open_connection(&path, &key, false)?;
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|e| CoreError::format(e.to_string()))?;
    if check != "ok" {
        return Err(CoreError::format("integrity_check failed"));
    }
    Ok(())
}

fn read_vault_uuid_from_dir(vault_dir: &Path) -> Result<Uuid> {
    let body = fs::read_to_string(vault_dir.join("vault.json"))
        .map_err(|e| CoreError::io(e.to_string()))?;
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| CoreError::format(e.to_string()))?;
    let id = v
        .get("vault_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| CoreError::format("vault_id"))?;
    Uuid::parse_str(id).map_err(|_| CoreError::format("vault_id uuid"))
}

/// 一致性副本：checkpoint 后通过 backup API 导出（避免复制 WAL 中的打开态文件）。
pub fn export_database_bytes(vault_dir: &Path, vmk: &[u8; 32]) -> Result<Vec<u8>> {
    let path = db_path(vault_dir);
    let vault_id = read_vault_uuid_from_dir(vault_dir)?;
    let key = derive_sqlcipher_key(vmk, vault_id.as_bytes());
    let src = open_connection(&path, &key, false)?;
    src.execute_batch("PRAGMA wal_checkpoint(FULL);")
        .map_err(|e| CoreError::io(e.to_string()))?;

    let tmp = tempfile::NamedTempFile::new().map_err(|e| CoreError::io(e.to_string()))?;
    let mut dest = Connection::open(tmp.path()).map_err(|e| CoreError::io(e.to_string()))?;
    apply_cipher_key(&mut dest, &key)?;
    let backup = Backup::new(&src, &mut dest).map_err(|e| CoreError::io(e.to_string()))?;
    backup
        .run_to_completion(100, Duration::from_millis(50), None)
        .map_err(|e| CoreError::io(e.to_string()))?;

    let bytes = fs::read(tmp.path()).map_err(|e| CoreError::io(e.to_string()))?;
    if bytes.len() as u64 > MAX_OVB_FILE_BYTES {
        return Err(CoreError::limit("database export"));
    }
    Ok(bytes)
}

pub fn import_database_bytes(vault_dir: &Path, vmk: &[u8; 32], bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_OVB_FILE_BYTES {
        return Err(CoreError::limit("database import"));
    }
    let path = db_path(vault_dir);
    if path.exists() {
        return Err(CoreError::format("vault.db exists"));
    }
    let vault_id = read_vault_uuid_from_dir(vault_dir)?;
    let key = derive_sqlcipher_key(vmk, vault_id.as_bytes());
    fs::write(&path, bytes).map_err(|e| CoreError::io(e.to_string()))?;
    let _conn = open_connection(&path, &key, false)?;
    verify_database(vault_dir, vmk)?;
    Ok(())
}

/// M1-5 审计：列出 SQLCipher 可能产生的旁路文件（须与 vault.db 同目录）。
pub fn sqlcipher_sidecar_paths(vault_dir: &Path) -> Vec<PathBuf> {
    let base = db_path(vault_dir);
    [
        PathBuf::from(format!("{}-wal", base.display())),
        PathBuf::from(format!("{}-shm", base.display())),
        PathBuf::from(format!("{}-journal", base.display())),
    ]
    .into_iter()
    .collect()
}
