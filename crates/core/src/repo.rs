use crate::error::{CoreError, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCredentialSummary {
    pub id: String,
    pub item_id: String,
    pub origin: String,
    pub username: String,
    pub linked_totp_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LoginCredentialRecord {
    pub id: String,
    pub item_id: String,
    pub origin: String,
    pub username: String,
    pub password: String,
    pub current_revision: String,
    pub linked_totp_id: Option<String>,
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn new_revision() -> String {
    Uuid::new_v4().to_string()
}

/// M2-2：新建 Item + Login（在已有连接/事务上执行）。
pub fn insert_login_credential(
    conn: &Connection,
    origin: &str,
    username: &str,
    password: &str,
) -> Result<LoginCredentialRecord> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rec = insert_login_credential_in_tx(&tx, origin, username, password)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(rec)
}

pub fn insert_login_credential_in_tx(
    conn: &Connection,
    origin: &str,
    username: &str,
    password: &str,
) -> Result<LoginCredentialRecord> {
    let item_id = Uuid::new_v4().to_string();
    let cred_id = Uuid::new_v4().to_string();
    let revision = new_revision();
    let ts = now_ms();
    let title = format!("{origin} ({username})");

    conn.execute(
        "INSERT INTO items (id, kind, title, trashed, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, 'login', ?2, 0, ?3, ?4, ?4)",
        params![item_id, title, revision, ts],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    conn.execute(
        "INSERT INTO login_credentials (id, item_id, origin, username, secret, current_revision, created_at_ms, updated_at_ms, password_active_since_ms, active_password_revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 0, ?6)",
        params![cred_id, item_id, origin, username, password, revision, ts],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;

    Ok(LoginCredentialRecord {
        id: cred_id,
        item_id,
        origin: origin.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        current_revision: revision,
        linked_totp_id: None,
    })
}

pub fn list_login_by_origin(conn: &Connection, origin: &str) -> Result<Vec<LoginCredentialSummary>> {
    let mut stmt = conn
        .prepare(
            "SELECT c.id, c.item_id, c.origin, c.username, c.linked_totp_id
             FROM login_credentials c
             INNER JOIN items i ON i.id = c.item_id
             WHERE c.origin = ?1 AND i.trashed = 0
             ORDER BY c.updated_at_ms DESC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rows = stmt
        .query_map(params![origin], |row| {
            Ok(LoginCredentialSummary {
                id: row.get(0)?,
                item_id: row.get(1)?,
                origin: row.get(2)?,
                username: row.get(3)?,
                linked_totp_id: row.get(4)?,
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    Ok(out)
}

pub fn get_login_secret(conn: &Connection, credential_id: &str) -> Result<LoginCredentialRecord> {
    conn.query_row(
        "SELECT c.id, c.item_id, c.origin, c.username, c.secret, c.current_revision, c.linked_totp_id
         FROM login_credentials c
         INNER JOIN items i ON i.id = c.item_id
         WHERE c.id = ?1 AND i.trashed = 0",
        params![credential_id],
        |row| {
            Ok(LoginCredentialRecord {
                id: row.get(0)?,
                item_id: row.get(1)?,
                origin: row.get(2)?,
                username: row.get(3)?,
                password: row.get(4)?,
                current_revision: row.get(5)?,
                linked_totp_id: row.get(6)?,
            })
        },
    )
    .map_err(|_| CoreError::format("credential not found"))
}

pub fn count_login_credentials(conn: &Connection) -> Result<u64> {
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM login_credentials c
             INNER JOIN items i ON i.id = c.item_id WHERE i.trashed = 0",
            [],
            |row| row.get(0),
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    Ok(n as u64)
}
