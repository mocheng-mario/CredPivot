use crate::error::{CoreError, Result};
use crate::repo::{new_revision, now_ms};
use rusqlite::{params, Connection};
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerProfileRow {
    pub id: String,
    pub item_id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub manual_username: String,
    pub linked_login_id: Option<String>,
    pub linked_totp_id: Option<String>,
    pub linked_ssh_key_id: Option<String>,
    pub group_id: Option<String>,
    pub current_revision: String,
    pub updated_at_ms: i64,
}

pub fn list_server_profiles(conn: &Connection) -> Result<Vec<ServerProfileRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.id, s.item_id, s.label, s.host, s.port, s.manual_username, s.linked_login_id, s.linked_totp_id,
                    s.linked_ssh_key_id, i.group_id, s.current_revision, s.updated_at_ms
             FROM server_login_profiles s
             INNER JOIN items i ON i.id = s.item_id
             WHERE i.trashed = 0
             ORDER BY s.updated_at_ms DESC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(ServerProfileRow {
                id: row.get(0)?,
                item_id: row.get(1)?,
                label: row.get(2)?,
                host: row.get(3)?,
                port: row.get::<_, i64>(4)? as u16,
                manual_username: row.get(5)?,
                linked_login_id: row.get(6)?,
                linked_totp_id: row.get(7)?,
                linked_ssh_key_id: row.get(8)?,
                group_id: row.get(9)?,
                current_revision: row.get(10)?,
                updated_at_ms: row.get(11)?,
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    Ok(out)
}

pub fn insert_server_profile(
    conn: &Connection,
    label: &str,
    host: &str,
    port: u16,
    manual_username: &str,
    linked_login_id: Option<&str>,
    linked_totp_id: Option<&str>,
    linked_ssh_key_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<ServerProfileRow> {
    let item_id = Uuid::new_v4().to_string();
    let id = Uuid::new_v4().to_string();
    let revision = new_revision();
    let ts = now_ms();
    let title = format!("{label} ({host}:{port})");
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    if let Some(key_id) = linked_ssh_key_id {
        // 下拉选项可能已过期，不能把服务器重新关联到已删除的密钥。
        crate::repo_m2::load_ssh_key_by_id(&tx, key_id)?;
    }
    tx.execute(
        "INSERT INTO items (id, kind, title, trashed, group_id, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, 'server_login', ?2, 0, ?3, ?4, ?5, ?5)",
        params![item_id, title, group_id, revision, ts],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO server_login_profiles (id, item_id, label, host, port, manual_username, linked_login_id, linked_totp_id,
         linked_ssh_key_id, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
        params![
            id,
            item_id,
            label,
            host,
            port as i64,
            manual_username,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            revision,
            ts
        ],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(ServerProfileRow {
        id,
        item_id,
        label: label.to_string(),
        host: host.to_string(),
        port,
        manual_username: manual_username.to_string(),
        linked_login_id: linked_login_id.map(|s| s.to_string()),
        linked_totp_id: linked_totp_id.map(|s| s.to_string()),
        linked_ssh_key_id: linked_ssh_key_id.map(|s| s.to_string()),
        group_id: group_id.map(|s| s.to_string()),
        current_revision: revision,
        updated_at_ms: ts,
    })
}

pub fn update_server_profile(
    conn: &Connection,
    id: &str,
    expected_revision: &str,
    label: &str,
    host: &str,
    port: u16,
    manual_username: &str,
    linked_login_id: Option<&str>,
    linked_totp_id: Option<&str>,
    linked_ssh_key_id: Option<&str>,
    group_id: Option<&str>,
) -> Result<ServerProfileRow> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    if let Some(key_id) = linked_ssh_key_id {
        crate::repo_m2::load_ssh_key_by_id(&tx, key_id)?;
    }
    let (item_id, current_rev): (String, String) = tx
        .query_row(
            "SELECT s.item_id, s.current_revision FROM server_login_profiles s
             INNER JOIN items i ON i.id = s.item_id
             WHERE s.id = ?1 AND i.trashed = 0",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| CoreError::format("server profile not found"))?;
    if current_rev != expected_revision {
        return Err(CoreError::Conflict);
    }
    let revision = new_revision();
    let ts = now_ms();
    let title = format!("{label} ({host}:{port})");
    tx.execute(
        "UPDATE server_login_profiles SET label = ?1, host = ?2, port = ?3, manual_username = ?4, linked_login_id = ?5,
         linked_totp_id = ?6, linked_ssh_key_id = ?7, current_revision = ?8, updated_at_ms = ?9
         WHERE id = ?10",
        params![
            label,
            host,
            port as i64,
            manual_username,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            revision,
            ts,
            id
        ],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "UPDATE items SET title = ?1, group_id = ?2, current_revision = ?3, updated_at_ms = ?4 WHERE id = ?5",
        params![title, group_id, revision, ts, item_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    list_server_profiles(conn)?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| CoreError::format("server profile not found"))
}
