use crate::error::{CoreError, Result};
use crate::repo::{new_revision, now_ms};
use rusqlite::{params, Connection, OptionalExtension};
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
    #[serde(default)]
    pub unavailable: bool,
    #[serde(default)]
    pub unavailable_reason: String,
    #[serde(default)]
    pub stale_linked_login_id: Option<String>,
    #[serde(default)]
    pub stale_linked_totp_id: Option<String>,
    #[serde(default)]
    pub stale_linked_ssh_key_id: Option<String>,
    #[serde(default)]
    pub has_manual_secret: bool,
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
                unavailable: false,
                unavailable_reason: String::new(),
                stale_linked_login_id: None,
                stale_linked_totp_id: None,
                stale_linked_ssh_key_id: None,
                has_manual_secret: false,
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    if crate::associations::stale_ready(conn)? {
        for row in &mut out {
            let stale: Option<(i64, String, Option<String>, Option<String>, Option<String>)> = conn.query_row(
                "SELECT unavailable, unavailable_reason, linked_login_id, linked_totp_id, linked_ssh_key_id FROM server_stale_auth WHERE profile_id=?1",
                [&row.id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).optional()
                .map_err(|e| CoreError::format(e.to_string()))?;
            if let Some((unavailable, reason, login, totp, ssh)) = stale {
                row.unavailable = unavailable != 0;
                row.unavailable_reason = reason;
                row.stale_linked_login_id = login;
                row.stale_linked_totp_id = totp;
                row.stale_linked_ssh_key_id = ssh;
            }
            if let Ok(has_secret) = conn.query_row("SELECT length(manual_secret)>0 FROM server_login_profiles WHERE id=?1", [&row.id], |r| r.get::<_, i64>(0)) {
                row.has_manual_secret = has_secret != 0;
            }
        }
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
    manual_secret: Option<&str>,
) -> Result<ServerProfileRow> {
    insert_server_profile_in_partition(conn, crate::partitions::PERSONAL, label, host, port, manual_username, linked_login_id, linked_totp_id, linked_ssh_key_id, group_id, manual_secret)
}

pub fn insert_server_profile_in_partition(
    conn: &Connection,
    partition_id: &str,
    label: &str,
    host: &str,
    port: u16,
    manual_username: &str,
    linked_login_id: Option<&str>,
    linked_totp_id: Option<&str>,
    linked_ssh_key_id: Option<&str>,
    group_id: Option<&str>,
    manual_secret: Option<&str>,
) -> Result<ServerProfileRow> {
    crate::partitions::require(conn, partition_id)?;
    let item_id = Uuid::new_v4().to_string();
    let id = Uuid::new_v4().to_string();
    let revision = new_revision();
    let ts = now_ms();
    let title = format!("{label} ({host}:{port})");
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    let (stored_user, stored_secret) = checked_auth(&tx, partition_id, manual_username, manual_secret, linked_login_id, linked_totp_id, linked_ssh_key_id)?;
    tx.execute(
        "INSERT INTO items (id, kind, title, trashed, group_id, current_revision, created_at_ms, updated_at_ms, partition_id)
         VALUES (?1, 'server_login', ?2, 0, ?3, ?4, ?5, ?5, ?6)",
        params![item_id, title, group_id, revision, ts, partition_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO server_login_profiles (id, item_id, label, host, port, manual_username, linked_login_id, linked_totp_id,
         linked_ssh_key_id, manual_secret, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)",
        params![
            id,
            item_id,
            label,
            host,
            port as i64,
            stored_user,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            stored_secret,
            revision,
            ts
        ],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    crate::mark_restore_dirty(&tx)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(ServerProfileRow {
        id,
        item_id,
        label: label.to_string(),
        host: host.to_string(),
        port,
        manual_username: stored_user,
        linked_login_id: linked_login_id.map(|s| s.to_string()),
        linked_totp_id: linked_totp_id.map(|s| s.to_string()),
        linked_ssh_key_id: linked_ssh_key_id.map(|s| s.to_string()),
        group_id: group_id.map(|s| s.to_string()),
        current_revision: revision,
        updated_at_ms: ts,
        unavailable: false,
        unavailable_reason: String::new(),
        stale_linked_login_id: None,
        stale_linked_totp_id: None,
        stale_linked_ssh_key_id: None,
        has_manual_secret: false,
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
    manual_secret: Option<&str>,
) -> Result<ServerProfileRow> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    let (item_id, current_rev, partition_id, existing_secret): (String, String, String, String) = tx
        .query_row(
            "SELECT s.item_id, s.current_revision, i.partition_id, s.manual_secret FROM server_login_profiles s
             INNER JOIN items i ON i.id = s.item_id
             WHERE s.id = ?1 AND i.trashed = 0",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| CoreError::format("server profile not found"))?;
    if current_rev != expected_revision {
        return Err(CoreError::Conflict);
    }
    let secret = manual_secret.or(if existing_secret.is_empty() { None } else { Some(existing_secret.as_str()) });
    let (stored_user, stored_secret) = checked_auth(&tx, &partition_id, manual_username, secret, linked_login_id, linked_totp_id, linked_ssh_key_id)?;
    let revision = new_revision();
    let ts = now_ms();
    let title = format!("{label} ({host}:{port})");
    tx.execute(
        "UPDATE server_login_profiles SET label = ?1, host = ?2, port = ?3, manual_username = ?4, linked_login_id = ?5,
         linked_totp_id = ?6, linked_ssh_key_id = ?7, manual_secret = ?8, current_revision = ?9, updated_at_ms = ?10
         WHERE id = ?11",
        params![
            label,
            host,
            port as i64,
            stored_user,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            stored_secret,
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
    crate::associations::clear_unavailable(&tx, id)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    list_server_profiles(conn)?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| CoreError::format("server profile not found"))
}

fn checked_auth(
    conn: &rusqlite::Connection,
    partition: &str,
    manual_username: &str,
    manual_secret: Option<&str>,
    login_id: Option<&str>,
    totp_id: Option<&str>,
    ssh_id: Option<&str>,
) -> Result<(String, String)> {
    if let Some(login_id) = login_id.filter(|id| !id.is_empty()) {
        let (item, username, secret, login_partition): (String, String, String, String) = conn.query_row(
            "SELECT c.item_id, c.username, c.secret, i.partition_id FROM login_credentials c JOIN items i ON i.id=c.item_id WHERE c.id=?1 AND i.trashed=0",
            [login_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).map_err(|_| CoreError::format("关联账户已不存在"))?;
        if login_partition != partition { return Err(CoreError::format("关联账户必须与连接位于同一分区")); }
        if username.trim().is_empty() { return Err(CoreError::format("关联账户的用户名为空，不能保存")); }
        if secret.trim().is_empty() { return Err(CoreError::format("关联账户的密码为空，不能保存")); }
        if let Some(totp_id) = totp_id.filter(|id| !id.is_empty()) {
            if !crate::associations::mfa_credential_ids(conn, &item)?.iter().any(|id| id == totp_id) {
                return Err(CoreError::format("所选 MFA 不属于该账户"));
            }
        }
        if let Some(ssh_id) = ssh_id.filter(|id| !id.is_empty()) {
            if !crate::associations::ssh_key_ids(conn, &item)?.iter().any(|id| id == ssh_id) {
                return Err(CoreError::format("所选 SSH 密钥不属于该账户"));
            }
        }
        return Ok((String::new(), String::new()));
    }
    if manual_username.trim().is_empty() { return Err(CoreError::format("请填写连接自己的用户名")); }
    let secret = manual_secret.unwrap_or("");
    if secret.trim().is_empty() { return Err(CoreError::format("请填写连接自己的密码")); }
    if let Some(totp_id) = totp_id.filter(|id| !id.is_empty()) {
        let same = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM totp_credentials t JOIN items i ON i.id=t.item_id WHERE t.id=?1 AND i.trashed=0 AND i.partition_id=?2)",
            params![totp_id, partition], |row| row.get::<_, bool>(0)).unwrap_or(false);
        if !same { return Err(CoreError::format("所选 MFA 必须位于同一分区")); }
    }
    if let Some(ssh_id) = ssh_id.filter(|id| !id.is_empty()) {
        crate::repo_m2::load_ssh_key_by_id(conn, ssh_id)?;
        let same = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM ssh_keys s JOIN items i ON i.id=s.item_id WHERE s.id=?1 AND i.partition_id=?2)",
            params![ssh_id, partition], |row| row.get::<_, bool>(0)).unwrap_or(false);
        if !same { return Err(CoreError::format("所选 SSH 密钥必须位于同一分区")); }
    }
    Ok((manual_username.trim().to_string(), secret.to_string()))
}

/// 读取连接是否停用，以及独立模式下自己保存的密码。密码只交给调用方，不写入日志。
pub fn connection_auth(conn: &Connection, profile_id: &str) -> Result<(bool, String, bool)> {
    let secret: String = conn.query_row(
        "SELECT manual_secret FROM server_login_profiles WHERE id=?1",
        [profile_id],
        |row| row.get(0),
    ).map_err(|_| CoreError::format("连接不存在"))?;
    let unavailable = if crate::associations::stale_ready(conn)? {
        conn.query_row(
            "SELECT unavailable FROM server_stale_auth WHERE profile_id=?1",
            [profile_id],
            |row| row.get::<_, i64>(0),
        ).optional().map_err(|e| CoreError::format(e.to_string()))?.unwrap_or(0) != 0
    } else { false };
    let has_login: bool = conn.query_row(
        "SELECT linked_login_id IS NOT NULL AND linked_login_id<>'' FROM server_login_profiles WHERE id=?1",
        [profile_id],
        |row| row.get(0),
    ).unwrap_or(false);
    Ok((unavailable, if has_login { String::new() } else { secret }, has_login))
}
