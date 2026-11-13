use crate::error::{CoreError, Result};
use crate::repo::{new_revision, now_ms};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

pub const PASSWORD_STALE_DAYS: i64 = 90;
const MS_PER_DAY: i64 = 86_400_000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoginListRow {
    pub id: String,
    pub item_id: String,
    pub title: String,
    pub display_name: String,
    pub origin: String,
    pub username: String,
    pub connection_host: String,
    pub linked_totp_id: Option<String>,
    pub group_id: Option<String>,
    pub current_revision: String,
    pub updated_at_ms: i64,
    pub password_active_since_ms: i64,
    #[serde(default)]
    pub linked_mfa_ids: Vec<String>,
    #[serde(default)]
    pub linked_ssh_key_ids: Vec<String>,
}

const LOGIN_LIST_SELECT: &str = "SELECT c.id, c.item_id, i.title, c.display_name, c.origin, c.username, c.connection_host,
                 c.linked_totp_id, i.group_id, c.current_revision, c.updated_at_ms, c.password_active_since_ms";

#[derive(Debug, Clone, serde::Serialize)]
pub struct SecuritySummary {
    pub login_count: u64,
    pub totp_count: u64,
    pub ssh_key_count: u64,
    pub recovery_code_count: u64,
    pub passwords_stale_90d: u64,
    pub trashed_count: u64,
}

pub fn list_logins(conn: &Connection, query: Option<&str>, limit: u32) -> Result<Vec<LoginListRow>> {
    list_logins_page(conn, query, limit, 0)
}

pub fn list_logins_page(conn: &Connection, query: Option<&str>, limit: u32, offset: u32) -> Result<Vec<LoginListRow>> {
    list_logins_page_in_partition(conn,query,limit,offset,None)
}

pub fn list_logins_page_in_partition(conn: &Connection, query: Option<&str>, limit: u32, offset: u32, partition: Option<&str>) -> Result<Vec<LoginListRow>> {
    let lim = limit.clamp(1, 500);
    let q = query.map(|s| s.trim()).filter(|s| !s.is_empty());
    let mut out = Vec::new();
    if let Some(qs) = q {
        let pattern = format!("%{qs}%");
        let mut stmt = conn
            .prepare(
                &format!(
                    "{LOGIN_LIST_SELECT}
                 FROM login_credentials c
                 INNER JOIN items i ON i.id = c.item_id
                 WHERE i.trashed = 0 AND (?4 IS NULL OR i.partition_id=?4) AND (i.title LIKE ?1 OR c.display_name LIKE ?1 OR c.origin LIKE ?1 OR c.username LIKE ?1
                   OR EXISTS (SELECT 1 FROM json_each(i.details_json, '$.uris') AS rule WHERE json_extract(rule.value, '$.uri') LIKE ?1))
                 ORDER BY c.updated_at_ms DESC, c.id ASC LIMIT ?2 OFFSET ?3"
                ),
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
        let rows = stmt
            .query_map(params![pattern, lim, offset, partition], map_login_row)
            .map_err(|e| CoreError::format(e.to_string()))?;
        for r in rows {
            out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
        }
    } else {
        let mut stmt = conn
            .prepare(
                &format!(
                    "{LOGIN_LIST_SELECT}
                 FROM login_credentials c
                 INNER JOIN items i ON i.id = c.item_id
                 WHERE i.trashed = 0 AND (?3 IS NULL OR i.partition_id=?3)
                 ORDER BY c.updated_at_ms DESC, c.id ASC LIMIT ?1 OFFSET ?2"
                ),
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
        let rows = stmt
            .query_map(params![lim, offset, partition], map_login_row)
            .map_err(|e| CoreError::format(e.to_string()))?;
        for r in rows {
            out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
        }
    }
    attach_login_links(conn, &mut out)?;
    Ok(out)
}

/// 按 ID 读取写入结果，避免受列表分页和相同更新时间的排序影响。
pub(crate) fn get_login_row(conn: &Connection, credential_id: &str) -> Result<LoginListRow> {
    let mut row = conn.query_row(
        &format!(
            "{LOGIN_LIST_SELECT}
             FROM login_credentials c
             INNER JOIN items i ON i.id = c.item_id
             WHERE c.id = ?1 AND i.trashed = 0"
        ),
        params![credential_id],
        map_login_row,
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    attach_login_links(conn, std::slice::from_mut(&mut row))?;
    Ok(row)
}

fn map_login_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LoginListRow> {
    Ok(LoginListRow {
        id: row.get(0)?,
        item_id: row.get(1)?,
        title: row.get(2)?,
        display_name: row.get(3)?,
        origin: row.get(4)?,
        username: row.get(5)?,
        connection_host: row.get(6)?,
        linked_totp_id: row.get(7)?,
        group_id: row.get(8)?,
        current_revision: row.get(9)?,
        updated_at_ms: row.get(10)?,
        password_active_since_ms: row.get(11)?,
        linked_mfa_ids: Vec::new(),
        linked_ssh_key_ids: Vec::new(),
    })
}

fn attach_login_links(conn: &Connection, rows: &mut [LoginListRow]) -> Result<()> {
    for row in rows {
        row.linked_mfa_ids = crate::associations::mfa_credential_ids(conn, &row.item_id)?;
        row.linked_ssh_key_ids = crate::associations::ssh_key_ids(conn, &row.item_id)?;
    }
    Ok(())
}

fn login_item_title(display_name: &str, origin: &str, username: &str) -> String {
    let dn = display_name.trim();
    if !dn.is_empty() {
        dn.to_string()
    } else {
        format!("{origin} ({username})")
    }
}

/// 新建登录项（含显示名、分组、堡垒机关联字段）。
pub fn insert_login_extended(
    conn: &Connection,
    origin: &str,
    username: &str,
    password: &str,
    display_name: &str,
    connection_host: &str,
    linked_totp_id: Option<&str>,
    group_id: Option<&str>,
    website_rules: Option<&[crate::UriRule]>,
    linked_mfa_ids: Option<&[String]>,
    password_active_since_ms: Option<i64>,
) -> Result<LoginListRow> {
    insert_login_extended_in_partition(conn, crate::partitions::PERSONAL, origin, username, password, display_name, connection_host, linked_totp_id, group_id, website_rules, linked_mfa_ids, password_active_since_ms, None, None)
}

pub fn insert_login_extended_in_partition(
    conn: &Connection,
    partition_id: &str,
    origin: &str,
    username: &str,
    password: &str,
    display_name: &str,
    connection_host: &str,
    linked_totp_id: Option<&str>,
    group_id: Option<&str>,
    website_rules: Option<&[crate::UriRule]>,
    linked_mfa_ids: Option<&[String]>,
    password_active_since_ms: Option<i64>,
    linked_ssh_key_ids: Option<&[String]>,
    linked_passkey_ids: Option<&[String]>,
) -> Result<LoginListRow> {
    crate::partitions::require(conn, partition_id)?;
    let item_id = Uuid::new_v4().to_string();
    let cred_id = Uuid::new_v4().to_string();
    let revision = new_revision();
    let ts = now_ms();
    let since = password_active_since_ms.unwrap_or(ts);
    crate::credential_management::validate_password_active_since(since)?;
    let title = login_item_title(display_name, origin, username);
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO items (id, kind, title, trashed, group_id, current_revision, created_at_ms, updated_at_ms, partition_id)
         VALUES (?1, 'login', ?2, 0, ?3, ?4, ?5, ?5, ?6)",
        params![item_id, title, group_id, revision, ts, partition_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO login_credentials (id, item_id, origin, username, secret, display_name, connection_host, linked_totp_id,
         current_revision, created_at_ms, updated_at_ms, password_active_since_ms, active_password_revision)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11, ?9)",
        params![
            cred_id,
            item_id,
            origin,
            username,
            password,
            display_name.trim(),
            connection_host.trim(),
            None::<&str>,
            revision,
            ts,
            since
        ],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    if let Some(rules) = website_rules { crate::website_rules::save_login_website_rules(&tx, &item_id, rules)?; }
    if let Some(ids) = linked_mfa_ids {
        crate::website_rules::save_linked_mfas(&tx, &item_id, ids)?;
    } else if let Some(id) = linked_totp_id {
        crate::website_rules::save_linked_mfas(&tx, &item_id, &[id.to_string()])?;
    }
    if let Some(ids) = linked_ssh_key_ids {
        crate::associations::replace_ssh_keys(&tx, &item_id, ids)?;
    }
    if let Some(ids) = linked_passkey_ids {
        crate::associations::replace_passkeys(&tx, &item_id, ids)?;
    }

    let row = get_login_row(&tx, &cred_id)?;
    crate::mark_restore_dirty(&tx)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(row)
}

/// 更新登录凭据；`expected_revision` 不匹配时返回 Conflict。
pub fn update_login_credential(
    conn: &Connection,
    credential_id: &str,
    expected_revision: &str,
    origin: &str,
    username: &str,
    display_name: &str,
    connection_host: &str,
    linked_totp_id: Option<&str>,
    group_id: Option<&str>,
    new_password: Option<&str>,
    website_rules: Option<&[crate::UriRule]>,
) -> Result<LoginListRow> {
    update_login_with_mfa(conn, credential_id, expected_revision, origin, username, display_name, connection_host, linked_totp_id, group_id, new_password, website_rules, None, None, None)
}

pub(crate) fn update_login_with_mfa(
    conn: &Connection,
    credential_id: &str,
    expected_revision: &str,
    origin: &str,
    username: &str,
    display_name: &str,
    connection_host: &str,
    linked_totp_id: Option<&str>,
    group_id: Option<&str>,
    new_password: Option<&str>,
    website_rules: Option<&[crate::UriRule]>,
    linked_mfa_ids: Option<&[String]>,
    linked_ssh_key_ids: Option<&[String]>,
    linked_passkey_ids: Option<&[String]>,
) -> Result<LoginListRow> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    let (item_id, current_rev, old_secret, old_username): (String, String, String, String) = tx
        .query_row(
            "SELECT c.item_id, c.current_revision, c.secret, c.username
             FROM login_credentials c
             INNER JOIN items i ON i.id = c.item_id
             WHERE c.id = ?1 AND i.trashed = 0",
            params![credential_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| CoreError::format("credential not found"))?;
    if current_rev != expected_revision {
        return Err(CoreError::Conflict);
    }
    let revision = new_revision();
    let ts = now_ms();
    let title = login_item_title(display_name, origin, username);

    // 改密先保存候选；用户确认已在网站应用后，才替换当前可填充密码。
    if let Some(pw) = new_password {
        if pw != old_secret { crate::credential_management::create_candidate(&tx, credential_id, expected_revision, pw)?; }
    }
    tx.execute(
        "UPDATE login_credentials SET origin=?1, username=?2, display_name=?3, connection_host=?4,
         linked_totp_id=NULL, current_revision=?5, updated_at_ms=?6 WHERE id=?7",
        params![origin,username,display_name.trim(),connection_host.trim(),revision,ts,credential_id],
    )?;
    tx.execute(
        "UPDATE items SET title = ?1, group_id = ?2, current_revision = ?3, updated_at_ms = ?4 WHERE id = ?5",
        params![title, group_id, revision, ts, item_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    if let Some(rules) = website_rules { crate::website_rules::save_login_website_rules(&tx, &item_id, rules)?; }
    if let Some(ids) = linked_mfa_ids {
        crate::website_rules::save_linked_mfas(&tx, &item_id, ids)?;
    } else if let Some(id) = linked_totp_id {
        crate::website_rules::save_linked_mfas(&tx, &item_id, &[id.to_string()])?;
    }
    crate::associations::note_username_cleared(&tx, credential_id, &old_username, username)?;
    if let Some(ids) = linked_ssh_key_ids {
        crate::associations::replace_ssh_keys(&tx, &item_id, ids)?;
    }
    if let Some(ids) = linked_passkey_ids {
        crate::associations::replace_passkeys(&tx, &item_id, ids)?;
    }

    let row = get_login_row(&tx, credential_id)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(row)
}

pub fn trash_item(conn: &Connection, item_id: &str) -> Result<()> {
    let tx = conn.unchecked_transaction().map_err(|e| CoreError::format(e.to_string()))?;
    trash_item_in_tx(&tx, item_id)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(())
}

pub(crate) fn trash_item_in_tx(conn: &Connection, item_id: &str) -> Result<()> {
    let ts = now_ms();
    let revision = new_revision();
    let ssh_key: Option<(String, bool)> = conn.query_row(
        "SELECT s.id, s.is_default FROM ssh_keys s INNER JOIN items i ON i.id = s.item_id
         WHERE s.item_id = ?1 AND i.trashed = 0",
        params![item_id],
        |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
    ).optional().map_err(|e| CoreError::format(e.to_string()))?;
    let kind: String = conn.query_row("SELECT kind FROM items WHERE id=?1 AND trashed=0", [item_id], |row| row.get(0))
        .map_err(|_| CoreError::format("item not found"))?;
    match kind.as_str() {
        "login" => {
            if let Some(id) = conn.query_row("SELECT id FROM login_credentials WHERE item_id=?1", [item_id], |row| row.get::<_, String>(0)).optional()? {
                crate::associations::disable_profiles_for_credential(conn, "linked_login_id", &id, "关联账户已删除")?;
            }
            crate::associations::snapshot_links(conn, item_id)?;
            crate::associations::delete_links_for_item(conn, item_id)?;
        }
        "totp" => {
            if let Some(id) = conn.query_row("SELECT id FROM totp_credentials WHERE item_id=?1", [item_id], |row| row.get::<_, String>(0)).optional()? {
                crate::associations::disable_profiles_for_credential(conn, "linked_totp_id", &id, "所选 MFA 已删除")?;
            }
            crate::associations::snapshot_links(conn, item_id)?;
            crate::associations::delete_links_for_item(conn, item_id)?;
            trash_mfa_recovery(conn, item_id)?;
        }
        "ssh_key" => {
            if let Some((key_id, _)) = &ssh_key {
                crate::associations::disable_profiles_for_credential(conn, "linked_ssh_key_id", key_id, "所选 SSH 密钥已删除")?;
            }
            crate::associations::snapshot_links(conn, item_id)?;
            crate::associations::delete_links_for_item(conn, item_id)?;
        }
        "passkey" => {
            crate::associations::snapshot_links(conn, item_id)?;
            crate::associations::delete_links_for_item(conn, item_id)?;
        }
        _ => {}
    }
    let n = conn
        .execute(
            "UPDATE items SET trashed = 1, trashed_at_ms = ?2, current_revision = ?1, updated_at_ms = ?2 WHERE id = ?3 AND trashed = 0",
            params![revision, ts, item_id],
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    if n == 0 {
        return Err(CoreError::format("item not found"));
    }
    if let Some((key_id, was_default)) = ssh_key {
        conn.execute("UPDATE ssh_keys SET is_default = 0 WHERE id = ?1", params![key_id])
            .map_err(|e| CoreError::format(e.to_string()))?;
        if was_default {
            // 不生成替代密钥；有剩余密钥时沿用最近的一把，没有时允许空列表。
            conn.execute(
                "UPDATE ssh_keys SET is_default = 1 WHERE id = (
                   SELECT s.id FROM ssh_keys s INNER JOIN items i ON i.id = s.item_id
                   WHERE i.trashed = 0 ORDER BY s.updated_at_ms DESC, s.id LIMIT 1)", [],
            ).map_err(|e| CoreError::format(e.to_string()))?;
        }
    }
    crate::website_rules::detach_mfa_references(conn,item_id)?;
    crate::restore_point::mark_restore_dirty(conn)?;
    Ok(())
}

fn trash_mfa_recovery(conn: &Connection, totp_item: &str) -> Result<()> {
    crate::schema::ensure_runtime_extras(conn)?;
    let mut statement = conn.prepare(
        "SELECT r.item_id FROM recovery_code_items r JOIN items i ON i.id=r.item_id WHERE r.mfa_item_id=?1 AND i.trashed=0",
    )?;
    let ids = statement.query_map([totp_item], |row| row.get::<_, String>(0))?;
    let ids = ids.collect::<std::result::Result<Vec<_>, _>>()?;
    for id in ids {
        trash_item_in_tx(conn, &id)?;
    }
    Ok(())
}

pub(crate) fn restore_mfa_recovery(conn: &Connection, totp_item: &str) -> Result<()> {
    crate::schema::ensure_runtime_extras(conn)?;
    let revision = new_revision();
    let ts = now_ms();
    conn.execute(
        "UPDATE items SET trashed=0, trashed_at_ms=NULL, current_revision=?1, updated_at_ms=?2
         WHERE trashed=1 AND id IN (SELECT item_id FROM recovery_code_items WHERE mfa_item_id=?3)",
        params![revision, ts, totp_item],
    )?;
    conn.execute(
        "UPDATE recovery_code_items SET current_revision=?1, updated_at_ms=?2 WHERE mfa_item_id=?3",
        params![revision, ts, totp_item],
    )?;
    Ok(())
}

pub fn security_summary(conn: &Connection) -> Result<SecuritySummary> {
    let login_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM login_credentials c INNER JOIN items i ON i.id = c.item_id WHERE i.trashed = 0",
            [],
            |r| r.get(0),
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let totp_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM totp_credentials t INNER JOIN items i ON i.id = t.item_id WHERE i.trashed = 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let ssh_key_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM ssh_keys s INNER JOIN items i ON i.id = s.item_id WHERE i.trashed = 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let recovery_code_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM recovery_code_items r INNER JOIN items i ON i.id = r.item_id WHERE i.trashed = 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let trashed_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM items WHERE trashed = 1", [], |r| r.get(0))
        .map_err(|e| CoreError::format(e.to_string()))?;
    let cutoff = now_ms() - PASSWORD_STALE_DAYS * MS_PER_DAY;
    let passwords_stale_90d: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM login_credentials c
             INNER JOIN items i ON i.id = c.item_id
             WHERE i.trashed = 0 AND c.password_active_since_ms > 0 AND c.password_active_since_ms < ?1",
            params![cutoff],
            |r| r.get(0),
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    Ok(SecuritySummary {
        login_count: login_count as u64,
        totp_count: totp_count as u64,
        ssh_key_count: ssh_key_count as u64,
        recovery_code_count: recovery_code_count as u64,
        passwords_stale_90d: passwords_stale_90d as u64,
        trashed_count: trashed_count as u64,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SshKeyRecord {
    pub id: String,
    pub item_id: String,
    pub label: String,
    pub public_openssh: String,
    pub seed: [u8; 32],
    pub is_default: bool,
}

pub fn ensure_default_ssh_key(conn: &Connection) -> Result<SshKeyRecord> {
    if let Some(existing) = load_default_ssh_key(conn)? {
        return Ok(existing);
    }
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut OsRng);
    let seed = signing.to_bytes();
    let vk = signing.verifying_key();
    let public = format_ssh_ed25519_openssh(vk.as_bytes(), "credpivot");
    insert_ssh_key(conn, "Default", &public, &seed, true, None)
}

pub fn insert_ssh_key(
    conn: &Connection,
    label: &str,
    public_openssh: &str,
    seed: &[u8; 32],
    is_default: bool,
    group_id: Option<&str>,
) -> Result<SshKeyRecord> {
    insert_ssh_key_in_partition(conn, crate::partitions::PERSONAL, label, public_openssh, seed, is_default, group_id)
}

pub fn insert_ssh_key_in_partition(
    conn: &Connection,
    partition_id: &str,
    label: &str,
    public_openssh: &str,
    seed: &[u8; 32],
    is_default: bool,
    group_id: Option<&str>,
) -> Result<SshKeyRecord> {
    insert_ssh_key_with_details(conn,partition_id,label,public_openssh,seed,is_default,group_id,"{}")
}

fn insert_ssh_key_with_details(
    conn: &Connection, partition_id: &str, label: &str, public_openssh: &str,
    seed: &[u8;32], is_default: bool, group_id: Option<&str>, details: &str,
) -> Result<SshKeyRecord> {
    crate::partitions::require(conn, partition_id)?;
    let item_id = Uuid::new_v4().to_string();
    let key_id = Uuid::new_v4().to_string();
    let revision = new_revision();
    let ts = now_ms();
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    if is_default {
        tx.execute(
            "UPDATE ssh_keys SET is_default = 0 WHERE is_default = 1",
            [],
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    }
    tx.execute(
        "INSERT INTO items (id, kind, title, trashed, group_id, current_revision, created_at_ms, updated_at_ms, partition_id, details_json)
         VALUES (?1, 'ssh_key', ?2, 0, ?3, ?4, ?5, ?5, ?6, ?7)",
        params![item_id, label, group_id, revision, ts, partition_id, details],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO ssh_keys (id, item_id, label, public_openssh, private_key_seed, is_default, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            key_id,
            item_id,
            label,
            public_openssh,
            seed.as_slice(),
            if is_default { 1 } else { 0 },
            revision,
            ts
        ],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    crate::mark_restore_dirty(&tx)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(SshKeyRecord {
        id: key_id,
        item_id,
        label: label.to_string(),
        public_openssh: public_openssh.to_string(),
        seed: *seed,
        is_default,
    })
}

pub fn load_ssh_key_by_id(conn: &Connection, key_id: &str) -> Result<SshKeyRecord> {
    conn.query_row(
        "SELECT s.id, s.item_id, s.label, s.public_openssh, s.private_key_seed, s.is_default
         FROM ssh_keys s INNER JOIN items i ON i.id = s.item_id
         WHERE s.id = ?1 AND i.trashed = 0",
        params![key_id],
        |row| {
            let seed_blob: Vec<u8> = row.get(4)?;
            if seed_blob.len() != 32 {
                return Err(rusqlite::Error::InvalidColumnType(
                    4,
                    "private_key_seed".into(),
                    rusqlite::types::Type::Blob,
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_blob);
            Ok(SshKeyRecord {
                id: row.get(0)?,
                item_id: row.get(1)?,
                label: row.get(2)?,
                public_openssh: row.get(3)?,
                seed,
                is_default: row.get::<_, i64>(5)? != 0,
            })
        },
    )
    .map_err(|_| CoreError::format("ssh key not found"))
}

pub fn load_default_ssh_key(conn: &Connection) -> Result<Option<SshKeyRecord>> {
    let row = conn.query_row(
        "SELECT s.id, s.item_id, s.label, s.public_openssh, s.private_key_seed, s.is_default
         FROM ssh_keys s INNER JOIN items i ON i.id = s.item_id
         WHERE i.trashed = 0 AND s.is_default = 1 LIMIT 1",
        [],
        |row| {
            let seed_blob: Vec<u8> = row.get(4)?;
            if seed_blob.len() != 32 {
                return Err(rusqlite::Error::InvalidColumnType(
                    4,
                    "private_key_seed".into(),
                    rusqlite::types::Type::Blob,
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_blob);
            Ok(SshKeyRecord {
                id: row.get(0)?,
                item_id: row.get(1)?,
                label: row.get(2)?,
                public_openssh: row.get(3)?,
                seed,
                is_default: row.get::<_, i64>(5)? != 0,
            })
        },
    );
    match row {
        Ok(r) => Ok(Some(r)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(CoreError::format(e.to_string())),
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TotpListRow {
    pub id: String,
    pub item_id: String,
    pub issuer: String,
    pub account: String,
    pub group_id: Option<String>,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub website_rules: Vec<crate::UriRule>,
    #[serde(default)]
    pub pending_rule_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TotpRevealRow {
    pub issuer: String,
    pub account: String,
    pub secret_base32: String,
    pub otpauth_uri: String,
    pub website_rules: Vec<crate::UriRule>,
    pub pending_website_rules: Vec<crate::UriRule>,
    pub current_revision: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshKeyListRow {
    pub id: String,
    pub item_id: String,
    pub label: String,
    pub public_openssh: String,
    pub is_default: bool,
    pub group_id: Option<String>,
}

pub fn list_totp_credentials(conn: &Connection) -> Result<Vec<TotpListRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.item_id, t.issuer, t.account, i.group_id, t.updated_at_ms, i.details_json
             FROM totp_credentials t
             INNER JOIN items i ON i.id = t.item_id
             WHERE i.trashed = 0
             ORDER BY t.updated_at_ms DESC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let raw: String = row.get(6)?;
            let details: crate::credential_management::ItemDetails = serde_json::from_str(&raw)
                .map_err(|e|rusqlite::Error::FromSqlConversionFailure(6,rusqlite::types::Type::Text,Box::new(e)))?;
            Ok(TotpListRow {
                id: row.get(0)?,
                item_id: row.get(1)?,
                issuer: row.get(2)?,
                account: row.get(3)?,
                group_id: row.get(4)?,
                updated_at_ms: row.get(5)?,
                website_rules: details.uris,
                pending_rule_count: details.pending_mfa_uris.len(),
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    Ok(out)
}

pub fn list_ssh_keys(conn: &Connection) -> Result<Vec<SshKeyListRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.id, s.item_id, s.label, s.public_openssh, s.is_default, i.group_id
             FROM ssh_keys s
             INNER JOIN items i ON i.id = s.item_id
             WHERE i.trashed = 0
             ORDER BY s.is_default DESC, s.updated_at_ms DESC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(SshKeyListRow {
                id: row.get(0)?,
                item_id: row.get(1)?,
                label: row.get(2)?,
                public_openssh: row.get(3)?,
                is_default: row.get::<_, i64>(4)? != 0,
                group_id: row.get(5)?,
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    Ok(out)
}

pub fn generate_ssh_key(
    conn: &Connection,
    label: &str,
    set_default: bool,
    group_id: Option<&str>,
) -> Result<SshKeyListRow> {
    generate_ssh_key_in_partition(conn, crate::partitions::PERSONAL, label, set_default, group_id)
}

pub fn generate_ssh_key_in_partition(
    conn: &Connection,
    partition_id: &str,
    label: &str,
    set_default: bool,
    group_id: Option<&str>,
) -> Result<SshKeyListRow> {
    generate_ssh_key_with_options_in_partition(conn,partition_id,label,set_default,group_id,"","",&[])
}

pub fn generate_ssh_key_with_options_in_partition(
    conn: &Connection, partition_id: &str, label: &str, set_default: bool,
    group_id: Option<&str>, comment: &str, sign_policy: &str, git_rules: &[String],
) -> Result<SshKeyListRow> {
    crate::partitions::require(conn, partition_id)?;
    let label=label.trim(); let comment=comment.trim();
    if label.is_empty() || label.len()>200 || label.chars().any(char::is_control) { return Err(CoreError::format("ssh.errors.name")); }
    if comment.chars().count()>256 || comment.chars().any(char::is_control) { return Err(CoreError::format("ssh.errors.comment")); }
    if !matches!(sign_policy,""|"session"|"confirm"|"biometric") { return Err(CoreError::format("ssh.errors.policy")); }
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut OsRng);
    let seed = zeroize::Zeroizing::new(signing.to_bytes());
    let vk = signing.verifying_key();
    let public = format_ssh_ed25519_openssh(vk.as_bytes(), if comment.is_empty() { "credpivot" } else { comment });
    let details=serde_json::to_string(&crate::credential_management::ItemDetails {
        ssh_sign_policy:sign_policy.into(), ssh_git_rules:crate::ssh_git::normalize_rules(git_rules)?, ..Default::default()
    }).map_err(|_|CoreError::format("ssh.errors.policy"))?;
    // 身份、分组和策略一起提交，不能在策略保存失败后留下已生成的半条记录。
    let rec = insert_ssh_key_with_details(conn, partition_id, label, &public, &seed, set_default, group_id, &details)?;
    Ok(SshKeyListRow {
        id: rec.id,
        item_id: rec.item_id,
        label: rec.label,
        public_openssh: rec.public_openssh,
        is_default: rec.is_default,
        group_id: group_id.map(|s| s.to_string()),
    })
}

fn ssh_ed25519_wire_blob(key_bytes: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::new();
    let type_name = b"ssh-ed25519";
    blob.extend_from_slice(&(type_name.len() as u32).to_be_bytes());
    blob.extend_from_slice(type_name);
    blob.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(key_bytes);
    blob
}

pub fn format_ssh_ed25519_openssh(key_bytes: &[u8; 32], comment: &str) -> String {
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        ssh_ed25519_wire_blob(key_bytes),
    );
    format!("ssh-ed25519 {b64} {comment}")
}

pub fn insert_totp(
    conn: &Connection,
    issuer: &str,
    account: &str,
    secret_base32: &str,
    group_id: Option<&str>,
) -> Result<String> {
    insert_totp_with_rules(conn,issuer,account,secret_base32,group_id,&[])
}

pub(crate) fn insert_totp_with_rules(
    conn: &Connection,
    issuer: &str,
    account: &str,
    secret_base32: &str,
    group_id: Option<&str>,
    website_rules: &[crate::UriRule],
) -> Result<String> {
    insert_totp_with_rules_in_partition(conn, crate::partitions::PERSONAL, issuer, account, secret_base32, group_id, website_rules)
}

pub fn insert_totp_with_rules_in_partition(
    conn: &Connection,
    partition_id: &str,
    issuer: &str,
    account: &str,
    secret_base32: &str,
    group_id: Option<&str>,
    website_rules: &[crate::UriRule],
) -> Result<String> {
    let tx = conn.unchecked_transaction()?;
    let id = insert_totp_with_rules_in_tx(&tx, partition_id, issuer, account, secret_base32, group_id, website_rules)?;
    tx.commit()?;
    Ok(id)
}

fn insert_totp_with_rules_in_tx(
    conn: &Connection, partition_id: &str, issuer: &str, account: &str, secret_base32: &str,
    group_id: Option<&str>, website_rules: &[crate::UriRule],
) -> Result<String> {
    crate::partitions::require(conn, partition_id)?;
    crate::website_rules::validate_website_rules(website_rules)?;
    let parsed = crate::totp::parse_totp_input(secret_base32)?;
    let issuer = if issuer.trim().is_empty() { parsed.issuer.as_str() } else { issuer.trim() };
    let account = if account.trim().is_empty() { parsed.account.as_str() } else { account.trim() };
    let params = crate::totp::totp_params_for_storage(secret_base32)?;
    let alg = crate::totp::algorithm_name(params.algorithm);
    let item_id = Uuid::new_v4().to_string();
    let totp_id = Uuid::new_v4().to_string();
    let revision = new_revision();
    let ts = now_ms();
    let title = format!("{issuer}:{account}");
    conn.execute(
        "INSERT INTO items (id, kind, title, trashed, group_id, current_revision, created_at_ms, updated_at_ms, partition_id)
         VALUES (?1, 'totp', ?2, 0, ?3, ?4, ?5, ?5, ?6)",
        params![item_id, title, group_id, revision, ts, partition_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    conn.execute(
        "INSERT INTO totp_credentials (id, item_id, issuer, account, secret_base32, totp_algorithm, totp_digits, totp_period,
         current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
        params![
            totp_id,
            item_id,
            issuer,
            account,
            params.secret_base32,
            alg,
            params.digits,
            params.period as i64,
            revision,
            ts
        ],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    let details = crate::credential_management::ItemDetails { uris:website_rules.to_vec(),otp_extra_parameters:parsed.extra_parameters,..Default::default() };
    conn.execute("UPDATE items SET details_json=?1 WHERE id=?2",params![serde_json::to_string(&details).map_err(|_|CoreError::format("MFA 详情编码失败"))?,item_id])?;
    crate::mark_restore_dirty(conn)?;
    Ok(totp_id)
}

/// 浏览器添加的 MFA 和账号关联必须一起提交，不能留下只创建了一半的记录。
pub fn insert_browser_totp(
    conn: &Connection, partition_id: &str, origin: &str, linked_login_id: &str,
    issuer: &str, account: &str, input: &str, website_rules: &[crate::UriRule],
) -> Result<String> {
    let page = url::Url::parse(origin).map_err(|_|CoreError::format("网站地址无效"))?;
    if !matches!(page.scheme(), "https" | "http") || page.host_str().is_none()
        || page.origin().ascii_serialization() != origin {
        return Err(CoreError::format("网站来源无效"));
    }
    let tx = conn.unchecked_transaction()?;
    let login = if linked_login_id.is_empty() { None } else {
        if !crate::website_rules::credential_matches_origin(&tx, linked_login_id, origin)? {
            return Err(CoreError::format("所选账密不属于当前网站"));
        }
        Some(get_login_row(&tx, linked_login_id)?)
    };
    let partition = match &login {
        Some(login) => crate::partitions::item_partition(&tx, &login.item_id)?,
        None => partition_id.to_string(),
    };
    let id = insert_totp_with_rules_in_tx(&tx, &partition, issuer, account, input, None, website_rules)?;
    if let Some(login) = login {
        let mut details = crate::credential_management::details_for(&tx, &login.item_id)?;
        if details.linked_mfa_ids.len() >= 100 { return Err(CoreError::limit("MFA 关联过多")); }
        details.linked_mfa_ids.push(id.clone());
        crate::website_rules::save_linked_mfas(&tx, &login.item_id, &details.linked_mfa_ids)?;
        let single = if details.linked_mfa_ids.len() == 1 { Some(id.as_str()) } else { None };
        let revision = new_revision();
        let timestamp = now_ms();
        tx.execute("UPDATE login_credentials SET linked_totp_id=COALESCE(linked_totp_id,?1),current_revision=?2,updated_at_ms=?3 WHERE id=?4",
            params![single,revision,timestamp,linked_login_id])?;
        tx.execute("UPDATE items SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",params![revision,timestamp,login.item_id])?;
    }
    tx.commit()?;
    Ok(id)
}

pub fn insert_totp_row(
    conn: &Connection,
    issuer: &str,
    account: &str,
    secret_base32: &str,
    group_id: Option<&str>,
) -> Result<TotpListRow> {
    let totp_id = insert_totp(conn, issuer, account, secret_base32, group_id)?;
    list_totp_credentials(conn)?
        .into_iter()
        .find(|r| r.id == totp_id)
        .ok_or_else(|| CoreError::format("totp not found after insert"))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryCodeRow {
    pub id: String,
    pub item_id: String,
    pub service_name: String,
    pub codes: Vec<String>,
    pub current_revision: String,
    pub updated_at_ms: i64,
}

pub fn insert_recovery_codes(
    conn: &Connection,
    service_name: &str,
    codes: &[String],
) -> Result<RecoveryCodeRow> {
    insert_recovery_codes_in_partition(conn, crate::partitions::PERSONAL, service_name, codes)
}

pub fn insert_recovery_codes_in_partition(
    conn: &Connection,
    partition_id: &str,
    service_name: &str,
    codes: &[String],
) -> Result<RecoveryCodeRow> {
    crate::partitions::require(conn, partition_id)?;
    if service_name.trim().is_empty() {
        return Err(CoreError::format("service_name required"));
    }
    let cleaned: Vec<String> = codes
        .iter()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Err(CoreError::format("at least one recovery code required"));
    }
    let item_id = Uuid::new_v4().to_string();
    let rec_id = Uuid::new_v4().to_string();
    let revision = new_revision();
    let ts = now_ms();
    let codes_json =
        serde_json::to_string(&cleaned).map_err(|e| CoreError::format(e.to_string()))?;
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO items (id, kind, title, trashed, current_revision, created_at_ms, updated_at_ms, partition_id)
         VALUES (?1, 'recovery_codes', ?2, 0, ?3, ?4, ?4, ?5)",
        params![item_id, service_name, revision, ts, partition_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO recovery_code_items (id, item_id, service_name, codes_json, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![rec_id, item_id, service_name, codes_json, revision, ts],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    crate::credential_management::sync_recovery_entries(&tx, &rec_id, &cleaned)?;
    crate::mark_restore_dirty(&tx)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(RecoveryCodeRow {
        id: rec_id,
        item_id,
        service_name: service_name.to_string(),
        codes: cleaned,
        current_revision: revision,
        updated_at_ms: ts,
    })
}

pub fn list_recovery_codes(conn: &Connection) -> Result<Vec<RecoveryCodeRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT r.id, r.item_id, r.service_name, r.codes_json, r.current_revision, r.updated_at_ms
             FROM recovery_code_items r
             INNER JOIN items i ON i.id = r.item_id
             WHERE i.trashed = 0
             ORDER BY r.updated_at_ms DESC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            let json: String = row.get(3)?;
            let codes: Vec<String> =
                serde_json::from_str(&json).map_err(|_| {
                    rusqlite::Error::InvalidColumnType(3, "codes_json".into(), rusqlite::types::Type::Text)
                })?;
            Ok(RecoveryCodeRow {
                id: row.get(0)?,
                item_id: row.get(1)?,
                service_name: row.get(2)?,
                codes,
                current_revision: row.get(4)?,
                updated_at_ms: row.get(5)?,
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    Ok(out)
}

pub fn mfa_recovery_status(conn: &Connection, totp_item: &str) -> Result<serde_json::Value> {
    crate::schema::ensure_runtime_extras(conn)?;
    let found: Option<(String, String, String)> = conn.query_row(
        "SELECT r.id, r.item_id, r.service_name FROM recovery_code_items r JOIN items i ON i.id=r.item_id WHERE r.mfa_item_id=?1 AND i.trashed=0",
        [totp_item],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional()?;
    let Some((id, item_id, service_name)) = found else {
        return Ok(serde_json::json!({"attached": false}));
    };
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM recovery_code_entries WHERE recovery_id=?1", [&id], |row| row.get(0))?;
    let remaining: i64 = conn.query_row("SELECT COUNT(*) FROM recovery_code_entries WHERE recovery_id=?1 AND used_at_ms IS NULL", [&id], |row| row.get(0))?;
    Ok(serde_json::json!({"attached": true, "id": id, "item_id": item_id, "service_name": service_name, "remaining": remaining, "total": total}))
}

pub fn save_mfa_recovery(conn: &Connection, totp_item: &str, codes: &[String]) -> Result<serde_json::Value> {
    crate::schema::ensure_runtime_extras(conn)?;
    let (partition, label): (String, String) = conn.query_row(
        "SELECT i.partition_id, t.issuer || ' · ' || t.account FROM totp_credentials t JOIN items i ON i.id=t.item_id WHERE t.item_id=?1 AND i.trashed=0",
        [totp_item],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| CoreError::format("MFA 不存在"))?;
    let cleaned: Vec<String> = codes.iter().map(|code| code.trim().to_string()).filter(|code| !code.is_empty()).collect();
    if cleaned.is_empty() || cleaned.len() > 100 || cleaned.iter().any(|code| code.chars().count() > 200) {
        return Err(CoreError::format("恢复码数量或长度无效"));
    }
    let existing: Option<(String, String)> = conn.query_row(
        "SELECT id, item_id FROM recovery_code_items WHERE mfa_item_id=?1",
        [totp_item],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let revision = new_revision();
    let ts = now_ms();
    let codes_json = serde_json::to_string(&cleaned).map_err(|e| CoreError::format(e.to_string()))?;
    let (recovery_id, item_id) = if let Some((id, item_id)) = existing {
        conn.execute("UPDATE items SET title=?1, trashed=0, trashed_at_ms=NULL, current_revision=?2, updated_at_ms=?3 WHERE id=?4", params![label, revision, ts, item_id])?;
        conn.execute("UPDATE recovery_code_items SET service_name=?1, codes_json=?2, current_revision=?3, updated_at_ms=?4 WHERE id=?5", params![label, codes_json, revision, ts, id])?;
        crate::credential_management::sync_recovery_entries(conn, &id, &cleaned)?;
        (id, item_id)
    } else {
        let item_id = Uuid::new_v4().to_string();
        let recovery_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO items (id, kind, title, trashed, current_revision, created_at_ms, updated_at_ms, partition_id) VALUES (?1, 'recovery_codes', ?2, 0, ?3, ?4, ?4, ?5)",
            params![item_id, label, revision, ts, partition],
        )?;
        conn.execute(
            "INSERT INTO recovery_code_items (id, item_id, service_name, codes_json, current_revision, created_at_ms, updated_at_ms, mfa_item_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
            params![recovery_id, item_id, label, codes_json, revision, ts, totp_item],
        )?;
        crate::credential_management::sync_recovery_entries(conn, &recovery_id, &cleaned)?;
        (recovery_id, item_id)
    };
    crate::mark_restore_dirty(conn)?;
    Ok(serde_json::json!({"id": recovery_id, "item_id": item_id, "remaining": cleaned.len(), "total": cleaned.len()}))
}

pub fn update_recovery_codes(
    conn: &Connection,
    id: &str,
    expected_revision: &str,
    service_name: &str,
    codes: &[String],
) -> Result<RecoveryCodeRow> {
    let cleaned: Vec<String> = codes
        .iter()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Err(CoreError::format("at least one recovery code required"));
    }
    let tx = conn.unchecked_transaction()?;
    let (item_id, current_rev): (String, String) = tx
        .query_row(
            "SELECT r.item_id, r.current_revision FROM recovery_code_items r
             INNER JOIN items i ON i.id = r.item_id
             WHERE r.id = ?1 AND i.trashed = 0",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| CoreError::format("recovery codes not found"))?;
    if current_rev != expected_revision {
        return Err(CoreError::Conflict);
    }
    let revision = new_revision();
    let ts = now_ms();
    let codes_json =
        serde_json::to_string(&cleaned).map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "UPDATE recovery_code_items SET service_name = ?1, codes_json = ?2, current_revision = ?3, updated_at_ms = ?4 WHERE id = ?5",
        params![service_name, codes_json, revision, ts, id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "UPDATE items SET title = ?1, current_revision = ?2, updated_at_ms = ?3 WHERE id = ?4",
        params![service_name, revision, ts, item_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    crate::credential_management::sync_recovery_entries(&tx, id, &cleaned)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(RecoveryCodeRow {
        id: id.to_string(),
        item_id,
        service_name: service_name.to_string(),
        codes: cleaned,
        current_revision: revision,
        updated_at_ms: ts,
    })
}

pub fn totp_params_for_id(conn: &Connection, totp_id: &str) -> Result<crate::totp::TotpStoredParams> {
    let params = conn.query_row(
        "SELECT t.secret_base32, t.totp_algorithm, t.totp_digits, t.totp_period FROM totp_credentials t
         INNER JOIN items i ON i.id = t.item_id
         WHERE t.id = ?1 AND i.trashed = 0",
        params![totp_id],
        |row| {
            let alg_name: String = row.get(1)?;
            let algorithm = crate::totp::algorithm_from_name(&alg_name)
                .map_err(|e| rusqlite::Error::InvalidColumnType(1, e.to_string(), rusqlite::types::Type::Text))?;
            Ok(crate::totp::TotpStoredParams {
                secret_base32: row.get(0)?,
                algorithm,
                digits: row.get::<_, i64>(2)? as usize,
                period: row.get::<_, i64>(3)? as u64,
            })
        },
    )
    .map_err(|_| CoreError::format("totp not found"))?;
    crate::totp::validate_totp_stored_params(&params)?;
    Ok(params)
}

pub fn totp_code_for_id(conn: &Connection, totp_id: &str) -> Result<String> {
    let params = totp_params_for_id(conn, totp_id)?;
    crate::totp::totp_code_from_params(&params)
}

pub fn totp_secret_for_id(conn: &Connection, totp_id: &str) -> Result<String> {
    Ok(totp_params_for_id(conn, totp_id)?.secret_base32)
}

pub fn totp_reveal_for_id(conn: &Connection, totp_id: &str) -> Result<TotpRevealRow> {
    let (issuer, account, secret): (String, String, String) = conn
        .query_row(
            "SELECT t.issuer, t.account, t.secret_base32 FROM totp_credentials t
             INNER JOIN items i ON i.id = t.item_id
             WHERE t.id = ?1 AND i.trashed = 0",
            params![totp_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| CoreError::format("totp not found"))?;
    let params = totp_params_for_id(conn, totp_id)?;
    let item: String = conn.query_row("SELECT item_id FROM totp_credentials WHERE id=?1",[totp_id],|r|r.get(0))?;
    let details = crate::credential_management::details_for(conn, &item)?;
    let mut uri = url::Url::parse(&crate::totp::build_otpauth_uri_from_params(&issuer, &account, &params)?)
        .map_err(|_|CoreError::format("MFA URI 编码失败"))?;
    for (key,value) in &details.otp_extra_parameters { uri.query_pairs_mut().append_pair(key,value); }
    let otpauth_uri = uri.to_string();
    Ok(TotpRevealRow {
        issuer,
        account,
        secret_base32: secret,
        otpauth_uri,
        website_rules: details.uris,
        pending_website_rules: details.pending_mfa_uris,
        current_revision: conn.query_row("SELECT current_revision FROM totp_credentials WHERE id=?1",[totp_id],|r|r.get(0))?,
    })
}
