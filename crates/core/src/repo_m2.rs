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
                 WHERE i.trashed = 0 AND (i.title LIKE ?1 OR c.display_name LIKE ?1 OR c.origin LIKE ?1 OR c.username LIKE ?1
                   OR EXISTS (SELECT 1 FROM json_each(i.details_json, '$.uris') AS rule WHERE json_extract(rule.value, '$.uri') LIKE ?1))
                 ORDER BY c.updated_at_ms DESC, c.id ASC LIMIT ?2 OFFSET ?3"
                ),
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
        let rows = stmt
            .query_map(params![pattern, lim, offset], map_login_row)
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
                 WHERE i.trashed = 0
                 ORDER BY c.updated_at_ms DESC, c.id ASC LIMIT ?1 OFFSET ?2"
                ),
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
        let rows = stmt
            .query_map(params![lim, offset], map_login_row)
            .map_err(|e| CoreError::format(e.to_string()))?;
        for r in rows {
            out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
        }
    }
    Ok(out)
}

/// 按 ID 读取写入结果，避免受列表分页和相同更新时间的排序影响。
pub(crate) fn get_login_row(conn: &Connection, credential_id: &str) -> Result<LoginListRow> {
    conn.query_row(
        &format!(
            "{LOGIN_LIST_SELECT}
             FROM login_credentials c
             INNER JOIN items i ON i.id = c.item_id
             WHERE c.id = ?1 AND i.trashed = 0"
        ),
        params![credential_id],
        map_login_row,
    )
    .map_err(|e| CoreError::format(e.to_string()))
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
    })
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
        "INSERT INTO items (id, kind, title, trashed, group_id, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, 'login', ?2, 0, ?3, ?4, ?5, ?5)",
        params![item_id, title, group_id, revision, ts],
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
            linked_totp_id,
            revision,
            ts,
            since
        ],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    if let Some(rules) = website_rules { crate::website_rules::save_login_website_rules(&tx, &item_id, rules)?; }
    if let Some(ids) = linked_mfa_ids {
        crate::website_rules::save_linked_mfas(&tx, &item_id, ids)?;
        // 服务器仍使用单 MFA：保留仍被选择的旧关联，多条时不任意挑选。
        let legacy = linked_totp_id.filter(|id| ids.iter().any(|v|v.as_str() == *id))
            .or_else(|| if ids.len() == 1 { Some(ids[0].as_str()) } else { None });
        tx.execute("UPDATE login_credentials SET linked_totp_id=?1 WHERE item_id=?2", params![legacy,item_id])?;
    } else if let Some(id) = linked_totp_id {
        let mut details = crate::credential_management::details_for(&tx, &item_id)?;
        if !details.linked_mfa_ids.iter().any(|v|v == id) {
            details.linked_mfa_ids.push(id.into());
            crate::website_rules::save_linked_mfas(&tx, &item_id, &details.linked_mfa_ids)?;
        }
    }

    let row = get_login_row(&tx, &cred_id)?;
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
    update_login_with_mfa(conn, credential_id, expected_revision, origin, username, display_name, connection_host, linked_totp_id, group_id, new_password, website_rules, None)
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
) -> Result<LoginListRow> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    let (item_id, current_rev, old_secret, _active_since): (String, String, String, i64) = tx
        .query_row(
            "SELECT c.item_id, c.current_revision, c.secret, c.password_active_since_ms
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
         linked_totp_id=?5, current_revision=?6, updated_at_ms=?7 WHERE id=?8",
        params![origin,username,display_name.trim(),connection_host.trim(),linked_totp_id,revision,ts,credential_id],
    )?;
    tx.execute(
        "UPDATE items SET title = ?1, group_id = ?2, current_revision = ?3, updated_at_ms = ?4 WHERE id = ?5",
        params![title, group_id, revision, ts, item_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    if let Some(rules) = website_rules { crate::website_rules::save_login_website_rules(&tx, &item_id, rules)?; }
    if let Some(ids) = linked_mfa_ids {
        crate::website_rules::save_linked_mfas(&tx, &item_id, ids)?;
        // 服务器仍使用单 MFA：保留仍被选择的旧关联，多条时不任意挑选。
        let legacy = linked_totp_id.filter(|id| ids.iter().any(|v|v.as_str() == *id))
            .or_else(|| if ids.len() == 1 { Some(ids[0].as_str()) } else { None });
        tx.execute("UPDATE login_credentials SET linked_totp_id=?1 WHERE item_id=?2", params![legacy,item_id])?;
    } else if let Some(id) = linked_totp_id {
        let mut details = crate::credential_management::details_for(&tx, &item_id)?;
        if !details.linked_mfa_ids.iter().any(|v|v == id) {
            details.linked_mfa_ids.push(id.into());
            crate::website_rules::save_linked_mfas(&tx, &item_id, &details.linked_mfa_ids)?;
        }
    }

    let row = get_login_row(&tx, credential_id)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(row)
}

pub fn trash_item(conn: &Connection, item_id: &str) -> Result<()> {
    let ts = now_ms();
    let revision = new_revision();
    let tx = conn.unchecked_transaction().map_err(|e| CoreError::format(e.to_string()))?;
    let ssh_key: Option<(String, bool)> = tx.query_row(
        "SELECT s.id, s.is_default FROM ssh_keys s INNER JOIN items i ON i.id = s.item_id
         WHERE s.item_id = ?1 AND i.trashed = 0",
        params![item_id],
        |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
    ).optional().map_err(|e| CoreError::format(e.to_string()))?;
    if let Some((key_id, _)) = &ssh_key {
        let references: i64 = tx.query_row(
            "SELECT COUNT(*) FROM server_login_profiles s INNER JOIN items i ON i.id = s.item_id
             WHERE s.linked_ssh_key_id = ?1 AND i.trashed = 0",
            params![key_id], |row| row.get(0),
        ).map_err(|e| CoreError::format(e.to_string()))?;
        if references > 0 {
            return Err(CoreError::format("SSH 密钥仍被服务器配置引用，请先编辑服务器解除关联"));
        }
    }
    let n = tx
        .execute(
            "UPDATE items SET trashed = 1, trashed_at_ms = ?2, current_revision = ?1, updated_at_ms = ?2 WHERE id = ?3 AND trashed = 0",
            params![revision, ts, item_id],
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    if n == 0 {
        return Err(CoreError::format("item not found"));
    }
    if let Some((key_id, was_default)) = ssh_key {
        tx.execute("UPDATE ssh_keys SET is_default = 0 WHERE id = ?1", params![key_id])
            .map_err(|e| CoreError::format(e.to_string()))?;
        if was_default {
            // 不生成替代密钥；有剩余密钥时沿用最近的一把，没有时允许空列表。
            tx.execute(
                "UPDATE ssh_keys SET is_default = 1 WHERE id = (
                   SELECT s.id FROM ssh_keys s INNER JOIN items i ON i.id = s.item_id
                   WHERE i.trashed = 0 ORDER BY s.updated_at_ms DESC, s.id LIMIT 1)", [],
            ).map_err(|e| CoreError::format(e.to_string()))?;
        }
    }
    crate::website_rules::detach_mfa_references(&tx,item_id)?;
    crate::restore_point::mark_restore_dirty(&tx)?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
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
        "INSERT INTO items (id, kind, title, trashed, group_id, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, 'ssh_key', ?2, 0, ?3, ?4, ?5, ?5)",
        params![item_id, label, group_id, revision, ts],
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
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut OsRng);
    let seed = signing.to_bytes();
    let vk = signing.verifying_key();
    let public = format_ssh_ed25519_openssh(vk.as_bytes(), "credpivot");
    let rec = insert_ssh_key(conn, label, &public, &seed, set_default, group_id)?;
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
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO items (id, kind, title, trashed, group_id, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, 'totp', ?2, 0, ?3, ?4, ?5, ?5)",
        params![item_id, title, group_id, revision, ts],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
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
    tx.execute("UPDATE items SET details_json=?1 WHERE id=?2",params![serde_json::to_string(&details).map_err(|_|CoreError::format("MFA 详情编码失败"))?,item_id])?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(totp_id)
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
        "INSERT INTO items (id, kind, title, trashed, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, 'recovery_codes', ?2, 0, ?3, ?4, ?4)",
        params![item_id, service_name, revision, ts],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.execute(
        "INSERT INTO recovery_code_items (id, item_id, service_name, codes_json, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
        params![rec_id, item_id, service_name, codes_json, revision, ts],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    crate::credential_management::sync_recovery_entries(&tx, &rec_id, &cleaned)?;
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
