use crate::error::{CoreError, Result};
use crate::repo::{new_revision, now_ms};
use rusqlite::{params, Connection};
use uuid::Uuid;

pub const PASSWORD_HISTORY_MAX: usize = 20;
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
                 WHERE i.trashed = 0 AND (i.title LIKE ?1 OR c.display_name LIKE ?1 OR c.origin LIKE ?1 OR c.username LIKE ?1)
                 ORDER BY c.updated_at_ms DESC LIMIT ?2"
                ),
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
        let rows = stmt
            .query_map(params![pattern, lim], map_login_row)
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
                 ORDER BY c.updated_at_ms DESC LIMIT ?1"
                ),
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
        let rows = stmt
            .query_map(params![lim], map_login_row)
            .map_err(|e| CoreError::format(e.to_string()))?;
        for r in rows {
            out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
        }
    }
    Ok(out)
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
) -> Result<LoginListRow> {
    let item_id = Uuid::new_v4().to_string();
    let cred_id = Uuid::new_v4().to_string();
    let revision = new_revision();
    let ts = now_ms();
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
         current_revision, created_at_ms, updated_at_ms, password_active_since_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?10)",
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
            ts
        ],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    list_logins(conn, None, 500)?
        .into_iter()
        .find(|r| r.id == cred_id)
        .ok_or_else(|| CoreError::format("credential not found after insert"))
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
) -> Result<LoginListRow> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    let (item_id, current_rev, old_secret, active_since): (String, String, String, i64) = tx
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

    if let Some(pw) = new_password {
        if pw != old_secret {
            tx.execute(
                "INSERT INTO password_history (id, credential_id, secret, activated_at_ms, retired_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    Uuid::new_v4().to_string(),
                    credential_id,
                    old_secret,
                    active_since,
                    ts
                ],
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
            trim_password_history(&tx, credential_id)?;
            tx.execute(
                "UPDATE login_credentials SET origin = ?1, username = ?2, secret = ?3, display_name = ?4,
                 connection_host = ?5, linked_totp_id = ?6, current_revision = ?7, updated_at_ms = ?8, password_active_since_ms = ?8
                 WHERE id = ?9",
                params![
                    origin,
                    username,
                    pw,
                    display_name.trim(),
                    connection_host.trim(),
                    linked_totp_id,
                    revision,
                    ts,
                    credential_id
                ],
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
        } else {
            tx.execute(
                "UPDATE login_credentials SET origin = ?1, username = ?2, display_name = ?3, connection_host = ?4,
                 linked_totp_id = ?5, current_revision = ?6, updated_at_ms = ?7
                 WHERE id = ?8",
                params![
                    origin,
                    username,
                    display_name.trim(),
                    connection_host.trim(),
                    linked_totp_id,
                    revision,
                    ts,
                    credential_id
                ],
            )
            .map_err(|e| CoreError::format(e.to_string()))?;
        }
    } else {
        tx.execute(
            "UPDATE login_credentials SET origin = ?1, username = ?2, display_name = ?3, connection_host = ?4,
             linked_totp_id = ?5, current_revision = ?6, updated_at_ms = ?7
             WHERE id = ?8",
            params![
                origin,
                username,
                display_name.trim(),
                connection_host.trim(),
                linked_totp_id,
                revision,
                ts,
                credential_id
            ],
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    }
    tx.execute(
        "UPDATE items SET title = ?1, group_id = ?2, current_revision = ?3, updated_at_ms = ?4 WHERE id = ?5",
        params![title, group_id, revision, ts, item_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;

    list_logins(conn, None, 1)?
        .into_iter()
        .find(|r| r.id == credential_id)
        .ok_or_else(|| CoreError::format("credential not found"))
}

fn trim_password_history(conn: &Connection, credential_id: &str) -> Result<()> {
    let mut stmt = conn
        .prepare(
            "SELECT id FROM password_history WHERE credential_id = ?1 ORDER BY retired_at_ms DESC, activated_at_ms DESC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let ids: Vec<String> = stmt
        .query_map(params![credential_id], |row| row.get(0))
        .map_err(|e| CoreError::format(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();
    if ids.len() <= PASSWORD_HISTORY_MAX {
        return Ok(());
    }
    for id in ids.iter().skip(PASSWORD_HISTORY_MAX) {
        conn.execute("DELETE FROM password_history WHERE id = ?1", params![id])
            .map_err(|e| CoreError::format(e.to_string()))?;
    }
    Ok(())
}

pub fn trash_item(conn: &Connection, item_id: &str) -> Result<()> {
    let ts = now_ms();
    let revision = new_revision();
    let n = conn
        .execute(
            "UPDATE items SET trashed = 1, current_revision = ?1, updated_at_ms = ?2 WHERE id = ?3 AND trashed = 0",
            params![revision, ts, item_id],
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    if n == 0 {
        return Err(CoreError::format("item not found"));
    }
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
    insert_ssh_key(conn, "Default", &public, &seed, true)
}

pub fn insert_ssh_key(
    conn: &Connection,
    label: &str,
    public_openssh: &str,
    seed: &[u8; 32],
    is_default: bool,
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
        "INSERT INTO items (id, kind, title, trashed, current_revision, created_at_ms, updated_at_ms)
         VALUES (?1, 'ssh_key', ?2, 0, ?3, ?4, ?4)",
        params![item_id, label, revision, ts],
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
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TotpRevealRow {
    pub issuer: String,
    pub account: String,
    pub secret_base32: String,
    pub otpauth_uri: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SshKeyListRow {
    pub id: String,
    pub item_id: String,
    pub label: String,
    pub public_openssh: String,
    pub is_default: bool,
}

pub fn list_totp_credentials(conn: &Connection) -> Result<Vec<TotpListRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.item_id, t.issuer, t.account, i.group_id, t.updated_at_ms
             FROM totp_credentials t
             INNER JOIN items i ON i.id = t.item_id
             WHERE i.trashed = 0
             ORDER BY t.updated_at_ms DESC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| {
            Ok(TotpListRow {
                id: row.get(0)?,
                item_id: row.get(1)?,
                issuer: row.get(2)?,
                account: row.get(3)?,
                group_id: row.get(4)?,
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

pub fn list_ssh_keys(conn: &Connection) -> Result<Vec<SshKeyListRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.id, s.item_id, s.label, s.public_openssh, s.is_default
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
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    Ok(out)
}

pub fn generate_ssh_key(conn: &Connection, label: &str, set_default: bool) -> Result<SshKeyListRow> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut OsRng);
    let seed = signing.to_bytes();
    let vk = signing.verifying_key();
    let public = format_ssh_ed25519_openssh(vk.as_bytes(), "credpivot");
    let rec = insert_ssh_key(conn, label, &public, &seed, set_default)?;
    Ok(SshKeyListRow {
        id: rec.id,
        item_id: rec.item_id,
        label: rec.label,
        public_openssh: rec.public_openssh,
        is_default: rec.is_default,
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
    let (item_id, current_rev): (String, String) = conn
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
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
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
    conn.query_row(
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
    .map_err(|_| CoreError::format("totp not found"))
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
    let otpauth_uri = crate::totp::build_otpauth_uri(&issuer, &account, &secret)?;
    Ok(TotpRevealRow {
        issuer,
        account,
        secret_base32: secret,
        otpauth_uri,
    })
}
