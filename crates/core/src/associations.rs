//! 账户与通行密钥、MFA、SSH 密钥的认证关联。资料里的任意互相关联不在这里。
use crate::error::{CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension};

pub(crate) fn table_ready(conn: &Connection) -> Result<bool> {
    let ready: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='credential_links')",
        [],
        |row| row.get(0),
    )?;
    Ok(ready)
}

fn require_table(conn: &Connection) -> Result<()> {
    if table_ready(conn)? {
        Ok(())
    } else {
        Err(CoreError::format("请先执行关联清空，再保存认证关联"))
    }
}

/// 一条通行密钥最多属于一个账户。已经挂在这个账户上时不重复写入。
pub(crate) fn link_passkey(conn: &Connection, account_item: &str, passkey_item: &str, now: i64) -> Result<()> {
    require_table(conn)?;
    let owner: Option<String> = conn
        .query_row(
            "SELECT account_item_id FROM credential_links WHERE target_item_id=?1 AND kind='passkey'",
            [passkey_item],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(owner) = owner {
        if owner != account_item {
            return Err(CoreError::format("这条通行密钥已经关联其他账户，请先更换关联账户"));
        }
        return Ok(());
    }
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM credential_links WHERE account_item_id=?1 AND kind='passkey'",
        [account_item],
        |row| row.get(0),
    )?;
    if count >= 100 {
        return Err(CoreError::limit("账密关联记录数量已达上限"));
    }
    conn.execute(
        "INSERT INTO credential_links (account_item_id, target_item_id, kind, created_at_ms) VALUES (?1, ?2, 'passkey', ?3)",
        params![account_item, passkey_item, now],
    )?;
    Ok(())
}

pub(crate) fn passkey_count(conn: &Connection, account_item: &str) -> Result<i64> {
    if !table_ready(conn)? {
        return Ok(0);
    }
    Ok(conn.query_row(
        "SELECT count(*) FROM credential_links WHERE account_item_id=?1 AND kind='passkey'",
        [account_item],
        |row| row.get(0),
    )?)
}

/// 合并账户时把通行密钥挂接到保留的账户。同一条通行密钥不会同时挂两个账户。
pub(crate) fn move_passkey_links(conn: &Connection, from_items: &[String], to_item: &str) -> Result<()> {
    if !table_ready(conn)? || from_items.is_empty() {
        return Ok(());
    }
    for from in from_items {
        conn.execute(
            "UPDATE credential_links SET account_item_id=?1 WHERE account_item_id=?2 AND kind='passkey'",
            params![to_item, from],
        )?;
    }
    Ok(())
}

pub(crate) fn delete_links_for_item(conn: &Connection, item: &str) -> Result<()> {
    if !table_ready(conn)? {
        return Ok(());
    }
    conn.execute(
        "DELETE FROM credential_links WHERE account_item_id=?1 OR target_item_id=?1",
        [item],
    )?;
    Ok(())
}

pub(crate) fn stale_ready(conn: &Connection) -> Result<bool> {
    let ready: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='server_stale_auth')",
        [],
        |row| row.get(0),
    )?;
    Ok(ready)
}

pub(crate) fn mfa_credential_ids(conn: &Connection, account_item: &str) -> Result<Vec<String>> {
    if !table_ready(conn)? {
        return Ok(Vec::new());
    }
    let mut statement = conn.prepare(
        "SELECT t.id FROM credential_links k
         JOIN totp_credentials t ON t.item_id=k.target_item_id
         JOIN items i ON i.id=t.item_id
         WHERE k.account_item_id=?1 AND k.kind='mfa' AND i.trashed=0
         ORDER BY t.id",
    )?;
    let rows = statement.query_map([account_item], |row| row.get::<_, String>(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(CoreError::from)
}

pub(crate) fn mfa_enabled(conn: &Connection, account_item: &str) -> Result<bool> {
    Ok(!mfa_credential_ids(conn, account_item)?.is_empty())
}

/// 替换一个账户的 MFA。已经挂在其他账户上的 MFA 不能在这里悄悄改挂。
pub(crate) fn replace_mfas(conn: &Connection, account_item: &str, totp_ids: &[String]) -> Result<()> {
    require_table(conn)?;
    if totp_ids.len() > 100 {
        return Err(CoreError::limit("MFA 关联过多"));
    }
    let account_partition = crate::partitions::item_partition(conn, account_item)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut targets = Vec::new();
    for id in totp_ids {
        if id.is_empty() || !seen.insert(id.clone()) {
            return Err(CoreError::format("MFA 关联重复或无效"));
        }
        let (item, partition, trashed): (String, String, i64) = conn
            .query_row(
                "SELECT t.item_id, i.partition_id, i.trashed FROM totp_credentials t JOIN items i ON i.id=t.item_id WHERE t.id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| CoreError::format("关联的 MFA 已不存在"))?;
        if trashed != 0 || partition != account_partition {
            return Err(CoreError::format("关联的 MFA 必须位于同一分区"));
        }
        let owner: Option<String> = conn
            .query_row(
                "SELECT account_item_id FROM credential_links WHERE target_item_id=?1 AND kind='mfa'",
                [&item],
                |row| row.get(0),
            )
            .optional()?;
        if owner.as_deref().is_some_and(|owner| owner != account_item) {
            return Err(CoreError::format("这条 MFA 已经关联其他账户，请先更换关联账户"));
        }
        targets.push((id.clone(), item));
    }
    let previous = mfa_credential_ids(conn, account_item)?;
    let login_id: Option<String> = conn
        .query_row("SELECT id FROM login_credentials WHERE item_id=?1", [account_item], |row| row.get(0))
        .optional()?;
    conn.execute("DELETE FROM credential_links WHERE account_item_id=?1 AND kind='mfa'", [account_item])?;
    let now = crate::repo::now_ms();
    for (_id, item) in &targets {
        conn.execute(
            "INSERT INTO credential_links (account_item_id, target_item_id, kind, created_at_ms) VALUES (?1, ?2, 'mfa', ?3)",
            params![account_item, item, now],
        )?;
    }
    if let Some(login_id) = login_id {
        for id in previous.iter().filter(|id| !seen.contains(*id)) {
            disable_associated_selection(conn, &login_id, "linked_totp_id", id, "所选 MFA 已不再属于该账户")?;
        }
    }
    sync_mfa_state(conn, account_item)?;
    Ok(())
}

pub(crate) fn sync_mfa_state(conn: &Connection, account_item: &str) -> Result<()> {
    let mut details = crate::credential_management::details_for(conn, account_item)?;
    let state = if mfa_enabled(conn, account_item)? { "enabled" } else { "disabled" };
    if details.mfa_state == state && details.linked_mfa_ids.is_empty() {
        return Ok(());
    }
    details.mfa_state = state.into();
    details.linked_mfa_ids.clear();
    conn.execute(
        "UPDATE items SET details_json=?1 WHERE id=?2",
        params![serde_json::to_string(&details).map_err(|_| CoreError::format("MFA 状态无法保存"))?, account_item],
    )?;
    conn.execute("UPDATE login_credentials SET linked_totp_id=NULL WHERE item_id=?1", [account_item])?;
    Ok(())
}

pub(crate) fn ssh_key_ids(conn: &Connection, account_item: &str) -> Result<Vec<String>> {
    if !table_ready(conn)? {
        return Ok(Vec::new());
    }
    let mut statement = conn.prepare(
        "SELECT s.id FROM credential_links k
         JOIN ssh_keys s ON s.item_id=k.target_item_id
         JOIN items i ON i.id=s.item_id
         WHERE k.account_item_id=?1 AND k.kind='ssh_key' AND i.trashed=0
         ORDER BY s.id",
    )?;
    let rows = statement.query_map([account_item], |row| row.get::<_, String>(0))?;
    rows.collect::<std::result::Result<Vec<_>, _>>().map_err(CoreError::from)
}

pub(crate) fn replace_ssh_keys(conn: &Connection, account_item: &str, key_ids: &[String]) -> Result<()> {
    require_table(conn)?;
    if key_ids.len() > 100 {
        return Err(CoreError::limit("SSH 密钥关联过多"));
    }
    let account_partition = crate::partitions::item_partition(conn, account_item)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut targets = Vec::new();
    for id in key_ids {
        if id.is_empty() || !seen.insert(id.clone()) {
            return Err(CoreError::format("SSH 密钥关联重复或无效"));
        }
        let (item, partition, trashed): (String, String, i64) = conn
            .query_row(
                "SELECT s.item_id, i.partition_id, i.trashed FROM ssh_keys s JOIN items i ON i.id=s.item_id WHERE s.id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| CoreError::format("关联的 SSH 密钥已不存在"))?;
        if trashed != 0 || partition != account_partition {
            return Err(CoreError::format("关联的 SSH 密钥必须位于同一分区"));
        }
        targets.push(item);
    }
    let previous = ssh_key_ids(conn, account_item)?;
    let login_id: Option<String> = conn
        .query_row("SELECT id FROM login_credentials WHERE item_id=?1", [account_item], |row| row.get(0))
        .optional()?;
    conn.execute("DELETE FROM credential_links WHERE account_item_id=?1 AND kind='ssh_key'", [account_item])?;
    let now = crate::repo::now_ms();
    for item in &targets {
        conn.execute(
            "INSERT INTO credential_links (account_item_id, target_item_id, kind, created_at_ms) VALUES (?1, ?2, 'ssh_key', ?3)",
            params![account_item, item, now],
        )?;
    }
    if let Some(login_id) = login_id {
        for id in previous.iter().filter(|id| !seen.contains(*id)) {
            disable_associated_selection(conn, &login_id, "linked_ssh_key_id", id, "所选 SSH 密钥已不再属于该账户")?;
        }
    }
    Ok(())
}

fn disable_associated_selection(conn: &Connection, login_id: &str, column: &str, target_id: &str, reason: &str) -> Result<()> {
    if !matches!(column, "linked_totp_id" | "linked_ssh_key_id") {
        return Err(CoreError::format("连接引用无效"));
    }
    let mut statement = conn.prepare(&format!(
        "SELECT id FROM server_login_profiles WHERE linked_login_id=?1 AND {column}=?2"
    ))?;
    let ids = statement.query_map(params![login_id, target_id], |row| row.get::<_, String>(0))?;
    for id in ids {
        disable_profile(conn, &id?, reason)?;
    }
    Ok(())
}

/// 停用连接并保留当前引用供查看。已经停用的连接不改写旧引用。
pub(crate) fn disable_profile(conn: &Connection, profile_id: &str, reason: &str) -> Result<()> {
    if !stale_ready(conn)? {
        return Ok(());
    }
    let current: Option<(Option<String>, Option<String>, Option<String>, String, i64)> = conn
        .query_row(
            "SELECT s.linked_login_id, s.linked_totp_id, s.linked_ssh_key_id, s.item_id,
                    COALESCE((SELECT unavailable FROM server_stale_auth WHERE profile_id=s.id), 0)
             FROM server_login_profiles s WHERE s.id=?1",
            [profile_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let Some((login, totp, ssh, item_id, unavailable)) = current else { return Ok(()) };
    if unavailable != 0 {
        return Ok(());
    }
    let mode = if login.as_deref().is_some_and(|value| !value.is_empty()) { "account" } else { "independent" };
    conn.execute(
        "INSERT INTO server_stale_auth (profile_id, linked_login_id, linked_totp_id, linked_ssh_key_id, auth_mode, unavailable, unavailable_reason)
         VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
         ON CONFLICT(profile_id) DO UPDATE SET linked_login_id=excluded.linked_login_id, linked_totp_id=excluded.linked_totp_id,
           linked_ssh_key_id=excluded.linked_ssh_key_id, auth_mode=excluded.auth_mode, unavailable=1, unavailable_reason=excluded.unavailable_reason",
        params![profile_id, login, totp, ssh, mode, reason],
    )?;
    let revision = crate::repo::new_revision();
    let now = crate::repo::now_ms();
    conn.execute(
        "UPDATE server_login_profiles SET linked_login_id=NULL, linked_totp_id=NULL, linked_ssh_key_id=NULL, current_revision=?1, updated_at_ms=?2 WHERE id=?3",
        params![revision, now, profile_id],
    )?;
    conn.execute("UPDATE items SET current_revision=?1, updated_at_ms=?2 WHERE id=?3", params![revision, now, item_id])?;
    Ok(())
}

pub(crate) fn disable_profiles_for_credential(conn: &Connection, column: &str, target_id: &str, reason: &str) -> Result<()> {
    if !matches!(column, "linked_login_id" | "linked_totp_id" | "linked_ssh_key_id") {
        return Err(CoreError::format("连接引用无效"));
    }
    let mut statement = conn.prepare(&format!("SELECT id FROM server_login_profiles WHERE {column}=?1"))?;
    let ids = statement.query_map([target_id], |row| row.get::<_, String>(0))?;
    for id in ids {
        disable_profile(conn, &id?, reason)?;
    }
    Ok(())
}

pub(crate) fn clear_unavailable(conn: &Connection, profile_id: &str) -> Result<()> {
    if !stale_ready(conn)? {
        return Ok(());
    }
    conn.execute("DELETE FROM server_stale_auth WHERE profile_id=?1", [profile_id])?;
    Ok(())
}

pub(crate) fn note_username_cleared(conn: &Connection, login_id: &str, old_username: &str, new_username: &str) -> Result<()> {
    if !old_username.trim().is_empty() && new_username.trim().is_empty() {
        disable_profiles_for_credential(conn, "linked_login_id", login_id, "关联账户的用户名已清空")?;
    }
    Ok(())
}

/// 迁走之后，跨分区的有效关联断开；连接停用并保留旧引用。
pub(crate) fn break_cross_partition(conn: &Connection) -> Result<()> {
    if table_ready(conn)? {
        let mut statement = conn.prepare(
            "SELECT k.account_item_id, k.target_item_id, k.kind FROM credential_links k
             JOIN items a ON a.id=k.account_item_id JOIN items b ON b.id=k.target_item_id
             WHERE a.partition_id<>b.partition_id",
        )?;
        let broken = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?;
        let broken = broken.collect::<std::result::Result<Vec<_>, _>>()?;
        for (account, target, kind) in broken {
            conn.execute(
                "DELETE FROM credential_links WHERE account_item_id=?1 AND target_item_id=?2 AND kind=?3",
                params![account, target, kind],
            )?;
            if kind == "mfa" {
                sync_mfa_state(conn, &account)?;
            }
        }
    }
    let logins = {
        let mut statement = conn.prepare("SELECT id, partition_id, details_json FROM items WHERE kind='login'")?;
        let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (item, partition, json) in logins {
        let mut details: crate::credential_management::ItemDetails = serde_json::from_str(&json).unwrap_or_default();
        let before = details.linked_mfa_ids.len();
        details.linked_mfa_ids.retain(|id| {
            conn.query_row(
                "SELECT i.partition_id=?2 FROM totp_credentials t JOIN items i ON i.id=t.item_id WHERE t.id=?1",
                params![id, partition],
                |row| row.get::<_, bool>(0),
            ).unwrap_or(false)
        });
        if details.linked_mfa_ids.len() != before {
            let revision = crate::repo::new_revision();
            let now = crate::repo::now_ms();
            conn.execute(
                "UPDATE items SET details_json=?1, current_revision=?2, updated_at_ms=?3 WHERE id=?4",
                params![serde_json::to_string(&details).map_err(|_| CoreError::format("MFA 关联无法编码"))?, revision, now, item],
            )?;
        }
    }
    conn.execute(
        "UPDATE login_credentials SET linked_totp_id=NULL WHERE id IN (
            SELECT c.id FROM login_credentials c
            JOIN items a ON a.id=c.item_id
            JOIN totp_credentials t ON t.id=c.linked_totp_id
            JOIN items b ON b.id=t.item_id
            WHERE a.partition_id<>b.partition_id)",
        [],
    )?;
    if !stale_ready(conn)? {
        return Ok(());
    }
    for (column, table, reason) in [
        ("linked_login_id", "login_credentials", "关联账户已不在同一分区"),
        ("linked_totp_id", "totp_credentials", "所选 MFA 已不在同一分区"),
        ("linked_ssh_key_id", "ssh_keys", "所选 SSH 密钥已不在同一分区"),
    ] {
        let mut statement = conn.prepare(&format!(
            "SELECT s.id FROM server_login_profiles s
             JOIN items a ON a.id=s.item_id
             JOIN {table} t ON t.id=s.{column}
             JOIN items b ON b.id=t.item_id
             WHERE a.partition_id<>b.partition_id"
        ))?;
        let ids = statement.query_map([], |row| row.get::<_, String>(0))?;
        for id in ids {
            disable_profile(conn, &id?, reason)?;
        }
    }
    Ok(())
}

pub(crate) fn move_account_links(conn: &Connection, from_items: &[String], to_item: &str) -> Result<()> {
    if !table_ready(conn)? || from_items.is_empty() {
        return Ok(());
    }
    for from in from_items {
        let rows = {
            let mut statement = conn.prepare(
                "SELECT target_item_id, kind FROM credential_links WHERE account_item_id=?1 AND kind IN ('mfa','ssh_key')",
            )?;
            let mapped = statement.query_map([from], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
            mapped.collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (target, kind) in rows {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM credential_links WHERE account_item_id=?1 AND target_item_id=?2 AND kind=?3)",
                params![to_item, target, kind],
                |row| row.get(0),
            )?;
            if exists {
                conn.execute(
                    "DELETE FROM credential_links WHERE account_item_id=?1 AND target_item_id=?2 AND kind=?3",
                    params![from, target, kind],
                )?;
            } else {
                conn.execute(
                    "UPDATE credential_links SET account_item_id=?1 WHERE account_item_id=?2 AND target_item_id=?3 AND kind=?4",
                    params![to_item, from, target, kind],
                )?;
            }
        }
    }
    sync_mfa_state(conn, to_item)?;
    Ok(())
}

pub(crate) fn snapshot_links(conn: &Connection, item: &str) -> Result<()> {
    crate::schema::ensure_runtime_extras(conn)?;
    if !table_ready(conn)? {
        return Ok(());
    }
    let rows = {
        let mut statement = conn.prepare(
            "SELECT account_item_id, target_item_id, kind FROM credential_links WHERE account_item_id=?1 OR target_item_id=?1",
        )?;
        let mapped = statement.query_map([item], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?;
        mapped.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (account, target, kind) in rows {
        conn.execute(
            "INSERT OR REPLACE INTO trashed_credential_links (owner_item_id, account_item_id, target_item_id, kind) VALUES (?1, ?2, ?3, ?4)",
            params![item, account, target, kind],
        )?;
    }
    Ok(())
}

pub(crate) fn restore_links(conn: &Connection, item: &str) -> Result<()> {
    crate::schema::ensure_runtime_extras(conn)?;
    if !table_ready(conn)? {
        return Ok(());
    }
    let rows = {
        let mut statement = conn.prepare(
            "SELECT owner_item_id, account_item_id, target_item_id, kind FROM trashed_credential_links
             WHERE owner_item_id=?1 OR account_item_id=?1 OR target_item_id=?1",
        )?;
        let mapped = statement.query_map([item], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)))?;
        mapped.collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (owner, account, target, kind) in rows {
        let account_state = item_presence(conn, &account)?;
        let target_state = item_presence(conn, &target)?;
        if account_state == Presence::Missing || target_state == Presence::Missing {
            delete_trashed_link(conn, &owner, &account, &target, &kind)?;
            continue;
        }
        // 对端还在回收站时保留快照，等它恢复后再挂接。
        if account_state == Presence::Trashed || target_state == Presence::Trashed {
            continue;
        }
        if crate::partitions::item_partition(conn, &account)? != crate::partitions::item_partition(conn, &target)? {
            delete_trashed_link(conn, &owner, &account, &target, &kind)?;
            continue;
        }
        if kind == "mfa" || kind == "passkey" {
            let current: Option<String> = conn.query_row(
                "SELECT account_item_id FROM credential_links WHERE target_item_id=?1 AND kind=?2",
                params![target, kind],
                |row| row.get(0),
            ).optional()?;
            if current.is_some_and(|current| current != account) {
                delete_trashed_link(conn, &owner, &account, &target, &kind)?;
                continue;
            }
        }
        conn.execute(
            "INSERT OR IGNORE INTO credential_links (account_item_id, target_item_id, kind, created_at_ms) VALUES (?1, ?2, ?3, ?4)",
            params![account, target, kind, crate::repo::now_ms()],
        )?;
        if kind == "mfa" {
            sync_mfa_state(conn, &account)?;
        }
        delete_trashed_link(conn, &owner, &account, &target, &kind)?;
    }
    Ok(())
}

fn delete_trashed_link(conn: &Connection, owner: &str, account: &str, target: &str, kind: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM trashed_credential_links WHERE owner_item_id=?1 AND account_item_id=?2 AND target_item_id=?3 AND kind=?4",
        params![owner, account, target, kind],
    )?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Presence { Active, Trashed, Missing }

fn item_presence(conn: &Connection, item: &str) -> Result<Presence> {
    Ok(match conn.query_row("SELECT trashed FROM items WHERE id=?1", [item], |row| row.get::<_, i64>(0)).optional()? {
        Some(0) => Presence::Active,
        Some(_) => Presence::Trashed,
        None => Presence::Missing,
    })
}

pub(crate) fn login_delete_preview(conn: &Connection, item: &str) -> Result<serde_json::Value> {
    let kind: String = conn.query_row("SELECT kind FROM items WHERE id=?1 AND trashed=0", [item], |row| row.get(0))
        .map_err(|_| CoreError::format("账户不存在"))?;
    if kind != "login" {
        return Err(CoreError::format("只能在账户上选择关联内容一起删除"));
    }
    let mut items = Vec::new();
    if table_ready(conn)? {
        let mut statement = conn.prepare(
            "SELECT k.target_item_id, k.kind, i.title FROM credential_links k JOIN items i ON i.id=k.target_item_id WHERE k.account_item_id=?1 AND i.trashed=0 ORDER BY k.kind, i.title",
        )?;
        let rows = statement.query_map([item], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?;
        for row in rows {
            let (id, kind, title) = row?;
            let mut others = Vec::new();
            if kind == "ssh_key" {
                let mut other = conn.prepare(
                    "SELECT a.title FROM credential_links k JOIN items a ON a.id=k.account_item_id WHERE k.target_item_id=?1 AND k.kind='ssh_key' AND k.account_item_id<>?2 AND a.trashed=0",
                )?;
                let names = other.query_map(params![id, item], |row| row.get::<_, String>(0))?;
                for name in names {
                    others.push(name?);
                }
            }
            items.push(serde_json::json!({"item_id": id, "kind": kind, "title": title, "other_accounts": others}));
        }
    }
    Ok(serde_json::json!({"items": items}))
}

pub(crate) fn login_delete_apply(conn: &Connection, item: &str, also: &[String]) -> Result<()> {
    let preview = login_delete_preview(conn, item)?;
    let allowed: std::collections::BTreeSet<String> = preview["items"].as_array().unwrap_or(&Vec::new()).iter()
        .filter_map(|row| row["item_id"].as_str().map(str::to_string)).collect();
    if also.len() > 100 || also.iter().any(|id| !allowed.contains(id)) {
        return Err(CoreError::format("只能删除这个账户直接关联的内容"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in also {
        if !seen.insert(id.clone()) {
            continue;
        }
        let linked: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM credential_links WHERE account_item_id=?1 AND target_item_id=?2)",
            params![item, id],
            |row| row.get(0),
        )?;
        if !linked {
            return Err(CoreError::format("只能删除这个账户直接关联的内容"));
        }
        crate::repo_m2::trash_item_in_tx(conn, id)?;
    }
    crate::repo_m2::trash_item_in_tx(conn, item)?;
    Ok(())
}

pub fn replace_account_ssh_keys(conn: &Connection, account_item: &str, key_ids: &[String]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    replace_ssh_keys(&tx, account_item, key_ids)?;
    tx.commit()?;
    Ok(())
}
