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
