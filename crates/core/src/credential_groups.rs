use crate::error::{CoreError, Result};
use crate::repo::{new_revision, now_ms};
use rusqlite::{params, Connection};
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialGroupRow {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub sort_order: i64,
}

pub fn list_credential_groups(conn: &Connection, scope: &str) -> Result<Vec<CredentialGroupRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, name, scope, sort_order FROM credential_groups
             WHERE scope = ?1 ORDER BY sort_order ASC, name ASC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rows = stmt
        .query_map(params![scope], |row| {
            Ok(CredentialGroupRow {
                id: row.get(0)?,
                name: row.get(1)?,
                scope: row.get(2)?,
                sort_order: row.get(3)?,
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    Ok(out)
}

pub fn create_credential_group(conn: &Connection, scope: &str, name: &str) -> Result<CredentialGroupRow> {
    let id = Uuid::new_v4().to_string();
    let ts = now_ms();
    let sort: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM credential_groups WHERE scope = ?1",
            params![scope],
            |row| row.get(0),
        )
        .unwrap_or(0);
    conn.execute(
        "INSERT INTO credential_groups (id, name, scope, sort_order, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![id, name.trim(), scope, sort, ts],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    Ok(CredentialGroupRow {
        id,
        name: name.trim().to_string(),
        scope: scope.to_string(),
        sort_order: sort,
    })
}

pub fn rename_credential_group(conn: &Connection, id: &str, name: &str) -> Result<()> {
    let n = conn
        .execute(
            "UPDATE credential_groups SET name = ?1 WHERE id = ?2",
            params![name.trim(), id],
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    if n == 0 {
        return Err(CoreError::format("group not found"));
    }
    Ok(())
}

pub fn delete_credential_group(conn: &Connection, id: &str) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let revision = new_revision();
    let ts = now_ms();
    // 分组也属于编辑状态；删除分组后，旧编辑窗口应发生冲突而非恢复旧引用。
    for table in ["login_credentials", "totp_credentials", "ssh_keys", "recovery_code_items", "server_login_profiles"] {
        tx.execute(&format!("UPDATE {table} SET current_revision=?1,updated_at_ms=?2 WHERE item_id IN (SELECT id FROM items WHERE group_id=?3)"), params![revision,ts,id])?;
    }
    tx.execute(
        "UPDATE items SET group_id=NULL,current_revision=?1,updated_at_ms=?2 WHERE group_id=?3",
        params![revision, ts, id],
    )?;
    let n = tx
        .execute("DELETE FROM credential_groups WHERE id = ?1", params![id])
        .map_err(|e| CoreError::format(e.to_string()))?;
    if n == 0 {
        return Err(CoreError::format("group not found"));
    }
    crate::mark_restore_dirty(&tx)?;
    tx.commit()?;
    Ok(())
}

pub fn set_item_group(conn: &Connection, item_id: &str, group_id: Option<&str>) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    if let Some(group) = group_id {
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM credential_groups WHERE id=?1)", [group], |row| row.get(0))?;
        if !exists { return Err(CoreError::format("group not found")); }
    }
    let revision = new_revision();
    let ts = now_ms();
    if tx.execute(
        "UPDATE items SET group_id=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4 AND trashed=0",
        params![group_id, revision, ts, item_id],
    )? == 0 {
        return Err(CoreError::format("item not found"));
    }
    for table in ["login_credentials", "totp_credentials", "ssh_keys", "recovery_code_items", "server_login_profiles"] {
        tx.execute(&format!("UPDATE {table} SET current_revision=?1,updated_at_ms=?2 WHERE item_id=?3"), params![revision,ts,item_id])?;
    }
    crate::mark_restore_dirty(&tx)?;
    tx.commit()?;
    Ok(())
}
