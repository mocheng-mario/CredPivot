use crate::error::{CoreError, Result};
use crate::repo::{new_revision, now_ms};
use rusqlite::{params, Connection};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialGroupRow {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub sort_order: i64,
    pub partition_id: String,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub usage_counts: BTreeMap<String, i64>,
}

pub fn list_credential_groups(conn: &Connection, scope: &str) -> Result<Vec<CredentialGroupRow>> {
    checked_scope(scope)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, name, scope, sort_order, partition_id, updated_at_ms FROM credential_groups
             WHERE scope IN (?1, 'shared') ORDER BY sort_order ASC, name ASC, id ASC",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
    let rows = stmt
        .query_map(params![scope], |row| {
            Ok(CredentialGroupRow {
                id: row.get(0)?,
                name: row.get(1)?,
                scope: row.get(2)?,
                sort_order: row.get(3)?,
                partition_id: row.get(4)?,
                updated_at_ms: row.get(5)?,
                usage_counts: BTreeMap::new(),
            })
        })
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| CoreError::format(e.to_string()))?);
    }
    // 统计所有子模块（含回收站），删除共享分组时不能只展示当前列表的影响。
    let mut usage = conn.prepare("SELECT i.group_id,i.kind,COUNT(*) FROM items i JOIN credential_groups g ON g.id=i.group_id
        WHERE g.scope IN (?1,'shared') GROUP BY i.group_id,i.kind")?;
    let counts = usage.query_map([scope], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?)))?;
    let mut by_group = BTreeMap::<String,BTreeMap<String,i64>>::new();
    for row in counts { let (id,kind,count)=row?; by_group.entry(id).or_default().insert(kind,count); }
    for group in &mut out { group.usage_counts=by_group.remove(&group.id).unwrap_or_default(); }
    Ok(out)
}

fn checked_scope(scope: &str) -> Result<()> {
    if matches!(scope,"shared"|"login"|"totp"|"ssh"|"server"|"passkey"|"recovery_codes"|"secure_note") { Ok(()) }
    else { Err(CoreError::format("partitions.errors.groupScope")) }
}

pub fn create_credential_group(conn: &Connection, scope: &str, name: &str) -> Result<CredentialGroupRow> {
    create_credential_group_in_partition(conn,crate::partitions::PERSONAL,scope,name)
}

fn checked_name(conn: &Connection, partition: &str, scope: &str, name: &str, except: &str) -> Result<String> {
    checked_scope(scope)?;
    let name=name.trim();
    if name.is_empty() || name.chars().count()>80 || name.chars().any(char::is_control)
        || name.eq_ignore_ascii_case("internal_work") { return Err(CoreError::format("partitions.errors.groupName")); }
    let duplicate:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM credential_groups WHERE partition_id=?1 AND scope=?2 AND lower(name)=lower(?3) AND id<>?4)",
        params![partition,scope,name,except],|r|r.get(0))?;
    if duplicate { return Err(CoreError::format("partitions.errors.groupDuplicate")); }
    Ok(name.into())
}

pub fn create_credential_group_in_partition(conn: &Connection, partition_id: &str, scope: &str, name: &str) -> Result<CredentialGroupRow> {
    crate::partitions::require(conn,partition_id)?;
    let name=checked_name(conn,partition_id,scope,name,"")?;
    let id = Uuid::new_v4().to_string();
    let ts = now_ms();
    let sort: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(sort_order), -1) + 1 FROM credential_groups WHERE scope = ?1 AND partition_id=?2",
            params![scope,partition_id],
            |row| row.get(0),
        )
        .unwrap_or(0);
    conn.execute(
        "INSERT INTO credential_groups (id, name, scope, sort_order, created_at_ms, updated_at_ms, partition_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
        params![id, name, scope, sort, ts,partition_id],
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    crate::mark_restore_dirty(conn)?;
    Ok(CredentialGroupRow {
        id,
        name: name.trim().to_string(),
        scope: scope.to_string(),
        sort_order: sort,
        partition_id: partition_id.into(),
        updated_at_ms: ts,
        usage_counts: BTreeMap::new(),
    })
}

pub fn rename_credential_group(conn: &Connection, id: &str, name: &str) -> Result<()> {
    rename_credential_group_checked(conn,id,name,None)
}

pub fn rename_credential_group_checked(conn: &Connection, id: &str, name: &str, expected: Option<i64>) -> Result<()> {
    update_credential_group_checked(conn,id,name,None,expected)
}

pub fn update_credential_group_checked(conn: &Connection, id: &str, name: &str, scope: Option<&str>, expected: Option<i64>) -> Result<()> {
    let tx=conn.unchecked_transaction()?;
    let (partition,old_scope,modified):(String,String,i64)=tx.query_row("SELECT partition_id,scope,updated_at_ms FROM credential_groups WHERE id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    if expected.is_some_and(|value|value!=modified) { return Err(CoreError::Conflict); }
    let scope=scope.unwrap_or(&old_scope);
    let name=checked_name(&tx,&partition,scope,name,id)?;
    // 共享改为独享时，数据库约束会同时检查其他类型与回收站记录，不能遗留不可恢复的引用。
    tx.execute("UPDATE credential_groups SET name=?1,scope=?2,updated_at_ms=?3 WHERE id=?4",params![name,scope,now_ms(),id])?;
    crate::mark_restore_dirty(&tx)?;
    tx.commit()?;
    Ok(())
}

/// 新数据库初始化时安装分组范围约束。
pub(crate) fn install_constraints(conn: &Connection) -> Result<()> {
    let normal="NOT EXISTS(SELECT 1 FROM sync_state WHERE key IN ('applying','partition_moving'))";
    let item_scope="CASE NEW.kind WHEN 'ssh_key' THEN 'ssh' WHEN 'server_login' THEN 'server' ELSE NEW.kind END";
    for event in ["INSERT","UPDATE"] {
        conn.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS credential_group_item_{event} BEFORE {event} ON items WHEN {normal}
BEGIN SELECT CASE WHEN NEW.group_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM credential_groups g
 WHERE g.id=NEW.group_id AND g.partition_id=NEW.partition_id AND (g.scope='shared' OR g.scope={item_scope}))
 THEN RAISE(ABORT,'partitions.errors.groupScope') END; END;
CREATE TRIGGER IF NOT EXISTS credential_group_scope_{event} BEFORE {event} ON credential_groups WHEN {normal}
BEGIN SELECT CASE WHEN NEW.scope NOT IN ('shared','login','totp','ssh','server','passkey','recovery_codes','secure_note')
 OR (NEW.scope<>'shared' AND EXISTS(SELECT 1 FROM items i WHERE i.group_id=NEW.id
 AND NEW.scope<>CASE i.kind WHEN 'ssh_key' THEN 'ssh' WHEN 'server_login' THEN 'server' ELSE i.kind END))
 THEN RAISE(ABORT,'partitions.errors.groupInUse') END; END;"))?;
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
    set_item_group_in_tx(&tx, item_id, group_id)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn set_item_group_in_tx(conn: &Connection, item_id: &str, group_id: Option<&str>) -> Result<()> {
    if let Some(group) = group_id {
        let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM credential_groups WHERE id=?1)", [group], |row| row.get(0))?;
        if !exists { return Err(CoreError::format("group not found")); }
    }
    let revision = new_revision();
    let ts = now_ms();
    if conn.execute(
        "UPDATE items SET group_id=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4 AND trashed=0",
        params![group_id, revision, ts, item_id],
    )? == 0 {
        return Err(CoreError::format("item not found"));
    }
    for table in ["login_credentials", "totp_credentials", "ssh_keys", "recovery_code_items", "server_login_profiles"] {
        conn.execute(&format!("UPDATE {table} SET current_revision=?1,updated_at_ms=?2 WHERE item_id=?3"), params![revision,ts,item_id])?;
    }
    crate::mark_restore_dirty(conn)?;
    Ok(())
}
