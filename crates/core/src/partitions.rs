use crate::credential_management::{rows, ItemDetails};
use crate::repo::{new_revision, now_ms};
use crate::{CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const PERSONAL: &str = "00000000-0000-4000-8000-000000000001";
pub const WORK: &str = "00000000-0000-4000-8000-000000000002";

fn error(key: &str) -> CoreError { CoreError::format(format!("partitions.errors.{key}")) }

pub fn require(conn: &Connection, partition: &str) -> Result<()> {
    if !conn.query_row("SELECT EXISTS(SELECT 1 FROM partitions WHERE id=?1)", [partition], |r| r.get::<_,bool>(0))? {
        return Err(error("notFound"));
    }
    Ok(())
}

fn name(conn: &Connection, value: &str, except: Option<&str>) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 80 || value.chars().any(char::is_control)
        || value.eq_ignore_ascii_case("internal_work") { return Err(error("name")); }
    if conn.query_row("SELECT EXISTS(SELECT 1 FROM partitions WHERE lower(name)=lower(?1) AND id<>?2)",
        params![value,except.unwrap_or("")], |r| r.get::<_,bool>(0))? { return Err(error("duplicateName")); }
    Ok(value.into())
}

/// 浏览器保存账号时只需要分区名称，不返回条目数量。
pub fn names(conn: &Connection) -> Result<Value> {
    Ok(json!({"partitions":rows(conn,"SELECT id,name FROM partitions ORDER BY sort_order,id",[])?,
        "default_partition_id":PERSONAL}))
}

pub fn list(conn: &Connection) -> Result<Value> {
    Ok(json!({"partitions":rows(conn,"SELECT p.*,
        (SELECT count(*) FROM items i WHERE i.partition_id=p.id AND i.trashed=0) AS item_count,
        (SELECT count(*) FROM items i WHERE i.partition_id=p.id AND i.trashed=1) AS trashed_count
        FROM partitions p ORDER BY sort_order,id",[])?,"default_partition_id":PERSONAL}))
}

pub fn create(conn: &Connection, value: &str) -> Result<Value> {
    let tx = conn.unchecked_transaction()?;
    let value = name(&tx,value,None)?;
    let id = uuid::Uuid::new_v4().to_string();
    let ts = now_ms();
    tx.execute("INSERT INTO partitions(id,name,sort_order,current_revision,created_at_ms,updated_at_ms)
        VALUES (?1,?2,(SELECT COALESCE(max(sort_order),-1)+1 FROM partitions),?3,?4,?4)",
        params![id,value,new_revision(),ts])?;
    crate::mark_restore_dirty(&tx)?;
    tx.commit()?;
    Ok(json!({"id":id}))
}

pub fn rename(conn: &Connection, id: &str, expected: &str, value: &str) -> Result<Value> {
    let tx = conn.unchecked_transaction()?;
    let value = name(&tx,value,Some(id))?;
    if tx.execute("UPDATE partitions SET name=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4 AND current_revision=?5",
        params![value,new_revision(),now_ms(),id,expected])? != 1 { return Err(CoreError::Conflict); }
    crate::mark_restore_dirty(&tx)?; tx.commit()?;
    Ok(json!({"renamed":true}))
}

pub fn reorder(conn: &Connection, ids: &[String], expected: &BTreeMap<String,String>) -> Result<Value> {
    let tx = conn.unchecked_transaction()?;
    let current = rows(&tx,"SELECT id,current_revision FROM partitions",[])?;
    if current.len() != ids.len() || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        || current.iter().any(|row| expected.get(row["id"].as_str().unwrap_or(""))
            .map(String::as_str) != row["current_revision"].as_str()) { return Err(CoreError::Conflict); }
    for (position,id) in ids.iter().enumerate() {
        if tx.execute("UPDATE partitions SET sort_order=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4",
            params![position as i64,new_revision(),now_ms(),id])? != 1 { return Err(CoreError::Conflict); }
    }
    crate::mark_restore_dirty(&tx)?; tx.commit()?;
    Ok(json!({"reordered":true}))
}

pub fn delete(conn: &Connection, id: &str, expected: &str) -> Result<Value> {
    if id == PERSONAL { return Err(error("defaultDelete")); }
    let tx = conn.unchecked_transaction()?;
    if tx.query_row("SELECT EXISTS(SELECT 1 FROM items WHERE partition_id=?1)",[id],|r|r.get::<_,bool>(0))? {
        return Err(error("notEmpty"));
    }
    tx.execute("DELETE FROM credential_groups WHERE partition_id=?1",[id])?;
    if tx.execute("DELETE FROM partitions WHERE id=?1 AND current_revision=?2",params![id,expected])? != 1 {
        return Err(CoreError::Conflict);
    }
    crate::mark_restore_dirty(&tx)?; tx.commit()?;
    Ok(json!({"deleted":true}))
}

/// 关联按双向边计算：共用同一 MFA 的账号也属于同一迁移批次；分组关系不是凭据依赖边。
fn edges(conn: &Connection) -> Result<Vec<(String,String)>> {
    let mut result = Vec::new();
    for (table,fields) in [("login_credentials",vec![("linked_totp_id","totp_credentials")]),
        ("server_login_profiles",vec![("linked_login_id","login_credentials"),("linked_totp_id","totp_credentials"),("linked_ssh_key_id","ssh_keys")])] {
        for (column,target) in fields {
            for row in rows(conn,&format!("SELECT s.item_id AS source,t.item_id AS target FROM {table} s JOIN {target} t ON t.id=s.{column}"),[])? {
                result.push((row["source"].as_str().unwrap_or("").into(),row["target"].as_str().unwrap_or("").into()));
            }
        }
    }
    for row in rows(conn,"SELECT id,details_json FROM items",[])? {
        let source = row["id"].as_str().ok_or_else(||error("invalid"))?;
        let details: ItemDetails = serde_json::from_str(row["details_json"].as_str().unwrap_or("{}"))
            .map_err(|_|error("invalid"))?;
        for totp in details.linked_mfa_ids {
            let target: Option<String> = conn.query_row("SELECT item_id FROM totp_credentials WHERE id=?1",[totp],|r|r.get(0)).optional()?;
            if let Some(target)=target { result.push((source.into(),target)); }
        }
    }
    if crate::associations::table_ready(conn)? {
        for row in rows(conn, "SELECT account_item_id, target_item_id FROM credential_links", [])? {
            result.push((row["account_item_id"].as_str().unwrap_or("").into(), row["target_item_id"].as_str().unwrap_or("").into()));
        }
    }
    result.sort(); result.dedup();
    Ok(result)
}

pub fn validate(conn: &Connection) -> Result<()> {
    require(conn,PERSONAL)?;
    for row in rows(conn,"SELECT id,name FROM partitions",[])? {
        name(conn,row["name"].as_str().ok_or_else(||error("invalid"))?,row["id"].as_str())?;
    }
    let invalid: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM items i LEFT JOIN partitions p ON p.id=i.partition_id
        LEFT JOIN credential_groups g ON g.id=i.group_id WHERE p.id IS NULL OR (i.group_id IS NOT NULL AND (g.id IS NULL OR g.partition_id<>i.partition_id
        OR (g.scope<>'shared' AND g.scope<>CASE i.kind WHEN 'ssh_key' THEN 'ssh' WHEN 'server_login' THEN 'server' ELSE i.kind END))))
        OR EXISTS(SELECT 1 FROM credential_groups g LEFT JOIN partitions p ON p.id=g.partition_id WHERE p.id IS NULL
        OR g.scope NOT IN ('shared','login','totp','ssh','server','passkey','recovery_codes','secure_note'))",[],|r|r.get(0))?;
    if invalid { return Err(error("invalid")); }
    let parts: BTreeMap<String,String> = rows(conn,"SELECT id,partition_id FROM items",[])?.into_iter()
        .map(|r|(r["id"].as_str().unwrap_or("").into(),r["partition_id"].as_str().unwrap_or("").into())).collect();
    for (source,target) in edges(conn)? {
        if parts.get(&source).is_none() || parts.get(&source) != parts.get(&target) { return Err(error("crossLink")); }
    }
    Ok(())
}

pub fn item_partition(conn: &Connection, item: &str) -> Result<String> {
    conn.query_row("SELECT partition_id FROM items WHERE id=?1",[item],|r|r.get(0)).map_err(|_|error("notFound"))
}

pub fn same_credentials(conn: &Connection, login: &str, totp: &str) -> Result<bool> {
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM login_credentials l JOIN items a ON a.id=l.item_id
        JOIN totp_credentials t ON t.id=?2 JOIN items b ON b.id=t.item_id
        WHERE l.id=?1 AND a.partition_id=b.partition_id)",params![login,totp],|r|r.get(0))?)
}

/// 列表只附加分区元数据；凭据内容不参与分区标签或迁移预览。
pub fn annotate(conn: &Connection, payload: &mut Value, scope: Option<&str>) -> Result<()> {
    fn row(conn: &Connection, value: &mut Value) -> Result<()> {
        let Some(object)=value.as_object_mut() else { return Ok(()); };
        let id=object.get("item_id").or_else(||object.get("id")).or_else(||object.get("credential_id"))
            .and_then(Value::as_str).unwrap_or("").to_string();
        if id.is_empty() { return Ok(()); }
        let metadata: Option<(String,String,i64,Option<i64>)>=conn.query_row("SELECT i.partition_id,p.name,i.updated_at_ms,(SELECT last_used_at_ms FROM local_usage WHERE item_id=i.id) FROM items i JOIN partitions p ON p.id=i.partition_id
          WHERE i.id=?1 OR i.id IN (SELECT item_id FROM login_credentials WHERE id=?1 UNION SELECT item_id FROM totp_credentials WHERE id=?1
          UNION SELECT item_id FROM ssh_keys WHERE id=?1 UNION SELECT item_id FROM recovery_code_items WHERE id=?1
          UNION SELECT item_id FROM server_login_profiles WHERE id=?1 UNION SELECT item_id FROM passkey_credentials WHERE credential_id=?1)
          UNION ALL SELECT g.partition_id,p.name,g.updated_at_ms,NULL FROM credential_groups g JOIN partitions p ON p.id=g.partition_id WHERE g.id=?1 LIMIT 1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((id,name,updated,used))=metadata {
            object.insert("partition_id".into(),json!(id)); object.insert("partition_name".into(),json!(name));
            object.insert("updated_at_ms".into(),json!(updated)); object.insert("last_used_at_ms".into(),json!(used));
        }
        Ok(())
    }
    if let Some(requests)=payload.get_mut("requests").and_then(Value::as_array_mut) {
        for request in requests { annotate(conn,request,None)?; }
    }
    for key in ["items","candidates"] {
        if let Some(values)=payload.get_mut(key).and_then(Value::as_array_mut) {
            for value in values.iter_mut() { row(conn,value)?; }
            if let Some(scope)=scope { values.retain(|v|v["partition_id"].as_str()==Some(scope)); }
        }
    }
    // 可选账号列表已带分区信息，不再让逐项元数据查询影响通行密钥确认。
    if let Some(scope)=scope {
        if let Some(values)=payload.get_mut("login_candidates").and_then(Value::as_array_mut) {
            values.retain(|v|v["partition_id"].as_str()==Some(scope));
        }
    }
    for key in ["credential","item"] {
        if let Some(value)=payload.get_mut(key) { row(conn,value)?; }
    }
    row(conn,payload)
}

pub fn create_note(conn: &Connection, partition: &str, title: &str, text: &str) -> Result<Value> {
    require(conn,partition)?;
    if title.trim().is_empty() || title.len()>1000 || text.len()>1_000_000 { return Err(error("invalid")); }
    let tx=conn.unchecked_transaction()?;
    let id=uuid::Uuid::new_v4().to_string(); let ts=now_ms();
    let details=ItemDetails { notes:text.into(), ..Default::default() };
    tx.execute("INSERT INTO items(id,kind,title,current_revision,created_at_ms,updated_at_ms,details_json,partition_id)
        VALUES (?1,'secure_note',?2,?3,?4,?4,?5,?6)",params![id,title.trim(),new_revision(),ts,
        serde_json::to_string(&details).map_err(|_|error("invalid"))?,partition])?;
    crate::mark_restore_dirty(&tx)?;tx.commit()?;
    Ok(json!({"item_id":id}))
}

pub fn import_ssh_key(conn: &Connection, partition: &str, label: &str, pem: &str, passphrase: &str) -> Result<Value> {
    crate::ssh_transfer::import_key_in_partition(conn,partition,label,pem,passphrase)
}

pub fn preview(conn: &Connection, selected: &[String], target: &str) -> Result<Value> {
    preview_with_group(conn, selected, target, None, None)
}

pub fn preview_with_group(conn: &Connection, selected: &[String], target: &str, target_group_name: Option<&str>, target_group_id: Option<&str>) -> Result<Value> {
    require(conn,target)?;
    if selected.is_empty() || selected.len()>10000 { return Err(error("selection")); }
    // 已有分组按 ID 落点。同名共享分组存在时，按名称会选中 ID 最小的另一个分组。
    let target_group_id = match target_group_id.map(str::trim).filter(|id| !id.is_empty()) {
        Some(id) => {
            if uuid::Uuid::parse_str(id).is_err() { return Err(error("notFound")); }
            let found: Option<(String, String)> = conn.query_row(
                "SELECT partition_id, scope FROM credential_groups WHERE id=?1",
                [id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
            let Some((partition, scope)) = found else { return Err(error("notFound")); };
            if partition != target || scope != "shared" { return Err(error("groupScope")); }
            Some(id.to_string())
        }
        None => None,
    };
    let target_group_name = if target_group_id.is_some() { None } else { target_group_name.map(str::trim) };
    if let Some(name) = target_group_name {
        if name.is_empty() || name.chars().count()>80 || name.chars().any(char::is_control)
            || name.eq_ignore_ascii_case("internal_work") { return Err(error("groupName")); }
    }
    let items = rows(conn,"SELECT i.id,i.kind,i.title,i.partition_id,i.group_id,i.current_revision,i.trashed,
        p.name AS partition_name,g.name AS group_name,
        COALESCE((SELECT username FROM login_credentials WHERE item_id=i.id),(SELECT account FROM totp_credentials WHERE item_id=i.id),'') AS account
        FROM items i JOIN partitions p ON p.id=i.partition_id LEFT JOIN credential_groups g ON g.id=i.group_id ORDER BY i.id",[])?;
    let relations = edges(conn)?;
    let mut adjacency: BTreeMap<String,BTreeSet<String>> = BTreeMap::new();
    for (a,b) in &relations { adjacency.entry(a.clone()).or_default().insert(b.clone()); adjacency.entry(b.clone()).or_default().insert(a.clone()); }
    let known: BTreeSet<_> = items.iter().filter_map(|r|r["id"].as_str()).collect();
    if selected.iter().any(|id|!known.contains(id.as_str())) { return Err(error("notFound")); }
    let selected_set: BTreeSet<_> = selected.iter().cloned().collect();
    let moved: Vec<_> = items.iter().filter(|r| selected_set.contains(r["id"].as_str().unwrap_or("")) && r["partition_id"]!=target).cloned().collect();
    let moved_ids: BTreeSet<String> = moved.iter().filter_map(|r| r["id"].as_str().map(str::to_string)).collect();
    let mut dependency_ids = BTreeSet::new();
    for id in &moved_ids {
        if let Some(links) = adjacency.get(id) {
            for linked in links {
                if !moved_ids.contains(linked) { dependency_ids.insert(linked.clone()); }
            }
        }
    }
    let dependencies: Vec<_> = items.iter().filter(|r| dependency_ids.contains(r["id"].as_str().unwrap_or(""))).cloned().collect();
    // 整体图的修订也参与预览指纹，防止确认后新增的反向引用被悄悄带入迁移。
    let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&json!({"items":items,"edges":relations,"target":target,"selected":selected.iter().collect::<BTreeSet<_>>(),"target_group_name":target_group_name,"target_group_id":target_group_id,
        "partitions":rows(conn,"SELECT * FROM partitions ORDER BY id",[])?,"groups":rows(conn,"SELECT * FROM credential_groups ORDER BY id",[]) ?}))
        .map_err(|_|error("invalid"))?));
    Ok(json!({"items":moved,"dependencies":dependencies,"count":moved.len(),"selected_count":selected.len(),"fingerprint":fingerprint,"target_partition_id":target,"target_group_name":target_group_name,"target_group_id":target_group_id}))
}

pub fn migrate(conn: &Connection, selected: &[String], target: &str, expected: &str) -> Result<Value> {
    migrate_with_group(conn, selected, target, expected, None, None)
}

pub fn migrate_with_group(conn: &Connection, selected: &[String], target: &str, expected: &str, target_group_name: Option<&str>, target_group_id: Option<&str>) -> Result<Value> {
    let tx = conn.unchecked_transaction()?;
    let plan = preview_with_group(&tx,selected,target,target_group_name,target_group_id)?;
    if plan["fingerprint"].as_str()!=Some(expected) { return Err(CoreError::Conflict); }
    // 关联迁移可能包含不同类型，统一归组只使用目标分区的共享分组。
    // 创建与迁移在同一事务，取消预览或迁移失败都不会留下空分组。
    let target_group = if plan["count"].as_u64().unwrap_or(0)>0 {
        if let Some(id) = plan["target_group_id"].as_str() {
            Some(id.to_string())
        } else if let Some(name) = plan["target_group_name"].as_str() {
            let existing:Option<String>=tx.query_row("SELECT id FROM credential_groups WHERE partition_id=?1 AND scope='shared' AND lower(name)=lower(?2) ORDER BY id LIMIT 1",
                params![target,name],|r|r.get(0)).optional()?;
            Some(match existing { Some(id)=>id, None=>crate::credential_groups::create_credential_group_in_partition(&tx,target,"shared",name)?.id })
        } else { None }
    } else { None };
    tx.execute("INSERT OR REPLACE INTO sync_state VALUES ('partition_moving','true')",[])?;
    let mut groups = BTreeMap::<String,String>::new();
    for item in plan["items"].as_array().ok_or_else(||error("invalid"))? {
        let id = item["id"].as_str().ok_or_else(||error("invalid"))?;
        let group = if let Some(group)=&target_group { Some(group.clone()) } else if let Some(old)=item["group_id"].as_str() {
            if let Some(mapped)=groups.get(old) { Some(mapped.clone()) } else {
                let (scope,name):(String,String)=tx.query_row("SELECT scope,name FROM credential_groups WHERE id=?1",[old],|r|Ok((r.get(0)?,r.get(1)?)))?;
                let existing:Option<String>=tx.query_row("SELECT id FROM credential_groups WHERE partition_id=?1 AND scope=?2 AND lower(name)=lower(?3) ORDER BY id LIMIT 1",
                    params![target,scope,name],|r|r.get(0)).optional()?;
                let mapped=if let Some(id)=existing { id } else { crate::credential_groups::create_credential_group_in_partition(&tx,target,&scope,&name)?.id };
                groups.insert(old.into(),mapped.clone()); Some(mapped)
            }
        } else { None };
        let revision=new_revision(); let ts=now_ms();
        tx.execute("UPDATE items SET partition_id=?1,group_id=?2,current_revision=?3,updated_at_ms=?4 WHERE id=?5",params![target,group,revision,ts,id])?;
        for table in ["login_credentials","totp_credentials","ssh_keys","recovery_code_items","server_login_profiles"] {
            tx.execute(&format!("UPDATE {table} SET current_revision=?1,updated_at_ms=?2 WHERE item_id=?3"),params![revision,ts,id])?;
        }
    }
    crate::associations::break_cross_partition(&tx)?;
    validate(&tx)?;
    tx.execute("DELETE FROM sync_state WHERE key='partition_moving'",[])?;
    crate::mark_restore_dirty(&tx)?; tx.commit()?;
    Ok(json!({"migrated":plan["count"]}))
}

/// 约束位于数据库写入边界，导入/编辑等入口都无法绕过；整批迁移和同步在提交前另做全量关系校验。
pub(crate) fn install_constraints(conn: &Connection) -> Result<()> {
    let normal="NOT EXISTS(SELECT 1 FROM sync_state WHERE key IN ('applying','partition_moving'))";
    for event in ["INSERT","UPDATE"] {
        conn.execute_batch(&format!("CREATE TRIGGER partition_item_{event} BEFORE {event} ON items WHEN {normal}
BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM partitions WHERE id=NEW.partition_id) THEN RAISE(ABORT,'partitions.errors.notFound') END;
 SELECT CASE WHEN NEW.group_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM credential_groups WHERE id=NEW.group_id AND partition_id=NEW.partition_id) THEN RAISE(ABORT,'partitions.errors.crossGroup') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM json_each(NEW.details_json,'$.related_item_ids') j JOIN items t ON t.id=j.value WHERE t.partition_id<>NEW.partition_id)
 OR EXISTS(SELECT 1 FROM json_each(NEW.details_json,'$.linked_mfa_ids') j JOIN totp_credentials t ON t.id=j.value JOIN items i ON i.id=t.item_id WHERE i.partition_id<>NEW.partition_id)
 THEN RAISE(ABORT,'partitions.errors.crossLink') END;
END;
CREATE TRIGGER partition_group_{event} BEFORE {event} ON credential_groups WHEN {normal}
BEGIN SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM partitions WHERE id=NEW.partition_id) THEN RAISE(ABORT,'partitions.errors.notFound') END; END;"))?;
        for (table,fields) in [("login_credentials",vec![("linked_totp_id","totp_credentials")]),
            ("server_login_profiles",vec![("linked_login_id","login_credentials"),("linked_totp_id","totp_credentials"),("linked_ssh_key_id","ssh_keys")])] {
            for (column,target) in fields {
                conn.execute_batch(&format!("CREATE TRIGGER partition_{table}_{column}_{event} BEFORE {event} ON {table} WHEN {normal}
BEGIN SELECT CASE WHEN EXISTS(SELECT 1 FROM items a JOIN {target} t ON t.id=NEW.{column} JOIN items b ON b.id=t.item_id
 WHERE a.id=NEW.item_id AND a.partition_id<>b.partition_id) THEN RAISE(ABORT,'partitions.errors.crossLink') END; END;"))?;
            }
        }
    }
    conn.execute_batch("CREATE TRIGGER credential_link_partition_insert BEFORE INSERT ON credential_links
WHEN NOT EXISTS(SELECT 1 FROM sync_state WHERE key IN ('applying','partition_moving'))
BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM items a JOIN items b ON b.id=NEW.target_item_id
  WHERE a.id=NEW.account_item_id AND a.partition_id=b.partition_id) THEN RAISE(ABORT,'partitions.errors.crossLink') END;
END;
CREATE TRIGGER credential_link_partition_update BEFORE UPDATE ON credential_links
WHEN NOT EXISTS(SELECT 1 FROM sync_state WHERE key IN ('applying','partition_moving'))
BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM items a JOIN items b ON b.id=NEW.target_item_id
  WHERE a.id=NEW.account_item_id AND a.partition_id=b.partition_id) THEN RAISE(ABORT,'partitions.errors.crossLink') END;
END;")?;
    conn.execute_batch(&format!("CREATE TRIGGER partition_item_move BEFORE UPDATE OF partition_id ON items WHEN {normal} AND NEW.partition_id<>OLD.partition_id
BEGIN SELECT RAISE(ABORT,'partitions.errors.migrationRequired'); END;
CREATE TRIGGER partition_group_move BEFORE UPDATE OF partition_id ON credential_groups WHEN {normal} AND NEW.partition_id<>OLD.partition_id
BEGIN SELECT RAISE(ABORT,'partitions.errors.migrationRequired'); END;
CREATE TRIGGER partition_deleted BEFORE DELETE ON partitions WHEN {normal}
BEGIN
 SELECT CASE WHEN OLD.id='{PERSONAL}' THEN RAISE(ABORT,'partitions.errors.defaultDelete') END;
 SELECT CASE WHEN EXISTS(SELECT 1 FROM items WHERE partition_id=OLD.id) OR EXISTS(SELECT 1 FROM credential_groups WHERE partition_id=OLD.id) THEN RAISE(ABORT,'partitions.errors.notEmpty') END;
END;"))?;
    Ok(())
}
