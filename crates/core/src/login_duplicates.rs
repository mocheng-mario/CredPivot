use crate::credential_management::{details_for, rows, ItemDetails};
use crate::repo::{new_revision, now_ms};
use crate::{CoreError, Result};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn identity(origin: &str, username: &str) -> Result<(String, String)> {
    let url = url::Url::parse(origin).map_err(|_| CoreError::format("网站地址无效"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(CoreError::format("仅支持整理网站账密"));
    }
    // 账号大小写可能有业务含义，不做忽略大小写或去空格的合并。
    Ok((format!("{}:{}", url.host_str().unwrap_or_default(), url.port_or_known_default().unwrap_or(0)), username.into()))
}

fn metadata(conn: &Connection, partition: &str) -> Result<Vec<Value>> {
    rows(conn,"SELECT i.id,i.title,i.current_revision,i.partition_id,i.group_id,i.updated_at_ms,c.id AS credential_id,
        c.origin,c.username,g.name AS group_name FROM items i JOIN login_credentials c ON c.item_id=i.id
        LEFT JOIN credential_groups g ON g.id=i.group_id WHERE i.trashed=0 AND i.partition_id=?1
        ORDER BY i.updated_at_ms DESC,i.id",[partition])
}

pub(crate) fn list(conn: &Connection, partition: &str) -> Result<Value> {
    crate::partitions::require(conn,partition)?;
    let mut groups = BTreeMap::<(String,String),Vec<Value>>::new();
    for row in metadata(conn,partition)? {
        if let Ok(key)=identity(row["origin"].as_str().unwrap_or_default(),row["username"].as_str().unwrap_or_default()) {
            groups.entry(key).or_default().push(row);
        }
    }
    Ok(json!({"groups":groups.into_iter().filter(|(_,v)|v.len()>1).map(|((host,username),items)|
        json!({"host":host,"username":username,"items":items})).collect::<Vec<_>>()}))
}

fn union_strings(target: &mut Vec<String>, source: &[String]) {
    for value in source { if !target.contains(value) { target.push(value.clone()); } }
}

fn merge_details(mut target: ItemDetails, sources: &[(String,ItemDetails)], excluded: &BTreeSet<String>) -> Result<ItemDetails> {
    for (title,source) in sources {
        if !source.notes.is_empty() && source.notes != target.notes {
            target.notes.push_str(&format!("\n\n—— {title} ——\n{}",source.notes));
        }
        union_strings(&mut target.tags,&source.tags);
        union_strings(&mut target.related_item_ids,&source.related_item_ids);
        union_strings(&mut target.linked_mfa_ids,&source.linked_mfa_ids);
        target.favorite |= source.favorite;
        for field in &source.custom_fields {
            if !target.custom_fields.iter().any(|f|f.name==field.name && f.value==field.value && f.secret==field.secret) {
                target.custom_fields.push(field.clone());
            }
        }
        for (dest,rules) in [(&mut target.uris,&source.uris),(&mut target.pending_mfa_uris,&source.pending_mfa_uris)] {
            for rule in rules {
                if !dest.iter().any(|r|r.uri==rule.uri && r.match_mode==rule.match_mode) {
                    let mut rule=rule.clone();
                    if dest.iter().any(|r|r.id==rule.id) { rule.id=uuid::Uuid::new_v4().to_string(); }
                    dest.push(rule);
                }
            }
        }
    }
    target.related_item_ids.retain(|id|!excluded.contains(id));
    if !target.linked_mfa_ids.is_empty() { target.mfa_state="enabled".into(); }
    if target.notes.len()>1_000_000 || target.tags.len()>100 || target.custom_fields.len()>100
        || target.related_item_ids.len()>100 || target.uris.len()>100 || target.linked_mfa_ids.len()>100
        || target.pending_mfa_uris.len()>100 {
        return Err(CoreError::limit("合并后的资料过多，请先减少本次选择或整理资料"));
    }
    Ok(target)
}

fn plan(conn: &Connection, keeper: &str, sources: &[String]) -> Result<(Value, ItemDetails, Vec<Value>)> {
    let ids: BTreeSet<String>=sources.iter().cloned().collect();
    if ids.is_empty() || ids.len()>99 || ids.contains(keeper) || ids.len()!=sources.len() {
        return Err(CoreError::format("合并记录选择无效"));
    }
    let partition=crate::partitions::item_partition(conn,keeper)?;
    let available=metadata(conn,&partition)?;
    let kept=available.iter().find(|r|r["id"]==keeper).ok_or(CoreError::Conflict)?;
    let key=identity(kept["origin"].as_str().unwrap_or_default(),kept["username"].as_str().unwrap_or_default())?;
    let mut selected=vec![kept.clone()];
    for id in &ids {
        let row=available.iter().find(|r|r["id"]==id.as_str()).ok_or(CoreError::Conflict)?;
        if identity(row["origin"].as_str().unwrap_or_default(),row["username"].as_str().unwrap_or_default())? != key {
            return Err(CoreError::format("只能合并同一分区、域名端口和账号的账密"));
        }
        selected.push(row.clone());
    }
    let mut selected_logins=Vec::new();
    let mut histories=Vec::new();
    let mut candidates=Vec::new();
    let mut details=Vec::new();
    let mut fingerprint_details=Vec::new();
    for item in &mut selected {
        let id=item["id"].as_str().ok_or(CoreError::Conflict)?.to_string();
        let credential=item["credential_id"].as_str().ok_or(CoreError::Conflict)?.to_string();
        let login=crate::get_login_secret(conn,&credential)?;
        let mut extra=details_for(conn,&id)?;
        if let Some(mfa)=login.linked_totp_id.as_ref() { union_strings(&mut extra.linked_mfa_ids,std::slice::from_ref(mfa)); }
        fingerprint_details.push(json!({"id":id,"details":extra}));
        item["mfa_count"]=json!(extra.linked_mfa_ids.len());
        let mut passkeys=0;
        for related in &extra.related_item_ids {
            if conn.query_row("SELECT EXISTS(SELECT 1 FROM items WHERE id=?1 AND kind='passkey' AND trashed=0)",
                [related],|r|r.get::<_,bool>(0))? { passkeys+=1; }
        }
        item["passkey_count"]=json!(passkeys);
        item["notes_length"]=json!(extra.notes.chars().count());
        item["custom_field_count"]=json!(extra.custom_fields.len());
        histories.extend(rows(conn,"SELECT * FROM password_history WHERE credential_id=?1 ORDER BY id",[&credential])?);
        candidates.extend(rows(conn,"SELECT * FROM password_candidates WHERE credential_id=?1 ORDER BY id",[&credential])?);
        details.push((item["title"].as_str().unwrap_or_default().to_string(),extra));
        selected_logins.push(login);
    }
    if candidates.len()>10 { return Err(CoreError::limit("合并后候选密码超过 10 个，请先整理候选密码")); }
    for (item,login) in selected.iter_mut().zip(&selected_logins) {
        item["password_matches_keeper"]=json!(login.password==selected_logins[0].password);
        let servers=rows(conn,"SELECT id,linked_totp_id FROM server_login_profiles WHERE linked_login_id=?1",[&login.id])?;
        item["server_count"]=json!(servers.len());
        if login.id!=selected_logins[0].id && !servers.is_empty() {
            if login.password!=selected_logins[0].password {
                return Err(CoreError::format("待合并账密仍被服务器引用且密码不同，请保留该记录作为主记录，或先调整服务器引用"));
            }
            if login.linked_totp_id.is_none() && selected_logins[0].linked_totp_id.is_some()
                && servers.iter().any(|s|s["linked_totp_id"].is_null()) {
                return Err(CoreError::format("合并会改变服务器继承的 MFA，请先明确服务器的 MFA 关联，或选择没有默认 MFA 的主记录"));
            }
        }
    }
    let mut excluded=ids.clone(); excluded.insert(keeper.into());
    let merged=merge_details(details[0].1.clone(),&details[1..],&excluded)?;
    // 修订、候选、历史和资料共同绑定到预览，不能用旧预览覆盖另一端的修改。
    let fingerprint=hex::encode(Sha256::digest(serde_json::to_vec(&json!({
        "selected":selected,"details":fingerprint_details,"history":histories,"candidates":candidates,
        "revisions":rows(conn,"SELECT id,current_revision FROM items ORDER BY id",[])?
    })).map_err(|_|CoreError::format("无法生成合并预览"))?));
    Ok((json!({"items":selected,"keeper":keeper,"fingerprint":fingerprint,
        "history_count":histories.len(),"candidate_count":candidates.len(),
        "merged_mfa_count":merged.linked_mfa_ids.len(),"merged_related_count":merged.related_item_ids.len()}),merged,selected))
}

pub(crate) fn preview(conn: &Connection, keeper: &str, sources: &[String]) -> Result<Value> {
    let tx=conn.unchecked_transaction()?;
    let (preview,_,_)=plan(&tx,keeper,sources)?;
    tx.commit()?;
    Ok(preview)
}

fn bump(conn: &Connection, item: &str) -> Result<()> {
    let revision=new_revision(); let ts=now_ms();
    conn.execute("UPDATE items SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",params![revision,ts,item])?;
    for table in ["login_credentials","totp_credentials","ssh_keys","recovery_code_items","server_login_profiles"] {
        conn.execute(&format!("UPDATE {table} SET current_revision=?1,updated_at_ms=?2 WHERE item_id=?3"),params![revision,ts,item])?;
    }
    Ok(())
}

pub(crate) fn apply(conn: &Connection, keeper: &str, sources: &[String], expected: &str) -> Result<Value> {
    let tx=conn.unchecked_transaction()?;
    let (preview,merged,selected)=plan(&tx,keeper,sources)?;
    if preview["fingerprint"].as_str()!=Some(expected) { return Err(CoreError::Conflict); }
    let kept=selected[0]["credential_id"].as_str().ok_or(CoreError::Conflict)?;
    let active:String=tx.query_row("SELECT active_password_revision FROM login_credentials WHERE id=?1",[kept],|r|r.get(0))?;
    for item in &selected[1..] {
        let source=item["credential_id"].as_str().ok_or(CoreError::Conflict)?;
        let original=crate::get_login_secret(&tx,source)?;
        let since:i64=tx.query_row("SELECT password_active_since_ms FROM login_credentials WHERE id=?1",[source],|r|r.get(0))?;
        if !item["password_matches_keeper"].as_bool().unwrap_or(false) {
            tx.execute("INSERT INTO password_history(id,credential_id,secret,activated_at_ms,retired_at_ms) VALUES (?1,?2,?3,?4,?5)",
                params![uuid::Uuid::new_v4().to_string(),kept,original.password,since,now_ms()])?;
        }
        // 原记录仍在回收站；复制历史和候选，不从原记录移走，便于单独恢复查看。
        for row in rows(&tx,"SELECT secret,activated_at_ms,retired_at_ms FROM password_history WHERE credential_id=?1",[source])? {
            tx.execute("INSERT INTO password_history(id,credential_id,secret,activated_at_ms,retired_at_ms) VALUES (?1,?2,?3,?4,?5)",
                params![uuid::Uuid::new_v4().to_string(),kept,row["secret"].as_str(),row["activated_at_ms"].as_i64(),row["retired_at_ms"].as_i64()])?;
        }
        let source_active:String=tx.query_row("SELECT active_password_revision FROM login_credentials WHERE id=?1",[source],|r|r.get(0))?;
        for row in rows(&tx,"SELECT secret,created_at_ms,base_active_revision FROM password_candidates WHERE credential_id=?1",[source])? {
            let base=if row["base_active_revision"].as_str()==Some(source_active.as_str()) { active.clone() }
                else if row["base_active_revision"].as_str()==Some(active.as_str()) { new_revision() }
                else { row["base_active_revision"].as_str().unwrap_or_default().to_string() };
            tx.execute("INSERT INTO password_candidates(id,credential_id,base_active_revision,secret,created_at_ms) VALUES (?1,?2,?3,?4,?5)",
                params![uuid::Uuid::new_v4().to_string(),kept,base,row["secret"].as_str(),row["created_at_ms"].as_i64()])?;
        }
        for server in rows(&tx,"SELECT id,item_id FROM server_login_profiles WHERE linked_login_id=?1",[source])? {
            tx.execute("UPDATE server_login_profiles SET linked_login_id=?1,linked_totp_id=COALESCE(linked_totp_id,?2) WHERE id=?3",
                params![kept,original.linked_totp_id,server["id"].as_str()])?;
            bump(&tx,server["item_id"].as_str().ok_or(CoreError::Conflict)?)?;
        }
        tx.execute("UPDATE import_mappings SET local_item_id=?1 WHERE local_item_id=?2",params![keeper,item["id"].as_str()])?;
    }
    tx.execute("UPDATE items SET details_json=?1 WHERE id=?2",params![serde_json::to_string(&merged).map_err(|_|CoreError::format("无法保存合并资料"))?,keeper])?;
    let source_ids:BTreeSet<_>=sources.iter().cloned().collect();
    for row in rows(&tx,"SELECT id,details_json FROM items ORDER BY id",[])? {
        let id=row["id"].as_str().ok_or(CoreError::Conflict)?;
        if source_ids.contains(id) { continue; }
        let mut details=details_for(&tx,id)?;
        if !details.related_item_ids.iter().any(|id|source_ids.contains(id)) { continue; }
        details.related_item_ids=details.related_item_ids.into_iter().map(|id|if source_ids.contains(&id) {keeper.to_string()} else {id})
            .filter(|related|related!=id).collect::<BTreeSet<_>>().into_iter().collect();
        tx.execute("UPDATE items SET details_json=?1 WHERE id=?2",params![serde_json::to_string(&details).map_err(|_|CoreError::format("无法更新关联资料"))?,id])?;
        bump(&tx,id)?;
    }
    for source in sources { crate::repo_m2::trash_item_in_tx(&tx,source)?; }
    bump(&tx,keeper)?;
    crate::partitions::validate(&tx)?;
    crate::mark_restore_dirty(&tx)?;
    tx.commit()?;
    Ok(json!({"merged":sources.len(),"keeper":keeper}))
}
