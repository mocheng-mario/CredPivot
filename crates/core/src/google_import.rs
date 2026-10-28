use crate::credential_management::{ItemDetails, UriRule};
use crate::repo::{new_revision, now_ms};
use crate::{CoreError, Result};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
struct CsvRow {
    line: usize,
    fields: Vec<String>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Login {
    line: usize,
    name: String,
    origin: String,
    username: String,
    password: String,
    note: String,
    state: String,
    reason: String,
}

fn csv_error(line: usize) -> CoreError {
    // 不在错误中回显 CSV 内容，字段可能是明文密码或备注。
    CoreError::format(format!("Google CSV 第 {line} 行格式无效，请检查引号和列数"))
}

/// 处理引号、转义引号、逗号和字段内换行，不能使用逐行 split(',')。
fn csv_rows(input: &str) -> Result<Vec<CsvRow>> {
    let mut rows = Vec::new();
    let mut fields = Zeroizing::new(Vec::<String>::new());
    let mut field = Zeroizing::new(String::new());
    let mut quoted = false;
    let mut closed = false;
    let mut line = 1;
    let mut start = 1;
    let mut chars = input.strip_prefix('\u{feff}').unwrap_or(input).chars().peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    quoted = false;
                    closed = true;
                }
            } else {
                field.push(ch);
                if ch == '\n' || (ch == '\r' && chars.peek() != Some(&'\n')) { line += 1; }
            }
        } else if ch == ',' || ch == '\n' || ch == '\r' {
            fields.push(std::mem::take(&mut *field));
            closed = false;
            if fields.len() > 64 { return Err(csv_error(start)); }
            if ch != ',' {
                if ch == '\r' && chars.peek() == Some(&'\n') { chars.next(); }
                if fields.iter().any(|v| !v.is_empty()) {
                    rows.push(CsvRow { line: start, fields: std::mem::take(&mut *fields) });
                } else {
                    fields.clear();
                }
                line += 1;
                start = line;
            }
        } else if ch == '"' && field.is_empty() && !closed {
            quoted = true;
        } else if closed || ch == '"' {
            return Err(csv_error(start));
        } else {
            field.push(ch);
        }
        if field.len() > 1_000_000 { return Err(CoreError::limit("Google CSV 单个字段不能超过 1MB")); }
        if rows.len() > 10_001 { return Err(CoreError::limit("Google CSV 一次最多导入 10000 条记录")); }
    }
    if quoted { return Err(csv_error(start)); }
    if closed || !field.is_empty() || !fields.is_empty() {
        fields.push(std::mem::take(&mut *field));
        if fields.len() > 64 { return Err(csv_error(start)); }
        rows.push(CsvRow { line: start, fields: std::mem::take(&mut *fields) });
    }
    if rows.len() < 2 { return Err(CoreError::format("Google CSV 中没有密码记录")); }
    if rows.len() > 10_001 { return Err(CoreError::limit("Google CSV 一次最多导入 10000 条记录")); }
    Ok(rows)
}

fn logins(input: &str) -> Result<Vec<Login>> {
    let rows = csv_rows(input)?;
    let header = &rows[0];
    let mut columns = HashMap::new();
    for (index, value) in header.fields.iter().enumerate() {
        if columns.insert(value.trim().to_ascii_lowercase(), index).is_some() {
            return Err(CoreError::format("Google CSV 包含重复的列名"));
        }
    }
    if ["url", "username", "password"].iter().any(|name| !columns.contains_key(*name)) {
        return Err(CoreError::format("请选择 Google 导出的 CSV，须包含 url、username、password 列"));
    }
    let mut records = Vec::new();
    for row in &rows[1..] {
        if row.fields.len() != header.fields.len() { return Err(csv_error(row.line)); }
        let value = |key: &str| columns.get(key).map(|index| row.fields[*index].as_str()).unwrap_or("");
        let raw_url = value("url").trim();
        let parsed = url::Url::parse(raw_url).ok();
        let valid_url = parsed.as_ref().is_some_and(|url| {
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
                && url.username().is_empty() && url.password().is_none()
                && raw_url.len() <= 4096 && !raw_url.chars().any(char::is_control)
        });
        let name = if value("name").trim().is_empty() {
            parsed.as_ref().and_then(|url| url.host_str()).unwrap_or("").to_string()
        } else { value("name").trim().to_string() };
        let reason = if !valid_url { "import.google.invalidWebsite" }
            else if value("password").is_empty() { "import.google.emptyPassword" }
            else if value("password").len() > 65536 || value("username").len() > 4096 || name.len() > 4096 {
                "import.google.fieldTooLong"
            } else { "" };
        records.push(Login {
            line: row.line, name,
            origin: if valid_url { parsed.unwrap().origin().ascii_serialization() } else { String::new() },
            // 账号与密码不 trim，避免改变 Google 实际保存的凭据。
            username: value("username").into(), password: value("password").into(),
            note: columns.get("note").or_else(|| columns.get("notes"))
                .map(|index| row.fields[*index].clone()).unwrap_or_default(),
            state: if reason.is_empty() { "new" } else { "invalid" }.into(), reason: reason.into(),
        });
    }
    Ok(records)
}

fn credential_hash(origin: &str, username: &str, password: Option<&str>) -> [u8; 32] {
    let mut hash = Sha256::new();
    for value in [Some(origin), Some(username), password].into_iter().flatten() {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}

fn prepare(conn: &Connection, input: &str, partition: &str, group: Option<&str>, new_group: &str)
    -> Result<(Value, Vec<Login>)> {
    crate::partitions::require(conn, partition)?;
    let new_group = new_group.trim();
    if let Some(group) = group {
        if !new_group.is_empty() || !conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM credential_groups WHERE id=?1 AND partition_id=?2 AND scope='login')",
            params![group, partition], |r| r.get::<_, bool>(0))? {
            return Err(CoreError::format("请选择目标分区内的登录密码分组"));
        }
    }
    if !new_group.is_empty() {
        if new_group.chars().count() > 80 || new_group.chars().any(char::is_control)
            || new_group.eq_ignore_ascii_case("internal_work") {
            return Err(CoreError::format("partitions.errors.groupName"));
        }
        if conn.query_row("SELECT EXISTS(SELECT 1 FROM credential_groups WHERE partition_id=?1 AND scope='login' AND lower(name)=lower(?2))",
            params![partition,new_group], |r| r.get::<_,bool>(0))? {
            return Err(CoreError::format("partitions.errors.groupDuplicate"));
        }
    }
    let mut token = Sha256::new();
    token.update(input.as_bytes());
    token.update(json!([partition,group,new_group]).to_string().as_bytes());
    let mut accounts = HashSet::new();
    let mut exact = HashSet::new();
    let mut statement = conn.prepare("SELECT i.id,i.current_revision,c.origin,c.username,c.secret FROM login_credentials c JOIN items i ON i.id=c.item_id WHERE i.partition_id=?1 AND i.trashed=0 ORDER BY i.id")?;
    let mut rows = statement.query([partition])?;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let revision: String = row.get(1)?;
        let stored_origin: String = row.get(2)?;
        let origin = url::Url::parse(stored_origin.trim())
            .map(|url| url.origin().ascii_serialization()).unwrap_or(stored_origin);
        let username: String = row.get(3)?;
        let password = Zeroizing::new(row.get::<_,String>(4)?);
        token.update(id.as_bytes()); token.update(revision.as_bytes());
        accounts.insert(credential_hash(&origin, &username, None));
        exact.insert(credential_hash(&origin, &username, Some(password.as_str())));
    }
    let mut records = logins(input)?;
    for row in &mut records {
        if row.state == "invalid" { continue; }
        let account = credential_hash(&row.origin, &row.username, None);
        let identity = credential_hash(&row.origin, &row.username, Some(&row.password));
        row.state = if exact.contains(&identity) { "duplicate" }
            else if accounts.contains(&account) { "conflict" } else { "new" }.into();
        accounts.insert(account); exact.insert(identity);
    }
    let items: Vec<Value> = records.iter().enumerate().map(|(index, row)| json!({
        "row_id":index,"line":row.line,"title":row.name,"origin":row.origin,
        "username":row.username,"state":row.state,"reason":row.reason,
    })).collect();
    Ok((json!({"items":items,"preview_token":hex::encode(token.finalize())}), records))
}

pub(crate) fn preview(conn: &Connection, input: &str, partition: &str, group: Option<&str>, new_group: &str) -> Result<Value> {
    Ok(prepare(conn,input,partition,group,new_group)?.0)
}

pub(crate) fn apply(conn: &Connection, input: &str, partition: &str, group: Option<&str>, new_group: &str,
    selected: &[usize], preview_token: &str) -> Result<Value> {
    let tx = conn.unchecked_transaction()?;
    let (preview, records) = prepare(&tx,input,partition,group,new_group)?;
    if preview["preview_token"].as_str() != Some(preview_token) { return Err(CoreError::Conflict); }
    let selected: HashSet<usize> = selected.iter().copied().collect();
    if selected.is_empty() || selected.iter().any(|index| records.get(*index)
        .is_none_or(|row| !matches!(row.state.as_str(), "new" | "conflict"))) {
        return Err(CoreError::format("请选择预览中可导入的记录"));
    }
    // 分组与全部凭据处于同一事务，失败或取消不会留下空分组或半批数据。
    let group = if new_group.trim().is_empty() { group.map(str::to_string) } else {
        Some(crate::credential_groups::create_credential_group_in_partition(&tx,partition,"login",new_group)?.id)
    };
    let mut copied = 0;
    for index in &selected {
        let row = &records[*index];
        let item = Uuid::new_v4().to_string();
        let credential = Uuid::new_v4().to_string();
        let revision = new_revision();
        let ts = now_ms();
        let mut details = ItemDetails { notes: row.note.clone(), ..Default::default() };
        let details_json = Zeroizing::new(serde_json::to_string(&details)
            .map_err(|_| CoreError::format("导入详情格式无效"))?);
        details.notes.zeroize();
        tx.execute("INSERT INTO items(id,kind,title,trashed,group_id,current_revision,created_at_ms,updated_at_ms,partition_id,details_json) VALUES (?1,'login',?2,0,?3,?4,?5,?5,?6,?7)",
            params![item,row.name,group,revision,ts,partition,&*details_json])?;
        tx.execute("INSERT INTO login_credentials(id,item_id,origin,username,secret,display_name,current_revision,created_at_ms,updated_at_ms,password_active_since_ms,active_password_revision) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8,0,?7)",
            params![credential,item,row.origin,row.username,row.password,row.name,revision,ts])?;
        crate::website_rules::save_login_website_rules(&tx,&item,&[UriRule {
            id: Uuid::new_v4().to_string(), uri: row.origin.clone(), match_mode:"exact_origin".into(),
        }])?;
        if row.state == "conflict" { copied += 1; }
    }
    crate::mark_restore_dirty(&tx)?;
    tx.commit()?;
    Ok(json!({"imported":selected.len(),"copied":copied,"skipped":records.len()-selected.len(),"partition_id":partition,"group_id":group}))
}
