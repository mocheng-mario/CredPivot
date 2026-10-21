use crate::repo::{new_revision, now_ms};
use crate::{CoreError, Result};
use rand::{rngs::OsRng, seq::SliceRandom, Rng};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// 仅通过 App 身份验证后的通道调用；浏览器不能访问历史、回收站或批量秘密。
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum VaultAction {
    GeneratePassword {
        length: usize,
        symbols: bool,
        exclude_ambiguous: bool,
    },
    PasswordVersions {
        credential_id: String,
    },
    CandidateCreate {
        credential_id: String,
        expected_revision: String,
        password: String,
    },
    CandidateActivate {
        credential_id: String,
        expected_revision: String,
        candidate_id: String,
    },
    CandidateDiscard {
        credential_id: String,
        candidate_id: String,
    },
    HistoryRestore {
        credential_id: String,
        expected_revision: String,
        history_id: String,
    },
    MarkPasswordActive {
        credential_id: String,
        expected_revision: String,
    },
    TrashList,
    TrashRestore {
        item_id: String,
        expected_revision: String,
    },
    TrashPurge {
        item_id: String,
        expected_revision: String,
    },
    ItemDetails {
        item_id: String,
    },
    ItemDetailsSave {
        item_id: String,
        expected_revision: String,
        details: ItemDetails,
        #[serde(default)]
        title: Option<String>,
    },
    NoteCreate {
        title: String,
        text: String,
    },
    ItemSearch {
        query: String,
    },
    SecurityReport,
    TotpUpdate {
        id: String,
        expected_revision: String,
        issuer: String,
        account: String,
        secret: String,
    },
    TotpStatus {
        id: String,
        min_valid_seconds: u64,
        #[serde(default)]
        passive: bool,
    },
    RecoveryEntries {
        id: String,
    },
    RecoveryEntryUse {
        id: String,
        expected_revision: String,
        entry_id: String,
        used: bool,
    },
    SshImport {
        label: String,
        pem: String,
        passphrase: String,
    },
    SshExport {
        id: String,
        passphrase: String,
    },
    BitwardenPreview {
        path: String,
        password: String,
        namespace: String,
    },
    BitwardenImport {
        path: String,
        password: String,
        namespace: String,
        choices: HashMap<String, String>,
        preview_token: String,
    },
}

impl VaultAction {
    pub fn requires_sensitive_auth(&self) -> bool {
        !matches!(
            self,
            Self::GeneratePassword { .. }
                | Self::ItemSearch { .. }
                | Self::SecurityReport
                | Self::TrashList
                | Self::NoteCreate { .. }
        )
    }
    pub fn is_passive(&self) -> bool {
        matches!(self, Self::TotpStatus { passive: true, .. })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ItemDetails {
    pub notes: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub category: String,
    pub custom_fields: Vec<CustomField>,
    pub related_item_ids: Vec<String>,
    // URI 匹配规则原样保留；自动填充仅接受 exact_origin，其他规则须用户确认后修改。
    pub uris: Vec<UriRule>,
    pub history_limit: Option<usize>,
    pub reminder_days: Option<u32>,
    pub mfa_state: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub secret: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UriRule {
    pub uri: String,
    pub match_mode: String,
}

fn id() -> String {
    Uuid::new_v4().to_string()
}
fn parse<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(|_| CoreError::format("数据格式无效"))
}
fn encode(value: &impl Serialize) -> Result<String> {
    serde_json::to_string(value).map_err(|_| CoreError::format("数据无法序列化"))
}
fn rows(conn: &Connection, sql: &str, args: impl rusqlite::Params) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare(sql)?;
    let names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut cursor = stmt.query(args)?;
    let mut result = Vec::new();
    while let Some(row) = cursor.next()? {
        let mut item = serde_json::Map::new();
        for (n, name) in names.iter().enumerate() {
            use rusqlite::types::ValueRef;
            let value = match row.get_ref(n)? {
                ValueRef::Null => Value::Null,
                ValueRef::Integer(n) => json!(n),
                ValueRef::Real(n) => json!(n),
                ValueRef::Text(s) => json!(String::from_utf8_lossy(s)),
                ValueRef::Blob(b) => {
                    use base64::Engine;
                    json!({"base64": base64::engine::general_purpose::STANDARD.encode(b)})
                }
            };
            item.insert(name.clone(), value);
        }
        result.push(Value::Object(item));
    }
    Ok(result)
}
fn active_item(conn: &Connection, item_id: &str) -> Result<String> {
    conn.query_row(
        "SELECT current_revision FROM items WHERE id=?1 AND trashed=0",
        [item_id],
        |r| r.get(0),
    )
    .map_err(|_| CoreError::format("记录不存在或已删除"))
}
fn check_revision(actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        Err(CoreError::Conflict)
    } else {
        Ok(())
    }
}
pub(crate) fn details_for(conn: &Connection, item: &str) -> Result<ItemDetails> {
    let text: String =
        conn.query_row("SELECT details_json FROM items WHERE id=?1", [item], |r| {
            r.get(0)
        })?;
    parse(&text)
}
pub(crate) fn history_limit(conn: &Connection, credential: &str) -> Result<usize> {
    let item: String = conn.query_row(
        "SELECT item_id FROM login_credentials WHERE id=?1",
        [credential],
        |r| r.get(0),
    )?;
    Ok(details_for(conn, &item)?
        .history_limit
        .unwrap_or(crate::effective_app_settings().password_history_limit))
}
pub(crate) fn trim_history(conn: &Connection, credential: &str) -> Result<()> {
    conn.execute("DELETE FROM password_history WHERE credential_id=?1 AND id NOT IN
        (SELECT id FROM password_history WHERE credential_id=?1 ORDER BY retired_at_ms DESC, id DESC LIMIT ?2)",
        params![credential, history_limit(conn, credential)? as i64])?;
    Ok(())
}
pub(crate) fn create_candidate(
    conn: &Connection,
    credential: &str,
    expected: &str,
    password: &str,
) -> Result<String> {
    if password.is_empty() || password.len() > 16384 {
        return Err(CoreError::limit("密码长度无效"));
    }
    let row = crate::get_login_secret(conn, credential)?;
    check_revision(&row.current_revision, expected)?;
    if row.password == password {
        return Err(CoreError::format("候选密码与当前密码相同"));
    }
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM password_candidates WHERE credential_id=?1",
        [credential],
        |r| r.get(0),
    )?;
    if count >= 10 {
        return Err(CoreError::limit("最多保留 10 个候选密码，请先处理已有候选"));
    }
    let active: String = conn.query_row(
        "SELECT active_password_revision FROM login_credentials WHERE id=?1",
        [credential],
        |r| r.get(0),
    )?;
    let candidate = id();
    conn.execute(
        "INSERT INTO password_candidates VALUES (?1,?2,?3,?4,?5)",
        params![candidate, credential, active, password, now_ms()],
    )?;
    Ok(candidate)
}
fn activate(conn: &Connection, credential: &str, expected: &str, candidate: &str) -> Result<()> {
    let row = crate::get_login_secret(conn, credential)?;
    check_revision(&row.current_revision, expected)?;
    let (secret, base): (String, String) = conn.query_row(
        "SELECT secret, base_active_revision FROM password_candidates WHERE id=?1 AND credential_id=?2",
        params![candidate, credential], |r| Ok((r.get(0)?, r.get(1)?)))?;
    let (active, since): (String, i64) = conn.query_row(
        "SELECT active_password_revision, password_active_since_ms FROM login_credentials WHERE id=?1", [credential], |r| Ok((r.get(0)?,r.get(1)?)))?;
    // 防止候选基于旧密码创建后覆盖另一端已启用的新密码。
    check_revision(&active, &base)?;
    let rev = new_revision();
    let ts = now_ms();
    conn.execute(
        "INSERT INTO password_history VALUES (?1,?2,?3,?4,?5)",
        params![id(), credential, row.password, since, ts],
    )?;
    conn.execute(
        "UPDATE login_credentials SET secret=?1, current_revision=?2, active_password_revision=?2,
        password_active_since_ms=?3, updated_at_ms=?3 WHERE id=?4",
        params![secret, rev, ts, credential],
    )?;
    conn.execute(
        "UPDATE items SET current_revision=?1, updated_at_ms=?2 WHERE id=?3",
        params![rev, ts, row.item_id],
    )?;
    conn.execute("DELETE FROM password_candidates WHERE id=?1", [candidate])?;
    trim_history(conn, credential)
}

/// 更新恢复码组时按码值保留稳定 ID 和使用状态，不能把旧码重新变成未使用。
pub(crate) fn sync_recovery_entries(
    conn: &Connection,
    recovery: &str,
    codes: &[String],
) -> Result<()> {
    let old = rows(
        conn,
        "SELECT id, code FROM recovery_code_entries WHERE recovery_id=?1",
        [recovery],
    )?;
    let mut retained = Vec::new();
    for (position, code) in codes.iter().enumerate() {
        if codes[..position].contains(code) {
            continue;
        }
        let entry = old
            .iter()
            .find(|v| v["code"].as_str() == Some(code.as_str()))
            .and_then(|v| v["id"].as_str())
            .map(String::from)
            .unwrap_or_else(id);
        conn.execute(
            "INSERT INTO recovery_code_entries(id,recovery_id,code,position) VALUES (?1,?2,?3,?4)
            ON CONFLICT(id) DO UPDATE SET position=excluded.position",
            params![entry, recovery, code, position as i64],
        )?;
        retained.push(entry);
    }
    for entry in old {
        let entry_id = entry["id"].as_str().unwrap_or_default();
        if !retained.iter().any(|s| s == entry_id) {
            conn.execute("DELETE FROM recovery_code_entries WHERE id=?1", [entry_id])?;
        }
    }
    Ok(())
}

fn trash_change(conn: &Connection, item: &str, expected: &str, purge: bool) -> Result<()> {
    let revision: String = conn.query_row(
        "SELECT current_revision FROM items WHERE id=?1 AND trashed=1",
        [item],
        |r| r.get(0),
    )?;
    check_revision(&revision, expected)?;
    if !purge {
        // 被删除的关联对象可能已永久清理，恢复时只保留仍然存在的引用。
        let revision = new_revision();
        let ts = now_ms();
        conn.execute("UPDATE items SET trashed=0,trashed_at_ms=NULL,current_revision=?1,updated_at_ms=?2 WHERE id=?3", params![revision,ts,item])?;
        for table in [
            "login_credentials",
            "totp_credentials",
            "ssh_keys",
            "recovery_code_items",
            "server_login_profiles",
        ] {
            conn.execute(
                &format!(
                    "UPDATE {table} SET current_revision=?1,updated_at_ms=?2 WHERE item_id=?3"
                ),
                params![revision, ts, item],
            )?;
        }
        return Ok(());
    }
    let revision = new_revision();
    let timestamp = now_ms();
    conn.execute("UPDATE items SET current_revision=?1,updated_at_ms=?2 WHERE id IN (SELECT item_id FROM login_credentials WHERE linked_totp_id IN (SELECT id FROM totp_credentials WHERE item_id=?3))", params![revision,timestamp,item])?;
    conn.execute("UPDATE login_credentials SET linked_totp_id=NULL,current_revision=?1,updated_at_ms=?2 WHERE linked_totp_id IN (SELECT id FROM totp_credentials WHERE item_id=?3)", params![revision,timestamp,item])?;
    for row in rows(
        conn,
        "SELECT id,details_json FROM items WHERE id<>?1",
        [item],
    )? {
        let mut details: ItemDetails = parse(row["details_json"].as_str().unwrap_or("{}"))?;
        if details.related_item_ids.iter().any(|id| id == item) {
            details.related_item_ids.retain(|id| id != item);
            conn.execute(
                "UPDATE items SET details_json=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4",
                params![
                    encode(&details)?,
                    new_revision(),
                    now_ms(),
                    row["id"].as_str().unwrap_or_default()
                ],
            )?;
        }
    }
    for (column, table) in [
        ("linked_login_id", "login_credentials"),
        ("linked_totp_id", "totp_credentials"),
        ("linked_ssh_key_id", "ssh_keys"),
    ] {
        let revision = new_revision();
        let timestamp = now_ms();
        conn.execute(&format!("UPDATE items SET current_revision=?1,updated_at_ms=?2 WHERE id IN (SELECT item_id FROM server_login_profiles WHERE {column} IN (SELECT id FROM {table} WHERE item_id=?3))"), params![revision,timestamp,item])?;
        conn.execute(&format!("UPDATE server_login_profiles SET {column}=NULL, current_revision=?1, updated_at_ms=?2 WHERE {column} IN (SELECT id FROM {table} WHERE item_id=?3)"), params![revision,timestamp,item])?;
    }
    conn.execute("DELETE FROM password_history WHERE credential_id IN (SELECT id FROM login_credentials WHERE item_id=?1)",[item])?;
    conn.execute("DELETE FROM password_candidates WHERE credential_id IN (SELECT id FROM login_credentials WHERE item_id=?1)",[item])?;
    conn.execute("DELETE FROM recovery_code_entries WHERE recovery_id IN (SELECT id FROM recovery_code_items WHERE item_id=?1)",[item])?;
    for table in [
        "server_login_profiles",
        "login_credentials",
        "totp_credentials",
        "ssh_keys",
        "recovery_code_items",
    ] {
        conn.execute(&format!("DELETE FROM {table} WHERE item_id=?1"), [item])?;
    }
    conn.execute("DELETE FROM local_usage WHERE item_id=?1", [item])?;
    conn.execute("DELETE FROM import_mappings WHERE local_item_id=?1", [item])?;
    conn.execute("DELETE FROM items WHERE id=?1", [item])?;
    Ok(())
}
fn security_report(conn: &Connection) -> Result<Value> {
    let all = rows(conn,"SELECT c.id,c.item_id,i.title,c.secret,c.password_active_since_ms,i.created_at_ms,i.details_json,(SELECT last_used_at_ms FROM local_usage u WHERE u.item_id=i.id) AS last_used_at_ms FROM login_credentials c JOIN items i ON i.id=c.item_id WHERE i.trashed=0",[])?;
    let mut frequencies = HashMap::<&str, usize>::new();
    for v in &all {
        *frequencies
            .entry(v["secret"].as_str().unwrap_or_default())
            .or_default() += 1;
    }
    let mut findings = Vec::new();
    for v in &all {
        let secret = v["secret"].as_str().unwrap_or_default();
        let since = v["password_active_since_ms"].as_i64().unwrap_or(0);
        let details: ItemDetails = parse(v["details_json"].as_str().unwrap_or("{}"))?;
        let days = details
            .reminder_days
            .unwrap_or(crate::effective_app_settings().password_reminder_days);
        let mut reasons = Vec::new();
        let common = [
            "password",
            "password123",
            "123456",
            "123456789",
            "qwerty",
            "admin",
            "12345678",
        ];
        if secret.chars().count() < 12 || common.contains(&secret.to_ascii_lowercase().as_str()) {
            reasons.push("weak");
        }
        if frequencies.get(secret).copied().unwrap_or(0) > 1 {
            reasons.push("reused");
        }
        if since <= 0 {
            reasons.push("activation_unknown");
        } else if days > 0 && now_ms() - since >= i64::from(days) * 86_400_000 {
            reasons.push("reminder_due");
        }
        if details.mfa_state == "disabled" {
            reasons.push("mfa_disabled");
        }
        let last_use = v["last_used_at_ms"]
            .as_i64()
            .unwrap_or_else(|| v["created_at_ms"].as_i64().unwrap_or(0));
        if last_use > 0 && now_ms() - last_use > 180 * 86_400_000 {
            reasons.push("unused");
        }
        if !reasons.is_empty() {
            findings.push(json!({"id":v["id"],"item_id":v["item_id"],"title":v["title"],"last_used_at_ms":v["last_used_at_ms"],"reasons":reasons}));
        }
    }
    Ok(
        json!({"items":findings,"total":all.len(),"weak_rule":"少于 12 字符或命中常见密码；为本地启发式检查，未联网查询泄露库"}),
    )
}

pub fn manage_credentials(conn: &Connection, action: VaultAction) -> Result<Value> {
    use VaultAction::*;
    // 这些操作内部已有事务，避免嵌套 BEGIN。
    match action {
        SshImport {
            label,
            pem,
            passphrase,
        } => {
            let result = crate::ssh_transfer::import_key(conn, &label, &pem, &passphrase)?;
            crate::mark_restore_dirty(conn)?;
            return Ok(result);
        }
        SshExport { id, passphrase } => {
            return crate::ssh_transfer::export_key(conn, &id, &passphrase)
        }
        BitwardenPreview {
            path,
            password,
            namespace,
        } => {
            let json = read_import_file(&path)?;
            return crate::bitwarden_import::preview(conn, &json, &password, &namespace);
        }
        BitwardenImport {
            path,
            password,
            namespace,
            choices,
            preview_token,
        } => {
            let json = read_import_file(&path)?;
            return crate::bitwarden_import::import_with_choices(
                conn,
                &json,
                &password,
                &namespace,
                &choices,
                &preview_token,
            );
        }
        other => return manage_local(conn, other),
    }
}

fn read_import_file(path: &str) -> Result<zeroize::Zeroizing<String>> {
    use std::io::Read;
    // App-only 操作在验证后直接读取文件，避免把整份导出在 4MB IPC 请求中再次编码。
    let file = std::fs::File::open(path).map_err(|_| CoreError::io("无法读取导入文件"))?;
    if !file
        .metadata()
        .map_err(|_| CoreError::io("无法读取导入文件"))?
        .is_file()
    {
        return Err(CoreError::format("请选择普通 JSON 文件"));
    }
    let mut input = zeroize::Zeroizing::new(String::new());
    file.take(32 * 1024 * 1024 + 1)
        .read_to_string(&mut input)
        .map_err(|_| CoreError::format("导入文件须为 UTF-8 JSON"))?;
    if input.len() > 32 * 1024 * 1024 {
        return Err(CoreError::limit("导入文件不能超过 32MB"));
    }
    Ok(input)
}
fn manage_local(conn: &Connection, action: VaultAction) -> Result<Value> {
    use VaultAction::*;
    let tx = conn.unchecked_transaction()?;
    let mut changed = true;
    let value = match action {
        GeneratePassword {
            length,
            symbols,
            exclude_ambiguous,
        } => {
            changed = false;
            if !(12..=128).contains(&length) {
                return Err(CoreError::limit("密码长度应为 12–128"));
            }
            let mut groups = vec![
                b"abcdefghijkmnpqrstuvwxyz".to_vec(),
                b"ABCDEFGHJKLMNPQRSTUVWXYZ".to_vec(),
                b"23456789".to_vec(),
            ];
            if !exclude_ambiguous {
                groups[0].extend(b"lo");
                groups[1].extend(b"IO");
                groups[2].extend(b"01");
            }
            if symbols {
                groups.push(b"!@#$%^&*_-+=?".to_vec());
            }
            let pool: Vec<u8> = groups.iter().flatten().copied().collect();
            let mut rng = OsRng;
            let mut password: Vec<u8> = groups
                .iter()
                .map(|g| g[rng.gen_range(0..g.len())])
                .collect();
            while password.len() < length {
                password.push(pool[rng.gen_range(0..pool.len())]);
            }
            password.shuffle(&mut rng);
            json!({"password":String::from_utf8(password).map_err(|_| CoreError::format("密码生成失败"))?})
        }
        PasswordVersions { credential_id } => {
            changed = false;
            let current = crate::get_login_secret(&tx, &credential_id)?;
            json!({"current_revision":current.current_revision,"active_password_revision":tx.query_row("SELECT active_password_revision FROM login_credentials WHERE id=?1",[&credential_id],|r|r.get::<_,String>(0))?,"candidates":rows(&tx,"SELECT id,secret,created_at_ms,base_active_revision FROM password_candidates WHERE credential_id=?1 ORDER BY created_at_ms DESC",[&credential_id])?,
                "history":rows(&tx,"SELECT id,secret,activated_at_ms,retired_at_ms FROM password_history WHERE credential_id=?1 ORDER BY retired_at_ms DESC,id DESC",[&credential_id])?})
        }
        CandidateCreate {
            credential_id,
            expected_revision,
            password,
        } => json!({"id":create_candidate(&tx,&credential_id,&expected_revision,&password)?}),
        CandidateActivate {
            credential_id,
            expected_revision,
            candidate_id,
        } => {
            activate(&tx, &credential_id, &expected_revision, &candidate_id)?;
            json!({"activated":true})
        }
        CandidateDiscard {
            credential_id,
            candidate_id,
        } => {
            crate::get_login_secret(&tx, &credential_id)?;
            if tx.execute(
                "DELETE FROM password_candidates WHERE id=?1 AND credential_id=?2",
                params![candidate_id, credential_id],
            )? != 1
            {
                return Err(CoreError::Conflict);
            }
            json!({"discarded":true})
        }
        HistoryRestore {
            credential_id,
            expected_revision,
            history_id,
        } => {
            let secret: String = tx.query_row(
                "SELECT secret FROM password_history WHERE id=?1 AND credential_id=?2",
                params![history_id, credential_id],
                |r| r.get(0),
            )?;
            json!({"id":create_candidate(&tx,&credential_id,&expected_revision,&secret)?})
        }
        MarkPasswordActive {
            credential_id,
            expected_revision,
        } => {
            let row = crate::get_login_secret(&tx, &credential_id)?;
            check_revision(&row.current_revision, &expected_revision)?;
            let rev = new_revision();
            tx.execute("UPDATE login_credentials SET password_active_since_ms=?1,current_revision=?2,updated_at_ms=?1 WHERE id=?3",params![now_ms(),rev,credential_id])?;
            tx.execute(
                "UPDATE items SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",
                params![rev, now_ms(), row.item_id],
            )?;
            json!({"updated":true})
        }
        TrashList => {
            changed = false;
            json!({"items":rows(&tx,"SELECT id,kind,title,current_revision,trashed_at_ms FROM items WHERE trashed=1 ORDER BY trashed_at_ms DESC",[]) ?})
        }
        TrashRestore {
            item_id,
            expected_revision,
        } => {
            trash_change(&tx, &item_id, &expected_revision, false)?;
            json!({"restored":true})
        }
        TrashPurge {
            item_id,
            expected_revision,
        } => {
            trash_change(&tx, &item_id, &expected_revision, true)?;
            json!({"purged":true})
        }
        ItemDetails { item_id } => {
            changed = false;
            let rev = active_item(&tx, &item_id)?;
            json!({"details":details_for(&tx,&item_id)?,"current_revision":rev})
        }
        ItemDetailsSave {
            item_id,
            expected_revision,
            mut details,
            title,
        } => {
            check_revision(&active_item(&tx, &item_id)?, &expected_revision)?;
            if details.notes.len() > 1_000_000
                || details.tags.len() > 100
                || details.custom_fields.len() > 100
                || details.related_item_ids.len() > 100
                || details.uris.len() > 100
                || details.tags.iter().any(|s| s.len() > 200)
                || details.category.len() > 200
                || details
                    .custom_fields
                    .iter()
                    .any(|f| f.name.len() > 200 || f.value.len() > 65536)
                || details
                    .uris
                    .iter()
                    .any(|u| u.uri.len() > 4096 || u.match_mode.len() > 100)
                || details.history_limit.is_some_and(|n| n > 50)
                || details.reminder_days.is_some_and(|n| n > 3650)
            {
                return Err(CoreError::limit("详情超出限制"));
            }
            for related in &details.related_item_ids {
                if related == &item_id {
                    return Err(CoreError::format("不能关联自身"));
                }
                active_item(&tx, related)?;
            }
            details
                .tags
                .iter_mut()
                .for_each(|s| *s = s.trim().to_string());
            details.tags.retain(|s| !s.is_empty());
            details.tags.sort();
            details.tags.dedup();
            if let Some(title) = title {
                let kind: String =
                    tx.query_row("SELECT kind FROM items WHERE id=?1", [&item_id], |r| {
                        r.get(0)
                    })?;
                if kind != "secure_note" || title.trim().is_empty() || title.len() > 500 {
                    return Err(CoreError::format("笔记标题无效"));
                }
                tx.execute(
                    "UPDATE items SET title=?1 WHERE id=?2",
                    params![title.trim(), item_id],
                )?;
            }
            tx.execute(
                "UPDATE items SET details_json=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4",
                params![encode(&details)?, new_revision(), now_ms(), item_id],
            )?;
            json!({"updated":true})
        }
        NoteCreate { title, text } => {
            if title.trim().is_empty() || title.len() > 500 || text.len() > 1_000_000 {
                return Err(CoreError::format(
                    "请输入标题（不超过 500 字节），正文不超过 1MB",
                ));
            }
            let item = id();
            let details = self::ItemDetails {
                notes: text,
                ..Default::default()
            };
            tx.execute("INSERT INTO items(id,kind,title,current_revision,created_at_ms,updated_at_ms,details_json) VALUES (?1,'secure_note',?2,?3,?4,?4,?5)",params![item,title.trim(),new_revision(),now_ms(),encode(&details)?])?;
            json!({"item_id":item})
        }
        ItemSearch { query } => {
            changed = false;
            // 在内存搜索非秘密元数据，隐藏字段、备注和安全笔记正文不进入列表响应。
            let mut found = Vec::new();
            let q = query.to_lowercase();
            for mut row in rows(&tx,"SELECT id,kind,title,current_revision,details_json,(SELECT last_used_at_ms FROM local_usage u WHERE u.item_id=items.id) AS last_used_at_ms FROM items WHERE trashed=0 ORDER BY updated_at_ms DESC",[])? {
                let d: self::ItemDetails=parse(row["details_json"].as_str().unwrap_or("{}"))?;
                let login:Option<(String,String)>=conn.query_row("SELECT origin,username FROM login_credentials WHERE item_id=?1",[row["id"].as_str().unwrap_or_default()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                let account_match=login.is_some_and(|(origin,user)|origin.to_lowercase().contains(&q)||user.to_lowercase().contains(&q));
                if q.is_empty() || account_match || row["title"].as_str().unwrap_or_default().to_lowercase().contains(&q) || d.tags.iter().any(|t|t.to_lowercase().contains(&q)) || d.category.to_lowercase().contains(&q) || d.notes.to_lowercase().contains(&q) || d.custom_fields.iter().any(|f|!f.secret && (f.name.to_lowercase().contains(&q)||f.value.to_lowercase().contains(&q))) {
                    row.as_object_mut().unwrap().remove("details_json"); row["tags"]=json!(d.tags); row["favorite"]=json!(d.favorite); row["category"]=json!(d.category);found.push(row);
                }
            }
            json!({"items":found})
        }
        SecurityReport => {
            changed = false;
            security_report(&tx)?
        }
        TotpUpdate {
            id,
            expected_revision,
            issuer,
            account,
            secret,
        } => {
            let (item,rev):(String,String)=tx.query_row("SELECT t.item_id,t.current_revision FROM totp_credentials t JOIN items i ON i.id=t.item_id WHERE t.id=?1 AND i.trashed=0",[&id],|r|Ok((r.get(0)?,r.get(1)?)))?;
            check_revision(&rev, &expected_revision)?;
            let p = crate::totp::totp_params_for_storage(&secret)?;
            let rev = new_revision();
            tx.execute("UPDATE totp_credentials SET issuer=?1,account=?2,secret_base32=?3,totp_algorithm=?4,totp_digits=?5,totp_period=?6,current_revision=?7,updated_at_ms=?8 WHERE id=?9",params![issuer,account,p.secret_base32,crate::totp::algorithm_name(p.algorithm),p.digits as i64,p.period as i64,rev,now_ms(),id])?;
            tx.execute(
                "UPDATE items SET title=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4",
                params![format!("{issuer} ({account})"), rev, now_ms(), item],
            )?;
            json!({"updated":true})
        }
        TotpStatus {
            id,
            min_valid_seconds,
            passive: _,
        } => {
            changed = false;
            let p = crate::repo_m2::totp_params_for_id(&tx, &id)?;
            let seconds = now_ms().max(0) as u64 / 1000;
            let remaining = p.period - seconds % p.period;
            // 自定义的短周期不能要求整周期有效，否则每次刷新都只会继续等待。
            let minimum = min_valid_seconds.min((p.period / 2).max(1));
            if remaining < minimum {
                json!({"wait_seconds":remaining,"period":p.period})
            } else {
                json!({"code":crate::totp::totp_code_at(&p,seconds)?,"remaining_seconds":remaining,"period":p.period,"expires_at_ms":(seconds+remaining)*1000})
            }
        }
        RecoveryEntries { id } => {
            changed = false;
            let rev:String=tx.query_row("SELECT r.current_revision FROM recovery_code_items r JOIN items i ON i.id=r.item_id WHERE r.id=?1 AND i.trashed=0",[&id],|r|r.get(0))?;
            json!({"current_revision":rev,"items":rows(&tx,"SELECT id,code,used_at_ms FROM recovery_code_entries WHERE recovery_id=?1 ORDER BY position",[id])?})
        }
        RecoveryEntryUse {
            id,
            expected_revision,
            entry_id,
            used,
        } => {
            let (rev,item):(String,String)=tx.query_row("SELECT r.current_revision,r.item_id FROM recovery_code_items r JOIN items i ON i.id=r.item_id WHERE r.id=?1 AND i.trashed=0",[&id],|r|Ok((r.get(0)?,r.get(1)?)))?;
            check_revision(&rev, &expected_revision)?;
            if tx.execute(
                "UPDATE recovery_code_entries SET used_at_ms=?1 WHERE id=?2 AND recovery_id=?3",
                params![if used { Some(now_ms()) } else { None }, entry_id, id],
            )? != 1
            {
                return Err(CoreError::Conflict);
            }
            let next = new_revision();
            tx.execute(
                "UPDATE recovery_code_items SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",
                params![next, now_ms(), id],
            )?;
            tx.execute(
                "UPDATE items SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",
                params![next, now_ms(), item],
            )?;
            json!({"current_revision":next})
        }
        _ => return Err(CoreError::format("不支持的操作")),
    };
    if changed {
        crate::mark_restore_dirty(&tx)?;
    }
    tx.commit()?;
    Ok(value)
}

/// 可迁移的逻辑导出，显式列出业务表；不导出 VMK、钥匙串和本机配置。
pub fn export_logical_json(conn: &Connection) -> Result<String> {
    let tx = conn.unchecked_transaction()?;
    let mut tables = serde_json::Map::new();
    for table in [
        "items",
        "login_credentials",
        "password_history",
        "password_candidates",
        "totp_credentials",
        "ssh_keys",
        "recovery_code_items",
        "recovery_code_entries",
        "server_login_profiles",
        "credential_groups",
        "import_mappings",
    ] {
        tables.insert(
            table.into(),
            json!(rows(&tx, &format!("SELECT * FROM {table}"), [])?),
        );
    }
    let output=serde_json::to_string_pretty(&json!({"format":"credpivot-logical","version":1,"schema_version":crate::SCHEMA_USER_VERSION,"exported_at_ms":now_ms(),"tables":tables}))
        .map_err(|_| CoreError::format("导出失败"))?;
    tx.commit()?;
    Ok(output)
}

pub fn update_login_from_browser(
    conn: &Connection,
    credential: &str,
    expected: &str,
    username: &str,
    password: &str,
) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let row = crate::get_login_secret(&tx, credential)?;
    check_revision(&row.current_revision, expected)?;
    if row.password != password {
        let candidate = create_candidate(&tx, credential, expected, password)?;
        activate(&tx, credential, expected, &candidate)?;
    }
    let revision = new_revision();
    tx.execute(
        "UPDATE login_credentials SET username=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4",
        params![username, revision, now_ms(), credential],
    )?;
    tx.execute(
        "UPDATE items SET current_revision=?1,updated_at_ms=?2 WHERE id=?3",
        params![revision, now_ms(), row.item_id],
    )?;
    crate::mark_restore_dirty(&tx)?;
    tx.commit()?;
    Ok(())
}

/// 只向调用方提供可用于匹配的来源；不返回隐藏字段和备注。
pub fn credential_origins(conn: &Connection, credential: &str) -> Result<Vec<String>> {
    let row = crate::repo_m2::get_login_row(conn, credential)?;
    let details = details_for(conn, &row.item_id)?;
    if details.uris.is_empty() {
        return Ok(vec![row.origin]);
    }
    Ok(details
        .uris
        .iter()
        .filter(|u| matches!(u.match_mode.as_str(), "exact_origin" | "bitwarden_default"))
        .map(|u| crate::bitwarden_import::normalize_login_origin(&u.uri))
        .collect())
}

/// 浏览器候选按站点筛选，不能先套用 App 列表的分页上限，否则较旧账号会漏选。
pub fn browser_login_candidates(conn: &Connection) -> Result<Vec<crate::LoginListRow>> {
    let mut statement = conn.prepare("SELECT c.id FROM login_credentials c JOIN items i ON i.id=c.item_id WHERE i.trashed=0 ORDER BY c.updated_at_ms DESC")?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ids.iter()
        .map(|id| crate::repo_m2::get_login_row(conn, id))
        .collect()
}

/// 本机使用痕迹不参与业务 revision，也不进入任何导出或恢复点。
pub fn record_credential_use(conn: &Connection, credential: &str) -> Result<()> {
    conn.execute("INSERT INTO local_usage(item_id,last_used_at_ms,use_count) SELECT item_id,?1,1 FROM login_credentials WHERE id=?2 ON CONFLICT(item_id) DO UPDATE SET last_used_at_ms=excluded.last_used_at_ms,use_count=use_count+1",params![now_ms(),credential])?;
    Ok(())
}
