use crate::credential_management::{CustomField, ItemDetails, UriRule};
use crate::repo::{new_revision, now_ms};
use crate::{CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Debug, serde::Serialize)]
pub struct ImportReport {
    pub imported: u32,
    pub skipped_duplicate: u32,
    pub skipped_invalid: u32,
    pub skipped_unsupported_fields: u32,
}
fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}
fn digest(v: &Value) -> String {
    hex::encode(Sha256::digest(v.to_string().as_bytes()))
}
fn uid() -> String {
    Uuid::new_v4().to_string()
}

/// Bitwarden Password protected JSON：盐使用 Base64 文本本身，HKDF 仅 expand。
fn decode_export(input: &str, password: &str) -> Result<Value> {
    if input.len() > 32 * 1024 * 1024 {
        return Err(CoreError::limit("导入文件不能超过 32MB"));
    }
    let value: Value =
        serde_json::from_str(input).map_err(|_| CoreError::format("JSON 格式无效"))?;
    if value["encrypted"] != true {
        return Ok(value);
    }
    if value["passwordProtected"] != true {
        return Err(CoreError::format(
            "不支持账户绑定加密导出，请在 Bitwarden 导出时选择 Password protected",
        ));
    }
    if password.is_empty() {
        return Err(CoreError::format("请输入导出文件密码"));
    }
    let iterations = value["kdfIterations"].as_u64().unwrap_or(0);
    let salt = text(&value, "salt");
    if salt.is_empty() || salt.len() > 1024 {
        return Err(CoreError::format("KDF 盐无效"));
    }
    let mut derived = Zeroizing::new([0u8; 32]);
    match value["kdfType"].as_u64() {
        Some(0) => {
            if !(5000..=2_000_000).contains(&iterations) {
                return Err(CoreError::limit("PBKDF2 迭代数超出允许范围"));
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                salt.as_bytes(),
                iterations as u32,
                &mut *derived,
            );
        }
        Some(1) => {
            let memory = value["kdfMemory"].as_u64().unwrap_or(0);
            let parallel = value["kdfParallelism"].as_u64().unwrap_or(0);
            if !(1..=10).contains(&iterations)
                || !(16..=256).contains(&memory)
                || !(1..=16).contains(&parallel)
            {
                return Err(CoreError::limit("Argon2 参数超出允许范围"));
            }
            let params = argon2::Params::new(
                memory as u32 * 1024,
                iterations as u32,
                parallel as u32,
                Some(32),
            )
            .map_err(|_| CoreError::format("Argon2 参数无效"))?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(
                    password.as_bytes(),
                    &Sha256::digest(salt.as_bytes()),
                    &mut *derived,
                )
                .map_err(|_| CoreError::BadSecret)?;
        }
        _ => return Err(CoreError::format("不支持的 Bitwarden KDF")),
    }
    let hk =
        hkdf::Hkdf::<Sha256>::from_prk(derived.as_slice()).map_err(|_| CoreError::BadSecret)?;
    let mut enc = Zeroizing::new([0u8; 32]);
    let mut mac = Zeroizing::new([0u8; 32]);
    hk.expand(b"enc", &mut *enc)
        .map_err(|_| CoreError::BadSecret)?;
    hk.expand(b"mac", &mut *mac)
        .map_err(|_| CoreError::BadSecret)?;
    let validation = decrypt_string(text(&value, "encKeyValidation_DO_NOT_EDIT"), &enc, &mac)?;
    Uuid::parse_str(&validation).map_err(|_| CoreError::BadSecret)?;
    let plaintext = decrypt_string(text(&value, "data"), &enc, &mac)?;
    serde_json::from_str(&plaintext).map_err(|_| CoreError::format("解密后的 JSON 无效"))
}
fn decrypt_string(s: &str, enc: &[u8; 32], key_mac: &[u8; 32]) -> Result<Zeroizing<String>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use hmac::{Hmac, Mac};
    let data = s.strip_prefix("2.").ok_or(CoreError::BadSecret)?;
    let parts: Vec<_> = data.split('|').collect();
    if parts.len() != 3 {
        return Err(CoreError::BadSecret);
    }
    let iv = STANDARD
        .decode(parts[0])
        .map_err(|_| CoreError::BadSecret)?;
    let ct = STANDARD
        .decode(parts[1])
        .map_err(|_| CoreError::BadSecret)?;
    let tag = STANDARD
        .decode(parts[2])
        .map_err(|_| CoreError::BadSecret)?;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key_mac).map_err(|_| CoreError::BadSecret)?;
    mac.update(&iv);
    mac.update(&ct);
    mac.verify_slice(&tag).map_err(|_| CoreError::BadSecret)?;
    // 先验 MAC，再解密；任何错误均不回显密文、口令或解密内容。
    let bytes = Zeroizing::new(
        cbc::Decryptor::<aes::Aes256>::new_from_slices(enc, &iv)
            .map_err(|_| CoreError::BadSecret)?
            .decrypt_padded_vec_mut::<Pkcs7>(&ct)
            .map_err(|_| CoreError::BadSecret)?,
    );
    Ok(Zeroizing::new(
        String::from_utf8(bytes.to_vec()).map_err(|_| CoreError::BadSecret)?,
    ))
}
fn items(root: &Value) -> Result<&Vec<Value>> {
    root.get("items")
        .unwrap_or(root)
        .as_array()
        .ok_or_else(|| CoreError::format("Bitwarden 导出须包含 items 数组"))
}
fn source_id(v: &Value) -> String {
    if text(v, "id").is_empty() {
        digest(v)
    } else {
        text(v, "id").into()
    }
}
fn ns(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 {
        return Err(CoreError::format(
            "请输入稳定的来源账户名称（重复导入须保持一致）",
        ));
    }
    Ok(format!("bitwarden:{value}"))
}
fn mapping(
    conn: &Connection,
    namespace: &str,
    source: &str,
) -> Result<Option<(String, String, String)>> {
    Ok(conn.query_row("SELECT m.local_item_id,m.source_digest,i.current_revision FROM import_mappings m JOIN items i ON i.id=m.local_item_id WHERE m.source_namespace=?1 AND m.source_item_id=?2",params![namespace,source],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?)
}
fn preview_root(conn: &Connection, root: &Value, namespace: &str) -> Result<Value> {
    let mut list = Vec::new();
    let mut token = Sha256::new();
    token.update(namespace.as_bytes());
    token.update(digest(root));
    let mut seen = std::collections::HashSet::new();
    for v in items(root)? {
        let source = source_id(v);
        if !seen.insert(source.clone()) {
            return Err(CoreError::format("源文件含重复条目 ID"));
        }
        let old = mapping(conn, namespace, &source)?;
        let kind = v["type"]
            .as_i64()
            .unwrap_or(if v["login"].is_object() { 1 } else { 0 });
        let supported = matches!(kind, 1 | 2);
        let state = if !supported {
            "unsupported"
        } else if let Some((_, hash, _)) = &old {
            if hash == &digest(v) {
                "unchanged"
            } else {
                "changed"
            }
        } else {
            "new"
        };
        if let Some((id, hash, rev)) = &old {
            token.update(id);
            token.update(hash);
            token.update(rev);
        }
        let warnings = warnings(v);
        let mut changed_fields = Vec::new();
        if let Some((item, _, _)) = &old {
            let old_details = crate::credential_management::details_for(conn, item)?;
            let new_details = details(v);
            if old_details.notes != new_details.notes {
                changed_fields.push("备注");
            }
            if old_details.favorite != new_details.favorite {
                changed_fields.push("收藏");
            }
            if serde_json::to_value(&old_details.custom_fields).ok()
                != serde_json::to_value(&new_details.custom_fields).ok()
            {
                changed_fields.push("自定义字段");
            }
            if serde_json::to_value(&old_details.uris).ok()
                != serde_json::to_value(&new_details.uris).ok()
            {
                changed_fields.push("网站 / 匹配规则");
            }
            let login: Option<(String, String)> = conn
                .query_row(
                    "SELECT username,secret FROM login_credentials WHERE item_id=?1",
                    [item],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((user, password)) = login {
                if user != text(&v["login"], "username") {
                    changed_fields.push("用户名");
                }
                if password != text(&v["login"], "password") {
                    changed_fields.push("密码（隐藏）");
                }
            }
        }
        list.push(json!({"source_id":source,"title":text(v,"name"),"kind":kind,"state":state,"warnings":warnings,"changed_fields":changed_fields}));
    }
    Ok(json!({"items":list,"preview_token":hex::encode(token.finalize())}))
}
fn warnings(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if v["attachments"].as_array().is_some_and(|a| !a.is_empty()) {
        out.push("附件不包含在 JSON 中，未迁入".into());
    }
    if v["login"]["fido2Credentials"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        out.push("Passkey 未迁入".into());
    }
    if v["fields"]
        .as_array()
        .is_some_and(|a| a.iter().any(|f| f["type"] == 3))
    {
        out.push("链接字段已保留为静态字段，请检查".into());
    }
    if v["login"]["uris"]
        .as_array()
        .is_some_and(|a| a.iter().any(|u| u["match"] != 1))
    {
        out.push(
            "原 URI 匹配规则已保留；默认规则收紧为精确来源，其他规则暂停自动匹配，请检查".into(),
        );
    }
    let totp = text(&v["login"], "totp");
    if !totp.is_empty() && crate::totp::totp_params_for_storage(totp).is_err() {
        out.push("TOTP 格式无效，原值将保留为隐藏字段".into());
    }
    out
}
pub fn preview(conn: &Connection, input: &str, password: &str, namespace: &str) -> Result<Value> {
    preview_root(conn, &decode_export(input, password)?, &ns(namespace)?)
}
fn details(v: &Value) -> ItemDetails {
    let mut d = ItemDetails {
        notes: text(v, "notes").into(),
        favorite: v["favorite"] == true,
        ..Default::default()
    };
    if let Some(fields) = v["fields"].as_array() {
        d.custom_fields = fields
            .iter()
            .map(|f| CustomField {
                name: text(f, "name").into(),
                value: if f["type"] == 3 {
                    format!("linkedId:{}", f["linkedId"])
                } else {
                    text(f, "value").into()
                },
                secret: f["type"] == 1,
            })
            .collect();
    }
    if let Some(uris) = v["login"]["uris"].as_array() {
        d.uris = uris
            .iter()
            .map(|u| UriRule {
                uri: text(u, "uri").into(),
                match_mode: match u["match"].as_i64() {
                    Some(1) => "exact_origin".into(),
                    None => "bitwarden_default".into(),
                    Some(n) => format!("bitwarden_{n}"),
                },
            })
            .collect();
    }
    let totp = text(&v["login"], "totp");
    if !totp.is_empty() {
        if crate::totp::totp_params_for_storage(totp).is_ok() {
            d.mfa_state = "enabled".into();
        } else {
            d.custom_fields.push(CustomField {
                name: "Bitwarden TOTP（未解析）".into(),
                value: totp.into(),
                secret: true,
            });
        }
    }
    d
}
pub fn import_with_choices(
    conn: &Connection,
    input: &str,
    password: &str,
    namespace: &str,
    choices: &HashMap<String, String>,
    token: &str,
) -> Result<Value> {
    let root = decode_export(input, password)?;
    let namespace = ns(namespace)?;
    let tx = conn.unchecked_transaction()?;
    let current = preview_root(&tx, &root, &namespace)?;
    if current["preview_token"].as_str() != Some(token) {
        return Err(CoreError::Conflict);
    }
    let mut report = json!({"imported":0,"updated":0,"copied":0,"skipped":0,"skipped_duplicate":0,"skipped_invalid":0,"skipped_unsupported_fields":0,"items":[]});
    let folders: HashMap<String, String> = root["folders"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|f| (text(f, "id").into(), text(f, "name").into()))
                .collect()
        })
        .unwrap_or_default();
    let mut results = Vec::new();
    for v in items(&root)? {
        let source = source_id(v);
        let old = mapping(&tx, &namespace, &source)?;
        let kind = v["type"]
            .as_i64()
            .unwrap_or(if v["login"].is_object() { 1 } else { 0 });
        let default = if old.is_some() { "skip" } else { "import" };
        let choice = choices.get(&source).map(String::as_str).unwrap_or(default);
        if !matches!(kind, 1 | 2) {
            let n = report["skipped_invalid"].as_u64().unwrap_or(0);
            report["skipped_invalid"] = json!(n + 1);
            results.push(json!({"title":text(v,"name"),"result":"unsupported_type"}));
            continue;
        }
        if choice == "skip" {
            let n = report["skipped"].as_u64().unwrap_or(0);
            report["skipped"] = json!(n + 1);
            if old.is_some() {
                let n = report["skipped_duplicate"].as_u64().unwrap_or(0);
                report["skipped_duplicate"] = json!(n + 1);
            }
            results.push(json!({"title":text(v,"name"),"result":"skipped","warnings":warnings(v)}));
            continue;
        }
        if !matches!(choice, "import" | "update" | "copy") {
            return Err(CoreError::format("无效的导入选择"));
        }
        if old.is_some() && choice == "import" {
            return Err(CoreError::Conflict);
        }
        let updating = choice == "update";
        let item = if updating {
            old.as_ref().ok_or(CoreError::Conflict)?.0.clone()
        } else {
            uid()
        };
        let rev = new_revision();
        let ts = now_ms();
        let mut d = details(v);
        if updating {
            // 源导出不包含 CredPivot 策略和多对多关联，更新源字段时不能抹掉这些本地设置。
            let previous = crate::credential_management::details_for(&tx, &item)?;
            d.tags = previous.tags;
            d.category = previous.category;
            d.history_limit = previous.history_limit;
            d.reminder_days = previous.reminder_days;
            d.related_item_ids = previous.related_item_ids;
        }
        let group = if let Some(name) = folders.get(text(v, "folderId")) {
            let scope = if kind == 1 { "login" } else { "secure_note" };
            let existing: Option<String> = tx
                .query_row(
                    "SELECT id FROM credential_groups WHERE name=?1 AND scope=?2",
                    params![name, scope],
                    |r| r.get(0),
                )
                .optional()?;
            let group = existing.unwrap_or_else(uid);
            tx.execute("INSERT OR IGNORE INTO credential_groups(id,name,scope,sort_order,created_at_ms) VALUES (?1,?2,?3,0,?4)",params![group,name,scope,ts])?;
            Some(group)
        } else {
            None
        };
        let kind_name = if kind == 1 { "login" } else { "secure_note" };
        if updating {
            let previous: String =
                tx.query_row("SELECT kind FROM items WHERE id=?1", [&item], |r| r.get(0))?;
            if previous != kind_name {
                return Err(CoreError::format("源条目类型已改变，请选择保留副本"));
            }
            tx.execute("UPDATE items SET title=?1,details_json=?2,group_id=?3,trashed=0,trashed_at_ms=NULL,current_revision=?4,updated_at_ms=?5 WHERE id=?6",params![text(v,"name"),d_to_json(&d)?,group,rev,ts,item])?;
        } else {
            tx.execute("INSERT INTO items(id,kind,title,current_revision,created_at_ms,updated_at_ms,details_json,group_id) VALUES (?1,?2,?3,?4,?5,?5,?6,?7)",params![item,kind_name,text(v,"name"),rev,ts,d_to_json(&d)?,group])?;
        }
        if kind == 1 {
            let login = &v["login"];
            let origin = login["uris"]
                .as_array()
                .and_then(|u| u.first())
                .map(|u| normalize_login_origin(text(u, "uri")))
                .unwrap_or_default();
            let user = text(login, "username");
            let secret = text(login, "password");
            let credential = if updating {
                let (cid,old_secret,since):(String,String,i64)=tx.query_row("SELECT id,secret,password_active_since_ms FROM login_credentials WHERE item_id=?1",[&item],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
                if old_secret != secret {
                    tx.execute(
                        "INSERT INTO password_history VALUES (?1,?2,?3,?4,?5)",
                        params![uid(), cid, old_secret, since, ts],
                    )?;
                }
                tx.execute("UPDATE login_credentials SET origin=?1,username=?2,secret=?3,display_name=?4,current_revision=?5,updated_at_ms=?6,active_password_revision=CASE WHEN secret<>?3 THEN ?5 ELSE active_password_revision END,password_active_since_ms=CASE WHEN secret<>?3 THEN 0 ELSE password_active_since_ms END WHERE id=?7",params![origin,user,secret,text(v,"name"),rev,ts,cid])?;
                cid
            } else {
                let cid = uid();
                tx.execute("INSERT INTO login_credentials(id,item_id,origin,username,secret,display_name,current_revision,created_at_ms,updated_at_ms,password_active_since_ms,active_password_revision) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8,0,?7)",params![cid,item,origin,user,secret,text(v,"name"),rev,ts])?;
                cid
            };
            let totp = text(login, "totp");
            if !totp.is_empty() {
                match crate::totp::totp_params_for_storage(totp) {
                    Ok(p) => {
                        let existing:Option<String>=tx.query_row("SELECT t.id FROM totp_credentials t JOIN items i ON i.id=t.item_id WHERE i.trashed=0 AND t.issuer=?1 AND t.account=?2 AND t.secret_base32=?3 AND t.totp_algorithm=?4 AND t.totp_digits=?5 AND t.totp_period=?6 LIMIT 1",params![text(v,"name"),user,p.secret_base32,crate::totp::algorithm_name(p.algorithm),p.digits as i64,p.period as i64],|r|r.get(0)).optional()?;
                        let tid = if let Some(tid) = existing {
                            tid
                        } else {
                            let tid = uid();
                            let ti = uid();
                            tx.execute("INSERT INTO items(id,kind,title,current_revision,created_at_ms,updated_at_ms,group_id) VALUES (?1,'totp',?2,?3,?4,?4,NULL)",params![ti,text(v,"name"),rev,ts])?;
                            tx.execute("INSERT INTO totp_credentials(id,item_id,issuer,account,secret_base32,totp_algorithm,totp_digits,totp_period,current_revision,created_at_ms,updated_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",params![tid,ti,text(v,"name"),user,p.secret_base32,crate::totp::algorithm_name(p.algorithm),p.digits as i64,p.period as i64,rev,ts])?;
                            tid
                        };
                        tx.execute(
                            "UPDATE login_credentials SET linked_totp_id=?1 WHERE id=?2",
                            params![tid, credential],
                        )?;
                    }
                    Err(_) => {
                        tx.execute(
                            "UPDATE login_credentials SET linked_totp_id=NULL WHERE id=?1",
                            [&credential],
                        )?;
                        results.push(
                            json!({"title":text(v,"name"),"result":"invalid_totp_not_imported"}),
                        );
                    }
                }
            }
            if updating && totp.is_empty() {
                tx.execute(
                    "UPDATE login_credentials SET linked_totp_id=NULL WHERE id=?1",
                    [&credential],
                )?;
            }
            if let Some(history) = v["passwordHistory"].as_array() {
                for entry in history {
                    let pw = text(entry, "password");
                    if pw.is_empty() {
                        continue;
                    }
                    let retired = chrono::DateTime::parse_from_rfc3339(text(entry, "lastUsedDate"))
                        .ok()
                        .map(|date| date.timestamp_millis());
                    // 重复导入只补充缺失的历史，不制造相同密码和退役时间的副本。
                    tx.execute("INSERT INTO password_history SELECT ?1,?2,?3,0,?4 WHERE NOT EXISTS (SELECT 1 FROM password_history WHERE credential_id=?2 AND secret=?3 AND retired_at_ms IS ?4)",params![uid(),credential,pw,retired])?;
                }
            }
            crate::credential_management::trim_history(&tx, &credential)?;
        }
        if choice != "copy" {
            tx.execute("INSERT INTO import_mappings(source_namespace,source_item_id,local_item_id,source_digest) VALUES (?1,?2,?3,?4) ON CONFLICT(source_namespace,source_item_id) DO UPDATE SET local_item_id=excluded.local_item_id,source_digest=excluded.source_digest",params![namespace,source,item,digest(v)])?;
        }
        let key = if updating {
            "updated"
        } else if choice == "copy" {
            "copied"
        } else {
            "imported"
        };
        let n = report[key].as_u64().unwrap_or(0);
        report[key] = json!(n + 1);
        let warnings = warnings(v);
        if !warnings.is_empty() {
            let n = report["skipped_unsupported_fields"].as_u64().unwrap_or(0);
            report["skipped_unsupported_fields"] = json!(n + 1);
        }
        results.push(json!({"title":text(v,"name"),"result":key,"warnings":warnings}));
    }
    crate::mark_restore_dirty(&tx)?;
    tx.commit()?;
    report["items"] = json!(results);
    Ok(report)
}
fn d_to_json(d: &ItemDetails) -> Result<String> {
    serde_json::to_string(d).map_err(|_| CoreError::format("详情序列化失败"))
}
pub fn import_bitwarden_json(conn: &Connection, input: &str) -> Result<ImportReport> {
    let preview = preview(conn, input, "", "personal")?;
    let report = import_with_choices(
        conn,
        input,
        "",
        "personal",
        &HashMap::new(),
        preview["preview_token"].as_str().unwrap_or_default(),
    )?;
    Ok(ImportReport {
        imported: report["imported"].as_u64().unwrap_or(0) as u32,
        skipped_duplicate: report["skipped_duplicate"].as_u64().unwrap_or(0) as u32,
        skipped_invalid: report["skipped_invalid"].as_u64().unwrap_or(0) as u32,
        skipped_unsupported_fields: report["skipped_unsupported_fields"].as_u64().unwrap_or(0)
            as u32,
    })
}

pub(crate) fn normalize_login_origin(uri: &str) -> String {
    let s = uri.trim();
    if let Some((scheme, rest)) = s.split_once("://") {
        if matches!(scheme, "https" | "http") {
            let authority = rest
                .split(['/', '?', '#'])
                .next()
                .unwrap_or_default()
                .rsplit('@')
                .next()
                .unwrap_or_default()
                .to_lowercase();
            return format!("{scheme}://{authority}");
        }
    }
    s.to_string()
}
