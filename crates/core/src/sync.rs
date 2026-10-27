//! 全量逻辑快照的三方合并。WebDAV 仅传递 OVB 密文，业务状态及共同基线留在 SQLCipher 内。
use crate::credential_management::rows;
use crate::error::{CoreError, Result};
use crate::{CpvcConfig, SlotType};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use rusqlite::{params, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

const FORMAT: &str = "credpivot-sync";
pub const MAX_SYNC_BYTES: usize = 64 * 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavSettings {
    pub root: String,
    // root 保留最终地址和原连接标识；展示字段不参与保险库绑定和钥匙串索引。
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub directory: String,
    pub username: String,
    pub location: String,
    pub automatic: bool,
    pub interval_seconds: u64,
    #[serde(default = "default_daily_history_count")]
    pub daily_history_count: usize,
}
fn default_daily_history_count() -> usize { 5 }
impl WebDavSettings {
    pub fn valid(&self) -> bool {
        let Ok(url) = url::Url::parse(&self.root) else {
            return false;
        };
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && self.root.ends_with('/')
            && self.root.len() <= 4096
            && !self.root.chars().any(char::is_control)
            && matches!(
                self.provider.as_str(),
                "" | "custom" | "nutstore" | "nextcloud" | "owncloud"
            )
            && self.valid_directory()
            && !self.username.is_empty()
            && self.username.len() <= 1024
            && !self.username.contains(':')
            && !self.username.chars().any(char::is_control)
            && self.location.len() == 64
            && hex::decode(&self.location).is_ok()
            && (60..=3600).contains(&self.interval_seconds)
            && (3..=99).contains(&self.daily_history_count)
    }

    fn valid_directory(&self) -> bool {
        // 旧配置只有 root，展示时将它作为服务器地址，避免迁移时改变连接身份。
        if self.server_url.is_empty() {
            return self.directory.is_empty();
        }
        let Ok(mut server) = url::Url::parse(&self.server_url) else {
            return false;
        };
        if server.scheme() != "https"
            || server.host_str().is_none()
            || !server.username().is_empty()
            || server.password().is_some()
            || server.query().is_some()
            || server.fragment().is_some()
            || !self.server_url.ends_with('/')
            || self.server_url.len() > 4096
            || self.server_url.chars().any(char::is_control)
            || self.directory.len() > 2048
            || self.directory.contains('\\')
            || self.directory.chars().any(char::is_control)
            || self.directory.split('/').any(|s| matches!(s, "." | ".."))
        {
            return false;
        }
        {
            let Ok(mut segments) = server.path_segments_mut() else {
                return false;
            };
            segments.pop_if_empty();
            for segment in self.directory.split('/').filter(|s| !s.is_empty()) {
                segments.push(segment);
            }
            segments.push("");
        }
        // 用同一个 URL 解析器比较，允许 Foundation 与 url 对默认端口的规范化差异。
        url::Url::parse(&self.root).is_ok_and(|root| root == server)
    }
}
const TABLES: &[&str] = &[
    "partitions",
    "credential_groups",
    "items",
    "login_credentials",
    "totp_credentials",
    "ssh_keys",
    "recovery_code_items",
    "server_login_profiles",
    "passkey_credentials",
    "password_history",
    "password_candidates",
    "recovery_code_entries",
    "import_mappings",
];

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub tables: BTreeMap<String, Vec<Value>>,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub records: BTreeMap<String, Record>,
    pub tombstones: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub format: String,
    pub version: u32,
    pub vault_id: String,
    pub generation: String,
    pub revision: String,
    pub parent: Option<String>,
    pub snapshot: String,
    pub sha256: String,
    pub mac: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    version: u32,
    schema_version: i32,
    generation: String,
    revision: String,
    parent: Option<String>,
    vault_json: String,
    document: Document,
    // 来源名称随快照加密，不放进远端明文 head.json，也不写入诊断日志。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    host_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Binding {
    pub location: String,
    pub head: Option<Head>,
    pub baseline: Document,
    pub control_hash: String,
    pub remote_control_hash: Option<String>,
    pub last_synced_ms: i64,
    #[serde(default)]
    pub host_name: String,
    /// 首次合并独立保险库、尚未发布成功时，用于重新读取旧远端。仅存于加密数据库。
    pub previous_remote_vmk: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Pending {
    head: Head,
    document: Document,
    #[serde(default)]
    host_name: String,
    #[serde(default)]
    preserve_previous: bool,
}

pub struct Plan {
    pub id: String,
    pub location: String,
    pub initial: bool,
    pub strategy: String,
    pub local_fingerprint: String,
    pub local_control_hash: String,
    pub remote_control_hash: Option<String>,
    pub local: Document,
    pub remote: Document,
    pub result: Document,
    pub conflicts: Vec<String>,
    pub remote_head: Option<Head>,
    pub target_config: CpvcConfig,
    pub target_vmk: Zeroizing<[u8; 32]>,
    pub previous_remote_vmk: Option<String>,
    pub decisions: BTreeMap<String, String>,
    pub no_upload: bool,
    pub host_name: String,
    pub remote_host_name: String,
    pub preserve_previous: bool,
    generation: String,
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncPlan([REDACTED])")
    }
}

fn invalid() -> CoreError {
    CoreError::format("sync.errors.format")
}
pub fn now_ms() -> i64 {
    crate::repo::now_ms()
}
pub fn valid_host_name(name: &str) -> bool {
    name.chars().count() <= 128 && !name.chars().any(char::is_control)
}
fn archive_time() -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms())
        .map(|date| date.format("%Y%m%dT%H%M%SZ").to_string())
        .unwrap_or_else(|| now_ms().to_string())
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}
pub fn control_hash(config: &CpvcConfig) -> Result<String> {
    Ok(digest(&encoded(config)?))
}
pub fn fingerprint(doc: &Document) -> Result<String> {
    Ok(digest(&encoded(doc)?))
}

fn read_state<T: serde::de::DeserializeOwned>(conn: &Connection, key: &str) -> Result<Option<T>> {
    let text: Option<String> = conn
        .query_row("SELECT value FROM sync_state WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?;
    text.map(|s| serde_json::from_str(&s).map_err(|_| invalid()))
        .transpose()
}
fn write_state(conn: &Connection, key: &str, value: &impl Serialize) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO sync_state(key,value) VALUES (?1,?2)",
        params![
            key,
            String::from_utf8(encoded(value)?).map_err(|_| invalid())?
        ],
    )?;
    Ok(())
}

fn remember_head(conn: &Connection, head: &Head) -> Result<()> {
    // 只记入已采用/已确认的版本和它声明的父版本；观察预览不算提交。
    // 留在本机加密状态表，不上传、不改远端格式，也不因断开连接而删除防回退记录。
    for revision in std::iter::once(head.revision.as_str()).chain(head.parent.as_deref()) {
        write_state(conn, &format!("seen:{revision}"), &true)?;
    }
    Ok(())
}
pub fn binding(conn: &Connection) -> Result<Option<Binding>> {
    read_state(conn, "binding")
}
pub fn status(conn: &Connection) -> Result<Value> {
    let state = binding(conn)?;
    let pending: Option<Pending> = read_state(conn, "pending")?;
    Ok(
        json!({"connected":state.is_some(),"location":state.as_ref().map(|s|&s.location),
        "last_synced_ms":state.as_ref().map(|s|s.last_synced_ms),"pending_upload":pending.is_some(),
        "generation":state.as_ref().and_then(|s|s.head.as_ref()).map(|h|&h.generation),
        "remote_host_name":state.as_ref().map(|s|&s.host_name)}),
    )
}
pub fn disconnect(conn: &Connection) -> Result<()> {
    conn.execute(
        "DELETE FROM sync_state WHERE key IN ('binding','pending')",
        [],
    )?;
    Ok(())
}

/// 固定白名单表和关系，不能将远端 JSON 中的名称拼入 SQL。
pub fn capture(conn: &Connection) -> Result<Document> {
    let tx = conn.unchecked_transaction()?;
    let mut doc = Document::default();
    for partition in rows(&tx,"SELECT * FROM partitions ORDER BY id",[])? {
        let id=partition["id"].as_str().ok_or_else(invalid)?.to_string();
        doc.records.insert(format!("partition:{id}"),Record {tables:BTreeMap::from([("partitions".into(),vec![partition])])});
    }
    for group in rows(&tx, "SELECT * FROM credential_groups ORDER BY id", [])? {
        let id = group["id"].as_str().ok_or_else(invalid)?.to_string();
        doc.records.insert(
            format!("group:{id}"),
            Record {
                tables: BTreeMap::from([("credential_groups".into(), vec![group])]),
            },
        );
    }
    for item in rows(&tx, "SELECT * FROM items ORDER BY id", [])? {
        let id = item["id"].as_str().ok_or_else(invalid)?.to_string();
        let mut tables = BTreeMap::from([("items".into(), vec![item])]);
        for table in &TABLES[3..] {
            let sql = match *table {
                "password_history" | "password_candidates" => format!("SELECT * FROM {table} WHERE credential_id IN (SELECT id FROM login_credentials WHERE item_id=?1) ORDER BY id"),
                "recovery_code_entries" => format!("SELECT * FROM {table} WHERE recovery_id IN (SELECT id FROM recovery_code_items WHERE item_id=?1) ORDER BY id"),
                "import_mappings" => "SELECT * FROM import_mappings WHERE local_item_id=?1 ORDER BY source_namespace,source_item_id".into(),
                "passkey_credentials" => format!("SELECT * FROM {table} WHERE item_id=?1 ORDER BY credential_id"),
                _ => format!("SELECT * FROM {table} WHERE item_id=?1 ORDER BY id"),
            };
            let mut values = rows(&tx, &sql, [&id])?;
            if *table == "ssh_keys" {
                // 默认 SSH 身份是本机选择，不覆盖其他设备的活动身份。
                for row in &mut values {
                    row.as_object_mut()
                        .ok_or_else(invalid)?
                        .remove("is_default");
                }
            }
            if !values.is_empty() {
                tables.insert(table.to_string(), values);
            }
        }
        doc.records.insert(format!("item:{id}"), Record { tables });
    }
    for row in rows(
        &tx,
        "SELECT record_key,deleted_at_ms FROM sync_tombstones ORDER BY record_key",
        [],
    )? {
        let key = row["record_key"].as_str().ok_or_else(invalid)?.to_string();
        if !doc.records.contains_key(&key) {
            doc.tombstones
                .insert(key, row["deleted_at_ms"].as_i64().ok_or_else(invalid)?);
        }
    }
    tx.commit()?;
    Ok(doc)
}

fn semantic_record(record: &Record) -> Value {
    let mut value = serde_json::to_value(record).unwrap_or(Value::Null);
    if let Some(tables) = value.get_mut("tables").and_then(Value::as_object_mut) {
        for rows in tables.values_mut().filter_map(Value::as_array_mut) {
            for row in rows {
                if let Some(row) = row.as_object_mut() {
                    for name in ["current_revision", "created_at_ms", "updated_at_ms"] {
                        row.remove(name);
                    }
                    // JSON 对象的字段顺序不代表业务差异。
                    for name in ["details_json", "codes_json"] {
                        if let Some(parsed) = row
                            .get(name)
                            .and_then(Value::as_str)
                            .and_then(|s| serde_json::from_str::<Value>(s).ok())
                        {
                            row.insert(name.into(), parsed);
                        }
                    }
                }
            }
        }
    }
    value
}
fn same(a: Option<&Record>, b: Option<&Record>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => semantic_record(a) == semantic_record(b),
        _ => false,
    }
}
fn same_document(a: &Document, b: &Document) -> bool {
    a.records.len() == b.records.len()
        && a.records
            .iter()
            .all(|(key, r)| same(Some(r), b.records.get(key)))
        && a.tombstones.keys().eq(b.tombstones.keys())
}

fn metadata(record: Option<&Record>, deleted_at: Option<i64>) -> Value {
    let Some(record) = record else {
        return json!({"deleted":true,"updated_at_ms":deleted_at});
    };
    let row = record
        .tables
        .get("items")
        .or_else(|| record.tables.get("credential_groups"))
        .or_else(|| record.tables.get("partitions"))
        .and_then(|r| r.first());
    let updated = record
        .tables
        .values()
        .flatten()
        .filter_map(|r| r["updated_at_ms"].as_i64())
        .filter(|ts| *ts > 0)
        .max()
        .or_else(|| row.and_then(|r| r["created_at_ms"].as_i64()));
    // 预览只投影用于辨认记录的字段；绝不能把原始行、资料 JSON、密码或密钥送到对比界面。
    let first = |table: &str| record.tables.get(table).and_then(|rows| rows.first());
    let username = first("login_credentials").and_then(|r| r["username"].as_str())
        .or_else(|| first("totp_credentials").and_then(|r| r["account"].as_str()))
        .or_else(|| first("server_login_profiles").and_then(|r| r["manual_username"].as_str()))
        .or_else(|| first("passkey_credentials").and_then(|r| r["username"].as_str()));
    let primary_website = first("login_credentials").and_then(|r| r["origin"].as_str())
        .or_else(|| first("totp_credentials").and_then(|r| r["issuer"].as_str()))
        .or_else(|| first("server_login_profiles").and_then(|r| r["host"].as_str()))
        .or_else(|| first("passkey_credentials").and_then(|r| r["rp_id"].as_str()));
    let websites: Vec<String> = row.and_then(|r| r["details_json"].as_str())
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .map(|details| details["uris"].as_array().into_iter().flatten()
            .filter_map(|rule| rule["uri"].as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    let website = if websites.is_empty() { primary_website.map(str::to_owned) } else { Some(websites.join("\n")) };
    json!({"deleted":false,"title":row.and_then(|r|r.get("title").or_else(||r.get("name"))).and_then(Value::as_str),
        "kind":if record.tables.contains_key("partitions") { Some("partition") } else { row.and_then(|r|r.get("kind").or_else(||r.get("scope"))).and_then(Value::as_str) },
        "partition_id":row.and_then(|r|r["partition_id"].as_str()),
        "username":username,"website":website,"trashed":row.is_some_and(|r| r["trashed"] == 1),
        "created_at_ms":row.and_then(|r|r["created_at_ms"].as_i64()),"updated_at_ms":updated})
}

fn record_change(before: Option<&Record>, after: Option<&Record>) -> &'static str {
    if same(before, after) { return "unchanged"; }
    match (before, after) {
        (None, Some(_)) => "added",
        (Some(_), None) => "deleted",
        _ => "modified",
    }
}

fn document_metadata(doc: &Document, key: &str) -> Value {
    let mut info = metadata(doc.records.get(key), doc.tombstones.get(key).copied());
    if let Some(partition) = info["partition_id"].as_str() {
        let name = doc.records.get(&format!("partition:{partition}"))
            .and_then(|record| record.tables.get("partitions"))
            .and_then(|rows| rows.first()).and_then(|row| row["name"].as_str())
            .map(str::to_owned);
        info["partition_name"] = json!(name);
    }
    info
}

fn record_error(key: &str, record: Option<&Record>, source: CoreError) -> CoreError {
    let info = metadata(record, None);
    CoreError::RecordValidation {
        // 只携带定位所需信息，不附带网站、原始行、资料正文或 MFA 种子。
        record: json!({"id":key,"kind":if key.starts_with("group:") { json!("group") } else if key.starts_with("partition:") {json!("partition")} else { info["kind"].clone() },
            "title":info["title"],"account":info["username"],"trashed":info["trashed"]}),
        source: Box::new(source),
    }
}
fn changed_fields(a: Option<&Record>, b: Option<&Record>) -> Vec<String> {
    let mut fields = BTreeSet::new();
    if let (Some(a), Some(b)) = (a, b) {
        for table in TABLES {
            let ar = a.tables.get(*table);
            let br = b.tables.get(*table);
            if ar == br {
                continue;
            }
            if let (Some(ar), Some(br)) = (ar, br) {
                if ar.len() == 1 && br.len() == 1 {
                    if let (Some(ao), Some(bo)) = (ar[0].as_object(), br[0].as_object()) {
                        for key in ao.keys().chain(bo.keys()) {
                            if !["current_revision", "updated_at_ms", "created_at_ms"]
                                .contains(&key.as_str())
                                && ao.get(key) != bo.get(key)
                            {
                                if key == "details_json" {
                                    let a = ao.get(key).and_then(Value::as_str).and_then(|v| serde_json::from_str::<Value>(v).ok());
                                    let b = bo.get(key).and_then(Value::as_str).and_then(|v| serde_json::from_str::<Value>(v).ok());
                                    if let (Some(Value::Object(a)), Some(Value::Object(b))) = (a, b) {
                                        if a == b { continue; }
                                        let mut known = false;
                                        // 只返回固定字段名，备注、自定义字段及 MFA 参数的实际值不进入预览。
                                        for field in ["notes", "tags", "favorite", "category", "custom_fields", "related_item_ids",
                                            "uris", "linked_mfa_ids", "history_limit", "reminder_days", "mfa_state",
                                            "ssh_sign_policy", "mfa_bindings", "pending_mfa_uris", "otp_extra_parameters"] {
                                            if a.get(field) != b.get(field) {
                                                fields.insert(format!("{table}.details_json.{field}"));
                                                known = true;
                                            }
                                        }
                                        if known { continue; }
                                    }
                                }
                                fields.insert(format!("{table}.{key}"));
                            }
                        }
                        continue;
                    }
                }
            }
            fields.insert(table.to_string());
        }
    } else {
        fields.insert("deletion".into());
    }
    fields.into_iter().collect()
}

fn merge(base: Option<&Document>, local: &Document, remote: &Document) -> (Document, Vec<String>) {
    let mut result = Document::default();
    let mut conflicts = Vec::new();
    let keys: BTreeSet<_> = local
        .records
        .keys()
        .chain(remote.records.keys())
        .chain(local.tombstones.keys())
        .chain(remote.tombstones.keys())
        .chain(base.into_iter().flat_map(|b| b.records.keys()))
        .cloned()
        .collect();
    for key in keys {
        let l = local.records.get(&key);
        let r = remote.records.get(&key);
        let b = base.and_then(|b| b.records.get(&key));
        let selected = if same(l, r) {
            r.or(l)
        } else if base.is_some() && same(l, b) {
            r
        } else if base.is_some() && same(r, b) {
            l
        } else if base.is_none() && l.is_none() && !local.tombstones.contains_key(&key) {
            r
        } else if base.is_none() && r.is_none() && !remote.tombstones.contains_key(&key) {
            l
        } else {
            conflicts.push(key.clone());
            l
        };
        if let Some(record) = selected {
            result.records.insert(key, record.clone());
        } else {
            let ts = local
                .tombstones
                .get(&key)
                .into_iter()
                .chain(remote.tombstones.get(&key))
                .copied()
                .max()
                .unwrap_or_else(now_ms);
            result.tombstones.insert(key, ts);
        }
    }
    (result, conflicts)
}

fn related_conflicts(
    local: &Document,
    remote: &Document,
    result: &Document,
    conflicts: &mut Vec<String>,
) {
    let mut owners = BTreeMap::new();
    for doc in [local, remote] {
        for (key, record) in &doc.records {
            for (table, rows) in &record.tables {
                if ["login_credentials", "totp_credentials", "ssh_keys"].contains(&table.as_str()) {
                    for row in rows {
                        if let Some(id) = row["id"].as_str() {
                            owners.insert(id.to_string(), key.clone());
                        }
                    }
                }
            }
        }
    }
    for (key, record) in &result.records {
        let mut targets = Vec::new();
        for rows in record.tables.values() {
            for row in rows {
                if let Some(partition)=row["partition_id"].as_str() { targets.push(format!("partition:{partition}")); }
                if let Some(group) = row["group_id"].as_str().filter(|g| !g.is_empty()) {
                    targets.push(format!("group:{group}"));
                }
                for field in ["linked_login_id", "linked_totp_id", "linked_ssh_key_id"] {
                    if let Some(target) = row[field].as_str().and_then(|id| owners.get(id)) {
                        targets.push(target.clone());
                    }
                }
                if let Some(details) = row["details_json"]
                    .as_str()
                    .and_then(|s| serde_json::from_str::<Value>(s).ok())
                {
                    for id in details["related_item_ids"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                    {
                        targets.push(format!("item:{id}"));
                    }
                    for id in details["linked_mfa_ids"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                    {
                        if let Some(target) = owners.get(id) {
                            targets.push(target.clone());
                        }
                    }
                }
            }
        }
        for target in targets {
            let partition_of=|key:&str| result.records.get(key).and_then(|record|
                record.tables.get("items").or_else(||record.tables.get("credential_groups")))
                .and_then(|rows|rows.first()).and_then(|row|row["partition_id"].as_str());
            let cross_partition = !target.starts_with("partition:") && partition_of(key).is_some()
                && partition_of(key)!=partition_of(&target);
            if !result.records.contains_key(&target) || cross_partition {
                // 选择保留旧关联时，也必须能选择恢复其目标记录，而不是产生无法解决的错误。
                for candidate in [key, &target] {
                    if (local.records.contains_key(candidate)
                        || remote.records.contains_key(candidate))
                        && !conflicts.contains(candidate)
                    {
                        conflicts.push(candidate.clone());
                    }
                }
            }
        }
    }
    // 两台设备各自创建同名分区时，必须先选择保留哪一份，不能生成无法分辨的入口。
    let mut names = BTreeMap::<String, Vec<String>>::new();
    for (key, record) in &result.records {
        if let Some(row) = record.tables.get("partitions").and_then(|rows| rows.first()) {
            if let Some(name) = row["name"].as_str() {
                names.entry(name.trim().to_ascii_lowercase()).or_default().push(key.clone());
            }
        }
    }
    for keys in names.values().filter(|keys| keys.len() > 1) {
        for key in keys {
            if !conflicts.contains(key) { conflicts.push(key.clone()); }
        }
        // 一并提供这些分区内记录的来源选择，避免删除同名入口后留下无法在界面解决的悬空引用。
        for doc in [local, remote] {
            for (key, record) in &doc.records {
                let partition = record.tables.get("items").or_else(|| record.tables.get("credential_groups"))
                    .and_then(|rows| rows.first()).and_then(|row| row["partition_id"].as_str());
                if partition.is_some_and(|id| keys.contains(&format!("partition:{id}"))) && !conflicts.contains(key) {
                    conflicts.push(key.clone());
                }
            }
        }
    }
    conflicts.sort();
}

fn possible_duplicates(doc: &Document) -> usize {
    let mut seen = BTreeMap::<String, usize>::new();
    for record in doc.records.values() {
        for row in record.tables.get("login_credentials").into_iter().flatten() {
            let signature = json!([row["origin"], row["username"]]).to_string();
            *seen.entry(signature).or_default() += 1;
        }
    }
    seen.values().filter(|n| **n > 1).count()
}

fn normalize_import_mappings(doc: &mut Document, local: &Document) {
    // 同一来源可能被两个独立保险库分别导入。保留两条业务记录，导入去重入口优先指向本地已有记录。
    let mut chosen = BTreeMap::<(String, String), String>::new();
    let mut keys: Vec<_> = doc.records.keys().cloned().collect();
    keys.sort_by_key(|key| (!local.records.contains_key(key), key.clone()));
    for key in &keys {
        for row in doc.records[key]
            .tables
            .get("import_mappings")
            .into_iter()
            .flatten()
        {
            if let (Some(namespace), Some(id)) = (
                row["source_namespace"].as_str(),
                row["source_item_id"].as_str(),
            ) {
                chosen
                    .entry((namespace.into(), id.into()))
                    .or_insert_with(|| key.clone());
            }
        }
    }
    for (key, record) in &mut doc.records {
        if let Some(rows) = record.tables.get_mut("import_mappings") {
            rows.retain(|row| {
                row["source_namespace"]
                    .as_str()
                    .zip(row["source_item_id"].as_str())
                    .and_then(|(ns, id)| chosen.get(&(ns.into(), id.into())))
                    .is_some_and(|owner| owner.as_str() == key.as_str())
            });
        }
        record.tables.retain(|_, rows| !rows.is_empty());
    }
}

fn sign_head(head: &Head, vmk: &[u8; 32]) -> Result<String> {
    let mut unsigned = head.clone();
    unsigned.mac.clear();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(vmk).map_err(|_| invalid())?;
    mac.update(b"CredPivot WebDAV head v1\0");
    mac.update(&encoded(&unsigned)?);
    Ok(hex::encode(mac.finalize().into_bytes()))
}
fn verify_head(head: &Head, vmk: &[u8; 32]) -> Result<()> {
    let expected = hex::decode(&head.mac).map_err(|_| invalid())?;
    let mut unsigned = head.clone();
    unsigned.mac.clear();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(vmk).map_err(|_| invalid())?;
    mac.update(b"CredPivot WebDAV head v1\0");
    mac.update(&encoded(&unsigned)?);
    mac.verify_slice(&expected).map_err(|_| CoreError::Auth)
}

pub fn validate_head(head: &Head) -> Result<()> {
    if head.format != FORMAT
        || head.version != 1
        || Uuid::parse_str(&head.vault_id).is_err()
        || Uuid::parse_str(&head.generation).is_err()
        || Uuid::parse_str(&head.revision).is_err()
        || head
            .parent
            .as_ref()
            .is_some_and(|p| Uuid::parse_str(p).is_err())
        || head.sha256.len() != 64
        || hex::decode(&head.sha256).is_err()
        || head.mac.len() != 64
        || hex::decode(&head.mac).is_err()
        || !head.snapshot.starts_with("snapshots/credpivot_")
        || !head.snapshot.ends_with(".ovb")
        || head.snapshot.len() > 180
        || !head
            .snapshot
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
        || head.snapshot[10..].contains('/')
        || head.snapshot.contains("..")
    {
        return Err(invalid());
    }
    Ok(())
}

fn decode_remote(
    bytes: &[u8],
    head: &Head,
    current_vmk: &[u8; 32],
    password: &str,
    previous: Option<&str>,
) -> Result<(Envelope, CpvcConfig, Zeroizing<[u8; 32]>)> {
    if bytes.len() > MAX_SYNC_BYTES {
        return Err(CoreError::limit("sync snapshot"));
    }
    validate_head(head)?;
    if digest(bytes) != head.sha256 {
        return Err(CoreError::format("sync.errors.integrity"));
    }
    let (header, aad, ciphertext) = crate::parse_ovb_with_aad(bytes)?;
    let mut vmk = Zeroizing::new(*current_vmk);
    let decrypt = |key: &[u8; 32]| crate::decrypt_snapshot(key, &header, &aad, &ciphertext);
    let plain = Zeroizing::new(if !password.is_empty() {
        let slot = header
            .slots
            .iter()
            .find(|s| s.slot_type == SlotType::MasterPassword)
            .ok_or_else(invalid)?;
        vmk = slot.unwrap_vmk(
            &header.vault_id.to_string(),
            crate::FORMAT_MAJOR,
            password.as_bytes(),
        )?;
        decrypt(&vmk)?
    } else if let Ok(plain) = decrypt(&vmk) {
        plain
    } else if let Some(previous) = previous {
        let decoded = Zeroizing::new(STANDARD.decode(previous).map_err(|_| invalid())?);
        if decoded.len() != 32 {
            return Err(invalid());
        }
        vmk.copy_from_slice(decoded.as_slice());
        decrypt(&vmk)?
    } else {
        return Err(CoreError::format("sync.errors.remotePassword"));
    });
    verify_head(head, &vmk)?;
    let envelope: Envelope = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    if envelope.schema_version != crate::SCHEMA_USER_VERSION {
        return Err(CoreError::format("sync.errors.schemaVersion"));
    }
    let config = crate::parse_config(&envelope.vault_json)?;
    config.verify_mac(&vmk)?;
    if encoded(&config.key_slots)? != encoded(&header.slots)? {
        return Err(invalid());
    }
    if envelope.format != FORMAT
        || envelope.version != 1
        || envelope.schema_version != crate::SCHEMA_USER_VERSION
        || !valid_host_name(&envelope.host_name)
        || envelope.generation != head.generation
        || envelope.revision != head.revision
        || envelope.parent != head.parent
        || config.vault_id != head.vault_id
        || config.vault_id != header.vault_id.to_string()
    {
        return Err(invalid());
    }
    validate_document(&envelope.document)?;
    Ok((envelope, config, vmk))
}

pub fn prepare(
    conn: &Connection,
    config: &CpvcConfig,
    vmk: &[u8; 32],
    location: &str,
    head: Option<Head>,
    remote_bytes: Option<&[u8]>,
    strategy: Option<&str>,
    remote_password: &str,
) -> Result<Plan> {
    if location.len() != 64 || hex::decode(location).is_err() {
        return Err(invalid());
    }
    let state = binding(conn)?;
    let pending: Option<Pending> = read_state(conn, "pending")?;
    let initial = strategy.is_some();
    if !initial && state.as_ref().is_none_or(|s| s.location != location) {
        return Err(CoreError::format("sync.errors.initialRequired"));
    }
    let strategy = strategy.unwrap_or("merge");
    if !["local", "remote", "merge"].contains(&strategy) {
        return Err(invalid());
    }
    let local = capture(conn)?;
    let previous = state
        .as_ref()
        .and_then(|s| s.previous_remote_vmk.as_deref());
    let remote = match (&head, remote_bytes) {
        (Some(head), Some(bytes)) => {
            Some(decode_remote(bytes, head, vmk, remote_password, previous)?)
        }
        (None, None) => None,
        _ => return Err(invalid()),
    };
    let remote_host_name = remote.as_ref().map(|(envelope, _, _)| envelope.host_name.clone())
        .unwrap_or_default();
    if !initial {
        let state = state.as_ref().ok_or_else(invalid)?;
        if state.control_hash != control_hash(config)? {
            return Err(CoreError::format("sync.errors.localControlChanged"));
        }
        if head.is_none() && (state.head.is_some() || pending.is_none()) {
            return Err(CoreError::format("sync.errors.remoteMissing"));
        }
        if let Some(remote_head) = &head {
            if state
                .head
                .as_ref()
                .is_none_or(|previous| previous.revision != remote_head.revision)
                && read_state::<bool>(conn, &format!("seen:{}", remote_head.revision))?
                    == Some(true)
            {
                return Err(CoreError::format("sync.errors.knownOldVersion"));
            }
        }
        if let (Some(previous_head), Some(remote_head)) = (&state.head, &head) {
            if remote_head.revision != previous_head.revision
                && previous_head.parent.as_ref() == Some(&remote_head.revision)
            {
                return Err(CoreError::format("sync.errors.knownOldVersion"));
            }
            if remote_head.generation != previous_head.generation
                && !pending
                    .as_ref()
                    .is_some_and(|p| p.head.generation == remote_head.generation)
            {
                return Err(CoreError::format("sync.errors.generationChanged"));
            }
        }
        if let Some((_, remote_config, _)) = &remote {
            let observed = control_hash(remote_config)?;
            // 首次合并可暂时读旧远端，但不能因此放行它在确认之后发生的安全配置变更。
            let expected = state
                .remote_control_hash
                .as_deref()
                .unwrap_or(&state.control_hash);
            if observed != expected && observed != state.control_hash {
                return Err(CoreError::format("sync.errors.remoteControlChanged"));
            }
        }
    }
    let remote_doc = remote
        .as_ref()
        .map(|(e, _, _)| e.document.clone())
        .unwrap_or_default();
    let (result, mut conflicts) = match strategy {
        "remote" if remote.is_none() => return Err(CoreError::format("sync.errors.remoteEmpty")),
        "remote" => (remote_doc.clone(), vec![]),
        "local" => (local.clone(), vec![]),
        _ => merge(
            if initial {
                None
            } else {
                state.as_ref().map(|s| &s.baseline)
            },
            &local,
            &remote_doc,
        ),
    };
    if strategy == "merge" {
        related_conflicts(&local, &remote_doc, &result, &mut conflicts);
    }
    let (target_config, target_vmk) = if strategy == "remote" {
        let (_, remote_config, key) = remote.as_ref().ok_or_else(invalid)?;
        if control_hash(remote_config)? != control_hash(config)? {
            if remote_password.is_empty() {
                return Err(CoreError::format("sync.errors.remotePassword"));
            }
            // decode_remote 已用输入密码验证了与该配置一致的 OVB 密钥槽，不重复执行 Argon2。
        }
        (remote_config.clone(), Zeroizing::new(**key))
    } else {
        (config.clone(), Zeroizing::new(*vmk))
    };
    let previous_remote_vmk = remote
        .as_ref()
        .filter(|(_, _, key)| key.as_ref() != target_vmk.as_ref())
        .map(|(_, _, key)| STANDARD.encode(key.as_ref()));
    let remote_control_hash = remote
        .as_ref()
        .map(|(_, cfg, _)| control_hash(cfg))
        .transpose()?;
    // 重试发布时也要保留首次接入/冲突处理的保护标记，不能因本地已应用而丢失。
    let preserve_previous = initial || !conflicts.is_empty()
        || control_hash(&target_config)? != control_hash(config)?
        || pending.as_ref().is_some_and(|p| p.preserve_previous);
    let generation = if initial {
        if strategy == "remote" {
            // 重新接入采用所选远端的代际，不能继承上一次未完成发布的任务。
            head.as_ref().ok_or_else(invalid)?.generation.clone()
        } else {
            Uuid::new_v4().to_string()
        }
    } else {
        pending
            .map(|p| p.head.generation)
            .or_else(|| head.as_ref().map(|h| h.generation.clone()))
            .unwrap_or_else(|| Uuid::new_v4().to_string())
    };
    Ok(Plan {
        id: Uuid::new_v4().to_string(),
        location: location.into(),
        initial,
        strategy: strategy.into(),
        generation,
        local_fingerprint: fingerprint(&local)?,
        local_control_hash: control_hash(config)?,
        remote_control_hash,
        local,
        remote: remote_doc,
        result,
        conflicts,
        remote_head: head,
        target_config,
        target_vmk,
        previous_remote_vmk,
        decisions: BTreeMap::new(),
        no_upload: false,
        host_name: String::new(),
        remote_host_name,
        preserve_previous,
    })
}

impl Plan {
    pub fn preview_changes(&self, offset: usize, limit: usize) -> Value {
        let limit = limit.clamp(1, 100);
        let conflict_keys: BTreeSet<_> = self.conflicts.iter().collect();
        let keys: BTreeSet<_> = self.local.records.keys().chain(self.remote.records.keys())
            .chain(self.result.records.keys()).chain(self.conflicts.iter()).collect();
        let changed: Vec<_> = keys.into_iter().filter(|key| {
            let local = self.local.records.get(*key);
            conflict_keys.contains(key) || !same(local, self.remote.records.get(*key))
                || !same(local, self.result.records.get(*key))
        }).collect();
        let count = changed.len();
        let offset = offset.min(count.saturating_sub(1) / limit * limit);
        // 只为当前页构造可见元数据，不把整库对比内容一次发送给界面。
        let changes: Vec<_> = changed.into_iter().skip(offset).take(limit).map(|key| {
            let local = self.local.records.get(key);
            let remote = self.remote.records.get(key);
            let result = self.result.records.get(key);
            let conflict = conflict_keys.contains(&key);
            let pending = conflict && !self.decisions.contains_key(key);
            let mut fields: BTreeSet<_> = changed_fields(local, remote).into_iter().collect();
            if !pending {
                fields.extend(changed_fields(local, result));
                fields.extend(changed_fields(remote, result));
            }
            // 两端都不存在并不是“删除”；记录的存在变化由增删标签表达。
            fields.remove("deletion");
            json!({"key":key,"pending":pending,"conflict":conflict,
                "local":document_metadata(&self.local,key),
                "remote":document_metadata(&self.remote,key),
                "result":if pending { Value::Null } else { document_metadata(&self.result,key) },
                "local_action":if pending { "pending" } else { record_change(local,result) },
                "remote_action":if pending { "pending" } else { record_change(remote,result) },
                "changed_fields":fields})
        }).collect();
        json!({"plan_id":self.id,"changes":changes,"changes_total":count,"changes_offset":offset})
    }

    pub fn preview(&self) -> Value {
        let conflicts: Vec<_> = self.conflicts.iter().map(|key| {
            let l=self.local.records.get(key); let r=self.remote.records.get(key);
            json!({"key":key,"local":document_metadata(&self.local,key),
                "remote":document_metadata(&self.remote,key),"changed_fields":changed_fields(l,r)})
        }).collect();
        let page = self.preview_changes(0, 20);
        json!({"plan_id":self.id,"initial":self.initial,"strategy":self.strategy,"local_count":self.local.records.len(),
            "remote_host_name":self.remote_host_name,
            "remote_count":self.remote.records.len(),"result_count":self.result.records.len(),"conflicts":conflicts,
            "remote_present":self.remote_head.is_some(),"decisions":self.decisions,
            "changes":page["changes"],"changes_total":page["changes_total"],"changes_offset":page["changes_offset"],
            "possible_duplicates":possible_duplicates(&self.result),
            "local_only":self.local.records.keys().filter(|k|!self.remote.records.contains_key(*k)).count(),
            "remote_only":self.remote.records.keys().filter(|k|!self.local.records.contains_key(*k)).count()})
    }
    pub fn resolve(&mut self, decisions: BTreeMap<String, String>) -> Result<()> {
        if decisions.keys().any(|k| !self.conflicts.contains(k))
            || decisions.values().any(|v| v != "local" && v != "remote")
        {
            return Err(invalid());
        }
        self.decisions = decisions;
        for (key, side) in &self.decisions {
            let source = if side == "local" {
                &self.local
            } else {
                &self.remote
            };
            if let Some(record) = source.records.get(key) {
                self.result.records.insert(key.clone(), record.clone());
                self.result.tombstones.remove(key);
            } else {
                self.result.records.remove(key);
                self.result.tombstones.insert(
                    key.clone(),
                    source.tombstones.get(key).copied().unwrap_or_else(now_ms),
                );
            }
        }
        Ok(())
    }
    pub fn finish(&mut self) -> Result<()> {
        for key in &self.conflicts {
            let side = self
                .decisions
                .get(key)
                .ok_or_else(|| CoreError::format("sync.errors.unresolved"))?;
            let source = if side == "local" {
                &self.local
            } else {
                &self.remote
            };
            if let Some(record) = source.records.get(key) {
                self.result.records.insert(key.clone(), record.clone());
                self.result.tombstones.remove(key);
            } else {
                self.result.records.remove(key);
                self.result.tombstones.insert(
                    key.clone(),
                    source.tombstones.get(key).copied().unwrap_or_else(now_ms),
                );
            }
        }
        // 已使用恢复码不能因为选择了旧版本而重新变为可用。
        let mut used = BTreeMap::<(String, String), i64>::new();
        for doc in [&self.local, &self.remote] {
            for (record_key, record) in &doc.records {
                for entry in record
                    .tables
                    .get("recovery_code_entries")
                    .into_iter()
                    .flatten()
                {
                    if let (Some(code), Some(ts)) =
                        (entry["code"].as_str(), entry["used_at_ms"].as_i64())
                    {
                        used.entry((record_key.clone(), code.into()))
                            .and_modify(|v| *v = (*v).max(ts))
                            .or_insert(ts);
                    }
                }
            }
        }
        for (record_key, record) in &mut self.result.records {
            for entry in record
                .tables
                .get_mut("recovery_code_entries")
                .into_iter()
                .flatten()
            {
                if let Some(ts) = entry["code"]
                    .as_str()
                    .and_then(|c| used.get(&(record_key.clone(), c.into())))
                    .copied()
                {
                    entry["used_at_ms"] = json!(ts);
                }
            }
            let last_used = record
                .tables
                .get("recovery_code_entries")
                .into_iter()
                .flatten()
                .filter_map(|entry| entry["used_at_ms"].as_i64())
                .max();
            if let Some(timestamp) = last_used {
                for table in ["items", "recovery_code_items"] {
                    for row in record.tables.get_mut(table).into_iter().flatten() {
                        let modified = row["updated_at_ms"].as_i64().unwrap_or(0).max(timestamp);
                        row["updated_at_ms"] = json!(modified);
                    }
                }
            }
        }
        normalize_import_mappings(&mut self.result, &self.local);
        // 远端的历史/恢复码变更未必改变旧版记录修订；为实际变更的本地记录使旧编辑窗口失效。
        // 保留内容原有时间，不把下载时间伪装成用户修改时间。
        for (key, record) in &mut self.result.records {
            if self.local.records.contains_key(key)
                && !same(Some(record), self.local.records.get(key))
            {
                let revision = Uuid::new_v4().to_string();
                for row in record.tables.values_mut().flatten() {
                    if let Some(object) = row.as_object_mut() {
                        if object.contains_key("current_revision") {
                            object.insert("current_revision".into(), json!(revision));
                        }
                    }
                }
            }
        }
        validate_document(&self.result)?;
        self.no_upload = self.remote_head.is_some()
            && same_document(&self.result, &self.remote)
            && self
                .remote_head
                .as_ref()
                .is_some_and(|h| h.vault_id == self.target_config.vault_id)
            && self.previous_remote_vmk.is_none()
            && (!self.initial || self.strategy == "remote");
        Ok(())
    }
    pub fn changes_local(&self) -> bool {
        !same_document(&self.local, &self.result)
    }
    pub fn archive(&self) -> Result<(Head, Vec<u8>)> {
        if !valid_host_name(&self.host_name) { return Err(invalid()); }
        let generation = self.generation.clone();
        let revision = Uuid::new_v4().to_string();
        let parent = self.remote_head.as_ref().map(|h| h.revision.clone());
        let envelope = Envelope {
            format: FORMAT.into(),
            version: 1,
            schema_version: crate::SCHEMA_USER_VERSION,
            generation: generation.clone(),
            revision: revision.clone(),
            parent: parent.clone(),
            vault_json: crate::serialize_config(&self.target_config)?,
            document: self.result.clone(),
            host_name: self.host_name.clone(),
        };
        let plain = Zeroizing::new(encoded(&envelope)?);
        let vault_id = Uuid::parse_str(&self.target_config.vault_id).map_err(|_| invalid())?;
        let archive = crate::build_ovb_file(
            &self.target_vmk,
            &vault_id,
            self.target_config.key_slots.clone(),
            &plain,
        )?;
        if archive.len() > MAX_SYNC_BYTES {
            return Err(CoreError::limit("sync snapshot"));
        }
        let mut head = Head {
            format: FORMAT.into(),
            version: 1,
            vault_id: vault_id.to_string(),
            generation,
            revision,
            parent,
            snapshot: format!(
                "snapshots/credpivot_{}_{}.ovb",
                archive_time(),
                Uuid::new_v4()
            ),
            sha256: digest(&archive),
            mac: String::new(),
        };
        head.mac = sign_head(&head, &self.target_vmk)?;
        Ok((head, archive))
    }
}

fn insert_row(conn: &Connection, table: &str, value: &Value) -> Result<()> {
    if !TABLES.contains(&table) {
        return Err(invalid());
    }
    let object = value.as_object().ok_or_else(invalid)?;
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|_| CoreError::format("sync.errors.recordSchema"))?;
    let columns: BTreeMap<String, String> = stmt
        .query_map([], |r| Ok((r.get(1)?, r.get(2)?)))?
        .collect::<std::result::Result<_, _>>()?;
    if object.is_empty() || object.keys().any(|k| !columns.contains_key(k)) {
        return Err(CoreError::format("sync.errors.recordSchema"));
    }
    let mut names = Vec::new();
    let mut values = Vec::new();
    for (key, value) in object {
        names.push(key.as_str());
        values.push(match value {
            Value::Null => SqlValue::Null,
            Value::Number(n) => SqlValue::Integer(n.as_i64().ok_or_else(|| CoreError::format("sync.errors.recordSchema"))?),
            Value::String(s) => SqlValue::Text(s.clone()),
            Value::Object(o) if o.len() == 1 && o.contains_key("base64") => SqlValue::Blob(
                STANDARD
                    .decode(o["base64"].as_str().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?,
            ),
            _ => return Err(CoreError::format("sync.errors.recordSchema")),
        });
        let valid_type = matches!(
            (columns[key].as_str(), values.last()),
            (_, Some(SqlValue::Null))
                | ("TEXT", Some(SqlValue::Text(_)))
                | ("INTEGER", Some(SqlValue::Integer(_)))
                | ("BLOB", Some(SqlValue::Blob(_)))
        );
        if !valid_type {
            return Err(CoreError::format("sync.errors.recordSchema"));
        }
    }
    let placeholders = vec!["?"; names.len()].join(",");
    conn.execute(
        &format!(
            "INSERT INTO {table} ({}) VALUES ({placeholders})",
            names.join(",")
        ),
        rusqlite::params_from_iter(values),
    ).map_err(|error| {
        // SQLite 正文可能带字段值；只返回固定分类，不暴露 SQL 或具体数据。
        let key = match error {
            rusqlite::Error::SqliteFailure(code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation => "sync.errors.recordConstraint",
            _ => "sync.errors.recordSchema",
        };
        CoreError::format(key)
    })?;
    Ok(())
}

fn load_rows(conn: &Connection, doc: &Document) -> Result<()> {
    for table in TABLES {
        for (key, record) in &doc.records {
            for row in record.tables.get(*table).into_iter().flatten() {
                insert_row(conn, table, row).map_err(|source| record_error(key, Some(record), source))?;
            }
        }
    }
    Ok(())
}

fn validate_relations(conn: &Connection, doc: &Document) -> Result<()> {
    crate::partitions::validate(conn)?;
    let invalid_group: Option<String> = conn.query_row("SELECT i.id FROM items i WHERE group_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM credential_groups g WHERE g.id=i.group_id) LIMIT 1",[],|r|r.get(0)).optional()?;
    if let Some(id) = invalid_group {
        let key = format!("item:{id}");
        return Err(record_error(&key, doc.records.get(&key), CoreError::format("sync.errors.relatedGroup")));
    }
    for (table, columns) in [
        (
            "login_credentials",
            vec![("linked_totp_id", "totp_credentials")],
        ),
        (
            "server_login_profiles",
            vec![
                ("linked_login_id", "login_credentials"),
                ("linked_totp_id", "totp_credentials"),
                ("linked_ssh_key_id", "ssh_keys"),
            ],
        ),
    ] {
        for (column, target) in columns {
            let invalid_link:Option<String>=conn.query_row(&format!("SELECT s.item_id FROM {table} s WHERE {column} IS NOT NULL AND {column}!='' AND NOT EXISTS(SELECT 1 FROM {target} t WHERE t.id=s.{column}) LIMIT 1"),[],|r|r.get(0)).optional()?;
            if let Some(id) = invalid_link {
                let key = format!("item:{id}");
                return Err(record_error(&key, doc.records.get(&key), CoreError::format("sync.errors.relatedCredential")));
            }
        }
    }
    // 新版多 MFA 关联保存在资料 JSON 中，也需要检查引用完整性。
    let ids: BTreeSet<String> = rows(conn, "SELECT id FROM totp_credentials", [])?
        .into_iter()
        .filter_map(|v| v["id"].as_str().map(str::to_string))
        .collect();
    let item_ids: BTreeSet<String> = rows(conn, "SELECT id FROM items", [])?
        .into_iter()
        .filter_map(|v| v["id"].as_str().map(str::to_string))
        .collect();
    for row in rows(conn, "SELECT id,details_json FROM items", [])? {
        let key = format!("item:{}", row["id"].as_str().ok_or_else(invalid)?);
        let details: Value =
            serde_json::from_str(row["details_json"].as_str().ok_or_else(invalid)?)
                .map_err(|_| invalid())?;
        if details["related_item_ids"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|id| id.as_str().is_none_or(|id| !item_ids.contains(id)))
        {
            return Err(record_error(&key, doc.records.get(&key), CoreError::format("sync.errors.relatedCredential")));
        }
        if let Some(links) = details.get("linked_mfa_ids").and_then(Value::as_array) {
            if links
                .iter()
                .any(|id| id.as_str().is_none_or(|id| !ids.contains(id)))
            {
                return Err(record_error(&key, doc.records.get(&key), CoreError::format("sync.errors.relatedMfa")));
            }
        }
    }
    let mut stmt = conn.prepare("PRAGMA foreign_key_check")?;
    if stmt.query([])?.next()?.is_some() {
        return Err(invalid());
    }
    Ok(())
}

pub fn validate_document(doc: &Document) -> Result<()> {
    if doc.records.len() + doc.tombstones.len() > 100_000 {
        return Err(CoreError::limit("sync records"));
    }
    for (key, record) in &doc.records {
        let checked: Result<()> = (|| {
            let (prefix, id) = key.split_once(':').ok_or_else(invalid)?;
            if Uuid::parse_str(id).is_err() || doc.tombstones.contains_key(key) {
                return Err(invalid());
            }
            let primary = match prefix {
                "item" => "items",
                "group" => "credential_groups",
                "partition" => "partitions",
                _ => return Err(invalid()),
            };
            let root = record
                .tables
                .get(primary)
                .filter(|rows| rows.len() == 1)
                .and_then(|r| r.first())
                .ok_or_else(invalid)?;
            if root["id"].as_str() != Some(id) {
                return Err(invalid());
            }
            for (table, rows) in &record.tables {
                if !TABLES.contains(&table.as_str())
                    || (prefix != "item" && table != primary)
                    || (prefix == "item" && ["credential_groups","partitions"].contains(&table.as_str()))
                {
                    return Err(invalid());
                }
                for row in rows {
                    if table == "items" && row["id"].as_str() != Some(id) {
                        return Err(invalid());
                    }
                    if [
                        "login_credentials",
                        "totp_credentials",
                        "ssh_keys",
                        "recovery_code_items",
                        "server_login_profiles",
                        "passkey_credentials",
                    ]
                    .contains(&table.as_str())
                        && row["item_id"].as_str() != Some(id)
                    {
                        return Err(invalid());
                    }
                    if table == "import_mappings" && row["local_item_id"].as_str() != Some(id) {
                        return Err(invalid());
                    }
                    if [
                        "password_history",
                        "password_candidates",
                        "recovery_code_entries",
                    ]
                    .contains(&table.as_str())
                    {
                        let (parent, column) = if table == "recovery_code_entries" {
                            ("recovery_code_items", "recovery_id")
                        } else {
                            ("login_credentials", "credential_id")
                        };
                        if !record
                            .tables
                            .get(parent)
                            .into_iter()
                            .flatten()
                            .any(|p| p["id"] == row[column])
                        {
                            return Err(invalid());
                        }
                    }
                    if table == "items" {
                        let details: crate::credential_management::ItemDetails =
                            serde_json::from_str(row["details_json"].as_str().ok_or_else(invalid)?)
                                .map_err(|_| CoreError::format("sync.errors.invalidDetails"))?;
                        crate::website_rules::validate_website_rules(&details.uris)
                            .map_err(|_| CoreError::format("sync.errors.invalidWebsiteRules"))?;
                    }
                    if table == "totp_credentials" {
                        // 校验已入库参数，不把种子重新当作待添加的 URI 解析；与实际生成验证码共用规则。
                        let secret = row["secret_base32"].as_str()
                            .ok_or_else(|| CoreError::format("sync.errors.invalidMfaSecret"))?;
                        crate::totp::validate_base32_secret(secret)
                            .map_err(|_| CoreError::format("sync.errors.invalidMfaSecret"))?;
                        let algorithm = row["totp_algorithm"].as_str()
                            .and_then(|v| crate::totp::algorithm_from_name(v).ok())
                            .ok_or_else(|| CoreError::format("sync.errors.invalidMfaAlgorithm"))?;
                        let digits = row["totp_digits"].as_u64().and_then(|v| usize::try_from(v).ok())
                            .ok_or_else(|| CoreError::format("sync.errors.invalidMfaParameters"))?;
                        let period = row["totp_period"].as_u64()
                            .ok_or_else(|| CoreError::format("sync.errors.invalidMfaParameters"))?;
                        crate::totp::validate_totp_stored_params(&crate::totp::TotpStoredParams {
                            secret_base32: secret.into(), algorithm, digits, period,
                        }).map_err(|_| CoreError::format("sync.errors.invalidMfaParameters"))?;
                    }
                    if table == "ssh_keys" || table == "passkey_credentials" {
                        let field = if table == "ssh_keys" {
                            "private_key_seed"
                        } else {
                            "private_key"
                        };
                        let key = Zeroizing::new(
                            STANDARD
                                .decode(row[field]["base64"].as_str().ok_or_else(invalid)?)
                                .map_err(|_| CoreError::format("sync.errors.invalidKey"))?,
                        );
                        if key.len() != 32 || (table == "ssh_keys" && row.get("is_default").is_some()) {
                            return Err(CoreError::format("sync.errors.invalidKey"));
                        }
                        if table == "passkey_credentials"
                            && p256::ecdsa::SigningKey::from_slice(&key).is_err()
                        {
                            return Err(CoreError::format("sync.errors.invalidKey"));
                        }
                    }
                }
            }
            Ok(())
        })();
        checked.map_err(|source| record_error(key, Some(record), source))?;
    }
    // 只用内存库校验结构和约束，任何失败都不能影响正在使用的保险库。
    let conn = Connection::open_in_memory()?;
    conn.execute_batch("PRAGMA temp_store=MEMORY;")?;
    crate::migrate_to_latest(&conn)?;
    conn.execute("INSERT INTO sync_state VALUES ('applying','1')", [])?;
    conn.execute("DELETE FROM partitions",[])?;
    load_rows(&conn, doc)?;
    validate_relations(&conn, doc)
}

fn apply_contents(tx: &Connection, doc: &Document) -> Result<()> {
    tx.execute(
        "INSERT OR REPLACE INTO sync_state VALUES ('applying','1')",
        [],
    )?;
    let selected: Option<String> = tx
        .query_row(
            "SELECT id FROM ssh_keys WHERE is_default=1 LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    for table in TABLES.iter().rev() {
        tx.execute(&format!("DELETE FROM {table}"), [])?;
    }
    load_rows(&tx, doc)?;
    if let Some(id) = selected {
        tx.execute("UPDATE ssh_keys SET is_default=1 WHERE id=?1", [id])?;
    }
    tx.execute(
        "DELETE FROM local_usage WHERE item_id NOT IN (SELECT id FROM items)",
        [],
    )?;
    tx.execute("DELETE FROM sync_tombstones", [])?;
    for (key, ts) in &doc.tombstones {
        tx.execute(
            "INSERT INTO sync_tombstones VALUES (?1,?2)",
            params![key, ts],
        )?;
    }
    validate_relations(&tx, doc)?;
    crate::mark_restore_dirty(&tx)?;
    tx.execute("DELETE FROM sync_state WHERE key='applying'", [])?;
    Ok(())
}

pub fn apply_document(conn: &Connection, doc: &Document) -> Result<()> {
    validate_document(doc)?;
    let tx = conn.unchecked_transaction()?;
    apply_contents(&tx, doc)?;
    tx.commit()?;
    Ok(())
}

pub fn apply_plan(conn: &Connection, plan: &Plan, head: &Head) -> Result<()> {
    validate_document(&plan.result)?;
    let tx = conn.unchecked_transaction()?;
    apply_contents(&tx, &plan.result)?;
    store_applied(&tx, plan, head)?;
    tx.commit()?;
    Ok(())
}

pub fn store_applied(conn: &Connection, plan: &Plan, published_head: &Head) -> Result<()> {
    let old = binding(conn)?;
    if let Some(head) = old.as_ref().and_then(|state| state.head.as_ref()) {
        remember_head(conn, head)?;
    }
    if let Some(head) = &plan.remote_head {
        remember_head(conn, head)?;
    }
    let state = Binding {
        location: plan.location.clone(),
        head: plan.remote_head.clone(),
        baseline: plan.remote.clone(),
        control_hash: control_hash(&plan.target_config)?,
        remote_control_hash: plan.remote_control_hash.clone(),
        last_synced_ms: old.map(|s| s.last_synced_ms).unwrap_or(0),
        previous_remote_vmk: plan.previous_remote_vmk.clone(),
        host_name: plan.remote_host_name.clone(),
    };
    write_state(conn, "binding", &state)?;
    write_state(
        conn,
        "pending",
        &Pending {
            head: published_head.clone(),
            document: plan.result.clone(),
            host_name: plan.host_name.clone(),
            preserve_previous: plan.preserve_previous,
        },
    )
}
pub fn store_pending(conn: &Connection, plan: &Plan, head: &Head) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    store_applied(&tx, plan, head)?;
    tx.commit()?;
    Ok(())
}
/// 发布和确认都绑定当前控制配置及待上传任务，不能继续使用改密/安全重建前的快照。
/// 返回待上传任务的历史保护标记，不能仅由界面参数决定是否保留旧远端版本。
pub fn authorize_publish(conn: &Connection, config: &CpvcConfig, location: &str, head: &Head) -> Result<bool> {
    // 每个网络步骤都会检查；只取控制字段，避免反复反序列化整库基线和待上传文档。
    let state: Option<(String, String)> = conn.query_row(
        "SELECT json_extract(value,'$.location'),json_extract(value,'$.control_hash') FROM sync_state WHERE key='binding'",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let (bound_location, expected_control) = state.ok_or_else(invalid)?;
    if bound_location != location {
        return Err(CoreError::Conflict);
    }
    if expected_control != control_hash(config)? {
        return Err(CoreError::format("sync.errors.localControlChanged"));
    }
    let pending: Option<(String, bool)> = conn.query_row(
        "SELECT json_extract(value,'$.head'),COALESCE(json_extract(value,'$.preserve_previous'),0) FROM sync_state WHERE key='pending'",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?;
    let (pending, preserve_previous) = pending.ok_or_else(invalid)?;
    let pending: Head = serde_json::from_str(&pending).map_err(|_| invalid())?;
    if pending != *head {
        return Err(CoreError::Conflict);
    }
    Ok(preserve_previous)
}
pub fn acknowledge(conn: &Connection, config: &CpvcConfig, location: &str, head: &Head) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    authorize_publish(&tx, config, location, head)?;
    let mut state = binding(&tx)?.ok_or_else(invalid)?;
    if state.location != location {
        return Err(CoreError::Conflict);
    }
    let pending: Pending = read_state(&tx, "pending")?.ok_or_else(invalid)?;
    if pending.head != *head {
        return Err(CoreError::Conflict);
    }
    if let Some(previous) = &state.head {
        remember_head(&tx, previous)?;
    }
    remember_head(&tx, head)?;
    state.head = Some(head.clone());
    state.baseline = pending.document;
    state.host_name = pending.host_name;
    state.last_synced_ms = now_ms();
    state.previous_remote_vmk = None;
    state.remote_control_hash = Some(state.control_hash.clone());
    write_state(&tx, "binding", &state)?;
    tx.execute("DELETE FROM sync_state WHERE key='pending'", [])?;
    tx.commit()?;
    Ok(())
}
pub fn acknowledge_observed(conn: &Connection, config: &CpvcConfig, location: &str, head: &Head) -> Result<bool> {
    let pending: Option<Pending> = read_state(conn, "pending")?;
    if pending.as_ref().is_some_and(|p| p.head == *head) {
        acknowledge(conn, config, location, head)?;
        return Ok(true);
    }
    Ok(false)
}
pub fn store_current(conn: &Connection, plan: &Plan) -> Result<()> {
    let state = Binding {
        location: plan.location.clone(),
        head: plan.remote_head.clone(),
        baseline: plan.remote.clone(),
        control_hash: control_hash(&plan.target_config)?,
        remote_control_hash: plan.remote_control_hash.clone(),
        last_synced_ms: now_ms(),
        previous_remote_vmk: None,
        host_name: plan.remote_host_name.clone(),
    };
    let tx = conn.unchecked_transaction()?;
    if let Some(previous) = binding(&tx)?.and_then(|state| state.head) {
        remember_head(&tx, &previous)?;
    }
    if let Some(head) = &plan.remote_head {
        remember_head(&tx, head)?;
    }
    write_state(&tx, "binding", &state)?;
    tx.execute("DELETE FROM sync_state WHERE key='pending'", [])?;
    tx.commit()?;
    Ok(())
}

/// 本地替换前的独立归档；保留既有数据库快照格式，现有 CLI 也能恢复。
pub fn backup(dir: &Path, vmk: &Zeroizing<[u8; 32]>) -> Result<String> {
    let config = crate::read_vault_json(dir)?;
    config.verify_mac(vmk)?;
    let plain = Zeroizing::new(crate::snapshot::pack_snapshot_from_dir(dir, vmk)?);
    let id = Uuid::parse_str(&config.vault_id).map_err(|_| invalid())?;
    let bytes = crate::build_ovb_file(vmk, &id, config.key_slots.clone(), &plain)?;
    let (header, aad, cipher) = crate::parse_ovb_with_aad(&bytes)?;
    let verified = Zeroizing::new(crate::decrypt_snapshot(vmk, &header, &aad, &cipher)?);
    if *verified != *plain {
        return Err(CoreError::Auth);
    }
    let path = dir.join("sync-backups").join(format!(
        "credpivot_{}_{}.ovb",
        archive_time(),
        Uuid::new_v4()
    ));
    crate::write_file_atomic(&path, &bytes)?;
    if digest(&std::fs::read(&path).map_err(|_| CoreError::io("sync.errors.backup"))?)
        != digest(&bytes)
    {
        return Err(CoreError::Auth);
    }
    Ok(path.to_string_lossy().into_owned())
}

/// WebDAV OVB 同样支持独立恢复；不可将同步对象当作数据库文件直接覆盖。
pub(crate) fn unpack_sync_snapshot(
    plain: &[u8],
    dir: &Path,
    vmk: &Zeroizing<[u8; 32]>,
) -> Result<()> {
    let envelope: Envelope = serde_json::from_slice(plain).map_err(|_| invalid())?;
    if envelope.format != FORMAT
        || envelope.version != 1
        || envelope.schema_version != crate::SCHEMA_USER_VERSION
        || !valid_host_name(&envelope.host_name)
    {
        return Err(invalid());
    }
    let config = crate::parse_config(&envelope.vault_json)?;
    config.verify_mac(vmk)?;
    validate_document(&envelope.document)?;
    crate::write_vault_json_atomic(dir, &config)?;
    let id = Uuid::parse_str(&config.vault_id).map_err(|_| invalid())?;
    crate::local_db::init_database(dir, vmk, &id)?;
    let db = crate::open_database(dir, vmk)?;
    apply_document(&db, &envelope.document)
}

pub fn restore_with_vmk(bytes: &[u8], dir: &Path, vmk: &Zeroizing<[u8; 32]>) -> Result<()> {
    crate::ensure_empty_target(dir)?;
    let (head, aad, cipher) = crate::parse_ovb_with_aad(bytes)?;
    let plain = Zeroizing::new(crate::decrypt_snapshot(vmk, &head, &aad, &cipher)?);
    unpack_sync_snapshot(&plain, dir, vmk)?;
    crate::verify_database(dir, vmk)
}
