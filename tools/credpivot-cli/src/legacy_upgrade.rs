//! 仅独立 CLI 使用；App/FFI 不依赖此模块。报告不包含业务字段值。
use fs2::FileExt;
use rusqlite::{backup::Backup, params, Connection, OpenFlags};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;
const LOCAL_SCRIPT: &str = include_str!("../../../scripts/upgrade-legacy-settings.py");
const CATALOG: &str = include_str!("../../../apps/macos/assets/languages/zh-CN.json");

#[derive(Clone)]
struct Item {
    kind: String,
    partition: String,
    details: Value,
}
struct Login {
    id: String,
    item: String,
    origin: String,
    totp: Option<String>,
}
struct Plan {
    items: BTreeMap<String, Item>,
    changed: BTreeSet<String>,
    single_mfa: Vec<(String, Option<String>)>,
    counts: BTreeMap<&'static str, usize>,
}

fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|_| "无法创建独立备份目录")
}

fn private_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "无法创建备份文件")
}

fn open_db(path: &Path, key: &[u8; 32], writable: bool) -> Result<Connection> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let conn = Connection::open_with_flags(path, flags).map_err(|_| "无法打开保险库数据库")?;
    let hex = Zeroizing::new(super::hex_encode(key));
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()));
    conn.execute_batch(&pragma)
        .map_err(|_| "无法设置数据库密钥")?;
    conn.execute_batch(
        "PRAGMA cipher_page_size=4096; PRAGMA kdf_iter=256000;
        PRAGMA cipher_hmac_algorithm=HMAC_SHA512; PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512;
        PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
    )
    .map_err(|_| "无法设置数据库参数")?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|_| "数据库无法解密或已损坏")?;
    if !writable {
        conn.execute_batch("PRAGMA query_only=ON;")
            .map_err(|_| "无法启用只读检查")?;
    }
    Ok(conn)
}

fn array(details: &Value, field: &str) -> Result<Vec<String>> {
    let Some(value) = details.get(field) else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or("关联字段不是数组")?
        .iter()
        .map(|v| v.as_str().map(str::to_string).ok_or("关联字段包含无效值"))
        .collect()
}

fn values(details: &Value, field: &str) -> Result<Vec<Value>> {
    match details.get(field) {
        None => Ok(Vec::new()),
        Some(value) => value
            .as_array()
            .cloned()
            .ok_or("网站规则或 MFA 关联字段不是数组"),
    }
}

fn append(item: &mut Item, field: &str, id: &str) -> Result<bool> {
    let mut ids = array(&item.details, field)?;
    if ids.iter().any(|value| value == id) {
        return Ok(false);
    }
    if ids.len() >= 100 {
        return Err("关联数量超出限制，需要在 App 中处理后重试");
    }
    ids.push(id.into());
    item.details[field] = json!(ids);
    Ok(true)
}

fn plan(conn: &Connection) -> Result<Plan> {
    let mut items = BTreeMap::new();
    let mut stmt = conn
        .prepare("SELECT id,kind,partition_id,details_json FROM items")
        .map_err(|_| "无法检查凭据元数据")?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })
        .map_err(|_| "无法读取凭据元数据")?;
    for row in rows {
        let (id, kind, partition, details) = row.map_err(|_| "凭据元数据损坏")?;
        let details: Value = serde_json::from_str(&details).map_err(|_| "凭据资料 JSON 损坏")?;
        if !details.is_object() {
            return Err("凭据资料不是对象");
        }
        items.insert(
            id,
            Item {
                kind,
                partition,
                details,
            },
        );
    }
    let original = items.clone();
    let mut changed = BTreeSet::new();
    let mut counts = BTreeMap::from([
        ("1_4_passkey_backlinks", 0),
        ("5_mfa_bindings", 0),
        ("5_mfa_binding_fields", 0),
        ("5_single_mfa_inconsistent", 0),
        ("5_pending_mfa_rules", 0),
        ("5_pending_mfa_rules_after_migration", 0),
        ("6_missing_website_rules", 0),
    ]);
    let mut edges = Vec::new();
    for (id, item) in &items {
        if item.kind != "passkey" {
            continue;
        }
        for target in array(&item.details, "related_item_ids")? {
            if items.get(&target).is_some_and(|v| v.kind == "login") {
                edges.push((id.clone(), target));
            }
        }
    }
    for (passkey, login) in edges {
        if items[&passkey].partition != items[&login].partition {
            return Err("存在跨分区关联，需要先在 App 中处理");
        }
        if append(items.get_mut(&login).unwrap(), "related_item_ids", &passkey)? {
            changed.insert(login.clone());
        }
        let remaining: Vec<_> = array(&items[&passkey].details, "related_item_ids")?
            .into_iter()
            .filter(|id| id != &login)
            .collect();
        items.get_mut(&passkey).unwrap().details["related_item_ids"] = json!(remaining);
        changed.insert(passkey);
        *counts.get_mut("1_4_passkey_backlinks").unwrap() += 1;
    }
    let mut stmt = conn
        .prepare("SELECT id,item_id,origin,linked_totp_id FROM login_credentials")
        .map_err(|_| "无法检查账密关联")?;
    let logins = stmt
        .query_map([], |r| {
            Ok(Login {
                id: r.get(0)?,
                item: r.get(1)?,
                origin: r.get(2)?,
                totp: r.get(3)?,
            })
        })
        .map_err(|_| "无法读取账密关联")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| "账密关联损坏")?;
    let mut stmt = conn
        .prepare("SELECT id,item_id FROM totp_credentials")
        .map_err(|_| "无法检查 MFA 关联")?;
    let totps = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|_| "无法读取 MFA 关联")?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()
        .map_err(|_| "MFA 关联损坏")?;
    let mut single_mfa = Vec::new();
    *counts.get_mut("5_mfa_binding_fields").unwrap() = original
        .values()
        .filter(|item| item.details.get("mfa_bindings").is_some())
        .count();
    for login in logins {
        let item = items.get_mut(&login.item).ok_or("账密缺少所属记录")?;
        let mut rules = values(&item.details, "uris")?;
        if rules.is_empty() && !login.origin.trim().is_empty() {
            let rule = json!({"id":Uuid::new_v4().to_string(),"uri":login.origin,"match_mode":"exact_origin"});
            let parsed = serde_json::from_value(rule.clone()).map_err(|_| "旧网站规则无法转换")?;
            credpivot_core::manage_credentials(
                conn,
                credpivot_core::VaultAction::WebsiteRulesTest {
                    rules: vec![parsed],
                    target: None,
                },
            )
            .map_err(|_| "旧网站地址无效，需要在 App 中确认后重试")?;
            rules.push(rule);
            item.details["uris"] = json!(&rules);
            changed.insert(login.item.clone());
            *counts.get_mut("6_missing_website_rules").unwrap() += 1;
        }
        if let Some(id) = &login.totp {
            if !totps.contains_key(id) {
                return Err("账密存在失效的单 MFA 引用，请在 App 中处理");
            }
            if append(item, "linked_mfa_ids", id)? {
                changed.insert(login.item.clone());
            }
        }
        let bindings = values(&item.details, "mfa_bindings")?;
        *counts.get_mut("5_mfa_bindings").unwrap() += bindings.len();
        for binding in &bindings {
            let id = binding["totp_id"].as_str().ok_or("旧 MFA 关联格式无效")?;
            if append(items.get_mut(&login.item).unwrap(), "linked_mfa_ids", id)? {
                changed.insert(login.item.clone());
            }
            let target = totps.get(id).ok_or("旧 MFA 关联指向不存在的记录")?;
            if items[&login.item].partition
                != items.get(target).ok_or("MFA 缺少所属记录")?.partition
            {
                return Err("旧 MFA 存在跨分区关联");
            }
            let selected = binding["website_rule_ids"]
                .as_array()
                .ok_or("旧 MFA 网站规则格式无效")?;
            if selected.iter().any(|value| value.as_str().is_none()) {
                return Err("旧 MFA 网站规则包含无效引用");
            }
            // 旧账号范围只转为待确认建议，不自动成为 MFA 的可填充网站。
            let mfa = items.get_mut(target).ok_or("MFA 缺少所属记录")?;
            let active = values(&mfa.details, "uris")?;
            let mut pending = values(&mfa.details, "pending_mfa_uris")?;
            for rule in rules.iter().filter(|r| selected.contains(&r["id"])) {
                if active
                    .iter()
                    .chain(&pending)
                    .any(|r| r["uri"] == rule["uri"] && r["match_mode"] == rule["match_mode"])
                {
                    continue;
                }
                let mut rule = rule.clone();
                rule["id"] = json!(Uuid::new_v4().to_string());
                pending.push(rule);
                if pending.len() > 100 {
                    return Err("MFA 待确认规则过多，请在 App 中处理");
                }
                mfa.details["pending_mfa_uris"] = json!(&pending);
                changed.insert(target.clone());
            }
        }
        if items[&login.item].details.get("mfa_bindings").is_some() {
            items
                .get_mut(&login.item)
                .unwrap()
                .details
                .as_object_mut()
                .unwrap()
                .remove("mfa_bindings");
            changed.insert(login.item.clone());
        }
        let ids = array(&items[&login.item].details, "linked_mfa_ids")?;
        // 服务器登录仍使用单 MFA 字段；只同步它，不删除仍在使用的业务字段。
        let single = login
            .totp
            .as_ref()
            .filter(|id| ids.contains(id))
            .cloned()
            .or_else(|| {
                if ids.len() == 1 {
                    Some(ids[0].clone())
                } else {
                    None
                }
            });
        if single != login.totp
            || original[&login.item].details.get("linked_mfa_ids")
                != items[&login.item].details.get("linked_mfa_ids")
        {
            *counts.get_mut("5_single_mfa_inconsistent").unwrap() += 1;
        }
        if single != login.totp {
            single_mfa.push((login.id, single));
            changed.insert(login.item);
        }
    }
    for (id, item) in &mut items {
        if item.kind == "login" || item.details.get("mfa_bindings").is_none() {
            continue;
        }
        if !values(&item.details, "mfa_bindings")?.is_empty() {
            return Err("非账密记录包含旧 MFA 绑定，需要人工确认");
        }
        item.details.as_object_mut().unwrap().remove("mfa_bindings");
        changed.insert(id.clone());
    }
    let mut pending_before = 0;
    for item in original.values().filter(|i| i.kind == "totp") {
        pending_before += values(&item.details, "pending_mfa_uris")?.len();
    }
    *counts.get_mut("5_pending_mfa_rules").unwrap() = pending_before;
    let mut pending_count = 0;
    for item in items.values().filter(|i| i.kind == "totp") {
        pending_count += values(&item.details, "pending_mfa_uris")?.len();
    }
    *counts
        .get_mut("5_pending_mfa_rules_after_migration")
        .unwrap() = pending_count;
    Ok(Plan {
        items,
        changed,
        single_mfa,
        counts,
    })
}

fn backup(conn: &Connection, dir: &Path, backup_dir: &Path, key: &[u8; 32]) -> Result<()> {
    private_dir(backup_dir)?;
    let mut config = private_file(&backup_dir.join("vault.json"))?;
    config
        .write_all(&fs::read(dir.join("vault.json")).map_err(|_| "无法备份控制文件")?)
        .map_err(|_| "无法写入控制文件备份")?;
    config.sync_all().map_err(|_| "无法持久化控制文件备份")?;
    private_file(&backup_dir.join("vault.db"))?;
    let mut dest = open_db(&backup_dir.join("vault.db"), key, true)?;
    let copy = Backup::new(conn, &mut dest).map_err(|_| "无法建立加密数据库备份")?;
    copy.run_to_completion(100, Duration::from_millis(20), None)
        .map_err(|_| "加密数据库备份失败")?;
    drop(copy);
    let check: String = dest
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|_| "备份校验失败")?;
    if check != "ok" {
        return Err("备份校验失败");
    }
    Ok(())
}

fn local_config(apply: bool, backup_dir: Option<&Path>, launch: Option<bool>) -> Result<Value> {
    let catalog: Value = serde_json::from_str(CATALOG).map_err(|_| "内置语言目录无效")?;
    let keys: Vec<_> = catalog["messages"]
        .as_object()
        .ok_or("内置语言目录无效")?
        .keys()
        .collect();
    let mut child = Command::new("python3")
        .arg("-c")
        .arg(LOCAL_SCRIPT)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "需要 Python 3 才能检查本机配置")?;
    let request =
        json!({"apply":apply,"backup_dir":backup_dir,"catalog_keys":keys,"launch_at_login":launch});
    let mut input = child.stdin.take().ok_or("无法连接本地配置检查器")?;
    let sent = input.write_all(request.to_string().as_bytes());
    drop(input);
    let out = child.wait_with_output().map_err(|_| "本地配置检查未完成")?;
    sent.map_err(|_| "无法启动本地配置检查")?;
    let report: Value = serde_json::from_slice(&out.stdout).map_err(|_| "本地配置检查未完成")?;
    if !out.status.success() || report["ok"] != true {
        println!("{}", report);
        return Err("本机配置存在待处理项；未继续迁移");
    }
    Ok(report)
}

pub fn run(vault_dir: Option<PathBuf>, apply: bool, launch: Option<bool>) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let home = std::env::var_os("HOME").ok_or("找不到用户目录")?;
    let runtime = PathBuf::from(home).join(".credpivot");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(runtime.join("vault.runtime.lock"))
        .map_err(|_| "无法打开保险库运行锁")?;
    lock.try_lock_exclusive()
        .map_err(|_| "请先完全退出 CredPivot App，再执行独立升级脚本")?;
    let settings: Value = if runtime.join("settings.json").is_file() {
        serde_json::from_slice(
            &fs::read(runtime.join("settings.json")).map_err(|_| "无法读取本机配置")?,
        )
        .map_err(|_| "本机配置格式无效")?
    } else {
        json!({})
    };
    let dir = vault_dir
        .or_else(|| settings["vault_directory"].as_str().map(PathBuf::from))
        .or_else(|| {
            fs::read_to_string(runtime.join("active_vault_dir"))
                .ok()
                .map(|v| PathBuf::from(v.trim()))
        })
        .unwrap_or_else(|| runtime.join("vault"));
    let local_before = local_config(false, None, launch)?;
    if apply && local_before["manual_required"] == true {
        println!("{}", local_before);
        return Err("请按报告补齐参数后重试，尚未修改数据");
    }
    let config = credpivot_core::read_vault_json(&dir).map_err(|_| "无法读取保险库控制文件")?;
    let password = Zeroizing::new(
        rpassword::prompt_password("主密码（仅本地使用，不回显）: ")
            .map_err(|_| "无法读取主密码")?,
    );
    let vmk = config
        .unlock_master(&password)
        .map_err(|_| "无法解锁保险库")?;
    drop(password);
    config
        .verify_mac(&vmk)
        .map_err(|_| "保险库控制文件校验失败")?;
    let vault_id = Uuid::parse_str(&config.vault_id).map_err(|_| "保险库标识无效")?;
    let key = Zeroizing::new(credpivot_core::derive_sqlcipher_key(
        &vmk,
        vault_id.as_bytes(),
    ));
    let mut conn = open_db(&dir.join("vault.db"), &key, apply)?;
    let schema: i32 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(|_| "无法读取数据库版本")?;
    credpivot_core::validate_schema_version(&conn)
        .map_err(|_| "数据库版本不受支持；独立脚本只清理当前结构的数据，不升级历史结构")?;
    let before = json!(plan(&conn)?.counts);
    let mut report = json!({"mode":if apply {"apply"} else {"check"},"schema_before":schema,
        "schema_upgrade_required":false,"database_before":before,
        "local_before":local_before,"other_vaults_and_archives_checked":false,"remote_cleanup_performed":false});
    if !apply {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return Ok(());
    }
    let parent = dir.join("upgrade-backups");
    if !parent.exists() {
        private_dir(&parent)?;
    }
    let name = format!(
        "{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "系统时间无效")?
            .as_millis(),
        Uuid::new_v4()
    );
    let backup_dir = parent.join(&name);
    backup(&conn, &dir, &backup_dir, &key)?;
    eprintln!("已创建加密备份：upgrade-backups/{name}");
    report["backup_relative_path"] = json!(format!("upgrade-backups/{name}"));
    report["schema_after"] = json!(schema);
    let migration = plan(&conn)?;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| "无法开始数据迁移事务")?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "系统时间无效")?
        .as_millis() as i64;
    for id in &migration.changed {
        let revision = Uuid::new_v4().to_string();
        tx.execute(
            "UPDATE items SET details_json=?1,current_revision=?2,updated_at_ms=?3 WHERE id=?4",
            params![
                migration.items[id].details.to_string(),
                revision,
                timestamp,
                id
            ],
        )
        .map_err(|_| "凭据关系迁移失败，当前事务已撤销")?;
        for table in [
            "login_credentials",
            "totp_credentials",
            "ssh_keys",
            "recovery_code_items",
            "server_login_profiles",
        ] {
            tx.execute(
                &format!(
                    "UPDATE {table} SET current_revision=?1,updated_at_ms=?2 WHERE item_id=?3"
                ),
                params![revision, timestamp, id],
            )
            .map_err(|_| "凭据版本更新失败，当前事务已撤销")?;
        }
    }
    for (id, single) in &migration.single_mfa {
        tx.execute(
            "UPDATE login_credentials SET linked_totp_id=?1 WHERE id=?2",
            params![single, id],
        )
        .map_err(|_| "单 MFA 关联同步失败，当前事务已撤销")?;
    }
    credpivot_core::partitions::validate(&tx)
        .map_err(|_| "迁移结果关系校验失败，当前事务已撤销")?;
    if !migration.changed.is_empty() {
        credpivot_core::mark_restore_dirty(&tx).map_err(|_| "无法更新恢复点状态")?;
    }
    tx.commit()
        .map_err(|_| "数据事务提交失败；原始加密备份已保留")?;
    report["database_after"] = json!(plan(&conn)?.counts);
    report["local_after"] = local_config(true, Some(&backup_dir), launch)?;
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok(())
}
