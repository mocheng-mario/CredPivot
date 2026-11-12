//! 一次性清空认证关联。只由独立 CLI 执行，App 不调用。
//! 不升级数据库版本，不读取、不打印、不复制密码或其他秘密。
use fs2::FileExt;
use rusqlite::{backup::Backup, params, Connection, OpenFlags};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, &'static str>;

struct Counts {
    logins_with_totp: usize,
    items_with_mfa: usize,
    items_with_related: usize,
    logins_marked_disabled: usize,
    connections: usize,
    connections_with_refs: usize,
}

pub fn run(vault_dir: Option<PathBuf>, apply: bool) -> Result<()> {
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
        .map_err(|_| "请先完全退出 CredPivot App 和同步，再执行此脚本")?;
    let settings: Value = if runtime.join("settings.json").is_file() {
        serde_json::from_slice(&fs::read(runtime.join("settings.json")).map_err(|_| "无法读取本机配置")?)
            .map_err(|_| "本机配置格式无效")?
    } else {
        json!({})
    };
    let dir = vault_dir
        .or_else(|| settings["vault_directory"].as_str().map(PathBuf::from))
        .or_else(|| {
            fs::read_to_string(runtime.join("active_vault_dir"))
                .ok()
                .map(|value| PathBuf::from(value.trim()))
                .filter(|path| !path.as_os_str().is_empty())
        })
        .unwrap_or_else(|| runtime.join("vault"));
    let config = credpivot_core::read_vault_json(&dir).map_err(|_| "无法读取保险库控制文件")?;
    let password = Zeroizing::new(
        rpassword::prompt_password("主密码（仅本地使用，不回显）: ").map_err(|_| "无法读取主密码")?,
    );
    let vmk = config.unlock_master(&password).map_err(|_| "无法解锁保险库")?;
    drop(password);
    config.verify_mac(&vmk).map_err(|_| "保险库控制文件校验失败")?;
    let vault_id = Uuid::parse_str(&config.vault_id).map_err(|_| "保险库标识无效")?;
    let key = Zeroizing::new(credpivot_core::derive_sqlcipher_key(&vmk, vault_id.as_bytes()));
    let mut conn = open_db(&dir.join("vault.db"), &key, apply)?;
    let schema: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| "无法读取数据库版本")?;
    if schema != 14 {
        return Err("数据库不是当前版本 14。此脚本不升级结构，也没有修改数据");
    }
    if table_exists(&conn, "server_stale_auth")? {
        return Err("已经执行过关联清空，未做任何修改");
    }
    let counts = inspect(&conn)?;
    println!(
        "将清空：账密上的 MFA 引用 {mfa_links} 条，资料里的 MFA 列表 {mfa_lists} 条，普通关联 {related} 条。",
        mfa_links = counts.logins_with_totp,
        mfa_lists = counts.items_with_mfa,
        related = counts.items_with_related
    );
    println!(
        "将把 {logins} 条账户的 MFA 状态记为未启用。",
        logins = counts.logins_marked_disabled
    );
    println!(
        "将停用全部 {connections} 条服务器连接；其中 {linked} 条保留旧引用供以后查看，不作为有效认证。",
        connections = counts.connections,
        linked = counts.connections_with_refs
    );
    println!("不复制密码，不改密码、历史、候选、网站规则、MFA 规则、SSH 规则、分组和分区。数据库版本保持 14。");
    if !apply {
        println!("这是预览，没有修改数据。确认后执行：cargo run -p credpivot-cli -- clear-associations --apply");
        return Ok(());
    }
    let parent = dir.join("upgrade-backups");
    if !parent.exists() {
        private_dir(&parent)?;
    }
    let name = format!(
        "association-clear-{}-{}",
        SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "系统时间无效")?.as_millis(),
        Uuid::new_v4()
    );
    let backup_dir = parent.join(&name);
    backup(&conn, &dir, &backup_dir, &key)?;
    eprintln!("已创建加密备份：upgrade-backups/{name}");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "系统时间无效")?
        .as_millis() as i64;
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| "无法开始事务")?;
    tx.execute_batch(
        "CREATE TABLE server_stale_auth (
            profile_id TEXT PRIMARY KEY NOT NULL,
            linked_login_id TEXT,
            linked_totp_id TEXT,
            linked_ssh_key_id TEXT,
            auth_mode TEXT NOT NULL,
            unavailable INTEGER NOT NULL,
            unavailable_reason TEXT NOT NULL
        );",
    )
    .map_err(|_| "无法保存连接的旧引用，当前事务已撤销")?;
    let profiles = profiles(&tx)?;
    for profile in &profiles {
        let revision = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO server_stale_auth (profile_id, linked_login_id, linked_totp_id, linked_ssh_key_id, auth_mode, unavailable, unavailable_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, '需要重新确认关联后才能使用')",
            params![profile.id, profile.login, profile.totp, profile.ssh, profile.mode],
        )
        .map_err(|_| "无法保存连接的旧引用，当前事务已撤销")?;
        tx.execute(
            "UPDATE server_login_profiles
             SET linked_login_id=NULL, linked_totp_id=NULL, linked_ssh_key_id=NULL, current_revision=?1, updated_at_ms=?2
             WHERE id=?3",
            params![revision, timestamp, profile.id],
        )
        .map_err(|_| "无法停用服务器连接，当前事务已撤销")?;
        tx.execute(
            "UPDATE items SET current_revision=?1, updated_at_ms=?2 WHERE id=?3",
            params![revision, timestamp, profile.item_id],
        )
        .map_err(|_| "无法更新服务器连接版本，当前事务已撤销")?;
    }
    let items = items(&tx)?;
    for mut item in items {
        if !clear_details(&item.kind, &mut item.details)? {
            continue;
        }
        let revision = Uuid::new_v4().to_string();
        tx.execute(
            "UPDATE items SET details_json=?1, current_revision=?2, updated_at_ms=?3 WHERE id=?4",
            params![item.details.to_string(), revision, timestamp, item.id],
        )
        .map_err(|_| "无法清空资料关联，当前事务已撤销")?;
        for table in ["login_credentials", "totp_credentials", "ssh_keys", "recovery_code_items", "server_login_profiles"] {
            tx.execute(
                &format!("UPDATE {table} SET current_revision=?1, updated_at_ms=?2 WHERE item_id=?3"),
                params![revision, timestamp, item.id],
            )
            .map_err(|_| "无法更新凭据版本，当前事务已撤销")?;
        }
    }
    let pending = linked_totp(&tx)?;
    for (id, item_id) in pending {
        let revision = Uuid::new_v4().to_string();
        tx.execute(
            "UPDATE login_credentials SET linked_totp_id=NULL, current_revision=?1, updated_at_ms=?2 WHERE id=?3",
            params![revision, timestamp, id],
        )
        .map_err(|_| "无法清空账密上的 MFA 引用，当前事务已撤销")?;
        tx.execute(
            "UPDATE items SET current_revision=?1, updated_at_ms=?2 WHERE id=?3",
            params![revision, timestamp, item_id],
        )
        .map_err(|_| "无法清空账密上的 MFA 引用，当前事务已撤销")?;
    }
    credpivot_core::partitions::validate(&tx).map_err(|_| "清空后的关系校验失败，当前事务已撤销")?;
    credpivot_core::mark_restore_dirty(&tx).map_err(|_| "无法更新恢复点状态")?;
    tx.commit().map_err(|_| "提交失败；原始加密备份已保留，数据库版本未改变")?;
    let check: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| "清空后的完整性检查失败")?;
    if check != "ok" {
        return Err("清空后的完整性检查失败；请先不要启动 App，用刚才的加密备份人工处理");
    }
    println!("关联已清空。数据库版本仍是 14。");
    println!("先不要启动当前这版 Mac App，也不要恢复旧备份或重新打开同步。");
    Ok(())
}

struct Profile {
    id: String,
    item_id: String,
    login: Option<String>,
    totp: Option<String>,
    ssh: Option<String>,
    mode: &'static str,
}

struct ItemRow {
    id: String,
    kind: String,
    details: Value,
}

fn inspect(conn: &Connection) -> Result<Counts> {
    let logins_with_totp = count(
        conn,
        "SELECT count(*) FROM login_credentials WHERE linked_totp_id IS NOT NULL AND linked_totp_id!=''",
    )?;
    let connections = count(conn, "SELECT count(*) FROM server_login_profiles")?;
    let connections_with_refs = count(
        conn,
        "SELECT count(*) FROM server_login_profiles
         WHERE (linked_login_id IS NOT NULL AND linked_login_id!='')
            OR (linked_totp_id IS NOT NULL AND linked_totp_id!='')
            OR (linked_ssh_key_id IS NOT NULL AND linked_ssh_key_id!='')",
    )?;
    let mut items_with_mfa = 0;
    let mut items_with_related = 0;
    let mut logins_marked_disabled = 0;
    for item in items(conn)? {
        let mfa = array(&item.details, "linked_mfa_ids")?;
        let related = array(&item.details, "related_item_ids")?;
        if !mfa.is_empty() {
            items_with_mfa += 1;
        }
        if !related.is_empty() {
            items_with_related += 1;
        }
        if item.kind == "login" && item.details.get("mfa_state").and_then(Value::as_str) != Some("disabled") {
            logins_marked_disabled += 1;
        }
    }
    Ok(Counts { logins_with_totp, items_with_mfa, items_with_related, logins_marked_disabled, connections, connections_with_refs })
}

fn clear_details(kind: &str, details: &mut Value) -> Result<bool> {
    let object = details.as_object_mut().ok_or("资料不是对象，已停止且未修改数据")?;
    let mut changed = false;
    for field in ["linked_mfa_ids", "related_item_ids"] {
        if object.get(field).is_some_and(|value| value.as_array().is_some_and(|ids| !ids.is_empty())) {
            if !object[field].is_array() {
                return Err("关联字段不是数组，已停止且未修改数据");
            }
            object.insert(field.to_string(), json!([]));
            changed = true;
        } else if object.get(field).is_some_and(|value| !value.is_array()) {
            return Err("关联字段不是数组，已停止且未修改数据");
        }
    }
    if kind == "login" && object.get("mfa_state").and_then(Value::as_str) != Some("disabled") {
        object.insert("mfa_state".to_string(), json!("disabled"));
        changed = true;
    }
    Ok(changed)
}

fn items(conn: &Connection) -> Result<Vec<ItemRow>> {
    let mut statement = conn
        .prepare("SELECT id, kind, details_json FROM items ORDER BY id")
        .map_err(|_| "无法读取凭据资料")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })
        .map_err(|_| "无法读取凭据资料")?;
    let mut out = Vec::new();
    for row in rows {
        let (id, kind, details) = row.map_err(|_| "无法读取凭据资料")?;
        let details = serde_json::from_str(&details).map_err(|_| "资料不是对象，已停止且未修改数据")?;
        out.push(ItemRow { id, kind, details });
    }
    Ok(out)
}

fn profiles(conn: &Connection) -> Result<Vec<Profile>> {
    let mut statement = conn
        .prepare(
            "SELECT id, item_id, linked_login_id, linked_totp_id, linked_ssh_key_id
             FROM server_login_profiles ORDER BY id",
        )
        .map_err(|_| "无法读取服务器连接")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                blank(row.get(2)?),
                blank(row.get(3)?),
                blank(row.get(4)?),
            ))
        })
        .map_err(|_| "无法读取服务器连接")?;
    let mut out = Vec::new();
    for row in rows {
        let (id, item_id, login, totp, ssh) = row.map_err(|_| "无法读取服务器连接")?;
        let mode = if login.is_some() { "account" } else { "independent" };
        out.push(Profile { id, item_id, login, totp, ssh, mode });
    }
    Ok(out)
}

fn linked_totp(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut statement = conn
        .prepare("SELECT id, item_id FROM login_credentials WHERE linked_totp_id IS NOT NULL AND linked_totp_id!=''")
        .map_err(|_| "无法清空账密上的 MFA 引用，当前事务已撤销")?;
    let rows = statement
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|_| "无法清空账密上的 MFA 引用，当前事务已撤销")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|_| "无法清空账密上的 MFA 引用，当前事务已撤销")?);
    }
    Ok(out)
}

fn blank(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

fn array(details: &Value, field: &str) -> Result<Vec<String>> {
    match details.get(field) {
        None => Ok(Vec::new()),
        Some(value) => value
            .as_array()
            .ok_or("关联字段不是数组，已停止且未修改数据")?
            .iter()
            .map(|item| item.as_str().map(str::to_string).ok_or("关联字段包含无效值，已停止且未修改数据"))
            .collect(),
    }
}

fn count(conn: &Connection, sql: &str) -> Result<usize> {
    let value: i64 = conn.query_row(sql, [], |row| row.get(0)).map_err(|_| "无法统计关联")?;
    Ok(value as usize)
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let value: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
            params![name],
            |row| row.get(0),
        )
        .map_err(|_| "无法检查是否已经清空")?;
    Ok(value != 0)
}

fn open_db(path: &Path, key: &[u8; 32], writable: bool) -> Result<Connection> {
    let flags = if writable { OpenFlags::SQLITE_OPEN_READ_WRITE } else { OpenFlags::SQLITE_OPEN_READ_ONLY };
    let conn = Connection::open_with_flags(path, flags).map_err(|_| "无法打开保险库数据库")?;
    let hex = Zeroizing::new(super::hex_encode(key));
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", hex.as_str()));
    conn.execute_batch(&pragma).map_err(|_| "无法设置数据库密钥")?;
    conn.execute_batch(
        "PRAGMA cipher_page_size=4096; PRAGMA kdf_iter=256000;
         PRAGMA cipher_hmac_algorithm=HMAC_SHA512; PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512;
         PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;",
    )
    .map_err(|_| "无法设置数据库参数")?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get::<_, i64>(0))
        .map_err(|_| "数据库无法解密或已损坏")?;
    if !writable {
        conn.execute_batch("PRAGMA query_only=ON;").map_err(|_| "无法启用只读检查")?;
    }
    Ok(conn)
}

fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).recursive(true).create(path).map_err(|_| "无法创建备份目录")
}

fn private_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|_| "无法创建备份文件")
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
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| "备份校验失败")?;
    if check != "ok" {
        return Err("备份校验失败");
    }
    Ok(())
}
