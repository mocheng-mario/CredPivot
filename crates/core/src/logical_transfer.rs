use crate::{CoreError, Result};
use crate::credential_management::LOGICAL_TABLES;
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params_from_iter, types::Value as SqlValue};
use serde_json::Value;
use std::{fs, path::Path};

/// 只创建独立新库；输入表名和列名都必须来自本地模式白名单。
pub fn import_logical_json_to_dir(json: &str, target: &Path, password: &str) -> Result<String> {
    if password.chars().count() < 8 { return Err(CoreError::format("新主密码至少需要 8 个字符")); }
    let invalid = || CoreError::format("明文文件格式、版本或记录不正确");
    let doc: Value = serde_json::from_str(json).map_err(|_| invalid())?;
    if doc["format"] != "credpivot-logical" || doc["version"] != 1
        || doc["schema_version"] != crate::SCHEMA_USER_VERSION { return Err(invalid()); }
    let tables = doc["tables"].as_object().ok_or_else(invalid)?;
    if tables.len() != LOGICAL_TABLES.len() || LOGICAL_TABLES.iter().any(|t| !tables.get(*t).is_some_and(Value::is_array)) { return Err(invalid()); }
    crate::ensure_empty_target(target)?;
    let parent = target.parent().ok_or_else(invalid)?;
    let staging = parent.join(format!(".credpivot-import-{}", uuid::Uuid::new_v4()));
    // 原子占有临时目录，失败清理只涉及本次创建的目录。
    fs::create_dir(&staging).map_err(|e| CoreError::io(e.to_string()))?;
    let result = (|| {
        let material = crate::bootstrap_vault_dir(&staging, password)?;
        let conn = crate::local_db::open_database(&staging, &material.vmk)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch("PRAGMA defer_foreign_keys=ON; INSERT INTO sync_state(key,value) VALUES ('applying','true');")?;
        for table in LOGICAL_TABLES.iter().rev() { tx.execute(&format!("DELETE FROM {table}"), [])?; }
        for &table in LOGICAL_TABLES {
            let mut stmt = tx.prepare(&format!("PRAGMA table_info({table})"))?;
            let columns = stmt.query_map([], |r| r.get::<_, String>(1))?.collect::<std::result::Result<Vec<_>, _>>()?;
            let names = columns.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(",");
            let sql = format!("INSERT INTO {table} ({names}) VALUES ({})", vec!["?"; columns.len()].join(","));
            let mut insert = tx.prepare(&sql)?;
            for row in tables[table].as_array().ok_or_else(invalid)? {
                let row = row.as_object().ok_or_else(invalid)?;
                if row.len() != columns.len() { return Err(invalid()); }
                let values = columns.iter().map(|c| {
                    Ok(match row.get(c).ok_or_else(invalid)? {
                        Value::Null => SqlValue::Null,
                        Value::String(s) => SqlValue::Text(s.clone()),
                        Value::Number(n) if n.is_i64() => SqlValue::Integer(n.as_i64().ok_or_else(invalid)?),
                        Value::Number(n) if n.is_f64() => SqlValue::Real(n.as_f64().ok_or_else(invalid)?),
                        Value::Object(o) if o.len() == 1 => SqlValue::Blob(STANDARD.decode(o.get("base64").and_then(Value::as_str).ok_or_else(invalid)?).map_err(|_| invalid())?),
                        _ => return Err(invalid()),
                    })
                }).collect::<Result<Vec<_>>>()?;
                insert.execute(params_from_iter(values)).map_err(|_| invalid())?;
            }
        }
        crate::partitions::validate(&tx)?;
        if tx.prepare("PRAGMA foreign_key_check")?.query([])?.next()?.is_some() { return Err(invalid()); }
        tx.execute("DELETE FROM sync_state WHERE key='applying'", [])?;
        crate::mark_restore_dirty(&tx)?;
        tx.commit()?;
        crate::sync::validate_document(&crate::sync::capture(&conn)?)?;
        drop(conn);
        crate::local_db::verify_database(&staging, &material.vmk)?;
        crate::ensure_empty_target(target)?;
        fs::File::open(&staging).and_then(|file| file.sync_all()).map_err(|e| CoreError::io(e.to_string()))?;
        fs::rename(&staging, target).map_err(|e| CoreError::io(e.to_string()))?;
        // 目录已激活后不再返回错误，确保新恢复码始终交付给调用方。
        let _ = fs::File::open(parent).and_then(|file| file.sync_all());
        Ok(material.recovery_display)
    })();
    if result.is_err() { let _ = fs::remove_dir_all(&staging); }
    result
}
