use crate::error::{CoreError, Result};
use crate::repo::insert_login_credential_in_tx;
use rusqlite::{params, Connection};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    uris: Option<Vec<BwUri>>,
}

#[derive(Debug, Deserialize)]
struct BwUri {
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwItem {
    id: Option<String>,
    name: Option<String>,
    notes: Option<String>,
    login: Option<BwLogin>,
}

/// Bitwarden 官方导出：`{ "items": [ ... ] }`
#[derive(Debug, Deserialize)]
struct BwExportRoot {
    items: Option<Vec<BwItem>>,
}

fn parse_bitwarden_items(json: &str) -> Result<Vec<BwItem>> {
    if let Ok(root) = serde_json::from_str::<BwExportRoot>(json) {
        return Ok(root.items.unwrap_or_default());
    }
    serde_json::from_str(json).map_err(|e| CoreError::format(e.to_string()))
}

#[derive(Debug, serde::Serialize)]
pub struct ImportReport {
    pub imported: u32,
    pub skipped_duplicate: u32,
    pub skipped_invalid: u32,
    /// 含备注、额外 URI、TOTP 等当前未迁入字段的条目数（仍可能已导入登录）。
    pub skipped_unsupported_fields: u32,
}

pub fn import_bitwarden_json(conn: &Connection, json: &str) -> Result<ImportReport> {
    let items: Vec<BwItem> = parse_bitwarden_items(json)?;
    let mut report = ImportReport {
        imported: 0,
        skipped_duplicate: 0,
        skipped_invalid: 0,
        skipped_unsupported_fields: 0,
    };
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| CoreError::format(e.to_string()))?;
    for item in items {
        let login = match item.login {
            Some(l) => l,
            None => {
                report.skipped_invalid += 1;
                continue;
            }
        };
        let username = login.username.unwrap_or_default();
        let password = login.password.unwrap_or_default();
        if username.is_empty() && password.is_empty() {
            report.skipped_invalid += 1;
            continue;
        }
        let uris = login.uris.unwrap_or_default();
        let origin = uris
            .first()
            .and_then(|x| x.uri.as_deref())
            .filter(|s| !s.is_empty())
            .map(normalize_login_origin)
            .unwrap_or_else(|| item.name.clone().unwrap_or_else(|| "imported".into()));
        let has_extra_uri = uris.len() > 1;
        let has_notes = item.notes.as_deref().is_some_and(|n| !n.trim().is_empty());
        if has_extra_uri || has_notes {
            report.skipped_unsupported_fields += 1;
        }
        let source_id = item.id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
        let exists: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM import_mappings WHERE source_namespace = 'bitwarden' AND source_item_id = ?1",
                params![source_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if exists > 0 {
            report.skipped_duplicate += 1;
            continue;
        }
        let rec = insert_login_credential_in_tx(&tx, &origin, &username, &password)?;
        tx.execute(
            "INSERT INTO import_mappings (source_namespace, source_item_id, local_item_id) VALUES ('bitwarden', ?1, ?2)",
            params![source_id, rec.item_id],
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
        report.imported += 1;
    }
    tx.commit().map_err(|e| CoreError::format(e.to_string()))?;
    Ok(report)
}

/// 与浏览器填充查询一致：仅保留 scheme + host（无路径）。
fn normalize_login_origin(uri: &str) -> String {
    let s = uri.trim();
    let (scheme, rest) = if let Some(r) = s.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = s.strip_prefix("http://") {
        ("http", r)
    } else {
        return s.to_string();
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .split(':')
        .next()
        .unwrap_or(authority);
    format!("{scheme}://{host}")
}
