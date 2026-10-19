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
    login: Option<BwLogin>,
}

#[derive(Debug, serde::Serialize)]
pub struct ImportReport {
    pub imported: u32,
    pub skipped_duplicate: u32,
    pub skipped_invalid: u32,
}

pub fn import_bitwarden_json(conn: &Connection, json: &str) -> Result<ImportReport> {
    let items: Vec<BwItem> = serde_json::from_str(json).map_err(|e| CoreError::format(e.to_string()))?;
    let mut report = ImportReport {
        imported: 0,
        skipped_duplicate: 0,
        skipped_invalid: 0,
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
        let origin = login
            .uris
            .and_then(|u| u.first().and_then(|x| x.uri.clone()))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| item.name.clone().unwrap_or_else(|| "imported".into()));
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
