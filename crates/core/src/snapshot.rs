use crate::error::{CoreError, Result};
use crate::local_db;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

pub const SNAPSHOT_FORMAT: &str = "credpivot-snapshot-m1";
pub const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct M1Snapshot {
    format: String,
    version: u32,
    vault_json: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    database_b64: Option<String>,
}

pub fn pack_snapshot_from_dir(vault_dir: &Path, vmk: &Zeroizing<[u8; 32]>) -> Result<Vec<u8>> {
    let vault_json = fs::read_to_string(vault_dir.join("vault.json"))
        .map_err(|e| CoreError::io(e.to_string()))?;
    let db_bytes = local_db::export_database_bytes(vault_dir, &**vmk)?;
    let snap = M1Snapshot {
        format: SNAPSHOT_FORMAT.into(),
        version: SNAPSHOT_VERSION,
        vault_json,
        database_b64: Some(STANDARD.encode(db_bytes)),
    };
    serde_json::to_vec(&snap).map_err(|e| CoreError::format(e.to_string()))
}

pub fn unpack_snapshot_to_dir(snapshot: &[u8], vault_dir: &Path, vmk: &Zeroizing<[u8; 32]>) -> Result<()> {
    let snap: M1Snapshot =
        serde_json::from_slice(snapshot).map_err(|e| CoreError::format(e.to_string()))?;
    if snap.format != SNAPSHOT_FORMAT || snap.version != SNAPSHOT_VERSION {
        return Err(CoreError::format("snapshot version"));
    }
    fs::create_dir_all(vault_dir).map_err(|e| CoreError::io(e.to_string()))?;
    fs::write(vault_dir.join("vault.json"), snap.vault_json.as_bytes())
        .map_err(|e| CoreError::io(e.to_string()))?;
    if let Some(b64) = snap.database_b64 {
        let bytes = STANDARD
            .decode(b64)
            .map_err(|_| CoreError::format("database b64"))?;
        local_db::import_database_bytes(vault_dir, &**vmk, &bytes)?;
    }
    Ok(())
}
