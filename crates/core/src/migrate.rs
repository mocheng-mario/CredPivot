use crate::error::{CoreError, Result};
use rusqlite::Connection;

/// SQLCipher `user_version`：与迁移脚本同步递增。
pub const SCHEMA_USER_VERSION: i32 = 3;

const MIGRATION_V1: &str = "
CREATE TABLE IF NOT EXISTS vault_meta (
  key TEXT PRIMARY KEY NOT NULL,
  value BLOB NOT NULL
);
INSERT OR IGNORE INTO vault_meta(key, value) VALUES ('m1_marker', X'01');
";

const MIGRATION_V2: &str = "
CREATE TABLE IF NOT EXISTS items (
  id TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  trashed INTEGER NOT NULL DEFAULT 0 CHECK (trashed IN (0, 1)),
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  username TEXT NOT NULL,
  secret TEXT NOT NULL,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (item_id) REFERENCES items(id)
);

CREATE INDEX IF NOT EXISTS idx_login_credentials_origin ON login_credentials(origin);
";

const MIGRATION_V3: &str = "
CREATE TABLE IF NOT EXISTS password_history (
  id TEXT PRIMARY KEY NOT NULL,
  credential_id TEXT NOT NULL,
  secret TEXT NOT NULL,
  activated_at_ms INTEGER NOT NULL,
  retired_at_ms INTEGER,
  FOREIGN KEY (credential_id) REFERENCES login_credentials(id)
);

CREATE TABLE IF NOT EXISTS totp_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  account TEXT NOT NULL,
  secret_base32 TEXT NOT NULL,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (item_id) REFERENCES items(id)
);

CREATE TABLE IF NOT EXISTS ssh_keys (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  label TEXT NOT NULL,
  public_openssh TEXT NOT NULL,
  private_key_seed BLOB NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (item_id) REFERENCES items(id)
);

CREATE TABLE IF NOT EXISTS recovery_code_items (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  service_name TEXT NOT NULL,
  codes_json TEXT NOT NULL,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (item_id) REFERENCES items(id)
);

CREATE TABLE IF NOT EXISTS vault_settings (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS import_mappings (
  source_namespace TEXT NOT NULL,
  source_item_id TEXT NOT NULL,
  local_item_id TEXT NOT NULL,
  PRIMARY KEY (source_namespace, source_item_id)
);

ALTER TABLE login_credentials ADD COLUMN password_active_since_ms INTEGER NOT NULL DEFAULT 0;
";

pub fn migrate_to_latest(conn: &Connection) -> Result<()> {
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| CoreError::format(e.to_string()))?;

    if version < 1 {
        conn.execute_batch(MIGRATION_V1)
            .map_err(|e| CoreError::format(e.to_string()))?;
        conn.pragma_update(None, "user_version", 1)
            .map_err(|e| CoreError::format(e.to_string()))?;
    }
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| CoreError::format(e.to_string()))?;
    if version < 2 {
        conn.execute_batch(MIGRATION_V2)
            .map_err(|e| CoreError::format(e.to_string()))?;
        conn.pragma_update(None, "user_version", 2)
            .map_err(|e| CoreError::format(e.to_string()))?;
    }
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| CoreError::format(e.to_string()))?;
    if version < 3 {
        conn.execute_batch(MIGRATION_V3)
            .map_err(|e| CoreError::format(e.to_string()))?;
        conn.pragma_update(None, "user_version", SCHEMA_USER_VERSION)
            .map_err(|e| CoreError::format(e.to_string()))?;
    }
    Ok(())
}
