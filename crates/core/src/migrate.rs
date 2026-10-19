use crate::error::{CoreError, Result};
use rusqlite::Connection;

/// SQLCipher `user_version`：与迁移脚本同步递增。
pub const SCHEMA_USER_VERSION: i32 = 2;

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
        conn.pragma_update(None, "user_version", SCHEMA_USER_VERSION)
            .map_err(|e| CoreError::format(e.to_string()))?;
    }
    Ok(())
}
