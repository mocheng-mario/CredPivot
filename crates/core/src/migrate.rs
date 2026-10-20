use crate::error::{CoreError, Result};
use rusqlite::Connection;

/// SQLCipher `user_version`：与迁移脚本同步递增。
pub const SCHEMA_USER_VERSION: i32 = 8;

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

const MIGRATION_V4: &str = "
ALTER TABLE login_credentials ADD COLUMN connection_host TEXT NOT NULL DEFAULT '';
ALTER TABLE login_credentials ADD COLUMN linked_totp_id TEXT;
";

const MIGRATION_V5: &str = "
CREATE TABLE IF NOT EXISTS server_login_profiles (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  label TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  manual_username TEXT NOT NULL DEFAULT '',
  linked_login_id TEXT,
  linked_totp_id TEXT,
  linked_ssh_key_id TEXT,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (item_id) REFERENCES items(id)
);
CREATE INDEX IF NOT EXISTS idx_server_login_profiles_host ON server_login_profiles(host);
";

const MIGRATION_V6: &str = "
ALTER TABLE items ADD COLUMN group_id TEXT;
ALTER TABLE login_credentials ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS credential_groups (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  scope TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credential_groups_scope ON credential_groups(scope);
";

const MIGRATION_V7: &str = "
ALTER TABLE totp_credentials ADD COLUMN totp_algorithm TEXT NOT NULL DEFAULT 'SHA1';
ALTER TABLE totp_credentials ADD COLUMN totp_digits INTEGER NOT NULL DEFAULT 6;
ALTER TABLE totp_credentials ADD COLUMN totp_period INTEGER NOT NULL DEFAULT 30;
";

/// 早期开发库在 V5 可能已创建不含 `manual_username` 的 `server_login_profiles`（CREATE IF NOT EXISTS 不会补列）。
fn repair_server_login_profiles_columns(conn: &Connection) -> Result<()> {
    ensure_column(
        conn,
        "server_login_profiles",
        "manual_username",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(conn, "server_login_profiles", "linked_ssh_key_id", "TEXT")?;
    Ok(())
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| CoreError::format(e.to_string()))?;
    let mut exists = false;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| CoreError::format(e.to_string()))?;
    for name in rows {
        if name.as_deref() == Ok(column) {
            exists = true;
            break;
        }
    }
    if !exists {
        let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
        conn.execute(&sql, [])
            .map_err(|e| CoreError::format(e.to_string()))?;
    }
    Ok(())
}

fn current_user_version(conn: &Connection) -> Result<i32> {
    conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| CoreError::format(e.to_string()))
}

fn apply_migration_step(
    conn: &Connection,
    target_version: i32,
    apply: impl FnOnce(&Connection) -> Result<()>,
) -> Result<()> {
    if current_user_version(conn)? >= target_version {
        return Ok(());
    }
    conn.execute("BEGIN IMMEDIATE", [])
        .map_err(|e| CoreError::format(e.to_string()))?;
    let outcome = (|| {
        apply(conn)?;
        conn
            .pragma_update(None, "user_version", target_version)
            .map_err(|e| CoreError::format(e.to_string()))?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = conn.execute("ROLLBACK", []);
        return outcome;
    }
    conn.execute("COMMIT", [])
        .map_err(|e| CoreError::format(e.to_string()))?;
    Ok(())
}

pub fn migrate_to_latest(conn: &Connection) -> Result<()> {
    apply_migration_step(conn, 1, |c| {
        c.execute_batch(MIGRATION_V1)
            .map_err(|e| CoreError::format(e.to_string()))?;
        Ok(())
    })?;
    apply_migration_step(conn, 2, |c| {
        c.execute_batch(MIGRATION_V2)
            .map_err(|e| CoreError::format(e.to_string()))?;
        Ok(())
    })?;
    apply_migration_step(conn, 3, |c| {
        c.execute_batch(MIGRATION_V3)
            .map_err(|e| CoreError::format(e.to_string()))?;
        Ok(())
    })?;
    apply_migration_step(conn, 4, |c| {
        c.execute_batch(MIGRATION_V4)
            .map_err(|e| CoreError::format(e.to_string()))?;
        Ok(())
    })?;
    apply_migration_step(conn, 5, |c| {
        c.execute_batch(MIGRATION_V5)
            .map_err(|e| CoreError::format(e.to_string()))?;
        Ok(())
    })?;
    apply_migration_step(conn, 6, |c| {
        ensure_column(c, "items", "group_id", "TEXT")?;
        ensure_column(c, "login_credentials", "display_name", "TEXT NOT NULL DEFAULT ''")?;
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS credential_groups (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  scope TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_credential_groups_scope ON credential_groups(scope);",
        )
        .map_err(|e| CoreError::format(e.to_string()))?;
        Ok(())
    })?;
    apply_migration_step(conn, 7, |c| {
        ensure_column(c, "totp_credentials", "totp_algorithm", "TEXT NOT NULL DEFAULT 'SHA1'")?;
        ensure_column(c, "totp_credentials", "totp_digits", "INTEGER NOT NULL DEFAULT 6")?;
        ensure_column(c, "totp_credentials", "totp_period", "INTEGER NOT NULL DEFAULT 30")?;
        Ok(())
    })?;
    apply_migration_step(conn, SCHEMA_USER_VERSION, |c| {
        repair_server_login_profiles_columns(c)?;
        Ok(())
    })?;
    Ok(())
}
