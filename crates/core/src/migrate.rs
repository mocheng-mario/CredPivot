use crate::error::{CoreError, Result};
use rusqlite::Connection;

/// SQLCipher `user_version`：与迁移脚本同步递增。
pub const SCHEMA_USER_VERSION: i32 = 13;

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
    apply_migration_step(conn, 8, |c| {
        repair_server_login_profiles_columns(c)?;
        Ok(())
    })?;
    apply_migration_step(conn, 9, |c| {
        c.execute_batch("ALTER TABLE items ADD COLUMN details_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE items ADD COLUMN trashed_at_ms INTEGER;
ALTER TABLE login_credentials ADD COLUMN active_password_revision TEXT NOT NULL DEFAULT '';
-- 旧版本的时间来自创建/编辑，未经用户确认，不作为真实密码启用时间。
UPDATE login_credentials SET active_password_revision = current_revision, password_active_since_ms = 0;
UPDATE items SET trashed_at_ms = updated_at_ms WHERE trashed = 1;
CREATE TABLE local_usage (item_id TEXT PRIMARY KEY, last_used_at_ms INTEGER NOT NULL, use_count INTEGER NOT NULL);
CREATE TABLE password_candidates (
 id TEXT PRIMARY KEY, credential_id TEXT NOT NULL REFERENCES login_credentials(id),
 base_active_revision TEXT NOT NULL, secret TEXT NOT NULL, created_at_ms INTEGER NOT NULL
);
CREATE TABLE recovery_code_entries (
 id TEXT PRIMARY KEY, recovery_id TEXT NOT NULL REFERENCES recovery_code_items(id),
 code TEXT NOT NULL, used_at_ms INTEGER, position INTEGER NOT NULL
);
ALTER TABLE import_mappings ADD COLUMN source_digest TEXT NOT NULL DEFAULT '';
UPDATE import_mappings SET source_namespace='bitwarden:personal' WHERE source_namespace='bitwarden';
")?;
        let mut stmt = c.prepare("SELECT id, codes_json FROM recovery_code_items")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (id, json) = row?;
            let codes: Vec<String> = serde_json::from_str(&json)
                .map_err(|_| CoreError::format("恢复码数据格式错误，迁移已取消"))?;
            crate::credential_management::sync_recovery_entries(c, &id, &codes)?;
        }
        Ok(())
    })?;
    apply_migration_step(conn, 10, |c| {
        crate::website_rules::migrate_mfa_bindings(c)?;
        crate::mark_restore_dirty(c)?;
        Ok(())
    })?;
    apply_migration_step(conn, 11, |c| {
        crate::website_rules::migrate_mfa_owned_rules(c)?;
        crate::mark_restore_dirty(c)?;
        Ok(())
    })?;
    apply_migration_step(conn, 12, |c| {
        c.execute_batch("CREATE TABLE passkey_credentials (
 credential_id TEXT PRIMARY KEY NOT NULL,
 item_id TEXT NOT NULL UNIQUE REFERENCES items(id),
 rp_id TEXT NOT NULL,
 user_handle TEXT NOT NULL,
 username TEXT NOT NULL,
 display_name TEXT NOT NULL,
 private_key BLOB NOT NULL,
 created_at_ms INTEGER NOT NULL
);
CREATE INDEX idx_passkey_rp_id ON passkey_credentials(rp_id);")?;
        crate::mark_restore_dirty(c)?;
        Ok(())
    })?;
    apply_migration_step(conn, 13, |c| {
        ensure_column(c, "credential_groups", "updated_at_ms", "INTEGER NOT NULL DEFAULT 0")?;
        c.execute_batch("UPDATE credential_groups SET updated_at_ms=created_at_ms WHERE updated_at_ms=0;
CREATE TABLE sync_state (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
CREATE TABLE sync_tombstones (record_key TEXT PRIMARY KEY NOT NULL, deleted_at_ms INTEGER NOT NULL);
CREATE TRIGGER sync_item_deleted AFTER DELETE ON items
WHEN NOT EXISTS (SELECT 1 FROM sync_state WHERE key='applying')
BEGIN
 INSERT OR REPLACE INTO sync_tombstones VALUES ('item:' || OLD.id, CAST((julianday('now')-2440587.5)*86400000 AS INTEGER));
END;
CREATE TRIGGER sync_group_deleted AFTER DELETE ON credential_groups
WHEN NOT EXISTS (SELECT 1 FROM sync_state WHERE key='applying')
BEGIN
 INSERT OR REPLACE INTO sync_tombstones VALUES ('group:' || OLD.id, CAST((julianday('now')-2440587.5)*86400000 AS INTEGER));
END;
CREATE TRIGGER sync_group_changed AFTER UPDATE OF name,scope,sort_order ON credential_groups
WHEN NOT EXISTS (SELECT 1 FROM sync_state WHERE key='applying')
BEGIN
 UPDATE credential_groups SET updated_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) WHERE id=NEW.id;
END;")?;
        // 历史/候选密码及恢复码的变更也属于其所属记录，不能漏掉修改时间。
        for (table, parent) in [
            ("password_history", "SELECT item_id FROM login_credentials WHERE id={row}.credential_id"),
            ("password_candidates", "SELECT item_id FROM login_credentials WHERE id={row}.credential_id"),
            ("recovery_code_entries", "SELECT item_id FROM recovery_code_items WHERE id={row}.recovery_id"),
        ] {
            for (event, row) in [("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")] {
                let parent = parent.replace("{row}", row);
                c.execute_batch(&format!("CREATE TRIGGER sync_{table}_{event} AFTER {event} ON {table}
WHEN NOT EXISTS (SELECT 1 FROM sync_state WHERE key='applying')
BEGIN UPDATE items SET updated_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) WHERE id IN ({parent}); END;"))?;
            }
        }
        crate::mark_restore_dirty(c)?;
        Ok(())
    })?;
    Ok(())
}
