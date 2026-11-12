use crate::error::{CoreError, Result};
use rusqlite::Connection;

/// 当前 SQLCipher 数据库结构版本；已有库只校验，不自动升级。
pub const SCHEMA_USER_VERSION: i32 = 14;

const CURRENT_SCHEMA: &str = "
CREATE TABLE vault_meta (
  key TEXT PRIMARY KEY NOT NULL,
  value BLOB NOT NULL
);
INSERT INTO vault_meta(key, value) VALUES ('m1_marker', X'01');

CREATE TABLE items (
  id TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  trashed INTEGER NOT NULL DEFAULT 0 CHECK (trashed IN (0, 1)),
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  group_id TEXT,
  details_json TEXT NOT NULL DEFAULT '{}',
  trashed_at_ms INTEGER,
  partition_id TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000001'
);

CREATE TABLE login_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  username TEXT NOT NULL,
  secret TEXT NOT NULL,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  password_active_since_ms INTEGER NOT NULL DEFAULT 0,
  connection_host TEXT NOT NULL DEFAULT '',
  linked_totp_id TEXT,
  display_name TEXT NOT NULL DEFAULT '',
  active_password_revision TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (item_id) REFERENCES items(id)
);
CREATE INDEX idx_login_credentials_origin ON login_credentials(origin);

CREATE TABLE password_history (
  id TEXT PRIMARY KEY NOT NULL,
  credential_id TEXT NOT NULL,
  secret TEXT NOT NULL,
  activated_at_ms INTEGER NOT NULL,
  retired_at_ms INTEGER,
  FOREIGN KEY (credential_id) REFERENCES login_credentials(id)
);

CREATE TABLE totp_credentials (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  issuer TEXT NOT NULL,
  account TEXT NOT NULL,
  secret_base32 TEXT NOT NULL,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  totp_algorithm TEXT NOT NULL DEFAULT 'SHA1',
  totp_digits INTEGER NOT NULL DEFAULT 6,
  totp_period INTEGER NOT NULL DEFAULT 30,
  FOREIGN KEY (item_id) REFERENCES items(id)
);

CREATE TABLE ssh_keys (
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

CREATE TABLE recovery_code_items (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  service_name TEXT NOT NULL,
  codes_json TEXT NOT NULL,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  mfa_item_id TEXT,
  FOREIGN KEY (item_id) REFERENCES items(id)
);
CREATE UNIQUE INDEX idx_recovery_one_mfa ON recovery_code_items(mfa_item_id) WHERE mfa_item_id IS NOT NULL;

CREATE TABLE vault_settings (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL
);

CREATE TABLE import_mappings (
  source_namespace TEXT NOT NULL,
  source_item_id TEXT NOT NULL,
  local_item_id TEXT NOT NULL,
  source_digest TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (source_namespace, source_item_id)
);

CREATE TABLE server_login_profiles (
  id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL,
  label TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 22,
  manual_username TEXT NOT NULL DEFAULT '',
  linked_login_id TEXT,
  linked_totp_id TEXT,
  linked_ssh_key_id TEXT,
  manual_secret TEXT NOT NULL DEFAULT '',
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  FOREIGN KEY (item_id) REFERENCES items(id)
);
CREATE INDEX idx_server_login_profiles_host ON server_login_profiles(host);

CREATE TABLE server_stale_auth (
  profile_id TEXT PRIMARY KEY NOT NULL,
  linked_login_id TEXT,
  linked_totp_id TEXT,
  linked_ssh_key_id TEXT,
  auth_mode TEXT NOT NULL,
  unavailable INTEGER NOT NULL,
  unavailable_reason TEXT NOT NULL
);

CREATE TABLE credential_groups (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  scope TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL DEFAULT 0,
  partition_id TEXT NOT NULL DEFAULT '00000000-0000-4000-8000-000000000001'
);
CREATE INDEX idx_credential_groups_scope ON credential_groups(scope);

CREATE TABLE local_usage (
  item_id TEXT PRIMARY KEY,
  last_used_at_ms INTEGER NOT NULL,
  use_count INTEGER NOT NULL
);

CREATE TABLE password_candidates (
  id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL REFERENCES login_credentials(id),
  base_active_revision TEXT NOT NULL,
  secret TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);

CREATE TABLE recovery_code_entries (
  id TEXT PRIMARY KEY,
  recovery_id TEXT NOT NULL REFERENCES recovery_code_items(id),
  code TEXT NOT NULL,
  used_at_ms INTEGER,
  position INTEGER NOT NULL
);

CREATE TABLE passkey_credentials (
  credential_id TEXT PRIMARY KEY NOT NULL,
  item_id TEXT NOT NULL UNIQUE REFERENCES items(id),
  rp_id TEXT NOT NULL,
  user_handle TEXT NOT NULL,
  username TEXT NOT NULL,
  display_name TEXT NOT NULL,
  private_key BLOB NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX idx_passkey_rp_id ON passkey_credentials(rp_id);

CREATE TABLE credential_links (
  account_item_id TEXT NOT NULL,
  target_item_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('mfa','ssh_key','passkey')),
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (account_item_id, target_item_id, kind)
);
CREATE UNIQUE INDEX idx_credential_links_one_owner
  ON credential_links(target_item_id)
  WHERE kind IN ('mfa','passkey');
CREATE INDEX idx_credential_links_target ON credential_links(target_item_id, kind);

CREATE TABLE trashed_credential_links (
  owner_item_id TEXT NOT NULL,
  account_item_id TEXT NOT NULL,
  target_item_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('mfa','ssh_key','passkey')),
  PRIMARY KEY (owner_item_id, account_item_id, target_item_id, kind)
);

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
END;

CREATE TABLE partitions (
  id TEXT PRIMARY KEY NOT NULL,
  name TEXT NOT NULL,
  sort_order INTEGER NOT NULL,
  current_revision TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
INSERT INTO partitions VALUES ('00000000-0000-4000-8000-000000000001','个人',0,'00000000-0000-4000-8000-000000000001',0,0);
INSERT INTO partitions VALUES ('00000000-0000-4000-8000-000000000002','工作',1,'00000000-0000-4000-8000-000000000002',0,0);
CREATE INDEX idx_items_partition ON items(partition_id,trashed);
CREATE INDEX idx_groups_partition ON credential_groups(partition_id,scope);
CREATE TRIGGER sync_partition_deleted AFTER DELETE ON partitions
WHEN NOT EXISTS (SELECT 1 FROM sync_state WHERE key='applying')
BEGIN
  INSERT OR REPLACE INTO sync_tombstones VALUES ('partition:' || OLD.id, CAST((julianday('now')-2440587.5)*86400000 AS INTEGER));
END;
";

pub fn validate_schema_version(conn: &Connection) -> Result<()> {
    let version: i32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCHEMA_USER_VERSION {
        return Err(CoreError::format(format!(
            "数据库结构版本 {version} 不受支持，需要版本 {SCHEMA_USER_VERSION}；不会自动升级"
        )));
    }
    Ok(())
}

/// 现有版本 14 的库补上关联恢复和 MFA 恢复码所需的表，不改变数据库版本。
pub fn ensure_runtime_extras(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS trashed_credential_links (
            owner_item_id TEXT NOT NULL,
            account_item_id TEXT NOT NULL,
            target_item_id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('mfa','ssh_key','passkey')),
            PRIMARY KEY (owner_item_id, account_item_id, target_item_id, kind)
        );",
    )?;
    let has_mfa: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('recovery_code_items') WHERE name='mfa_item_id'",
        [],
        |row| row.get(0),
    )?;
    if has_mfa == 0 {
        conn.execute_batch("ALTER TABLE recovery_code_items ADD COLUMN mfa_item_id TEXT")?;
    }
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_one_mfa ON recovery_code_items(mfa_item_id) WHERE mfa_item_id IS NOT NULL",
    )?;
    Ok(())
}

/// 只用于空数据库；新建保险库、逻辑恢复和内存校验共用完整结构。
pub fn initialize_schema(conn: &Connection) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    let version: i32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let occupied: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name NOT LIKE 'sqlite_%')",
        [],
        |row| row.get(0),
    )?;
    if version != 0 || occupied {
        return Err(CoreError::format("只能初始化空数据库"));
    }
    tx.execute_batch(CURRENT_SCHEMA)?;
    // 子记录变化仍需推进所属记录的同步时间。
    for (table, parent) in [
        ("password_history", "SELECT item_id FROM login_credentials WHERE id={row}.credential_id"),
        ("password_candidates", "SELECT item_id FROM login_credentials WHERE id={row}.credential_id"),
        ("recovery_code_entries", "SELECT item_id FROM recovery_code_items WHERE id={row}.recovery_id"),
    ] {
        for (event, row) in [("INSERT", "NEW"), ("UPDATE", "NEW"), ("DELETE", "OLD")] {
            let parent = parent.replace("{row}", row);
            tx.execute_batch(&format!("CREATE TRIGGER sync_{table}_{event} AFTER {event} ON {table}
WHEN NOT EXISTS (SELECT 1 FROM sync_state WHERE key='applying')
BEGIN UPDATE items SET updated_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) WHERE id IN ({parent}); END;"))?;
        }
    }
    crate::partitions::install_constraints(&tx)?;
    crate::credential_groups::install_constraints(&tx)?;
    crate::mark_restore_dirty(&tx)?;
    tx.pragma_update(None, "user_version", SCHEMA_USER_VERSION)?;
    tx.commit()?;
    Ok(())
}
