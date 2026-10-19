mod atomic_config;
mod canonical_json;
mod cpvc1;
mod crypto;
mod error;
mod key_slot;
mod limits;
mod local_db;
mod migrate;
mod bitwarden_import;
mod repo;
mod repo_m2;
mod restore_point;
mod totp;
mod ovb1;
mod password_change;
mod recovery_key;
mod snapshot;
mod vault_db;
mod vault_init;
mod vault_pipeline;

pub use atomic_config::{read_vault_json, recover_pending_next, write_vault_json_atomic};
pub use cpvc1::{parse_config, serialize_config, CpvcConfig, FORMAT_MAJOR, MAGIC};
pub use crypto::{derive_sqlcipher_key, VMK_LEN};
pub use error::{CoreError, Result};
pub use key_slot::KeySlot;
pub use ovb1::{build_ovb_file, decrypt_snapshot, parse_ovb_file, parse_ovb_with_aad, OvbHeader};
pub use password_change::change_master_password;
pub use recovery_key::{format_display, generate as generate_recovery_key, parse_display as parse_recovery_display};
pub use local_db::{open_database, sqlcipher_sidecar_paths, verify_database, SQLCIPHER_M1_LABEL};
pub use migrate::SCHEMA_USER_VERSION;
pub use bitwarden_import::{import_bitwarden_json, ImportReport};
pub use repo::{
    count_login_credentials, get_login_secret, insert_login_credential, list_login_by_origin,
    LoginCredentialRecord, LoginCredentialSummary,
};
pub use repo_m2::{
    ensure_default_ssh_key, list_logins, load_default_ssh_key, security_summary, trash_item,
    totp_secret_for_id, update_login_credential, insert_totp, insert_ssh_key, LoginListRow,
    SecuritySummary, SshKeyRecord,
};
pub use restore_point::{
    create_restore_point, create_restore_point_if_due, mark_restore_dirty,
    should_create_restore_point, MAX_RESTORE_POINTS, RESTORE_POINTS_DIR,
};
pub use totp::totp_code_now;
pub use snapshot::{SNAPSHOT_FORMAT, SNAPSHOT_VERSION};
pub use vault_db::VaultDatabase;
pub use vault_init::{create_vault_config, NewVaultMaterial};
pub use vault_pipeline::{
    bootstrap_vault_dir, change_master_password_in_dir, ensure_empty_target, export_ovb_from_dir,
    recover_ovb_to_dir, RecoveryUnlock,
};
