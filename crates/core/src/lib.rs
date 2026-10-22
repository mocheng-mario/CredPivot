mod atomic_config;
mod app_settings;
mod backup_status;
mod canonical_json;
mod cpvc1;
mod crypto;
mod error;
mod key_slot;
mod limits;
mod local_db;
mod migrate;
mod bitwarden_import;
mod credential_groups;
mod repo;
mod repo_m2;
mod server_profiles;
mod restore_point;
mod totp;
mod ovb1;
mod password_change;
pub mod passkey;
mod recovery_key;
mod snapshot;
mod vault_db;
mod vault_init;
mod vault_pipeline;

pub use atomic_config::{
    read_vault_json, recover_pending_next, write_file_atomic, write_vault_json_atomic,
};
pub use app_settings::{app_settings_path, backup_app_settings, effective_app_settings, read_app_settings, write_app_settings, AppSettings};
pub use backup_status::{
    mark_local_restore_verified, mark_ovb_decrypt_verified, mark_ovb_export_verified,
    mark_recovery_key_verified, read_backup_status, BackupVerificationStatus,
};
pub use cpvc1::{parse_config, serialize_config, CpvcConfig, FORMAT_MAJOR, MAGIC};
pub use crypto::{derive_sqlcipher_key, VMK_LEN};
pub use error::{CoreError, Result};
pub use key_slot::{KeySlot, SlotType};
pub use ovb1::{build_ovb_file, decrypt_snapshot, parse_ovb_file, parse_ovb_with_aad, read_ovb_file, OvbHeader};
pub use password_change::change_master_password;
pub use recovery_key::{format_display, generate as generate_recovery_key, parse_display as parse_recovery_display};
pub use local_db::{open_database, sqlcipher_sidecar_paths, verify_database, DB_FILENAME, SQLCIPHER_M1_LABEL};
pub use migrate::{migrate_to_latest, SCHEMA_USER_VERSION};
pub use bitwarden_import::{import_bitwarden_json, ImportReport};
pub use repo::{
    count_login_credentials, get_login_secret, insert_login_credential, list_login_by_origin,
    LoginCredentialRecord, LoginCredentialSummary,
};
pub use repo_m2::{
    ensure_default_ssh_key, insert_recovery_codes, list_logins, list_recovery_codes,
    load_default_ssh_key, security_summary, trash_item, totp_secret_for_id,
    update_login_credential, update_recovery_codes, generate_ssh_key, insert_ssh_key, insert_totp,
    insert_totp_row,     format_ssh_ed25519_openssh, list_ssh_keys, list_totp_credentials, LoginListRow, RecoveryCodeRow,
    SecuritySummary, SshKeyListRow, SshKeyRecord, TotpListRow, TotpRevealRow,
};
pub use restore_point::{
    create_restore_point, create_restore_point_for_risky_op, create_restore_point_if_due,
    list_restore_points, mark_restore_dirty, should_create_restore_point, RestorePointInfo,
    MAX_RESTORE_POINTS, RESTORE_POINTS_DIR,
};
pub use credential_groups::{
    create_credential_group, delete_credential_group, list_credential_groups,
    rename_credential_group, set_item_group, CredentialGroupRow,
};
pub use server_profiles::{
    insert_server_profile, list_server_profiles, update_server_profile, ServerProfileRow,
};
pub use totp::{build_otpauth_uri, normalize_totp_secret_for_storage, totp_code_now};
pub use snapshot::{SNAPSHOT_FORMAT, SNAPSHOT_VERSION};
pub use vault_db::VaultDatabase;
pub use vault_init::{create_vault_config, NewVaultMaterial};
pub use vault_pipeline::{
    bootstrap_vault_dir, change_master_password_in_dir, clone_vault_to_empty_dir,
    ensure_empty_target, export_ovb_from_dir, recover_ovb_to_dir, recover_restore_point_to_dir,
    security_rebuild_in_dir, RecoveryUnlock,
};

mod credential_management;
mod website_rules;
pub use website_rules::{browser_mfa_candidates, mfa_matches_origin, credential_matches_origin, credential_website_rules};
pub use credential_management::{UriRule, MfaBinding};
pub use credential_management::{VaultAction, manage_credentials, export_logical_json, update_login_from_browser, credential_origins, browser_login_candidates, record_credential_use};
mod ssh_transfer;
