mod atomic_config;
mod canonical_json;
mod cpvc1;
mod crypto;
mod error;
mod key_slot;
mod limits;
mod local_db;
mod ovb1;
mod password_change;
mod recovery_key;
mod snapshot;
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
pub use local_db::{sqlcipher_sidecar_paths, verify_database, SQLCIPHER_M1_LABEL};
pub use snapshot::{SNAPSHOT_FORMAT, SNAPSHOT_VERSION};
pub use vault_init::{create_vault_config, NewVaultMaterial};
pub use vault_pipeline::{
    bootstrap_vault_dir, change_master_password_in_dir, ensure_empty_target, export_ovb_from_dir,
    recover_ovb_to_dir, RecoveryUnlock,
};
