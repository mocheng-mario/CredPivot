use credpivot_core::{
    bootstrap_vault_dir, change_master_password, read_vault_json, recover_pending_next,
};
use tempfile::tempdir;

/// M1：模拟改密写入中断后，通过 vault.json.next 恢复。
#[test]
fn password_change_crash_recovery() {
    let dir = tempdir().expect("tmpdir");
    bootstrap_vault_dir(dir.path(), "old-pass").expect("bootstrap");
    let cfg = read_vault_json(dir.path()).expect("read");
    let next_cfg = change_master_password(&cfg, "old-pass", "new-pass").expect("change");
    let body = credpivot_core::serialize_config(&next_cfg).expect("ser");
    std::fs::write(dir.path().join("vault.json.next"), body).expect("crash write");
    recover_pending_next(dir.path()).expect("recover");
    let loaded = read_vault_json(dir.path()).expect("read after recover");
    assert_eq!(loaded.control_revision, 2);
    let vmk = loaded.unlock_master("new-pass").expect("unlock");
    loaded.verify_mac(&*vmk).expect("mac");
}
