use credpivot_core::{
    bootstrap_vault_dir, change_master_password_in_dir, export_ovb_from_dir, read_vault_json,
    recover_ovb_to_dir, verify_database, RecoveryUnlock,
};
use ovb1_structure::parse_layout;
use std::fs;
use tempfile::tempdir;

/// 与 UI/CLI 相同路径：落盘 OVB → 独立结构校验 → 主密码/恢复密钥恢复 → vault.db 完整性。
#[test]
fn export_file_recover_after_password_change() {
    let source = tempdir().expect("source");
    let material = bootstrap_vault_dir(source.path(), "pass-v1").expect("bootstrap");
    let vault_id_before = read_vault_json(source.path()).expect("read").vault_id;

    change_master_password_in_dir(source.path(), "pass-v1", "pass-v2").expect("change");

    let ovb_path = source.path().join("archive.ovb");
    let bytes = export_ovb_from_dir(source.path(), "pass-v2").expect("export");
    fs::write(&ovb_path, &bytes).expect("write ovb");
    parse_layout(&bytes).expect("independent layout ok");

    let recovered = tempdir().expect("recovered");
    recover_ovb_to_dir(
        &bytes,
        recovered.path(),
        RecoveryUnlock::MasterPassword("pass-v2".into()),
    )
    .expect("recover with new password");

    let cfg = read_vault_json(recovered.path()).expect("read recovered");
    assert_eq!(cfg.vault_id, vault_id_before);
    assert_eq!(cfg.control_revision, 2);
    let vmk = cfg.unlock_master("pass-v2").expect("unlock");
    cfg.verify_mac(&*vmk).expect("mac");
    verify_database(recovered.path(), &*vmk).expect("db integrity");

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&material.recovery_secret);
    let recovered2 = tempdir().expect("recovered2");
    recover_ovb_to_dir(
        &bytes,
        recovered2.path(),
        RecoveryUnlock::RecoverySecret(secret),
    )
    .expect("recover with recovery key");
    let cfg2 = read_vault_json(recovered2.path()).expect("read2");
    assert_eq!(cfg2.vault_id, vault_id_before);
}

#[test]
fn tampered_ovb_rejected() {
    let source = tempdir().expect("source");
    bootstrap_vault_dir(source.path(), "pw").expect("bootstrap");
    let mut bytes = export_ovb_from_dir(source.path(), "pw").expect("export");
    if let Some(b) = bytes.last_mut() {
        *b ^= 0xff;
    }
    let target = tempdir().expect("target");
    let err = recover_ovb_to_dir(
        &bytes,
        target.path(),
        RecoveryUnlock::MasterPassword("pw".into()),
    )
    .expect_err("must fail");
    assert!(!target.path().join("vault.json").exists(), "cleanup on fail: {err}");
}
