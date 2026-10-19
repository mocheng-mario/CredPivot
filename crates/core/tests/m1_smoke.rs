use credpivot_core::{
    bootstrap_vault_dir, build_ovb_file, change_master_password_in_dir, create_vault_config,
    decrypt_snapshot, export_ovb_from_dir, generate_recovery_key, parse_recovery_display, parse_ovb_with_aad,
    read_vault_json, recover_ovb_to_dir, recover_pending_next, write_vault_json_atomic, RecoveryUnlock,
};
use tempfile::tempdir;

#[test]
fn create_unlock_master_and_recovery() {
    let material = create_vault_config("test-password-m1").expect("create");
    let cfg = &material.config;
    let vmk1 = cfg.unlock_master("test-password-m1").expect("master");
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&material.recovery_secret);
    let vmk2 = cfg.unlock_recovery(&secret).expect("recovery");
    assert_eq!(vmk1.as_ref(), vmk2.as_ref());
}

#[test]
fn change_password_keeps_vmk() {
    let dir = tempdir().expect("tmpdir");
    bootstrap_vault_dir(dir.path(), "old-pass").expect("bootstrap");
    change_master_password_in_dir(dir.path(), "old-pass", "new-pass").expect("change");
    let loaded = read_vault_json(dir.path()).expect("read");
    assert_eq!(loaded.control_revision, 2);
    let vmk = loaded.unlock_master("new-pass").expect("new unlock");
    loaded.verify_mac(&*vmk).expect("mac");
}

#[test]
fn atomic_write_and_ovb_roundtrip() {
    let dir = tempdir().expect("tmpdir");
    let material = create_vault_config("vault-pass").expect("create");
    write_vault_json_atomic(dir.path(), &material.config).expect("write");
    let loaded = read_vault_json(dir.path()).expect("read");
    let vmk = loaded.unlock_master("vault-pass").expect("unlock");
    let vault_uuid = uuid::Uuid::parse_str(&loaded.vault_id).unwrap();
    let snapshot = br#"{"format":"credpivot-snapshot-m1","version":1,"vault_json":"{}"}"#;
    let file = build_ovb_file(&*vmk, &vault_uuid, loaded.key_slots.clone(), snapshot).expect("ovb");
    let (header, aad, ct) = parse_ovb_with_aad(&file).expect("parse");
    let plain = decrypt_snapshot(&*vmk, &header, &aad, &ct).expect("decrypt");
    assert_eq!(plain, snapshot);
}

#[test]
fn recovery_display_checksum() {
    let (secret, display) = generate_recovery_key();
    let parsed = parse_recovery_display(&display).expect("parse");
    assert_eq!(secret, parsed);
}

#[test]
fn bootstrap_export_recover_master_and_recovery() {
    let source = tempdir().expect("source");
    let material = bootstrap_vault_dir(source.path(), "export-pass").expect("bootstrap");
    let ovb = export_ovb_from_dir(source.path(), "export-pass").expect("export");

    let master_target = tempdir().expect("master_tgt");
    recover_ovb_to_dir(
        &ovb,
        master_target.path(),
        RecoveryUnlock::MasterPassword("export-pass".into()),
    )
    .expect("recover master");
    let cfg_m = read_vault_json(master_target.path()).expect("read");
    let vmk_m = cfg_m.unlock_master("export-pass").expect("unlock");
    cfg_m.verify_mac(&*vmk_m).expect("mac");

    let recovery_target = tempdir().expect("recovery_tgt");
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&material.recovery_secret);
    recover_ovb_to_dir(
        &ovb,
        recovery_target.path(),
        RecoveryUnlock::RecoverySecret(secret),
    )
    .expect("recover recovery");
    let cfg_r = read_vault_json(recovery_target.path()).expect("read");
    let vmk_r = cfg_r.unlock_recovery(&secret).expect("unlock recovery");
    assert_eq!(vmk_m.as_ref(), vmk_r.as_ref());
}

#[test]
fn pending_next_recovery() {
    let dir = tempdir().expect("tmpdir");
    let material = create_vault_config("pw").expect("create");
    let next = dir.path().join("vault.json.next");
    let body = credpivot_core::serialize_config(&material.config).expect("ser");
    std::fs::write(&next, body).expect("write next");
    recover_pending_next(dir.path()).expect("recover");
    read_vault_json(dir.path()).expect("vault exists");
}
