use credpivot_core::{
    bootstrap_vault_dir, import_bitwarden_json, open_database, update_login_credential, CoreError,
    VaultDatabase,
};
use tempfile::tempdir;

#[test]
fn revision_conflict_on_stale_update() {
    let dir = tempdir().expect("tmpdir");
    let material = bootstrap_vault_dir(dir.path(), "m2-pass").expect("bootstrap");
    let db = VaultDatabase::open(dir.path(), &*material.vmk).expect("open");
    let rec = db
        .insert_login("https://a.com", "u", "p1")
        .expect("insert");
    let updated = db
        .update_login(&rec.id, &rec.current_revision, "https://a.com", "u", Some("p2"))
        .expect("update");
    let conn = open_database(dir.path(), &*material.vmk).expect("conn");
    let err = update_login_credential(
        &conn,
        &rec.id,
        &rec.current_revision,
        "https://a.com",
        "u",
        Some("p3"),
    )
    .expect_err("conflict");
    assert!(matches!(err, CoreError::Conflict));
    let got = db.get_login(&rec.id).expect("get");
    assert_eq!(got.password, "p2");
    assert_ne!(updated.current_revision, rec.current_revision);
}

#[test]
fn bitwarden_skips_duplicate() {
    let dir = tempdir().expect("tmpdir");
    let material = bootstrap_vault_dir(dir.path(), "m2-pass").expect("bootstrap");
    let conn = open_database(dir.path(), &*material.vmk).expect("open");
    let json = r#"[
      {"id":"bw-1","name":"Site","login":{"username":"a","password":"b","uris":[{"uri":"https://x.com"}]}}
    ]"#;
    let r1 = import_bitwarden_json(&conn, json).expect("import1");
    assert_eq!(r1.imported, 1);
    let r2 = import_bitwarden_json(&conn, json).expect("import2");
    assert_eq!(r2.skipped_duplicate, 1);
    assert_eq!(r2.imported, 0);
}
