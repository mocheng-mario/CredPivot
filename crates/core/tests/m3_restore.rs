use credpivot_core::{
    bootstrap_vault_dir, clone_vault_to_empty_dir, create_restore_point, list_restore_points,
    open_database, mark_restore_dirty, security_rebuild_in_dir, VaultDatabase,
};
use tempfile::tempdir;

#[test]
fn restore_point_roundtrip_to_empty_dir() {
    let dir = tempdir().expect("tmpdir");
    let material = bootstrap_vault_dir(dir.path(), "m3-pass").expect("bootstrap");
    let vmk = material.vmk;
    let db = VaultDatabase::open(dir.path(), &*vmk).expect("open");
    db.insert_login("https://x.com", "u", "p").expect("insert");
    let conn = open_database(dir.path(), &*vmk).expect("conn");
    mark_restore_dirty(&conn).expect("dirty");
    let point = create_restore_point(dir.path(), &*vmk, &conn).expect("point");
    assert!(point.join("vault.db").is_file());

    let target = tempdir().expect("target");
    credpivot_core::recover_restore_point_to_dir(&point, target.path(), &vmk).expect("recover");
    let db2 = VaultDatabase::open(target.path(), &*vmk).expect("open2");
    assert_eq!(db2.login_count().expect("count"), 1);

    let listed = list_restore_points(dir.path()).expect("list");
    assert_eq!(listed.len(), 1);
}

#[test]
fn clone_vault_to_empty_dir_keeps_data() {
    let dir = tempdir().expect("srcdir");
    let material = bootstrap_vault_dir(dir.path(), "m3-pass").expect("bootstrap");
    let vmk = material.vmk;
    let db = VaultDatabase::open(dir.path(), &*vmk).expect("open");
    db.insert_login("https://y.com", "a", "b").expect("insert");

    let target = tempdir().expect("target");
    clone_vault_to_empty_dir(dir.path(), target.path(), &vmk).expect("clone");
    let db2 = VaultDatabase::open(target.path(), &*vmk).expect("open2");
    assert_eq!(db2.login_count().expect("count"), 1);
}

#[test]
fn security_rebuild_rotates_vmk_but_keeps_data() {
    let dir = tempdir().expect("dir");
    let material = bootstrap_vault_dir(dir.path(), "m3-pass").expect("bootstrap");
    let recovery = material.recovery_display.clone();
    let vmk = material.vmk;
    let db = VaultDatabase::open(dir.path(), &*vmk).expect("open");
    db.insert_login("https://z.com", "u", "pw").expect("insert");
    security_rebuild_in_dir(dir.path(), "m3-pass", &recovery).expect("rebuild");
    assert!(VaultDatabase::open(dir.path(), &*vmk).is_err());
    let cfg = credpivot_core::read_vault_json(dir.path()).expect("cfg");
    let new_vmk = cfg.unlock_master("m3-pass").expect("unlock after rebuild");
    let db3 = VaultDatabase::open(dir.path(), &*new_vmk).expect("open new");
    assert_eq!(db3.login_count().expect("count"), 1);
}
