use credpivot_core::{partitions, sync, CoreError};
use rusqlite::Connection;
use tempfile::tempdir;

fn memory_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    credpivot_core::initialize_schema(&conn).unwrap();
    conn
}

fn login_with_mfa(conn: &Connection, name: &str, mfa: &str, group: Option<&str>) -> credpivot_core::LoginListRow {
    credpivot_core::insert_login_extended_in_partition(conn, partitions::PERSONAL,
        "https://example.test", name, "release-test-password", name, "", Some(mfa), group,
        None, Some(&[mfa.to_string()]), None).unwrap()
}

fn login_only(conn: &Connection, name: &str, group: Option<&str>) -> credpivot_core::LoginListRow {
    credpivot_core::insert_login_extended_in_partition(conn, partitions::PERSONAL,
        "https://example.test", name, "release-test-password", name, "", None, group,
        None, None, None).unwrap()
}

fn mfa(conn: &Connection) -> String {
    credpivot_core::insert_totp_with_rules_in_partition(conn, partitions::PERSONAL,
        "Example", "test-account", "JBSWY3DPEHPK3PXP", None, &[]).unwrap()
}

#[test]
fn migration_moves_only_selected_items_and_reuses_group() {
    // 只迁移勾选的账户。关联的 MFA 和连接留在原分区，连接因此停用。
    let conn = memory_db();
    let source = credpivot_core::create_credential_group_in_partition(&conn, partitions::PERSONAL, "login", "Accounts").unwrap();
    let target = credpivot_core::create_credential_group_in_partition(&conn, partitions::WORK, "login", "Accounts").unwrap();
    let otp = mfa(&conn);
    let first = login_with_mfa(&conn, "first", &otp, Some(&source.id));
    let second = login_only(&conn, "second", Some(&source.id));
    credpivot_core::trash_item(&conn, &second.item_id).unwrap();
    credpivot_core::insert_server_profile_in_partition(&conn, partitions::PERSONAL,
        "Server", "example.test", 22, "", Some(&first.id), Some(&otp), None, None, None).unwrap();
    let active: String = conn.query_row("SELECT active_password_revision FROM login_credentials WHERE id=?1", [&first.id], |r| r.get(0)).unwrap();
    let selected = vec![first.item_id.clone()];
    let preview = partitions::preview(&conn, &selected, partitions::WORK).unwrap();
    assert_eq!(preview["count"], 1);
    partitions::migrate(&conn, &selected, partitions::WORK, preview["fingerprint"].as_str().unwrap()).unwrap();
    assert_eq!(conn.query_row("SELECT count(*) FROM items WHERE partition_id=?1", [partitions::WORK], |r| r.get::<_, i64>(0)).unwrap(), 1);
    assert_eq!(conn.query_row("SELECT group_id FROM items WHERE id=?1", [&first.item_id], |r| r.get::<_, String>(0)).unwrap(), target.id);
    assert_eq!(conn.query_row("SELECT trashed FROM items WHERE id=?1", [&second.item_id], |r| r.get::<_, i64>(0)).unwrap(), 1);
    assert_eq!(conn.query_row("SELECT active_password_revision FROM login_credentials WHERE id=?1", [&first.id], |r| r.get::<_, String>(0)).unwrap(), active);
    partitions::validate(&conn).unwrap();
}

#[test]
fn cross_partition_writes_and_stale_preview_are_rejected() {
    let conn = memory_db();
    let otp = mfa(&conn);
    let login = login_with_mfa(&conn, "first", &otp, None);
    // 从创建入口拒绝跨分区关联，并确认事务没有留下半条记录。
    assert!(credpivot_core::insert_login_extended_in_partition(&conn, partitions::WORK,
        "https://example.test", "invalid", "password", "invalid", "", Some(&otp),
        None, None, None, None).is_err());
    assert_eq!(conn.query_row("SELECT count(*) FROM items", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
    let group = credpivot_core::create_credential_group_in_partition(&conn, partitions::WORK, "login", "Work").unwrap();
    assert!(credpivot_core::set_item_group(&conn, &login.item_id, Some(&group.id)).is_err());
    let selected = vec![login.item_id.clone()];
    let preview = partitions::preview(&conn, &selected, partitions::WORK).unwrap();
    partitions::create(&conn, "New partition after preview").unwrap();
    assert!(matches!(partitions::migrate(&conn, &selected, partitions::WORK,
        preview["fingerprint"].as_str().unwrap()), Err(CoreError::Conflict)));
    assert_eq!(partitions::item_partition(&conn, &login.item_id).unwrap(), partitions::PERSONAL);
}

#[test]
fn sync_and_ovb_restore_preserve_partitions() {
    // 只用临时库验证同步快照重建、主密码恢复、恢复密钥恢复，不访问真实保险库或远端。
    let source = tempdir().unwrap();
    let material = credpivot_core::bootstrap_vault_dir(source.path(), "release-test-master").unwrap();
    let conn = credpivot_core::open_database(source.path(), &material.vmk).unwrap();
    let otp = mfa(&conn);
    let login = login_with_mfa(&conn, "first", &otp, None);
    let selected = vec![login.item_id.clone()];
    let preview = partitions::preview(&conn, &selected, partitions::WORK).unwrap();
    partitions::migrate(&conn, &selected, partitions::WORK, preview["fingerprint"].as_str().unwrap()).unwrap();
    let doc = sync::capture(&conn).unwrap();
    sync::validate_document(&doc).unwrap();
    let replica = memory_db();
    sync::apply_document(&replica, &doc).unwrap();
    assert_eq!(partitions::item_partition(&replica, &login.item_id).unwrap(), partitions::WORK);
    assert_eq!(credpivot_core::get_login_secret(&replica, &login.id).unwrap().password, "release-test-password");
    let bytes = credpivot_core::export_ovb_from_dir(source.path(), "release-test-master").unwrap();
    let mut recovery = [0; 32];
    recovery.copy_from_slice(&material.recovery_secret);
    for unlock in [credpivot_core::RecoveryUnlock::MasterPassword("release-test-master".into()),
        credpivot_core::RecoveryUnlock::RecoverySecret(recovery)] {
        let destination = tempdir().unwrap();
        credpivot_core::recover_ovb_to_dir(&bytes, destination.path(), unlock).unwrap();
        let config = credpivot_core::read_vault_json(destination.path()).unwrap();
        let vmk = config.unlock_master("release-test-master").unwrap();
        let restored = credpivot_core::open_database(destination.path(), &vmk).unwrap();
        partitions::validate(&restored).unwrap();
        assert_eq!(partitions::item_partition(&restored, &login.item_id).unwrap(), partitions::WORK);
        assert_eq!(credpivot_core::get_login_secret(&restored, &login.id).unwrap().password, "release-test-password");
    }
}
