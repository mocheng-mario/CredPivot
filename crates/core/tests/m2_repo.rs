use credpivot_core::{bootstrap_vault_dir, open_database, VaultDatabase};
use tempfile::tempdir;

#[test]
fn login_persists_in_sqlcipher() {
    let dir = tempdir().expect("tmpdir");
    let material = bootstrap_vault_dir(dir.path(), "m2-pass").expect("bootstrap");
    let vmk = material.vmk;
    let db = VaultDatabase::open(dir.path(), &*vmk).expect("open");
    let rec = db
        .insert_login("https://example.com", "alice", "secret-1")
        .expect("insert");
    assert_eq!(db.login_count().expect("count"), 1);
    let list = db.list_by_origin("https://example.com").expect("list");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, rec.id);
    let got = db.get_login(&rec.id).expect("get");
    assert_eq!(got.password, "secret-1");

    let db2 = open_database(dir.path(), &*vmk).expect("reopen");
    let n: i64 = db2
        .query_row("SELECT COUNT(*) FROM login_credentials", [], |r| r.get(0))
        .expect("count");
    assert_eq!(n, 1);
}
