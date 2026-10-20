use credpivot_core::migrate_to_latest;
use rusqlite::Connection;

#[test]
fn v8_repairs_server_profile_manual_username_column() {
    let conn = Connection::open_in_memory().expect("open");
    conn.execute_batch(
        "
        PRAGMA user_version = 7;
        CREATE TABLE items (
          id TEXT PRIMARY KEY,
          kind TEXT NOT NULL,
          title TEXT NOT NULL,
          trashed INTEGER NOT NULL DEFAULT 0,
          group_id TEXT,
          current_revision TEXT NOT NULL,
          created_at_ms INTEGER NOT NULL,
          updated_at_ms INTEGER NOT NULL
        );
        CREATE TABLE server_login_profiles (
          id TEXT PRIMARY KEY NOT NULL,
          item_id TEXT NOT NULL,
          label TEXT NOT NULL,
          host TEXT NOT NULL,
          port INTEGER NOT NULL DEFAULT 22,
          linked_login_id TEXT,
          linked_totp_id TEXT,
          current_revision TEXT NOT NULL,
          created_at_ms INTEGER NOT NULL,
          updated_at_ms INTEGER NOT NULL
        );
        ",
    )
    .expect("schema");
    migrate_to_latest(&conn).expect("migrate");
    let version: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("version");
    assert_eq!(version, 8);
    conn.execute(
        "INSERT INTO items VALUES ('i1','server','s',0,NULL,'r',1,1)",
        [],
    )
    .expect("items");
    conn.execute(
        "INSERT INTO server_login_profiles (id, item_id, label, host, port, linked_login_id, linked_totp_id, current_revision, created_at_ms, updated_at_ms)
         VALUES ('s1','i1','lab','h',22,NULL,NULL,'r',1,1)",
        [],
    )
    .expect("server");
    let username: String = conn
        .query_row(
            "SELECT manual_username FROM server_login_profiles WHERE id = 's1'",
            [],
            |row| row.get(0),
        )
        .expect("select");
    assert_eq!(username, "");
}
