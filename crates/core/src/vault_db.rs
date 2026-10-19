use crate::error::Result;
use crate::local_db::open_database;
use crate::repo::{
    count_login_credentials, get_login_secret, insert_login_credential, list_login_by_origin,
    LoginCredentialRecord, LoginCredentialSummary,
};
use rusqlite::Connection;
use std::path::Path;

/// 已解锁工作库连接（M2）。
pub struct VaultDatabase {
    conn: Connection,
}

impl std::fmt::Debug for VaultDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultDatabase")
    }
}

impl VaultDatabase {
    pub fn open(vault_dir: &Path, vmk: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            conn: open_database(vault_dir, vmk)?,
        })
    }

    pub fn insert_login(&self, origin: &str, username: &str, password: &str) -> Result<LoginCredentialRecord> {
        insert_login_credential(&self.conn, origin, username, password)
    }

    pub fn list_by_origin(&self, origin: &str) -> Result<Vec<LoginCredentialSummary>> {
        list_login_by_origin(&self.conn, origin)
    }

    pub fn get_login(&self, credential_id: &str) -> Result<LoginCredentialRecord> {
        get_login_secret(&self.conn, credential_id)
    }

    pub fn login_count(&self) -> Result<u64> {
        count_login_credentials(&self.conn)
    }
}
