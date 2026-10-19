use crate::bitwarden_import::{import_bitwarden_json, ImportReport};
use crate::error::Result;
use crate::local_db::open_database;
use crate::repo::{
    count_login_credentials, get_login_secret, insert_login_credential, list_login_by_origin,
    LoginCredentialRecord, LoginCredentialSummary,
};
use crate::backup_status::{read_backup_status, BackupVerificationStatus};
use crate::repo_m2::{
    ensure_default_ssh_key, insert_recovery_codes, list_logins, list_recovery_codes,
    load_default_ssh_key, security_summary, trash_item, totp_secret_for_id,
    update_login_credential, update_recovery_codes, generate_ssh_key, insert_totp_row,
    list_ssh_keys, list_totp_credentials, LoginListRow, RecoveryCodeRow, SecuritySummary,
    SshKeyListRow, SshKeyRecord, TotpListRow,
};
use crate::restore_point::{
    create_restore_point_for_risky_op, create_restore_point_if_due, mark_restore_dirty,
};
use std::path::Path;
use crate::totp::totp_code_now;
use rusqlite::Connection;

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
        let rec = insert_login_credential(&self.conn, origin, username, password)?;
        mark_restore_dirty(&self.conn)?;
        Ok(rec)
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

    pub fn list_logins(&self, query: Option<&str>, limit: u32) -> Result<Vec<LoginListRow>> {
        list_logins(&self.conn, query, limit)
    }

    pub fn update_login(
        &self,
        credential_id: &str,
        expected_revision: &str,
        origin: &str,
        username: &str,
        new_password: Option<&str>,
    ) -> Result<LoginListRow> {
        let row = update_login_credential(
            &self.conn,
            credential_id,
            expected_revision,
            origin,
            username,
            new_password,
        )?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
    }

    pub fn trash_item(&self, item_id: &str) -> Result<()> {
        trash_item(&self.conn, item_id)?;
        mark_restore_dirty(&self.conn)?;
        Ok(())
    }

    pub fn security_summary(&self) -> Result<SecuritySummary> {
        security_summary(&self.conn)
    }

    pub fn import_bitwarden(
        &self,
        vault_dir: &Path,
        vmk: &[u8; 32],
        json: &str,
    ) -> Result<ImportReport> {
        create_restore_point_for_risky_op(vault_dir, vmk, &self.conn)?;
        let report = import_bitwarden_json(&self.conn, json)?;
        if report.imported > 0 {
            mark_restore_dirty(&self.conn)?;
        }
        Ok(report)
    }

    pub fn list_recovery_codes(&self) -> Result<Vec<RecoveryCodeRow>> {
        list_recovery_codes(&self.conn)
    }

    pub fn add_recovery_codes(&self, service_name: &str, codes: &[String]) -> Result<RecoveryCodeRow> {
        let row = insert_recovery_codes(&self.conn, service_name, codes)?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
    }

    pub fn update_recovery_codes(
        &self,
        id: &str,
        expected_revision: &str,
        service_name: &str,
        codes: &[String],
    ) -> Result<RecoveryCodeRow> {
        let row = update_recovery_codes(&self.conn, id, expected_revision, service_name, codes)?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
    }

    pub fn backup_status(&self) -> Result<BackupVerificationStatus> {
        read_backup_status(&self.conn)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn ensure_default_ssh(&self) -> Result<SshKeyRecord> {
        ensure_default_ssh_key(&self.conn)
    }

    pub fn default_ssh(&self) -> Result<Option<SshKeyRecord>> {
        load_default_ssh_key(&self.conn)
    }

    pub fn list_totp(&self) -> Result<Vec<TotpListRow>> {
        list_totp_credentials(&self.conn)
    }

    pub fn add_totp(&self, issuer: &str, account: &str, secret_base32: &str) -> Result<TotpListRow> {
        let row = insert_totp_row(&self.conn, issuer, account, secret_base32)?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
    }

    pub fn list_ssh(&self) -> Result<Vec<SshKeyListRow>> {
        list_ssh_keys(&self.conn)
    }

    pub fn generate_ssh(&self, label: &str, set_default: bool) -> Result<SshKeyListRow> {
        let row = generate_ssh_key(&self.conn, label, set_default)?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
    }

    pub fn totp_code(&self, totp_id: &str) -> Result<String> {
        let secret = totp_secret_for_id(&self.conn, totp_id)?;
        totp_code_now(&secret)
    }

    pub fn try_restore_point_if_due(
        &self,
        vault_dir: &Path,
        vmk: &[u8; 32],
    ) -> Result<Option<std::path::PathBuf>> {
        create_restore_point_if_due(vault_dir, vmk, &self.conn)
    }
}
