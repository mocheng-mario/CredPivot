use crate::bitwarden_import::{import_bitwarden_json, ImportReport};
use crate::error::Result;
use crate::local_db::open_database;
use crate::repo::{
    count_login_credentials, get_login_secret, insert_login_credential, list_login_by_origin,
    LoginCredentialRecord, LoginCredentialSummary,
};
use crate::backup_status::{read_backup_status, BackupVerificationStatus};
use crate::credential_groups::{
    create_credential_group, delete_credential_group, list_credential_groups, set_item_group,
    CredentialGroupRow,
};
use crate::repo_m2::{
    ensure_default_ssh_key, insert_login_extended, insert_recovery_codes, list_logins,
    list_recovery_codes, load_default_ssh_key, security_summary, trash_item, totp_reveal_for_id,
    totp_code_for_id, update_login_credential, update_recovery_codes,
    generate_ssh_key,
    insert_totp_row, list_ssh_keys, list_totp_credentials, LoginListRow, RecoveryCodeRow,
    SecuritySummary, SshKeyListRow, SshKeyRecord, TotpListRow, TotpRevealRow,
};
use crate::server_profiles::{
    insert_server_profile, list_server_profiles, update_server_profile, ServerProfileRow,
};
use crate::restore_point::{
    create_restore_point_for_risky_op, create_restore_point_if_due, mark_restore_dirty,
};
use std::path::Path;
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

    pub fn insert_login_full(
        &self,
        origin: &str,
        username: &str,
        password: &str,
        display_name: &str,
        connection_host: &str,
        linked_totp_id: Option<&str>,
        group_id: Option<&str>,
    ) -> Result<LoginListRow> {
        let row = insert_login_extended(
            &self.conn,
            origin,
            username,
            password,
            display_name,
            connection_host,
            linked_totp_id,
            group_id,
        )?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
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
        display_name: &str,
        connection_host: &str,
        linked_totp_id: Option<&str>,
        group_id: Option<&str>,
        new_password: Option<&str>,
    ) -> Result<LoginListRow> {
        let row = update_login_credential(
            &self.conn,
            credential_id,
            expected_revision,
            origin,
            username,
            display_name,
            connection_host,
            linked_totp_id,
            group_id,
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

    pub fn add_totp(
        &self,
        issuer: &str,
        account: &str,
        secret_base32: &str,
        group_id: Option<&str>,
    ) -> Result<TotpListRow> {
        let row = insert_totp_row(&self.conn, issuer, account, secret_base32, group_id)?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
    }

    pub fn totp_reveal(&self, totp_id: &str) -> Result<TotpRevealRow> {
        totp_reveal_for_id(&self.conn, totp_id)
    }

    pub fn list_credential_groups(&self, scope: &str) -> Result<Vec<CredentialGroupRow>> {
        list_credential_groups(&self.conn, scope)
    }

    pub fn create_credential_group(&self, scope: &str, name: &str) -> Result<CredentialGroupRow> {
        let row = create_credential_group(&self.conn, scope, name)?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
    }

    pub fn delete_credential_group(&self, id: &str) -> Result<()> {
        delete_credential_group(&self.conn, id)?;
        mark_restore_dirty(&self.conn)?;
        Ok(())
    }

    pub fn set_item_group(&self, item_id: &str, group_id: Option<&str>) -> Result<()> {
        set_item_group(&self.conn, item_id, group_id)?;
        mark_restore_dirty(&self.conn)?;
        Ok(())
    }

    pub fn list_server_profiles(&self) -> Result<Vec<ServerProfileRow>> {
        list_server_profiles(&self.conn)
    }

    pub fn create_server_profile(
        &self,
        label: &str,
        host: &str,
        port: u16,
        manual_username: &str,
        linked_login_id: Option<&str>,
        linked_totp_id: Option<&str>,
        linked_ssh_key_id: Option<&str>,
        group_id: Option<&str>,
    ) -> Result<ServerProfileRow> {
        let row = insert_server_profile(
            &self.conn,
            label,
            host,
            port,
            manual_username,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            group_id,
        )?;
        mark_restore_dirty(&self.conn)?;
        Ok(row)
    }

    pub fn update_server_profile(
        &self,
        id: &str,
        expected_revision: &str,
        label: &str,
        host: &str,
        port: u16,
        manual_username: &str,
        linked_login_id: Option<&str>,
        linked_totp_id: Option<&str>,
        linked_ssh_key_id: Option<&str>,
        group_id: Option<&str>,
    ) -> Result<ServerProfileRow> {
        let row = update_server_profile(
            &self.conn,
            id,
            expected_revision,
            label,
            host,
            port,
            manual_username,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            group_id,
        )?;
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
        totp_code_for_id(&self.conn, totp_id)
    }

    pub fn try_restore_point_if_due(
        &self,
        vault_dir: &Path,
        vmk: &[u8; 32],
    ) -> Result<Option<std::path::PathBuf>> {
        create_restore_point_if_due(vault_dir, vmk, &self.conn)
    }
}
