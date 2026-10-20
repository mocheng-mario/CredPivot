use crate::error::{AgentError, Result};
use base64::Engine;
use credpivot_core::{
    bootstrap_vault_dir, change_master_password_in_dir, clone_vault_to_empty_dir,
    create_restore_point_for_risky_op, export_ovb_from_dir, list_restore_points,
    mark_local_restore_verified, mark_ovb_decrypt_verified, mark_ovb_export_verified,
    mark_recovery_key_verified, parse_ovb_with_aad, parse_recovery_display, read_vault_json,
    recover_ovb_to_dir, FORMAT_MAJOR, SlotType,
    recover_restore_point_to_dir, security_rebuild_in_dir, RecoveryUnlock, VaultDatabase, VMK_LEN,
};
use std::path::Path;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// 进程内 Vault 会话：M1 控制面 + M2 SQLCipher 业务库。
#[derive(Debug)]
pub struct VaultSession {
    pub vault_dir: PathBuf,
    pub vmk: Option<Zeroizing<[u8; VMK_LEN]>>,
    pub db: Option<VaultDatabase>,
    pub unlocked: bool,
    pub touch_id_wrapped_token: Option<Vec<u8>>,
    pub ssh_signing_key: SigningKey,
    pub idle_timeout: Duration,
    pub last_activity: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeCredential {
    pub id: String,
    pub origin: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillGrant {
    pub request_id: String,
    pub credential_id: String,
    pub origin: String,
    pub tab_id: u64,
    pub frame_id: i64,
    pub document_id: String,
    pub expires_at_ms: u128,
}

impl VaultSession {
    pub fn new() -> Self {
        Self::new_at(crate::paths::vault_data_dir())
    }

    pub fn new_at(vault_dir: PathBuf) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            vault_dir,
            vmk: None,
            db: None,
            unlocked: false,
            touch_id_wrapped_token: None,
            ssh_signing_key: signing_key,
            idle_timeout: Duration::from_secs(5 * 60),
            last_activity: Instant::now(),
        }
    }

    fn attach_database(&mut self) -> Result<()> {
        let vmk = self
            .vmk
            .as_ref()
            .ok_or_else(|| AgentError::Vault("vmk not available".into()))?;
        let db = VaultDatabase::open(&self.vault_dir, &**vmk)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        self.db = Some(db);
        self.sync_ssh_from_db()?;
        self.try_restore_point_if_due()?;
        Ok(())
    }

    pub fn try_restore_point_if_due(&mut self) -> Result<()> {
        let vmk = self.vmk.as_ref().ok_or_else(|| AgentError::Vault("vmk missing".into()))?;
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let _ = db
            .try_restore_point_if_due(&self.vault_dir, &**vmk)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        Ok(())
    }

    fn sync_ssh_from_db(&mut self) -> Result<()> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let rec = db
            .ensure_default_ssh()
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        let sk = SigningKey::from_bytes(&rec.seed);
        self.ssh_signing_key = sk;
        Ok(())
    }

    pub fn vault_exists(&self) -> bool {
        self.vault_dir.join("vault.json").exists()
    }

    pub fn open_dir(&mut self, path: PathBuf) -> Result<()> {
        if self.unlocked {
            return Err(AgentError::Vault("lock vault before switching directory".into()));
        }
        if !path.join("vault.json").exists() {
            return Err(AgentError::Vault("vault.json not found in directory".into()));
        }
        self.vault_dir = path;
        let _ = crate::paths::persist_active_vault_dir(&self.vault_dir);
        Ok(())
    }

    pub fn vault_status_json(&self) -> serde_json::Value {
        let cred_count = self
            .db
            .as_ref()
            .and_then(|db| db.login_count().ok())
            .unwrap_or(0);
        let mut out = serde_json::json!({
            "format": "m2",
            "schema_user_version": credpivot_core::SCHEMA_USER_VERSION,
            "vault_exists": self.vault_exists(),
            "vault_path": self.vault_dir.to_string_lossy(),
            "unlocked": self.unlocked,
            "database_attached": self.db.is_some(),
            "idle_timeout_sec": self.idle_timeout.as_secs(),
            "credential_count": cred_count,
            "ssh_pubkey": self.ssh_public_key_openssh(),
            "touch_id_token_configured": self.touch_id_wrapped_token.is_some(),
        });
        if self.vault_exists() {
            if let Ok(cfg) = read_vault_json(&self.vault_dir) {
                out["vault_id"] = serde_json::json!(cfg.vault_id);
                out["control_revision"] = serde_json::json!(cfg.control_revision);
            }
        }
        out
    }

    pub fn touch_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn idle_expired(&self) -> bool {
        self.unlocked && self.last_activity.elapsed() > self.idle_timeout
    }

    pub fn lock(&mut self) {
        if self.unlocked {
            let _ = self.try_restore_point_if_due();
        }
        self.unlocked = false;
        self.vmk = None;
        self.db = None;
        self.ssh_signing_key = SigningKey::generate(&mut OsRng);
    }

    pub fn create_vault(&mut self, password: &str) -> Result<String> {
        if self.vault_dir.exists() {
            let mut empty = true;
            if let Ok(rd) = std::fs::read_dir(&self.vault_dir) {
                empty = !rd.into_iter().any(|e| e.is_ok());
            }
            if !empty && self.vault_exists() {
                return Err(AgentError::Vault("vault already exists".into()));
            }
        }
        let material = bootstrap_vault_dir(&self.vault_dir, password)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        self.vmk = Some(material.vmk);
        if let Err(e) = self.attach_database() {
            self.vmk = None;
            return Err(AgentError::Vault(e.to_string()));
        }
        self.unlocked = true;
        self.touch_activity();
        Ok(material.recovery_display)
    }

    pub fn unlock_password(&mut self, password: &str) -> Result<()> {
        if !self.vault_exists() {
            return Err(AgentError::Vault("no vault — create one first".into()));
        }
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        let vmk = cfg
            .unlock_master(password)
            .map_err(|_| AgentError::Vault("invalid password".into()))?;
        cfg.verify_mac(&*vmk)
            .map_err(|_| AgentError::Vault("control mac failed".into()))?;
        self.vmk = Some(vmk);
        if let Err(e) = self.attach_database() {
            self.vmk = None;
            return Err(e);
        }
        self.unlocked = true;
        self.touch_activity();
        Ok(())
    }

    /// 门槛令牌不等于 Vault 解锁：无 VMK/数据库时不标记为已解锁。
    pub fn unlock_touch_id_token(&mut self, _token: &[u8]) -> bool {
        false
    }

    pub fn change_password(&mut self, old: &str, new: &str) -> Result<()> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        if let (Some(vmk), Some(db)) = (self.vmk.as_ref(), self.db.as_ref()) {
            create_restore_point_for_risky_op(&self.vault_dir, &**vmk, db.conn())
                .map_err(|e| AgentError::Vault(e.to_string()))?;
        }
        let prior_vmk = self.vmk.clone();
        self.db = None;
        if let Err(e) = change_master_password_in_dir(&self.vault_dir, old, new) {
            if let Some(vmk) = prior_vmk {
                self.vmk = Some(vmk);
                let _ = self.attach_database();
            }
            return Err(AgentError::Vault(e.to_string()));
        }
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        let vmk = cfg
            .unlock_master(new)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        cfg.verify_mac(&*vmk).map_err(|e| AgentError::Vault(e.to_string()))?;
        self.vmk = Some(vmk);
        self.attach_database()?;
        Ok(())
    }

    pub fn export_ovb(&self, output_path: &str, password: &str) -> Result<()> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        let bytes = export_ovb_from_dir(&self.vault_dir, password)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        credpivot_core::write_file_atomic(Path::new(output_path), &bytes)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        if let Some(db) = self.db.as_ref() {
            let _ = mark_ovb_export_verified(db.conn());
        }
        Ok(())
    }

    pub fn recover_ovb(
        ovb_path: &str,
        target_dir: &str,
        password: Option<&str>,
        recovery_key: Option<&str>,
    ) -> Result<()> {
        let data = std::fs::read(ovb_path).map_err(AgentError::from)?;
        let target = PathBuf::from(target_dir);
        if password.is_some() {
            let pw = password.unwrap();
            recover_ovb_to_dir(&data, &target, RecoveryUnlock::MasterPassword(pw.to_string()))
                .map_err(|e| AgentError::Vault(e.to_string()))?;
        } else if let Some(display) = recovery_key {
            let secret = credpivot_core::parse_recovery_display(display.trim())
                .map_err(|e| AgentError::Vault(e.to_string()))?;
            let mut arr = [0u8; VMK_LEN];
            arr.copy_from_slice(&secret);
            recover_ovb_to_dir(&data, &target, RecoveryUnlock::RecoverySecret(arr))
                .map_err(|e| AgentError::Vault(e.to_string()))?;
        } else {
            return Err(AgentError::Vault("password or recovery_key required".into()));
        }
        Ok(())
    }

    pub fn ssh_public_key_openssh(&self) -> String {
        let vk: VerifyingKey = self.ssh_signing_key.verifying_key();
        let bytes = vk.to_bytes();
        credpivot_core::format_ssh_ed25519_openssh(&bytes, "credpivot-m2")
    }

    pub fn save_credential(
        &mut self,
        origin: &str,
        username: &str,
        password: &str,
        display_name: &str,
        connection_host: &str,
        linked_totp_id: Option<&str>,
        group_id: Option<&str>,
    ) -> Result<credpivot_core::LoginListRow> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("unlock with master password to access database".into()))?;
        db.insert_login_full(
            origin,
            username,
            password,
            display_name,
            connection_host,
            linked_totp_id,
            group_id,
        )
        .map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn suggest_for_origin(&self, origin: &str) -> Result<Vec<FakeCredential>> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let list = db
            .list_by_origin(origin)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        Ok(list
            .into_iter()
            .map(|c| FakeCredential {
                id: c.id,
                origin: c.origin,
                username: c.username,
                password: String::new(),
            })
            .collect())
    }

    pub fn list_credentials(&self, query: Option<&str>, limit: u32) -> Result<Vec<credpivot_core::LoginListRow>> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.list_logins(query, limit).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn update_credential(
        &self,
        credential_id: &str,
        expected_revision: &str,
        origin: &str,
        username: &str,
        display_name: &str,
        connection_host: &str,
        linked_totp_id: Option<&str>,
        group_id: Option<&str>,
        password: Option<&str>,
    ) -> Result<credpivot_core::LoginListRow> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.update_login(
            credential_id,
            expected_revision,
            origin,
            username,
            display_name,
            connection_host,
            linked_totp_id,
            group_id,
            password,
        )
            .map_err(|e| match e {
                credpivot_core::CoreError::Conflict => AgentError::Vault("revision conflict".into()),
                other => AgentError::Vault(other.to_string()),
            })
    }

    pub fn trash_credential_item(&self, item_id: &str) -> Result<()> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.trash_item(item_id).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn security_summary(&self) -> Result<credpivot_core::SecuritySummary> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.security_summary().map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn import_bitwarden(&self, json: &str) -> Result<credpivot_core::ImportReport> {
        let vmk = self
            .vmk
            .as_ref()
            .ok_or_else(|| AgentError::Vault("vmk not available".into()))?;
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.import_bitwarden(&self.vault_dir, &**vmk, json)
            .map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn totp_code(&self, totp_id: &str) -> Result<String> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.totp_code(totp_id).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn list_totp(&self) -> Result<Vec<credpivot_core::TotpListRow>> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.list_totp().map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn create_totp(
        &self,
        issuer: &str,
        account: &str,
        secret_base32: &str,
        group_id: Option<&str>,
    ) -> Result<credpivot_core::TotpListRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.add_totp(issuer, account, secret_base32, group_id)
            .map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn totp_reveal(&self, totp_id: &str) -> Result<credpivot_core::TotpRevealRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.totp_reveal(totp_id).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn list_credential_groups(&self, scope: &str) -> Result<Vec<credpivot_core::CredentialGroupRow>> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.list_credential_groups(scope).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn create_credential_group(&self, scope: &str, name: &str) -> Result<credpivot_core::CredentialGroupRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.create_credential_group(scope, name).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn delete_credential_group(&self, id: &str) -> Result<()> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.delete_credential_group(id).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn set_item_group(&self, item_id: &str, group_id: Option<&str>) -> Result<()> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.set_item_group(item_id, group_id).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn list_server_profiles(&self) -> Result<Vec<credpivot_core::ServerProfileRow>> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.list_server_profiles().map_err(|e| AgentError::Vault(e.to_string()))
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
    ) -> Result<credpivot_core::ServerProfileRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.create_server_profile(
            label,
            host,
            port,
            manual_username,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            group_id,
        )
        .map_err(|e| AgentError::Vault(e.to_string()))
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
    ) -> Result<credpivot_core::ServerProfileRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.update_server_profile(
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
        )
        .map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn list_ssh_keys(&self) -> Result<Vec<credpivot_core::SshKeyListRow>> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.list_ssh().map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn generate_ssh_key(&mut self, label: &str, set_default: bool) -> Result<credpivot_core::SshKeyListRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let row = db
            .generate_ssh(label, set_default)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        if set_default {
            self.sync_ssh_from_db()?;
        }
        Ok(row)
    }

    pub fn get_credential(&self, credential_id: &str) -> Result<FakeCredential> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let rec = db
            .get_login(credential_id)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        Ok(FakeCredential {
            id: rec.id,
            origin: rec.origin,
            username: rec.username,
            password: rec.password,
        })
    }

    pub fn list_recovery_codes(&self) -> Result<Vec<credpivot_core::RecoveryCodeRow>> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.list_recovery_codes().map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn create_recovery_codes(&self, service_name: &str, codes: &[String]) -> Result<credpivot_core::RecoveryCodeRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.add_recovery_codes(service_name, codes)
            .map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn update_recovery_codes(
        &self,
        id: &str,
        expected_revision: &str,
        service_name: &str,
        codes: &[String],
    ) -> Result<credpivot_core::RecoveryCodeRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.update_recovery_codes(id, expected_revision, service_name, codes)
            .map_err(|e| match e {
                credpivot_core::CoreError::Conflict => AgentError::Vault("revision conflict".into()),
                other => AgentError::Vault(other.to_string()),
            })
    }

    pub fn list_restore_points(&self) -> Result<Vec<credpivot_core::RestorePointInfo>> {
        list_restore_points(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn recover_restore_point(&self, created_at_ms: i64, target_dir: &str) -> Result<()> {
        let vmk = self.vmk.as_ref().ok_or_else(|| AgentError::Vault("vmk not available".into()))?;
        let point = self
            .vault_dir
            .join(credpivot_core::RESTORE_POINTS_DIR)
            .join(created_at_ms.to_string());
        recover_restore_point_to_dir(&point, Path::new(target_dir), vmk)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        if let Some(db) = self.db.as_ref() {
            let _ = mark_local_restore_verified(db.conn());
        }
        Ok(())
    }

    pub fn migrate_vault_to(&mut self, target_dir: &str) -> Result<()> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        let vmk = self.vmk.as_ref().ok_or_else(|| AgentError::Vault("vmk not available".into()))?;
        if let Some(db) = self.db.as_ref() {
            create_restore_point_for_risky_op(&self.vault_dir, &**vmk, db.conn())
                .map_err(|e| AgentError::Vault(e.to_string()))?;
        }
        self.db = None;
        clone_vault_to_empty_dir(&self.vault_dir, Path::new(target_dir), vmk)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        self.vault_dir = PathBuf::from(target_dir);
        let _ = crate::paths::persist_active_vault_dir(&self.vault_dir);
        self.attach_database()?;
        Ok(())
    }

    pub fn security_rebuild(&mut self, password: &str, recovery_key: &str) -> Result<String> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        if let (Some(vmk), Some(db)) = (self.vmk.as_ref(), self.db.as_ref()) {
            create_restore_point_for_risky_op(&self.vault_dir, &**vmk, db.conn())
                .map_err(|e| AgentError::Vault(e.to_string()))?;
        }
        self.db = None;
        let new_recovery = security_rebuild_in_dir(&self.vault_dir, password, recovery_key)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        let vmk = cfg
            .unlock_master(password)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        cfg.verify_mac(&*vmk).map_err(|e| AgentError::Vault(e.to_string()))?;
        self.vmk = Some(vmk);
        self.attach_database()?;
        Ok(new_recovery)
    }

    pub fn backup_status(&self) -> Result<credpivot_core::BackupVerificationStatus> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.backup_status().map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn verify_recovery_key(&self, recovery_display: &str) -> Result<()> {
        let vmk = self.vmk.as_ref().ok_or_else(|| AgentError::Vault("vmk not available".into()))?;
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        let secret = parse_recovery_display(recovery_display.trim())
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        let mut arr = [0u8; VMK_LEN];
        arr.copy_from_slice(&secret);
        let via = cfg
            .unlock_recovery(&arr)
            .map_err(|_| AgentError::Vault("recovery key mismatch".into()))?;
        if via.as_ref() != vmk.as_ref() {
            return Err(AgentError::Vault("recovery key mismatch".into()));
        }
        if let Some(db) = self.db.as_ref() {
            let _ = mark_recovery_key_verified(db.conn());
        }
        Ok(())
    }

    pub fn verify_ovb_file(&self, ovb_path: &str, password: &str) -> Result<()> {
        let data = std::fs::read(ovb_path).map_err(AgentError::from)?;
        let (header, aad, ciphertext) =
            parse_ovb_with_aad(&data).map_err(|e| AgentError::Vault(e.to_string()))?;
        let slot = header
            .slots
            .iter()
            .find(|s| s.slot_type == SlotType::MasterPassword)
            .ok_or_else(|| AgentError::Vault("no master slot".into()))?;
        let _vmk = slot
            .unwrap_vmk(
                &header.vault_id.to_string(),
                FORMAT_MAJOR,
                password.as_bytes(),
            )
            .map_err(|_| AgentError::Vault("invalid ovb password".into()))?;
        let _plain = credpivot_core::decrypt_snapshot(&_vmk, &header, &aad, &ciphertext)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        if let Some(db) = self.db.as_ref() {
            let _ = mark_ovb_decrypt_verified(db.conn());
        }
        Ok(())
    }
}
