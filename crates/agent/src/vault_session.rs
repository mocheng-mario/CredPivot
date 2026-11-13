use crate::error::{AgentError, Result};
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
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
use base64::{engine::general_purpose::STANDARD, Engine};

// “每次验证”仍需为验证完成到实际请求之间保留一次性执行窗口。
const SENSITIVE_REQUEST_HANDOFF: Duration = Duration::from_secs(30);

fn authentication_time_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// 仅由 App 从本机钥匙串恢复；不能接受浏览器或 askpass 提交的策略。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalUnlockPolicy {
    pub binding: String,
    pub last_master_ms: u64,
    pub last_unlock_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalUnlockMaterial {
    pub vmk: String,
    pub policy: LocalUnlockPolicy,
}

impl std::fmt::Debug for LocalUnlockMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalUnlockMaterial([REDACTED])")
    }
}

/// 进程内 Vault 会话：M1 控制面 + M2 SQLCipher 业务库。
#[derive(Debug)]
pub struct VaultSession {
    pub(crate) bootstrap_plan: Option<credpivot_core::sync::BootstrapPlan>,
    pub(crate) sync_plan: Option<credpivot_core::sync::Plan>,
    pub vault_dir: PathBuf,
    pub vmk: Option<Zeroizing<[u8; VMK_LEN]>>,
    pub db: Option<VaultDatabase>,
    pub unlocked: bool,
    pub local_unlock_policy: LocalUnlockPolicy,
    settings: credpivot_core::AppSettings,
    sensitive_authenticated_at: Option<Instant>,
    pub ssh_signing_key: Option<SigningKey>,
    pub ssh_signing_key_id: Option<String>,
    pub ssh_signing_key_comment: String,
    pub ssh_authorization: crate::ssh_agent::SshAuthorization,
    pub passkey_requests: crate::passkey::PendingRequests,
    pub browser_mfa_requests: crate::browser_mfa::PendingRequests,
    pub(crate) terminal_connections: std::collections::HashMap<String, crate::terminal_connect::PendingConnection>,
    pub data_revision: String,
    pub idle_timeout: Duration,
    pub last_activity: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeCredential {
    pub id: String,
    pub origin: String,
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_totp_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillGrant {
    pub request_id: String,
    pub browser_session: Option<uuid::Uuid>,
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
        let settings = credpivot_core::effective_app_settings();
        Self {
            bootstrap_plan: None,
            sync_plan: None,
            vault_dir,
            vmk: None,
            db: None,
            unlocked: false,
            local_unlock_policy: LocalUnlockPolicy::default(),
            sensitive_authenticated_at: None,
            ssh_signing_key: None,
            ssh_signing_key_id: None,
            ssh_signing_key_comment: String::new(),
            ssh_authorization: Default::default(),
            passkey_requests: Default::default(),
            browser_mfa_requests: Default::default(),
            terminal_connections: Default::default(),
            data_revision: uuid::Uuid::new_v4().to_string(),
            idle_timeout: Duration::from_secs(settings.vault_idle_seconds),
            settings,
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
        if self.try_restore_point_if_due().is_err() {
            crate::diagnostics::warn("backup", "scheduled restore point skipped");
        }
        Ok(())
    }

    fn abort_partial_unlock(&mut self) {
        self.terminal_connections.clear();
        self.sync_plan = None;
        self.passkey_requests.clear();
        self.browser_mfa_requests.clear();
        self.ssh_authorization.clear();
        self.ssh_signing_key_id = None;
        self.ssh_signing_key_comment.clear();
        self.unlocked = false;
        self.vmk = None;
        self.db = None;
        self.ssh_signing_key = None;
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

    pub(crate) fn sync_ssh_from_db(&mut self) -> Result<()> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let rec = db
            .default_ssh()
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        self.ssh_signing_key_id = rec.as_ref().map(|key| key.id.clone());
        self.ssh_signing_key_comment = rec.as_ref().map(|key| key.public_openssh.splitn(3,' ').nth(2).unwrap_or("").to_string()).unwrap_or_default();
        self.ssh_authorization.clear();
        self.ssh_signing_key = rec.map(|key| SigningKey::from_bytes(&key.seed));
        Ok(())
    }

    pub fn vault_exists(&self) -> bool {
        self.vault_dir.join("vault.json").exists()
    }

    pub fn open_dir(&mut self, path: PathBuf) -> Result<()> {
        let path = std::fs::canonicalize(path).map_err(|e| AgentError::Vault(e.to_string()))?;
        read_vault_json(&path).map_err(|_| AgentError::Vault("不是有效的保险库目录".into()))?;
        if !path.join("vault.db").is_file() {
            return Err(AgentError::Vault("保险库缺少 vault.db".into()));
        }
        crate::paths::persist_active_vault_dir(&path).map_err(|e| AgentError::Vault(e.to_string()))?;
        self.lock();
        self.data_revision = uuid::Uuid::new_v4().to_string();
        self.vault_dir = path;
        self.local_unlock_policy = LocalUnlockPolicy::default();
        self.sensitive_authenticated_at = None;
        Ok(())
    }

    pub fn vault_status_json(&self) -> serde_json::Value {
        let cred_count = self
            .db
            .as_ref()
            .and_then(|db| db.login_count().ok())
            .unwrap_or(0);
        let mut out = serde_json::json!({
            "agent_version": env!("CARGO_PKG_VERSION"),
            "protocol_version": crate::PROTOCOL_VERSION,
            "expected_extension_version": serde_json::from_str::<serde_json::Value>(include_str!("../../../apps/chrome-extension/manifest.json"))
                .ok().and_then(|v|v["version"].as_str().map(String::from)),
            "format": "m2",
            "data_revision": self.data_revision,
            "schema_user_version": credpivot_core::SCHEMA_USER_VERSION,
            "vault_exists": self.vault_exists(),
            "vault_path": self.vault_dir.to_string_lossy(),
            "unlocked": self.unlocked,
            "database_attached": self.db.is_some(),
            "idle_timeout_sec": self.idle_timeout.as_secs(),
            "credential_count": cred_count,
            "ssh_pubkey": self.ssh_public_key_openssh(),
            "master_password_required": self.master_password_required(),
            "master_password_reason": self.master_password_reason(),
            "sensitive_auth_active": self.sensitive_auth_active(),
            "settings_valid": credpivot_core::read_app_settings().is_ok(),
            "vault_lock_generation": crate::paths::read_vault_lock_generation(),
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

    pub fn apply_settings(&mut self, settings: credpivot_core::AppSettings) -> bool {
        let security_changed = self.settings.security_differs(&settings);
        if security_changed { self.sensitive_authenticated_at = None; self.ssh_authorization.clear(); self.passkey_requests.clear(); self.browser_mfa_requests.clear(); self.terminal_connections.clear(); }
        self.idle_timeout = Duration::from_secs(settings.vault_idle_seconds);
        self.settings = settings;
        security_changed
    }

    pub fn idle_expired(&self) -> bool {
        self.unlocked && (self.last_activity.elapsed() > self.idle_timeout || self.master_password_required())
    }

    /// 丢掉内存中的密钥，不写恢复点。重置前使用，避免把即将删除的库再备份一份。
    pub fn discard_secrets(&mut self) {
        self.terminal_connections.clear();
        self.bootstrap_plan = None;
        self.sync_plan = None;
        self.passkey_requests.clear();
        self.browser_mfa_requests.clear();
        self.unlocked = false;
        self.ssh_authorization.clear();
        self.ssh_signing_key_id = None;
        self.ssh_signing_key_comment.clear();
        self.sensitive_authenticated_at = None;
        self.vmk = None;
        self.db = None;
        self.ssh_signing_key = None;
        self.local_unlock_policy = LocalUnlockPolicy::default();
        crate::paths::bump_vault_lock_generation();
    }

    pub fn lock(&mut self) {
        self.terminal_connections.clear();
        self.bootstrap_plan = None;
        self.sync_plan = None;
        self.passkey_requests.clear();
        self.browser_mfa_requests.clear();
        if self.unlocked {
            if self.try_restore_point_if_due().is_err() {
                crate::diagnostics::warn("backup", "restore point before lock failed");
            }
            crate::diagnostics::info("vault", "locked");
        }
        self.unlocked = false;
        self.ssh_authorization.clear();
        self.ssh_signing_key_id = None;
        self.ssh_signing_key_comment.clear();
        self.sensitive_authenticated_at = None;
        self.vmk = None;
        self.db = None;
        self.ssh_signing_key = None;
        crate::paths::bump_vault_lock_generation();
    }

    /// 将 Agent SSH 身份切换为库内指定密钥（供服务器一键连接使用）。
    pub fn select_ssh_key(&mut self, key_id: &str) -> Result<()> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let rec = db
            .load_ssh_key(key_id)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        self.ssh_authorization.clear();
        self.ssh_signing_key_id = Some(rec.id.clone());
        self.ssh_signing_key_comment = rec.public_openssh.splitn(3,' ').nth(2).unwrap_or("").to_string();
        self.ssh_signing_key = Some(SigningKey::from_bytes(&rec.seed));
        Ok(())
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
        // 默认密钥只在新建保险库时生成，读取或重新解锁不能复活已删除的密钥。
        if let Err(e) = self.attach_database().and_then(|_| {
            self.generate_ssh_key("Default", true, None).map(|_| ())
        }) {
            self.abort_partial_unlock();
            return Err(AgentError::Vault(e.to_string()));
        }
        if let Err(e) = self.record_master_verification() {
            self.abort_partial_unlock();
            return Err(e);
        }
        self.unlocked = true;
        self.touch_activity();
        crate::diagnostics::info("vault", "created and unlocked");
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
            self.abort_partial_unlock();
            return Err(e);
        }
        if let Err(e) = self.record_master_verification() {
            self.abort_partial_unlock();
            return Err(e);
        }
        self.unlocked = true;
        self.touch_activity();
        crate::diagnostics::info("vault", "unlocked");
        Ok(())
    }

    fn local_unlock_binding(&self) -> Result<String> {
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        let slot = cfg.key_slots.iter().find(|s| s.slot_type == SlotType::MasterPassword)
            .ok_or_else(|| AgentError::Vault("master slot missing".into()))?;
        Ok(format!("{}:{}:{}", cfg.vault_id, cfg.control_id, slot.slot_id))
    }

    pub fn load_local_unlock_policy(&mut self, policy: LocalUnlockPolicy) -> bool {
        let valid = self.local_unlock_binding().ok().as_deref() == Some(policy.binding.as_str());
        self.local_unlock_policy = if valid {
            policy
        } else {
            LocalUnlockPolicy::default()
        };
        valid
    }

    pub fn master_password_required(&self) -> bool {
        self.master_password_reason().is_some()
    }

    pub fn master_password_reason(&self) -> Option<&'static str> {
        let now = authentication_time_ms();
        let policy = &self.local_unlock_policy;
        if policy.last_master_ms == 0 || policy.last_unlock_ms == 0 { Some("policy_missing") }
        else if now < policy.last_master_ms || now < policy.last_unlock_ms { Some("clock_changed") }
        else if now.saturating_sub(policy.last_master_ms) >= self.settings.master_password_days * 86_400_000 { Some("master_period") }
        else if now.saturating_sub(policy.last_unlock_ms) >= self.settings.master_password_idle_hours * 3_600_000 { Some("unlock_idle") }
        else { None }
    }

    pub(crate) fn record_master_verification(&mut self) -> Result<()> {
        let now = authentication_time_ms();
        self.local_unlock_policy = LocalUnlockPolicy {
            binding: self.local_unlock_binding()?, last_master_ms: now, last_unlock_ms: now,
        };
        self.grant_sensitive_auth();
        Ok(())
    }

    pub fn verify_master_password(&mut self, password: &str) -> Result<()> {
        if !self.unlocked { return Err(AgentError::Locked); }
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        let key = cfg.unlock_master(password).map_err(|_| AgentError::Vault("invalid password".into()))?;
        cfg.verify_mac(&key).map_err(|_| AgentError::Vault("control mac failed".into()))?;
        if self.vmk.as_deref() != Some(&*key) {
            self.lock();
            return Err(AgentError::Vault("vault changed; unlock again".into()));
        }
        // 验证身份不重新打开数据库，也不延长“上次解锁”的强制主密码窗口。
        self.local_unlock_policy.last_master_ms = authentication_time_ms();
        self.grant_sensitive_auth();
        Ok(())
    }

    pub fn local_unlock_material(&self) -> Result<LocalUnlockMaterial> {
        if !self.unlocked || self.master_password_required() { return Err(AgentError::Locked); }
        let key = self.vmk.as_ref().ok_or(AgentError::Locked)?;
        Ok(LocalUnlockMaterial { vmk: STANDARD.encode(&**key), policy: self.local_unlock_policy.clone() })
    }

    pub fn unlock_local(&mut self, material: LocalUnlockMaterial) -> Result<()> {
        if self.master_password_required() || material.policy.binding != self.local_unlock_binding()? {
            return Err(AgentError::Vault("master password required".into()));
        }
        let bytes = Zeroizing::new(STANDARD.decode(&material.vmk)
            .map_err(|_| AgentError::Vault("invalid local unlock material".into()))?);
        if bytes.len() != VMK_LEN { return Err(AgentError::Vault("invalid local unlock material".into())); }
        let mut key = Zeroizing::new([0u8; VMK_LEN]);
        key.copy_from_slice(&bytes);
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        cfg.verify_mac(&key).map_err(|_| AgentError::Vault("local unlock material expired".into()))?;
        self.vmk = Some(key);
        if let Err(e) = self.attach_database() { self.abort_partial_unlock(); return Err(e); }
        self.local_unlock_policy.last_unlock_ms = authentication_time_ms();
        self.unlocked = true;
        self.grant_sensitive_auth();
        self.touch_activity();
        crate::diagnostics::info("vault", "unlocked with local authentication");
        Ok(())
    }

    pub fn grant_sensitive_auth(&mut self) {
        self.sensitive_authenticated_at = Some(Instant::now());
    }

    pub fn sensitive_auth_active(&self) -> bool {
        self.unlocked && !self.master_password_required()
            && self.settings.sensitive_auth_seconds > 0
            && self.sensitive_authenticated_at.is_some_and(|t| t.elapsed() < Duration::from_secs(self.settings.sensitive_auth_seconds))
    }

    pub fn authorize_sensitive_operation(&mut self) -> bool {
        if self.settings.sensitive_auth_seconds > 0 { return self.sensitive_auth_active(); }
        let authorized = self.unlocked && !self.master_password_required()
            && self.sensitive_authenticated_at.is_some_and(|t| t.elapsed() < SENSITIVE_REQUEST_HANDOFF);
        // 0 秒表示只允许刚刚确认的这一个请求，不能作为下一次操作的复用凭据。
        self.sensitive_authenticated_at = None;
        authorized
    }

    pub fn change_password(&mut self, old: &str, new: &str) -> Result<()> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        self.sync_plan = None;
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
            return Err(AgentError::Vault(match e {
                credpivot_core::CoreError::Format(message) if message.starts_with("sync.") => message,
                error => error.to_string(),
            }));
        }
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        let vmk = cfg
            .unlock_master(new)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        cfg.verify_mac(&*vmk).map_err(|e| AgentError::Vault(e.to_string()))?;
        self.vmk = Some(vmk);
        self.attach_database()?;
        self.record_master_verification()?;
        Ok(())
    }

    pub fn export_json(&mut self, path: &str, password: &str) -> Result<()> {
        use std::io::Write;
        self.verify_master_password(password)?;
        let db = self.db.as_ref().ok_or(AgentError::Locked)?;
        let json = credpivot_core::export_logical_json(db.conn()).map_err(|e| AgentError::Vault(e.to_string()))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(path).map_err(|_| AgentError::Vault("无法创建明文文件，请选择未使用的文件名".into()))?;
        if file.write_all(json.as_bytes()).and_then(|_| file.sync_all()).is_err() {
            drop(file);
            let _ = std::fs::remove_file(path);
            return Err(AgentError::Vault("明文导出失败".into()));
        }
        Ok(())
    }

    pub fn reset_recovery_key(&mut self, password: &str, recovery_key: &str) -> Result<String> {
        self.verify_master_password(password)?;
        self.sync_plan = None;
        let key = credpivot_core::reset_recovery_key_in_dir(&self.vault_dir, password, recovery_key)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        self.data_revision = uuid::Uuid::new_v4().to_string();
        // 配置已生效后，刷新失败也不能丢失应交付的新恢复码。
        if self.record_master_verification().is_err() { self.lock(); }
        Ok(key)
    }

    pub fn export_ovb(&mut self, output_path: &str, password: &str) -> Result<()> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        let bytes = export_ovb_from_dir(&self.vault_dir, password)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        credpivot_core::write_file_atomic(Path::new(output_path), &bytes)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        self.local_unlock_policy.last_master_ms = authentication_time_ms();
        self.grant_sensitive_auth();
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
        let data = credpivot_core::read_ovb_file(Path::new(ovb_path))
            .map_err(|e| AgentError::Vault(e.to_string()))?;
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
        let Some(key) = &self.ssh_signing_key else { return String::new(); };
        let vk: VerifyingKey = key.verifying_key();
        let bytes = vk.to_bytes();
        credpivot_core::format_ssh_ed25519_openssh(&bytes, &self.ssh_signing_key_comment)
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
        website_rules: Option<&[credpivot_core::UriRule]>,
        linked_mfa_ids: Option<&[String]>,
        password_active_since_ms: Option<i64>,
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
            website_rules,
            linked_mfa_ids,
            password_active_since_ms,
        )
        .map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn suggest_for_origin(&self, origin: &str) -> Result<Vec<FakeCredential>> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let list = credpivot_core::browser_login_candidates(db.conn()).map_err(|e| AgentError::Vault(e.to_string()))?
            .into_iter().filter(|row| self.credential_matches_page(&row.id, origin)).collect::<Vec<_>>();
        Ok(list
            .into_iter()
            .map(|c| FakeCredential {
                id: c.id,
                origin: c.origin,
                username: c.username,
                password: String::new(),
                linked_totp_id: c.linked_totp_id,
            })
            .collect())
    }

    pub fn credential_matches_page(&self, credential_id: &str, origin: &str) -> bool {
        self.db.as_ref().is_some_and(|db| credpivot_core::credential_matches_origin(db.conn(), credential_id, origin).unwrap_or(false))
    }

    pub fn list_credentials(&self, query: Option<&str>, limit: u32, offset: u32) -> Result<Vec<credpivot_core::LoginListRow>> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.list_logins_page(query, limit, offset).map_err(|e| AgentError::Vault(e.to_string()))
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
        website_rules: Option<&[credpivot_core::UriRule]>,
        linked_mfa_ids: Option<&[String]>,
        linked_ssh_key_ids: Option<&[String]>,
        linked_passkey_ids: Option<&[String]>,
    ) -> Result<credpivot_core::LoginListRow> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.update_login_with_mfa(
            credential_id,
            expected_revision,
            origin,
            username,
            display_name,
            connection_host,
            linked_totp_id,
            group_id,
            password,
            website_rules,
            linked_mfa_ids,
            linked_ssh_key_ids,
            linked_passkey_ids,
        )
            .map_err(|e| match e {
                credpivot_core::CoreError::Conflict => AgentError::Vault("revision conflict".into()),
                other => AgentError::Vault(other.to_string()),
            })
    }

    pub fn trash_credential_item(&mut self, item_id: &str) -> Result<()> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let active_public = self.ssh_public_key_openssh();
        let deleting_active = db.list_ssh().map_err(|e| AgentError::Vault(e.to_string()))?
            .iter().any(|row| row.item_id == item_id
                && row.public_openssh.split_whitespace().nth(1) == active_public.split_whitespace().nth(1));
        db.trash_item(item_id).map_err(|e| AgentError::Vault(e.to_string()))?;
        if deleting_active {
            // 数据库删除后立即清空缓存，不能让已删除的密钥继续签名。
            self.ssh_signing_key = None;
            self.sync_ssh_from_db()?;
        }
        Ok(())
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
        website_rules: &[credpivot_core::UriRule],
    ) -> Result<credpivot_core::TotpListRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.add_totp_with_rules(issuer, account, secret_base32, group_id, website_rules)
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
        manual_secret: Option<&str>,
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
            manual_secret,
        )
        .map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn list_ssh_keys(&self) -> Result<Vec<credpivot_core::SshKeyListRow>> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        db.list_ssh().map_err(|e| AgentError::Vault(e.to_string()))
    }

    pub fn generate_ssh_key(
        &mut self,
        label: &str,
        set_default: bool,
        group_id: Option<&str>,
    ) -> Result<credpivot_core::SshKeyListRow> {
        let db = self.db.as_ref().ok_or_else(|| AgentError::Vault("database not attached".into()))?;
        let row = db
            .generate_ssh(label, set_default, group_id)
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
            linked_totp_id: rec.linked_totp_id,
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

    pub fn list_restore_points(&self) -> Result<Vec<serde_json::Value>> {
        let vmk = self.vmk.as_ref().ok_or_else(|| AgentError::Vault("vmk not available".into()))?;
        let points = list_restore_points(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        Ok(points.into_iter().map(|point| {
            let same_generation = read_vault_json(&point.path)
                .and_then(|cfg| cfg.verify_mac(&**vmk)).is_ok();
            serde_json::json!({"created_at_ms":point.created_at_ms,"path":point.path,"requires_password":!same_generation})
        }).collect())
    }

    pub fn recover_restore_point(&self, created_at_ms: i64, target_dir: &str, password: Option<&str>) -> Result<()> {
        let vmk = self.vmk.as_ref().ok_or_else(|| AgentError::Vault("vmk not available".into()))?;
        let point = self
            .vault_dir
            .join(credpivot_core::RESTORE_POINTS_DIR)
            .join(created_at_ms.to_string());
        let current_json = self.vault_dir.join("vault.json");
        let point_cfg = read_vault_json(&point).map_err(|e| AgentError::Vault(e.to_string()))?;
        let current_cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        if point_cfg.vault_id != current_cfg.vault_id {
            return Err(AgentError::Vault("恢复点不属于当前保险库".into()));
        }
        let same_generation = point_cfg.verify_mac(&**vmk).is_ok();
        // 安全重建前的恢复点使用旧 VMK，必须用该副本自身的主密码槽解锁。
        let old_vmk = if same_generation { None } else {
            let password = password.ok_or_else(|| AgentError::Vault("此恢复点需要创建时的主密码".into()))?;
            let key = point_cfg.unlock_master(password).map_err(|_| AgentError::Vault("恢复点主密码不正确或副本损坏".into()))?;
            point_cfg.verify_mac(&*key).map_err(|e| AgentError::Vault(e.to_string()))?;
            Some(key)
        };
        recover_restore_point_to_dir(
            &point,
            Path::new(target_dir),
            old_vmk.as_ref().unwrap_or(vmk),
            if same_generation { Some(current_json.as_path()) } else { None },
        )
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        // 旧代际可恢复，不能证明当前代际的备份已验证。
        if same_generation {
            if let Some(db) = self.db.as_ref() {
                let _ = mark_local_restore_verified(db.conn());
            }
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
        let previous_dir = self.vault_dir.clone();
        self.db = None;
        if let Err(e) = clone_vault_to_empty_dir(&self.vault_dir, Path::new(target_dir), vmk) {
            self.attach_database()?;
            return Err(AgentError::Vault(e.to_string()));
        }
        self.vault_dir = PathBuf::from(target_dir);
        if let Err(e) = crate::paths::persist_active_vault_dir(&self.vault_dir) {
            self.vault_dir = previous_dir;
            self.attach_database()?;
            return Err(AgentError::Vault(e.to_string()));
        }
        if let Err(e) = self.attach_database() {
            self.vault_dir = previous_dir;
            let _ = crate::paths::persist_active_vault_dir(&self.vault_dir);
            self.attach_database()?;
            return Err(e);
        }
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
        let new_recovery = match security_rebuild_in_dir(&self.vault_dir, password, recovery_key) {
            Ok(r) => r,
            Err(e) => {
                self.attach_database()?;
                return Err(AgentError::Vault(e.to_string()));
            }
        };
        // 工作库已切换，此后即使会话重建失败，也必须把新恢复密钥交付给用户。
        let refresh: Result<()> = (|| {
            let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
            let vmk = cfg.unlock_master(password).map_err(|e| AgentError::Vault(e.to_string()))?;
            cfg.verify_mac(&*vmk).map_err(|e| AgentError::Vault(e.to_string()))?;
            self.vmk = Some(vmk);
            self.attach_database()?;
            self.record_master_verification()
        })();
        if refresh.is_err() {
            self.lock();
            crate::diagnostics::error("vault_security_rebuild", "vault rebuilt but session refresh failed");
        }
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
        let data = credpivot_core::read_ovb_file(Path::new(ovb_path))
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        let (header, aad, ciphertext) =
            parse_ovb_with_aad(&data).map_err(|e| AgentError::Vault(e.to_string()))?;
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        if header.vault_id.to_string() != cfg.vault_id {
            return Err(AgentError::Vault("备份不属于当前保险库，未更新验证记录".into()));
        }
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
        if self.vmk.as_deref() != Some(&*_vmk) {
            return Err(AgentError::Vault("备份属于旧密钥代际，请为当前保险库重新导出备份".into()));
        }
        let _plain = credpivot_core::decrypt_snapshot(&_vmk, &header, &aad, &ciphertext)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        if let Some(db) = self.db.as_ref() {
            let _ = mark_ovb_decrypt_verified(db.conn());
        }
        Ok(())
    }
}
