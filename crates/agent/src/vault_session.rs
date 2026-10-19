use crate::error::{AgentError, Result};
use base64::Engine;
use credpivot_core::{
    bootstrap_vault_dir, change_master_password_in_dir, export_ovb_from_dir, read_vault_json,
    recover_ovb_to_dir, RecoveryUnlock, VMK_LEN,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// 进程内 Vault 会话：M1 加密库 + M0 演示凭据/SSH（业务入库在 M2）。
#[derive(Debug)]
pub struct VaultSession {
    pub vault_dir: PathBuf,
    pub vmk: Option<Zeroizing<[u8; VMK_LEN]>>,
    pub unlocked: bool,
    pub touch_id_wrapped_token: Option<Vec<u8>>,
    pub credentials: HashMap<String, FakeCredential>,
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
            unlocked: false,
            touch_id_wrapped_token: None,
            credentials: HashMap::new(),
            ssh_signing_key: signing_key,
            idle_timeout: Duration::from_secs(5 * 60),
            last_activity: Instant::now(),
        }
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
        Ok(())
    }

    pub fn vault_status_json(&self) -> serde_json::Value {
        let mut out = serde_json::json!({
            "format": "m1",
            "vault_exists": self.vault_exists(),
            "vault_path": self.vault_dir.to_string_lossy(),
            "unlocked": self.unlocked,
            "idle_timeout_sec": self.idle_timeout.as_secs(),
            "credential_count": self.credentials.len(),
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
        self.unlocked = false;
        self.vmk = None;
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
        self.unlocked = true;
        self.touch_activity();
        Ok(())
    }

    pub fn unlock_touch_id_token(&mut self, token: &[u8]) -> bool {
        if self.touch_id_wrapped_token.as_deref() == Some(token) && self.vault_exists() {
            // M1：Touch ID 仍为操作门槛（非 VMK 绑定）；扩展/SSH 演示可在无 VMK 时工作。
            self.unlocked = true;
            self.touch_activity();
            return true;
        }
        false
    }

    pub fn change_password(&mut self, old: &str, new: &str) -> Result<()> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        change_master_password_in_dir(&self.vault_dir, old, new)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        let cfg = read_vault_json(&self.vault_dir).map_err(|e| AgentError::Vault(e.to_string()))?;
        let vmk = cfg
            .unlock_master(new)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        cfg.verify_mac(&*vmk).map_err(|e| AgentError::Vault(e.to_string()))?;
        self.vmk = Some(vmk);
        Ok(())
    }

    pub fn export_ovb(&self, output_path: &str, password: &str) -> Result<()> {
        if !self.unlocked {
            return Err(AgentError::Locked);
        }
        let bytes = export_ovb_from_dir(&self.vault_dir, password)
            .map_err(|e| AgentError::Vault(e.to_string()))?;
        std::fs::write(output_path, bytes).map_err(AgentError::from)?;
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
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        format!("ssh-ed25519 {b64} credpivot-m1")
    }

    pub fn save_credential(&mut self, origin: &str, username: &str, password: &str) -> FakeCredential {
        let id = uuid::Uuid::new_v4().to_string();
        let cred = FakeCredential {
            id,
            origin: origin.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        };
        self.credentials.insert(cred.id.clone(), cred.clone());
        cred
    }

    pub fn suggest_for_origin(&self, origin: &str) -> Vec<FakeCredential> {
        self.credentials
            .values()
            .filter(|c| c.origin == origin)
            .cloned()
            .collect()
    }
}
