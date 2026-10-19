use crate::canonical_json::canonical_json_bytes;
use crate::crypto::{derive_config_mac_key, hmac_sha256, VMK_LEN};
use crate::error::{CoreError, Result};
use crate::key_slot::{KeySlot, SlotType};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const MAGIC: &str = "CPVC1";
pub const FORMAT_MAJOR: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpvcConfig {
    pub magic: String,
    pub format_major: u8,
    pub vault_id: String,
    pub control_id: String,
    pub control_revision: u64,
    pub key_slots: Vec<KeySlot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_mac: Option<String>,
}

impl CpvcConfig {
    pub fn without_mac(&self) -> Value {
        json!({
            "magic": self.magic,
            "format_major": self.format_major,
            "vault_id": self.vault_id,
            "control_id": self.control_id,
            "control_revision": self.control_revision,
            "key_slots": self.key_slots,
        })
    }

    pub fn sign(&mut self, vmk: &[u8; VMK_LEN]) -> Result<()> {
        let vault_uuid = Uuid::parse_str(&self.vault_id).map_err(|_| CoreError::format("vault_id"))?;
        let mac_key = derive_config_mac_key(vmk, vault_uuid.as_bytes());
        let body = self.without_mac();
        let mac = hmac_sha256(&mac_key, &canonical_json_bytes(&body));
        self.control_mac = Some(URL_SAFE_NO_PAD.encode(mac));
        Ok(())
    }

    pub fn verify_mac(&self, vmk: &[u8; VMK_LEN]) -> Result<()> {
        let mac_b64 = self
            .control_mac
            .as_ref()
            .ok_or_else(|| CoreError::format("missing control_mac"))?;
        let got = URL_SAFE_NO_PAD
            .decode(mac_b64)
            .map_err(|_| CoreError::format("control_mac b64"))?;
        let vault_uuid = Uuid::parse_str(&self.vault_id).map_err(|_| CoreError::format("vault_id"))?;
        let mac_key = derive_config_mac_key(vmk, vault_uuid.as_bytes());
        let body = self.without_mac();
        let expect = hmac_sha256(&mac_key, &canonical_json_bytes(&body));
        if got.as_slice() != expect {
            return Err(CoreError::Auth);
        }
        Ok(())
    }

    pub fn unlock_master(&self, password: &str) -> Result<Zeroizing<[u8; VMK_LEN]>> {
        let slot = self
            .key_slots
            .iter()
            .find(|s| s.slot_type == SlotType::MasterPassword)
            .ok_or_else(|| CoreError::format("no master slot"))?;
        slot.unwrap_vmk(&self.vault_id, self.format_major, password.as_bytes())
    }

    pub fn unlock_recovery(&self, recovery_secret: &[u8; VMK_LEN]) -> Result<Zeroizing<[u8; VMK_LEN]>> {
        let slot = self
            .key_slots
            .iter()
            .find(|s| s.slot_type == SlotType::RecoveryKey)
            .ok_or_else(|| CoreError::format("no recovery slot"))?;
        slot.unwrap_vmk(&self.vault_id, self.format_major, recovery_secret)
    }
}

pub fn parse_config(json_str: &str) -> Result<CpvcConfig> {
    let cfg: CpvcConfig = serde_json::from_str(json_str).map_err(|e| CoreError::format(e.to_string()))?;
    if cfg.magic != MAGIC || cfg.format_major != FORMAT_MAJOR {
        return Err(CoreError::format("cpvc magic/version"));
    }
    if cfg.key_slots.len() > crate::limits::MAX_KEY_SLOTS {
        return Err(CoreError::limit("too many slots"));
    }
    Ok(cfg)
}

pub fn serialize_config(cfg: &CpvcConfig) -> Result<String> {
    serde_json::to_string_pretty(cfg).map_err(|e| CoreError::format(e.to_string()))
}
