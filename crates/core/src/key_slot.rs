use crate::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_master_kek, derive_recovery_kek, random_bytes,
    wrap_vmk_slot_aad, NONCE_LEN, SALT_LEN, VMK_LEN,
};
use crate::error::{CoreError, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const DEFAULT_ARGON_MEMORY_KIB: u32 = 65536;
pub const DEFAULT_ARGON_ITERS: u32 = 3;
pub const DEFAULT_ARGON_PARALLELISM: u32 = 4;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SlotType {
    MasterPassword,
    RecoveryKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySlot {
    pub slot_id: Uuid,
    #[serde(rename = "type")]
    pub slot_type: SlotType,
    pub kdf: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    pub salt: String,
    pub nonce: String,
    pub wrapped_vmk: String,
}

impl KeySlot {
    pub fn create_master_password(
        vault_id: &str,
        format_major: u8,
        password: &str,
        vmk: &[u8; VMK_LEN],
    ) -> Result<Self> {
        let salt = random_bytes(SALT_LEN);
        let nonce_bytes = random_bytes(NONCE_LEN);
        let nonce = nonce_bytes.as_slice();
        let kek = derive_master_kek(
            password.as_bytes(),
            &salt,
            DEFAULT_ARGON_MEMORY_KIB,
            DEFAULT_ARGON_ITERS,
            DEFAULT_ARGON_PARALLELISM,
        )?;
        let slot_id = Uuid::new_v4();
        let aad = wrap_vmk_slot_aad(
            "CPVC1-AAD",
            vault_id,
            &slot_id.to_string(),
            "master-password",
            format_major,
        );
        let wrapped = aes_gcm_encrypt(&*kek, nonce.try_into().unwrap(), &aad, vmk)?;
        Ok(Self {
            slot_id,
            slot_type: SlotType::MasterPassword,
            kdf: "argon2id".into(),
            memory_kib: Some(DEFAULT_ARGON_MEMORY_KIB),
            iterations: Some(DEFAULT_ARGON_ITERS),
            parallelism: Some(DEFAULT_ARGON_PARALLELISM),
            salt: URL_SAFE_NO_PAD.encode(salt),
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            wrapped_vmk: URL_SAFE_NO_PAD.encode(wrapped),
        })
    }

    pub fn create_recovery(
        vault_id: &str,
        format_major: u8,
        recovery_secret: &[u8; VMK_LEN],
        vmk: &[u8; VMK_LEN],
    ) -> Result<Self> {
        let salt = random_bytes(SALT_LEN);
        let nonce_bytes = random_bytes(NONCE_LEN);
        let vault_uuid = Uuid::parse_str(vault_id).map_err(|_| CoreError::format("vault_id"))?;
        let kek = derive_recovery_kek(recovery_secret, &salt, vault_uuid.as_bytes());
        let slot_id = Uuid::new_v4();
        let aad = wrap_vmk_slot_aad(
            "CPVC1-AAD",
            vault_id,
            &slot_id.to_string(),
            "recovery-key",
            format_major,
        );
        let wrapped = aes_gcm_encrypt(&kek, nonce_bytes.as_slice().try_into().unwrap(), &aad, vmk)?;
        Ok(Self {
            slot_id,
            slot_type: SlotType::RecoveryKey,
            kdf: "hkdf-sha256".into(),
            memory_kib: None,
            iterations: None,
            parallelism: None,
            salt: URL_SAFE_NO_PAD.encode(salt),
            nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
            wrapped_vmk: URL_SAFE_NO_PAD.encode(wrapped),
        })
    }

    pub fn unwrap_vmk(&self, vault_id: &str, format_major: u8, secret: &[u8]) -> Result<Zeroizing<[u8; VMK_LEN]>> {
        let salt = URL_SAFE_NO_PAD
            .decode(&self.salt)
            .map_err(|_| CoreError::format("salt"))?;
        let nonce = URL_SAFE_NO_PAD
            .decode(&self.nonce)
            .map_err(|_| CoreError::format("nonce"))?;
        if nonce.len() != NONCE_LEN {
            return Err(CoreError::format("nonce len"));
        }
        let wrapped = URL_SAFE_NO_PAD
            .decode(&self.wrapped_vmk)
            .map_err(|_| CoreError::format("wrapped"))?;
        let aad = wrap_vmk_slot_aad(
            "CPVC1-AAD",
            vault_id,
            &self.slot_id.to_string(),
            match self.slot_type {
                SlotType::MasterPassword => "master-password",
                SlotType::RecoveryKey => "recovery-key",
            },
            format_major,
        );
        let kek: Zeroizing<[u8; 32]> = match self.slot_type {
            SlotType::MasterPassword => {
                let mem = self.memory_kib.unwrap_or(DEFAULT_ARGON_MEMORY_KIB);
                let it = self.iterations.unwrap_or(DEFAULT_ARGON_ITERS);
                let par = self.parallelism.unwrap_or(DEFAULT_ARGON_PARALLELISM);
                derive_master_kek(secret, &salt, mem, it, par)?
            }
            SlotType::RecoveryKey => {
                if secret.len() != VMK_LEN {
                    return Err(CoreError::BadSecret);
                }
                let mut sec = [0u8; VMK_LEN];
                sec.copy_from_slice(secret);
                let vault_uuid = Uuid::parse_str(vault_id).map_err(|_| CoreError::format("vault_id"))?;
                Zeroizing::new(derive_recovery_kek(&sec, &salt, vault_uuid.as_bytes()))
            }
        };
        let plain = aes_gcm_decrypt(&*kek, nonce.as_slice().try_into().unwrap(), &aad, &wrapped)?;
        if plain.len() != VMK_LEN {
            return Err(CoreError::Auth);
        }
        let mut vmk = Zeroizing::new([0u8; VMK_LEN]);
        vmk.copy_from_slice(&plain);
        Ok(vmk)
    }
}
