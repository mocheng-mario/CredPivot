use crate::error::{CoreError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const VMK_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 32;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf
}

pub fn derive_master_kek(password: &[u8], salt: &[u8], memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Zeroizing<[u8; 32]>> {
    if memory_kib > crate::limits::MAX_ARGON2_MEMORY_KIB {
        return Err(CoreError::limit("argon2 memory too large"));
    }
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| CoreError::format(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| CoreError::BadSecret)?;
    Ok(out)
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| CoreError::format("hkdf expand failed"))?;
    Ok(okm)
}

pub fn derive_sqlcipher_key(vmk: &[u8; 32], vault_id_bytes: &[u8]) -> [u8; 32] {
    hkdf_sha256(vault_id_bytes, vmk, b"credpivot/local-db/v1").unwrap_or([0u8; 32])
}

pub fn derive_config_mac_key(vmk: &[u8; 32], vault_id_bytes: &[u8]) -> [u8; 32] {
    hkdf_sha256(vault_id_bytes, vmk, b"credpivot/config-mac/v1").unwrap_or([0u8; 32])
}

pub fn derive_ovb_snapshot_key(vmk: &[u8; 32], vault_id_bytes: &[u8], archive_id: &[u8; 32]) -> [u8; 32] {
    let mut info = Vec::from(b"credpivot/ovb-snapshot/v1");
    info.extend_from_slice(archive_id);
    hkdf_sha256(vault_id_bytes, vmk, &info).unwrap_or([0u8; 32])
}

pub fn derive_recovery_kek(recovery_secret: &[u8; 32], salt: &[u8], vault_id_bytes: &[u8]) -> [u8; 32] {
    let mut info = Vec::from(b"credpivot/recovery-kek/v1");
    info.extend_from_slice(vault_id_bytes);
    hkdf_sha256(salt, recovery_secret, &info).unwrap_or([0u8; 32])
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

pub fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::format("bad aes key"))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CoreError::Auth)
}

pub fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::format("bad aes key"))?;
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| CoreError::Auth)
}

pub fn wrap_vmk_slot_aad(prefix: &str, vault_id: &str, slot_id: &str, slot_type: &str, format_major: u8) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(prefix.as_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(slot_id.as_bytes());
    aad.extend_from_slice(slot_type.as_bytes());
    aad.push(format_major);
    aad
}
