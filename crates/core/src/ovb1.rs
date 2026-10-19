use crate::crypto::{
    aes_gcm_decrypt, aes_gcm_encrypt, derive_ovb_snapshot_key, random_bytes, VMK_LEN,
};
use crate::error::{CoreError, Result};
use crate::key_slot::KeySlot;
use crate::limits::{MAX_HEADER_SLOTS_BYTES, MAX_OVB_FILE_BYTES};
use uuid::Uuid;

pub const OVB_MAGIC: &[u8; 4] = b"OVB1";

pub struct OvbHeader {
    pub vault_id: Uuid,
    pub archive_id: [u8; 32],
    pub nonce: [u8; 12],
    pub slots: Vec<KeySlot>,
    pub ciphertext_len: u32,
}

pub fn build_ovb_file(
    vmk: &[u8; VMK_LEN],
    vault_id: &Uuid,
    slots: Vec<KeySlot>,
    snapshot_plaintext: &[u8],
) -> Result<Vec<u8>> {
    if slots.len() > crate::limits::MAX_KEY_SLOTS {
        return Err(CoreError::limit("slots"));
    }
    let archive_id: [u8; 32] = random_bytes(32).try_into().unwrap();
    let nonce: [u8; 12] = random_bytes(12).try_into().unwrap();
    let slots_bytes = encode_slots(&slots)?;
    if slots_bytes.len() > MAX_HEADER_SLOTS_BYTES {
        return Err(CoreError::limit("header slots"));
    }

    let mut header = Vec::new();
    header.extend_from_slice(OVB_MAGIC);
    header.push(1); // major
    header.push(0); // minor
    header.extend_from_slice(vault_id.as_bytes());
    header.extend_from_slice(&archive_id);
    header.push(1); // cipher aes-256-gcm
    header.extend_from_slice(&nonce);
    header.extend_from_slice(&(slots_bytes.len() as u32).to_be_bytes());
    header.extend_from_slice(&slots_bytes);
    let aad = header.clone();
    let key = derive_ovb_snapshot_key(vmk, vault_id.as_bytes(), &archive_id);
    let ciphertext = aes_gcm_encrypt(&key, &nonce, &aad, snapshot_plaintext)?;
    header.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    header.extend_from_slice(&ciphertext);
    if header.len() as u64 > MAX_OVB_FILE_BYTES {
        return Err(CoreError::limit("ovb file"));
    }
    Ok(header)
}

pub fn parse_ovb_file(data: &[u8]) -> Result<(OvbHeader, Vec<u8>)> {
    if data.len() as u64 > MAX_OVB_FILE_BYTES {
        return Err(CoreError::limit("ovb file"));
    }
    if data.len() < 71 {
        return Err(CoreError::format("ovb short"));
    }
    if &data[0..4] != OVB_MAGIC {
        return Err(CoreError::format("ovb magic"));
    }
    if data[4] != 1 {
        return Err(CoreError::format("ovb version"));
    }
    let vault_id = Uuid::from_bytes(data[6..22].try_into().unwrap());
    let archive_id: [u8; 32] = data[22..54].try_into().unwrap();
    let nonce: [u8; 12] = data[55..67].try_into().unwrap();
    let slots_len = u32::from_be_bytes(data[67..71].try_into().unwrap()) as usize;
    if slots_len > MAX_HEADER_SLOTS_BYTES {
        return Err(CoreError::limit("header slots"));
    }
    let slots_end = 71 + slots_len;
    if data.len() < slots_end + 4 {
        return Err(CoreError::format("ovb truncated"));
    }
    let slots = decode_slots(&data[71..slots_end])?;
    let ct_len = u32::from_be_bytes(data[slots_end..slots_end + 4].try_into().unwrap());
    let ct_start = slots_end + 4;
    if data.len() < ct_start + ct_len as usize {
        return Err(CoreError::format("ciphertext truncated"));
    }
    let ciphertext = data[ct_start..ct_start + ct_len as usize].to_vec();
    Ok((
        OvbHeader {
            vault_id,
            archive_id,
            nonce,
            slots,
            ciphertext_len: ct_len,
        },
        ciphertext,
    ))
}

pub fn decrypt_snapshot(
    vmk: &[u8; VMK_LEN],
    header: &OvbHeader,
    header_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key = derive_ovb_snapshot_key(vmk, header.vault_id.as_bytes(), &header.archive_id);
    aes_gcm_decrypt(&key, &header.nonce, header_bytes, ciphertext)
}

fn encode_slots(slots: &[KeySlot]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(slots).map_err(|e| CoreError::format(e.to_string()))?;
    Ok(json)
}

fn decode_slots(bytes: &[u8]) -> Result<Vec<KeySlot>> {
    let slots: Vec<KeySlot> = serde_json::from_slice(bytes).map_err(|e| CoreError::format(e.to_string()))?;
    Ok(slots)
}

/// 解析时重建 AAD（至 slots 结束）。
pub fn header_aad(data: &[u8], slots_end: usize) -> Result<Vec<u8>> {
    if slots_end > data.len() {
        return Err(CoreError::format("aad"));
    }
    Ok(data[..slots_end].to_vec())
}

pub fn parse_ovb_with_aad(data: &[u8]) -> Result<(OvbHeader, Vec<u8>, Vec<u8>)> {
    let (header, ciphertext) = parse_ovb_file(data)?;
    let slots_len = u32::from_be_bytes(data[67..71].try_into().unwrap()) as usize;
    let slots_end = 71 + slots_len;
    let aad = header_aad(data, slots_end)?;
    Ok((header, aad, ciphertext))
}
