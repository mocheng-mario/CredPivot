//! 不复用 Core 的 OVB1 结构检查（M1-9 独立解析路径）。

const MAX_FILE: usize = 256 * 1024 * 1024;
const MAX_SLOTS: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum StructureError {
    TooLarge,
    TooShort,
    BadMagic,
    BadVersion,
    SlotsTooLarge,
    Truncated,
}

pub struct ParsedLayout {
    pub vault_id: [u8; 16],
    pub archive_id: [u8; 32],
    pub ciphertext_len: u32,
    pub total_len: usize,
}

pub fn parse_layout(data: &[u8]) -> Result<ParsedLayout, StructureError> {
    if data.len() > MAX_FILE {
        return Err(StructureError::TooLarge);
    }
    if data.len() < 71 {
        return Err(StructureError::TooShort);
    }
    if &data[0..4] != b"OVB1" {
        return Err(StructureError::BadMagic);
    }
    if data[4] != 1 {
        return Err(StructureError::BadVersion);
    }
    let slots_len = u32::from_be_bytes(data[67..71].try_into().unwrap()) as usize;
    if slots_len > MAX_SLOTS {
        return Err(StructureError::SlotsTooLarge);
    }
    let slots_end = 71 + slots_len;
    if data.len() < slots_end + 4 {
        return Err(StructureError::Truncated);
    }
    let ct_len = u32::from_be_bytes(data[slots_end..slots_end + 4].try_into().unwrap());
    if data.len() < slots_end + 4 + ct_len as usize {
        return Err(StructureError::Truncated);
    }
    Ok(ParsedLayout {
        vault_id: data[6..22].try_into().unwrap(),
        archive_id: data[22..54].try_into().unwrap(),
        ciphertext_len: ct_len,
        total_len: data.len(),
    })
}
