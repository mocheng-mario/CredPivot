use crate::crypto::{random_bytes, VMK_LEN};
use crate::error::{CoreError, Result};

const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTUVWXYZ";

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for b in data {
        crc ^= u16::from(*b) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

fn encode_base32(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

fn decode_base32(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for ch in s.chars() {
        let v = ALPHABET
            .iter()
            .position(|&c| c as char == ch)
            .ok_or_else(|| CoreError::format("invalid recovery key character"))?;
        buffer = (buffer << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

/// 生成 256-bit 恢复秘密及人类可读串（带 CRC16 校验）。
pub fn generate() -> (Vec<u8>, String) {
    let secret = random_bytes(VMK_LEN);
    let display = format_display(&secret);
    (secret, display)
}

pub fn format_display(secret: &[u8]) -> String {
    let payload = encode_base32(secret);
    let crc = crc16_ccitt(payload.as_bytes());
    let check = format!("{:04X}", crc);
    let mut groups = Vec::new();
    let chars: Vec<char> = payload.chars().collect();
    for chunk in chars.chunks(5) {
        groups.push(chunk.iter().collect::<String>());
    }
    format!("{}-{}", groups.join("-"), check)
}

pub fn parse_display(s: &str) -> Result<Vec<u8>> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() < 2 {
        return Err(CoreError::format("recovery key too short"));
    }
    let check = parts.last().unwrap();
    if check.len() != 4 {
        return Err(CoreError::format("bad recovery checksum"));
    }
    let payload = parts[..parts.len() - 1].join("");
    let expected = format!("{:04X}", crc16_ccitt(payload.as_bytes()));
    if expected != *check {
        return Err(CoreError::format("recovery checksum mismatch"));
    }
    let bytes = decode_base32(&payload)?;
    if bytes.len() != VMK_LEN {
        return Err(CoreError::format("recovery secret length"));
    }
    Ok(bytes)
}
