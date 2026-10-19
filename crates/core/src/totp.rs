use crate::error::{CoreError, Result};
use totp_rs::{Algorithm, Secret, TOTP};

/// 从 Base32 或完整 `otpauth://` URI 生成当前 6 位 TOTP（SHA1 / 30s）。
pub fn totp_code_now(secret_or_uri: &str) -> Result<String> {
    let totp = build_totp(secret_or_uri)?;
    Ok(totp
        .generate_current()
        .map_err(|e| CoreError::format(e.to_string()))?)
}

/// 入库前规范化：只保留 Base32 密钥（从 URI 提取或规范化粘贴内容）。
pub fn normalize_totp_secret_for_storage(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.to_lowercase().starts_with("otpauth://") {
        if let Ok(totp) = TOTP::from_url(trimmed) {
            return Ok(totp.get_secret_base32());
        }
        let secret = extract_secret_from_otpauth(trimmed)?;
        return Ok(normalize_base32(&secret));
    }
    Ok(normalize_base32(trimmed))
}

fn build_totp(secret_or_uri: &str) -> Result<TOTP> {
    let trimmed = secret_or_uri.trim();
    if trimmed.to_lowercase().starts_with("otpauth://") {
        if let Ok(totp) = TOTP::from_url(trimmed) {
            return Ok(totp);
        }
        let secret = extract_secret_from_otpauth(trimmed)?;
        return totp_from_base32(&secret);
    }
    totp_from_base32(trimmed)
}

fn extract_secret_from_otpauth(url: &str) -> Result<String> {
    let q = url
        .split('?')
        .nth(1)
        .ok_or_else(|| CoreError::format("otpauth missing query"))?;
    for pair in q.split('&') {
        let mut kv = pair.splitn(2, '=');
        if kv.next() == Some("secret") {
            if let Some(v) = kv.next() {
                return Ok(v.to_string());
            }
        }
    }
    Err(CoreError::format("otpauth missing secret"))
}

fn totp_from_base32(secret_base32: &str) -> Result<TOTP> {
    let normalized = normalize_base32(secret_base32);
    let secret = Secret::Encoded(normalized)
        .to_bytes()
        .map_err(|e| CoreError::format(e.to_string()))?;
    // RFC 6238 / Google Authenticator 常用 80-bit 密钥；totp-rs 的 `new` 要求 ≥128-bit。
    Ok(TOTP::new_unchecked(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        None,
        "".to_string(),
    ))
}

fn normalize_base32(s: &str) -> String {
    let mut t = s
        .trim()
        .replace([' ', '-', '\n', '\r'], "")
        .to_uppercase();
    let pad = (8 - t.len() % 8) % 8;
    t.push_str(&"=".repeat(pad));
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_test_secret_generates_six_digits() {
        let c = totp_code_now("JBSWY3DPEHPK3PXP").expect("code");
        assert_eq!(c.len(), 6);
        assert!(c.chars().all(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn otpauth_uri_from_user_example() {
        let url = "otpauth://totp/TestApp:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestApp&algorithm=SHA1&digits=6&period=30";
        let c = totp_code_now(url).expect("code from uri");
        assert_eq!(c.len(), 6);
        let stored = normalize_totp_secret_for_storage(url).expect("normalize");
        assert_eq!(stored, "JBSWY3DPEHPK3PXP");
    }
}
