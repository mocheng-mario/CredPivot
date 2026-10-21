use crate::error::{CoreError, Result};
use totp_rs::{Algorithm, Secret, TOTP};

/// 从 Base32 或完整 `otpauth://` URI 生成当前 6 位 TOTP（SHA1 / 30s）。
pub fn totp_code_now(secret_or_uri: &str) -> Result<String> {
    let totp = build_totp(secret_or_uri)?;
    Ok(totp
        .generate_current()
        .map_err(|e| CoreError::format(e.to_string()))?)
}

/// 由发行方、账号与入库参数生成 `otpauth://` URI。
pub fn build_otpauth_uri_from_params(
    issuer: &str,
    account: &str,
    params: &TotpStoredParams,
) -> Result<String> {
    let secret = params.secret_base32.clone();
    let alg = algorithm_name(params.algorithm);
    let iss = issuer.trim();
    let acc = account.trim();
    let label = if iss.is_empty() {
        encode_otpauth_path_component(acc)
    } else if acc.is_empty() {
        encode_otpauth_path_component(iss)
    } else {
        format!(
            "{}:{}",
            encode_otpauth_path_component(iss),
            encode_otpauth_path_component(acc)
        )
    };
    let issuer_q = encode_otpauth_query_value(iss);
    Ok(format!(
        "otpauth://totp/{label}?secret={secret}&issuer={issuer_q}&algorithm={alg}&digits={}&period={}",
        params.digits,
        params.period
    ))
}

/// 由发行方、账号与 Base32 密钥生成标准 `otpauth://` URI（SHA1 / 6 / 30s）。
pub fn build_otpauth_uri(issuer: &str, account: &str, secret_base32: &str) -> Result<String> {
    let params = totp_params_for_storage(secret_base32)?;
    build_otpauth_uri_from_params(issuer, account, &params)
}

fn encode_otpauth_path_component(s: &str) -> String {
    percent_encode(s)
}

fn encode_otpauth_query_value(s: &str) -> String {
    percent_encode(s)
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// 入库参数：密钥与算法/位数/周期一并保存。
#[derive(Debug, Clone)]
pub struct TotpStoredParams {
    pub secret_base32: String,
    pub algorithm: Algorithm,
    pub digits: usize,
    pub period: u64,
}

/// 入库前规范化：从 URI 或 Base32 提取完整 TOTP 参数。
pub fn validate_totp_stored_params(params: &TotpStoredParams) -> Result<()> {
    if params.period == 0 || params.period > 86400 {
        return Err(CoreError::format("TOTP period 须在 1–86400 秒之间"));
    }
    if params.digits < 6 || params.digits > 8 {
        return Err(CoreError::format("TOTP digits 须在 6–8 之间"));
    }
    Ok(())
}

pub fn totp_params_for_storage(input: &str) -> Result<TotpStoredParams> {
    let trimmed = input.trim();
    if trimmed.to_lowercase().starts_with("otpauth://") {
        if !trimmed.to_lowercase().starts_with("otpauth://totp/") { return Err(CoreError::format("仅支持 TOTP URI")); }
        let secret = extract_secret_from_otpauth(trimmed)?;
        validate_base32_secret(&secret)?;
        let mut values = std::collections::HashMap::new();
        for pair in trimmed.split_once('?').map(|(_,q)|q).unwrap_or_default().split('&') {
            if let Some((key,value))=pair.split_once('=') {
                if values.insert(key,url_decode_component(value)).is_some() { return Err(CoreError::format("TOTP 参数重复")); }
            }
        }
        // 短密钥 URI 也必须保留显式参数，不能在解析失败时静默回退成 SHA1 / 6 / 30。
        let params = TotpStoredParams {
            secret_base32: normalize_base32(&secret),
            algorithm: algorithm_from_name(values.get("algorithm").map(String::as_str).unwrap_or("SHA1"))?,
            digits: values.get("digits").map(|v|v.parse()).transpose().map_err(|_|CoreError::format("TOTP 位数无效"))?.unwrap_or(6),
            period: values.get("period").map(|v|v.parse()).transpose().map_err(|_|CoreError::format("TOTP 周期无效"))?.unwrap_or(30),
        };
        validate_totp_stored_params(&params)?;
        return Ok(params);
    }
    validate_base32_secret(trimmed)?;
    let params = TotpStoredParams {
        secret_base32: normalize_base32(trimmed),
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
    };
    validate_totp_stored_params(&params)?;
    Ok(params)
}

/// 入库前规范化：只保留 Base32 密钥（兼容旧调用）。
pub fn normalize_totp_secret_for_storage(input: &str) -> Result<String> {
    Ok(totp_params_for_storage(input)?.secret_base32)
}

pub fn totp_code_from_params(params: &TotpStoredParams) -> Result<String> {
    totp_code_at(params, (crate::repo::now_ms().max(0) as u64) / 1000)
}
pub(crate) fn totp_code_at(params: &TotpStoredParams, unix_seconds: u64) -> Result<String> {
    validate_totp_stored_params(params)?;
    let secret = Secret::Encoded(params.secret_base32.clone())
        .to_bytes()
        .map_err(|e| CoreError::format(e.to_string()))?;
    let totp = TOTP::new_unchecked(
        params.algorithm,
        params.digits,
        1,
        params.period,
        secret,
        None,
        "".to_string(),
    );
    Ok(totp.generate(unix_seconds))
}

pub fn algorithm_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::SHA1 => "SHA1",
        Algorithm::SHA256 => "SHA256",
        Algorithm::SHA512 => "SHA512",
    }
}

pub fn algorithm_from_name(name: &str) -> Result<Algorithm> {
    match name.to_uppercase().as_str() {
        "SHA1" => Ok(Algorithm::SHA1),
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA512" => Ok(Algorithm::SHA512),
        other => Err(CoreError::format(format!("unsupported TOTP algorithm: {other}"))),
    }
}

fn validate_base32_secret(raw: &str) -> Result<()> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(CoreError::format("TOTP 密钥为空"));
    }
    if t.contains('{') || t.contains('}') {
        return Err(CoreError::format(
            "密钥无效：请填写真实 Base32 密钥，不要使用模板占位符（如 {secret}）",
        ));
    }
    Ok(())
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
        .ok_or_else(|| CoreError::format("otpauth URI 缺少查询参数"))?;
    for pair in q.split('&') {
        let mut kv = pair.splitn(2, '=');
        if kv.next() == Some("secret") {
            if let Some(v) = kv.next() {
                return Ok(url_decode_component(v));
            }
        }
    }
    Err(CoreError::format("otpauth URI 缺少 secret 参数"))
}

fn url_decode_component(s: &str) -> String {
    let mut out = String::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(
                &s[i + 1..i + 3],
                16,
            ) {
                if v.is_ascii() {
                    out.push(char::from(v));
                }
                i += 3;
                continue;
            }
        }
        let b = bytes[i];
        if b.is_ascii() {
            out.push(char::from(b));
        }
        i += 1;
    }
    out
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

    #[test]
    fn build_otpauth_roundtrip() {
        let uri = build_otpauth_uri("TestApp", "test@example.com", "JBSWY3DPEHPK3PXP").expect("uri");
        assert!(uri.starts_with("otpauth://totp/"));
        let c = totp_code_now(&uri).expect("code");
        assert_eq!(c.len(), 6);
    }
}
