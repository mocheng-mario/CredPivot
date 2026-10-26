use crate::error::{CoreError, Result};
use totp_rs::{Algorithm, Secret, TOTP};

/// 从 Base32 或完整 URI 生成 TOTP；URI 使用声明的算法、位数与周期。
pub fn totp_code_now(secret_or_uri: &str) -> Result<String> {
    totp_code_from_params(&totp_params_for_storage(secret_or_uri)?)
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
        if acc.is_empty() { "CredPivot:".into() } else { encode_otpauth_path_component(acc) }
    } else if acc.is_empty() {
        format!("{}:", encode_otpauth_path_component(iss))
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

/// 解析与保存使用同一入口，避免 App 展示和实际生成验证码使用不同参数。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ParsedTotpInput {
    pub secret_base32: String,
    pub algorithm: String,
    pub digits: usize,
    pub period: u64,
    pub issuer: String,
    pub account: String,
    pub label: String,
    pub suggested_website: Option<String>,
    pub extra_parameters: std::collections::BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

pub fn parse_totp_input(input: &str) -> Result<ParsedTotpInput> {
    let input = input.trim();
    if input.len() > 16384 { return Err(CoreError::limit("TOTP 输入过长")); }
    let mut parsed = ParsedTotpInput {
        secret_base32: String::new(), algorithm: "SHA1".into(), digits: 6, period: 30,
        issuer: String::new(), account: String::new(), label: String::new(),
        suggested_website: None, extra_parameters: Default::default(), warnings: Vec::new(),
    };
    if input.to_ascii_lowercase().starts_with("otpauth://") {
        if input.chars().any(char::is_control) { return Err(CoreError::format("TOTP URI 包含控制字符")); }
        let url = url::Url::parse(input).map_err(|_| CoreError::format("TOTP URI 无效"))?;
        if !url.host_str().is_some_and(|h| h.eq_ignore_ascii_case("totp")) {
            return Err(CoreError::format("仅支持基于时间的 TOTP；HOTP 计数器及其他 URI 类型尚不支持"));
        }
        if !url.username().is_empty() || url.password().is_some() || url.port().is_some() || url.fragment().is_some() {
            return Err(CoreError::format("TOTP URI 不允许用户信息、端口或片段"));
        }
        parsed.label = decode_component(url.path().strip_prefix('/').unwrap_or(url.path()), false)?;
        if parsed.label.is_empty() || parsed.label.len() > 1024 { return Err(CoreError::format("TOTP 标签为空或过长")); }
        let (label_issuer, account) = parsed.label.split_once(':').unwrap_or(("", &parsed.label));
        parsed.issuer = label_issuer.trim().into();
        parsed.account = account.trim().into();
        let mut values = std::collections::BTreeMap::new();
        let mut seen = std::collections::HashSet::new();
        for pair in url.query().unwrap_or_default().split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').ok_or_else(|| CoreError::format("TOTP 查询参数缺少等号"))?;
            let original_key = decode_component(key, true)?;
            let normalized = original_key.to_ascii_lowercase();
            if !seen.insert(normalized.clone()) { return Err(CoreError::format("TOTP 参数重复")); }
            let key = if matches!(normalized.as_str(),"secret"|"issuer"|"algorithm"|"digits"|"period"|"counter"|"t0"|"encoder"|"encoding") { normalized } else { original_key };
            let value = decode_component(value, true)?;
            if key.is_empty() || key.len() > 100 || value.len() > 4096 || values.len() >= 32 {
                return Err(CoreError::limit("TOTP 查询参数超出限制"));
            }
            if values.insert(key, value).is_some() { return Err(CoreError::format("TOTP 参数重复")); }
        }
        parsed.secret_base32 = values.remove("secret").ok_or_else(|| CoreError::format("TOTP URI 缺少 secret 参数"))?;
        if let Some(issuer) = values.remove("issuer") {
            if !parsed.issuer.is_empty() && !issuer.is_empty() && issuer.trim() != parsed.issuer {
                parsed.warnings.push("标签中的发行方与 issuer 不一致，已使用 issuer 参数，请核对。".into());
            }
            if !issuer.trim().is_empty() { parsed.issuer = issuer.trim().into(); }
        }
        if let Some(algorithm) = values.remove("algorithm") { parsed.algorithm = algorithm_name(algorithm_from_name(algorithm.trim())?).into(); }
        if let Some(digits) = values.remove("digits") { parsed.digits = digits.trim().parse().map_err(|_| CoreError::format("TOTP digits 无效"))?; }
        if let Some(period) = values.remove("period") { parsed.period = period.trim().parse().map_err(|_| CoreError::format("TOTP period 无效"))?; }
        if values.contains_key("counter") { return Err(CoreError::format("counter 属于 HOTP，不能作为 TOTP 保存")); }
        if values.get("t0").is_some_and(|v| v != "0") { return Err(CoreError::format("暂不支持非零 T0，不能忽略该参数生成验证码")); }
        if values.contains_key("encoder") || values.contains_key("encoding") {
            return Err(CoreError::format("暂不支持自定义 OTP 编码器，请使用标准数字 TOTP URI"));
        }
        if !values.is_empty() { parsed.warnings.push("附加参数将加密保留并随 URI 导出，不参与验证码计算，也不会下载图片或访问外部地址。".into()); }
        parsed.extra_parameters = values;
    } else {
        if input.contains("://") { return Err(CoreError::format("请输入 otpauth://totp/ URI 或 Base32 密钥")); }
        parsed.secret_base32 = input.into();
    }
    validate_base32_secret(&parsed.secret_base32)?;
    parsed.secret_base32 = normalize_base32(&parsed.secret_base32)?;
    validate_totp_stored_params(&TotpStoredParams {
        secret_base32: parsed.secret_base32.clone(), algorithm: algorithm_from_name(&parsed.algorithm)?,
        digits: parsed.digits, period: parsed.period,
    })?;
    if parsed.issuer.len() > 1024 || parsed.account.len() > 1024 { return Err(CoreError::limit("TOTP 发行方或账号过长")); }
    // issuer 仅作建议，用户确认后才成为浏览器的独立填充权限。
    if !parsed.issuer.is_empty() && !parsed.issuer.chars().any(char::is_whitespace) {
        let candidate = if parsed.issuer.contains("://") { parsed.issuer.clone() } else { format!("https://{}", parsed.issuer) };
        if let Ok(url) = url::Url::parse(&candidate) {
            if matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(|h| h.contains('.'))
                && url.username().is_empty() && url.password().is_none() && url.path() == "/"
                && url.query().is_none() && url.fragment().is_none() {
                parsed.suggested_website = Some(url.origin().ascii_serialization());
            }
        }
    }
    Ok(parsed)
}

pub fn totp_params_for_storage(input: &str) -> Result<TotpStoredParams> {
    let parsed = parse_totp_input(input)?;
    Ok(TotpStoredParams { secret_base32: parsed.secret_base32, algorithm: algorithm_from_name(&parsed.algorithm)?, digits: parsed.digits, period: parsed.period })
}

/// 严格百分号解码并保留 Unicode；不把畸形 UTF-8 静默替换成其他账号。
fn decode_component(value: &str, query: bool) -> Result<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let high = bytes.get(i + 1).and_then(|b| char::from(*b).to_digit(16));
                let low = bytes.get(i + 2).and_then(|b| char::from(*b).to_digit(16));
                let (Some(high), Some(low)) = (high, low) else { return Err(CoreError::format("TOTP URI 百分号编码无效")); };
                decoded.push((high * 16 + low) as u8); i += 3;
            }
            b'+' if query => { decoded.push(b' '); i += 1; }
            b => { decoded.push(b); i += 1; }
        }
    }
    let text = String::from_utf8(decoded).map_err(|_| CoreError::format("TOTP URI 不是有效 UTF-8"))?;
    if text.chars().any(char::is_control) { return Err(CoreError::format("TOTP 参数包含控制字符")); }
    Ok(text)
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
    let secret = decode_base32_secret(&params.secret_base32)?;
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
    match name.trim().to_uppercase().replace('-', "").as_str() {
        "SHA1" => Ok(Algorithm::SHA1),
        "SHA256" => Ok(Algorithm::SHA256),
        "SHA512" => Ok(Algorithm::SHA512),
        other => Err(CoreError::format(format!("unsupported TOTP algorithm: {other}"))),
    }
}

pub(crate) fn validate_base32_secret(raw: &str) -> Result<()> {
    decode_base32_secret(raw).map(|_| ())
}

fn decode_base32_secret(raw: &str) -> Result<Vec<u8>> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(CoreError::format("TOTP 密钥为空"));
    }
    if t.contains('{') || t.contains('}') {
        return Err(CoreError::format(
            "密钥无效：请填写真实 Base32 密钥，不要使用模板占位符（如 {secret}）",
        ));
    }
    let secret = Secret::Encoded(normalize_base32(t)?).to_bytes()
        .map_err(|_| CoreError::format("TOTP 密钥不是有效的 Base32"))?;
    if secret.is_empty() { return Err(CoreError::format("TOTP 密钥为空")); }
    Ok(secret)
}

fn normalize_base32(s: &str) -> Result<String> {
    let t = s
        .trim()
        .replace([' ', '-', '\n', '\r'], "")
        .to_uppercase();
    let unpadded = t.trim_end_matches('=');
    let padding = t.len() - unpadded.len();
    // totp-rs 使用无填充 Base32。不能给合法种子补 '=' 后再交给它解码。
    // 兼容正确的尾部填充，但内部 '=' 和错误的填充数量仍应被拒绝。
    if padding > 0 && (t.len() % 8 != 0 || !matches!(padding, 1 | 3 | 4 | 6)) {
        return Err(CoreError::format("TOTP 密钥不是有效的 Base32"));
    }
    Ok(unpadded.to_string())
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
