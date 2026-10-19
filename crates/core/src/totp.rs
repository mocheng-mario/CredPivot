use crate::error::{CoreError, Result};
use totp_rs::{Algorithm, Secret, TOTP};

pub fn totp_code_now(secret_base32: &str) -> Result<String> {
    let secret = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| CoreError::format(e.to_string()))?;
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        None,
        "".to_string(),
    )
    .map_err(|e| CoreError::format(e.to_string()))?;
    Ok(totp.generate_current().map_err(|e| CoreError::format(e.to_string()))?)
}
