use crate::error::{AgentError, Result};
use crate::vault_session::VaultSession;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SSH_SESSION_TTL_MS: u128 = 5 * 60 * 1000;
const MAX_PASSWORD_PROMPTS: u8 = 6;
const MAX_OTP_PROMPTS: u8 = 8;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshSessionGrant {
    pub session_id: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub login_credential_id: String,
    pub totp_id: Option<String>,
    pub expires_at_ms: u128,
    pub password_uses_left: u8,
    pub otp_uses_left: u8,
}

pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

pub fn purge_expired_sessions(map: &mut HashMap<String, SshSessionGrant>) {
    let now = now_ms();
    map.retain(|_, g| g.expires_at_ms > now);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AskpassKind {
    Password,
    Otp,
    Deny,
}

/// 根据 OpenSSH 提示分类；拒绝主机指纹确认等交互。
pub fn classify_askpass_prompt(prompt: &str) -> AskpassKind {
    let p = prompt.to_lowercase();
    if p.is_empty() {
        return AskpassKind::Password;
    }
    if looks_like_host_key_prompt(&p) {
        return AskpassKind::Deny;
    }
    if looks_like_yes_no(&p) {
        return AskpassKind::Deny;
    }
    if looks_like_passphrase(&p) {
        return AskpassKind::Deny;
    }
    if looks_like_otp(&p) {
        return AskpassKind::Otp;
    }
    if looks_like_password(&p) {
        return AskpassKind::Password;
    }
    AskpassKind::Deny
}

fn looks_like_host_key_prompt(p: &str) -> bool {
    p.contains("fingerprint")
        || p.contains("authenticity of host")
        || p.contains("host key")
        || p.contains("known_hosts")
}

fn looks_like_yes_no(p: &str) -> bool {
    p.contains("(yes/no")
        || p.contains("[yes/no")
        || p.trim_end().ends_with("?") && p.contains("continue connecting")
}

fn looks_like_passphrase(p: &str) -> bool {
    p.contains("passphrase") || p.contains("pass phrase")
}

/// MFA/OTP 提示关键词（须像输入提示，避免误匹配登录后 banner）。
fn looks_like_otp(p: &str) -> bool {
    let has_kw = p.contains("mfa") || p.contains("otp") || p.contains("2fa") || p.contains("验证码");
    if !has_kw {
        return false;
    }
    let promptish = p.contains("请输入")
        || p.contains("enter")
        || p.contains("verification code")
        || p.contains('：')
        || p.contains(':');
    has_kw && promptish
}

fn looks_like_password(p: &str) -> bool {
    p.contains("password")
        || p.contains("passwd")
        || p.contains("'s password")
        || p.contains("密码")
        || p.contains("口令")
}

pub fn prepare_session(
    map: &mut HashMap<String, SshSessionGrant>,
    host: &str,
    port: u16,
    user: &str,
    login_credential_id: &str,
    totp_id: Option<String>,
) -> String {
    purge_expired_sessions(map);
    let session_id = uuid::Uuid::new_v4().to_string();
    let now = now_ms();
    let grant = SshSessionGrant {
        session_id: session_id.clone(),
        host: host.trim().to_string(),
        port,
        user: user.trim().to_string(),
        login_credential_id: login_credential_id.trim().to_string(),
        totp_id: totp_id.filter(|s| !s.trim().is_empty()),
        expires_at_ms: now + SSH_SESSION_TTL_MS,
        password_uses_left: MAX_PASSWORD_PROMPTS,
        otp_uses_left: MAX_OTP_PROMPTS,
    };
    map.insert(session_id.clone(), grant);
    session_id
}

pub fn consume_askpass_secret(
    map: &mut HashMap<String, SshSessionGrant>,
    vault: &mut VaultSession,
    session_id: &str,
    prompt: &str,
    force_kind: Option<&str>,
) -> Result<String> {
    purge_expired_sessions(map);
    let grant = map
        .get_mut(session_id)
        .ok_or_else(|| AgentError::Protocol("unknown or expired ssh session".into()))?;
    if now_ms() > grant.expires_at_ms {
        map.remove(session_id);
        return Err(AgentError::Protocol("ssh session expired".into()));
    }
    let kind = match force_kind.map(|s| s.trim().to_lowercase()) {
        Some(k) if k == "password" => AskpassKind::Password,
        Some(k) if k == "otp" => AskpassKind::Otp,
        Some(_) => {
            return Err(AgentError::Protocol("invalid force_kind".into()));
        }
        None => classify_askpass_prompt(prompt),
    };
    let login_id = grant.login_credential_id.clone();
    let session_totp = grant.totp_id.clone();
    match kind {
        AskpassKind::Deny => Err(AgentError::Protocol(
            "prompt not allowed for automatic response".into(),
        )),
        AskpassKind::Password => {
            if grant.password_uses_left == 0 {
                return Err(AgentError::Protocol("password prompt budget exhausted".into()));
            }
            grant.password_uses_left -= 1;
            let cred = vault.get_credential(&login_id)?;
            let pw = cred.password;
            if pw.is_empty() {
                return Err(AgentError::Protocol("linked login password is empty".into()));
            }
            Ok(pw)
        }
        AskpassKind::Otp => {
            if grant.otp_uses_left == 0 {
                return Err(AgentError::Protocol("otp prompt budget exhausted".into()));
            }
            grant.otp_uses_left -= 1;
            let totp_id = session_totp.or(cred_totp_id(vault, &login_id)?);
            let id = totp_id
                .ok_or_else(|| AgentError::Protocol("no MFA configured for this session".into()))?;
            vault.totp_code(&id)
        }
    }
}

fn cred_totp_id(vault: &VaultSession, login_id: &str) -> Result<Option<String>> {
    let cred = vault.get_credential(login_id)?;
    Ok(cred.linked_totp_id.filter(|s| !s.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_host_key() {
        assert_eq!(
            classify_askpass_prompt("The authenticity of host 'x' can't be established."),
            AskpassKind::Deny
        );
    }

    #[test]
    fn password_prompt() {
        assert_eq!(
            classify_askpass_prompt("user@host's password:"),
            AskpassKind::Password
        );
    }

    #[test]
    fn otp_prompt() {
        assert_eq!(
            classify_askpass_prompt("Enter OTP code:"),
            AskpassKind::Otp
        );
    }

    #[test]
    fn otp_prompt_chinese_mfa() {
        assert_eq!(
            classify_askpass_prompt("请输入 MFA 验证码（第 1/3 次）："),
            AskpassKind::Otp
        );
    }

    #[test]
    fn otp_not_banner_noise() {
        assert_eq!(
            classify_askpass_prompt("Your account has 2FA enabled. Welcome!"),
            AskpassKind::Deny
        );
    }
}
