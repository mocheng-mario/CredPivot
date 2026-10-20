use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MIN_COMPATIBLE_PROTOCOL: u32 = 1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    Ping,
    Status,
    /// 扩展「连接」：Vault 已解锁时要求先通过 extension gate（指纹/系统密码）。
    ExtensionConnect,
    /// App 内指纹通过后授予 Chrome 扩展短时访问（秒）。
    ExtensionGateGrant {
        #[serde(default = "default_extension_gate_ttl")]
        ttl_secs: u64,
    },
    Lock,
    UnlockPassword { password: String },
    UnlockTouchIdToken { token: String },
    SetTouchIdToken { token: String },
    CredentialSave {
        request_id: String,
        origin: String,
        username: String,
        password: String,
        #[serde(default)]
        display_name: String,
        #[serde(default)]
        connection_host: String,
        #[serde(default)]
        linked_totp_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
    },
    CredentialSuggest {
        origin: String,
    },
    CredentialFillPrepare {
        request_id: String,
        credential_id: String,
        origin: String,
        tab_id: u64,
        frame_id: i64,
        document_id: String,
    },
    CredentialFillConsume {
        request_id: String,
        frame_id: i64,
        document_id: String,
        #[serde(default)]
        origin: String,
    },
    CancelRequest { request_id: String },
    CredentialList {
        query: Option<String>,
        limit: Option<u32>,
    },
    CredentialGet { credential_id: String },
    CredentialUpdate {
        credential_id: String,
        expected_revision: String,
        origin: String,
        username: String,
        #[serde(default)]
        display_name: String,
        #[serde(default)]
        group_id: String,
        #[serde(default)]
        connection_host: String,
        #[serde(default)]
        linked_totp_id: String,
        password: Option<String>,
    },
    CredentialTrash { item_id: String },
    SecuritySummary,
    ImportBitwarden { json: String },
    TotpList,
    TotpCreate {
        issuer: String,
        account: String,
        secret_base32: String,
        #[serde(default)]
        group_id: Option<String>,
    },
    TotpCode { totp_id: String },
    TotpReveal { totp_id: String },
    CredentialGroupList { scope: String },
    CredentialGroupCreate { scope: String, name: String },
    CredentialGroupDelete { id: String },
    CredentialItemSetGroup { item_id: String, group_id: String },
    ServerProfileList,
    ServerProfileCreate {
        label: String,
        host: String,
        #[serde(default = "default_ssh_port")]
        port: u16,
        #[serde(default)]
        manual_username: String,
        #[serde(default)]
        linked_login_id: Option<String>,
        #[serde(default)]
        linked_totp_id: Option<String>,
        #[serde(default)]
        linked_ssh_key_id: Option<String>,
        #[serde(default)]
        group_id: Option<String>,
    },
    ServerProfileUpdate {
        id: String,
        expected_revision: String,
        label: String,
        host: String,
        #[serde(default = "default_ssh_port")]
        port: u16,
        #[serde(default)]
        manual_username: String,
        #[serde(default)]
        linked_login_id: String,
        #[serde(default)]
        linked_totp_id: String,
        #[serde(default)]
        linked_ssh_key_id: String,
        #[serde(default)]
        group_id: String,
    },
    SshKeyList,
    SshKeyGenerate {
        label: String,
        set_default: Option<bool>,
        #[serde(default)]
        group_id: Option<String>,
    },
    /// 将 CredPivot SSH Agent 当前身份切换为指定库内密钥。
    SshSelectKey { key_id: String },
    /// App 内一键 SSH：登记短时会话，供 askpass 按提示取密（不落盘）。
    SshSessionPrepare {
        host: String,
        #[serde(default = "default_ssh_port")]
        port: u16,
        user: String,
        login_credential_id: String,
        #[serde(default)]
        totp_id: Option<String>,
    },
    /// 仅 credpivot-askpass 经 Unix IPC 调用。
    SshAskpass {
        session_id: String,
        #[serde(default)]
        prompt: String,
        /// expect 等调用方强制取密类型：`password` | `otp`（不依赖提示文案）。
        #[serde(default)]
        force_kind: Option<String>,
    },
    VaultCreate { password: String },
    VaultChangePassword {
        old_password: String,
        new_password: String,
    },
    VaultExportOvb {
        output_path: String,
        password: String,
    },
    VaultRecoverOvb {
        ovb_path: String,
        target_dir: String,
        password: Option<String>,
        recovery_key: Option<String>,
    },
    /// 锁定状态下切换本地工作库目录（须含 vault.json）。
    VaultOpenDir { path: String },
    RecoveryCodesList,
    RecoveryCodesCreate {
        service_name: String,
        codes: Vec<String>,
    },
    RecoveryCodesUpdate {
        id: String,
        expected_revision: String,
        service_name: String,
        codes: Vec<String>,
    },
    RestorePointsList,
    RestorePointRecover {
        created_at_ms: i64,
        target_dir: String,
    },
    VaultMigrate { target_dir: String },
    VaultSecurityRebuild {
        password: String,
        recovery_key: String,
    },
    BackupStatus,
    VaultVerifyOvb {
        ovb_path: String,
        password: String,
    },
    VaultVerifyRecoveryKey { recovery_key: String },
    DiagnosticLogTail {
        #[serde(default = "default_log_tail_lines")]
        max_lines: usize,
    },
}

fn default_log_tail_lines() -> usize {
    400
}

fn default_ssh_port() -> u16 {
    22
}

fn default_extension_gate_ttl() -> u64 {
    300
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentResponse {
    Ok {
        protocol_version: u32,
        payload: Value,
    },
    Err {
        protocol_version: u32,
        code: String,
        message: String,
    },
}

impl AgentResponse {
    pub fn ok(payload: Value) -> Self {
        Self::Ok {
            protocol_version: PROTOCOL_VERSION,
            payload,
        }
    }

    pub fn err(code: &str, message: impl Into<String>) -> Self {
        let message = message.into();
        crate::diagnostics::error("agent", format!("code={code} {message}"));
        Self::Err {
            protocol_version: PROTOCOL_VERSION,
            code: code.into(),
            message,
        }
    }
}
