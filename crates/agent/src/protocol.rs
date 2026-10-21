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
    DiagnosticLogSetLevel { level: crate::diagnostics::LogLevel },
}

impl AgentRequest {
    /// 仅记录固定操作名，不序列化含密码、令牌或导入内容的请求。
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Status => "status",
            Self::ExtensionConnect => "extension_connect",
            Self::ExtensionGateGrant { .. } => "extension_gate_grant",
            Self::Lock => "lock",
            Self::UnlockPassword { .. } => "unlock_password",
            Self::UnlockTouchIdToken { .. } => "unlock_touch_id_token",
            Self::SetTouchIdToken { .. } => "set_touch_id_token",
            Self::CredentialSave { .. } => "credential_save",
            Self::CredentialSuggest { .. } => "credential_suggest",
            Self::CredentialFillPrepare { .. } => "credential_fill_prepare",
            Self::CredentialFillConsume { .. } => "credential_fill_consume",
            Self::CancelRequest { .. } => "cancel_request",
            Self::CredentialList { .. } => "credential_list",
            Self::CredentialGet { .. } => "credential_get",
            Self::CredentialUpdate { .. } => "credential_update",
            Self::CredentialTrash { .. } => "credential_trash",
            Self::SecuritySummary => "security_summary",
            Self::ImportBitwarden { .. } => "import_bitwarden",
            Self::TotpList => "totp_list",
            Self::TotpCreate { .. } => "totp_create",
            Self::TotpCode { .. } => "totp_code",
            Self::TotpReveal { .. } => "totp_reveal",
            Self::CredentialGroupList { .. } => "credential_group_list",
            Self::CredentialGroupCreate { .. } => "credential_group_create",
            Self::CredentialGroupDelete { .. } => "credential_group_delete",
            Self::CredentialItemSetGroup { .. } => "credential_item_set_group",
            Self::ServerProfileList => "server_profile_list",
            Self::ServerProfileCreate { .. } => "server_profile_create",
            Self::ServerProfileUpdate { .. } => "server_profile_update",
            Self::SshKeyList => "ssh_key_list",
            Self::SshKeyGenerate { .. } => "ssh_key_generate",
            Self::SshSelectKey { .. } => "ssh_select_key",
            Self::SshSessionPrepare { .. } => "ssh_session_prepare",
            Self::SshAskpass { .. } => "ssh_askpass",
            Self::VaultCreate { .. } => "vault_create",
            Self::VaultChangePassword { .. } => "vault_change_password",
            Self::VaultExportOvb { .. } => "vault_export_ovb",
            Self::VaultRecoverOvb { .. } => "vault_recover_ovb",
            Self::VaultOpenDir { .. } => "vault_open_dir",
            Self::RecoveryCodesList => "recovery_codes_list",
            Self::RecoveryCodesCreate { .. } => "recovery_codes_create",
            Self::RecoveryCodesUpdate { .. } => "recovery_codes_update",
            Self::RestorePointsList => "restore_points_list",
            Self::RestorePointRecover { .. } => "restore_point_recover",
            Self::VaultMigrate { .. } => "vault_migrate",
            Self::VaultSecurityRebuild { .. } => "vault_security_rebuild",
            Self::BackupStatus => "backup_status",
            Self::VaultVerifyOvb { .. } => "vault_verify_ovb",
            Self::VaultVerifyRecoveryKey { .. } => "vault_verify_recovery_key",
            Self::DiagnosticLogTail { .. } => "diagnostic_log_tail",
            Self::DiagnosticLogSetLevel { .. } => "diagnostic_log_set_level",
        }
    }
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
        Self::Err {
            protocol_version: PROTOCOL_VERSION,
            code: code.into(),
            message,
        }
    }
}
