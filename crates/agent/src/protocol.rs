use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 2;
pub const MIN_COMPATIBLE_PROTOCOL: u32 = 2;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    /// App 的列表/创建请求携带分区；浏览器仍按网站匹配全库，不继承 App 页面状态。
    PartitionRequest { partition_id: String, request: Box<AgentRequest> },
    Ping,
    Status,
    SyncStatus,
    SyncControlAuthorize,
    SyncCancel,
    SyncPrepare {
        location: String,
        #[serde(default)] head: Option<credpivot_core::sync::Head>,
        #[serde(default)] remote_ovb: Option<String>,
        #[serde(default)] strategy: Option<String>,
        #[serde(default)] remote_password: String,
    },
    SyncResolve { plan_id: String, decisions: std::collections::BTreeMap<String,String> },
    SyncPreviewPage { plan_id: String, offset: usize, limit: usize },
    SyncApply { plan_id: String, #[serde(default)] host_name: String },
    SyncPublishAuthorize { location: String, head: credpivot_core::sync::Head },
    SyncAcknowledge { location: String, head: credpivot_core::sync::Head },
    SyncDisconnect,
    SyncBootstrapPrepare { location: String, head: credpivot_core::sync::Head, remote_ovb: String, password: String },
    SyncBootstrapApply { plan_id: String },
    SyncBootstrapCancel,
    SyncBootstrapFinish { location: String, head: credpivot_core::sync::Head },
    SshAuthorizationsPending,
    SshAuthorizationResolve { request_id: String, approved: bool, #[serde(default)] key_id: String, #[serde(default)] remember: bool },
    AppSettingsGet,
    AppSettingsBackup,
    AppSettingsSet { settings: credpivot_core::AppSettings },
    /// 浏览器会话由扩展的 session storage 持有，不能跨浏览器启动复用。
    BrowserRequest { session_id: String, request: Box<AgentRequest> },
    /// 扩展「连接」：必须由 App 对当前浏览器会话完成指纹/主密码验证。
    ExtensionConnect { request_id: String },
    /// 只撤销对应的待验证请求，不撤销已经授予的浏览器授权。
    ExtensionGateCancel { request_id: String },
    /// App 完成当前会话的身份验证后授予 Chrome 扩展短时访问（秒）。
    ExtensionGateGrant {
        session_id: String,
        request_id: String,
        #[serde(default = "default_extension_gate_ttl")]
        ttl_secs: u64,
    },
    Lock,
    UnlockPassword { password: String },
    LocalUnlockPolicySet { policy: crate::vault_session::LocalUnlockPolicy },
    LocalUnlockMaterial,
    UnlockLocal { material: crate::vault_session::LocalUnlockMaterial },
    VerifyMasterPassword { password: String },
    SensitiveAuthGrant,
    PasskeyBegin { request_id: String, kind: String, origin: String, options: Value },
    PasskeyPoll { request_id: String, origin: String },
    PasskeyCancel { request_id: String },
    PasskeyRequestsPending { #[serde(default)] status_only: bool },
    PasskeyResolve { request_id: String, approved: bool, #[serde(default)] credential_id: String, #[serde(default)] use_browser: bool,
        #[serde(default)] linked_login_id: String },
    PasskeyList,
    BrowserMfaBegin { request_id: String, origin: String, image: String },
    BrowserMfaPoll { request_id: String, origin: String },
    BrowserMfaCancel { request_id: String },
    BrowserMfaPending { #[serde(default)] request_id: String },
    BrowserMfaResolve { request_id: String, approved: bool, #[serde(default)] linked_login_id: String,
        #[serde(default)] issuer: String, #[serde(default)] account: String, #[serde(default)] input: String,
        #[serde(default)] website_rules: Vec<credpivot_core::UriRule> },
    AppPasskey {
        kind: String, origin: String, options: Value, package_name: String,
        #[serde(default)] client_data_hash: Option<String>,
        #[serde(default)] complete: bool,
        #[serde(default)] credential_id: String,
        #[serde(default)] linked_login_id: String,
    },
    CredentialSave {
        #[serde(default)]
        password_active_since_ms: Option<i64>,
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
        #[serde(default)]
        website_rules: Option<Vec<credpivot_core::UriRule>>,
        #[serde(default)]
        linked_mfa_ids: Option<Vec<String>>,
    },
    BrowserCredentialUpdate { credential_id: String, expected_revision: String, origin: String, username: String, password: String },
    /// Android 系统保存界面明确确认后更新当前密码；保留历史和所有关联资料。
    AppCredentialPasswordUpdate { credential_id: String, expected_revision: String, username: String, password: String },
    BrowserTotpCode { #[serde(default)] credential_id: String, origin: String, #[serde(default)] totp_id: String },
    BrowserMfaSuggest { origin: String, #[serde(default)] credential_id: String, #[serde(default)] include_other_matches: bool },
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
        #[serde(default)]
        offset: u32,
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
        #[serde(default)]
        website_rules: Option<Vec<credpivot_core::UriRule>>,
        #[serde(default)]
        linked_mfa_ids: Option<Vec<String>>,
    },
    CredentialTrash { item_id: String },
    VaultManage { action: credpivot_core::VaultAction },
    SecuritySummary,
    ImportBitwarden { json: String },
    TotpList,
    TotpCreate {
        #[serde(default)]
        website_rules: Vec<credpivot_core::UriRule>,
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
        #[serde(default)]
        comment: String,
        #[serde(default)]
        sign_policy: String,
        #[serde(default)]
        git_rules: Vec<String>,
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
    RecoveryCodesGet { id: String },
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
        password: Option<String>,
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
    VaultResetRecoveryKey { password: String, recovery_key: String },
    VaultExportJson { output_path: String, password: String },
    VaultImportJson { input_path: String, target_dir: String, password: String },
    DiagnosticLogTail {
        #[serde(default = "default_log_tail_lines")]
        max_lines: usize,
        #[serde(default)]
        file: Option<String>,
    },
    DiagnosticLogSetLevel { level: crate::diagnostics::LogLevel },
}

impl AgentRequest {
    /// 仅记录固定操作名，不序列化含密码、令牌或导入内容的请求。
    pub fn operation(&self) -> &'static str {
        match self {
            Self::PartitionRequest {request,..} => request.operation(),
            Self::Ping => "ping",
            Self::Status => "status",
            Self::SyncStatus => "sync_status",
            Self::SyncControlAuthorize => "sync_control_authorize",
            Self::SyncCancel => "sync_cancel",
            Self::SyncPrepare { .. } => "sync_prepare",
            Self::SyncResolve { .. } => "sync_resolve",
            Self::SyncPreviewPage { .. } => "sync_preview_page",
            Self::SyncApply { .. } => "sync_apply",
            Self::SyncPublishAuthorize { .. } => "sync_publish_authorize",
            Self::SyncAcknowledge { .. } => "sync_acknowledge",
            Self::SyncDisconnect => "sync_disconnect",
            Self::SyncBootstrapPrepare { .. } => "sync_bootstrap_prepare",
            Self::SyncBootstrapApply { .. } => "sync_bootstrap_apply",
            Self::SyncBootstrapCancel => "sync_bootstrap_cancel",
            Self::SyncBootstrapFinish { .. } => "sync_bootstrap_finish",
            Self::SshAuthorizationsPending => "ssh_authorizations_pending",
            Self::SshAuthorizationResolve { .. } => "ssh_authorization_resolve",
            Self::AppSettingsGet => "app_settings_get",
            Self::AppSettingsBackup => "app_settings_backup",
            Self::AppSettingsSet { .. } => "app_settings_set",
            Self::BrowserRequest { .. } => "browser_request",
            Self::ExtensionConnect { .. } => "extension_connect",
            Self::ExtensionGateCancel { .. } => "extension_gate_cancel",
            Self::ExtensionGateGrant { .. } => "extension_gate_grant",
            Self::Lock => "lock",
            Self::UnlockPassword { .. } => "unlock_password",
            Self::LocalUnlockPolicySet { .. } => "local_unlock_policy_set",
            Self::LocalUnlockMaterial => "local_unlock_material",
            Self::UnlockLocal { .. } => "unlock_local",
            Self::VerifyMasterPassword { .. } => "verify_master_password",
            Self::SensitiveAuthGrant => "sensitive_auth_grant",
            Self::PasskeyBegin { .. } => "passkey_begin",
            Self::PasskeyPoll { .. } => "passkey_poll",
            Self::PasskeyCancel { .. } => "passkey_cancel",
            Self::PasskeyRequestsPending { .. } => "passkey_requests_pending",
            Self::PasskeyResolve { .. } => "passkey_resolve",
            Self::PasskeyList => "passkey_list",
            Self::BrowserMfaBegin { .. } => "browser_mfa_begin",
            Self::BrowserMfaPoll { .. } => "browser_mfa_poll",
            Self::BrowserMfaCancel { .. } => "browser_mfa_cancel",
            Self::BrowserMfaPending { .. } => "browser_mfa_pending",
            Self::BrowserMfaResolve { .. } => "browser_mfa_resolve",
            Self::AppPasskey { .. } => "app_passkey",
            Self::CredentialSave { .. } => "credential_save",
            Self::BrowserCredentialUpdate { .. } => "browser_credential_update",
            Self::AppCredentialPasswordUpdate { .. } => "app_credential_password_update",
            Self::BrowserMfaSuggest { .. } => "browser_mfa_suggest",
            Self::BrowserTotpCode { .. } => "browser_totp_code",
            Self::CredentialSuggest { .. } => "credential_suggest",
            Self::CredentialFillPrepare { .. } => "credential_fill_prepare",
            Self::CredentialFillConsume { .. } => "credential_fill_consume",
            Self::CancelRequest { .. } => "cancel_request",
            Self::CredentialList { .. } => "credential_list",
            Self::CredentialGet { .. } => "credential_get",
            Self::CredentialUpdate { .. } => "credential_update",
            Self::CredentialTrash { .. } => "credential_trash",
            Self::VaultManage { .. } => "vault_manage",
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
            Self::RecoveryCodesGet { .. } => "recovery_codes_get",
            Self::RecoveryCodesCreate { .. } => "recovery_codes_create",
            Self::RecoveryCodesUpdate { .. } => "recovery_codes_update",
            Self::RestorePointsList => "restore_points_list",
            Self::RestorePointRecover { .. } => "restore_point_recover",
            Self::VaultMigrate { .. } => "vault_migrate",
            Self::VaultSecurityRebuild { .. } => "vault_security_rebuild",
            Self::BackupStatus => "backup_status",
            Self::VaultVerifyOvb { .. } => "vault_verify_ovb",
            Self::VaultVerifyRecoveryKey { .. } => "vault_verify_recovery_key",
            Self::VaultResetRecoveryKey { .. } => "vault_reset_recovery_key",
            Self::VaultExportJson { .. } => "vault_export_json",
            Self::VaultImportJson { .. } => "vault_import_json",
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        details: Option<Value>,
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
            details: None,
        }
    }

    pub fn err_with_details(code: &str, message: impl Into<String>, details: Value) -> Self {
        Self::Err {
            protocol_version: PROTOCOL_VERSION, code: code.into(), message: message.into(), details: Some(details),
        }
    }
}
