use crate::extension_gate::{clear_persisted_extension_gate, extension_gate_idle_secs};
use crate::error::AgentError;
#[cfg(not(target_os = "android"))]
use crate::error::Result;
use crate::peer_auth::PeerAuthConfig;
#[cfg(not(target_os = "android"))]
use crate::peer_auth::authorize_peer;
#[cfg(target_os = "macos")]
use crate::peer_auth::{peer_executable_path, peer_is_askpass_executable, peer_is_native_host_executable};
use crate::ssh_session::{prepare_session, consume_askpass_secret, SSH_SESSION_TTL_MS};
use crate::ssh_session::SshSessionGrant;
#[cfg(not(target_os = "android"))]
use crate::session_guard::expire_idle_session;
use crate::protocol::{AgentRequest, AgentResponse};
use crate::vault_session::{FillGrant, VaultSession};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
#[cfg(not(target_os = "android"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(target_os = "android"))]
use tokio::net::UnixListener;
use tokio::sync::Mutex;

const FILL_TTL_MS: u128 = 60_000;

#[derive(Debug, Clone, Copy, Default)]
pub struct RequestPeerContext {
    /// 只有进程内 FFI 可以读取解锁材料或授予身份验证，Unix socket 不具备此权限。
    pub from_app: bool,
    pub browser_session: Option<uuid::Uuid>,
    /// Chrome Native Messaging host 经 Unix socket 发起的请求。
    pub from_native_host: bool,
    /// credpivot-askpass 经 Unix socket 发起的请求。
    pub from_askpass: bool,
}

pub struct IpcState {
    pub vault: Arc<Mutex<VaultSession>>,
    pub pending_fills: HashMap<String, FillGrant>,
    pub pending_ssh_sessions: HashMap<String, SshSessionGrant>,
    pub peer_auth: PeerAuthConfig,
    /// 扩展经 native-host 访问敏感数据的截止时间（毫秒）。
    pub extension_gate_expires_ms: u128,
    /// 最近一次扩展（native-host）敏感操作时间（毫秒）。
    pub extension_gate_last_native_ms: u128,
    pub extension_gate_session: Option<uuid::Uuid>,
    pub extension_gate_pending_session: Option<uuid::Uuid>,
    pub shutting_down: bool,
}

fn extension_gate_active(st: &IpcState) -> bool {
    st.extension_gate_session.is_some() && now_ms() <= st.extension_gate_expires_ms
}

pub fn revoke_extension_gate(st: &mut IpcState) {
    st.extension_gate_expires_ms = 0;
    st.extension_gate_last_native_ms = 0;
    st.extension_gate_session = None;
    st.extension_gate_pending_session = None;
    st.pending_fills.clear();
    clear_persisted_extension_gate();
    let _ = crate::paths::clear_extension_gate_pending();
}

fn extension_gate_pending_request(st: &IpcState) -> Option<(uuid::Uuid, uuid::Uuid)> {
    let data = std::fs::read(crate::paths::extension_gate_pending_path()).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&data).ok()?;
    let session = uuid::Uuid::parse_str(value["session_id"].as_str()?).ok()?;
    let request = uuid::Uuid::parse_str(value["request_id"].as_str()?).ok()?;
    (st.extension_gate_pending_session == Some(session)).then_some((session, request))
}

fn request_extension_gate(st: &mut IpcState, session: uuid::Uuid, request: uuid::Uuid) -> std::io::Result<()> {
    if extension_gate_pending_request(st) == Some((session, request)) { return Ok(()); }
    crate::paths::ensure_runtime_dir()?;
    // 请求标识防止迟到的取消或验证结果影响同一浏览器刚发起的新请求。
    std::fs::write(crate::paths::extension_gate_pending_path(),
        json!({"session_id":session.to_string(),"request_id":request.to_string(),"created_ms":now_ms()}).to_string())?;
    st.extension_gate_pending_session = Some(session);
    Ok(())
}

fn maybe_expire_extension_gate_idle(st: &mut IpcState) {
    if st.extension_gate_expires_ms == 0 {
        return;
    }
    let idle_ms = extension_gate_idle_secs() as u128 * 1000;
    let last = st.extension_gate_last_native_ms;
    if last > 0 && now_ms() > last + idle_ms {
        revoke_extension_gate(st);
    }
}

fn grant_extension_gate(st: &mut IpcState, session: uuid::Uuid, ttl_secs: u64) {
    if st.extension_gate_session != Some(session) { st.pending_fills.clear(); }
    let ttl = ttl_secs.max(1);
    let until = now_ms() + ttl as u128 * 1000;
    st.extension_gate_expires_ms = until;
    st.extension_gate_last_native_ms = now_ms();
    st.extension_gate_session = Some(session);
    st.extension_gate_pending_session = None;
}

fn touch_extension_gate_native_activity(st: &mut IpcState) {
    if !extension_gate_active(st) {
        return;
    }
    st.extension_gate_last_native_ms = now_ms();
    let extend = now_ms() + extension_gate_idle_secs() as u128 * 1000;
    if extend > st.extension_gate_expires_ms {
        st.extension_gate_expires_ms = extend;
    }
}

pub fn load_extension_gate_into_state(st: &mut IpcState) {
    // App/Agent 重启后不恢复旧授权；磁盘上只允许保留待确认标记。
    revoke_extension_gate(st);
}

/// Chrome Native Host 不得直接调用的高危/旁路接口。
fn native_host_request_forbidden(req: &AgentRequest) -> bool {
    !matches!(req, AgentRequest::Ping | AgentRequest::Status | AgentRequest::ExtensionConnect { .. }
        | AgentRequest::ExtensionGateCancel { .. }
        | AgentRequest::CredentialSave { .. } | AgentRequest::CredentialSuggest { .. }
        | AgentRequest::BrowserCredentialUpdate { .. } | AgentRequest::BrowserTotpCode { .. } | AgentRequest::BrowserMfaSuggest { .. }
        | AgentRequest::CredentialFillPrepare { .. } | AgentRequest::CredentialFillConsume { .. }
        | AgentRequest::PasskeyBegin { .. } | AgentRequest::PasskeyPoll { .. } | AgentRequest::PasskeyCancel { .. }
        | AgentRequest::CancelRequest { .. })
}

fn req_requires_extension_gate(req: &AgentRequest) -> bool {
    matches!(
        req,
        AgentRequest::CredentialSave { .. }
            | AgentRequest::PasskeyBegin { .. } | AgentRequest::PasskeyPoll { .. }
            | AgentRequest::BrowserCredentialUpdate { .. } | AgentRequest::BrowserTotpCode { .. } | AgentRequest::BrowserMfaSuggest { .. }
            | AgentRequest::CredentialSuggest { .. }
            | AgentRequest::CredentialFillPrepare { .. }
            | AgentRequest::CredentialFillConsume { .. }
            | AgentRequest::CredentialGet { .. }
            | AgentRequest::TotpCode { .. }
    )
}

#[cfg(not(target_os = "android"))]
pub async fn serve_ipc(listener: UnixListener, state: Arc<Mutex<IpcState>>) -> Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if handle_ipc_connection(&mut stream, state).await.is_err() {
                crate::diagnostics::debug("ipc", "connection ended with transport or protocol error");
            }
        });
    }
}

#[cfg(not(target_os = "android"))]
async fn handle_ipc_connection(
    stream: &mut tokio::net::UnixStream,
    state: Arc<Mutex<IpcState>>,
) -> Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 4 * 1024 * 1024 {
        return Err(AgentError::Protocol("ipc message too large".into()));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let req: AgentRequest = serde_json::from_slice(&buf)
        .map_err(|e| AgentError::Protocol(e.to_string()))?;

    let peer_pid = peer_pid(stream)?;
    let mut peer = match peer_context_for_pid(peer_pid, &state).await {
        Ok(p) => p,
        Err(e) => {
            let code = if matches!(&e, AgentError::PeerDenied(reason) if reason == "native-host is outdated; reconnect to the installed version") {
                "host_outdated"
            } else { "peer_denied" };
            return write_ipc_response(
                stream,
                AgentResponse::err(code, e.to_string()),
            )
            .await;
        }
    };

    let req = match req {
        AgentRequest::BrowserRequest { session_id, request } if peer.from_native_host => {
            match uuid::Uuid::parse_str(&session_id) {
                Ok(id) => { peer.browser_session = Some(id); *request }
                Err(_) => return write_ipc_response(stream, AgentResponse::err("bad_args", "invalid browser session")).await,
            }
        }
        req if !peer.from_native_host => req,
        _ => return write_ipc_response(stream, AgentResponse::err("protocol_mismatch", "reload the updated CredPivot extension")).await,
    };

    expire_idle_session(&state).await;
    let resp = {
        let mut st = state.lock().await;
        handle_request(&mut st, req, peer).await
    };

    write_ipc_response(stream, resp).await
}

#[cfg(not(target_os = "android"))]
async fn write_ipc_response(
    stream: &mut tokio::net::UnixStream,
    resp: AgentResponse,
) -> Result<()> {
    let body = serde_json::to_vec(&resp).map_err(|e| AgentError::Protocol(e.to_string()))?;
    let frame_len = (body.len() as u32).to_le_bytes();
    stream.write_all(&frame_len).await?;
    stream.write_all(&body).await?;
    Ok(())
}

#[cfg(not(target_os = "android"))]
async fn peer_context_for_pid(
    peer_pid: u32,
    state: &Arc<Mutex<IpcState>>,
) -> std::result::Result<RequestPeerContext, AgentError> {
    let cfg = state.lock().await.peer_auth.clone();
    authorize_peer(peer_pid, &cfg)?;
    #[cfg(target_os = "macos")]
    {
        let path = peer_executable_path(peer_pid)?;
        let from_native_host = peer_is_native_host_executable(&path, &cfg);
        let from_askpass = peer_is_askpass_executable(&path);
        Ok(RequestPeerContext {
            from_app: false,
            browser_session: None,
            from_native_host,
            from_askpass,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = peer_pid;
        Ok(RequestPeerContext::default())
    }
}

pub async fn handle_request(
    st: &mut IpcState,
    req: AgentRequest,
    peer: RequestPeerContext,
) -> AgentResponse {
    let (req, partition) = match req {
        AgentRequest::PartitionRequest { partition_id, request } => {
            if !peer.from_app { return AgentResponse::err("forbidden","partition scope is App-only"); }
            let v=st.vault.lock().await;
            if !v.unlocked { return AgentResponse::err("locked","vault locked"); }
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","database not attached"); };
            if let Err(e)=credpivot_core::partitions::require(db.conn(),&partition_id) { return AgentResponse::err("vault",e.to_string().trim_start_matches("invalid format: ")); }
            (*request,Some(partition_id))
        }
        request => (request,None),
    };
    let moving_partition=matches!(&req,AgentRequest::VaultManage {action:credpivot_core::VaultAction::PartitionMoveApply {..}});
    let operation = req.operation();
    {
        let mut vault = st.vault.lock().await;
        if vault.bootstrap_plan.as_ref().is_some_and(|p|p.expired()) { vault.bootstrap_plan = None; }
    }
    crate::diagnostics::debug(operation, "request started");
    let mutates = matches!(&req,
        AgentRequest::CredentialSave { .. } | AgentRequest::CredentialUpdate { .. } | AgentRequest::BrowserCredentialUpdate { .. } | AgentRequest::AppCredentialPasswordUpdate { .. }
        | AgentRequest::CredentialTrash { .. } | AgentRequest::TotpCreate { .. } | AgentRequest::ImportBitwarden { .. }
        | AgentRequest::SshKeyGenerate { .. } | AgentRequest::SshSelectKey { .. }
        | AgentRequest::RecoveryCodesCreate { .. } | AgentRequest::RecoveryCodesUpdate { .. }
        | AgentRequest::ServerProfileCreate { .. } | AgentRequest::ServerProfileUpdate { .. })
        || matches!(&req, AgentRequest::AppPasskey { kind, complete: true, .. } if kind == "create")
        || matches!(&req, AgentRequest::CredentialGroupCreate { .. }
            | AgentRequest::CredentialGroupDelete { .. } | AgentRequest::CredentialItemSetGroup { .. })
        || matches!(&req,AgentRequest::VaultManage { action } if matches!(action,
            credpivot_core::VaultAction::ItemDetailsSave { .. } | credpivot_core::VaultAction::TotpUpdate { .. }
            | credpivot_core::VaultAction::CandidateCreate { .. } | credpivot_core::VaultAction::CandidateActivate { .. }
            | credpivot_core::VaultAction::CandidateDiscard { .. } | credpivot_core::VaultAction::HistoryRestore { .. }
            | credpivot_core::VaultAction::TrashRestore { .. } | credpivot_core::VaultAction::TrashPurge { .. }
            | credpivot_core::VaultAction::NoteCreate { .. } | credpivot_core::VaultAction::BitwardenImport { .. }
            | credpivot_core::VaultAction::GoogleImport { .. }
            | credpivot_core::VaultAction::SshImport { .. } | credpivot_core::VaultAction::RecoveryEntryUse { .. }
            | credpivot_core::VaultAction::PartitionCreate {..} | credpivot_core::VaultAction::PartitionRename {..}
            | credpivot_core::VaultAction::PartitionDelete {..} | credpivot_core::VaultAction::PartitionReorder {..}
            | credpivot_core::VaultAction::PartitionMoveApply {..} | credpivot_core::VaultAction::GroupRename {..}));
    let mut response = handle_request_inner(st, req, peer, partition.as_deref()).await;
    if let AgentResponse::Ok {payload,..}=&mut response {
        let v=st.vault.lock().await;
        if let Some(db)=v.db.as_ref() {
            if let Err(e)=credpivot_core::partitions::annotate(db.conn(),payload,partition.as_deref()) {
                response=AgentResponse::err("vault",e.to_string());
            }
        }
    }
    if mutates && matches!(&response,AgentResponse::Ok { .. }) {
        let mut v = st.vault.lock().await;
        v.data_revision = uuid::Uuid::new_v4().to_string();
        v.ssh_authorization.clear();
        if moving_partition {
            v.sync_plan=None;
            v.passkey_requests.clear();
            st.pending_fills.clear();
            st.pending_ssh_sessions.clear();
        }
    }
    if let AgentResponse::Err {message,..}=&mut response {
        let key=message.trim_start_matches("invalid format: ");
        if key.starts_with("partitions.errors.") && key.bytes().all(|c|c.is_ascii_alphanumeric() || c==b'.') { *message=key.to_string(); }
    }
    match &response {
        AgentResponse::Ok { .. } => match operation {
            "credential_save" | "credential_update" | "credential_trash"
            | "import_bitwarden" | "totp_create" | "ssh_key_generate" | "ssh_select_key"
            | "ssh_session_prepare" | "vault_change_password" | "vault_export_ovb"
            | "vault_recover_ovb" | "vault_open_dir" | "restore_point_recover"
            | "vault_migrate" | "vault_security_rebuild" | "recovery_codes_create"
            | "recovery_codes_update" | "server_profile_create" | "server_profile_update"
            | "sync_apply" => {
                crate::diagnostics::info(operation, "operation completed");
            }
            _ => crate::diagnostics::debug(operation, "request completed"),
        },
        AgentResponse::Err { code, message, .. } => {
            // 错误正文可能含用户输入或本地路径，只记录固定分类。
            match code.as_str() {
                "locked" => crate::diagnostics::warn(operation, "request rejected: vault locked"),
                "bad_unlock" => crate::diagnostics::warn(operation, "authentication failed"),
                "extension_gate_required" | "auth_required" => {
                    crate::diagnostics::debug(operation, "identity confirmation required");
                }
                "forbidden" | "peer_denied" | "askpass_denied" => {
                    crate::diagnostics::warn(operation, "request denied");
                }
                "bad_args" | "conflict" | "not_found" | "request_gone" => {
                    crate::diagnostics::warn(operation, "request rejected: invalid or stale input");
                }
                "origin_mismatch" | "frame_mismatch" => {
                    crate::diagnostics::warn(operation, "fill context mismatch");
                }
                "sync_error" => {
                    // 只展开固定错误键，不能把任意异常正文写入日志。
                    let event = match message.as_str() {
                        "sync.errors.localChanged" => "sync preview invalidated by local changes",
                        "sync.errors.previewExpired" => "sync preview missing or expired",
                        "sync.errors.previewValidation" => "sync preview validation failed",
                        "sync.errors.recordSchema" => "sync record schema or value type invalid",
                        "sync.errors.recordConstraint" => "sync record database constraint failed",
                        "sync.errors.invalidDetails" => "sync record details format invalid",
                        "sync.errors.invalidWebsiteRules" => "sync website matching rules invalid",
                        "sync.errors.invalidMfa" => "sync MFA secret or parameters invalid",
                        "sync.errors.invalidMfaSecret" => "sync MFA Base32 secret invalid",
                        "sync.errors.invalidMfaAlgorithm" => "sync MFA algorithm unsupported",
                        "sync.errors.invalidMfaParameters" => "sync MFA digits or period invalid",
                        "sync.errors.invalidKey" => "sync SSH or passkey material invalid",
                        "sync.errors.unresolved" => "sync conflicts unresolved",
                        "sync.errors.relatedCredential" => "sync related credential conflict",
                        "sync.errors.relatedMfa" => "sync related MFA conflict",
                        "sync.errors.relatedGroup" => "sync related group conflict",
                        "sync.errors.readLocal" => "sync local data read failed",
                        "sync.errors.backup" => "sync local backup failed",
                        "sync.errors.archive" => "sync encrypted snapshot creation failed",
                        "sync.errors.applyLocal" => "sync local result commit failed",
                        _ => "sync request failed",
                    };
                    crate::diagnostics::error(operation, event);
                }
                _ => crate::diagnostics::error(operation, "request failed"),
            }
        }
    }
    response
}

async fn handle_request_inner(
    st: &mut IpcState,
    req: AgentRequest,
    peer: RequestPeerContext,
    partition: Option<&str>,
) -> AgentResponse {
    if st.shutting_down {
        return AgentResponse::err("shutting_down", "agent is shutting down");
    }
    if matches!(&req, AgentRequest::LocalUnlockPolicySet { .. } | AgentRequest::LocalUnlockMaterial
        | AgentRequest::UnlockLocal { .. } | AgentRequest::VerifyMasterPassword { .. }
        | AgentRequest::SensitiveAuthGrant | AgentRequest::ExtensionGateGrant { .. }
        | AgentRequest::AppSettingsGet | AgentRequest::AppSettingsBackup | AgentRequest::AppSettingsSet { .. }
        | AgentRequest::SyncStatus | AgentRequest::SyncControlAuthorize | AgentRequest::SyncCancel | AgentRequest::SyncPrepare { .. } | AgentRequest::SyncResolve { .. }
        | AgentRequest::SyncPreviewPage { .. }
        | AgentRequest::SyncApply { .. } | AgentRequest::SyncPublishAuthorize { .. } | AgentRequest::SyncAcknowledge { .. } | AgentRequest::SyncDisconnect
        | AgentRequest::SyncBootstrapPrepare { .. } | AgentRequest::SyncBootstrapApply { .. } | AgentRequest::SyncBootstrapCancel | AgentRequest::SyncBootstrapFinish { .. }
        | AgentRequest::VaultManage { .. } | AgentRequest::AppCredentialPasswordUpdate { .. } | AgentRequest::AppPasskey { .. }
        | AgentRequest::SshAuthorizationsPending | AgentRequest::SshAuthorizationResolve { .. }
        | AgentRequest::PasskeyRequestsPending { .. } | AgentRequest::PasskeyResolve { .. } | AgentRequest::PasskeyList
        | AgentRequest::VaultResetRecoveryKey { .. } | AgentRequest::VaultExportJson { .. }
        | AgentRequest::VaultImportJson { .. } | AgentRequest::VaultVerifyRecoveryKey { .. } | AgentRequest::VaultOpenDir { .. }
        | AgentRequest::UnlockPassword { .. } | AgentRequest::VaultCreate { .. }) && !peer.from_app {
        return AgentResponse::err("forbidden", "authentication control is App-only");
    }
    // 连接、取消及周期状态查询必须保持轻量；恢复点已有独立定时任务，不能挡住验证弹窗。
    if !matches!(&req, AgentRequest::Ping | AgentRequest::Status | AgentRequest::SyncStatus | AgentRequest::AppSettingsGet
        | AgentRequest::ExtensionConnect { .. } | AgentRequest::ExtensionGateCancel { .. }
        | AgentRequest::ExtensionGateGrant { .. } | AgentRequest::SensitiveAuthGrant
        | AgentRequest::LocalUnlockPolicySet { .. } | AgentRequest::LocalUnlockMaterial
        | AgentRequest::UnlockLocal { .. } | AgentRequest::UnlockPassword { .. }
        | AgentRequest::VerifyMasterPassword { .. }
        | AgentRequest::SshAuthorizationsPending | AgentRequest::PasskeyRequestsPending { .. }) {
        let mut v = st.vault.lock().await;
        if v.unlocked {
            let _ = v.try_restore_point_if_due();
        }
    }
    maybe_expire_extension_gate_idle(st);
    let vault_locked = !st.vault.lock().await.unlocked;
    if vault_locked {
        st.pending_ssh_sessions.clear();
        if st.extension_gate_session.is_some() { revoke_extension_gate(st); }
    }
    if peer.from_native_host && native_host_request_forbidden(&req) {
        return AgentResponse::err(
            "forbidden",
            "browser extension cannot invoke this agent operation",
        );
    }
    if peer.from_native_host && req_requires_extension_gate(&req) {
        if !extension_gate_active(st) || st.extension_gate_session != peer.browser_session {
            // 读取列表、轮询和取密失败都不能重新唤起指纹；只有显式连接或新建通行密钥请求可以。
            if let AgentRequest::PasskeyBegin { request_id, .. } = &req {
                if let (Some(session), Ok(request)) = (peer.browser_session, uuid::Uuid::parse_str(request_id)) {
                    if request_extension_gate(st, session, request).is_err() {
                        return AgentResponse::err("auth_request_failed", "无法建立浏览器验证请求，请重试");
                    }
                }
            }
            return AgentResponse::err(
                "extension_gate_required",
                "请在 CredPivot App 中完成指纹确认后重试",
            );
        }
    }
    let bump_gate_activity = peer.from_native_host && req_requires_extension_gate(&req);
    if peer.from_app && (matches!(&req,
        AgentRequest::CredentialGet { .. } | AgentRequest::CredentialUpdate { .. } | AgentRequest::AppCredentialPasswordUpdate { .. } | AgentRequest::AppPasskey { complete: true, .. }
        | AgentRequest::CredentialTrash { .. } | AgentRequest::TotpCode { .. }
        | AgentRequest::TotpReveal { .. } | AgentRequest::RecoveryCodesGet { .. }
        | AgentRequest::RecoveryCodesUpdate { .. }
        | AgentRequest::ServerProfileUpdate { .. } | AgentRequest::SshSessionPrepare { .. }
        | AgentRequest::ImportBitwarden { .. } | AgentRequest::VaultChangePassword { .. }
        | AgentRequest::VaultExportOvb { .. } | AgentRequest::RestorePointRecover { .. }
        | AgentRequest::VaultMigrate { .. } | AgentRequest::VaultSecurityRebuild { .. })
        || matches!(&req, AgentRequest::VaultManage { action } if action.requires_sensitive_auth())) {
        let mut v = st.vault.lock().await;
        if !v.unlocked { return AgentResponse::err("locked", "vault locked"); }
        if !v.authorize_sensitive_operation() { return AgentResponse::err("auth_required", "identity verification required"); }
    }
    let resp = match req {
        AgentRequest::PartitionRequest {..} => AgentResponse::err("bad_args","nested partition scope is not supported"),
        request @ (AgentRequest::SyncBootstrapPrepare { .. } | AgentRequest::SyncBootstrapApply { .. } | AgentRequest::SyncBootstrapCancel | AgentRequest::SyncBootstrapFinish { .. }
            | AgentRequest::SyncStatus | AgentRequest::SyncControlAuthorize | AgentRequest::SyncCancel | AgentRequest::SyncPrepare { .. } | AgentRequest::SyncResolve { .. }
            | AgentRequest::SyncPreviewPage { .. }
            | AgentRequest::SyncApply { .. } | AgentRequest::SyncPublishAuthorize { .. } | AgentRequest::SyncAcknowledge { .. } | AgentRequest::SyncDisconnect) => {
            let applies=matches!(&request,AgentRequest::SyncApply { .. });
            let mut vault=st.vault.lock().await;
            let result=crate::sync::handle(&mut vault,request);
            let locked = !vault.unlocked;
            drop(vault);
            // 切换后的会话刷新失败会锁定；错误响应也必须清除切换前的浏览器/SSH 授权。
            if applies && (locked || result.as_ref().is_ok_and(|p|p["changed"]==true)) {
                st.pending_fills.clear(); st.pending_ssh_sessions.clear();
                if locked || result.as_ref().is_ok_and(|p|p["vault_switched"]==true) { revoke_extension_gate(st); }
            }
            match result {
                Ok(payload)=>AgentResponse::ok(payload),
                Err(AgentError::Locked)=>AgentResponse::err("locked","vault locked"),
                Err(AgentError::Protocol(message)) if message=="auth_required"=>AgentResponse::err("auth_required","identity verification required"),
                Err(AgentError::Vault(message))=>AgentResponse::err("sync_error",message),
                Err(AgentError::SyncRecord { message, record }) =>
                    AgentResponse::err_with_details("sync_error", message, json!({"record":record})),
                Err(_)=>AgentResponse::err("sync_error","sync.errors.operation"),
            }
        }
        AgentRequest::BrowserRequest { .. } => AgentResponse::err("forbidden", "nested browser request"),
        AgentRequest::Ping => AgentResponse::ok(json!({ "pong": true })),
        AgentRequest::AppPasskey { kind, origin, options, package_name, client_data_hash, complete, credential_id, linked_login_id } => {
            #[cfg(target_os = "android")]
            {
                let mut v = st.vault.lock().await;
                if !v.unlocked { return AgentResponse::err("locked", "vault locked"); }
                let Some(db) = v.db.as_ref() else { return AgentResponse::err("locked", "vault locked"); };
                let request = match credpivot_core::passkey::Request::parse_android(&kind, &origin, &options, &package_name, client_data_hash.as_deref()) {
                    Ok(request) => request,
                    Err(_) => return AgentResponse::err("passkey_request", "通行密钥请求无效或不受支持"),
                };
                let result = if complete {
                    request.complete_in_partition(db.conn(), &credential_id, partition.unwrap_or(credpivot_core::partitions::PERSONAL), &linked_login_id)
                        // WebAuthn 结果不使用通用 credential 字段，避免附加本地分区名称后交给网站。
                        .map(|credential|json!({"result":credential}))
                } else {
                    request.candidates(db.conn()).map(|items| {
                        let (logins, unavailable) = if request.create {
                            match request.login_candidates(db.conn()) {
                                Ok(logins) => (logins, false),
                                Err(_) => {
                                    crate::diagnostics::warn("passkey", "linked account list unavailable");
                                    (Vec::new(), true)
                                }
                            }
                        } else { (Vec::new(), false) };
                        json!({"items":items,"login_candidates":logins,"login_candidates_unavailable":unavailable,
                            "rp_id":request.rp_id,"username":request.username,"excluded":request.excluded(db.conn()).unwrap_or(true)})
                    })
                };
                match result {
                    Ok(payload) => { v.touch_activity(); AgentResponse::ok(payload) },
                    Err(_) => AgentResponse::err("passkey_request", "通行密钥操作失败，请核对请求或记录"),
                }
            }
            #[cfg(not(target_os = "android"))]
            {
                let _ = (kind, origin, options, package_name, client_data_hash, complete, credential_id, linked_login_id);
                AgentResponse::err("unsupported", "Android credential provider only")
            }
        }
        AgentRequest::PasskeyList => {
            let v = st.vault.lock().await;
            let Some(db) = v.db.as_ref().filter(|_|v.unlocked) else { return AgentResponse::err("locked","vault locked"); };
            match credpivot_core::passkey::list(db.conn()) {
                Ok(items) => AgentResponse::ok(json!({"items":items})),
                Err(_) => AgentResponse::err("vault_error","读取通行密钥失败"),
            }
        }
        AgentRequest::PasskeyBegin { request_id, kind, origin, options } => {
            let Some(session) = peer.browser_session.filter(|_|peer.from_native_host) else { return AgentResponse::err("forbidden","browser only"); };
            if uuid::Uuid::parse_str(&request_id).is_err() { return AgentResponse::err("bad_args","invalid request id"); }
            let request = match credpivot_core::passkey::Request::parse(&kind,&origin,&options) {
                Ok(r) => r,
                Err(_) => return AgentResponse::ok(json!({"state":"fallback"})),
            };
            let mut v = st.vault.lock().await;
            v.passkey_requests.expire();
            let Some(db) = v.db.as_ref().filter(|_|v.unlocked) else { return AgentResponse::err("locked","vault locked"); };
            let candidates = match request.candidates(db.conn()) {
                Ok(c) => c,
                Err(_) => return AgentResponse::err("vault_error","读取通行密钥失败"),
            };
            if !request.create && candidates.is_empty() { return AgentResponse::ok(json!({"state":"fallback"})); }
            if v.passkey_requests.0.contains_key(&request_id) || v.passkey_requests.0.len() >= 8 {
                return AgentResponse::err("busy","已有通行密钥请求正在处理");
            }
            v.passkey_requests.insert(request_id,request,session);
            v.touch_activity();
            AgentResponse::ok(json!({"state":"pending"}))
        }
        AgentRequest::PasskeyPoll { request_id, origin } => {
            let mut v = st.vault.lock().await;
            v.passkey_requests.expire();
            let Some(pending) = v.passkey_requests.0.get(&request_id).filter(|p|peer.from_native_host && Some(p.session) == peer.browser_session && p.request.origin == origin) else {
                return AgentResponse::err("request_gone","通行密钥请求已取消或过期");
            };
            if let Some(outcome) = pending.outcome.clone() {
                v.passkey_requests.0.remove(&request_id);
                AgentResponse::ok(outcome)
            } else { AgentResponse::ok(json!({"state":"pending"})) }
        }
        AgentRequest::PasskeyCancel { request_id } => {
            let mut v = st.vault.lock().await;
            if v.passkey_requests.0.get(&request_id).is_some_and(|p|peer.from_native_host && Some(p.session) == peer.browser_session) {
                v.passkey_requests.0.remove(&request_id);
            }
            AgentResponse::ok(json!({"cancelled":true}))
        }
        AgentRequest::PasskeyRequestsPending { status_only } => {
            let mut v = st.vault.lock().await;
            v.passkey_requests.expire();
            if !extension_gate_active(st) { v.passkey_requests.clear(); }
            let Some(db) = v.db.as_ref().filter(|_|v.unlocked) else { return AgentResponse::ok(json!({"requests":[]})); };
            let pending = v.passkey_requests.0.iter().filter(|(_,p)|p.outcome.is_none() && Some(p.session) == st.extension_gate_session);
            if status_only {
                // 弹窗存活检查只依赖请求状态，不重复读取可选账号或凭据资料。
                let ids: Vec<_> = pending.map(|(id,_)|id).collect();
                return AgentResponse::ok(json!({"request_ids":ids}));
            }
            let requests: Vec<_> = pending.filter_map(|(id,p)| {
                let c = p.request.candidates(db.conn()).ok()?;
                let (logins, unavailable) = if p.request.create {
                    match p.request.login_candidates(db.conn()) {
                        Ok(logins) => (logins, false),
                        Err(_) => {
                            crate::diagnostics::warn("passkey", "linked account list unavailable");
                            (Vec::new(), true)
                        }
                    }
                } else { (Vec::new(), false) };
                Some(json!({"id":id,"create":p.request.create,
                    "origin":p.request.origin,"rp_id":p.request.rp_id,"username":p.request.username,
                    "display_name":p.request.display_name,"candidates":c,"login_candidates":logins,
                    "login_candidates_unavailable":unavailable}))
            }).collect();
            AgentResponse::ok(json!({"requests":requests}))
        }
        AgentRequest::PasskeyResolve { request_id, approved, credential_id, use_browser, linked_login_id } => {
            let mut v = st.vault.lock().await;
            v.passkey_requests.expire();
            let Some(pending) = v.passkey_requests.0.get(&request_id).filter(|p|p.outcome.is_none() && Some(p.session) == st.extension_gate_session && extension_gate_active(st)) else {
                return AgentResponse::err("request_gone","通行密钥请求已取消或过期");
            };
            let request = pending.request.clone();
            let outcome = if use_browser { json!({"state":"fallback"}) }
            else if !approved { crate::passkey::rejected("NotAllowedError","用户取消了通行密钥操作") }
            else {
                if !v.unlocked || !v.authorize_sensitive_operation() { return AgentResponse::err("auth_required","请先验证身份"); }
                let Some(db) = v.db.as_ref() else { return AgentResponse::err("locked","vault locked"); };
                if request.excluded(db.conn()).unwrap_or(true) {
                    crate::passkey::rejected("InvalidStateError","此网站已经注册过该通行密钥")
                } else {
                    match request.complete(db.conn(),&credential_id,&linked_login_id) {
                        Ok(credential) => json!({"state":"done","credential":credential}),
                        Err(_) => crate::passkey::rejected("UnknownError","通行密钥操作失败，请重试"),
                    }
                }
            };
            if outcome.get("credential").is_some() {
                if request.create {
                    v.data_revision = uuid::Uuid::new_v4().to_string();
                    v.ssh_authorization.clear();
                }
                crate::diagnostics::info("passkey", if request.create { "credential created" } else { "assertion signed" });
            }
            if let Some(pending) = v.passkey_requests.0.get_mut(&request_id) { pending.outcome = Some(outcome); }
            v.touch_activity();
            AgentResponse::ok(json!({"resolved":true}))
        }
        AgentRequest::AppSettingsGet => {
            let warning = if credpivot_core::read_app_settings().is_err() {
                "配置文件无法读取或内容无效，当前使用保守设置；请修正后重新加载，或恢复默认并保存。"
            } else { "" };
            let v = st.vault.lock().await;
            AgentResponse::ok(json!({
                "settings": credpivot_core::effective_app_settings(),
                "defaults": credpivot_core::AppSettings::default(),
                "path": credpivot_core::app_settings_path().to_string_lossy(),
                "warning": warning,
                "vault_exists": v.vault_exists(),
                "vault_path": v.vault_dir.to_string_lossy(),
            }))
        }
        AgentRequest::AppSettingsBackup => {
            match credpivot_core::backup_app_settings() {
                Ok(path) => AgentResponse::ok(json!({ "path": path })),
                Err(_) => AgentResponse::err("settings_backup", "配置备份失败，未恢复默认值"),
            }
        }
        AgentRequest::AppSettingsSet { settings } => {
            if let Err(e) = settings.validate() { return AgentResponse::err("bad_settings", e.to_string()); }
            let old = credpivot_core::effective_app_settings();
            if old.vault_directory != settings.vault_directory {
                return AgentResponse::err("bad_settings", "请使用切换保险库入口修改目录，避免跳过锁定流程");
            }
            let security_changed = old.security_differs(&settings);
            let protection_changed = security_changed
                || old.restore_interval_hours != settings.restore_interval_hours
                || old.restore_keep_count != settings.restore_keep_count;
            let mut v = st.vault.lock().await;
            if protection_changed && v.vault_exists() && !v.authorize_sensitive_operation() {
                return AgentResponse::err("auth_required", "identity verification required");
            }
            if credpivot_core::write_app_settings(&settings).is_err() {
                return AgentResponse::err("settings_write", "配置保存失败，原配置未变更");
            }
            v.apply_settings(settings.clone());
            let locked = v.idle_expired();
            if locked { v.lock(); }
            drop(v);
            if security_changed || old.chrome_extension_id != settings.chrome_extension_id || locked {
                revoke_extension_gate(st);
            }
            if locked { st.pending_ssh_sessions.clear(); }
            crate::diagnostics::info("settings", "application settings updated");
            AgentResponse::ok(json!({ "settings": settings }))
        }
        AgentRequest::ExtensionConnect { request_id } => {
            let Ok(request) = uuid::Uuid::parse_str(&request_id) else {
                return AgentResponse::err("invalid_request", "browser verification request is invalid");
            };
            let v = st.vault.lock().await;
            let gate = extension_gate_active(st) && st.extension_gate_session == peer.browser_session;
            let mut payload = v.vault_status_json();
            drop(v);
            if !gate {
                if let Some(session) = peer.browser_session {
                    if request_extension_gate(st, session, request).is_err() {
                        return AgentResponse::err("auth_request_failed", "无法建立浏览器验证请求，请重试");
                    }
                }
                return AgentResponse::err("extension_gate_required", "请在 CredPivot App 中完成指纹或主密码确认");
            }
            payload["connected"] = json!(true);
            payload["extension_gate_active"] = json!(gate);
            payload["extension_gate_idle_secs"] = json!(extension_gate_idle_secs());
            AgentResponse::ok(payload)
        }
        AgentRequest::ExtensionGateCancel { request_id } => {
            let request = uuid::Uuid::parse_str(&request_id).ok();
            if let Some((session, pending)) = extension_gate_pending_request(st) {
                if (peer.from_app || peer.browser_session == Some(session)) && request == Some(pending) {
                    if crate::paths::clear_extension_gate_pending().is_err() {
                        return AgentResponse::err("auth_cancel_failed", "无法取消浏览器验证请求，请重试");
                    }
                    st.extension_gate_pending_session = None;
                }
            }
            AgentResponse::ok(json!({"cancelled":true}))
        }
        AgentRequest::ExtensionGateGrant { session_id, request_id, ttl_secs } => {
            let session = uuid::Uuid::parse_str(&session_id).ok();
            let request = uuid::Uuid::parse_str(&request_id).ok();
            if session.zip(request).is_none() || session.zip(request) != extension_gate_pending_request(st) {
                return AgentResponse::err("conflict", "browser request changed; retry connection");
            }
            if !st.vault.lock().await.authorize_sensitive_operation() { return AgentResponse::err("auth_required", "identity verification required"); }
            let idle = extension_gate_idle_secs();
            let ttl = if ttl_secs == 0 { idle } else { ttl_secs.min(idle) };
            grant_extension_gate(st, session.unwrap(), ttl);
            let _ = crate::paths::clear_extension_gate_pending();
            AgentResponse::ok(json!({
                "extension_gate_active": true,
                "expires_in_secs": ttl,
                "idle_secs": idle,
            }))
        }
        AgentRequest::SshAuthorizationsPending => {
            let mut v = st.vault.lock().await;
            v.ssh_authorization.expire();
            AgentResponse::ok(json!({"requests":v.ssh_authorization.pending.values().collect::<Vec<_>>()}))
        }
        AgentRequest::SshAuthorizationResolve { request_id, approved, key_id, remember } => {
            let mut v = st.vault.lock().await;
            v.ssh_authorization.expire();
            if !v.ssh_authorization.pending.contains_key(&request_id) {
                return AgentResponse::err("request_gone", "SSH 请求已断开或过期");
            }
            if approved && (!v.unlocked || !v.authorize_sensitive_operation()) { return AgentResponse::err("auth_required","请先验证身份"); }
            if v.ssh_authorization.resolve(&request_id,approved,key_id,remember) { AgentResponse::ok(json!({"resolved":true})) }
            else { AgentResponse::err("request_gone","SSH 请求已断开或过期") }
        }
        AgentRequest::Status => {
            let v = st.vault.lock().await;
            let mut payload = v.vault_status_json();
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "extension_gate_active".into(),
                    json!(extension_gate_active(st) && (!peer.from_native_host || st.extension_gate_session == peer.browser_session)),
                );
                obj.insert(
                    "extension_gate_idle_secs".into(),
                    json!(extension_gate_idle_secs()),
                );
                // 只读状态供页面填充等待验证；取消后不重新发起握手或误续上其他请求。
                let pending = extension_gate_pending_request(st).filter(|(session, _)|
                    !peer.from_native_host || Some(*session) == peer.browser_session);
                obj.insert("extension_gate_pending".into(), json!(pending.is_some()));
                obj.insert("extension_gate_request_id".into(), json!(pending.map(|(_, request)| request.to_string())));
            }
            AgentResponse::ok(payload)
        }
        AgentRequest::Lock => {
            st.vault.lock().await.lock();
            revoke_extension_gate(st);
            st.pending_ssh_sessions.clear();
            AgentResponse::ok(json!({ "locked": true }))
        }
        AgentRequest::UnlockPassword { password } => {
            match st.vault.lock().await.unlock_password(&password) {
                Ok(()) => AgentResponse::ok(json!({ "unlocked": true })),
                Err(e) => AgentResponse::err("bad_unlock", e.to_string()),
            }
        }
        AgentRequest::VaultCreate { password } => {
            if credpivot_core::read_app_settings().is_err() {
                return AgentResponse::err("bad_settings", "请先在设置页修复配置文件，再创建保险库");
            }
            match st.vault.lock().await.create_vault(&password) {
                Ok(recovery_display) => AgentResponse::ok(json!({
                    "created": true,
                    "recovery_key": recovery_display,
                })),
                Err(e) => AgentResponse::err("vault_create", e.to_string()),
            }
        }
        AgentRequest::VaultChangePassword {
            old_password,
            new_password,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.change_password(&old_password, &new_password) {
                Ok(()) => {
                    drop(v);
                    revoke_extension_gate(st);
                    st.pending_ssh_sessions.clear();
                    AgentResponse::ok(json!({ "changed": true }))
                }
                Err(AgentError::Vault(message)) if message.starts_with("sync.") => AgentResponse::err("sync_error", message),
                Err(e) => AgentResponse::err("change_password", e.to_string()),
            }
        }
        AgentRequest::VaultExportOvb { output_path, password } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.export_ovb(&output_path, &password) {
                Ok(()) => AgentResponse::ok(json!({ "exported": true, "path": output_path })),
                Err(e) => AgentResponse::err("export_ovb", e.to_string()),
            }
        }
        AgentRequest::VaultRecoverOvb {
            ovb_path,
            target_dir,
            password,
            recovery_key,
        } => match VaultSession::recover_ovb(
            &ovb_path,
            &target_dir,
            password.as_deref(),
            recovery_key.as_deref(),
        ) {
            Ok(()) => AgentResponse::ok(json!({
                "recovered": true,
                "target_dir": target_dir,
            })),
            Err(e) => AgentResponse::err("recover_ovb", e.to_string()),
        },
        AgentRequest::VaultOpenDir { path } => {
            let mut v = st.vault.lock().await;
            match v.open_dir(std::path::PathBuf::from(path)) {
                Ok(()) => {
                    let path = v.vault_dir.to_string_lossy().to_string();
                    drop(v);
                    revoke_extension_gate(st);
                    st.pending_fills.clear();
                    st.pending_ssh_sessions.clear();
                    AgentResponse::ok(json!({"opened": true, "vault_path": path}))
                },
                Err(e) => AgentResponse::err("open_dir", e.to_string()),
            }
        }
        AgentRequest::LocalUnlockPolicySet { policy } => {
            let configured = st.vault.lock().await.load_local_unlock_policy(policy);
            AgentResponse::ok(json!({ "configured": configured }))
        }
        AgentRequest::LocalUnlockMaterial => {
            match st.vault.lock().await.local_unlock_material() {
                Ok(material) => AgentResponse::ok(json!({ "material": material })),
                Err(_) => AgentResponse::err("locked", "master password required"),
            }
        }
        AgentRequest::UnlockLocal { material } => {
            match st.vault.lock().await.unlock_local(material) {
                Ok(()) => AgentResponse::ok(json!({ "unlocked": true })),
                Err(_) => AgentResponse::err("bad_unlock", "local unlock unavailable; use master password"),
            }
        }
        AgentRequest::VerifyMasterPassword { password } => {
            match st.vault.lock().await.verify_master_password(&password) {
                Ok(()) => AgentResponse::ok(json!({ "verified": true })),
                Err(_) => AgentResponse::err("bad_unlock", "master password verification failed"),
            }
        }
        AgentRequest::SensitiveAuthGrant => {
            let mut v = st.vault.lock().await;
            if !v.unlocked || v.master_password_required() { return AgentResponse::err("locked", "master password required"); }
            v.grant_sensitive_auth();
            AgentResponse::ok(json!({ "verified": true }))
        }
        AgentRequest::CredentialSave {
            password_active_since_ms,
            request_id,
            origin,
            username,
            password,
            display_name,
            connection_host,
            linked_totp_id,
            group_id,
            website_rules,
            linked_mfa_ids,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","database not attached"); };
            let cred = match credpivot_core::insert_login_extended_in_partition(db.conn(), partition.unwrap_or(credpivot_core::partitions::PERSONAL),
                &origin,
                &username,
                &password,
                &display_name,
                &connection_host,
                linked_totp_id.as_deref().and_then(|s| opt_nonempty(s)),
                group_id.as_deref().and_then(|s| opt_nonempty(s)),
                website_rules.as_deref(),
                linked_mfa_ids.as_deref(),
                password_active_since_ms,
            ) {
                Ok(c) => c,
                Err(e) => return AgentResponse::err("vault", e.to_string()),
            };
            AgentResponse::ok(json!({
                "request_id": request_id,
                "saved": true,
                "credential": cred,
            }))
        }
        AgentRequest::BrowserCredentialUpdate { credential_id, expected_revision, origin, username, password } => {
            if !peer.from_native_host { return AgentResponse::err("forbidden", "browser only"); }
            let mut v=st.vault.lock().await;
            if !v.unlocked { return AgentResponse::err("locked", "vault locked"); }
            let Ok(cred)=v.get_credential(&credential_id) else { return AgentResponse::err("not_found", "credential not found"); };
            if !v.credential_matches_page(&credential_id,&origin) { return AgentResponse::err("origin_mismatch", "网站与凭据不匹配"); }
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked", "vault locked"); };
            let _=cred;
            match credpivot_core::update_login_from_browser(db.conn(),&credential_id,&expected_revision,&username,&password) {
                Ok(())=>{v.touch_activity();AgentResponse::ok(json!({"updated":true}))},
                Err(credpivot_core::CoreError::Conflict)=>AgentResponse::err("conflict","记录已改变，请刷新后重试"),
                Err(_)=>AgentResponse::err("vault","密码更新失败"),
            }
        }
        AgentRequest::AppCredentialPasswordUpdate { credential_id, expected_revision, username, password } => {
            let mut v = st.vault.lock().await;
            let Some(db) = v.db.as_ref() else { return AgentResponse::err("locked", "vault locked"); };
            match credpivot_core::update_login_from_browser(db.conn(), &credential_id, &expected_revision, &username, &password) {
                Ok(()) => { v.touch_activity(); AgentResponse::ok(json!({"updated":true})) },
                Err(credpivot_core::CoreError::Conflict) => AgentResponse::err("conflict", "记录已改变，请刷新后重试"),
                Err(_) => AgentResponse::err("vault", "密码更新失败"),
            }
        }
        AgentRequest::BrowserMfaSuggest { origin, credential_id, include_other_matches } => {
            let v = st.vault.lock().await;
            if !v.unlocked { return AgentResponse::err("locked", "vault locked"); }
            let Some(db) = v.db.as_ref() else { return AgentResponse::err("locked", "vault locked"); };
            match credpivot_core::browser_mfa_candidates(db.conn(), &origin, opt_nonempty(&credential_id), include_other_matches) {
                Ok(payload) => AgentResponse::ok(payload),
                Err(_) => AgentResponse::err("vault", "MFA 候选读取失败"),
            }
        }
        AgentRequest::BrowserTotpCode { credential_id, origin, totp_id } => {
            if !peer.from_native_host { return AgentResponse::err("forbidden", "browser only"); }
            let mut v=st.vault.lock().await;
            if !v.unlocked { return AgentResponse::err("locked", "vault locked"); }
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","vault locked"); };
            if !credential_id.is_empty() && !v.credential_matches_page(&credential_id, &origin) {
                return AgentResponse::err("origin_mismatch", "账号与网站不匹配");
            }
            if !credential_id.is_empty() && !credpivot_core::partitions::same_credentials(db.conn(),&credential_id,&totp_id).unwrap_or(false) {
                return AgentResponse::err("forbidden","partitions.errors.crossLink");
            }
            // 明确选择 MFA 后仅验证该记录；不为读取验证码重新扫描全库。
            if totp_id.is_empty() { return AgentResponse::err("bad_args", "请选择当前网站的 MFA"); }
            if !credpivot_core::mfa_matches_origin(db.conn(), &totp_id, &origin).unwrap_or(false) {
                return AgentResponse::err("origin_mismatch", "MFA 与网站不匹配");
            }
            let id = totp_id;
            match credpivot_core::manage_credentials(db.conn(),credpivot_core::VaultAction::TotpStatus {id,min_valid_seconds:5,passive:false}) {
                Ok(payload)=>{v.touch_activity();AgentResponse::ok(payload)},Err(_)=>AgentResponse::err("vault","MFA 读取失败"),
            }
        }
        AgentRequest::CredentialSuggest { origin } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let items = match v.suggest_for_origin(&origin) {
                Ok(c) => c,
                Err(e) => return AgentResponse::err("vault", e.to_string()),
            };
            let items: Vec<_> = items.into_iter().map(|item| {
                let revision = v.db.as_ref().and_then(|db| db.get_login(&item.id).ok()).map(|r| r.current_revision);
                let mut value = json!(item);
                value["current_revision"] = json!(revision);
                value.as_object_mut().unwrap().remove("password");
                value
            }).collect();
            AgentResponse::ok(json!({ "candidates": items }))
        }
        AgentRequest::CredentialFillPrepare {
            request_id,
            credential_id,
            origin,
            tab_id,
            frame_id,
            document_id,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            if v.get_credential(&credential_id).is_err() {
                return AgentResponse::err("not_found", "credential not found");
            }
            if !v.credential_matches_page(&credential_id, &origin) {
                return AgentResponse::err("origin_mismatch", "credential does not match page origin");
            }
            let now = now_ms();
            // 页面跳转或面板关闭后可能不再 consume，过期授权不能永久留在内存。
            st.pending_fills.retain(|_, grant| grant.expires_at_ms > now);
            let grant = FillGrant {
                request_id: request_id.clone(),
                credential_id,
                origin,
                tab_id,
                frame_id,
                document_id,
                expires_at_ms: now + FILL_TTL_MS,
            };
            let rid = grant.request_id.clone();
            st.pending_fills.insert(rid.clone(), grant);
            AgentResponse::ok(json!({ "prepared": true, "request_id": rid }))
        }
        AgentRequest::CredentialFillConsume {
            request_id,
            frame_id,
            document_id,
            origin,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let grant = st.pending_fills.remove(&request_id);
            let grant = match grant {
                Some(g) => g,
                None => return AgentResponse::err("request_gone", "unknown or cancelled request"),
            };
            if now_ms() > grant.expires_at_ms {
                return AgentResponse::err("request_gone", "fill grant expired");
            }
            if grant.frame_id != frame_id || grant.document_id != document_id {
                return AgentResponse::err("frame_mismatch", "frame/document mismatch");
            }
            if grant.origin != origin {
                return AgentResponse::err("origin_mismatch", "origin mismatch");
            }
            match v.get_credential(&grant.credential_id) {
                Ok(c) => {
                    if !v.credential_matches_page(&grant.credential_id, &grant.origin) {
                        return AgentResponse::err("origin_mismatch", "credential origin mismatch");
                    }
                    if let Some(db)=v.db.as_ref() { let _=credpivot_core::record_credential_use(db.conn(),&grant.credential_id); }
                    let totp_code: Option<String> = None;
                    AgentResponse::ok(json!({
                    "username": c.username,
                    "password": c.password,
                    "origin": c.origin,
                    "linked_totp_id": c.linked_totp_id,
                    "totp_code": totp_code,
                }))
                }
                Err(_) => AgentResponse::err("not_found", "credential not found"),
            }
        }
        AgentRequest::CancelRequest { request_id } => {
            st.pending_fills.remove(&request_id);
            AgentResponse::ok(json!({ "cancelled": true }))
        }
        AgentRequest::CredentialGet { credential_id } => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.get_credential(&credential_id) {
                Ok(c) => {
                    if let Some(db)=v.db.as_ref() { let _=credpivot_core::record_credential_use(db.conn(),&credential_id); }
                    AgentResponse::ok(json!({"id":c.id,"origin":c.origin,"username":c.username,"password":c.password}))
                },
                Err(e) => AgentResponse::err("not_found", e.to_string()),
            }
        }
        AgentRequest::CredentialList { query, limit, offset } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let lim = limit.unwrap_or(100);
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","database not attached"); };
            match credpivot_core::list_logins_page_in_partition(db.conn(), query.as_deref(), lim, offset, partition) {
                Ok(items) => AgentResponse::ok(json!({ "items": items })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::CredentialUpdate {
            credential_id,
            expected_revision,
            origin,
            username,
            display_name,
            group_id,
            connection_host,
            linked_totp_id,
            password,
            website_rules,
            linked_mfa_ids,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.update_credential(
                &credential_id,
                &expected_revision,
                &origin,
                &username,
                &display_name,
                &connection_host,
                opt_nonempty(&linked_totp_id),
                opt_nonempty(&group_id),
                password.as_deref(),
                website_rules.as_deref(),
                linked_mfa_ids.as_deref(),
            ) {
                Ok(row) => AgentResponse::ok(json!({ "updated": true, "item": row })),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("revision conflict") {
                        AgentResponse::err("conflict", msg)
                    } else {
                        AgentResponse::err("vault", msg)
                    }
                }
            }
        }
        AgentRequest::CredentialTrash { item_id } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.trash_credential_item(&item_id) {
                Ok(()) => AgentResponse::ok(json!({ "trashed": true })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::VaultManage { action } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked { return AgentResponse::err("locked", "vault locked"); }
            let revoke_ssh=matches!(&action,credpivot_core::VaultAction::SshGitForget {..} | credpivot_core::VaultAction::SshGitRechoose {..});
            if !action.is_passive() { v.touch_activity(); }
            // 导入和永久删除前保留可恢复快照，且失败时不执行危险操作。
            if matches!(&action, credpivot_core::VaultAction::BitwardenImport { .. } | credpivot_core::VaultAction::GoogleImport { .. } | credpivot_core::VaultAction::TrashPurge { .. } | credpivot_core::VaultAction::PartitionMoveApply {..}) {
                let (Some(vmk), Some(db)) = (v.vmk.as_ref(), v.db.as_ref()) else { return AgentResponse::err("locked", "vault locked"); };
                if credpivot_core::create_restore_point_for_risky_op(&v.vault_dir, &**vmk, db.conn()).is_err() {
                    return AgentResponse::err("backup", "操作前的恢复点创建失败");
                }
            }
            let result = match v.db.as_ref() {
                Some(db) => match (partition,action) {
                    (Some(partition),credpivot_core::VaultAction::NoteCreate {title,text}) => credpivot_core::partitions::create_note(db.conn(),partition,&title,&text),
                    (Some(partition),credpivot_core::VaultAction::SshImport {label,pem,passphrase}) => credpivot_core::partitions::import_ssh_key(db.conn(),partition,&label,&pem,&passphrase),
                    (_,action) => credpivot_core::manage_credentials(db.conn(),action),
                },
                None => return AgentResponse::err("locked", "database not attached"),
            };
            match result {
                Ok(payload) => {
                    if revoke_ssh { v.ssh_authorization.clear(); }
                    AgentResponse::ok(payload)
                }
                Err(credpivot_core::CoreError::Conflict) => AgentResponse::err("conflict", "记录已改变，请刷新重试"),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::SecuritySummary => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.security_summary() {
                Ok(s) => AgentResponse::ok(json!({ "summary": s })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::ImportBitwarden { json } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.import_bitwarden(&json) {
                Ok(report) => AgentResponse::ok(json!({ "report": report })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::TotpList => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.list_totp() {
                Ok(items) => AgentResponse::ok(json!({ "items": items })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::TotpCreate {
            issuer,
            account,
            secret_base32,
            group_id,
            website_rules,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let result=(|| -> credpivot_core::Result<credpivot_core::TotpListRow> {
                let db=v.db.as_ref().ok_or_else(||credpivot_core::CoreError::format("database not attached"))?;
                let id=credpivot_core::insert_totp_with_rules_in_partition(db.conn(),partition.unwrap_or(credpivot_core::partitions::PERSONAL),
                &issuer,
                &account,
                &secret_base32,
                group_id.as_deref().and_then(|s| opt_nonempty(s)),
                &website_rules)?;
                db.list_totp()?.into_iter().find(|row|row.id==id).ok_or_else(||credpivot_core::CoreError::format("MFA not found"))
            })();
            match result {
                Ok(row) => AgentResponse::ok(json!({ "item": row })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::TotpReveal { totp_id } => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.totp_reveal(&totp_id) {
                Ok(reveal) => AgentResponse::ok(json!({ "reveal": reveal })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::TotpCode { totp_id } => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.totp_code(&totp_id) {
                Ok(code) => AgentResponse::ok(json!({ "code": code })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::SshKeyList => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.list_ssh_keys() {
                Ok(items) => AgentResponse::ok(json!({
                    "items": items,
                    "storage_path": v.vault_dir.join(credpivot_core::DB_FILENAME).to_string_lossy(),
                    "agent_socket": crate::paths::ssh_agent_socket_path().to_string_lossy(),
                })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::SshKeyGenerate {
            label,
            set_default,
            group_id,
            comment,
            sign_policy,
            git_rules,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let def = set_default.unwrap_or(false);
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","database not attached"); };
            match credpivot_core::generate_ssh_key_with_options_in_partition(db.conn(), partition.unwrap_or(credpivot_core::partitions::PERSONAL),
                &label,
                def,
                group_id.as_deref().and_then(|s| opt_nonempty(s)),
                &comment,
                &sign_policy,
                &git_rules,
            ) {
                Ok(row) => match v.sync_ssh_from_db() {
                    Ok(()) => AgentResponse::ok(json!({"item":row})),
                    Err(e) => AgentResponse::err("vault",e.to_string()),
                },
                Err(e) => AgentResponse::err("vault", e.to_string().trim_start_matches("invalid format: ")),
            }
        }
        AgentRequest::SshSelectKey { key_id } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.select_ssh_key(&key_id) {
                Ok(()) => AgentResponse::ok(json!({ "selected": key_id })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::SshSessionPrepare {
            host,
            port,
            user,
            login_credential_id,
            totp_id,
        } => {
            if peer.from_native_host {
                return AgentResponse::err("forbidden", "extension cannot prepare ssh session");
            }
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            if host.trim().is_empty() || user.trim().is_empty() || login_credential_id.trim().is_empty()
            {
                return AgentResponse::err("bad_args", "host, user and login_credential_id required");
            }
            if v.get_credential(&login_credential_id).is_err() {
                return AgentResponse::err("not_found", "login credential not found");
            }
            let totp = totp_id.filter(|s| !s.trim().is_empty());
            if let Some(totp)=&totp {
                let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","vault locked"); };
                if !credpivot_core::partitions::same_credentials(db.conn(),&login_credential_id,totp).unwrap_or(false) {
                    return AgentResponse::err("forbidden","partitions.errors.crossLink");
                }
            }
            let session_id = prepare_session(
                &mut st.pending_ssh_sessions,
                &host,
                port,
                &user,
                &login_credential_id,
                totp,
            );
            AgentResponse::ok(json!({
                "session_id": session_id,
                "expires_in_ms": SSH_SESSION_TTL_MS,
            }))
        }
        AgentRequest::SshAskpass {
            session_id,
            prompt,
            force_kind,
        } => {
            if !peer.from_askpass {
                return AgentResponse::err("peer_denied", "ssh askpass requires credpivot-askpass peer");
            }
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match consume_askpass_secret(
                &mut st.pending_ssh_sessions,
                &mut v,
                &session_id,
                &prompt,
                force_kind.as_deref(),
            ) {
                Ok(secret) => AgentResponse::ok(json!({ "secret": secret })),
                Err(e) => AgentResponse::err("askpass_denied", e.to_string()),
            }
        }
        AgentRequest::RecoveryCodesList => {
            let v = st.vault.lock().await;
            if !v.unlocked { return AgentResponse::err("locked", "vault locked"); }
            match v.list_recovery_codes() {
                Ok(items) => {
                    // 列表仅返回元数据，二次验证后再按条目读取恢复码。
                    let items: Vec<_> = items.into_iter().map(|item| {
                        let recovery_id = item.id.clone();
                        let mut value = json!(item);
                        let count = value["codes"].as_array().map_or(0, Vec::len);
                        value.as_object_mut().unwrap().remove("codes");
                        value["code_count"] = json!(count);
                        let (total, remaining) = v.db.as_ref().and_then(|db| db.conn().query_row(
                            "SELECT COUNT(*),COALESCE(SUM(used_at_ms IS NULL),0) FROM recovery_code_entries WHERE recovery_id=?1",
                            [&recovery_id], |r| Ok((r.get::<_, i64>(0)?,r.get::<_, i64>(1)?))).ok()).unwrap_or((count as i64,0));
                        value["code_count"] = json!(total);
                        value["remaining_count"] = json!(remaining);
                        value
                    }).collect();
                    AgentResponse::ok(json!({ "items": items }))
                }
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::RecoveryCodesGet { id } => {
            let v = st.vault.lock().await;
            if !v.unlocked { return AgentResponse::err("locked", "vault locked"); }
            match v.list_recovery_codes() {
                Ok(items) => match items.into_iter().find(|item| item.id == id) {
                    Some(item) => AgentResponse::ok(json!({ "item": item })),
                    None => AgentResponse::err("not_found", "recovery codes not found"),
                },
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::RecoveryCodesCreate { service_name, codes } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","database not attached"); };
            match credpivot_core::insert_recovery_codes_in_partition(db.conn(), partition.unwrap_or(credpivot_core::partitions::PERSONAL),&service_name, &codes) {
                Ok(row) => AgentResponse::ok(json!({ "item": row })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::RecoveryCodesUpdate {
            id,
            expected_revision,
            service_name,
            codes,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.update_recovery_codes(&id, &expected_revision, &service_name, &codes) {
                Ok(row) => AgentResponse::ok(json!({ "item": row })),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("revision conflict") {
                        AgentResponse::err("conflict", msg)
                    } else {
                        AgentResponse::err("vault", msg)
                    }
                }
            }
        }
        AgentRequest::RestorePointsList => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.list_restore_points() {
                Ok(points) => AgentResponse::ok(json!({ "points": points })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::RestorePointRecover {
            created_at_ms,
            target_dir,
            password,
        } => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.recover_restore_point(created_at_ms, &target_dir, password.as_deref()) {
                Ok(()) => AgentResponse::ok(json!({ "recovered": true, "target_dir": target_dir })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::VaultMigrate { target_dir } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.migrate_vault_to(&target_dir) {
                Ok(()) => AgentResponse::ok(json!({ "migrated": true, "vault_path": target_dir })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::VaultSecurityRebuild { password, recovery_key } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.security_rebuild(&password, &recovery_key) {
                Ok(new_recovery_key) => {
                    let warning = if v.unlocked { None } else {
                        Some("安全重建已完成，但会话恢复失败。请先保存新的恢复密钥，再重新解锁保险库。")
                    };
                    drop(v);
                    revoke_extension_gate(st);
                    st.pending_ssh_sessions.clear();
                    AgentResponse::ok(json!({
                        "rebuilt": true,
                        "new_recovery_key": new_recovery_key,
                        "warning": warning,
                    }))
                }
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::BackupStatus => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.backup_status() {
                Ok(s) => AgentResponse::ok(json!({ "status": s })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::VaultVerifyOvb { ovb_path, password } => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.verify_ovb_file(&ovb_path, &password) {
                Ok(()) => AgentResponse::ok(json!({ "verified": true })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::VaultExportJson { output_path, password } => {
            let mut v = st.vault.lock().await;
            match v.export_json(&output_path, &password) {
                Ok(()) => AgentResponse::ok(json!({"exported": true})),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::VaultImportJson { input_path, target_dir, password } => {
            // 持有会话锁，避免导入途中其他请求切换当前保险库。
            let _v = st.vault.lock().await;
            let result = (|| -> credpivot_core::Result<String> {
                let file = std::fs::File::open(&input_path).map_err(|_| credpivot_core::CoreError::format("无法读取明文文件"))?;
                use std::io::Read;
                let mut json = String::new();
                file.take(64 * 1024 * 1024 + 1).read_to_string(&mut json).map_err(|_| credpivot_core::CoreError::format("无法读取明文文件"))?;
                if json.len() > 64 * 1024 * 1024 { return Err(credpivot_core::CoreError::limit("明文文件最大 64 MiB")); }
                credpivot_core::import_logical_json_to_dir(&json, std::path::Path::new(&target_dir), &password)
            })();
            match result {
                Ok(key) => AgentResponse::ok(json!({"imported":true,"new_recovery_key":key})),
                Err(_) => AgentResponse::err("vault", "导入失败：请检查文件格式与版本、新主密码长度及目标目录是否为空"),
            }
        }
        AgentRequest::VaultResetRecoveryKey { password, recovery_key } => {
            let mut v = st.vault.lock().await;
            match v.reset_recovery_key(&password, &recovery_key) {
                Ok(key) => {
                    drop(v);
                    revoke_extension_gate(st);
                    st.pending_ssh_sessions.clear();
                    AgentResponse::ok(json!({"new_recovery_key": key}))
                },
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::VaultVerifyRecoveryKey { recovery_key } => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.verify_recovery_key(&recovery_key) {
                Ok(()) => AgentResponse::ok(json!({ "verified": true })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::CredentialGroupList { scope } => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.list_credential_groups(&scope) {
                Ok(items) => AgentResponse::ok(json!({ "items": items })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::CredentialGroupCreate { scope, name } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","database not attached"); };
            match credpivot_core::create_credential_group_in_partition(db.conn(), partition.unwrap_or(credpivot_core::partitions::PERSONAL),&scope, &name) {
                Ok(item) => AgentResponse::ok(json!({ "item": item })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::CredentialGroupDelete { id } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.delete_credential_group(&id) {
                Ok(()) => AgentResponse::ok(json!({ "deleted": true })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::CredentialItemSetGroup { item_id, group_id } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.set_item_group(&item_id, opt_nonempty(&group_id)) {
                Ok(()) => AgentResponse::ok(json!({ "updated": true })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::ServerProfileList => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.list_server_profiles() {
                Ok(items) => AgentResponse::ok(json!({ "items": items })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::ServerProfileCreate {
            label,
            host,
            port,
            manual_username,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            group_id,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let Some(db)=v.db.as_ref() else { return AgentResponse::err("locked","database not attached"); };
            match credpivot_core::insert_server_profile_in_partition(db.conn(), partition.unwrap_or(credpivot_core::partitions::PERSONAL),
                &label,
                &host,
                port,
                &manual_username,
                linked_login_id.as_deref().and_then(|s| opt_nonempty(s)),
                linked_totp_id.as_deref().and_then(|s| opt_nonempty(s)),
                linked_ssh_key_id.as_deref().and_then(|s| opt_nonempty(s)),
                group_id.as_deref().and_then(|s| opt_nonempty(s)),
            ) {
                Ok(item) => AgentResponse::ok(json!({ "item": item })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::ServerProfileUpdate {
            id,
            expected_revision,
            label,
            host,
            port,
            manual_username,
            linked_login_id,
            linked_totp_id,
            linked_ssh_key_id,
            group_id,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.update_server_profile(
                &id,
                &expected_revision,
                &label,
                &host,
                port,
                &manual_username,
                opt_nonempty(&linked_login_id),
                opt_nonempty(&linked_totp_id),
                opt_nonempty(&linked_ssh_key_id),
                opt_nonempty(&group_id),
            ) {
                Ok(item) => AgentResponse::ok(json!({ "item": item })),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("revision conflict") || msg.contains("Conflict") {
                        AgentResponse::err("conflict", msg)
                    } else {
                        AgentResponse::err("vault", msg)
                    }
                }
            }
        }
        AgentRequest::DiagnosticLogTail { max_lines, file } => {
            let lines = max_lines.clamp(1, 2000);
            match crate::diagnostics::read_log(file.as_deref(), lines) {
                Ok((path, text, files)) => AgentResponse::ok(json!({
                    "file": path.file_name().and_then(|v| v.to_str()),
                    "path": path.to_string_lossy(), "files": files,
                    "text": text, "order": "newest_first",
                    "level": crate::diagnostics::level(),
                })),
                Err(_) => AgentResponse::err("diagnostics", "log file unavailable"),
            }
        }
        AgentRequest::DiagnosticLogSetLevel { level } => {
            match crate::diagnostics::set_level(level) {
                Ok(()) => {
                    crate::diagnostics::info("diagnostics", "log level updated");
                    AgentResponse::ok(json!({ "level": level }))
                }
                Err(_) => AgentResponse::err("log_config", "日志级别保存失败"),
            }
        }
    };
    if bump_gate_activity && matches!(&resp, AgentResponse::Ok { .. }) {
        touch_extension_gate_native_activity(st);
    }
    resp
}

fn opt_nonempty(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t)
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn peer_pid(stream: &tokio::net::UnixStream) -> Result<u32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut uid = 0u32;
    let mut gid = 0u32;
    let mut pid = 0i32;
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return Err(AgentError::PeerDenied("getpeereid failed".into()));
    }
    // macOS also exposes peer pid via LOCAL_PEERPID if available; use getsockopt
    #[cfg(target_os = "macos")]
    {
        let mut p: i32 = 0;
        let mut len = std::mem::size_of::<i32>() as u32;
        const LOCAL_PEERPID: i32 = 0x002;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                LOCAL_PEERPID,
                &mut p as *mut _ as *mut _,
                &mut len,
            )
        };
        if rc == 0 {
            pid = p;
        }
    }
    if pid <= 0 {
        return Err(AgentError::PeerDenied("could not read peer pid".into()));
    }
    Ok(pid as u32)
}

#[cfg(not(any(target_os = "macos", target_os = "android")))]
fn peer_pid(_stream: &tokio::net::UnixStream) -> Result<u32> {
    // Android 仅允许进程内调用，不能把缺少桌面进程身份校验解释为授权成功。
    Err(AgentError::PeerDenied("external IPC is unavailable on this platform".into()))
}
