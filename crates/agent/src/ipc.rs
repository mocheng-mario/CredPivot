use crate::extension_gate::{
    clear_persisted_extension_gate, extension_gate_idle_secs, persist_extension_gate_until,
    read_persisted_extension_gate_until,
};
use crate::error::{AgentError, Result};
use crate::peer_auth::{
    authorize_peer, peer_executable_path, peer_is_native_host_executable, PeerAuthConfig,
};
use crate::session_guard::expire_idle_session;
use crate::protocol::{AgentRequest, AgentResponse};
use crate::vault_session::{FillGrant, VaultSession};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

const FILL_TTL_MS: u128 = 60_000;

#[derive(Debug, Clone, Copy, Default)]
pub struct RequestPeerContext {
    /// Chrome Native Messaging host 经 Unix socket 发起的请求。
    pub from_native_host: bool,
}

pub struct IpcState {
    pub vault: Arc<Mutex<VaultSession>>,
    pub pending_fills: HashMap<String, FillGrant>,
    pub peer_auth: PeerAuthConfig,
    /// 扩展经 native-host 访问敏感数据的截止时间（毫秒）。
    pub extension_gate_expires_ms: u128,
    /// 最近一次扩展（native-host）敏感操作时间（毫秒）。
    pub extension_gate_last_native_ms: u128,
    pub shutting_down: bool,
}

fn extension_gate_active(st: &IpcState) -> bool {
    now_ms() <= st.extension_gate_expires_ms
}

fn maybe_expire_extension_gate_idle(st: &mut IpcState) {
    if st.extension_gate_expires_ms == 0 {
        return;
    }
    let idle_ms = extension_gate_idle_secs() as u128 * 1000;
    let last = st.extension_gate_last_native_ms;
    if last > 0 && now_ms() > last + idle_ms {
        st.extension_gate_expires_ms = 0;
        clear_persisted_extension_gate();
    }
}

fn grant_extension_gate(st: &mut IpcState, ttl_secs: u64) {
    let ttl = ttl_secs.max(1);
    let until = now_ms() + ttl as u128 * 1000;
    st.extension_gate_expires_ms = until;
    st.extension_gate_last_native_ms = now_ms();
    let _ = persist_extension_gate_until(until);
}

fn touch_extension_gate_native_activity(st: &mut IpcState) {
    if !extension_gate_active(st) {
        return;
    }
    st.extension_gate_last_native_ms = now_ms();
    let extend = now_ms() + extension_gate_idle_secs() as u128 * 1000;
    if extend > st.extension_gate_expires_ms {
        st.extension_gate_expires_ms = extend;
        let _ = persist_extension_gate_until(extend);
    }
}

pub fn load_extension_gate_into_state(st: &mut IpcState) {
    let until = read_persisted_extension_gate_until();
    if until > now_ms() {
        st.extension_gate_expires_ms = until;
        if st.extension_gate_last_native_ms == 0 {
            st.extension_gate_last_native_ms = now_ms();
        }
    }
}

fn req_requires_extension_gate(req: &AgentRequest) -> bool {
    matches!(
        req,
        AgentRequest::CredentialSave { .. }
            | AgentRequest::CredentialSuggest { .. }
            | AgentRequest::CredentialFillPrepare { .. }
            | AgentRequest::CredentialFillConsume { .. }
            | AgentRequest::CredentialGet { .. }
            | AgentRequest::TotpCode { .. }
    )
}

pub async fn serve_ipc(listener: UnixListener, state: Arc<Mutex<IpcState>>) -> Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_ipc_connection(&mut stream, state).await {
                tracing::debug!("ipc connection ended: {e}");
            }
        });
    }
}

async fn handle_ipc_connection(
    stream: &mut tokio::net::UnixStream,
    state: Arc<Mutex<IpcState>>,
) -> Result<()> {
    let peer_pid = peer_pid(stream)?;
    let from_native_host = {
        let cfg = state.lock().await.peer_auth.clone();
        authorize_peer(peer_pid, &cfg)?;
        #[cfg(target_os = "macos")]
        {
            let path = peer_executable_path(peer_pid)?;
            peer_is_native_host_executable(&path, &cfg)
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    };
    let peer = RequestPeerContext {
        from_native_host,
    };

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

    expire_idle_session(&state).await;
    let resp = {
        let mut st = state.lock().await;
        handle_request(&mut st, req, peer).await
    };

    let body = serde_json::to_vec(&resp).map_err(|e| AgentError::Protocol(e.to_string()))?;
    let frame_len = (body.len() as u32).to_le_bytes();
    stream.write_all(&frame_len).await?;
    stream.write_all(&body).await?;
    Ok(())
}

pub async fn handle_request(
    st: &mut IpcState,
    req: AgentRequest,
    peer: RequestPeerContext,
) -> AgentResponse {
    if st.shutting_down {
        return AgentResponse::err("shutting_down", "agent is shutting down");
    }
    {
        let mut v = st.vault.lock().await;
        if v.unlocked {
            let _ = v.try_restore_point_if_due();
        }
    }
    maybe_expire_extension_gate_idle(st);
    if peer.from_native_host && req_requires_extension_gate(&req) {
        if !extension_gate_active(st) {
            let _ = crate::paths::touch_extension_gate_pending_if_absent();
            return AgentResponse::err(
                "extension_gate_required",
                "请在 CredPivot App 中完成指纹确认后重试",
            );
        }
    }
    let bump_gate_activity = peer.from_native_host && req_requires_extension_gate(&req);
    let resp = match req {
        AgentRequest::Ping => AgentResponse::ok(json!({ "pong": true })),
        AgentRequest::ExtensionConnect => {
            let v = st.vault.lock().await;
            let unlocked = v.unlocked;
            let gate = extension_gate_active(st);
            if unlocked && !gate {
                let _ = crate::paths::touch_extension_gate_pending_if_absent();
                return AgentResponse::err(
                    "extension_gate_required",
                    "请在 CredPivot App 中完成指纹或系统密码确认",
                );
            }
            AgentResponse::ok(json!({
                "connected": true,
                "unlocked": unlocked,
                "extension_gate_active": gate,
                "extension_gate_idle_secs": extension_gate_idle_secs(),
            }))
        }
        AgentRequest::ExtensionGateGrant { ttl_secs } => {
            if peer.from_native_host {
                return AgentResponse::err("peer_denied", "extension gate grant from app only");
            }
            let idle = extension_gate_idle_secs();
            let ttl = if ttl_secs == 0 { idle } else { ttl_secs };
            grant_extension_gate(st, ttl);
            let _ = crate::paths::clear_extension_gate_pending();
            AgentResponse::ok(json!({
                "extension_gate_active": true,
                "expires_in_secs": ttl,
                "idle_secs": idle,
            }))
        }
        AgentRequest::Status => {
            let v = st.vault.lock().await;
            let mut payload = v.vault_status_json();
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "extension_gate_active".into(),
                    json!(extension_gate_active(st)),
                );
                obj.insert(
                    "extension_gate_idle_secs".into(),
                    json!(extension_gate_idle_secs()),
                );
            }
            AgentResponse::ok(payload)
        }
        AgentRequest::Lock => {
            st.vault.lock().await.lock();
            st.pending_fills.clear();
            st.extension_gate_expires_ms = 0;
            st.extension_gate_last_native_ms = 0;
            clear_persisted_extension_gate();
            AgentResponse::ok(json!({ "locked": true }))
        }
        AgentRequest::UnlockPassword { password } => {
            match st.vault.lock().await.unlock_password(&password) {
                Ok(()) => AgentResponse::ok(json!({ "unlocked": true })),
                Err(e) => AgentResponse::err("bad_unlock", e.to_string()),
            }
        }
        AgentRequest::VaultCreate { password } => {
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
                Ok(()) => AgentResponse::ok(json!({ "changed": true })),
                Err(e) => AgentResponse::err("change_password", e.to_string()),
            }
        }
        AgentRequest::VaultExportOvb { output_path, password } => {
            let v = st.vault.lock().await;
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
                Ok(()) => AgentResponse::ok(json!({
                    "opened": true,
                    "vault_path": v.vault_dir.to_string_lossy(),
                })),
                Err(e) => AgentResponse::err("open_dir", e.to_string()),
            }
        }
        AgentRequest::UnlockTouchIdToken { token } => {
            let bytes = token.into_bytes();
            if st.vault.lock().await.unlock_touch_id_token(&bytes) {
                AgentResponse::ok(json!({ "unlocked": true, "via": "touch_id_gate" }))
            } else {
                AgentResponse::err("bad_unlock", "touch id token mismatch")
            }
        }
        AgentRequest::SetTouchIdToken { token } => {
            // M0：仅配置本机门槛令牌，可在锁定状态预置。
            st.vault.lock().await.touch_id_wrapped_token = Some(token.into_bytes());
            AgentResponse::ok(json!({ "configured": true }))
        }
        AgentRequest::CredentialSave {
            request_id,
            origin,
            username,
            password,
            display_name,
            connection_host,
            linked_totp_id,
            group_id,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let cred = match v.save_credential(
                &origin,
                &username,
                &password,
                &display_name,
                &connection_host,
                linked_totp_id.as_deref().and_then(|s| opt_nonempty(s)),
                group_id.as_deref().and_then(|s| opt_nonempty(s)),
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
            let cred = match v.get_credential(&credential_id) {
                Ok(c) => c,
                Err(_) => return AgentResponse::err("not_found", "credential not found"),
            };
            if !VaultSession::origin_matches_credential_page(&cred.origin, &origin) {
                return AgentResponse::err("origin_mismatch", "credential does not match page origin");
            }
            let now = now_ms();
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
                    if !VaultSession::origin_matches_credential_page(&c.origin, &grant.origin) {
                        return AgentResponse::err("origin_mismatch", "credential origin mismatch");
                    }
                    let totp_code = c
                        .linked_totp_id
                        .as_deref()
                        .and_then(|id| v.totp_code(id).ok());
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
                Ok(c) => AgentResponse::ok(json!({
                    "id": c.id,
                    "origin": c.origin,
                    "username": c.username,
                    "password": c.password,
                })),
                Err(e) => AgentResponse::err("not_found", e.to_string()),
            }
        }
        AgentRequest::CredentialList { query, limit } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let lim = limit.unwrap_or(100);
            match v.list_credentials(query.as_deref(), lim) {
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
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.create_totp(
                &issuer,
                &account,
                &secret_base32,
                group_id.as_deref().and_then(|s| opt_nonempty(s)),
            ) {
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
                Ok(items) => AgentResponse::ok(json!({ "items": items })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::SshKeyGenerate {
            label,
            set_default,
            group_id,
        } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let def = set_default.unwrap_or(false);
            match v.generate_ssh_key(
                &label,
                def,
                group_id.as_deref().and_then(|s| opt_nonempty(s)),
            ) {
                Ok(row) => AgentResponse::ok(json!({ "item": row })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
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
        AgentRequest::RecoveryCodesList => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.list_recovery_codes() {
                Ok(items) => AgentResponse::ok(json!({ "items": items })),
                Err(e) => AgentResponse::err("vault", e.to_string()),
            }
        }
        AgentRequest::RecoveryCodesCreate { service_name, codes } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            match v.create_recovery_codes(&service_name, &codes) {
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
        } => {
            let v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            match v.recover_restore_point(created_at_ms, &target_dir) {
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
                Ok(new_recovery_key) => AgentResponse::ok(json!({
                    "rebuilt": true,
                    "new_recovery_key": new_recovery_key,
                })),
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
            match v.create_credential_group(&scope, &name) {
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
            match v.create_server_profile(
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
        AgentRequest::DiagnosticLogTail { max_lines } => {
            let lines = max_lines.clamp(1, 2000);
            let text = crate::diagnostics::tail_lines(lines);
            AgentResponse::ok(json!({
                "path": crate::diagnostics::log_file_path().to_string_lossy(),
                "text": text,
            }))
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

#[cfg(unix)]
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

#[cfg(not(unix))]
fn peer_pid(_stream: &tokio::net::UnixStream) -> Result<u32> {
    Ok(0)
}
