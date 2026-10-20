use crate::error::{AgentError, Result};
use crate::peer_auth::{authorize_peer, PeerAuthConfig};
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

pub struct IpcState {
    pub vault: Arc<Mutex<VaultSession>>,
    pub pending_fills: HashMap<String, FillGrant>,
    pub peer_auth: PeerAuthConfig,
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
    {
        let cfg = state.lock().await.peer_auth.clone();
        authorize_peer(peer_pid, &cfg)?;
    }

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
        handle_request(&mut st, req).await
    };

    let body = serde_json::to_vec(&resp).map_err(|e| AgentError::Protocol(e.to_string()))?;
    let frame_len = (body.len() as u32).to_le_bytes();
    stream.write_all(&frame_len).await?;
    stream.write_all(&body).await?;
    Ok(())
}

pub async fn handle_request(st: &mut IpcState, req: AgentRequest) -> AgentResponse {
    {
        let mut v = st.vault.lock().await;
        if v.unlocked {
            let _ = v.try_restore_point_if_due();
        }
    }
    match req {
        AgentRequest::Ping => AgentResponse::ok(json!({ "pong": true })),
        AgentRequest::Status => {
            let v = st.vault.lock().await;
            AgentResponse::ok(v.vault_status_json())
        }
        AgentRequest::Lock => {
            st.vault.lock().await.lock();
            st.pending_fills.clear();
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
            if cred.origin != origin {
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
                    if c.origin != grant.origin {
                        return AgentResponse::err("origin_mismatch", "credential origin mismatch");
                    }
                    AgentResponse::ok(json!({
                    "username": c.username,
                    "password": c.password,
                    "origin": c.origin,
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
        AgentRequest::SshKeyGenerate { label, set_default } => {
            let mut v = st.vault.lock().await;
            if !v.unlocked {
                return AgentResponse::err("locked", "vault locked");
            }
            v.touch_activity();
            let def = set_default.unwrap_or(false);
            match v.generate_ssh_key(&label, def) {
                Ok(row) => AgentResponse::ok(json!({ "item": row })),
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
    }
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
