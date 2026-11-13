use crate::{ipc::IpcState, protocol::AgentResponse, vault_session::VaultSession};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const REQUEST_TTL: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub(crate) struct PendingConnection {
    vault_id: String,
    connection_id: String,
    created: Instant,
    target: Option<Target>,
    reply: oneshot::Sender<std::result::Result<Value, String>>,
}

#[derive(Debug, Clone)]
struct Target {
    label: String,
    host: String,
    port: u16,
    user: String,
    login_id: String,
    totp_id: Option<String>,
    ssh_key_id: Option<String>,
    partition_id: String,
    connection_revision: String,
}

impl Target {
    fn matches(&self, current: &Self) -> bool {
        self.host == current.host && self.port == current.port && self.user == current.user
            && self.login_id == current.login_id && self.totp_id == current.totp_id
            && self.ssh_key_id == current.ssh_key_id && self.partition_id == current.partition_id
            && self.connection_revision == current.connection_revision
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SessionSource {
    vault_id: String,
    connection_id: String,
    target: Target,
}

impl SessionSource {
    pub(crate) fn identity_file(&self, vault: &VaultSession) -> std::result::Result<Option<std::path::PathBuf>, String> {
        identity_file(vault, self.target.ssh_key_id.as_deref())
    }

    pub(crate) fn from_request(
        vault: &VaultSession, connection_id: &str, host: &str, port: u16, user: &str,
        login_id: &str, totp_id: Option<&str>,
    ) -> std::result::Result<Self, String> {
        let current = target(vault, connection_id)?;
        if current.host != host.trim() || current.port != port || current.user.trim() != user.trim()
            || current.login_id != login_id.trim() || current.totp_id.as_deref() != totp_id
        { return Err("连接配置已变化，请重新发起连接".into()); }
        let vault_id = credpivot_core::read_vault_json(&vault.vault_dir)
            .map_err(|_| "无法读取当前保险库标识")?.vault_id;
        Ok(Self { vault_id, connection_id: connection_id.into(), target: current })
    }

    pub(crate) fn validate(&self, vault: &VaultSession) -> std::result::Result<(), String> {
        if !vault_matches(vault, &self.vault_id) { return Err("保险库已切换，连接会话已失效".into()); }
        let current = target(vault, &self.connection_id)?;
        if !self.target.matches(&current) { return Err("连接配置已变化，连接会话已失效".into()); }
        Ok(())
    }

    pub(crate) fn password(&self, vault: &VaultSession) -> std::result::Result<String, String> {
        let db = vault.db.as_ref().ok_or("保险库未就绪")?;
        let (unavailable, secret, _) = credpivot_core::connection_auth(db.conn(), &self.connection_id).map_err(|e| e.to_string())?;
        if unavailable { return Err("连接已停用，连接会话已失效".into()); }
        Ok(secret)
    }
}

fn vault_matches(vault: &VaultSession, id: &str) -> bool {
    credpivot_core::read_vault_json(&vault.vault_dir).is_ok_and(|config| config.vault_id == id)
}

fn target(vault: &VaultSession, id: &str) -> std::result::Result<Target, String> {
    if !vault.unlocked { return Err("保险库已锁定，请重新执行连接命令".into()); }
    let db = vault.db.as_ref().ok_or("保险库未就绪")?;
    let row = db.list_server_profiles().map_err(|e| e.to_string())?.into_iter()
        .find(|row| row.id == id).ok_or("连接已删除或不存在")?;
    if row.unavailable {
        return Err("这条连接已停用，请在 App 中重新配置后再连接".into());
    }
    let partition_id = credpivot_core::partitions::item_partition(db.conn(), &row.item_id).map_err(|e| e.to_string())?;
    let login_id = row.linked_login_id.filter(|id| !id.is_empty()).unwrap_or_default();
    let user: String = if login_id.is_empty() {
        row.manual_username.clone()
    } else {
        db.conn().query_row(
            "SELECT l.username FROM login_credentials l JOIN items a ON a.id=l.item_id
             JOIN items s ON s.id=?2 WHERE l.id=?1 AND a.trashed=0 AND a.partition_id=s.partition_id",
            [&login_id, &row.item_id], |r| r.get(0),
        ).map_err(|_| "关联账户已不可用")?
    };
    let totp_id = row.linked_totp_id.filter(|id| !id.is_empty());
    if let Some(totp_id) = &totp_id {
        let valid = credpivot_core::partitions::server_profile_matches_totp(db.conn(), id, totp_id)
            .map_err(|e| e.to_string())?;
        let linked = if login_id.is_empty() { true } else {
            db.conn().query_row(
                "SELECT EXISTS(SELECT 1 FROM credential_links c
                 JOIN login_credentials l ON l.item_id=c.account_item_id
                 JOIN totp_credentials t ON t.item_id=c.target_item_id
                 WHERE l.id=?1 AND t.id=?2 AND c.kind='mfa')",
                [&login_id, totp_id], |r| r.get::<_, bool>(0),
            ).map_err(|e| e.to_string())?
        };
        if !valid || !linked { return Err("连接关联的 MFA 已不可用，请在 App 中重新配置".into()); }
    }
    let ssh_key_id = row.linked_ssh_key_id.filter(|id| !id.is_empty());
    if let Some(key_id) = &ssh_key_id {
        let valid = db.conn().query_row(
            "SELECT EXISTS(SELECT 1 FROM ssh_keys k JOIN items i ON i.id=k.item_id
             WHERE k.id=?1 AND i.trashed=0 AND i.partition_id=?2)",
            [key_id, &partition_id], |r| r.get::<_, bool>(0),
        ).map_err(|e| e.to_string())?;
        let linked = if login_id.is_empty() { true } else {
            db.conn().query_row(
                "SELECT EXISTS(SELECT 1 FROM credential_links c
                 JOIN login_credentials l ON l.item_id=c.account_item_id
                 JOIN ssh_keys k ON k.item_id=c.target_item_id
                 WHERE l.id=?1 AND k.id=?2 AND c.kind='ssh_key')",
                [&login_id, key_id], |r| r.get::<_, bool>(0),
            ).map_err(|e| e.to_string())?
        };
        if !valid || !linked { return Err("连接关联的 SSH 密钥已不可用，请在 App 中重新配置".into()); }
    }
    // 目标始终由连接记录解析；调用方不能借连接 ID 指定另一台主机。
    if row.port == 0 || row.host.is_empty() || user.trim().is_empty()
        || row.host.starts_with('-') || user.starts_with('-')
        || row.host.chars().any(|c| c.is_whitespace() || c.is_control())
        || user.chars().any(|c| c.is_control())
    { return Err("连接的主机、端口或用户名无效，请在 App 中重新配置".into()); }
    Ok(Target { label: row.label, host: row.host, port: row.port, user,
        login_id, totp_id, ssh_key_id, partition_id, connection_revision: row.current_revision })
}

fn identity_file(vault: &VaultSession, key_id: Option<&str>) -> std::result::Result<Option<std::path::PathBuf>, String> {
    use std::{fs, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}};
    let Some(key_id) = key_id else { return Ok(None) };
    uuid::Uuid::parse_str(key_id).map_err(|_| "SSH 密钥标识无效")?;
    let key = vault.db.as_ref().ok_or("保险库未就绪")?.list_ssh().map_err(|e| e.to_string())?
        .into_iter().find(|key| key.id == key_id).ok_or("所选 SSH 密钥已不可用")?;
    let directory = crate::paths::runtime_dir().join("ssh-public");
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let reference = directory.join(format!("{key_id}.pub"));
    let temporary = directory.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    // 只落盘公钥引用，OpenSSH 的签名仍交给本机 Agent。
    let written = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
        writeln!(file, "{}", key.public_openssh)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &reference)
    })();
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    Ok(Some(reference))
}

pub(crate) fn pending(vault: &mut VaultSession) -> Vec<Value> {
    vault.terminal_connections.retain(|_, request| request.created.elapsed() < REQUEST_TTL && !request.reply.is_closed());
    let ids: Vec<_> = vault.terminal_connections.keys().cloned().collect();
    let mut out = Vec::new();
    for id in ids {
        let request = &vault.terminal_connections[&id];
        if !vault_matches(vault, &request.vault_id) {
            if let Some(request) = vault.terminal_connections.remove(&id) {
                let _ = request.reply.send(Err("当前保险库与连接命令不符，请先在 App 中切换保险库".into()));
            }
            continue;
        }
        if !vault.unlocked {
            out.push(json!({"id": id, "needs_unlock": true}));
            continue;
        }
        let current = match target(vault, &request.connection_id) {
            Ok(target) => target,
            Err(message) => {
                if let Some(request) = vault.terminal_connections.remove(&id) { let _ = request.reply.send(Err(message)); }
                continue;
            }
        };
        let request = vault.terminal_connections.get_mut(&id).unwrap();
        // 只冻结当前连接与认证引用；其他记录的写入不影响本次授权。
        let shown = request.target.get_or_insert(current);
        out.push(json!({"id": id, "needs_unlock": false, "label": shown.label,
            "host": shown.host, "port": shown.port, "user": shown.user}));
    }
    out
}

pub(crate) async fn resolve(st: &mut IpcState, id: &str, approved: bool) -> AgentResponse {
    let shared_vault = st.vault.clone();
    let mut vault = shared_vault.lock().await;
    let Some(request) = vault.terminal_connections.remove(id) else {
        return AgentResponse::err("request_gone", "终端连接请求已结束");
    };
    if !approved || request.created.elapsed() >= REQUEST_TTL || request.reply.is_closed() {
        let _ = request.reply.send(Err("终端连接已取消或超时".into()));
        return AgentResponse::ok(json!({"resolved": true}));
    }
    let result = (|| -> std::result::Result<Value, String> {
        if !vault_matches(&vault, &request.vault_id) { return Err("保险库已切换，请重新执行连接命令".into()); }
        if !vault.unlocked || !vault.authorize_sensitive_operation() { return Err("身份验证已失效，请重新执行连接命令".into()); }
        let current = target(&vault, &request.connection_id)?;
        if !request.target.as_ref().is_some_and(|shown| shown.matches(&current)) { return Err("连接配置已变化，请重新执行连接命令".into()); }
        let identity_file = identity_file(&vault, current.ssh_key_id.as_deref())?;
        let session_id = crate::ssh_session::prepare_session(&mut st.pending_ssh_sessions,
            &current.host, current.port, &current.user, &current.login_id, current.totp_id.clone(), "");
        // 服务器连接只使用明确选中的 MFA，不继承账户上的其他验证器。
        if let Some(grant) = st.pending_ssh_sessions.get_mut(&session_id) {
            grant.allow_account_mfa_fallback = false;
            grant.connection_source = Some(SessionSource {
                vault_id: request.vault_id.clone(), connection_id: request.connection_id.clone(), target: current.clone(),
            });
        }
        vault.touch_activity();
        Ok(json!({"session_id": session_id, "host": current.host, "port": current.port, "user": current.user,
            "identity_file": identity_file}))
    })();
    let session_id = result.as_ref().ok().and_then(|value| value["session_id"].as_str()).map(str::to_owned);
    if request.reply.send(result).is_err() {
        if let Some(id) = session_id { st.pending_ssh_sessions.remove(&id); }
    }
    AgentResponse::ok(json!({"resolved": true}))
}

#[cfg(not(target_os = "android"))]
pub(crate) async fn serve(
    stream: &mut tokio::net::UnixStream,
    state: std::sync::Arc<tokio::sync::Mutex<IpcState>>,
    vault_id: &str,
    connection_id: &str,
) -> crate::Result<()> {
    use tokio::io::AsyncReadExt;
    let vault = state.lock().await.vault.clone();
    let id = uuid::Uuid::new_v4().to_string();
    let (reply, receiver) = oneshot::channel();
    {
        let mut vault = vault.lock().await;
        vault.terminal_connections.retain(|_, request| request.created.elapsed() < REQUEST_TTL && !request.reply.is_closed());
        let error = if uuid::Uuid::parse_str(vault_id).is_err() || uuid::Uuid::parse_str(connection_id).is_err() {
            Some("连接命令无效，请从 App 重新复制")
        } else if !vault_matches(&vault, vault_id) {
            Some("当前保险库与连接命令不符，请先在 App 中切换保险库")
        } else if vault.terminal_connections.len() >= 8 { Some("待确认连接过多，请稍后重试") } else { None };
        if let Some(message) = error {
            drop(vault);
            return crate::ipc::write_ipc_response(stream, AgentResponse::err("terminal_connect", message)).await;
        }
        vault.terminal_connections.insert(id.clone(), PendingConnection {
            vault_id: vault_id.into(), connection_id: connection_id.into(), created: Instant::now(), target: None, reply,
        });
    }
    let mut closed = [0];
    let result = tokio::select! {
        reply = tokio::time::timeout(REQUEST_TTL, receiver) => reply.ok().and_then(|reply| reply.ok())
            .unwrap_or_else(|| Err("终端连接已取消或超时".into())),
        _ = stream.read(&mut closed) => Err("终端连接已断开".into()),
    };
    vault.lock().await.terminal_connections.remove(&id);
    let session_id = result.as_ref().ok().and_then(|value| value["session_id"].as_str()).map(str::to_owned);
    let response = match result { Ok(payload) => AgentResponse::ok(payload), Err(message) => AgentResponse::err("terminal_connect", message) };
    let written = crate::ipc::write_ipc_response(stream, response).await;
    if written.is_err() {
        if let Some(id) = session_id { state.lock().await.pending_ssh_sessions.remove(&id); }
    }
    written
}
