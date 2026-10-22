use crate::error::{AgentError, Result};
use crate::vault_session::VaultSession;
use ed25519_dalek::{Signer, VerifyingKey};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use base64::Engine;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

const SSH_AGENT_FAILURE: u8 = 5;
/// SSH2 agent identities answer (OpenSSH authfd.h).
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

const AUTH_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Debug, serde::Serialize)]
pub struct PendingAuthorization {
    pub id: String,
    pub key_label: String,
    pub fingerprint: String,
    pub caller: String,
    pub policy: String,
    #[serde(skip)]
    created: Instant,
    #[serde(skip)]
    reply: oneshot::Sender<bool>,
}

#[derive(Debug, Default)]
pub struct SshAuthorization {
    pub pending: HashMap<String, PendingAuthorization>,
    grants: HashMap<(String, String), Instant>,
    generation: u64,
}
impl SshAuthorization {
    pub fn clear(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.pending.clear();
        self.grants.clear();
    }
    pub fn expire(&mut self) {
        self.pending.retain(|_,r|r.created.elapsed() < AUTH_TIMEOUT && !r.reply.is_closed());
        self.grants.retain(|_,until|*until > Instant::now());
    }
    pub fn resolve(&mut self, id: &str, approved: bool) -> bool {
        self.expire();
        self.pending.remove(id).is_some_and(|r|r.reply.send(approved).is_ok())
    }
}

fn signing_policy(v: &VaultSession) -> Result<(String, String)> {
    let id = v.ssh_signing_key_id.as_deref().ok_or(AgentError::Locked)?;
    let db = v.db.as_ref().ok_or(AgentError::Locked)?;
    // 授权信息只需要公有元数据，不再次读取私钥 seed。
    let key = db.list_ssh().map_err(|e|AgentError::Vault(e.to_string()))?
        .into_iter().find(|key| key.id == id).ok_or(AgentError::Locked)?;
    let data = credpivot_core::manage_credentials(db.conn(),credpivot_core::VaultAction::ItemDetails {item_id:key.item_id})
        .map_err(|e|AgentError::Vault(e.to_string()))?;
    let configured = data["details"]["ssh_sign_policy"].as_str().unwrap_or("");
    let policy = if configured.is_empty() {credpivot_core::effective_app_settings().ssh_sign_policy} else {configured.into()};
    Ok((key.label,policy))
}

async fn authorized_sign(stream: &mut tokio::net::UnixStream, vault: &Arc<Mutex<VaultSession>>, msg: &[u8], caller: &str, scope: &str) -> Result<Vec<u8>> {
    let (id, key_id, expected_key, policy, generation, receiver) = {
        let mut v = vault.lock().await;
        if session_denied(&mut v) { return Ok(failure_packet()); }
        // 先检查请求和密钥，畸形请求不能触发验证弹窗；此处尚未生成签名。
        let Some(key) = v.ssh_signing_key.as_ref() else { return Ok(failure_packet()); };
        let blob = ed25519_key_blob(&key.verifying_key());
        if sign_data(msg, &blob)?.is_none() { return Ok(failure_packet()); }
        let key_id = v.ssh_signing_key_id.clone().ok_or(AgentError::Locked)?;
        let (label, policy) = signing_policy(&v)?;
        v.ssh_authorization.expire();
        if policy == "session" && v.ssh_authorization.grants.contains_key(&(key_id.clone(),scope.into())) {
            v.touch_activity();
            return sign_request(&v,msg);
        }
        if v.ssh_authorization.pending.len() >= 8 { return Ok(failure_packet()); }
        let (reply, receiver) = oneshot::channel();
        let id = uuid::Uuid::new_v4().to_string();
        v.ssh_authorization.pending.insert(id.clone(),PendingAuthorization {
            id:id.clone(),key_label:label,fingerprint:format!("SHA256:{}",base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))),
            caller:caller.into(),policy:policy.clone(),created:Instant::now(),reply,
        });
        (id,key_id,blob,policy,v.ssh_authorization.generation,receiver)
    };
    // 不持有 Vault 锁等待用户；断开连接、超时、锁库都会撤销待确认请求。
    let mut disconnected = [0u8; 1];
    let approved = tokio::select! {
        decision = tokio::time::timeout(AUTH_TIMEOUT,receiver) => matches!(decision,Ok(Ok(true))),
        _ = stream.read(&mut disconnected) => false,
    };
    let mut v = vault.lock().await;
    v.ssh_authorization.pending.remove(&id);
    if !approved || session_denied(&mut v) || v.ssh_authorization.generation != generation
        || v.ssh_signing_key_id.as_ref() != Some(&key_id)
        || v.ssh_signing_key.as_ref().map(|k|ed25519_key_blob(&k.verifying_key())).as_ref() != Some(&expected_key)
        || signing_policy(&v)?.1 != policy { return Ok(failure_packet()); }
    let result = sign_request(&v,msg)?;
    if policy == "session" {
        let ttl = credpivot_core::effective_app_settings().sensitive_auth_seconds;
        if ttl > 0 { v.ssh_authorization.grants.insert((key_id,scope.into()),Instant::now()+Duration::from_secs(ttl)); }
    }
    v.touch_activity();
    Ok(result)
}

async fn authorized_identities(stream: &mut tokio::net::UnixStream, vault: &Arc<Mutex<VaultSession>>, caller: &str) -> Result<Vec<u8>> {
    let (id, receiver) = {
        let mut v = vault.lock().await;
        if !session_denied(&mut v) {
            v.touch_activity();
            return identities_answer(&v);
        }
        v.ssh_authorization.expire();
        if !v.vault_exists() || v.ssh_authorization.pending.len() >= 8 { return Ok(failure_packet()); }
        let id = uuid::Uuid::new_v4().to_string();
        let (reply, receiver) = oneshot::channel();
        v.ssh_authorization.pending.insert(id.clone(), PendingAuthorization {
            id: id.clone(), key_label: String::new(), fingerprint: String::new(),
            caller: caller.into(), policy: "unlock".into(), created: Instant::now(), reply,
        });
        (id, receiver)
    };
    let mut disconnected = [0u8; 1];
    let allowed = tokio::select! {
        decision = tokio::time::timeout(AUTH_TIMEOUT, receiver) => match decision {
            Ok(Ok(approved)) => approved,
            // 解锁会重新装载密钥并清空待处理请求；只在保险库确实已解锁时返回公钥。
            Ok(Err(_)) => true,
            Err(_) => false,
        },
        _ = stream.read(&mut disconnected) => false,
    };
    let mut v = vault.lock().await;
    v.ssh_authorization.pending.remove(&id);
    if !allowed || session_denied(&mut v) { return Ok(failure_packet()); }
    v.touch_activity();
    identities_answer(&v)
}

pub async fn serve_ssh_agent(listener: UnixListener, vault: Arc<Mutex<VaultSession>>) -> Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let vault = vault.clone();
        tokio::spawn(async move {
            if handle_ssh_connection(&mut stream, vault).await.is_err() {
                crate::diagnostics::debug("ssh", "connection ended with transport or protocol error");
            }
        });
    }
}

async fn handle_ssh_connection(
    stream: &mut tokio::net::UnixStream,
    vault: Arc<Mutex<VaultSession>>,
) -> Result<()> {
    let connection = uuid::Uuid::new_v4().to_string();
    let caller = stream.peer_cred().ok().and_then(|c|c.pid()).map(|pid| {
        #[cfg(target_os = "macos")]
        let name = crate::peer_auth::peer_executable_path(pid as u32).ok().and_then(|p|p.file_name().map(|v|v.to_string_lossy().into_owned())).unwrap_or_else(||"未知进程".into());
        #[cfg(not(target_os = "macos"))]
        let name = "本地进程";
        format!("{name} (PID {pid})")
    }).unwrap_or_else(||format!("未知调用进程 · 连接 {connection}"));
    loop {
        let mut len_buf = [0u8; 4];
        let n = stream.read_exact(&mut len_buf).await;
        if n.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 256 * 1024 {
            return Err(AgentError::Protocol("ssh agent message too large".into()));
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;
        let msg_type = msg.first().copied().unwrap_or(SSH_AGENT_FAILURE);

        let response = match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => authorized_identities(stream, &vault, &caller).await?,
            SSH_AGENTC_SIGN_REQUEST => authorized_sign(stream, &vault, &msg, &caller, &connection).await?,
            _ => failure_packet(),
        };
        stream.write_all(&response).await?;
    }
    Ok(())
}

fn session_denied(v: &mut VaultSession) -> bool {
    if v.idle_expired() {
        v.lock();
        return true;
    }
    !v.unlocked
}

fn failure_packet() -> Vec<u8> {
    let body = vec![SSH_AGENT_FAILURE];
    frame(&body)
}

fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn identities_answer(vault: &VaultSession) -> Result<Vec<u8>> {
    let Some(key) = &vault.ssh_signing_key else {
        return Ok(frame(&[SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]));
    };
    let vk: VerifyingKey = key.verifying_key();
    let key_blob = ed25519_key_blob(&vk);
    let comment = b"credpivot-m0";
    let mut body = vec![SSH2_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 1];
    body.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
    body.extend_from_slice(&key_blob);
    body.extend_from_slice(&(comment.len() as u32).to_be_bytes());
    body.extend_from_slice(comment);
    Ok(frame(&body))
}

fn ed25519_key_blob(vk: &VerifyingKey) -> Vec<u8> {
    let mut blob = Vec::new();
    let type_name = b"ssh-ed25519";
    blob.extend_from_slice(&(type_name.len() as u32).to_be_bytes());
    blob.extend_from_slice(type_name);
    let key = vk.to_bytes();
    blob.extend_from_slice(&(key.len() as u32).to_be_bytes());
    blob.extend_from_slice(&key);
    blob
}

fn sign_data<'a>(msg: &'a [u8], expected: &[u8]) -> Result<Option<&'a [u8]>> {
    let mut idx = 1;
    let key_len = read_u32_be(msg,&mut idx)? as usize;
    if key_len > msg.len().saturating_sub(idx) || &msg[idx..idx+key_len] != expected { return Ok(None); }
    idx += key_len;
    let len = read_u32_be(msg,&mut idx)? as usize;
    if len > msg.len().saturating_sub(idx) || msg.len()-idx-len != 4 { return Ok(None); }
    let data = &msg[idx..idx+len];
    idx += len;
    if read_u32_be(msg,&mut idx)? != 0 { return Ok(None); }
    Ok(Some(data))
}

fn sign_request(vault: &VaultSession, msg: &[u8]) -> Result<Vec<u8>> {
    let Some(key) = &vault.ssh_signing_key else { return Ok(failure_packet()); };
    let Some(data) = sign_data(msg,&ed25519_key_blob(&key.verifying_key()))? else { return Ok(failure_packet()); };
    let sig = key.sign(data);
    let sig_blob = ssh_ed25519_signature_blob(&sig.to_bytes());
    let mut body = vec![SSH_AGENT_SIGN_RESPONSE];
    body.extend_from_slice(&(sig_blob.len() as u32).to_be_bytes());
    body.extend_from_slice(&sig_blob);
    Ok(frame(&body))
}

fn ssh_ed25519_signature_blob(sig: &[u8; 64]) -> Vec<u8> {
    let mut blob = Vec::new();
    let type_name = b"ssh-ed25519";
    blob.extend_from_slice(&(type_name.len() as u32).to_be_bytes());
    blob.extend_from_slice(type_name);
    blob.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    blob.extend_from_slice(sig);
    blob
}

fn read_u32_be(buf: &[u8], idx: &mut usize) -> Result<u32> {
    if *idx + 4 > buf.len() {
        return Err(AgentError::Protocol("truncated ssh agent message".into()));
    }
    let v = u32::from_be_bytes(buf[*idx..*idx + 4].try_into().unwrap());
    *idx += 4;
    Ok(v)
}
