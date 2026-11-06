#[cfg(not(target_os = "android"))]
use crate::error::{AgentError, Result};
#[cfg(not(target_os = "android"))]
use crate::vault_session::VaultSession;
#[cfg(not(target_os = "android"))]
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
#[cfg(not(target_os = "android"))]
use zeroize::Zeroize;
#[cfg(not(target_os = "android"))]
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
#[cfg(not(target_os = "android"))]
use base64::Engine;
#[cfg(not(target_os = "android"))]
use sha2::{Digest, Sha256};
#[cfg(not(target_os = "android"))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(target_os = "android"))]
use tokio::net::UnixListener;
#[cfg(not(target_os = "android"))]
use tokio::sync::Mutex;

#[cfg(not(target_os = "android"))]
const SSH_AGENT_FAILURE: u8 = 5;
/// SSH2 agent identities answer (OpenSSH authfd.h).
#[cfg(not(target_os = "android"))]
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
#[cfg(not(target_os = "android"))]
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

#[cfg(not(target_os = "android"))]
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
#[cfg(not(target_os = "android"))]
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

const AUTH_TIMEOUT: Duration = Duration::from_secs(90);

/// 仓库信息只由已验证的 Git 适配器传入，不能根据普通 SSH 签名请求猜测。
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct GitContext {
    pub repository: String,
    // 包含 SSH 用户、主机、端口及仓库；不与普通 SSH 请求共享授权。
    #[serde(skip)]
    #[cfg(not(target_os = "android"))]
    pub authorization_scope: String,
    #[serde(skip)]
    #[cfg(not(target_os = "android"))]
    pub authorization_generation: u64,
    pub selection_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct PendingAuthorization {
    pub id: String,
    pub key_label: String,
    pub fingerprint: String,
    pub caller: String,
    pub policy: String,
    #[serde(flatten)]
    pub(crate) git: Option<GitContext>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reuse_seconds: Option<u64>,
    #[serde(skip)]
    pub(crate) created: Instant,
    #[serde(skip)]
    pub(crate) reply: oneshot::Sender<AuthorizationDecision>,
}

// Android 共用 IPC 的授权状态，但不启动消费这些决策的桌面 SSH 服务。
#[cfg_attr(target_os = "android", allow(dead_code))]
#[derive(Debug)]
pub(crate) struct AuthorizationDecision { pub approved: bool, pub key_id: String, pub remember: bool }

#[derive(Debug, Default)]
pub struct SshAuthorization {
    pub pending: HashMap<String, PendingAuthorization>,
    grants: HashMap<(String, String), Instant>,
    git_grants: HashMap<(String, String), Instant>,
    pub(crate) generation: u64,
    approved_once: HashMap<(String,String),(Instant,String)>,
}
impl SshAuthorization {
    pub fn clear(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.pending.clear();
        self.grants.clear();
        self.git_grants.clear();
        self.approved_once.clear();
    }
    pub fn expire(&mut self) {
        self.pending.retain(|_,r|r.created.elapsed() < AUTH_TIMEOUT && !r.reply.is_closed());
        self.grants.retain(|_,until|*until > Instant::now());
        self.git_grants.retain(|_,until|*until > Instant::now());
        self.approved_once.retain(|_,(at,_)|at.elapsed()<Duration::from_secs(120));
    }
    #[cfg(not(target_os = "android"))]
    pub(crate) fn approve_once(&mut self, key_id: String, scope: String, policy: String) {
        self.approved_once.insert((key_id,scope),(Instant::now(),policy));
    }
    pub fn resolve(&mut self, id: &str, approved: bool, key_id: String, remember: bool) -> bool {
        self.expire();
        self.pending.remove(id).is_some_and(|r|r.reply.send(AuthorizationDecision {approved,key_id,remember}).is_ok())
    }
}

/// 仅在明确批准且成功签名后建立固定期限，复用本身不会延长授权。
#[cfg(not(target_os = "android"))]
fn grant_session_authorization(v: &mut VaultSession, key_id: &str, scope: &str, git: Option<&GitContext>) {
    let settings=credpivot_core::effective_app_settings();
    if settings.sensitive_auth_seconds>0 {
        v.ssh_authorization.grants.insert((key_id.into(),scope.into()),Instant::now()+Duration::from_secs(settings.sensitive_auth_seconds));
    }
    if let Some(git)=git.filter(|g|!g.authorization_scope.is_empty()) {
        if settings.git_ssh_auth_seconds>0 {
            v.ssh_authorization.git_grants.insert((key_id.into(),git.authorization_scope.clone()),Instant::now()+Duration::from_secs(settings.git_ssh_auth_seconds));
        }
    }
}

#[cfg(not(target_os = "android"))]
fn signing_policy(v: &VaultSession, id: &str) -> Result<(String, String)> {
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

#[cfg(not(target_os = "android"))]
async fn authorized_sign(stream: &mut tokio::net::UnixStream, vault: &Arc<Mutex<VaultSession>>, msg: &[u8], caller: &str, scope: &str, selected: Option<&str>, git: Option<&GitContext>) -> Result<Vec<u8>> {
    let (id, key_id, expected_key, policy, generation, receiver) = {
        let mut v = vault.lock().await;
        if session_denied(&mut v) { return Ok(failure_packet()); }
        // 先检查请求和密钥，畸形请求不能触发验证弹窗；此处尚未生成签名。
        let Some((key_id,blob)) = requested_identity(&v,msg,selected)? else { return Ok(failure_packet()); };
        let (label, policy) = signing_policy(&v,&key_id)?;
        let git_reuse_seconds=if git.is_some() && policy=="session" {credpivot_core::effective_app_settings().git_ssh_auth_seconds} else {0};
        v.ssh_authorization.expire();
        if v.ssh_authorization.approved_once.remove(&(key_id.clone(),scope.into())).is_some_and(|(_,saved)|saved==policy) {
            let result=sign_request(&v,msg,&key_id)?;
            if policy=="session" && result.get(4)==Some(&SSH_AGENT_SIGN_RESPONSE) {
                grant_session_authorization(&mut v,&key_id,scope,git);
            }
            v.touch_activity(); return Ok(result);
        }
        if git_reuse_seconds>0 && git.is_some_and(|g|!g.authorization_scope.is_empty()
            && v.ssh_authorization.git_grants.contains_key(&(key_id.clone(),g.authorization_scope.clone()))) {
            v.touch_activity(); return sign_request(&v,msg,&key_id);
        }
        if policy == "session" && v.ssh_authorization.grants.contains_key(&(key_id.clone(),scope.into())) {
            v.touch_activity();
            return sign_request(&v,msg,&key_id);
        }
        if v.ssh_authorization.pending.len() >= 8 { return Ok(failure_packet()); }
        let (reply, receiver) = oneshot::channel();
        let id = uuid::Uuid::new_v4().to_string();
        v.ssh_authorization.pending.insert(id.clone(),PendingAuthorization {
            id:id.clone(),key_label:label,fingerprint:format!("SHA256:{}",base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))),
            caller:caller.into(),policy:policy.clone(),created:Instant::now(),reply,
            git:git.cloned(),candidates:Vec::new(),
            reuse_seconds:git.map(|_|git_reuse_seconds),
        });
        (id,key_id,blob,policy,v.ssh_authorization.generation,receiver)
    };
    // 不持有 Vault 锁等待用户；断开连接、超时、锁库都会撤销待确认请求。
    let mut disconnected = [0u8; 1];
    let approved = tokio::select! {
        decision = tokio::time::timeout(AUTH_TIMEOUT,receiver) => matches!(decision,Ok(Ok(AuthorizationDecision {approved:true,..}))),
        _ = stream.read(&mut disconnected) => false,
    };
    let mut v = vault.lock().await;
    v.ssh_authorization.pending.remove(&id);
    if !approved {
        if let Some(git)=git { v.ssh_authorization.git_grants.remove(&(key_id.clone(),git.authorization_scope.clone())); }
    }
    if !approved || session_denied(&mut v) || v.ssh_authorization.generation != generation
        || requested_identity(&v,msg,selected)?.as_ref() != Some(&(key_id.clone(),expected_key))
        || signing_policy(&v,&key_id)?.1 != policy { return Ok(failure_packet()); }
    let result = sign_request(&v,msg,&key_id)?;
    if policy == "session" && result.get(4)==Some(&SSH_AGENT_SIGN_RESPONSE) {
        grant_session_authorization(&mut v,&key_id,scope,git);
    }
    v.touch_activity();
    Ok(result)
}

#[cfg(not(target_os = "android"))]
pub(crate) async fn authorized_identities(stream: &mut tokio::net::UnixStream, vault: &Arc<Mutex<VaultSession>>, caller: &str, selected: Option<&str>, git: Option<&GitContext>) -> Result<Vec<u8>> {
    let (id, receiver) = {
        let mut v = vault.lock().await;
        if !session_denied(&mut v) {
            v.touch_activity();
            return identities_answer(&v,selected);
        }
        v.ssh_authorization.expire();
        if !v.vault_exists() || v.ssh_authorization.pending.len() >= 8 { return Ok(failure_packet()); }
        let id = uuid::Uuid::new_v4().to_string();
        let (reply, receiver) = oneshot::channel();
        v.ssh_authorization.pending.insert(id.clone(), PendingAuthorization {
            id: id.clone(), key_label: String::new(), fingerprint: String::new(),
            caller: caller.into(), policy: "unlock".into(), created: Instant::now(), reply,
            git:git.cloned(),candidates:Vec::new(),reuse_seconds:None,
        });
        (id, receiver)
    };
    let mut disconnected = [0u8; 1];
    let allowed = tokio::select! {
        decision = tokio::time::timeout(AUTH_TIMEOUT, receiver) => match decision {
            Ok(Ok(decision)) => decision.approved,
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
    identities_answer(&v,selected)
}

#[cfg(not(target_os = "android"))]
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

#[cfg(not(target_os = "android"))]
async fn handle_ssh_connection(stream: &mut tokio::net::UnixStream, vault: Arc<Mutex<VaultSession>>) -> Result<()> {
    let pid=stream.peer_cred().ok().and_then(|c|c.pid()).map(|v|v as u32);
    let Some(first)=read_message(stream).await? else { return Ok(()); };
    if first.starts_with(crate::git_ssh::SELECT_PREFIX) {
        return crate::git_ssh::serve_selection(stream,vault,pid,&first[crate::git_ssh::SELECT_PREFIX.len()..]).await;
    }
    normal_connection(stream,vault,None,Some(first)).await
}

#[cfg(not(target_os = "android"))]
pub(crate) async fn selected_connection(mut stream: tokio::net::UnixStream, vault: Arc<Mutex<VaultSession>>, key_id: String, scope: String, git: GitContext) -> Result<()> {
    normal_connection_with_scope(&mut stream,vault,Some(key_id),None,scope,Some(git)).await
}

#[cfg(not(target_os = "android"))]
async fn read_message(stream: &mut tokio::net::UnixStream) -> Result<Option<Vec<u8>>> {
    let mut size=[0;4];
    if stream.read_exact(&mut size).await.is_err() { return Ok(None); }
    let size=u32::from_be_bytes(size) as usize;
    if size==0 || size>256*1024 { return Err(AgentError::Protocol("SSH message size invalid".into())); }
    let mut message=vec![0;size]; stream.read_exact(&mut message).await?; Ok(Some(message))
}

#[cfg(not(target_os = "android"))]
async fn normal_connection(stream: &mut tokio::net::UnixStream, vault: Arc<Mutex<VaultSession>>, selected: Option<String>, mut first: Option<Vec<u8>>) -> Result<()> {
    normal_connection_with_scope(stream,vault,selected,first.take(),uuid::Uuid::new_v4().to_string(),None).await
}

#[cfg(not(target_os = "android"))]
async fn normal_connection_with_scope(stream: &mut tokio::net::UnixStream, vault: Arc<Mutex<VaultSession>>, selected: Option<String>, mut first: Option<Vec<u8>>, connection: String, git: Option<GitContext>) -> Result<()> {
    let caller=stream.peer_cred().ok().and_then(|c|c.pid()).map(|pid| {
        #[cfg(target_os="macos")]
        let name=crate::peer_auth::peer_executable_path(pid as u32).ok().and_then(|p|p.file_name().map(|s|s.to_string_lossy().into_owned())).unwrap_or_else(||"本地进程".into());
        #[cfg(not(target_os="macos"))]
        let name="本地进程";
        format!("{name} (PID {pid})")
    }).unwrap_or_else(||"本地 SSH 进程".into());
    loop {
        let msg=if let Some(first)=first.take() { first } else { match read_message(stream).await? {Some(msg)=>msg,None=>break} };
        let response=match msg[0] {
            SSH_AGENTC_REQUEST_IDENTITIES=>authorized_identities(stream,&vault,&caller,selected.as_deref(),git.as_ref()).await?,
            SSH_AGENTC_SIGN_REQUEST=>authorized_sign(stream,&vault,&msg,&caller,&connection,selected.as_deref(),git.as_ref()).await?,
            _=>failure_packet(),
        };
        stream.write_all(&response).await?;
    }
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn session_denied(v: &mut VaultSession) -> bool {
    if v.idle_expired() {
        v.lock();
        return true;
    }
    !v.unlocked
}

#[cfg(not(target_os = "android"))]
fn failure_packet() -> Vec<u8> {
    let body = vec![SSH_AGENT_FAILURE];
    frame(&body)
}

#[cfg(not(target_os = "android"))]
fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

#[cfg(not(target_os = "android"))]
fn identities_answer(vault: &VaultSession, selected: Option<&str>) -> Result<Vec<u8>> {
    let db=vault.db.as_ref().ok_or(AgentError::Locked)?;
    let mut keys=db.list_ssh().map_err(|_|AgentError::Protocol("SSH identity read failed".into()))?;
    keys.retain(|key|selected.is_none_or(|id|key.id==id));
    keys.sort_by_key(|key|(vault.ssh_signing_key_id.as_deref()!=Some(key.id.as_str()),!key.is_default));
    let mut body=vec![SSH2_AGENT_IDENTITIES_ANSWER];
    body.extend_from_slice(&(keys.len() as u32).to_be_bytes());
    for key in keys {
        let blob=public_blob(&key.public_openssh)?;
        let comment=key.public_openssh.splitn(3,' ').nth(2).unwrap_or("").as_bytes();
        body.extend_from_slice(&(blob.len() as u32).to_be_bytes()); body.extend_from_slice(&blob);
        body.extend_from_slice(&(comment.len() as u32).to_be_bytes()); body.extend_from_slice(comment);
    }
    if body.len()>256*1024 { return Err(AgentError::Protocol("SSH identity list too large".into())); }
    Ok(frame(&body))
}

#[cfg(not(target_os = "android"))]
pub(crate) fn public_blob(public: &str) -> Result<Vec<u8>> {
    let mut parts=public.split_whitespace();
    if parts.next()!=Some("ssh-ed25519") { return Err(AgentError::Protocol("SSH identity invalid".into())); }
    base64::engine::general_purpose::STANDARD.decode(parts.next().unwrap_or("")).map_err(|_|AgentError::Protocol("SSH identity invalid".into()))
}

#[cfg(not(target_os = "android"))]
fn requested_identity(vault: &VaultSession, msg: &[u8], selected: Option<&str>) -> Result<Option<(String,Vec<u8>)>> {
    let db=vault.db.as_ref().ok_or(AgentError::Locked)?;
    for key in db.list_ssh().map_err(|_|AgentError::Protocol("SSH identity read failed".into()))? {
        if selected.is_some_and(|id|key.id!=id) { continue; }
        let blob=public_blob(&key.public_openssh)?;
        if sign_data(msg,&blob)?.is_some() { return Ok(Some((key.id,blob))); }
    }
    Ok(None)
}

#[cfg(not(target_os = "android"))]
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

#[cfg(not(target_os = "android"))]
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

#[cfg(not(target_os = "android"))]
fn sign_request(vault: &VaultSession, msg: &[u8], key_id: &str) -> Result<Vec<u8>> {
    let db=vault.db.as_ref().ok_or(AgentError::Locked)?;
    let mut record=db.load_ssh_key(key_id).map_err(|_|AgentError::Protocol("SSH identity unavailable".into()))?;
    let key=SigningKey::from_bytes(&record.seed); record.seed.zeroize();
    let Some(data)=sign_data(msg,&ed25519_key_blob(&key.verifying_key()))? else { return Ok(failure_packet()); };
    let sig=key.sign(data);
    let sig_blob=ssh_ed25519_signature_blob(&sig.to_bytes());
    let mut body=vec![SSH_AGENT_SIGN_RESPONSE];
    body.extend_from_slice(&(sig_blob.len() as u32).to_be_bytes()); body.extend_from_slice(&sig_blob);
    Ok(frame(&body))
}

#[cfg(not(target_os = "android"))]
fn ssh_ed25519_signature_blob(sig: &[u8; 64]) -> Vec<u8> {
    let mut blob = Vec::new();
    let type_name = b"ssh-ed25519";
    blob.extend_from_slice(&(type_name.len() as u32).to_be_bytes());
    blob.extend_from_slice(type_name);
    blob.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    blob.extend_from_slice(sig);
    blob
}

#[cfg(not(target_os = "android"))]
fn read_u32_be(buf: &[u8], idx: &mut usize) -> Result<u32> {
    if *idx + 4 > buf.len() {
        return Err(AgentError::Protocol("truncated ssh agent message".into()));
    }
    let v = u32::from_be_bytes(buf[*idx..*idx + 4].try_into().unwrap());
    *idx += 4;
    Ok(v)
}
