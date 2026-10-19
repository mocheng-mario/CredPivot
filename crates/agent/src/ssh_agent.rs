use crate::error::{AgentError, Result};
use crate::vault_session::VaultSession;
use ed25519_dalek::{Signer, VerifyingKey};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 2;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

pub async fn serve_ssh_agent(listener: UnixListener, vault: Arc<Mutex<VaultSession>>) -> Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let vault = vault.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_ssh_connection(&mut stream, vault).await {
                tracing::debug!("ssh agent connection ended: {e}");
            }
        });
    }
}

async fn handle_ssh_connection(
    stream: &mut tokio::net::UnixStream,
    vault: Arc<Mutex<VaultSession>>,
) -> Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 256 * 1024 {
        return Err(AgentError::Protocol("ssh agent message too large".into()));
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    let msg_type = msg.first().copied().unwrap_or(SSH_AGENT_FAILURE);

    let response = match msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            let mut v = vault.lock().await;
            if !v.unlocked {
                failure_packet()
            } else {
                v.touch_activity();
                identities_answer(&v)?
            }
        }
        SSH_AGENTC_SIGN_REQUEST => {
            let mut v = vault.lock().await;
            if !v.unlocked {
                failure_packet()
            } else {
                v.touch_activity();
                sign_request(&v, &msg)?
            }
        }
        _ => failure_packet(),
    };
    stream.write_all(&response).await?;
    Ok(())
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
    let vk: VerifyingKey = vault.ssh_signing_key.verifying_key();
    let key_blob = ed25519_key_blob(&vk);
    let comment = b"credpivot-m0";
    let mut body = vec![SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 1];
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

fn sign_request(vault: &VaultSession, msg: &[u8]) -> Result<Vec<u8>> {
    if msg.len() < 5 {
        return Ok(failure_packet());
    }
    let mut idx = 1usize;
    let key_blob_len = read_u32_be(msg, &mut idx)? as usize;
    if idx + key_blob_len > msg.len() {
        return Ok(failure_packet());
    }
    idx += key_blob_len;
    let data_len = read_u32_be(msg, &mut idx)? as usize;
    if idx + data_len > msg.len() {
        return Ok(failure_packet());
    }
    let data = &msg[idx..idx + data_len];
    let sig = vault.ssh_signing_key.sign(data);
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
