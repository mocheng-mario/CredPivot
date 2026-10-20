use crate::error::Result;
use crate::ipc::{handle_request, IpcState, RequestPeerContext};
use crate::session_guard::expire_idle_session;
use crate::protocol::{AgentRequest, AgentResponse};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

/// Length-prefixed JSON IPC (same framing as native-host ↔ agent).
pub async fn call_agent(socket_path: &std::path::Path, req: AgentRequest) -> Result<AgentResponse> {
    let mut stream = UnixStream::connect(socket_path).await?;
    let body = serde_json::to_vec(&req).map_err(|e| crate::error::AgentError::Protocol(e.to_string()))?;
    let frame_len = (body.len() as u32).to_le_bytes();
    stream.write_all(&frame_len).await?;
    stream.write_all(&body).await?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let resp: AgentResponse = serde_json::from_slice(&buf)
        .map_err(|e| crate::error::AgentError::Protocol(e.to_string()))?;
    Ok(resp)
}

pub async fn call_in_process(
    state: &Arc<Mutex<IpcState>>,
    req: AgentRequest,
) -> AgentResponse {
    expire_idle_session(state).await;
    let mut st = state.lock().await;
    handle_request(&mut st, req, RequestPeerContext::default()).await
}
