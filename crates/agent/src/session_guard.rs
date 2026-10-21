use crate::ipc::IpcState;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 空闲超时锁定：IPC、FFI、SSH 共用。
pub async fn expire_idle_session(state: &Arc<Mutex<IpcState>>) {
    let mut st = state.lock().await;
    let expired = {
        let mut v = st.vault.lock().await;
        if v.idle_expired() {
            v.lock();
            true
        } else { false }
    };
    if expired {
        crate::ipc::revoke_extension_gate(&mut st);
        st.pending_ssh_sessions.clear();
    }
}
