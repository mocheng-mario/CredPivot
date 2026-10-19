use crate::error::Result;
use crate::ipc::{serve_ipc, IpcState};
use crate::paths::{agent_socket_path, ensure_runtime_dir, ssh_agent_socket_path};
use crate::peer_auth::PeerAuthConfig;
use crate::single_writer::SingleWriterLock;
use crate::ssh_agent::serve_ssh_agent;
use crate::vault_session::VaultSession;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::Mutex;

pub struct AgentRuntime {
    _lock: SingleWriterLock,
    pub state: Arc<Mutex<IpcState>>,
    tasks: tokio::task::JoinHandle<()>,
}

impl AgentRuntime {
    pub async fn start() -> Result<Self> {
        let lock = SingleWriterLock::acquire()?;
        ensure_runtime_dir()?;

        remove_stale_socket(&agent_socket_path())?;
        remove_stale_socket(&ssh_agent_socket_path())?;

        let ipc_listener = UnixListener::bind(agent_socket_path())?;
        let ssh_listener = UnixListener::bind(ssh_agent_socket_path())?;

        let vault = Arc::new(Mutex::new(VaultSession::new()));
        let state = Arc::new(Mutex::new(IpcState {
            vault: vault.clone(),
            pending_fills: std::collections::HashMap::new(),
            peer_auth: PeerAuthConfig::default(),
        }));

        let ipc_state = state.clone();
        let ipc_task = tokio::spawn(async move {
            if let Err(e) = serve_ipc(ipc_listener, ipc_state).await {
                tracing::error!("ipc server stopped: {e}");
            }
        });

        let ssh_vault = vault.clone();
        let ssh_task = tokio::spawn(async move {
            if let Err(e) = serve_ssh_agent(ssh_listener, ssh_vault).await {
                tracing::error!("ssh agent stopped: {e}");
            }
        });

        let tasks = tokio::spawn(async move {
            let _ = tokio::join!(ipc_task, ssh_task);
        });

        Ok(Self {
            _lock: lock,
            state,
            tasks,
        })
    }

    pub async fn shutdown(self) {
        self.tasks.abort();
    }
}

fn remove_stale_socket(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
