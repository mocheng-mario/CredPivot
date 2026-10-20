use crate::error::Result;
use crate::ipc::{serve_ipc, IpcState};
use crate::paths::{agent_socket_path, ensure_runtime_dir, ssh_agent_socket_path};
use crate::peer_auth::PeerAuthConfig;
use crate::session_guard::expire_idle_session;
use crate::single_writer::SingleWriterLock;
use crate::ssh_agent::serve_ssh_agent;
use crate::vault_session::VaultSession;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub struct AgentRuntime {
    _lock: SingleWriterLock,
    pub state: Arc<Mutex<IpcState>>,
    ipc_task: JoinHandle<()>,
    ssh_task: JoinHandle<()>,
    restore_task: JoinHandle<()>,
    idle_task: JoinHandle<()>,
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

        let restore_tick_vault = vault.clone();
        let restore_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30 * 60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let mut v = restore_tick_vault.lock().await;
                if v.unlocked {
                    let _ = v.try_restore_point_if_due();
                }
            }
        });

        let idle_state = state.clone();
        let idle_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                expire_idle_session(&idle_state).await;
            }
        });

        Ok(Self {
            _lock: lock,
            state,
            ipc_task,
            ssh_task,
            restore_task,
            idle_task,
        })
    }

    pub async fn shutdown(self) {
        {
            let mut st = self.state.lock().await;
            st.vault.lock().await.lock();
            st.pending_fills.clear();
        }
        self.ipc_task.abort();
        self.ssh_task.abort();
        self.restore_task.abort();
        self.idle_task.abort();
        let _ = tokio::join!(
            self.ipc_task,
            self.ssh_task,
            self.restore_task,
            self.idle_task,
        );
    }
}

fn remove_stale_socket(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
