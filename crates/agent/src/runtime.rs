use crate::error::Result;
use crate::ipc::{load_extension_gate_into_state, IpcState};
use crate::paths::ensure_runtime_dir;
#[cfg(not(target_os = "android"))]
use crate::{ipc::serve_ipc, paths::{agent_socket_path, ssh_agent_socket_path}, ssh_agent::serve_ssh_agent};
use crate::peer_auth::PeerAuthConfig;
use crate::session_guard::expire_idle_session;
use crate::single_writer::SingleWriterLock;
use crate::vault_session::VaultSession;
use std::sync::Arc;
use std::time::Duration;
#[cfg(not(target_os = "android"))]
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub struct AgentRuntime {
    _lock: SingleWriterLock,
    pub state: Arc<Mutex<IpcState>>,
    #[cfg(not(target_os = "android"))]
    ipc_task: JoinHandle<()>,
    #[cfg(not(target_os = "android"))]
    ssh_task: JoinHandle<()>,
    restore_task: JoinHandle<()>,
    idle_task: JoinHandle<()>,
}

impl AgentRuntime {
    pub async fn start() -> Result<Self> {
        let lock = SingleWriterLock::acquire()?;
        ensure_runtime_dir()?;
        #[cfg(not(target_os="android"))]
        {
            // 单写者锁已经持有；这里只移除上次进程异常退出留下的短期 Git socket。
            use std::os::unix::fs::FileTypeExt;
            if let Ok(entries)=std::fs::read_dir(crate::paths::runtime_dir().join("git-sockets")) {
                for entry in entries.flatten() {
                    let name=entry.file_name(); let name=name.to_string_lossy();
                    if name.len()==12 && name.bytes().all(|c|c.is_ascii_hexdigit()) && entry.file_type().is_ok_and(|t|t.is_socket()) {
                        let _=std::fs::remove_file(entry.path());
                    }
                }
            }
        }
        if !credpivot_core::app_settings_path().exists() {
            let settings = credpivot_core::read_app_settings()?;
            credpivot_core::write_app_settings(&settings)?;
        }
        crate::peer_auth::bootstrap_trusted_askpass_env();
        crate::diagnostics::init();

        // 手机端没有 Chrome Native Host 或桌面 SSH Agent，不创建外部 socket。
        #[cfg(not(target_os = "android"))]
        let (ipc_listener, ssh_listener) = {
            remove_stale_socket(&agent_socket_path())?;
            remove_stale_socket(&ssh_agent_socket_path())?;
            (UnixListener::bind(agent_socket_path())?, UnixListener::bind(ssh_agent_socket_path())?)
        };

        let vault = Arc::new(Mutex::new(VaultSession::new()));
        let mut ipc_state = IpcState {
            vault: vault.clone(),
            pending_fills: std::collections::HashMap::new(),
            pending_ssh_sessions: std::collections::HashMap::new(),
            peer_auth: PeerAuthConfig::default(),
            extension_gates: std::collections::HashMap::new(),
            extension_gate_pending_session: None,
            shutting_down: false,
        };
        load_extension_gate_into_state(&mut ipc_state);
        let state = Arc::new(Mutex::new(ipc_state));

        #[cfg(not(target_os = "android"))]
        let (ipc_task, ssh_task) = {
            let ipc_state = state.clone();
            let ipc_task = tokio::spawn(async move {
                if serve_ipc(ipc_listener, ipc_state).await.is_err() {
                    crate::diagnostics::error("ipc", "server stopped unexpectedly");
                }
            });

            let ssh_vault = vault.clone();
            let ssh_task = tokio::spawn(async move {
                if serve_ssh_agent(ssh_listener, ssh_vault).await.is_err() {
                    crate::diagnostics::error("ssh", "agent stopped unexpectedly");
                }
            });
            (ipc_task, ssh_task)
        };

        let restore_tick_vault = vault.clone();
        let restore_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30 * 60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let mut v = restore_tick_vault.lock().await;
                if v.unlocked {
                    if v.try_restore_point_if_due().is_err() {
                        crate::diagnostics::warn("backup", "scheduled restore point failed");
                    }
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

        crate::diagnostics::info("agent", "runtime started");
        Ok(Self {
            _lock: lock,
            state,
            #[cfg(not(target_os = "android"))]
            ipc_task,
            #[cfg(not(target_os = "android"))]
            ssh_task,
            restore_task,
            idle_task,
        })
    }

    pub async fn shutdown(self) {
        {
            let mut st = self.state.lock().await;
            st.shutting_down = true;
            st.vault.lock().await.lock();
            st.pending_fills.clear();
            st.pending_ssh_sessions.clear();
        }
        #[cfg(not(target_os = "android"))]
        {
            self.ipc_task.abort();
            self.ssh_task.abort();
            let _ = tokio::join!(self.ipc_task, self.ssh_task);
        }
        self.restore_task.abort();
        self.idle_task.abort();
        let _ = tokio::join!(self.restore_task, self.idle_task);
        crate::diagnostics::info("agent", "runtime stopped");
    }
}

#[cfg(not(target_os = "android"))]
fn remove_stale_socket(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
