mod client;
mod diagnostics;
mod extension_gate;
mod error;
mod ipc;
mod paths;
mod peer_auth;
mod protocol;
mod runtime;
mod session_guard;
mod single_writer;
mod ssh_agent;
mod ssh_session;
mod vault_session;

pub use client::{call_agent, call_in_process};
pub use diagnostics::{init as init_diagnostics, log_file_path, tail_lines as diagnostic_log_tail};
pub use error::{AgentError, Result};
pub use ipc::{handle_request, load_extension_gate_into_state, IpcState, RequestPeerContext};
pub use peer_auth::PeerAuthConfig;
pub use paths::{
    agent_socket_path, ensure_runtime_dir, materialized_askpass_path, materialized_native_host_path,
    runtime_dir, ssh_agent_socket_path, single_writer_lock_path, touch_extension_gate_pending,
    touch_extension_gate_pending_if_absent,
};
pub use protocol::{AgentRequest, AgentResponse, MIN_COMPATIBLE_PROTOCOL, PROTOCOL_VERSION};
pub use runtime::AgentRuntime;
pub use ssh_session::{classify_askpass_prompt, AskpassKind, SSH_SESSION_TTL_MS};
pub use single_writer::SingleWriterLock;
pub use vault_session::{FakeCredential, VaultSession};
