use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("agent already running elsewhere (single writer lock held)")]
    SingleWriterConflict,
    #[error("vault is locked")]
    Locked,
    #[error("vault already unlocked")]
    AlreadyUnlocked,
    #[error("invalid unlock material")]
    BadUnlock,
    #[error("request not found or expired")]
    RequestGone,
    #[error("peer not authorized: {0}")]
    PeerDenied(String),
    #[error("io error: {0}")]
    Io(std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("vault error: {0}")]
    Vault(String),
    // 记录标识只通过 App 的结构化错误上下文返回，不拼入日志文案。
    #[error("sync record validation failed: {message}")]
    SyncRecord { message: String, record: serde_json::Value },
}

impl From<std::io::Error> for AgentError {
    fn from(value: std::io::Error) -> Self {
        AgentError::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, AgentError>;
