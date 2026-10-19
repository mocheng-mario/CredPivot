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
}

impl From<std::io::Error> for AgentError {
    fn from(value: std::io::Error) -> Self {
        AgentError::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, AgentError>;
