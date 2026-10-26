use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid format: {0}")]
    Format(String),
    #[error("authentication failed")]
    Auth,
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("password/key rejected")]
    BadSecret,
    #[error("revision conflict")]
    Conflict,
    /// 仅含白名单记录标识；错误的显示文案不自动展开名称、账号等私有元数据。
    #[error("record validation failed: {source}")]
    RecordValidation {
        record: serde_json::Value,
        #[source]
        source: Box<CoreError>,
    },
}

pub type Result<T> = std::result::Result<T, CoreError>;

impl CoreError {
    pub fn format(msg: impl AsRef<str>) -> Self {
        Self::Format(msg.as_ref().to_string())
    }

    pub fn limit(msg: impl AsRef<str>) -> Self {
        Self::Limit(msg.as_ref().to_string())
    }

    pub fn io(msg: impl AsRef<str>) -> Self {
        Self::Io(msg.as_ref().to_string())
    }
}

impl From<rusqlite::Error> for CoreError {
    fn from(error: rusqlite::Error) -> Self { Self::format(error.to_string()) }
}
