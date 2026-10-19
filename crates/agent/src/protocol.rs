use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: u32 = 1;
pub const MIN_COMPATIBLE_PROTOCOL: u32 = 1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentRequest {
    Ping,
    Status,
    Lock,
    UnlockPassword { password: String },
    UnlockTouchIdToken { token: String },
    SetTouchIdToken { token: String },
    CredentialSave {
        request_id: String,
        origin: String,
        username: String,
        password: String,
    },
    CredentialSuggest {
        origin: String,
    },
    CredentialFillPrepare {
        request_id: String,
        credential_id: String,
        origin: String,
        tab_id: u64,
        frame_id: i64,
        document_id: String,
    },
    CredentialFillConsume {
        request_id: String,
        frame_id: i64,
        document_id: String,
    },
    CancelRequest { request_id: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentResponse {
    Ok {
        protocol_version: u32,
        payload: Value,
    },
    Err {
        protocol_version: u32,
        code: String,
        message: String,
    },
}

impl AgentResponse {
    pub fn ok(payload: Value) -> Self {
        Self::Ok {
            protocol_version: PROTOCOL_VERSION,
            payload,
        }
    }

    pub fn err(code: &str, message: impl Into<String>) -> Self {
        Self::Err {
            protocol_version: PROTOCOL_VERSION,
            code: code.into(),
            message: message.into(),
        }
    }
}
