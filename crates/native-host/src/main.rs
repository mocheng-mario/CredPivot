mod chrome_parent;
mod launch_app;

use chrome_parent::verify_chrome_parent;
use credpivot_agent::{
    agent_socket_path, call_agent, diagnostics, AgentRequest, AgentResponse, PROTOCOL_VERSION,
};
use launch_app::{launch_credpivot_app, wait_for_agent_socket};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

fn main() {
    if verify_chrome_parent().is_err() {
        diagnostics::error("native_host", "parent verification failed");
        eprintln!("credpivot-native-host: parent verification failed");
        std::process::exit(1);
    }

    diagnostics::info("native_host", "started");
    if run_native_messaging_loop().is_err() {
        diagnostics::error("native_host", "messaging loop failed");
        eprintln!("credpivot-native-host: messaging loop failed");
        std::process::exit(1);
    }
    diagnostics::info("native_host", "stopped");
}

fn run_native_messaging_loop() -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut handle = stdin.lock();

    loop {
        let mut len_buf = [0u8; 4];
        if read_exact_or_eof(&mut handle, &mut len_buf)? {
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut msg = vec![0u8; len];
        read_exact_or_eof(&mut handle, &mut msg)?;
        let value: Value = serde_json::from_slice(&msg)?;
        let request_id = value.get("request_id").cloned();
        let response = tokio::runtime::Runtime::new()?
            .block_on(async {
                match forward_to_agent(value).await {
                    Ok(v) => v,
                    Err(e) => {
                        diagnostics::warn("native_host", "forward to agent failed");
                        let msg = e.to_string();
                        error_envelope("forward_failed", &msg, request_id)
                    }
                }
            });
        write_native_message(&mut stdout, &response)?;
    }
    Ok(())
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, io::Error> {
    let mut off = 0;
    while off < buf.len() {
        match r.read(&mut buf[off..]) {
            Ok(0) => return Ok(off == 0),
            Ok(n) => off += n,
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

async fn forward_to_agent(envelope: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let request_id = envelope.get("request_id").cloned();
    let socket = agent_socket_path();
    if !socket.exists() {
        launch_credpivot_app();
        let ok = wait_for_agent_socket(&socket, 8_000).await;
        if !ok {
            return Ok(error_envelope(
                "app_unreachable",
                "CredPivot App is not running",
                request_id,
            ));
        }
    }

    let action = envelope
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    // 待确认会话由 Agent 写入，App 的协调器负责唤起身份验证。
    let req = map_extension_to_agent(&envelope, action)?;
    let session_id = envelope.get("browser_session_id").and_then(Value::as_str).unwrap_or("");
    if session_id.is_empty() {
        return Ok(error_envelope("protocol_mismatch", "请重新加载更新后的 CredPivot 扩展", request_id));
    }
    let resp = call_agent(&socket, AgentRequest::BrowserRequest {
        session_id: session_id.to_string(), request: Box::new(req),
    }).await?;
    Ok(agent_to_extension(resp, request_id))
}

fn map_extension_to_agent(
    envelope: &Value,
    action: &str,
) -> Result<AgentRequest, Box<dyn std::error::Error>> {
    match action {
        "handshake" | "extension.connect" => Ok(AgentRequest::ExtensionConnect),
        "status" | "agent.status" => Ok(AgentRequest::Status),
        "credential.save" => Ok(AgentRequest::CredentialSave {
            request_id: envelope
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            origin: envelope
                .get("origin")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            username: envelope
                .get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            password: envelope
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            display_name: String::new(),
            connection_host: String::new(),
            linked_totp_id: None,
            group_id: None,
        }),
        "credential.suggest_for_origin" => Ok(AgentRequest::CredentialSuggest {
            origin: envelope
                .get("origin")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }),
        "credential.fill_prepare" => Ok(AgentRequest::CredentialFillPrepare {
            request_id: envelope
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            credential_id: envelope
                .get("credential_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            origin: envelope
                .get("origin")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            tab_id: envelope.get("tab_id").and_then(|v| v.as_u64()).unwrap_or(0),
            frame_id: envelope
                .get("frame_id")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
            document_id: envelope
                .get("document_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }),
        "credential.fill_consume" => Ok(AgentRequest::CredentialFillConsume {
            request_id: envelope
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            frame_id: envelope
                .get("frame_id")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
            document_id: envelope
                .get("document_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            origin: envelope
                .get("origin")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }),
        "cancel" => Ok(AgentRequest::CancelRequest {
            request_id: envelope
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }),
        "credential.totp_code" => Ok(AgentRequest::BrowserTotpCode {
            credential_id: envelope.get("credential_id").and_then(Value::as_str).unwrap_or("").into(),
            origin: envelope.get("origin").and_then(Value::as_str).unwrap_or("").into(),
        }),
        "credential.update" => Ok(AgentRequest::BrowserCredentialUpdate {
            credential_id: envelope.get("credential_id").and_then(Value::as_str).unwrap_or("").into(),
            expected_revision: envelope.get("expected_revision").and_then(Value::as_str).unwrap_or("").into(),
            origin: envelope.get("origin").and_then(Value::as_str).unwrap_or("").into(),
            username: envelope.get("username").and_then(Value::as_str).unwrap_or("").into(),
            password: envelope.get("password").and_then(Value::as_str).unwrap_or("").into(),
        }),
        other => Err(format!("unsupported action: {other}").into()),
    }
}

fn agent_to_extension(resp: AgentResponse, request_id: Option<Value>) -> Value {
    let mut out = match resp {
        AgentResponse::Ok {
            protocol_version,
            payload,
        } => json!({
            "ok": true,
            "protocol_version": protocol_version,
            "payload": payload,
        }),
        AgentResponse::Err {
            protocol_version,
            code,
            message,
        } => json!({
            "ok": false,
            "protocol_version": protocol_version,
            "code": code,
            "message": message,
        }),
    };
    if let Some(rid) = request_id {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("request_id".to_string(), rid);
        }
    }
    out
}

fn error_envelope(code: &str, message: &str, request_id: Option<Value>) -> Value {
    agent_to_extension(
        AgentResponse::Err {
            protocol_version: PROTOCOL_VERSION,
            code: code.to_string(),
            message: message.to_string(),
        },
        request_id,
    )
}

fn write_native_message(stdout: &mut io::Stdout, value: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(value)?;
    let len = (body.len() as u32).to_le_bytes();
    stdout.write_all(&len)?;
    stdout.write_all(&body)?;
    stdout.flush()?;
    Ok(())
}
