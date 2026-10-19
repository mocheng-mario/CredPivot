mod chrome_parent;
mod launch_app;

use chrome_parent::verify_chrome_parent;
use credpivot_agent::{agent_socket_path, call_agent, AgentRequest, AgentResponse, PROTOCOL_VERSION};
use launch_app::{launch_credpivot_app, wait_for_agent_socket};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(e) = verify_chrome_parent() {
        eprintln!("credpivot-native-host: parent check failed: {e}");
        std::process::exit(1);
    }

    if let Err(e) = run_native_messaging_loop() {
        eprintln!("credpivot-native-host: {e}");
        std::process::exit(1);
    }
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
        let response = tokio::runtime::Runtime::new()?.block_on(async {
            forward_to_agent(value).await
        })?;
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
    let socket = agent_socket_path();
    if !socket.exists() {
        launch_credpivot_app();
        let ok = wait_for_agent_socket(&socket, 8_000).await;
        if !ok {
            return Ok(error_envelope(
                "app_unreachable",
                "CredPivot App is not running",
            ));
        }
    }

    let action = envelope
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let req = map_extension_to_agent(&envelope, action)?;
    let resp = call_agent(&socket, req).await?;
    Ok(agent_to_extension(resp))
}

fn map_extension_to_agent(
    envelope: &Value,
    action: &str,
) -> Result<AgentRequest, Box<dyn std::error::Error>> {
    match action {
        "handshake" => Ok(AgentRequest::Ping),
        "status" => Ok(AgentRequest::Status),
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
        }),
        "cancel" => Ok(AgentRequest::CancelRequest {
            request_id: envelope
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        }),
        other => Err(format!("unsupported action: {other}").into()),
    }
}

fn agent_to_extension(resp: AgentResponse) -> Value {
    match resp {
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
    }
}

fn error_envelope(code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "protocol_version": PROTOCOL_VERSION,
        "code": code,
        "message": message,
    })
}

fn write_native_message(stdout: &mut io::Stdout, value: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(value)?;
    let len = (body.len() as u32).to_le_bytes();
    stdout.write_all(&len)?;
    stdout.write_all(&body)?;
    stdout.flush()?;
    Ok(())
}
