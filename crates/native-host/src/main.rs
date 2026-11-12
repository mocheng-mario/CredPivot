mod chrome_parent;
mod launch_app;

use chrome_parent::verify_chrome_parent;
use credpivot_agent::{
    agent_socket_path, call_agent, diagnostics, AgentRequest, AgentResponse, PROTOCOL_VERSION,
};
use launch_app::{launch_credpivot_app, wait_for_agent_socket};
use serde_json::{json, Value};
use std::io::{self, Read, Write};

const MAX_NATIVE_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

fn main() {
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
    let parent = verify_chrome_parent();
    if let Err(error) = &parent { diagnostics::error("native_host", error.event()); }
    // 复用单线程运行时；中继逐个处理请求，不需要每条消息创建一组 Tokio 工作线程。
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

    loop {
        let mut len_buf = [0u8; 4];
        if read_exact_or_eof(&mut handle, &mut len_buf)? {
            break;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_NATIVE_MESSAGE_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "native message size invalid").into());
        }
        let mut msg = vec![0u8; len];
        if read_exact_or_eof(&mut handle, &mut msg)? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "native message truncated").into());
        }
        let value: Value = serde_json::from_slice(&msg)?;
        let request_id = value.get("request_id").cloned();
        if let Err(error) = &parent {
            write_native_message(&mut stdout, &error_envelope("browser_parent_denied", &error.to_string(), request_id))?;
            continue;
        }
        let response = runtime.block_on(async {
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
            Ok(0) if off == 0 => return Ok(true),
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "native message truncated")),
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

async fn forward_to_agent(envelope: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let started = std::time::Instant::now();
    let action = envelope.get("action").and_then(Value::as_str).unwrap_or("unknown");
    let verification = matches!(action, "handshake" | "extension.connect" | "extension.cancel" | "passkey.begin");
    if verification {
        let queued_ms = envelope.get("verification_started_ms").and_then(Value::as_u64).map(|sent| {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64).unwrap_or(sent);
            now.saturating_sub(sent)
        }).unwrap_or(0);
        diagnostics::browser_auth_event("native received verification command", queued_ms);
    }
    let request_id = envelope.get("request_id").cloned();
    let socket = agent_socket_path();
    // 文件存在也可能是崩溃遗留的 socket；以实际可连接性判断。
    if !matches!(tokio::time::timeout(std::time::Duration::from_secs(1), tokio::net::UnixStream::connect(&socket)).await, Ok(Ok(_))) {
        if !launch_credpivot_app() {
            return Ok(error_envelope("app_unreachable", "请从目标版本 App 更新 Native Host 后重试", request_id));
        }
        let ok = wait_for_agent_socket(&socket, 8_000).await;
        if !ok {
            return Ok(error_envelope(
                "app_unreachable",
                "CredPivot App is not running",
                request_id,
            ));
        }
    }

    // 待确认会话由 Agent 写入，App 的协调器负责唤起身份验证。
    let req = map_extension_to_agent(&envelope, action)?;
    let session_id = envelope.get("browser_session_id").and_then(Value::as_str).unwrap_or("");
    if session_id.is_empty() {
        return Ok(error_envelope("protocol_mismatch", "请重新加载更新后的 CredPivot 扩展", request_id));
    }
    let response = tokio::time::timeout(std::time::Duration::from_secs(20), call_agent(&socket, AgentRequest::BrowserRequest {
        session_id: session_id.to_string(), request: Box::new(req),
    })).await;
    if verification {
        diagnostics::browser_auth_event("Agent verification command returned", started.elapsed().as_millis() as u64);
    }
    let resp = match response {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return Ok(error_envelope("agent_unavailable", "本机 Agent 连接已中断，请重试", request_id)),
        Err(_) => return Ok(error_envelope("agent_timeout", "本机 Agent 响应超时；写入和签名不会自动重复，请检查后重试", request_id)),
    };
    // 唤醒后台 App 检查标记，避免仅靠定时器发现请求。通知本身不携带或授予授权。
    if (matches!(&resp, AgentResponse::Err { code, .. } if code == "extension_gate_required")
        && matches!(action, "handshake" | "extension.connect" | "passkey.begin"))
        || action == "extension.cancel"
    {
        notify_browser_verification();
    }
    let mut response = agent_to_extension(resp, request_id);
    if let Some(payload) = response.get_mut("payload").and_then(Value::as_object_mut) {
        payload.insert("native_host_version".into(),json!(env!("CARGO_PKG_VERSION")));
    }
    Ok(response)
}

fn notify_browser_verification() {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn notify_post(name: *const std::ffi::c_char) -> u32;
        }
        // Darwin 通知只提示 App 重新读取经过 Agent 校验的待验证请求。
        if unsafe { notify_post(b"com.credpivot.browser-verification\0".as_ptr().cast()) } != 0 {
            diagnostics::warn("native_host", "browser verification notification failed");
        }
    }
}

fn map_extension_to_agent(
    envelope: &Value,
    action: &str,
) -> Result<AgentRequest, Box<dyn std::error::Error>> {
    match action {
        "handshake" | "extension.connect" => Ok(AgentRequest::ExtensionConnect {
            request_id: envelope["request_id"].as_str().unwrap_or("").into(),
        }),
        "extension.cancel" => Ok(AgentRequest::ExtensionGateCancel {
            request_id: envelope["gate_request_id"].as_str().unwrap_or("").into(),
        }),
        "status" | "agent.status" => Ok(AgentRequest::Status),
        "mfa.begin" => Ok(AgentRequest::BrowserMfaBegin {
            request_id: envelope["mfa_request_id"].as_str().unwrap_or("").into(),
            origin: envelope["origin"].as_str().unwrap_or("").into(),
            image: envelope["image"].as_str().unwrap_or("").into(),
        }),
        "mfa.poll" => Ok(AgentRequest::BrowserMfaPoll {
            request_id: envelope["mfa_request_id"].as_str().unwrap_or("").into(),
            origin: envelope["origin"].as_str().unwrap_or("").into(),
        }),
        "mfa.cancel" => Ok(AgentRequest::BrowserMfaCancel {
            request_id: envelope["mfa_request_id"].as_str().unwrap_or("").into(),
        }),
        "passkey.begin" => Ok(AgentRequest::PasskeyBegin {
            request_id: envelope["passkey_request_id"].as_str().unwrap_or("").into(),
            kind: envelope["kind"].as_str().unwrap_or("").into(),
            origin: envelope["origin"].as_str().unwrap_or("").into(),
            options: envelope["options"].clone(),
        }),
        "passkey.poll" => Ok(AgentRequest::PasskeyPoll {
            request_id: envelope["passkey_request_id"].as_str().unwrap_or("").into(),
            origin: envelope["origin"].as_str().unwrap_or("").into(),
        }),
        "passkey.cancel" => Ok(AgentRequest::PasskeyCancel {
            request_id: envelope["passkey_request_id"].as_str().unwrap_or("").into(),
        }),
        "credential.save" => Ok(AgentRequest::CredentialSave {
            password_active_since_ms: None,
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
            display_name: envelope
                .get("display_name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            partition_id: envelope
                .get("partition_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            connection_host: String::new(),
            linked_totp_id: None,
            group_id: None,
            website_rules: None,
            linked_mfa_ids: None,
        }),
        "partitions.list" => Ok(AgentRequest::BrowserPartitions),
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
        "mfa.suggest_for_origin" => Ok(AgentRequest::BrowserMfaSuggest {
            include_other_matches: envelope.get("include_other_matches").and_then(Value::as_bool).unwrap_or(false),
            credential_id: envelope.get("credential_id").and_then(Value::as_str).unwrap_or("").into(),
            origin: envelope.get("origin").and_then(Value::as_str).unwrap_or("").into(),
        }),
        "credential.totp_code" => Ok(AgentRequest::BrowserTotpCode {
            totp_id: envelope.get("totp_id").and_then(Value::as_str).unwrap_or("").into(),
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
            // 记录标识等 App 专用错误详情不转发给浏览器扩展。
            ..
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
            details: None,
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
