use credpivot_agent::{agent_socket_path, call_agent, AgentRequest, AgentResponse};
use std::env;
use std::io::{self, Write};
use std::process;

fn main() {
    if let Err(e) = run() {
        eprintln!("credpivot-askpass: {e}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let session_id = env::var("CREDPIVOT_SESSION_ID")
        .map_err(|_| "CREDPIVOT_SESSION_ID not set")?;
    if session_id.trim().is_empty() {
        return Err("CREDPIVOT_SESSION_ID is empty".into());
    }
    let prompt = env::var("SSH_ASKPASS_PROMPT")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| env::args().nth(1))
        .unwrap_or_default();

    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let force_kind = env::var("CREDPIVOT_FORCE_KIND")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let resp = rt
        .block_on(call_agent(
            &agent_socket_path(),
            AgentRequest::SshAskpass {
                session_id,
                prompt,
                force_kind,
            },
        ))
        .map_err(|e| e.to_string())?;

    match resp {
        AgentResponse::Ok { payload, .. } => {
            let secret = payload
                .get("secret")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if secret.is_empty() {
                return Err("agent returned empty secret".into());
            }
            let mut out = io::stdout().lock();
            out.write_all(secret.as_bytes())
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        AgentResponse::Err { message, .. } => Err(message),
    }
}
