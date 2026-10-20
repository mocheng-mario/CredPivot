use credpivot_agent::{
    handle_request, AgentRequest, AgentResponse, IpcState, PeerAuthConfig, RequestPeerContext,
    VaultSession,
};
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;

fn test_state() -> (IpcState, tempfile::TempDir) {
    let dir = tempdir().expect("tmpdir");
    std::env::set_var("CREDPIVOT_VAULT_DIR", dir.path());
    let vault = VaultSession::new_at(dir.path().to_path_buf());
    let state = IpcState {
        vault: Arc::new(Mutex::new(vault)),
        pending_fills: HashMap::new(),
        peer_auth: PeerAuthConfig::default(),
        extension_gate_expires_ms: 0,
        extension_gate_last_native_ms: 0,
        shutting_down: false,
    };
    (state, dir)
}

fn assert_err_locked(resp: AgentResponse) {
    match resp {
        AgentResponse::Err { code, .. } => assert_eq!(code, "locked"),
        other => panic!("expected locked error, got {other:?}"),
    }
}

#[tokio::test]
async fn locked_vault_rejects_sensitive_agent_ops() {
    let (mut st, _dir) = test_state();
    assert_err_locked(
        handle_request(
            &mut st,
            AgentRequest::CredentialSave {
                request_id: "r1".into(),
                origin: "https://example.com".into(),
                username: "u".into(),
                password: "p".into(),
                display_name: String::new(),
                connection_host: String::new(),
                linked_totp_id: None,
                group_id: None,
            },
            RequestPeerContext::default(),
        )
        .await,
    );
}

#[tokio::test]
async fn unlock_then_save_then_lock_blocks_again() {
    let (mut st, _dir) = test_state();
    let create = handle_request(
        &mut st,
        AgentRequest::VaultCreate {
            password: "test-vault-pass".into(),
        },
        RequestPeerContext::default(),
    )
    .await;
    assert!(matches!(create, AgentResponse::Ok { .. }));

    let save = handle_request(
        &mut st,
        AgentRequest::CredentialSave {
            request_id: "r2".into(),
            origin: "https://example.com".into(),
            username: "u".into(),
            password: "p".into(),
            display_name: String::new(),
            connection_host: String::new(),
            linked_totp_id: None,
            group_id: None,
        },
        RequestPeerContext::default(),
    )
    .await;
    assert!(matches!(save, AgentResponse::Ok { .. }));

    let lock = handle_request(
        &mut st,
        AgentRequest::Lock,
        RequestPeerContext::default(),
    )
    .await;
    assert!(matches!(lock, AgentResponse::Ok { .. }));

    assert_err_locked(
        handle_request(
            &mut st,
            AgentRequest::CredentialSave {
                request_id: "r3".into(),
                origin: "https://example.com".into(),
                username: "u".into(),
                password: "p".into(),
                display_name: String::new(),
                connection_host: String::new(),
                linked_totp_id: None,
                group_id: None,
            },
            RequestPeerContext::default(),
        )
        .await,
    );
}

#[tokio::test]
async fn status_reports_locked_without_unlock() {
    let (mut st, _dir) = test_state();
    let resp = handle_request(
        &mut st,
        AgentRequest::Status,
        RequestPeerContext::default(),
    )
    .await;
    let AgentResponse::Ok { payload, .. } = resp else {
        panic!("expected ok status");
    };
    assert_eq!(payload.get("unlocked").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(payload.get("format").and_then(|v| v.as_str()), Some("m2"));
}
