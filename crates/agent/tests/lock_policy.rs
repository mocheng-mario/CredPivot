use credpivot_agent::{
    handle_request, AgentRequest, AgentResponse, IpcState, M0Vault, PeerAuthConfig,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

fn test_state() -> IpcState {
    IpcState {
        vault: Arc::new(Mutex::new(M0Vault::new())),
        pending_fills: HashMap::new(),
        peer_auth: PeerAuthConfig::default(),
    }
}

fn assert_err_locked(resp: AgentResponse) {
    match resp {
        AgentResponse::Err { code, .. } => assert_eq!(code, "locked"),
        other => panic!("expected locked error, got {other:?}"),
    }
}

#[tokio::test]
async fn locked_vault_rejects_sensitive_agent_ops() {
    let mut st = test_state();
    assert_err_locked(
        handle_request(
            &mut st,
            AgentRequest::CredentialSave {
                request_id: "r1".into(),
                origin: "https://example.com".into(),
                username: "u".into(),
                password: "p".into(),
            },
        )
        .await,
    );
    assert_err_locked(
        handle_request(
            &mut st,
            AgentRequest::CredentialSuggest {
                origin: "https://example.com".into(),
            },
        )
        .await,
    );
}

#[tokio::test]
async fn unlock_then_save_then_lock_blocks_again() {
    let mut st = test_state();
    let unlock = handle_request(
        &mut st,
        AgentRequest::UnlockPassword {
            password: "credpivot-m0".into(),
        },
    )
    .await;
    assert!(matches!(unlock, AgentResponse::Ok { .. }));

    let save = handle_request(
        &mut st,
        AgentRequest::CredentialSave {
            request_id: "r2".into(),
            origin: "https://example.com".into(),
            username: "u".into(),
            password: "p".into(),
        },
    )
    .await;
    assert!(matches!(save, AgentResponse::Ok { .. }));

    let lock = handle_request(&mut st, AgentRequest::Lock).await;
    assert!(matches!(lock, AgentResponse::Ok { .. }));

    assert_err_locked(
        handle_request(
            &mut st,
            AgentRequest::CredentialSave {
                request_id: "r3".into(),
                origin: "https://example.com".into(),
                username: "u".into(),
                password: "p".into(),
            },
        )
        .await,
    );
}

#[tokio::test]
async fn status_reports_locked_without_unlock() {
    let mut st = test_state();
    let resp = handle_request(&mut st, AgentRequest::Status).await;
    let AgentResponse::Ok { payload, .. } = resp else {
        panic!("expected ok status");
    };
    assert_eq!(payload.get("unlocked").and_then(|v| v.as_bool()), Some(false));
}
