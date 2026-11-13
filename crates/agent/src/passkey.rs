use credpivot_core::passkey::Request;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const REQUEST_TTL: Duration = Duration::from_secs(120);

#[derive(Debug)]
pub struct Pending {
    pub request: Request,
    pub session: Uuid,
    pub outcome: Option<Value>,
    pub preferred_linked_login_id: Option<String>,
    created: Instant,
}

#[derive(Debug, Default)]
pub struct PendingRequests(pub HashMap<String, Pending>);

impl PendingRequests {
    pub fn clear(&mut self) {
        self.0.clear();
    }

    pub fn expire(&mut self) {
        self.0.retain(|_, p| p.created.elapsed() < REQUEST_TTL);
    }

    pub fn insert(
        &mut self,
        id: String,
        request: Request,
        session: Uuid,
        preferred_linked_login_id: Option<String>,
    ) {
        self.0.insert(
            id,
            Pending {
                request,
                session,
                outcome: None,
                preferred_linked_login_id,
                created: Instant::now(),
            },
        );
    }
}

pub fn rejected(name: &str, message: &str) -> Value {
    json!({"state":"done","error":{"name":name,"message":message}})
}
