use serde_json::Value;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const REQUEST_TTL: Duration = Duration::from_secs(180);

pub struct Pending {
    pub origin: String,
    pub image: Option<String>,
    pub session: Uuid,
    pub claimed: bool,
    pub outcome: Option<Value>,
    created: Instant,
}

#[derive(Default)]
pub struct PendingRequests(pub HashMap<String, Pending>);

impl std::fmt::Debug for PendingRequests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingMfaRequests")
            .field("count", &self.0.len())
            .finish()
    }
}

impl PendingRequests {
    pub fn clear(&mut self) {
        self.0.clear();
    }
    pub fn expire(&mut self) {
        self.0
            .retain(|_, request| request.created.elapsed() < REQUEST_TTL);
    }
    pub fn insert(&mut self, id: String, origin: String, image: String, session: Uuid) {
        self.0.insert(
            id,
            Pending {
                origin,
                image: Some(image),
                session,
                claimed: false,
                outcome: None,
                created: Instant::now(),
            },
        );
    }
}
