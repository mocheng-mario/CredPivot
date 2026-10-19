use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// M0 fake vault: in-memory only, no SQLCipher.
#[derive(Debug)]
pub struct M0Vault {
    pub unlocked: bool,
    /// Demo password for M0: `credpivot-m0`
    pub demo_password: String,
    pub touch_id_wrapped_token: Option<Vec<u8>>,
    pub credentials: HashMap<String, FakeCredential>,
    pub ssh_signing_key: SigningKey,
    pub idle_timeout: Duration,
    pub last_activity: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeCredential {
    pub id: String,
    pub origin: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillGrant {
    pub request_id: String,
    pub credential_id: String,
    pub origin: String,
    pub tab_id: u64,
    pub frame_id: i64,
    pub document_id: String,
    pub expires_at_ms: u128,
}

impl M0Vault {
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            unlocked: false,
            demo_password: "credpivot-m0".into(),
            touch_id_wrapped_token: None,
            credentials: HashMap::new(),
            ssh_signing_key: signing_key,
            idle_timeout: Duration::from_secs(5 * 60),
            last_activity: Instant::now(),
        }
    }

    pub fn touch_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn idle_expired(&self) -> bool {
        self.unlocked && self.last_activity.elapsed() > self.idle_timeout
    }

    pub fn lock(&mut self) {
        self.unlocked = false;
    }

    pub fn unlock_password(&mut self, password: &str) -> bool {
        if password == self.demo_password {
            self.unlocked = true;
            self.touch_activity();
            true
        } else {
            false
        }
    }

    pub fn unlock_touch_id_token(&mut self, token: &[u8]) -> bool {
        if self.touch_id_wrapped_token.as_deref() == Some(token) {
            self.unlocked = true;
            self.touch_activity();
            true
        } else {
            false
        }
    }

    pub fn ssh_public_key_openssh(&self) -> String {
        let vk: VerifyingKey = self.ssh_signing_key.verifying_key();
        let bytes = vk.to_bytes();
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        format!("ssh-ed25519 {b64} credpivot-m0")
    }

    pub fn save_credential(&mut self, origin: &str, username: &str, password: &str) -> FakeCredential {
        let id = uuid::Uuid::new_v4().to_string();
        let cred = FakeCredential {
            id,
            origin: origin.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        };
        self.credentials.insert(cred.id.clone(), cred.clone());
        cred
    }

    pub fn suggest_for_origin(&self, origin: &str) -> Vec<FakeCredential> {
        self.credentials
            .values()
            .filter(|c| c.origin == origin)
            .cloned()
            .collect()
    }
}