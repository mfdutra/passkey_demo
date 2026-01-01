use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: String,
    pub updated_at: String,
}

impl User {
    pub fn new(username: String, display_name: String) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            username,
            display_name,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PasskeyCredential {
    pub id: String,
    pub user_id: String,
    pub credential_public_key: Vec<u8>,
    pub counter: i64,
    pub transports: Option<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub attestation_format: Option<String>,
    pub attestation_data: Option<Vec<u8>>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RegistrationChallenge {
    pub id: String,
    pub user_id: String,
    pub challenge_state: Vec<u8>,
    pub created_at: String,
    pub expires_at: String,
}

impl RegistrationChallenge {
    pub fn new(user_id: String, challenge_state: Vec<u8>) -> Self {
        let now = Utc::now();
        let expires = now + chrono::Duration::minutes(5);

        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            challenge_state,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthenticationChallenge {
    pub id: String,
    pub user_id: String,
    pub challenge_state: Vec<u8>,
    pub created_at: String,
    pub expires_at: String,
}

impl AuthenticationChallenge {
    pub fn new(user_id: String, challenge_state: Vec<u8>) -> Self {
        let now = Utc::now();
        let expires = now + chrono::Duration::minutes(5);

        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            challenge_state,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        }
    }
}
