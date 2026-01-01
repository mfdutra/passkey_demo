use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    pub user_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub user_id: String,
    pub credential: serde_json::Value,
}
