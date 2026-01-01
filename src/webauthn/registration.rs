use crate::db::{challenges, credentials, users};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use base64::prelude::*;
use serde_json::Value;
use webauthn_rs::prelude::*;

pub async fn start_registration(
    state: &AppState,
    username: &str,
    display_name: &str,
) -> AppResult<CreationChallengeResponse> {
    // Check if user already exists
    if users::find_by_username(&state.db, username).await.is_ok() {
        return Err(AppError::BadRequest(format!(
            "User '{}' already exists",
            username
        )));
    }

    // Create new user
    let user = users::create_user(&state.db, username, display_name).await?;

    // Generate WebAuthn registration challenge
    let user_uuid = Uuid::parse_str(&user.id)
        .map_err(|_| AppError::Internal("Invalid user UUID".to_string()))?;

    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_uuid, &user.username, &user.display_name, None)
        .map_err(|e| AppError::WebAuthn(e))?;

    // Serialize and store registration state
    let state_bytes = serde_json::to_vec(&reg_state)?;
    challenges::save_registration_challenge(&state.db, &user.id, &state_bytes).await?;

    Ok(ccr)
}

pub async fn finish_registration(
    state: &AppState,
    user_id: &str,
    credential: &Value,
) -> AppResult<()> {
    // Convert base64url user ID back to UUID
    // The user_id comes from the frontend as base64url encoded bytes
    // We need to decode it and convert to UUID string
    let user_id_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(user_id.as_bytes())
        .map_err(|_| AppError::BadRequest("Invalid user ID encoding".to_string()))?;

    let user_uuid = Uuid::from_slice(&user_id_bytes)
        .map_err(|_| AppError::BadRequest("Invalid user ID format".to_string()))?;

    let user_id_str = user_uuid.to_string();

    // Get user
    let user = users::find_by_id(&state.db, &user_id_str).await?;

    // Retrieve registration challenge state
    let challenge = challenges::get_registration_challenge(&state.db, &user.id).await?;

    // Deserialize registration state
    let reg_state: PasskeyRegistration = serde_json::from_slice(&challenge.challenge_state)?;

    // Parse the credential from JSON
    let reg_credential: RegisterPublicKeyCredential = serde_json::from_value(credential.clone())?;

    // Verify the credential
    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg_credential, &reg_state)
        .map_err(|e| AppError::WebAuthn(e))?;

    // Store the credential in database
    // Serialize the entire Passkey object
    let passkey_bytes = serde_json::to_vec(&passkey)?;
    let cred_id = format!("{:?}", passkey.cred_id()); // Debug format for now

    credentials::save_credential(
        &state.db,
        &cred_id,
        &user.id,
        &passkey_bytes,
        0, // counter - will be updated during authentication
        None, // transports
        false, // backup_eligible
        false, // backup_state
    )
    .await?;

    // Delete used challenge
    challenges::delete_registration_challenge(&state.db, &user.id).await?;

    Ok(())
}
