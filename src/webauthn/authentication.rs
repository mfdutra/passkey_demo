use crate::db::{challenges, credentials, users};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use serde_json::Value;
use webauthn_rs::prelude::*;

pub async fn start_authentication(state: &AppState, username: &str) -> AppResult<RequestChallengeResponse> {
    // Get user
    let user = users::find_by_username(&state.db, username).await?;

    // Get user's credentials
    let stored_creds = credentials::find_by_user_id(&state.db, &user.id).await?;

    if stored_creds.is_empty() {
        return Err(AppError::NotFound(format!(
            "No passkeys found for user '{}'",
            username
        )));
    }

    // Convert stored credentials to Passkey objects by deserializing
    let passkeys: Result<Vec<Passkey>, _> = stored_creds
        .iter()
        .map(|cred| {
            let passkey: Passkey = serde_json::from_slice(&cred.credential_public_key)?;
            Ok(passkey)
        })
        .collect();

    let passkeys = passkeys.map_err(|e: serde_json::Error| AppError::Serialization(e))?;

    // Generate authentication challenge
    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::WebAuthn(e))?;

    // Serialize and store authentication state
    let state_bytes = serde_json::to_vec(&auth_state)?;
    challenges::save_authentication_challenge(&state.db, &user.id, &state_bytes).await?;

    Ok(rcr)
}

pub async fn finish_authentication(
    state: &AppState,
    user_id: &str,
    credential: &Value,
) -> AppResult<String> {
    // Get user
    let user = users::find_by_id(&state.db, user_id).await?;

    // Retrieve authentication challenge state
    let challenge = challenges::get_authentication_challenge(&state.db, &user.id).await?;

    // Deserialize authentication state
    let auth_state: PasskeyAuthentication = serde_json::from_slice(&challenge.challenge_state)?;

    // Parse the credential from JSON
    let auth_credential: PublicKeyCredential = serde_json::from_value(credential.clone())?;

    // Verify the credential
    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&auth_credential, &auth_state)
        .map_err(|e| AppError::WebAuthn(e))?;

    // Update counter in database
    let cred_id = format!("{:?}", auth_result.cred_id());
    let new_counter = auth_result.counter();

    credentials::update_counter(&state.db, &cred_id, new_counter).await?;

    // Delete used challenge
    challenges::delete_authentication_challenge(&state.db, &user.id).await?;

    Ok(user.id)
}
