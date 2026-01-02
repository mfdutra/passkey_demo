//! # Passkey Authentication Logic
//!
//! This module handles the server-side logic for authenticating with passkeys.
//! Authentication is a two-step process: start and finish.
//!
//! ## Authentication Flow
//! 1. **Start**: Look up user's credentials → generate challenge → send to client
//! 2. **Finish**: Verify signature → update counter → create session
//!
//! ## Security Concepts
//! - **Challenge**: Fresh random value prevents replay attacks
//! - **Signature Verification**: Proves the user has the private key
//! - **Counter**: Increments on each use, detects cloned credentials

use crate::db::{challenges, credentials, users};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use base64::prelude::*; // For base64url encoding/decoding
use serde_json::Value;
use webauthn_rs::prelude::*;

/// Start the passkey authentication process
///
/// This is Step 1 of authentication. Looks up the user's registered credentials
/// and generates a cryptographic challenge for the client to sign.
///
/// ## Flow
/// 1. Find user by username
/// 2. Retrieve all passkeys registered to that user
/// 3. Generate authentication challenge
/// 4. Store challenge state in database (for verification later)
/// 5. Return challenge + allowed credentials to client
///
/// ## Parameters
/// - `state`: Application state (database + WebAuthn instance)
/// - `username`: Username attempting to log in
///
/// ## Returns
/// `RequestChallengeResponse` containing:
/// - Challenge (random bytes to sign)
/// - Allowed credentials (which passkeys can be used)
/// - RP ID
/// - Timeout
///
/// ## Errors
/// - NotFound: User doesn't exist or has no passkeys
/// - Database: Query failed
/// - Serialization: Stored credential data is corrupted
///
/// ## Client Behavior
/// The client will:
/// 1. Receive this challenge
/// 2. Prompt user to authenticate (Face ID, fingerprint, etc.)
/// 3. Sign the challenge with the private key
/// 4. Send the signed assertion back to finish_authentication
pub async fn start_authentication(
    state: &AppState,
    username: &str,
) -> AppResult<RequestChallengeResponse> {
    // Look up user by username
    let user = users::find_by_username(&state.db, username).await?;

    // Get all passkey credentials registered to this user
    // A user can have multiple passkeys (phone, laptop, security key, etc.)
    let stored_creds = credentials::find_by_user_id(&state.db, &user.id).await?;

    // Check if user has any passkeys
    if stored_creds.is_empty() {
        return Err(AppError::NotFound(format!(
            "No passkeys found for user '{}'",
            username
        )));
    }

    // Convert stored credentials (bytes) to Passkey objects
    // We stored the entire Passkey struct serialized as bytes
    // Now we deserialize them back to use with webauthn-rs
    //
    // The ? in the closure propagates serde errors
    // The collect() gathers all Results into a Result<Vec<_>>
    let passkeys: Result<Vec<Passkey>, _> = stored_creds
        .iter()
        .map(|cred| {
            // Deserialize bytes → Passkey
            let passkey: Passkey = serde_json::from_slice(&cred.credential_public_key)?;
            Ok(passkey)
        })
        .collect();

    // Convert Result<Vec<Passkey>, serde_json::Error> → Result<Vec<Passkey>, AppError>
    let passkeys = passkeys.map_err(|e: serde_json::Error| AppError::Serialization(e))?;

    // Generate authentication challenge
    //
    // webauthn-rs creates:
    // - rcr: RequestChallengeResponse (sent to client)
    //   - Contains the challenge and list of allowed credential IDs
    // - auth_state: PasskeyAuthentication (stored server-side)
    //   - Contains challenge and expected values for verification
    //
    // The client will see which credentials can be used
    // and prompt the user to authenticate with one of them
    let (rcr, auth_state) = state
        .webauthn
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::WebAuthn(e))?;

    // Serialize authentication state to bytes for database storage
    // We'll need this to verify the signature later
    let state_bytes = serde_json::to_vec(&auth_state)?;

    // Store challenge in database with 5-minute expiration
    challenges::save_authentication_challenge(&state.db, &user.id, &state_bytes).await?;

    // Return challenge to client
    // The client will use navigator.credentials.get() with this data
    Ok(rcr)
}

/// Finish the passkey authentication process
///
/// This is Step 2 of authentication. Verifies the signed assertion from the
/// authenticator and logs the user in if valid.
///
/// ## Flow
/// 1. Decode user ID from base64url
/// 2. Retrieve stored challenge from database
/// 3. Parse assertion from client
/// 4. Verify signature using stored public key
/// 5. Update signature counter (replay attack prevention)
/// 6. Delete one-time-use challenge
/// 7. Return user ID (caller will create session)
///
/// ## Parameters
/// - `state`: Application state (database + WebAuthn instance)
/// - `user_id`: Base64url-encoded user ID (from userHandle)
/// - `credential`: The assertion from navigator.credentials.get()
///
/// ## What gets verified?
/// - Signature is valid (proves user has private key)
/// - Challenge matches what we sent
/// - Challenge hasn't expired
/// - Counter is incremented (detects cloned credentials)
/// - RP ID matches our server
/// - Origin matches our server
///
/// ## Returns
/// User ID string (to create a session)
///
/// ## Errors
/// - BadRequest: Invalid user ID encoding or format
/// - NotFound: User or challenge not found
/// - Unauthorized: Challenge expired
/// - WebAuthn: Signature verification failed or counter anomaly
///
/// ## Security: Counter Validation
/// The signature counter increments with each authentication.
/// If the counter goes backwards, it may indicate a cloned credential.
/// webauthn-rs will reject the authentication in this case.
pub async fn finish_authentication(
    state: &AppState,
    user_id: &str,
    credential: &Value,
) -> AppResult<String> {
    // Convert base64url user ID back to UUID
    // Same decoding process as registration
    let user_id_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(user_id.as_bytes())
        .map_err(|_| AppError::BadRequest("Invalid user ID encoding".to_string()))?;

    let user_uuid = Uuid::from_slice(&user_id_bytes)
        .map_err(|_| AppError::BadRequest("Invalid user ID format".to_string()))?;

    let user_id_str = user_uuid.to_string();

    // Look up the user
    let user = users::find_by_id(&state.db, &user_id_str).await?;

    // Retrieve the authentication challenge we stored earlier
    // This contains the challenge and expected values for verification
    let challenge = challenges::get_authentication_challenge(&state.db, &user.id).await?;

    // Deserialize the challenge state from bytes back to PasskeyAuthentication
    // PasskeyAuthentication contains:
    // - The original challenge bytes
    // - Expected RP ID and origin
    // - Allowed credential IDs
    // - User verification requirements
    let auth_state: PasskeyAuthentication = serde_json::from_slice(&challenge.challenge_state)?;

    // Parse the assertion JSON from the client
    // The client calls navigator.credentials.get() which returns an assertion
    // The assertion contains:
    // - id: Credential ID that was used
    // - rawId: Raw credential ID bytes
    // - response.clientDataJSON: Client data (challenge, origin, type)
    // - response.authenticatorData: Authenticator data (RP ID hash, flags, counter)
    // - response.signature: Cryptographic signature over clientData + authenticatorData
    // - response.userHandle: User ID (for identifying which user is authenticating)
    let auth_credential: PublicKeyCredential = serde_json::from_value(credential.clone())?;

    // Verify the assertion using webauthn-rs
    // This performs cryptographic verification:
    // 1. Looks up the public key for the credential ID
    // 2. Validates the challenge matches what we sent
    // 3. Verifies the signature using the public key
    // 4. Checks RP ID and origin
    // 5. Validates the counter (must increment)
    // 6. Checks user verification flags
    //
    // If verification succeeds, returns AuthenticationResult containing:
    // - Credential ID that was used
    // - New counter value
    // - Whether user was verified
    // - Backup state information
    let auth_result = state
        .webauthn
        .finish_passkey_authentication(&auth_credential, &auth_state)
        .map_err(|e| AppError::WebAuthn(e))?;

    // Update the signature counter in the database
    // This is critical for security - detecting cloned credentials
    //
    // The counter increments with each authentication
    // If we ever see the counter go backwards, the credential
    // may have been cloned and should be revoked
    let cred_id = format!("{:?}", auth_result.cred_id());
    let new_counter = auth_result.counter();

    credentials::update_counter(&state.db, &cred_id, new_counter).await?;

    // Delete the challenge from database
    // Challenges are one-time use only
    // This prevents replay attacks
    challenges::delete_authentication_challenge(&state.db, &user.id).await?;

    // Return user ID
    // The caller (auth handler) will use this to create a session
    Ok(user.id)
}
