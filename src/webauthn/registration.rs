//! # Passkey Registration Logic
//!
//! This module handles the server-side logic for creating new passkey credentials.
//! Registration is a two-step process: start and finish.
//!
//! ## Registration Flow
//! 1. **Start**: Generate cryptographic challenge → send to client
//! 2. **Finish**: Verify credential response → store public key
//!
//! ## Security Concepts
//! - **Challenge**: Random value that must be signed to prove credential ownership
//! - **Public Key Cryptography**: Server stores public key, private key stays on device
//! - **Attestation**: Optional proof that the authenticator is legitimate

use crate::db::{challenges, credentials, users};
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use base64::prelude::*;  // For base64url encoding/decoding
use serde_json::Value;
use webauthn_rs::prelude::*;

/// Start the passkey registration process
///
/// This is Step 1 of registration. Creates a new user and generates a
/// cryptographic challenge for the client to complete with their authenticator.
///
/// ## Flow
/// 1. Check if username is available
/// 2. Create new user in database
/// 3. Generate WebAuthn registration challenge
/// 4. Store challenge state in database (for verification later)
/// 5. Return challenge to client
///
/// ## Parameters
/// - `state`: Application state (database + WebAuthn instance)
/// - `username`: Unique username for the new user
/// - `display_name`: Human-readable name (shown during passkey creation)
///
/// ## Returns
/// `CreationChallengeResponse` containing:
/// - Challenge (random bytes to sign)
/// - User information (ID, name)
/// - RP (Relying Party) information
/// - Authenticator selection criteria
///
/// ## Errors
/// - BadRequest: Username already taken
/// - Database: User creation or challenge storage failed
/// - Internal: Invalid UUID format
pub async fn start_registration(
    state: &AppState,
    username: &str,
    display_name: &str,
) -> AppResult<CreationChallengeResponse> {
    // Check if username is already taken
    // We check this first to fail fast before creating anything
    if users::find_by_username(&state.db, username).await.is_ok() {
        return Err(AppError::BadRequest(format!(
            "User '{}' already exists",
            username
        )));
    }

    // Create new user in database
    // This generates a UUID for the user
    let user = users::create_user(&state.db, username, display_name).await?;

    // Parse user ID string to UUID
    // WebAuthn requires UUID format for user IDs
    let user_uuid = Uuid::parse_str(&user.id)
        .map_err(|_| AppError::Internal("Invalid user UUID".to_string()))?;

    // Generate WebAuthn registration challenge
    // This creates a cryptographic challenge that the authenticator must sign
    //
    // Parameters:
    // - user_uuid: Unique user identifier
    // - username: Username (for display)
    // - display_name: Full name (for display)
    // - None: No excluded credentials (this is the first passkey for this user)
    //
    // Returns:
    // - ccr: CreationChallengeResponse (sent to client)
    // - reg_state: PasskeyRegistration (stored server-side for verification)
    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_uuid, &user.username, &user.display_name, None)
        .map_err(|e| AppError::WebAuthn(e))?;

    // Serialize registration state to bytes for database storage
    // The reg_state contains:
    // - The challenge we generated
    // - Expected RP ID and origin
    // - User information
    // We'll need this to verify the credential later
    let state_bytes = serde_json::to_vec(&reg_state)?;

    // Store challenge in database with 5-minute expiration
    challenges::save_registration_challenge(&state.db, &user.id, &state_bytes).await?;

    // Return challenge to client
    // The client will use navigator.credentials.create() with this data
    Ok(ccr)
}

/// Finish the passkey registration process
///
/// This is Step 2 of registration. Verifies the credential created by the
/// authenticator and stores the public key in the database.
///
/// ## Flow
/// 1. Decode user ID from base64url
/// 2. Retrieve stored challenge from database
/// 3. Parse credential from client
/// 4. Verify credential signature and data
/// 5. Store public key in database
/// 6. Delete one-time-use challenge
///
/// ## Parameters
/// - `state`: Application state (database + WebAuthn instance)
/// - `user_id`: Base64url-encoded user ID (from the challenge)
/// - `credential`: The credential created by navigator.credentials.create()
///
/// ## What gets verified?
/// - Challenge signature is valid
/// - Challenge hasn't expired
/// - RP ID and origin match our server
/// - Credential is properly formatted
/// - Authenticator data is valid
///
/// ## Errors
/// - BadRequest: Invalid user ID encoding or format
/// - NotFound: User or challenge not found
/// - Unauthorized: Challenge expired
/// - WebAuthn: Signature verification failed or invalid credential
///
/// ## Security Note
/// The private key NEVER leaves the user's device. We only store the public key
/// which is useless without the corresponding private key.
pub async fn finish_registration(
    state: &AppState,
    user_id: &str,
    credential: &Value,
) -> AppResult<()> {
    // Convert base64url user ID back to UUID
    //
    // The user_id comes from the frontend as base64url encoded bytes.
    // WebAuthn sends the user ID as ArrayBuffer, which the client
    // base64url-encodes before sending to us.
    //
    // We need to:
    // 1. Decode base64url → bytes
    // 2. Parse bytes → UUID
    // 3. Convert UUID → string (for database lookup)
    let user_id_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(user_id.as_bytes())
        .map_err(|_| AppError::BadRequest("Invalid user ID encoding".to_string()))?;

    let user_uuid = Uuid::from_slice(&user_id_bytes)
        .map_err(|_| AppError::BadRequest("Invalid user ID format".to_string()))?;

    let user_id_str = user_uuid.to_string();

    // Look up the user in the database
    let user = users::find_by_id(&state.db, &user_id_str).await?;

    // Retrieve the registration challenge we stored earlier
    // This contains the challenge we sent to the client and other state
    // needed to verify the credential
    let challenge = challenges::get_registration_challenge(&state.db, &user.id).await?;

    // Deserialize the challenge state from bytes back to PasskeyRegistration
    // PasskeyRegistration contains:
    // - The original challenge bytes
    // - Expected RP ID
    // - Expected origin
    // - User information
    let reg_state: PasskeyRegistration = serde_json::from_slice(&challenge.challenge_state)?;

    // Parse the credential JSON from the client
    // The client calls navigator.credentials.create() which returns a credential
    // The credential contains:
    // - id: Credential ID
    // - rawId: Raw credential ID bytes
    // - response.clientDataJSON: Client data (challenge, origin, type)
    // - response.attestationObject: Authenticator data + attestation
    let reg_credential: RegisterPublicKeyCredential = serde_json::from_value(credential.clone())?;

    // Verify the credential using webauthn-rs
    // This performs cryptographic verification:
    // 1. Validates the challenge matches what we sent
    // 2. Checks the signature is valid
    // 3. Verifies RP ID and origin
    // 4. Validates the attestation (if present)
    // 5. Checks credential is properly formatted
    //
    // If verification succeeds, returns a Passkey containing:
    // - Credential ID
    // - Public key (for future authentication)
    // - Counter (for replay attack detection)
    // - Other metadata
    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg_credential, &reg_state)
        .map_err(|e| AppError::WebAuthn(e))?;

    // Store the credential in database
    // We serialize the entire Passkey object to bytes
    // This includes the public key and all metadata we need for authentication
    let passkey_bytes = serde_json::to_vec(&passkey)?;

    // Generate credential ID string for database primary key
    // The Debug format gives us a string representation
    let cred_id = format!("{:?}", passkey.cred_id());

    // Save credential to database
    credentials::save_credential(
        &state.db,
        &cred_id,
        &user.id,
        &passkey_bytes,   // Serialized public key and metadata
        0,                // Initial counter (will increment on each use)
        None,             // Transports (USB, NFC, etc.) - not tracked in this impl
        false,            // backup_eligible - not tracked in this impl
        false,            // backup_state - not tracked in this impl
    )
    .await?;

    // Delete the challenge from database
    // Challenges are one-time use only for security
    // This prevents replay attacks
    challenges::delete_registration_challenge(&state.db, &user.id).await?;

    Ok(())
}
