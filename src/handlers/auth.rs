//! # Authentication HTTP Handlers
//!
//! This module contains the HTTP handlers for authentication endpoints.
//! These handlers bridge the WebAuthn logic with HTTP requests/responses.
//!
//! ## Endpoints
//! - POST /api/auth/register/start - Begin passkey registration
//! - POST /api/auth/register/finish - Complete passkey registration
//! - POST /api/auth/authenticate/start - Begin passkey authentication
//! - POST /api/auth/authenticate/finish - Complete passkey authentication (login)
//! - POST /api/auth/logout - End user session
//! - GET /api/auth/session - Check if user is logged in

use crate::error::AppResult;
use crate::state::AppState;
use crate::webauthn::types::*;
use crate::webauthn::{authentication, registration};
use axum::{extract::State, Json};
use serde_json::{json, Value};
use tower_sessions::Session;

// ============================================================================
// Registration Endpoints
// ============================================================================

/// Start passkey registration (Step 1 of 2)
///
/// Creates a new user and generates a WebAuthn challenge for credential creation.
///
/// ## Route
/// POST /api/auth/register/start
///
/// ## Request Body
/// ```json
/// {
///   "username": "alice",
///   "display_name": "Alice Smith"
/// }
/// ```
///
/// ## Response
/// Returns a WebAuthn CreationChallengeResponse:
/// ```json
/// {
///   "publicKey": {
///     "challenge": "base64url-encoded-random-bytes",
///     "rp": { "name": "Passkey Demo", "id": "localhost" },
///     "user": {
///       "id": "base64url-encoded-uuid",
///       "name": "alice",
///       "displayName": "Alice Smith"
///     },
///     "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
///     "timeout": 60000,
///     "attestation": "none"
///   }
/// }
/// ```
///
/// The client will pass this to `navigator.credentials.create()`
///
/// ## Errors
/// - 400 Bad Request: Username already exists
/// - 500 Internal Server Error: Database or WebAuthn error
pub async fn register_start(
    State(state): State<AppState>,
    Json(req): Json<RegistrationStartRequest>,
) -> AppResult<Json<Value>> {
    // Call the WebAuthn registration logic
    // This creates a user and generates a challenge
    let ccr = registration::start_registration(&state, &req.username, &req.display_name).await?;

    // Return the challenge as JSON
    // The serde_json::json! macro converts ccr to JSON
    Ok(Json(json!(ccr)))
}

/// Finish passkey registration (Step 2 of 2)
///
/// Verifies the credential created by the authenticator and stores the public key.
///
/// ## Route
/// POST /api/auth/register/finish
///
/// ## Request Body
/// ```json
/// {
///   "user_id": "base64url-encoded-uuid",
///   "credential": {
///     "id": "credential-id",
///     "rawId": "base64url-encoded-credential-id",
///     "type": "public-key",
///     "response": {
///       "clientDataJSON": "base64url-encoded-json",
///       "attestationObject": "base64url-encoded-cbor"
///     }
///   }
/// }
/// ```
///
/// ## Response
/// ```json
/// {
///   "success": true,
///   "message": "Registration successful"
/// }
/// ```
///
/// ## What happens
/// 1. Verifies the credential signature
/// 2. Stores the public key in database
/// 3. Deletes the one-time challenge
///
/// ## Errors
/// - 400 Bad Request: Invalid credential format or user ID
/// - 401 Unauthorized: Challenge expired
/// - 404 Not Found: User or challenge not found
/// - 500 Internal Server Error: Verification failed or database error
pub async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegistrationFinishRequest>,
) -> AppResult<Json<Value>> {
    // Call the WebAuthn registration verification logic
    // This verifies the credential and stores the public key
    registration::finish_registration(&state, &req.user_id, &req.credential).await?;

    // Return success response
    Ok(Json(json!({
        "success": true,
        "message": "Registration successful"
    })))
}

// ============================================================================
// Authentication Endpoints
// ============================================================================

/// Start passkey authentication (Step 1 of 2)
///
/// Looks up the user's passkeys and generates a challenge for them to sign.
///
/// ## Route
/// POST /api/auth/authenticate/start
///
/// ## Request Body
/// ```json
/// {
///   "username": "alice"
/// }
/// ```
///
/// ## Response
/// Returns a WebAuthn RequestChallengeResponse:
/// ```json
/// {
///   "publicKey": {
///     "challenge": "base64url-encoded-random-bytes",
///     "timeout": 60000,
///     "rpId": "localhost",
///     "allowCredentials": [
///       {
///         "type": "public-key",
///         "id": "base64url-encoded-credential-id"
///       }
///     ],
///     "userVerification": "preferred"
///   }
/// }
/// ```
///
/// The client will pass this to `navigator.credentials.get()`
///
/// ## Errors
/// - 404 Not Found: User doesn't exist or has no passkeys
/// - 500 Internal Server Error: Database or WebAuthn error
pub async fn authenticate_start(
    State(state): State<AppState>,
    Json(req): Json<AuthenticationStartRequest>,
) -> AppResult<Json<Value>> {
    // Call the WebAuthn authentication logic
    // This looks up the user's credentials and generates a challenge
    let rcr = authentication::start_authentication(&state, &req.username).await?;

    // Return the challenge as JSON
    Ok(Json(json!(rcr)))
}

/// Finish passkey authentication (Step 2 of 2)
///
/// Verifies the signed assertion and creates a session (logs the user in).
///
/// ## Route
/// POST /api/auth/authenticate/finish
///
/// ## Request Body
/// ```json
/// {
///   "user_id": "base64url-encoded-uuid",
///   "credential": {
///     "id": "credential-id",
///     "rawId": "base64url-encoded-credential-id",
///     "type": "public-key",
///     "response": {
///       "clientDataJSON": "base64url-encoded-json",
///       "authenticatorData": "base64url-encoded-data",
///       "signature": "base64url-encoded-signature",
///       "userHandle": "base64url-encoded-user-id"
///     }
///   }
/// }
/// ```
///
/// ## Response
/// ```json
/// {
///   "success": true,
///   "user_id": "550e8400-e29b-41d4-a716-446655440000",
///   "message": "Authentication successful"
/// }
/// ```
///
/// ## What happens
/// 1. Verifies the signature using stored public key
/// 2. Updates the signature counter
/// 3. Deletes the one-time challenge
/// 4. Creates a session (stores user_id in session)
///
/// ## Session Management
/// After successful authentication, the user's ID is stored in the session.
/// The session cookie is sent to the client, allowing them to make
/// authenticated requests to protected endpoints.
///
/// ## Errors
/// - 400 Bad Request: Invalid credential format or user ID
/// - 401 Unauthorized: Challenge expired or signature verification failed
/// - 404 Not Found: User or challenge not found
/// - 500 Internal Server Error: Database error or session error
pub async fn authenticate_finish(
    session: Session,
    State(state): State<AppState>,
    Json(req): Json<AuthenticationFinishRequest>,
) -> AppResult<Json<Value>> {
    // Call the WebAuthn authentication verification logic
    // This verifies the signature and returns the user ID
    let user_id =
        authentication::finish_authentication(&state, &req.user_id, &req.credential).await?;

    // Create session by storing user_id
    // The session is stored server-side (in SQLite)
    // The client receives a session cookie
    session
        .insert("user_id", &user_id)
        .await
        .map_err(|e| crate::error::AppError::Internal(format!("Session error: {}", e)))?;

    // Return success response with user ID
    Ok(Json(json!({
        "success": true,
        "user_id": user_id,
        "message": "Authentication successful"
    })))
}

// ============================================================================
// Session Management Endpoints
// ============================================================================

/// Log out the current user
///
/// Deletes the session, logging the user out.
///
/// ## Route
/// POST /api/auth/logout
///
/// ## Response
/// ```json
/// {
///   "success": true,
///   "message": "Logged out successfully"
/// }
/// ```
///
/// ## What happens
/// - Session is deleted from database
/// - Session cookie is invalidated
/// - User must re-authenticate to access protected endpoints
pub async fn logout(State(_state): State<AppState>, session: Session) -> AppResult<Json<Value>> {
    // Delete the session
    // This removes the session from the database
    session
        .delete()
        .await
        .map_err(|e| crate::error::AppError::Internal(format!("Session error: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "message": "Logged out successfully"
    })))
}

/// Check session status
///
/// Returns whether the user is currently logged in.
///
/// ## Route
/// GET /api/auth/session
///
/// ## Response (logged in)
/// ```json
/// {
///   "authenticated": true,
///   "user_id": "550e8400-e29b-41d4-a716-446655440000"
/// }
/// ```
///
/// ## Response (not logged in)
/// ```json
/// {
///   "authenticated": false
/// }
/// ```
///
/// ## Usage
/// The frontend calls this on page load to check if the user
/// is still logged in (e.g., after page refresh).
pub async fn session_info(
    State(_state): State<AppState>,
    session: Session,
) -> AppResult<Json<Value>> {
    // Try to get user_id from session
    let user_id: Option<String> = session
        .get("user_id")
        .await
        .map_err(|e| crate::error::AppError::Internal(format!("Session error: {}", e)))?;

    // Return different response based on whether user is logged in
    match user_id {
        Some(id) => Ok(Json(json!({
            "authenticated": true,
            "user_id": id
        }))),
        None => Ok(Json(json!({
            "authenticated": false
        }))),
    }
}
