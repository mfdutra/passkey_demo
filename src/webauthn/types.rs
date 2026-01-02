//! # WebAuthn API Types
//!
//! This module defines the request/response types for the WebAuthn API endpoints.
//! These structs are automatically serialized/deserialized to/from JSON.
//!
//! ## API Flow
//! Each WebAuthn operation has two steps: start and finish
//! - Start: Server creates challenge, client receives it
//! - Finish: Client sends response, server verifies it

use serde::{Deserialize, Serialize};

/// Request to start passkey registration
///
/// Sent by the client when a user wants to create a new passkey.
///
/// ## Example JSON
/// ```json
/// {
///   "username": "alice",
///   "display_name": "Alice Smith"
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    /// Unique username (used for login)
    pub username: String,
    /// Human-readable name (shown during passkey creation)
    pub display_name: String,
}

/// Request to complete passkey registration
///
/// Sent by the client after the user completes passkey creation
/// with their authenticator (Face ID, fingerprint, security key).
///
/// ## Why serde_json::Value?
/// The credential is a complex WebAuthn structure. Instead of defining
/// all nested types, we accept it as raw JSON and pass to webauthn-rs
/// for parsing and validation.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    /// User ID (base64url encoded from the challenge)
    /// The client echoes back the user ID we sent in the challenge
    pub user_id: String,

    /// The credential created by the WebAuthn API
    /// Contains attestation data and the public key
    pub credential: serde_json::Value,
}

/// Request to start passkey authentication
///
/// Sent by the client when a user wants to log in.
///
/// ## Example JSON
/// ```json
/// {
///   "username": "alice"
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationStartRequest {
    /// Username to authenticate as
    pub username: String,
}

/// Request to complete passkey authentication
///
/// Sent by the client after the user completes authentication
/// with their authenticator (signs the challenge).
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationFinishRequest {
    /// User ID (base64url encoded from userHandle)
    /// Identifies which user is authenticating
    pub user_id: String,

    /// The assertion (signed challenge) from the WebAuthn API
    /// Contains the signature and authenticator data
    pub credential: serde_json::Value,
}
