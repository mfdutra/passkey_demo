//! # Error Handling
//!
//! This module defines custom error types for the application and handles
//! converting them into HTTP responses.
//!
//! ## Learning Points
//! - Rust error handling with `Result<T, E>`
//! - The `thiserror` crate for deriving error traits
//! - Converting errors to HTTP responses
//! - Logging errors for debugging

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;  // Simplifies error type creation with derive macros

/// Application-wide error type
///
/// This enum represents all possible errors that can occur in the application.
/// Each variant corresponds to a different category of error.
///
/// ## The `#[derive(Error)]` macro
/// The `thiserror::Error` derive macro automatically implements:
/// - `std::error::Error` trait
/// - `Display` trait (using the `#[error(...)]` messages)
/// - Automatic conversion from source errors (using `#[from]`)
///
/// ## The `#[from]` attribute
/// This enables automatic conversion using the `?` operator. For example:
/// ```rust
/// let result = sqlx::query(...).fetch_one(...).await?;
/// // The ? automatically converts sqlx::Error to AppError::Database
/// ```
#[derive(Error, Debug)]
pub enum AppError {
    /// Database errors (SQLx library errors)
    ///
    /// The `#[from]` attribute automatically implements `From<sqlx::Error>` for AppError
    /// This means sqlx errors can be converted to AppError using the `?` operator
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// WebAuthn protocol errors
    ///
    /// These occur when credential creation/verification fails
    /// Common causes: invalid signature, mismatched challenge, expired challenge
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::prelude::WebauthnError),

    /// JSON serialization/deserialization errors
    ///
    /// Occurs when converting between Rust structs and JSON fails
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Resource not found errors (404)
    ///
    /// Used when a requested user, credential, or challenge doesn't exist
    #[error("Not found: {0}")]
    NotFound(String),

    /// Bad request errors (400)
    ///
    /// Used when client sends invalid data (malformed requests, invalid parameters)
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Authentication/authorization errors (401)
    ///
    /// Used when user is not logged in or session has expired
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Internal server errors (500)
    ///
    /// Used for unexpected errors that shouldn't normally occur
    #[error("Internal server error: {0}")]
    Internal(String),
}

/// Convert AppError into an HTTP response
///
/// This implementation allows Axum handlers to return `Result<T, AppError>`
/// and have errors automatically converted into proper HTTP error responses.
///
/// ## How it works
/// 1. Match the error type
/// 2. Log detailed error information (for server debugging)
/// 3. Determine appropriate HTTP status code
/// 4. Create user-friendly error message (hide internal details)
/// 5. Return JSON response with error
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Map each error variant to (HTTP status code, user-facing message)
        let (status, error_message) = match &self {
            AppError::Database(e) => {
                // Log detailed error for debugging (not shown to user)
                tracing::error!("Database error: {:?}", e);
                // Return generic message to user (don't leak database internals)
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
            }
            AppError::WebAuthn(e) => {
                tracing::error!("WebAuthn error: {:?}", e);
                // Generic message (WebAuthn errors can be complex)
                (StatusCode::BAD_REQUEST, "Authentication error".to_string())
            }
            AppError::Serialization(e) => {
                tracing::error!("Serialization error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error".to_string())
            }
            // For these errors, the custom message is safe to show to users
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        // Create JSON response body
        // Format: { "error": "error message here" }
        let body = Json(json!({
            "error": error_message,
        }));

        // Convert to Axum response (status code + JSON body)
        (status, body).into_response()
    }
}

/// Convenience type alias for Results using AppError
///
/// Instead of writing `Result<User, AppError>` everywhere,
/// we can write `AppResult<User>` which is shorter and more readable.
///
/// Example usage:
/// ```rust
/// pub async fn get_user(id: &str) -> AppResult<User> {
///     let user = db::find_user(id).await?;
///     Ok(user)
/// }
/// ```
pub type AppResult<T> = Result<T, AppError>;
