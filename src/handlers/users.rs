//! # User Handlers
//!
//! Handlers for user-related operations.
//! Currently only has endpoint for getting current user profile.

use crate::db::users;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::{extract::State, Json};
use serde_json::{json, Value};
use tower_sessions::Session;

/// Get current authenticated user's profile
///
/// Returns information about the currently logged-in user.
///
/// ## Route
/// GET /api/users/me
///
/// ## Authentication
/// Requires authentication (protected by require_auth middleware)
///
/// ## Response
/// ```json
/// {
///   "id": "550e8400-e29b-41d4-a716-446655440000",
///   "username": "alice",
///   "display_name": "Alice Smith",
///   "created_at": "2024-01-15T10:30:00Z"
/// }
/// ```
///
/// ## How it works
/// 1. Get user_id from session (set during login)
/// 2. Look up full user details from database
/// 3. Return user profile as JSON
///
/// ## Extractors
/// - `State(state)`: Access to database and WebAuthn instance
/// - `session`: User's session data
pub async fn get_current_user(
    State(state): State<AppState>,
    session: Session,
) -> AppResult<Json<Value>> {
    // Get user ID from session
    // The require_auth middleware already checked that user is logged in,
    // but we still need to handle the session access
    let user_id: String = session
        .get("user_id")
        .await
        .map_err(|e| AppError::Internal(format!("Session error: {}", e)))?
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?;

    // Look up full user details from database
    let user = users::find_by_id(&state.db, &user_id).await?;

    // Return user profile as JSON
    // Note: We don't return sensitive data like credential IDs or public keys
    Ok(Json(json!({
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "created_at": user.created_at
    })))
}
