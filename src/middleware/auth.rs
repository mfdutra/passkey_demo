//! # Authentication Middleware
//!
//! This middleware protects routes that require authentication.
//! It checks if the user has a valid session before allowing access.
//!
//! ## Usage in main.rs
//! ```rust
//! let protected_routes = Router::new()
//!     .route("/api/users/me", get(get_current_user))
//!     .layer(axum_middleware::from_fn(middleware::auth::require_auth));
//! ```
//!
//! Routes wrapped with this middleware will return 401 Unauthorized
//! if the user doesn't have a valid session.

use crate::error::AppError;
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use tower_sessions::Session;

/// Middleware function that requires authentication
///
/// This runs before the route handler and checks if the user is logged in.
///
/// ## How it works
/// 1. Extracts the session from the request
/// 2. Checks if session contains "user_id"
/// 3. If yes → allows request to continue to handler
/// 4. If no → returns 401 Unauthorized error
///
/// ## Parameters
/// - `session`: The user's session (contains user_id if logged in)
/// - `request`: The HTTP request
/// - `next`: The next middleware/handler in the chain
///
/// ## Returns
/// - Ok(Response): If authenticated, runs next handler and returns its response
/// - Err(AppError): If not authenticated, returns 401 error
pub async fn require_auth(
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Try to get user_id from session
    // Sessions are stored server-side, client only has session cookie
    let user_id: Option<String> = session
        .get("user_id")
        .await
        .map_err(|e| AppError::Internal(format!("Session error: {}", e)))?;

    // Check if user_id exists in session
    match user_id {
        // User is logged in → continue to the next handler
        Some(_) => Ok(next.run(request).await),

        // No user_id in session → user not logged in
        None => Err(AppError::Unauthorized("Not authenticated".to_string())),
    }
}
