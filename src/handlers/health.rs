//! # Health Check Handler
//!
//! Simple endpoint to check if the server is running.
//! Used by load balancers and monitoring systems.

use axum::Json;
use serde_json::{json, Value};

/// Health check endpoint
///
/// Returns a simple JSON response indicating the server is running.
///
/// ## Route
/// GET /health
///
/// ## Response
/// ```json
/// {
///   "status": "healthy",
///   "service": "passkey-auth-server"
/// }
/// ```
///
/// ## Usage
/// - Load balancers use this to know if the server is alive
/// - Monitoring systems can ping this endpoint
/// - Always returns 200 OK (unless server is down)
///
/// ## Why not return AppResult?
/// This handler never fails, so we return Json<Value> directly
/// instead of AppResult<Json<Value>>
pub async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "passkey-auth-server"
    }))
}
