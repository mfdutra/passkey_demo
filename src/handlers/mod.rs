//! # HTTP Request Handlers
//!
//! This module contains all the HTTP route handlers (controllers).
//! Each handler processes a specific API endpoint.
//!
//! ## Submodules
//! - `health`: Health check endpoint (for monitoring)
//! - `auth`: Authentication endpoints (register, login, logout, session)
//! - `users`: User-related endpoints (get current user profile)
//!
//! ## Handler Pattern
//! Handlers are async functions that:
//! 1. Extract data from request (path params, query params, JSON body, session)
//! 2. Call business logic (database operations, WebAuthn operations)
//! 3. Return a response (JSON, status code)
//!
//! ## Example Handler
//! ```rust
//! pub async fn my_handler(
//!     State(state): State<AppState>,   // Shared app state
//!     Json(req): Json<MyRequest>,      // JSON request body
//! ) -> AppResult<Json<MyResponse>> {
//!     // Do work here
//!     Ok(Json(response))
//! }
//! ```

pub mod auth;
pub mod health;
pub mod users;
