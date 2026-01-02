//! # Middleware Module
//!
//! Middleware intercepts HTTP requests and responses.
//! Used for cross-cutting concerns like authentication, logging, CORS, etc.
//!
//! ## What is Middleware?
//! Middleware functions run before (or after) your route handlers.
//! They can:
//! - Check authentication/authorization
//! - Log requests
//! - Add headers
//! - Transform requests/responses
//! - Short-circuit the request (return error before handler runs)
//!
//! ## Our Middleware
//! - `auth`: Checks if user is logged in (has valid session)

pub mod auth;
