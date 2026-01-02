//! # Database Module
//!
//! This module organizes all database-related code into submodules:
//! - `models`: Data structures (User, Credential, Challenge)
//! - `users`: CRUD operations for users
//! - `credentials`: CRUD operations for passkey credentials
//! - `challenges`: CRUD operations for WebAuthn challenges (registration & authentication)
//!
//! ## Why separate modules?
//! - **Organization**: Each table/concept has its own module
//! - **Maintainability**: Easy to find and update related code
//! - **Testing**: Can test each module independently

// Re-export submodules for easier imports
// Other modules can use `crate::db::users::create_user` instead of `crate::db::users::users::create_user`
pub mod challenges;
pub mod credentials;
pub mod models;
pub mod users;
