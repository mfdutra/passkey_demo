//! # WebAuthn Module
//!
//! This module contains the WebAuthn/Passkey logic for passwordless authentication.
//!
//! ## Submodules
//! - `types`: Request/response types for the API
//! - `registration`: Creating new passkey credentials
//! - `authentication`: Logging in with existing passkeys
//!
//! ## WebAuthn Flow Overview
//!
//! ### Registration (Creating a Passkey)
//! 1. Client requests registration → `registration::start_registration()`
//! 2. Server creates challenge and sends to client
//! 3. Client uses WebAuthn API to create credential with authenticator
//! 4. Client sends credential back to server → `registration::finish_registration()`
//! 5. Server verifies credential and stores public key
//!
//! ### Authentication (Logging In)
//! 1. Client requests authentication → `authentication::start_authentication()`
//! 2. Server creates challenge and sends allowed credentials to client
//! 3. Client uses WebAuthn API to sign challenge with authenticator
//! 4. Client sends signed assertion back to server → `authentication::finish_authentication()`
//! 5. Server verifies signature using stored public key
//! 6. If valid, create session for user

pub mod authentication;
pub mod registration;
pub mod types;
