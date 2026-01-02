//! # Application State
//!
//! This module defines the shared state that's accessible to all request handlers.
//! In Axum, state is how you share resources (database connections, configuration, etc.)
//! across different parts of your application.
//!
//! ## The State Pattern
//! Instead of creating new database connections for each request, we:
//! 1. Create a connection pool once at startup
//! 2. Store it in AppState
//! 3. Share it across all request handlers
//! 4. Axum clones the state for each request (cheap because we use Arc)

use crate::config::Config;
use anyhow::Result;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;  // Atomic Reference Counting - for thread-safe sharing
use webauthn_rs::prelude::*;

/// Shared application state
///
/// This struct holds resources that need to be shared across request handlers:
/// - Database connection pool
/// - WebAuthn instance (for creating and verifying credentials)
///
/// ## Why Clone?
/// The `#[derive(Clone)]` is essential for Axum. Each request handler gets a clone
/// of the state. This is efficient because:
/// - `SqlitePool` is already a clone-able pool of connections
/// - `Arc<Webauthn>` only clones a pointer (not the entire Webauthn instance)
///
/// ## Thread Safety
/// Both `SqlitePool` and `Arc<T>` are thread-safe, meaning they can be safely
/// shared across multiple async tasks/threads.
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    ///
    /// A pool maintains multiple database connections that can be reused.
    /// This is much more efficient than opening a new connection for each query.
    ///
    /// The pool automatically:
    /// - Manages connection lifecycle
    /// - Handles connection pooling and reuse
    /// - Validates connections before use
    pub db: SqlitePool,

    /// WebAuthn instance for cryptographic operations
    ///
    /// Wrapped in Arc (Atomic Reference Counter) for efficient sharing.
    /// Arc allows multiple owners of the same data without copying it.
    ///
    /// The WebAuthn instance handles:
    /// - Generating challenges for registration/authentication
    /// - Verifying cryptographic signatures
    /// - Validating credential responses
    pub webauthn: Arc<Webauthn>,
}

impl AppState {
    /// Initialize application state
    ///
    /// This function:
    /// 1. Connects to the SQLite database
    /// 2. Runs database migrations (creates tables if they don't exist)
    /// 3. Configures WebAuthn with the relying party information
    /// 4. Returns the initialized state
    ///
    /// # Errors
    /// Returns an error if:
    /// - Database connection fails
    /// - Migrations fail
    /// - WebAuthn configuration is invalid (e.g., malformed URL)
    pub async fn new(config: &Config) -> Result<Self> {
        // Create database connection pool
        // This establishes a pool of reusable connections to the SQLite database
        // The pool size is automatically managed by SQLx
        let db = SqlitePool::connect(&config.database_url).await?;

        // Run database migrations
        // The `sqlx::migrate!` macro embeds migrations from ./migrations directory
        // This automatically creates/updates database tables to match the schema
        // Migrations are run in order and tracked to avoid re-running them
        sqlx::migrate!("./migrations").run(&db).await?;

        // Configure WebAuthn with relying party information
        // The RP ID and Origin must match where your app is served from
        let rp_id = config.rp_id.clone();
        let rp_origin = Url::parse(&config.rp_origin)?;  // Parse and validate URL

        // Build the WebAuthn instance
        // This configures the cryptographic parameters for WebAuthn
        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?;
        let webauthn = Arc::new(builder.build()?);  // Wrap in Arc for sharing

        // Return the initialized state
        Ok(AppState { db, webauthn })
    }
}
