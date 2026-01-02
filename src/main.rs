//! # Passkey Authentication Server
//!
//! This is the main entry point for a WebAuthn/Passkey authentication server.
//! It demonstrates how to implement passwordless authentication using the WebAuthn standard.
//!
//! ## Key Concepts
//! - **WebAuthn**: Web Authentication API for passwordless authentication
//! - **Passkeys**: User-friendly implementation of WebAuthn credentials
//! - **FIDO2**: The underlying cryptographic protocol

// Module declarations - organize code into logical components
mod config;      // Configuration management (environment variables, settings)
mod db;          // Database operations (users, credentials, challenges)
mod error;       // Error handling and custom error types
mod handlers;    // HTTP request handlers (routes)
mod middleware;  // Request/response interceptors (authentication checks)
mod state;       // Shared application state
mod webauthn;    // WebAuthn/Passkey logic

// Import the configuration type
use crate::config::Config;
// Import authentication-related handlers (registration, login, logout)
use crate::handlers::auth::*;
// Import health check handler
use crate::handlers::health::health_check;
// Import user profile handler
use crate::handlers::users::get_current_user;
// Import shared application state
use crate::state::AppState;
// Axum is the web framework - provides routing, middleware, and HTTP handling
use axum::{middleware as axum_middleware, routing::{get, post}, Router};
// CORS (Cross-Origin Resource Sharing) - allows frontend to call API from different origin
use tower_http::cors::{Any, CorsLayer};
// Serves static files (HTML, CSS, JavaScript)
use tower_http::services::ServeDir;
// HTTP request/response tracing for debugging and monitoring
use tower_http::trace::TraceLayer;
use time::Duration;
// Session management - keeps users logged in across requests
use tower_sessions::{Expiry, SessionManagerLayer};
// SQLite-backed session storage
use tower_sessions_sqlx_store::SqliteStore;
// Structured logging setup
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Main application entry point
///
/// This function:
/// 1. Sets up logging for debugging and monitoring
/// 2. Loads configuration from environment variables
/// 3. Initializes database and WebAuthn components
/// 4. Starts a background task to clean up expired challenges
/// 5. Configures HTTP sessions for keeping users logged in
/// 6. Sets up API routes and middleware
/// 7. Starts the HTTP server
///
/// The `#[tokio::main]` attribute makes this an async main function,
/// allowing us to use async/await for non-blocking I/O operations.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing/logging system
    // This sets up structured logging that can be filtered by log level
    // Default: info level for most crates, debug level for our app
    // Can be overridden with RUST_LOG environment variable
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,passkey_auth_server=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration from environment variables and .env file
    // This includes database URL, server host/port, and WebAuthn settings
    let config = Config::from_env()?;
    tracing::info!("Configuration loaded: {:?}", config);

    // Initialize application state
    // This creates the database connection pool and WebAuthn instance
    // that will be shared across all request handlers
    let app_state = AppState::new(&config).await?;
    tracing::info!("Application state initialized");

    // Start background task for cleaning up expired challenges
    // WebAuthn challenges are temporary (5 minutes by default) and need cleanup
    // This prevents the database from filling up with old, unused challenges
    let cleanup_pool = app_state.db.clone();
    tokio::spawn(async move {
        // Run cleanup every 10 minutes
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            tracing::debug!("Running challenge cleanup task");
            if let Err(e) = crate::db::challenges::cleanup_expired_challenges(&cleanup_pool).await {
                tracing::error!("Challenge cleanup failed: {:?}", e);
            }
        }
    });

    // Configure session store using SQLite
    // Sessions keep users logged in by storing a session ID in a cookie
    // The session data (user_id) is stored server-side in SQLite
    let session_store = SqliteStore::new(app_state.db.clone());
    // Run migrations to create session tables
    session_store.migrate().await?;

    // Configure session expiry: 24 hours of inactivity
    // After 24 hours without activity, the user will need to re-authenticate
    let session_layer = SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(Duration::hours(24)));

    // Configure CORS (Cross-Origin Resource Sharing)
    // This allows the frontend (HTML/JS) to call the API even if served from different origin
    // In production, you should restrict this to specific origins for security
    let cors = CorsLayer::new()
        .allow_origin(Any)      // Allow requests from any origin (⚠️ use specific origins in production)
        .allow_methods(Any)     // Allow all HTTP methods (GET, POST, etc.)
        .allow_headers(Any);    // Allow all request headers

    // Build protected routes that require authentication
    // These routes are wrapped with the require_auth middleware
    // Any unauthenticated requests will receive a 401 Unauthorized error
    let protected_routes = Router::new()
        .route("/api/users/me", get(get_current_user))
        .layer(axum_middleware::from_fn(middleware::auth::require_auth))
        .with_state(app_state.clone());

    // Build main application router
    // This defines all the API endpoints and their handlers
    let app = Router::new()
        // Health check endpoint - useful for monitoring and load balancers
        .route("/health", get(health_check))

        // Registration flow (creating a new passkey)
        .route("/api/auth/register/start", post(register_start))      // Step 1: Get challenge
        .route("/api/auth/register/finish", post(register_finish))    // Step 2: Verify credential

        // Authentication flow (logging in with a passkey)
        .route("/api/auth/authenticate/start", post(authenticate_start))    // Step 1: Get challenge
        .route("/api/auth/authenticate/finish", post(authenticate_finish))  // Step 2: Verify assertion

        // Session management
        .route("/api/auth/logout", post(logout))           // End session
        .route("/api/auth/session", get(session_info))     // Check if logged in

        // Merge in protected routes that require authentication
        .merge(protected_routes)

        // Serve static files (index.html, app.js, styles.css, etc.)
        // This serves the frontend from the "static" directory
        .fallback_service(ServeDir::new("static"))

        // Apply middleware layers (processed in reverse order)
        .layer(session_layer)        // Session management
        .layer(cors)                 // CORS headers
        .layer(TraceLayer::new_for_http())  // HTTP request/response logging

        // Attach shared application state (database, WebAuthn instance)
        .with_state(app_state);

    // Start the HTTP server
    // Bind to the configured host and port (default: 127.0.0.1:8080)
    let bind_addr = config.bind_address();
    tracing::info!("Starting server on {}", bind_addr);

    // Create TCP listener and serve the application
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
