mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod state;
mod webauthn;

use crate::config::Config;
use crate::handlers::auth::*;
use crate::handlers::health::health_check;
use crate::handlers::users::get_current_user;
use crate::state::AppState;
use axum::{middleware as axum_middleware, routing::{get, post}, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use time::Duration;
use tower_sessions::{Expiry, SessionManagerLayer};
use tower_sessions_sqlx_store::SqliteStore;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,passkey_auth_server=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Configuration loaded: {:?}", config);

    // Initialize application state
    let app_state = AppState::new(&config).await?;
    tracing::info!("Application state initialized");

    // Start background task for cleaning up expired challenges
    let cleanup_pool = app_state.db.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600)); // 10 minutes
        loop {
            interval.tick().await;
            tracing::debug!("Running challenge cleanup task");
            if let Err(e) = crate::db::challenges::cleanup_expired_challenges(&cleanup_pool).await {
                tracing::error!("Challenge cleanup failed: {:?}", e);
            }
        }
    });

    // Configure session store
    let session_store = SqliteStore::new(app_state.db.clone());
    session_store.migrate().await?;

    let session_layer = SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(Duration::hours(24)));

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router
    let protected_routes = Router::new()
        .route("/api/users/me", get(get_current_user))
        .layer(axum_middleware::from_fn(middleware::auth::require_auth))
        .with_state(app_state.clone());

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/auth/register/start", post(register_start))
        .route("/api/auth/register/finish", post(register_finish))
        .route("/api/auth/authenticate/start", post(authenticate_start))
        .route("/api/auth/authenticate/finish", post(authenticate_finish))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/session", get(session_info))
        .merge(protected_routes)
        .fallback_service(ServeDir::new("static"))
        .layer(session_layer)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    // Start server
    let bind_addr = config.bind_address();
    tracing::info!("Starting server on {}", bind_addr);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
