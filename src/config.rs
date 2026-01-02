//! # Configuration Management
//!
//! This module handles loading configuration from environment variables.
//! It uses the "12-factor app" methodology where configuration comes from the environment.
//!
//! ## Environment Variables
//! - `HOST`: Server bind address (default: 127.0.0.1)
//! - `PORT`: Server port (default: 8080)
//! - `DATABASE_URL`: SQLite database connection string
//! - `RP_ID`: WebAuthn Relying Party ID (usually your domain)
//! - `RP_ORIGIN`: WebAuthn Relying Party Origin (full URL)
//! - `RP_NAME`: Human-readable name for your service

use anyhow::Result;
use std::env;

/// Application configuration
///
/// This struct holds all configuration values needed to run the server.
/// All fields are public for easy access from other modules.
///
/// ## WebAuthn Terminology
/// - **RP (Relying Party)**: Your application/website that relies on authentication
/// - **RP ID**: Your domain name (e.g., "example.com" or "localhost")
/// - **RP Origin**: Full URL of your application (e.g., "https://example.com")
///
/// The `#[derive(Debug, Clone)]` attributes allow:
/// - Debug: Pretty-printing the config for logging
/// - Clone: Making copies of the config (needed for sharing across threads)
#[derive(Debug, Clone)]
pub struct Config {
    /// Server host/IP address to bind to
    /// Examples: "127.0.0.1" (localhost only), "0.0.0.0" (all interfaces)
    pub host: String,

    /// Server port number (1-65535)
    /// Default: 8080
    pub port: u16,

    /// SQLite database connection URL
    /// Format: "sqlite:filename.db?mode=rwc"
    /// The "mode=rwc" means: read, write, create if not exists
    pub database_url: String,

    /// WebAuthn Relying Party ID
    /// This must match the domain your app is served from
    /// For local development: "localhost"
    /// For production: "example.com" (without protocol or port)
    pub rp_id: String,

    /// WebAuthn Relying Party Origin
    /// This is the full URL where your app is accessible
    /// For local development: "http://localhost:8080"
    /// For production: "https://example.com"
    pub rp_origin: String,

    /// Human-readable name for your application
    /// Shown to users during passkey creation
    /// Example: "My Awesome App"
    pub rp_name: String,
}

impl Config {
    /// Load configuration from environment variables
    ///
    /// This function:
    /// 1. Loads variables from .env file (if present) using dotenvy
    /// 2. Reads each configuration value from environment
    /// 3. Falls back to sensible defaults if variables aren't set
    /// 4. Returns an error if required parsing fails (e.g., invalid port number)
    ///
    /// ## Example .env file
    /// ```text
    /// HOST=127.0.0.1
    /// PORT=8080
    /// DATABASE_URL=sqlite:passkey.db?mode=rwc
    /// RP_ID=localhost
    /// RP_ORIGIN=http://localhost:8080
    /// RP_NAME=Passkey Demo
    /// ```
    pub fn from_env() -> Result<Self> {
        // Load .env file if it exists (dotenvy doesn't error if file missing)
        // This is useful for local development
        dotenvy::dotenv().ok();

        Ok(Config {
            // Server host - where to bind the TCP listener
            // Default: 127.0.0.1 (only accessible from this machine)
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),

            // Server port - what port to listen on
            // Parse string to u16, return error if invalid
            // The ? operator propagates parse errors
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,  // This can fail if PORT is not a valid number

            // Database URL for SQLite
            // The "mode=rwc" parameter means: read, write, create
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:passkey.db?mode=rwc".to_string()),

            // WebAuthn Relying Party ID - must match your domain
            // For localhost development, use "localhost"
            // For production, use your domain without protocol: "example.com"
            rp_id: env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string()),

            // WebAuthn Relying Party Origin - full URL of your app
            // Must include protocol (http:// or https://)
            rp_origin: env::var("RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),

            // Application name shown to users
            // This appears when creating a passkey
            rp_name: env::var("RP_NAME").unwrap_or_else(|_| "Passkey Demo".to_string()),
        })
    }

    /// Get the socket address to bind the server to
    ///
    /// Combines host and port into a format suitable for TCP binding.
    /// Example: "127.0.0.1:8080"
    ///
    /// This format is required by `tokio::net::TcpListener::bind()`
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
