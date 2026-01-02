//! # Challenge Database Operations
//!
//! This module handles CRUD operations for WebAuthn challenges.
//! Challenges are cryptographic nonces that prevent replay attacks.
//!
//! ## Two Types of Challenges
//! 1. **Registration**: Used when creating a new passkey
//! 2. **Authentication**: Used when logging in with an existing passkey
//!
//! ## Challenge Lifecycle
//! - Created: When user starts registration/authentication
//! - Stored: Temporarily in database (5 minute TTL)
//! - Retrieved: To verify the response from the client
//! - Deleted: After successful verification OR expiration
//!
//! ## Security
//! - Challenges are one-time use (deleted after verification)
//! - Short expiration (5 minutes) limits attack window
//! - Each challenge is cryptographically random and unique

use crate::db::models::{AuthenticationChallenge, RegistrationChallenge};
use crate::error::{AppError, AppResult};
use chrono::Utc;
use sqlx::SqlitePool;

// ============================================================================
// Registration Challenge Operations
// ============================================================================

/// Save a new registration challenge to the database
///
/// Called at the start of passkey registration.
/// The challenge must be completed within 5 minutes.
///
/// ## Parameters
/// - `user_id`: ID of the user registering a passkey
/// - `challenge_state`: Serialized WebAuthn state (contains the cryptographic challenge)
///
/// ## Returns
/// The challenge ID (for tracking/debugging)
pub async fn save_registration_challenge(
    pool: &SqlitePool,
    user_id: &str,
    challenge_state: &[u8],
) -> AppResult<String> {
    // Create a new challenge with auto-generated ID and 5-minute expiration
    let challenge = RegistrationChallenge::new(user_id.to_string(), challenge_state.to_vec());

    // Insert into database
    sqlx::query(
        "INSERT INTO registration_challenges (id, user_id, challenge_state, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&challenge.id)
    .bind(&challenge.user_id)
    .bind(&challenge.challenge_state) // Serialized PasskeyRegistration state
    .bind(&challenge.created_at)
    .bind(&challenge.expires_at) // Auto-set to now + 5 minutes
    .execute(pool)
    .await?;

    // Return the challenge ID
    Ok(challenge.id)
}

/// Retrieve the most recent registration challenge for a user
///
/// Gets the latest challenge (in case there are multiple, though there shouldn't be).
/// Validates that the challenge hasn't expired.
///
/// ## Error Cases
/// - Challenge not found → user needs to restart registration
/// - Challenge expired → return Unauthorized, user must restart
/// - Invalid timestamp → database corruption (shouldn't happen)
///
/// ## Why ORDER BY created_at DESC?
/// In case a user starts registration multiple times without finishing,
/// we get the most recent attempt.
pub async fn get_registration_challenge(
    pool: &SqlitePool,
    user_id: &str,
) -> AppResult<RegistrationChallenge> {
    // Get the most recent challenge for this user
    let challenge = sqlx::query_as::<_, RegistrationChallenge>(
        "SELECT * FROM registration_challenges
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => {
            AppError::NotFound("Registration challenge not found".to_string())
        }
        _ => AppError::Database(e),
    })?;

    // Validate that the challenge hasn't expired
    let now = Utc::now();
    let expires_at = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|_| AppError::Internal("Invalid expiration timestamp".to_string()))?;

    // If current time is past expiration, reject the challenge
    if now > expires_at {
        return Err(AppError::Unauthorized("Challenge expired".to_string()));
    }

    Ok(challenge)
}

/// Delete registration challenge(s) for a user
///
/// Called after successful registration or when cleaning up.
/// Challenges are one-time use, so they must be deleted after verification.
///
/// This deletes ALL registration challenges for the user (not just one),
/// in case there are multiple abandoned attempts.
pub async fn delete_registration_challenge(pool: &SqlitePool, user_id: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM registration_challenges WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Authentication Challenge Operations
// ============================================================================

/// Save a new authentication challenge to the database
///
/// Called at the start of passkey authentication (login).
/// The challenge must be completed within 5 minutes.
///
/// Same pattern as registration challenges but for login flow.
pub async fn save_authentication_challenge(
    pool: &SqlitePool,
    user_id: &str,
    challenge_state: &[u8],
) -> AppResult<String> {
    // Create challenge with auto-generated ID and 5-minute expiration
    let challenge = AuthenticationChallenge::new(user_id.to_string(), challenge_state.to_vec());

    // Insert into database
    sqlx::query(
        "INSERT INTO authentication_challenges (id, user_id, challenge_state, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&challenge.id)
    .bind(&challenge.user_id)
    .bind(&challenge.challenge_state)  // Serialized PasskeyAuthentication state
    .bind(&challenge.created_at)
    .bind(&challenge.expires_at)       // Auto-set to now + 5 minutes
    .execute(pool)
    .await?;

    Ok(challenge.id)
}

/// Retrieve the most recent authentication challenge for a user
///
/// Gets the latest challenge and validates it hasn't expired.
/// Same logic as get_registration_challenge but for authentication.
pub async fn get_authentication_challenge(
    pool: &SqlitePool,
    user_id: &str,
) -> AppResult<AuthenticationChallenge> {
    // Get the most recent challenge for this user
    let challenge = sqlx::query_as::<_, AuthenticationChallenge>(
        "SELECT * FROM authentication_challenges
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => {
            AppError::NotFound("Authentication challenge not found".to_string())
        }
        _ => AppError::Database(e),
    })?;

    // Validate expiration
    let now = Utc::now();
    let expires_at = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|_| AppError::Internal("Invalid expiration timestamp".to_string()))?;

    if now > expires_at {
        return Err(AppError::Unauthorized("Challenge expired".to_string()));
    }

    Ok(challenge)
}

/// Delete authentication challenge(s) for a user
///
/// Called after successful login or when cleaning up.
/// Challenges are one-time use.
pub async fn delete_authentication_challenge(pool: &SqlitePool, user_id: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM authentication_challenges WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// Cleanup Operations
// ============================================================================

/// Clean up expired challenges from the database
///
/// This should be run periodically (e.g., every 10 minutes) as a background task.
/// Removes both registration and authentication challenges that have expired.
///
/// ## Why cleanup?
/// - Prevents database from filling up with old challenges
/// - Improves query performance (fewer rows to scan)
/// - Good housekeeping
///
/// This is called from the background task in main.rs
pub async fn cleanup_expired_challenges(pool: &SqlitePool) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();

    // Delete expired registration challenges
    sqlx::query("DELETE FROM registration_challenges WHERE expires_at < ?")
        .bind(&now)
        .execute(pool)
        .await?;

    // Delete expired authentication challenges
    sqlx::query("DELETE FROM authentication_challenges WHERE expires_at < ?")
        .bind(&now)
        .execute(pool)
        .await?;

    Ok(())
}
