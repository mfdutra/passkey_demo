//! # Credential Database Operations
//!
//! This module handles CRUD operations for passkey credentials.
//! Credentials contain the public keys used to verify user authentication.
//!
//! ## Security Note
//! Only public keys are stored - private keys never leave the user's device.

use crate::db::models::PasskeyCredential;
use crate::error::{AppError, AppResult};
use chrono::Utc;
use sqlx::SqlitePool;

/// Save a new passkey credential to the database
///
/// Called after successful passkey registration.
/// Stores the public key and metadata needed for future authentication.
///
/// ## Parameters
/// - `credential_id`: Unique identifier for this credential (from WebAuthn)
/// - `user_id`: ID of the user who owns this credential
/// - `public_key`: Serialized public key (byte array/BLOB)
/// - `counter`: Initial signature counter (usually 0)
/// - `transports`: How the credential can be accessed (USB, NFC, etc.)
/// - `backup_eligible`: Can this credential be backed up to cloud?
/// - `backup_state`: Is it currently backed up?
pub async fn save_credential(
    pool: &SqlitePool,
    credential_id: &str,
    user_id: &str,
    public_key: &[u8],
    counter: u32,
    transports: Option<Vec<String>>,
    backup_eligible: bool,
    backup_state: bool,
) -> AppResult<()> {
    // Convert transports vector to JSON string for storage
    // Example: ["usb", "nfc"] -> "{\"usb\", \"nfc\"}"
    // The double .map().flatten() handles Option<Vec<String>> -> Option<String>
    let transports_json = transports.map(|t| serde_json::to_string(&t).ok()).flatten();
    let now = Utc::now().to_rfc3339();

    // Insert credential into database
    sqlx::query(
        "INSERT INTO passkey_credentials
         (id, user_id, credential_public_key, counter, transports, backup_eligible, backup_state, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(credential_id)
    .bind(user_id)
    .bind(public_key)         // Byte array stored as BLOB
    .bind(counter as i64)     // Convert u32 to i64 for SQLite
    .bind(transports_json)    // Optional JSON string
    .bind(backup_eligible)
    .bind(backup_state)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Get all credentials for a user
///
/// Returns all passkey credentials registered to a specific user.
/// Used during authentication to find which credentials can be used for login.
///
/// ## Returns
/// - Empty vector if user has no credentials
/// - Vector of credentials if found
/// - Error only if database operation fails
pub async fn find_by_user_id(pool: &SqlitePool, user_id: &str) -> AppResult<Vec<PasskeyCredential>> {
    let credentials = sqlx::query_as::<_, PasskeyCredential>(
        "SELECT * FROM passkey_credentials WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_all(pool)  // fetch_all returns Vec, empty if no rows
    .await?;

    Ok(credentials)
}

/// Find a specific credential by its ID
///
/// Looks up a credential by its unique identifier.
/// Used when verifying an authentication attempt to get the public key.
///
/// ## Error Handling
/// Returns NotFound if credential doesn't exist (may have been deleted)
pub async fn find_by_credential_id(
    pool: &SqlitePool,
    credential_id: &str,
) -> AppResult<PasskeyCredential> {
    let credential = sqlx::query_as::<_, PasskeyCredential>(
        "SELECT * FROM passkey_credentials WHERE id = ?",
    )
    .bind(credential_id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                AppError::NotFound(format!("Credential '{}' not found", credential_id))
            }
            _ => AppError::Database(e),
        })?;

    Ok(credential)
}

/// Update the signature counter for a credential
///
/// Called after successful authentication. The counter increments with each use.
/// This helps detect cloned credentials (replay attack prevention).
///
/// ## Security: Signature Counter
/// - Each authentication increments the counter
/// - If counter goes backwards → credential may be cloned → reject it
/// - Also updates last_used_at timestamp for auditing
///
/// ## Parameters
/// - `credential_id`: Which credential to update
/// - `new_counter`: The counter value from this authentication
pub async fn update_counter(
    pool: &SqlitePool,
    credential_id: &str,
    new_counter: u32,
) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();

    // Update both counter and last_used_at timestamp
    sqlx::query(
        "UPDATE passkey_credentials
         SET counter = ?, last_used_at = ?
         WHERE id = ?",
    )
    .bind(new_counter as i64)  // New counter value
    .bind(now)                  // Current timestamp
    .bind(credential_id)        // Which credential to update
    .execute(pool)
    .await?;

    Ok(())
}
