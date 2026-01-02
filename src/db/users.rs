//! # User Database Operations
//!
//! This module provides CRUD (Create, Read, Update, Delete) operations for users.
//! All functions are async because database I/O is non-blocking.
//!
//! ## SQLx Query Patterns
//! - `query()`: For INSERT/UPDATE/DELETE (no return value)
//! - `query_as::<_, Type>()`: For SELECT (maps rows to structs)
//! - `.bind(value)`: Binds parameters (prevents SQL injection)
//! - `.execute()`: Runs the query
//! - `.fetch_one()`: Gets exactly one row (errors if 0 or 2+)
//! - `?` operator: Propagates errors up the call stack

use crate::db::models::User;
use crate::error::{AppError, AppResult};
use sqlx::SqlitePool;

/// Create a new user in the database
///
/// This function:
/// 1. Creates a User struct with generated ID and timestamps
/// 2. Inserts it into the database
/// 3. Returns the created user (with its ID)
///
/// ## SQL Injection Prevention
/// The `?` placeholders are bind parameters, NOT string interpolation.
/// SQLx safely escapes all values, preventing SQL injection attacks.
///
/// ## Example
/// ```rust
/// let user = create_user(&pool, "alice", "Alice Smith").await?;
/// println!("Created user: {}", user.id);
/// ```
pub async fn create_user(pool: &SqlitePool, username: &str, display_name: &str) -> AppResult<User> {
    // Create a new User struct with generated UUID and timestamps
    let user = User::new(username.to_string(), display_name.to_string());

    // Insert the user into the database
    // The ? placeholders prevent SQL injection
    // bind() safely escapes each parameter
    sqlx::query(
        "INSERT INTO users (id, username, display_name, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&user.id)           // Bind parameter 1: user ID
    .bind(&user.username)      // Bind parameter 2: username
    .bind(&user.display_name)  // Bind parameter 3: display name
    .bind(&user.created_at)    // Bind parameter 4: creation timestamp
    .bind(&user.updated_at)    // Bind parameter 5: update timestamp
    .execute(pool)             // Execute the query
    .await?;                   // Await result, propagate errors with ?

    // Return the created user
    Ok(user)
}

/// Find a user by username
///
/// Looks up a user by their unique username.
/// Returns an error if the user doesn't exist.
///
/// ## Error Handling
/// - If user not found: Returns `AppError::NotFound` with helpful message
/// - If database error: Returns `AppError::Database` with underlying error
///
/// This pattern provides better error messages to users vs generic database errors.
pub async fn find_by_username(pool: &SqlitePool, username: &str) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(username)       // Safely bind the username parameter
        .fetch_one(pool)       // Fetch exactly one row (error if 0 or multiple)
        .await
        // Map SQLx errors to AppError for better error messages
        .map_err(|e| match e {
            // If row not found, return a user-friendly error message
            sqlx::Error::RowNotFound => AppError::NotFound(format!("User '{}' not found", username)),
            // For other database errors, wrap in AppError::Database
            _ => AppError::Database(e),
        })?;

    Ok(user)
}

/// Find a user by their ID
///
/// Looks up a user by their UUID.
/// Typically used when we have a user ID from a session or credential.
///
/// ## Usage
/// ```rust
/// // Get user ID from session
/// let user_id = session.get("user_id")?;
/// // Look up full user details
/// let user = find_by_id(&pool, &user_id).await?;
/// ```
pub async fn find_by_id(pool: &SqlitePool, user_id: &str) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        // Same error mapping pattern as find_by_username
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound(format!("User with id '{}' not found", user_id)),
            _ => AppError::Database(e),
        })?;

    Ok(user)
}
