use crate::db::models::{AuthenticationChallenge, RegistrationChallenge};
use crate::error::{AppError, AppResult};
use chrono::Utc;
use sqlx::SqlitePool;

// Registration Challenge Operations

pub async fn save_registration_challenge(
    pool: &SqlitePool,
    user_id: &str,
    challenge_state: &[u8],
) -> AppResult<String> {
    let challenge = RegistrationChallenge::new(user_id.to_string(), challenge_state.to_vec());

    sqlx::query(
        "INSERT INTO registration_challenges (id, user_id, challenge_state, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&challenge.id)
    .bind(&challenge.user_id)
    .bind(&challenge.challenge_state)
    .bind(&challenge.created_at)
    .bind(&challenge.expires_at)
    .execute(pool)
    .await?;

    Ok(challenge.id)
}

pub async fn get_registration_challenge(
    pool: &SqlitePool,
    user_id: &str,
) -> AppResult<RegistrationChallenge> {
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

    // Check if expired
    let now = Utc::now();
    let expires_at = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|_| AppError::Internal("Invalid expiration timestamp".to_string()))?;

    if now > expires_at {
        return Err(AppError::Unauthorized("Challenge expired".to_string()));
    }

    Ok(challenge)
}

pub async fn delete_registration_challenge(pool: &SqlitePool, user_id: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM registration_challenges WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// Authentication Challenge Operations

pub async fn save_authentication_challenge(
    pool: &SqlitePool,
    user_id: &str,
    challenge_state: &[u8],
) -> AppResult<String> {
    let challenge = AuthenticationChallenge::new(user_id.to_string(), challenge_state.to_vec());

    sqlx::query(
        "INSERT INTO authentication_challenges (id, user_id, challenge_state, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&challenge.id)
    .bind(&challenge.user_id)
    .bind(&challenge.challenge_state)
    .bind(&challenge.created_at)
    .bind(&challenge.expires_at)
    .execute(pool)
    .await?;

    Ok(challenge.id)
}

pub async fn get_authentication_challenge(
    pool: &SqlitePool,
    user_id: &str,
) -> AppResult<AuthenticationChallenge> {
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

    // Check if expired
    let now = Utc::now();
    let expires_at = chrono::DateTime::parse_from_rfc3339(&challenge.expires_at)
        .map_err(|_| AppError::Internal("Invalid expiration timestamp".to_string()))?;

    if now > expires_at {
        return Err(AppError::Unauthorized("Challenge expired".to_string()));
    }

    Ok(challenge)
}

pub async fn delete_authentication_challenge(pool: &SqlitePool, user_id: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM authentication_challenges WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

// Cleanup expired challenges (should be run periodically)
pub async fn cleanup_expired_challenges(pool: &SqlitePool) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query("DELETE FROM registration_challenges WHERE expires_at < ?")
        .bind(&now)
        .execute(pool)
        .await?;

    sqlx::query("DELETE FROM authentication_challenges WHERE expires_at < ?")
        .bind(&now)
        .execute(pool)
        .await?;

    Ok(())
}
