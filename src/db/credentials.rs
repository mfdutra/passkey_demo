use crate::db::models::PasskeyCredential;
use crate::error::{AppError, AppResult};
use chrono::Utc;
use sqlx::SqlitePool;

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
    let transports_json = transports.map(|t| serde_json::to_string(&t).ok()).flatten();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO passkey_credentials
         (id, user_id, credential_public_key, counter, transports, backup_eligible, backup_state, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(credential_id)
    .bind(user_id)
    .bind(public_key)
    .bind(counter as i64)
    .bind(transports_json)
    .bind(backup_eligible)
    .bind(backup_state)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn find_by_user_id(pool: &SqlitePool, user_id: &str) -> AppResult<Vec<PasskeyCredential>> {
    let credentials = sqlx::query_as::<_, PasskeyCredential>(
        "SELECT * FROM passkey_credentials WHERE user_id = ?",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(credentials)
}

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

pub async fn update_counter(
    pool: &SqlitePool,
    credential_id: &str,
    new_counter: u32,
) -> AppResult<()> {
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE passkey_credentials
         SET counter = ?, last_used_at = ?
         WHERE id = ?",
    )
    .bind(new_counter as i64)
    .bind(now)
    .bind(credential_id)
    .execute(pool)
    .await?;

    Ok(())
}
