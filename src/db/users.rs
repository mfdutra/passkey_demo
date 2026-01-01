use crate::db::models::User;
use crate::error::{AppError, AppResult};
use sqlx::SqlitePool;

pub async fn create_user(pool: &SqlitePool, username: &str, display_name: &str) -> AppResult<User> {
    let user = User::new(username.to_string(), display_name.to_string());

    sqlx::query(
        "INSERT INTO users (id, username, display_name, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&user.id)
    .bind(&user.username)
    .bind(&user.display_name)
    .bind(&user.created_at)
    .bind(&user.updated_at)
    .execute(pool)
    .await?;

    Ok(user)
}

pub async fn find_by_username(pool: &SqlitePool, username: &str) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(username)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound(format!("User '{}' not found", username)),
            _ => AppError::Database(e),
        })?;

    Ok(user)
}

pub async fn find_by_id(pool: &SqlitePool, user_id: &str) -> AppResult<User> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound(format!("User with id '{}' not found", user_id)),
            _ => AppError::Database(e),
        })?;

    Ok(user)
}
