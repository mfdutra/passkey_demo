use crate::error::AppError;
use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
};
use tower_sessions::Session;

pub async fn require_auth(
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let user_id: Option<String> = session
        .get("user_id")
        .await
        .map_err(|e| AppError::Internal(format!("Session error: {}", e)))?;

    match user_id {
        Some(_) => Ok(next.run(request).await),
        None => Err(AppError::Unauthorized("Not authenticated".to_string())),
    }
}
