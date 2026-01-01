use crate::db::users;
use crate::error::{AppError, AppResult};
use crate::state::AppState;
use axum::{extract::State, Json};
use serde_json::{json, Value};
use tower_sessions::Session;

pub async fn get_current_user(
    State(state): State<AppState>,
    session: Session,
) -> AppResult<Json<Value>> {
    let user_id: String = session
        .get("user_id")
        .await
        .map_err(|e| AppError::Internal(format!("Session error: {}", e)))?
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?;

    let user = users::find_by_id(&state.db, &user_id).await?;

    Ok(Json(json!({
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "created_at": user.created_at
    })))
}
