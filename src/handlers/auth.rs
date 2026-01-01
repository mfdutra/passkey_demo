use crate::error::AppResult;
use crate::state::AppState;
use crate::webauthn::types::*;
use crate::webauthn::{authentication, registration};
use axum::{extract::State, Json};
use serde_json::{json, Value};
use tower_sessions::Session;

// Registration endpoints

pub async fn register_start(
    State(state): State<AppState>,
    Json(req): Json<RegistrationStartRequest>,
) -> AppResult<Json<Value>> {
    let ccr = registration::start_registration(&state, &req.username, &req.display_name).await?;

    Ok(Json(json!(ccr)))
}

pub async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegistrationFinishRequest>,
) -> AppResult<Json<Value>> {
    registration::finish_registration(&state, &req.user_id, &req.credential).await?;

    Ok(Json(json!({
        "success": true,
        "message": "Registration successful"
    })))
}

// Authentication endpoints

pub async fn authenticate_start(
    State(state): State<AppState>,
    Json(req): Json<AuthenticationStartRequest>,
) -> AppResult<Json<Value>> {
    let rcr = authentication::start_authentication(&state, &req.username).await?;

    Ok(Json(json!(rcr)))
}

pub async fn authenticate_finish(
    session: Session,
    State(state): State<AppState>,
    Json(req): Json<AuthenticationFinishRequest>,
) -> AppResult<Json<Value>> {
    let user_id = authentication::finish_authentication(&state, &req.user_id, &req.credential).await?;

    // Create session
    session
        .insert("user_id", &user_id)
        .await
        .map_err(|e| crate::error::AppError::Internal(format!("Session error: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "user_id": user_id,
        "message": "Authentication successful"
    })))
}

pub async fn logout(State(_state): State<AppState>, session: Session) -> AppResult<Json<Value>> {
    session
        .delete()
        .await
        .map_err(|e| crate::error::AppError::Internal(format!("Session error: {}", e)))?;

    Ok(Json(json!({
        "success": true,
        "message": "Logged out successfully"
    })))
}

pub async fn session_info(State(_state): State<AppState>, session: Session) -> AppResult<Json<Value>> {
    let user_id: Option<String> = session
        .get("user_id")
        .await
        .map_err(|e| crate::error::AppError::Internal(format!("Session error: {}", e)))?;

    match user_id {
        Some(id) => Ok(Json(json!({
            "authenticated": true,
            "user_id": id
        }))),
        None => Ok(Json(json!({
            "authenticated": false
        }))),
    }
}
