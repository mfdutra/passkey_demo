use crate::config::Config;
use anyhow::Result;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub webauthn: Arc<Webauthn>,
}

impl AppState {
    pub async fn new(config: &Config) -> Result<Self> {
        // Create database connection pool
        let db = SqlitePool::connect(&config.database_url).await?;

        // Run migrations
        sqlx::migrate!("./migrations").run(&db).await?;

        // Configure WebAuthn
        let rp_id = config.rp_id.clone();
        let rp_origin = Url::parse(&config.rp_origin)?;

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?;
        let webauthn = Arc::new(builder.build()?);

        Ok(AppState { db, webauthn })
    }
}
