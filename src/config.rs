use anyhow::Result;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        Ok(Config {
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()?,
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:passkey.db?mode=rwc".to_string()),
            rp_id: env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            rp_origin: env::var("RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            rp_name: env::var("RP_NAME").unwrap_or_else(|_| "Passkey Demo".to_string()),
        })
    }

    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}
