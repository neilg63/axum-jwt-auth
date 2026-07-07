//! # axum-jwt-bridge
//!
//! JWT encode/decode for [Axum](https://docs.rs/axum) microservices,
//! compatible with Laravel's `tymon/jwt-auth` and any HS256 JWT issuer.
//!
//! Extracts `user_id: u32` from the `sub` claim.  Role-based
//! authorization is the consuming application's responsibility.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use axum::{routing::get, Extension, Router};
//! use axum_jwt_bridge::{AuthUser, JwtConfig};
//!
//! async fn handler(user: AuthUser) -> String {
//!     format!("user_id = {}", user.user_id)
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     // Ensure JWT_SECRET (and optionally BASE_URL, AUTH_PATH,
//!     // USER_MODEL_PATH) are set in the environment before calling from_env.
//!     let config = JwtConfig::from_env().unwrap();
//!
//!     let app: Router = Router::new()
//!         .route("/me", get(handler))
//!         .layer(Extension(config));
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!
//! ## Custom extra claims
//!
//! ```rust
//! use serde::{Deserialize, Serialize};
//! use axum_jwt_bridge::{Claims, verify_jwt_as, generate_jwt_with, JwtConfig};
//!
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! struct MyExtra {
//!     #[serde(default)]
//!     tenant_id: Option<String>,
//! }
//!
//! # fn example() {
//! let config = JwtConfig::new("secret");
//! let token = generate_jwt_with(42, &config, MyExtra { tenant_id: Some("acme".into()) }).unwrap();
//! let claims: Claims<MyExtra> = verify_jwt_as(&token, &config).unwrap();
//! assert_eq!(claims.extra.tenant_id.as_deref(), Some("acme"));
//! # }
//! ```
//!
//! ## Environment variables (`JwtConfig::from_env`)
//!
//! This Mod does **not** load `.env` files.
//!
//! | Variable               | Required | Default                 | Notes                                     |
//! |------------------------|----------|-------------------------|-------------------------------------------|
//! | `JWT_SECRET`           | one of   | —                       | HS256 shared secret                       |
//! | `JWT_KEY_NAME`         | these    | —                       | EdDSA: SSH-convention key name — `~/.ssh/{name}` / `~/.ssh/{name}.pub` |
//! | `JWT_KEY_PATH`         | three    | —                       | EdDSA: exact PEM file path, used as-is    |
//! | `BASE_URL`             | no       | `http://localhost:8000` |                                           |
//! | `AUTH_PATH`            | no       | `/api/login`            |                                           |
//! | `JWT_TTL_DAYS`         | no       | `14`                    | Token lifetime in days                    |
//! | `USER_MODEL_PATH`      | no       | *(unset — no prv)*      | Sets `prv` claim and **enables** its check|
//! | `JWT_VALIDATE_ISSUER`  | no       | `false`                 | `true` or `1` to enable                  |
//! | `JWT_AUDIENCE`         | no       | *(unset)*               | Comma-separated audience URIs             |
//!
//! For `JWT_KEY_NAME` / `JWT_KEY_PATH`, the PEM itself isn't read here —
//! it's read from disk lazily, at sign/verify time. See
//! [`AuthType::PubPriKey`] / [`AuthType::PubPriPath`] for details.
//!
//! ## Laravel migration
//!
//! To validate tokens still being issued by a Laravel `tymon/jwt-auth` server,
//! share the same `JWT_SECRET` and set `USER_MODEL_PATH` (which auto-enables
//! `prv` validation):
//!
//! ```rust,no_run
//! use axum_jwt_bridge::JwtConfig;
//!
//! // Code-based setup:
//! let config = JwtConfig::laravel_compat("your-jwt-secret", "App\\Models\\User");
//!
//! // Or via environment (JWT_SECRET + USER_MODEL_PATH):
//! let config = JwtConfig::from_env().unwrap();
//! ```
//!
//! When your Rust services start issuing tokens too, the same config signs them
//! with the same `prv` hash, so Laravel can validate them without any changes.

pub mod claims;
pub mod config;
pub mod error;
pub mod middleware;
pub mod token;

pub use claims::{Claims, NoExtraClaims};
pub use config::{AuthType, JwtConfig, MultiJwtConfig, ProviderStrategy};
pub use error::AuthError;
pub use middleware::{AuthUser, OptionalAuthUser};
pub use token::{
    generate_jti, generate_jwt, generate_jwt_with,
    verify_jwt, verify_jwt_as,
    verify_jwt_any, verify_jwt_any_as,
};
