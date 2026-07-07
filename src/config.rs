use std::path::{Path, PathBuf};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};

use crate::error::AuthError;

/// The signing/verification key material for a [`JwtConfig`].
///
/// `Secret` selects HS256 with a shared secret. `PubPriKey` and
/// `PubPriPath` both select EdDSA (Ed25519), differing only in how the
/// PEM file is located on disk — resolved lazily, at sign/verify time,
/// never held in memory ahead of use:
///
/// - `PubPriKey(name)` follows the SSH key-file convention: the private
///   key is `~/.ssh/{name}`, the public key is `~/.ssh/{name}.pub`. Both
///   sides of the exchange use the *same* name; each side only ever has
///   the one file it needs.
/// - `PubPriPath(path)` uses `path` exactly as given, with no suffix
///   convention — point one `JwtConfig` at the private key file to sign,
///   and a different `JwtConfig` at the public key file to verify.
///
/// ```text
/// openssl genpkey -algorithm Ed25519 -out private.pem
/// openssl pkey -in private.pem -pubout -out public.pem
/// ```
#[derive(Debug, Clone)]
pub enum AuthType {
    /// HMAC secret shared between issuer and verifier (HS256).
    Secret(String),
    /// SSH-convention key name (EdDSA): `~/.ssh/{name}` / `~/.ssh/{name}.pub`.
    PubPriKey(String),
    /// Exact PEM file path (EdDSA), used as-is for whichever role
    /// (signing or verifying) this `JwtConfig` plays.
    PubPriPath(String),
}

impl AuthType {
    /// The `jsonwebtoken` algorithm implied by this key type.
    pub fn algorithm(&self) -> Algorithm {
        match self {
            AuthType::Secret(_) => Algorithm::HS256,
            AuthType::PubPriKey(_) | AuthType::PubPriPath(_) => Algorithm::EdDSA,
        }
    }

    /// Build the key used to sign tokens. Reads a PKCS8 Ed25519 private
    /// key PEM from `~/.ssh/{name}` (`PubPriKey`) or `path` (`PubPriPath`).
    pub fn encoding_key(&self) -> Result<EncodingKey, AuthError> {
        match self {
            AuthType::Secret(secret) => Ok(EncodingKey::from_secret(secret.as_bytes())),
            AuthType::PubPriKey(name) => {
                let pem = read_pem(&ssh_key_path(name)?)?;
                EncodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| {
                    AuthError::ConfigError(format!("invalid Ed25519 private key: {e}"))
                })
            }
            AuthType::PubPriPath(path) => {
                let pem = read_pem(Path::new(path))?;
                EncodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| {
                    AuthError::ConfigError(format!("invalid Ed25519 private key: {e}"))
                })
            }
        }
    }

    /// Build the key used to verify tokens. Reads an SPKI Ed25519 public
    /// key PEM from `~/.ssh/{name}.pub` (`PubPriKey`) or `path` (`PubPriPath`).
    pub fn decoding_key(&self) -> Result<DecodingKey, AuthError> {
        match self {
            AuthType::Secret(secret) => Ok(DecodingKey::from_secret(secret.as_bytes())),
            AuthType::PubPriKey(name) => {
                let pem = read_pem(&ssh_pub_key_path(name)?)?;
                DecodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| {
                    AuthError::ConfigError(format!("invalid Ed25519 public key: {e}"))
                })
            }
            AuthType::PubPriPath(path) => {
                let pem = read_pem(Path::new(path))?;
                DecodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| {
                    AuthError::ConfigError(format!("invalid Ed25519 public key: {e}"))
                })
            }
        }
    }

    /// Whether the underlying key name/path/secret is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            AuthType::Secret(v) | AuthType::PubPriKey(v) | AuthType::PubPriPath(v) => {
                v.is_empty()
            }
        }
    }
}

fn home_ssh_dir() -> Result<PathBuf, AuthError> {
    let home = std::env::var("HOME")
        .map_err(|_| AuthError::ConfigError("HOME is not set; cannot resolve ~/.ssh key".into()))?;
    Ok(PathBuf::from(home).join(".ssh"))
}

fn ssh_key_path(name: &str) -> Result<PathBuf, AuthError> {
    Ok(home_ssh_dir()?.join(name))
}

fn ssh_pub_key_path(name: &str) -> Result<PathBuf, AuthError> {
    Ok(home_ssh_dir()?.join(format!("{name}.pub")))
}

fn read_pem(path: &Path) -> Result<String, AuthError> {
    std::fs::read_to_string(path)
        .map_err(|e| AuthError::ConfigError(format!("failed to read key file {}: {e}", path.display())))
}

/// How to compute the `prv` claim.
#[derive(Debug, Clone)]
pub enum ProviderStrategy {
    /// No `prv` claim.
    None,
    /// SHA-1 of the given string (Laravel convention).
    Sha1(String),
    /// A pre-computed literal value.
    Literal(String),
}

impl ProviderStrategy {
    pub fn laravel(class: impl Into<String>) -> Self {
        Self::Sha1(class.into())
    }

    pub fn compute(&self) -> Option<String> {
        match self {
            Self::None => Option::None,
            Self::Sha1(input) => {
                use sha1::Digest;
                let hash = sha1::Sha1::new_with_prefix(input.as_bytes()).finalize();
                Some(hex_encode(&hash))
            }
            Self::Literal(v) => Some(v.clone()),
        }
    }
}

/// Configuration for JWT encode/decode.
///
/// Build with [`new`](Self::new), [`laravel_compat`](Self::laravel_compat),
/// or [`from_env`](Self::from_env).  See `from_env` for supported env vars.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub key: AuthType,
    pub base_url: String,
    pub auth_path: String,
    pub provider: ProviderStrategy,
    pub ttl_days: u64,
    /// When `Some`, overrides `ttl_days` with second-level granularity.
    /// Set via [`ttl_minutes`](Self::ttl_minutes) or [`ttl_seconds`](Self::ttl_seconds).
    pub ttl_seconds: Option<i64>,
    pub validate_issuer: bool,
    pub validate_provider: bool,
    /// When `Some`, the `aud` claim is both written into generated tokens
    /// and enforced during verification.  `None` means no audience claim.
    pub audience: Option<Vec<String>>,
}

impl JwtConfig {
    /// New config with framework-agnostic defaults (no `prv` claim).
    ///
    /// For Laravel compatibility use [`laravel_compat`](Self::laravel_compat)
    /// or [`from_env`](Self::from_env) with `USER_MODEL_PATH` set.
    pub fn new(secret: impl Into<String>) -> Self {
        Self::with_key(AuthType::Secret(secret.into()))
    }

    /// New EdDSA (Ed25519) config using the SSH key-file convention:
    /// `~/.ssh/{name}` (private) / `~/.ssh/{name}.pub` (public).
    ///
    /// The PEM itself isn't passed here — it's read from disk lazily,
    /// when a token is actually signed or verified. See
    /// [`AuthType::PubPriKey`] for details.
    pub fn new_with_key_name(name: impl Into<String>) -> Self {
        Self::with_key(AuthType::PubPriKey(name.into()))
    }

    /// New EdDSA (Ed25519) config using an exact PEM file path.
    ///
    /// `path` is read from disk lazily, when a token is actually signed
    /// or verified, and used as-is — the private key PEM to sign, or the
    /// public key PEM to verify, depending on which is called. See
    /// [`AuthType::PubPriPath`] for details.
    pub fn new_with_key_path(path: impl Into<String>) -> Self {
        Self::with_key(AuthType::PubPriPath(path.into()))
    }

    fn with_key(key: AuthType) -> Self {
        Self {
            key,
            base_url: "http://localhost:8000".into(),
            auth_path: "/api/login".into(),
            provider: ProviderStrategy::None,
            ttl_days: 3,
            ttl_seconds: None,
            validate_issuer: false,
            validate_provider: false,
            audience: None,
        }
    }

    /// Drop-in config for Laravel `tymon/jwt-auth` compatibility.
    ///
    /// Sets the `prv` claim to `sha1(model_class)` and enables its validation,
    /// matching what `tymon/jwt-auth` issues and expects.  Use the same
    /// `JWT_SECRET` as the Laravel application.
    ///
    /// ```rust
    /// use axum_jwt_bridge::{JwtConfig, ProviderStrategy};
    ///
    /// let config = JwtConfig::laravel_compat("your-jwt-secret", "App\\Models\\User");
    /// // Optionally chain .validate_issuer(true) if BASE_URL / AUTH_PATH match.
    /// ```
    pub fn laravel_compat(
        secret: impl Into<String>,
        model_class: impl Into<String>,
    ) -> Self {
        Self::new(secret)
            .provider(ProviderStrategy::laravel(model_class))
            .validate_provider(true)
    }

    /// Build from environment variables already set in the process.
    ///
    /// | Variable              | Required | Default                 | Notes                                    |
    /// |-----------------------|----------|-------------------------|------------------------------------------|
    /// | `JWT_SECRET`          | one of   | —                       | HS256 shared secret                      |
    /// | `JWT_KEY_NAME`        | these    | —                       | EdDSA: SSH-convention key name — `~/.ssh/{name}` / `~/.ssh/{name}.pub` |
    /// | `JWT_KEY_PATH`        | three    | —                       | EdDSA: exact PEM file path, used as-is   |
    /// | `BASE_URL`            | no       | `http://localhost:8000` |                                          |
    /// | `AUTH_PATH`           | no       | `/api/login`            |                                          |
    /// | `JWT_TTL_DAYS`        | no       | `3`                    | Token lifetime in days                   |
    /// | `USER_MODEL_PATH`     | no       | *(unset)*               | Sets `prv` and **enables** its validation|
    /// | `JWT_VALIDATE_ISSUER` | no       | `false`                 | `true` or `1` to enable                 |
    /// | `JWT_AUDIENCE`        | no       | *(unset)*               | Comma-separated; sets and validates `aud`|
    ///
    /// Setting `USER_MODEL_PATH` automatically enables `validate_provider`.
    /// Exactly one of `JWT_SECRET`, `JWT_KEY_NAME`, or `JWT_KEY_PATH` must
    /// be set. For the latter two, the actual PEM is *not* read here —
    /// it's read from disk lazily at sign/verify time. See
    /// [`AuthType::PubPriKey`] / [`AuthType::PubPriPath`] for details.
    pub fn from_env() -> Result<Self, AuthError> {
        let key = if let Ok(secret) = std::env::var("JWT_SECRET") {
            AuthType::Secret(secret)
        } else if let Ok(path) = std::env::var("JWT_KEY_PATH") {
            AuthType::PubPriPath(path)
        } else if let Ok(name) = std::env::var("JWT_KEY_NAME") {
            AuthType::PubPriKey(name)
        } else {
            return Err(AuthError::ConfigError(
                "one of JWT_SECRET, JWT_KEY_NAME, or JWT_KEY_PATH must be set".into(),
            ));
        };

        let base_url =
            std::env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8000".into());
        let auth_path =
            std::env::var("AUTH_PATH").unwrap_or_else(|_| "/api/login".into());

        let ttl_days = std::env::var("JWT_TTL_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        // Setting USER_MODEL_PATH implies you want the prv claim enforced.
        let (provider, validate_provider) = match std::env::var("USER_MODEL_PATH") {
            Ok(class_path) if !class_path.is_empty() => (ProviderStrategy::laravel(class_path), true),
            _ => (ProviderStrategy::None, false),
        };

        let validate_issuer = std::env::var("JWT_VALIDATE_ISSUER")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        // Comma-separated list, e.g. "https://api.example.com,https://admin.example.com"
        let audience = std::env::var("JWT_AUDIENCE")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect());

        Ok(Self {
            key,
            base_url,
            auth_path,
            provider,
            ttl_days,
            ttl_seconds: None,
            validate_issuer,
            validate_provider,
            audience,
        })
    }

    /// Full issuer URI: `{base_url}/{auth_path}`.
    pub fn issuer(&self) -> String {
        let base = self.base_url.trim_end_matches('/');
        let path = self.auth_path.trim_start_matches('/');
        format!("{base}/{path}")
    }

    pub fn base_url(&mut self, v: impl Into<String>) -> Self {
        self.base_url = v.into();
        self.to_owned()
    }
    pub fn auth_path(&mut self, v: impl Into<String>) -> Self {
        self.auth_path = v.into();
        self.to_owned() 
    }
    pub fn provider(&mut self, v: ProviderStrategy) -> Self {
        self.provider = v;
        self.to_owned()
    }
    pub fn ttl_days(mut self, v: u64) -> Self {
        self.ttl_days = v;
        self
    }
    /// Overrides `ttl_days` with a shorter, second-level lifetime — for
    /// machine-to-machine tokens that should live minutes, not days.
    pub fn ttl_seconds(mut self, v: i64) -> Self {
        self.ttl_seconds = Some(v);
        self
    }
    pub fn ttl_minutes(mut self, v: u64) -> Self {
        self.ttl_seconds = Some((v as i64) * 60);
        self
    }
    pub fn validate_issuer(&mut self, v: bool) -> Self {
        self.validate_issuer = v;
        self.to_owned()
    }
    pub fn validate_provider(&mut self, v: bool) -> Self {
        self.validate_provider = v;
        self.to_owned()

    }
    pub fn audience(&mut self, v: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.audience = Some(v.into_iter().map(Into::into).collect());
        self.to_owned()
    }
}

/// An ordered list of [`JwtConfig`]s tried in sequence during verification.
///
/// Register as an Axum extension instead of (or alongside) a single
/// `JwtConfig` to accept tokens from multiple issuers.
///
/// ```rust,no_run
/// use axum::{routing::get, Extension, Router};
/// use axum_jwt_bridge::{AuthUser, JwtConfig, MultiJwtConfig};
///
/// # async fn handler(_: AuthUser) {}
/// # async fn example() {
/// let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
/// let dotnet  = JwtConfig::new("dotnet-secret").validate_issuer(true);
///
/// let app: Router = Router::new()
///     .route("/me", get(handler))
///     .layer(Extension(MultiJwtConfig::new([laravel, dotnet])));
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct MultiJwtConfig(Vec<JwtConfig>);

impl MultiJwtConfig {
    /// Create from any iterable of [`JwtConfig`]s.
    pub fn new(configs: impl IntoIterator<Item = JwtConfig>) -> Self {
        Self(configs.into_iter().collect())
    }

    /// Iterate over the contained configs.
    pub fn iter(&self) -> impl Iterator<Item = &JwtConfig> {
        self.0.iter()
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}