use jsonwebtoken::{Header, Validation, decode, encode, get_current_timestamp};
use rand::RngExt;
use serde::{de::DeserializeOwned, Serialize};

use crate::claims::{Claims, NoExtraClaims};
use crate::config::{JwtConfig, MultiJwtConfig};
use crate::error::AuthError;

/// Random alphanumeric `jti`.
pub fn generate_jti(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len())] as char)
        .collect()
}

/// Create a signed HS256 JWT.  `user_id` becomes the `sub` claim.
///
/// Extra claims are set to [`NoExtraClaims`] (nothing).  To include
/// framework-specific claims, use [`generate_jwt_with`].
pub fn generate_jwt(user_id: impl ToString, config: &JwtConfig) -> Result<String, AuthError> {
    generate_jwt_with(user_id, config, NoExtraClaims)
}

/// Create a signed HS256 JWT with custom extra claims flattened into the
/// payload.
///
/// ```rust,no_run
/// use serde::Serialize;
/// use axum_jwt_bridge::{generate_jwt_with, JwtConfig};
///
/// #[derive(Serialize)]
/// struct Extra { tenant_id: String }
///
/// # fn main() -> Result<(), axum_jwt_bridge::AuthError> {
/// let config = JwtConfig::new("secret");
/// let token = generate_jwt_with(42, &config, Extra { tenant_id: "acme".into() })?;
/// # Ok(())
/// # }
/// ```
pub fn generate_jwt_with<E: Serialize>(
    user_id: impl ToString,
    config: &JwtConfig,
    extra: E,
) -> Result<String, AuthError> {
    let sub = user_id.to_string();
    if sub.is_empty() {
        return Err(AuthError::InvalidSubject("user_id must not be empty".into()));
    }
    if config.key.is_empty() {
        return Err(AuthError::ConfigError("JWT key must not be empty".into()));
    }

    let now = get_current_timestamp() as i64;
    let ttl_secs = config.ttl_seconds.unwrap_or((config.ttl_days as i64) * 86_400);

    let claims = Claims {
        iss: config.issuer(),
        iat: now,
        exp: now + ttl_secs,
        nbf: now,
        jti: generate_jti(16),
        sub,
        aud: config.audience.clone(),
        prv: config.provider.compute(),
        extra,
    };

    encode(
        &Header::new(config.key.algorithm()),
        &claims,
        &config.key.encoding_key()?,
    )
    .map_err(|e| AuthError::InvalidToken(e.to_string()))
}

/// Verify an HS256 JWT, ignoring any extra claims.
///
/// Returns `Claims<NoExtraClaims>`.  To deserialize framework-specific
/// extra claims, use [`verify_jwt_as`].
pub fn verify_jwt(token: &str, config: &JwtConfig) -> Result<Claims, AuthError> {
    verify_jwt_as::<NoExtraClaims>(token, config)
}

/// Try each config in [`MultiJwtConfig`] in order; return the first success.
///
/// Intended for services that accept tokens from multiple issuers (e.g. a
/// Laravel backend and a .NET Core service during a migration).  Each config
/// is tried independently — a wrong-secret failure on one does not affect
/// the others.  The last error is returned only if every config fails.
pub fn verify_jwt_any(token: &str, configs: &MultiJwtConfig) -> Result<Claims, AuthError> {
    verify_jwt_any_as::<NoExtraClaims>(token, configs)
}

/// Like [`verify_jwt_any`] but deserializes extra claims into `E`.
pub fn verify_jwt_any_as<E: DeserializeOwned>(
    token: &str,
    configs: &MultiJwtConfig,
) -> Result<Claims<E>, AuthError> {
    let mut last_err = AuthError::InvalidToken("no configs provided".into());
    for config in configs.iter() {
        match verify_jwt_as::<E>(token, config) {
            Ok(claims) => return Ok(claims),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Verify an HS256 JWT, deserializing extra claims into `E`.
///
/// ```rust,no_run
/// use serde::Deserialize;
/// use axum_jwt_bridge::{Claims, verify_jwt_as, JwtConfig};
///
/// #[derive(Deserialize)]
/// struct Extra { tenant_id: Option<String> }
///
/// # fn main() -> Result<(), axum_jwt_bridge::AuthError> {
/// # let token = String::new();
/// let config = JwtConfig::new("secret");
/// let claims: Claims<Extra> = verify_jwt_as(&token, &config)?;
/// println!("tenant: {:?}", claims.extra.tenant_id);
/// # Ok(())
/// # }
/// ```
pub fn verify_jwt_as<E: DeserializeOwned>(
    token: &str,
    config: &JwtConfig,
) -> Result<Claims<E>, AuthError> {
    let mut validation = Validation::new(config.key.algorithm());
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "sub", "iat"]);

    if config.validate_issuer {
        if let Some(iss) = config.issuer() {
            validation.set_issuer(&[iss]);
        }
    }

    if let Some(aud) = &config.audience {
        validation.set_audience(aud);
    } else {
        validation.validate_aud = false;
    }

    let data = decode::<Claims<E>>(
        token,
        &config.key.decoding_key()?,
        &validation,
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
        jsonwebtoken::errors::ErrorKind::ImmatureSignature => AuthError::TokenNotYetValid,
        jsonwebtoken::errors::ErrorKind::InvalidIssuer => AuthError::InvalidIssuer,
        jsonwebtoken::errors::ErrorKind::InvalidAudience => AuthError::InvalidAudience,
        _ => AuthError::InvalidToken(e.to_string()),
    })?;

    let claims = data.claims;

    if config.validate_provider {
        if let Some(expected) = config.provider.compute() {
            match &claims.prv {
                Some(prv) if *prv == expected => {}
                _ => return Err(AuthError::InvalidProvider(format!(
                    "expected prv claim {:?}, got {:?}",
                    expected, claims.prv
                ))),
            }
        }
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cfg = JwtConfig::new("test-secret");
        let token = generate_jwt(42u32, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert_eq!(claims.user_id_u32(), Some(42));
        assert_eq!(claims.sub, "42");
        assert!(claims.prv.is_none());
    }

    #[test]
    fn roundtrip_laravel() {
        use crate::config::ProviderStrategy;
        let cfg = JwtConfig::new("test-secret")
            .provider(ProviderStrategy::laravel("App\\Models\\User"));
        let token = generate_jwt(42u32, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert_eq!(claims.user_id_u32(), Some(42));
        assert_eq!(claims.sub, "42");
        assert!(claims.prv.is_some());
    }

    #[test]
    fn wrong_secret_rejected() {
        let token = generate_jwt(1, &JwtConfig::new("good")).unwrap();
        assert!(verify_jwt(&token, &JwtConfig::new("bad")).is_err());
    }

    #[test]
    fn issuer_normalised() {
        let cfg = JwtConfig::new("s")
            .base_url("https://example.com/")
            .auth_path("/api/login");
        assert_eq!(cfg.issuer(), Some("https://example.com/api/login".to_string()));
    }

    #[test]
    fn no_base_url_omits_iss() {
        let cfg = JwtConfig::new("s");
        assert_eq!(cfg.issuer(), None);
        let token = generate_jwt(1, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert!(claims.iss.is_none());
    }

    #[test]
    fn no_provider_omits_prv() {
        use crate::config::ProviderStrategy;
        let cfg = JwtConfig::new("s").provider(ProviderStrategy::None);
        let token = generate_jwt(1, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert!(claims.prv.is_none());
    }

    #[test]
    fn prv_hash_is_deterministic() {
        use crate::config::ProviderStrategy;
        let a = ProviderStrategy::laravel("App\\Models\\User").compute();
        let b = ProviderStrategy::laravel("App\\Models\\User").compute();
        assert_eq!(a, b);
        assert_eq!(a.unwrap().len(), 40); // SHA-1 hex
    }

    #[test]
    fn roundtrip_with_extra_claims() {
        use serde::Deserialize;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct Extra {
            tenant_id: String,
        }

        let cfg = JwtConfig::new("test-secret");
        let token = generate_jwt_with(7, &cfg, Extra { tenant_id: "acme".into() }).unwrap();
        let claims = verify_jwt_as::<Extra>(&token, &cfg).unwrap();
        assert_eq!(claims.sub, "7");
        assert_eq!(claims.extra.tenant_id, "acme");
    }

    // ── Audience (aud) tests ──────────────────────────────────────────────────
    //
    // The `aud` claim (RFC 7519 §4.1.3) is used by:
    //   - Auth0          — identifies the API the token is issued for
    //   - Keycloak        — the client/resource-server the token targets
    //   - Okta            — the authorization server audience URI
    //   - AWS Cognito     — the app client ID
    //   - Firebase Auth   — the Firebase project ID
    //   - OAuth 2.0 JWT Bearer (RFC 9068) — mandatory `aud` field
    //
    // Laravel (tymon/jwt-auth) and Django REST Framework SimpleJWT do NOT
    // use `aud` by default, so `config.audience` is `None` for those.

    #[test]
    fn aud_roundtrip_single() {
        let cfg = JwtConfig::new("secret").audience(["https://api.example.com"]);
        let token = generate_jwt(1, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert_eq!(claims.aud.as_deref(), Some(["https://api.example.com".to_string()].as_slice()));
    }

    #[test]
    fn aud_roundtrip_multiple() {
        // Auth0 / Keycloak sometimes issue tokens with multiple audiences.
        let cfg = JwtConfig::new("secret")
            .audience(["https://api.example.com", "https://admin.example.com"]);
        let token = generate_jwt(1, &cfg).unwrap();
        let claims = verify_jwt(&token, &cfg).unwrap();
        let aud = claims.aud.unwrap();
        assert!(aud.contains(&"https://api.example.com".to_string()));
        assert!(aud.contains(&"https://admin.example.com".to_string()));
    }

    #[test]
    fn wrong_audience_rejected() {
        let issuing_cfg = JwtConfig::new("secret").audience(["https://api.example.com"]);
        let token = generate_jwt(1, &issuing_cfg).unwrap();

        // Verifier expects a different audience.
        let verifying_cfg = JwtConfig::new("secret").audience(["https://other.example.com"]);
        assert!(matches!(
            verify_jwt(&token, &verifying_cfg),
            Err(AuthError::InvalidAudience)
        ));
    }

    #[test]
    fn no_audience_config_ignores_aud_claim() {
        // Tokens that carry an aud claim should not be rejected when the
        // verifier has no audience configured (Laravel / Django behaviour).
        let issuing_cfg = JwtConfig::new("secret").audience(["https://api.example.com"]);
        let token = generate_jwt(1, &issuing_cfg).unwrap();

        let verifying_cfg = JwtConfig::new("secret"); // no audience check
        assert!(verify_jwt(&token, &verifying_cfg).is_ok());
    }

    // ── Multi-issuer tests ────────────────────────────────────────────────────

    #[test]
    fn multi_config_accepts_first_issuer() {
        use crate::config::MultiJwtConfig;
        let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
        let dotnet  = JwtConfig::new("dotnet-secret").validate_issuer(true);
        let multi   = MultiJwtConfig::new([laravel.clone(), dotnet]);

        let token = generate_jwt(1, &laravel).unwrap();
        assert!(verify_jwt_any(&token, &multi).is_ok());
    }

    #[test]
    fn multi_config_accepts_second_issuer() {
        use crate::config::MultiJwtConfig;
        let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
        let dotnet  = JwtConfig::new("dotnet-secret");
        let multi   = MultiJwtConfig::new([laravel, dotnet.clone()]);

        let token = generate_jwt(2, &dotnet).unwrap();
        assert!(verify_jwt_any(&token, &multi).is_ok());
    }

    #[test]
    fn multi_config_rejects_unknown_issuer() {
        use crate::config::MultiJwtConfig;
        let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
        let dotnet  = JwtConfig::new("dotnet-secret");
        let multi   = MultiJwtConfig::new([laravel, dotnet]);

        // Token signed with a completely different secret.
        let other = JwtConfig::new("unknown-secret");
        let token = generate_jwt(3, &other).unwrap();
        assert!(verify_jwt_any(&token, &multi).is_err());
    }

    // ── EdDSA (Ed25519 pub/priv) tests ─────────────────────────────────────────
    //
    // Keys generated with:
    //   openssl genpkey -algorithm Ed25519 -out private.pem
    //   openssl pkey -in private.pem -pubout -out public.pem

    const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIFhV9IQhWlsUUaXNJRIpFs2t1UrxFZ5+jqZj6OQaP/bP\n\
-----END PRIVATE KEY-----\n";

    const ED25519_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAzTkaQZpuuiMyLeAbAzwQZsevd074P9w1dc28P0Jm0ds=\n\
-----END PUBLIC KEY-----\n";

    /// `PubPriKey` follows the SSH key-file convention: `~/.ssh/{name}`
    /// (private) / `~/.ssh/{name}.pub` (public). HOME is process-global,
    /// so every scenario that needs a mocked `~/.ssh` runs inside this one
    /// test rather than racing across parallel tests — and a real HOME is
    /// restored, and the temp dir removed, before returning.
    #[test]
    fn eddsa_ssh_key_name_roundtrip_and_rejections() {
        let home_dir = std::env::temp_dir().join(format!("axum-jwt-bridge-test-home-{}", generate_jti(8)));
        let ssh_dir = home_dir.join(".ssh");
        std::fs::create_dir_all(&ssh_dir).unwrap();
        std::fs::write(ssh_dir.join("id_ed25519"), ED25519_PRIVATE_PEM).unwrap();
        std::fs::write(ssh_dir.join("id_ed25519.pub"), ED25519_PUBLIC_PEM).unwrap();
        std::fs::write(
            ssh_dir.join("other_key.pub"),
            "-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEA1y1CmbeUGoMfPNH9UBr8OG199ieLVVx/dT9uurMQclU=\n\
-----END PUBLIC KEY-----\n",
        )
        .unwrap();

        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", &home_dir);
        }

        // Roundtrip: Server A signs with ~/.ssh/id_ed25519, Server B
        // verifies with ~/.ssh/id_ed25519.pub — same name, different file.
        let signing_cfg = JwtConfig::new_with_key_name("id_ed25519");
        let token = generate_jwt(42u32, &signing_cfg).unwrap();
        let verifying_cfg = JwtConfig::new_with_key_name("id_ed25519");
        let claims = verify_jwt(&token, &verifying_cfg).unwrap();
        assert_eq!(claims.sub, "42");

        // A different keypair's public key must not validate this token.
        let wrong_cfg = JwtConfig::new_with_key_name("other_key");
        assert!(verify_jwt(&token, &wrong_cfg).is_err());

        // A missing private key file fails to sign, not silently produce
        // a bad token.
        let missing_cfg = JwtConfig::new_with_key_name("no_such_key");
        assert!(generate_jwt(1, &missing_cfg).is_err());

        unsafe {
            match &original_home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
        }
        let _ = std::fs::remove_dir_all(&home_dir);
    }

    /// `PubPriPath` uses the given path exactly as-is, with no suffix
    /// convention — each side points directly at the file it holds.
    #[test]
    fn eddsa_exact_path_roundtrip() {
        let dir = std::env::temp_dir();
        let priv_path = dir.join(format!("axum-jwt-bridge-test-{}-private.pem", generate_jti(8)));
        let pub_path = dir.join(format!("axum-jwt-bridge-test-{}-public.pem", generate_jti(8)));
        std::fs::write(&priv_path, ED25519_PRIVATE_PEM).unwrap();
        std::fs::write(&pub_path, ED25519_PUBLIC_PEM).unwrap();

        let signing_cfg = JwtConfig::new_with_key_path(priv_path.to_str().unwrap());
        let token = generate_jwt(99u32, &signing_cfg).unwrap();

        let verifying_cfg = JwtConfig::new_with_key_path(pub_path.to_str().unwrap());
        let claims = verify_jwt(&token, &verifying_cfg).unwrap();
        assert_eq!(claims.sub, "99");

        let _ = std::fs::remove_file(&priv_path);
        let _ = std::fs::remove_file(&pub_path);
    }

    #[test]
    fn eddsa_exact_path_public_key_cannot_sign() {
        let dir = std::env::temp_dir();
        let pub_path = dir.join(format!("axum-jwt-bridge-test-{}-public-only.pem", generate_jti(8)));
        std::fs::write(&pub_path, ED25519_PUBLIC_PEM).unwrap();

        // A public key PEM isn't a valid PKCS8 private key — signing must
        // fail rather than silently produce a bad token.
        let cfg = JwtConfig::new_with_key_path(pub_path.to_str().unwrap());
        assert!(generate_jwt(1, &cfg).is_err());

        let _ = std::fs::remove_file(&pub_path);
    }

    #[test]
    fn extra_claims_ignored_by_default() {
        use serde::Deserialize;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct Extra {
            custom_field: String,
        }

        let cfg = JwtConfig::new("test-secret");
        // Generate with extra claims
        let token = generate_jwt_with(1, &cfg, Extra { custom_field: "hello".into() }).unwrap();
        // Verify without — extra field is silently ignored
        let claims = verify_jwt(&token, &cfg).unwrap();
        assert_eq!(claims.sub, "1");
    }
}

