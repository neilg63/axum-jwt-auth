[![Mirror](https://img.shields.io/badge/mirror-github-blue)](https://github.com/neilg63/axum-jwt-bridge)
[![Crates.io](https://img.shields.io/crates/v/axum-jwt-bridge.svg)](https://crates.io/crates/axum-jwt-bridge)
[![Docs.rs](https://docs.rs/axum-jwt-bridge/badge.svg)](https://docs.rs/axum-jwt-bridge)

# axum-jwt-bridge

JWT encode/decode for [Axum](https://docs.rs/axum) microservices. Sign and verify with either an HS256 shared secret or an EdDSA (Ed25519) public/private keypair, with an audience claim (`aud`) for any standard issuer and a provider claim (`prv`) for Laravel's `tymon/jwt-auth`. Supports accepting tokens from multiple issuers simultaneously.

## Differences from `axum-jwt-auth`

- `axum-jwt-bridge` is focused on interoperability and migration scenarios (notably Laravel `prv` compatibility and multi-issuer acceptance during transitions).
- This crate can generate JWTs with standard registered claims (`iss`, `iat`, `exp`, `nbf`, `jti`, `sub`) plus optional `aud`/`prv`, while still prioritizing simple decode/extract middleware usage.
- [`axum-jwt-auth`](https://crates.io/crates/axum-jwt-auth) also supports standard-claims workflows and includes additional features that may be useful depending on your auth model; review both crates for your project needs.

Extracts `user_id: u32` from the `sub` claim. Role-based authorization is the consuming application's responsibility.

## Sample decoded token format

```json
{
    "iss": "https://subdomain.domain.tld/api/login",
    "iat": 1771440754,
    "exp": 1772650354,
    "nbf": 1771440754,
    "jti": "EzPm7S7qiUe0UVGw",
    "sub": "1232",
    "prv": "23bd5c8949f600adb39e701c400872db7a5976f7"
}
```

## Usage

The simplest pattern: add `AuthUser` as a handler parameter. Any route that includes it rejects unauthenticated requests automatically. Routes without it remain public.

```rust
use axum::{routing::get, Extension, Router};
use axum_jwt_bridge::{AuthUser, JwtConfig};

async fn handler(user: AuthUser) -> String {
    // user.user_id is the u32 parsed from "sub"
    // use it to query roles/permissions from your DB
    format!("user_id = {}", user.user_id)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok(); // your app loads .env, not this crate
    let config = JwtConfig::from_env().unwrap();

    let app: Router = Router::new()
        .route("/me", get(handler))
        .layer(Extension(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## Environment variables

This crate does **not** load `.env` files.

| Variable              | Required | Default                  | Notes                                      |
|-----------------------|----------|--------------------------|--------------------------------------------|
| `JWT_SECRET`          | one of   | —                        | HS256 shared secret                        |
| `JWT_KEY_NAME`        | these    | —                        | EdDSA: SSH-convention key name — `~/.ssh/{name}` / `~/.ssh/{name}.pub` |
| `JWT_KEY_PATH`        | three    | —                        | EdDSA: exact PEM file path, used as-is     |
| `BASE_URL`            | no       | *(unset — no `iss` claim)* | Combined with `AUTH_PATH` to form `iss` |
| `AUTH_PATH`           | no       | `/api/login`             | Only used if `BASE_URL` is set             |
| `JWT_TTL_DAYS`        | no       | `14`                     | Token lifetime in days                     |
| `USER_MODEL_PATH`     | no       | *(unset)*                | Sets `prv` and enables its validation      |
| `JWT_VALIDATE_ISSUER` | no       | `false`                  | Set to `true` or `1` to enable             |
| `JWT_AUDIENCE`        | no       | *(unset)*                | Comma-separated; sets and validates `aud`  |

Exactly one of `JWT_SECRET`, `JWT_KEY_NAME`, or `JWT_KEY_PATH` must be
set. For the latter two, the PEM isn't read at `from_env()` time — it's
read from disk lazily, at sign/verify time. See below.

## Programmatic configuration

```rust
use axum_jwt_bridge::{JwtConfig, ProviderStrategy};

// Framework-agnostic (no prv claim)
let config = JwtConfig::new("my-secret");

// Laravel tymon/jwt-auth compatible
// Note: This Rust string literal decodes to runtime value: App\Models\User.
// Keep runtime value aligned with your Laravel model class string.
// See Troubleshooting for .env / Node / PHP escaping differences.
// See the Troubleshooting section for details.
let config = JwtConfig::laravel_compat("my-secret", "App\\Models\\User");

// With audience claim (Auth0, Keycloak, Okta, etc.)
let config = JwtConfig::new("my-secret")
    .audience(["https://api.example.com"]);

// Custom issuer — sets the `iss` claim to "https://auth.example.com/v2/token".
// Without .base_url(...), no `iss` claim is written at all (there's no
// sane placeholder to default to).
let config = JwtConfig::new("my-secret")
    .base_url("https://auth.example.com")
    .auth_path("/v2/token");
```

## EdDSA (Ed25519 public/private key) configuration

For cross-service setups where the verifying service should never see the
signing secret, use an Ed25519 keypair instead of a shared HS256 secret.
Neither constructor below takes the PEM directly — the PEM is read from
disk lazily, the first time a token is actually signed or verified.

```sh
# Server A (issuer): generate a private key
openssl genpkey -algorithm Ed25519 -out private.pem

# Extract the public key to give to Server B (verifier)
openssl pkey -in private.pem -pubout -out public.pem
```

**By SSH-convention name** (`JwtConfig::new_with_key_name` / `JWT_KEY_NAME`)
— resolves to `~/.ssh/{name}` (private) and `~/.ssh/{name}.pub` (public).
Both sides use the same name; each side only ever has the one file it needs:

```sh
# Server A (issuer) has ~/.ssh/app_key (private key, no .pub file needed)
# Server B (verifier) has ~/.ssh/app_key.pub (public key, no private file needed)
```

```rust,no_run
use axum_jwt_bridge::JwtConfig;

// Server A signs — reads ~/.ssh/app_key.
let signing_config = JwtConfig::new_with_key_name("app_key");
let token = axum_jwt_bridge::generate_jwt(1264, &signing_config).unwrap();

// Server B verifies with the same name — reads ~/.ssh/app_key.pub.
let verifying_config = JwtConfig::new_with_key_name("app_key");
let claims = axum_jwt_bridge::verify_jwt(&token, &verifying_config).unwrap();
```

**By exact path** (`JwtConfig::new_with_key_path` / `JWT_KEY_PATH`) — the
path is used as-is, with no `.pub` suffix convention. Point each service
directly at the file it holds:

```rust,no_run
use axum_jwt_bridge::JwtConfig;

// Server A signs — reads exactly this path.
let signing_config = JwtConfig::new_with_key_path("/etc/keys/private.pem");
let token = axum_jwt_bridge::generate_jwt(1264, &signing_config).unwrap();

// Server B verifies — reads exactly this (different) path.
let verifying_config = JwtConfig::new_with_key_path("/etc/keys/public.pem");
let claims = axum_jwt_bridge::verify_jwt(&token, &verifying_config).unwrap();
```

Either way, a `JwtConfig` resolving only a public key can verify tokens
but cannot sign them — `generate_jwt`/`generate_jwt_with` return
`AuthError::ConfigError` if the private key file can't be read.

## Token generation

```rust
use axum_jwt_bridge::{generate_jwt, JwtConfig};

let config = JwtConfig::new("my-secret");
let token = generate_jwt(1264, &config).unwrap();
```

## Token verification

```rust
use axum_jwt_bridge::{generate_jwt, verify_jwt, JwtConfig};

let config = JwtConfig::new("my-secret");
let token = generate_jwt(1264, &config).unwrap();
let claims = verify_jwt(&token, &config).unwrap();
assert_eq!(claims.user_id_u32(), Some(1264));
```

## Optional authentication

```rust
use axum_jwt_bridge::OptionalAuthUser;

async fn handler(user: OptionalAuthUser) -> String {
    match user.into_inner() {
        Some(u) => format!("Hello, user {}!", u.user_id),
        None    => "Hello, anonymous!".into(),
    }
}
```

## Extra claims

Define a struct for any non-standard JWT fields your issuer includes:

```rust
use serde::Deserialize;
use axum_jwt_bridge::AuthUser;

#[derive(Debug, Clone, Deserialize)]
struct MyExtra {
    #[serde(default)]
    tenant_id: Option<String>,
}

async fn handler(user: AuthUser<MyExtra>) -> String {
    format!("tenant: {:?}", user.claims.extra.tenant_id)
}
```

Unknown fields are silently ignored when using the default `AuthUser` (no type parameter).

## Multi-issuer support

Accept tokens from multiple issuers simultaneously — useful when migrating between services. Each config is tried in order; the first success wins.

```rust
use axum::{routing::get, Extension, Router};
use axum_jwt_bridge::{AuthUser, JwtConfig, MultiJwtConfig};

# async fn handler(_: AuthUser) {}
# async fn example() {
let laravel = JwtConfig::laravel_compat("laravel-secret", "App\\Models\\User");
let dotnet  = JwtConfig::new("dotnet-secret")
    .base_url("https://dotnet.example.com")
    .validate_issuer(true);

let app: Router = Router::new()
    .route("/me", get(handler))
    .layer(Extension(MultiJwtConfig::new([laravel, dotnet])));
# }
```

`AuthUser` detects `MultiJwtConfig` automatically — no changes to handler code.

## Middleware for route groups

To protect an entire sub-router without touching individual handler signatures, use `axum::middleware::from_fn`:

```rust
use axum::{
    middleware::{self, Next},
    extract::Request,
    response::Response,
    routing::get,
    Extension, Router,
};
use axum_jwt_bridge::{verify_jwt, AuthError, JwtConfig};

async fn require_auth(
    Extension(config): Extension<JwtConfig>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let token = extract_bearer(&request)?;
    let claims = verify_jwt(&token, &config)?;
    request.extensions_mut().insert(claims); // available to handlers via Extension
    Ok(next.run(request).await)
}

fn extract_bearer(req: &Request) -> Result<String, AuthError> {
    req.headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or(AuthError::MissingHeader)
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let config = JwtConfig::from_env().unwrap();

    // All routes in this sub-router require a valid JWT.
    let protected = Router::new()
        .route("/me", get(me_handler))
        .route("/orders", get(orders_handler))
        .route_layer(middleware::from_fn(require_auth)); // use route_layer, not layer

    let app = Router::new()
        .route("/health", get(health_handler)) // public
        .merge(protected)                       // all protected
        .layer(Extension(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

> **Note:** Use `.route_layer` rather than `.layer` so the middleware only runs on matched routes. This prevents unauthenticated 404 responses for unknown paths.

### Which pattern to use

| Goal | Pattern |
|------|---------|
| Per-route auth, varying access levels | `AuthUser` / `OptionalAuthUser` extractor |
| Protect an entire router uniformly | `route_layer(from_fn(require_auth))` |
| Mix public + protected routes | Merge a protected sub-router |
| Multi-issuer (migration) | `Extension(MultiJwtConfig)` + either pattern |

## Troubleshooting

### "Invalid provider hash" error

If you're getting this error when verifying Laravel JWTs, the `prv` claim in your token doesn't match what this crate expects. This is usually due to **escaping differences between runtime values and source-code string literals**.

For standard Laravel 8+ setups, the intended runtime model path is usually:

```text
App\Models\User
```

That same runtime value may appear differently depending on where you set it:

- `.env`: `USER_MODEL_PATH=App\Models\User`
- Rust source literal: `"App\\Models\\User"`
- Node/JS source literal: `"App\\Models\\User"` (or `'App\\Models\\User'`)
- Laravel/PHP quoted string: often written with escaped backslashes, but should evaluate to `App\Models\User`

**Diagnose the issue:**

```bash
# Decode your JWT to see the actual prv value
cargo run --example decode -- YOUR_JWT_TOKEN_HERE
```

**Hash mapping (for quick checks):**

| Your JWT's `prv` hash | Runtime model path | Rust source literal |
|----------------------|-------------------------|-----------|
| `23bd5c8949f600adb39e701c400872db7a5976f7` | `App\Models\User` (Laravel 8+) | `"App\\Models\\User"` |
| `3bb14b87c47aabc7635b62725877baa20182812f` | `App\\Models\\User` (double backslashes in runtime value) | `"App\\\\Models\\\\User"` |
| `87e0af1ef9fd15812fdec97153a14e0b047546aa` | `App\User` (Laravel 5-7) | `"App\\User"` |

**Important:** match on **runtime value**, not how it is escaped in source files.

**How PHP quoting affects runtime value:**

- PHP single-quoted: `'App\\Models\\User'` → runtime `App\\Models\\User`
- PHP double-quoted: `"App\\Models\\User"` → runtime `App\Models\User`

Check your Laravel `config/auth.php` to see how the model is configured, then adjust your Rust code accordingly.

**Quick fix:** If you don't need the `prv` validation, disable it:

```rust
let config = JwtConfig::new("secret"); // no USER_MODEL_PATH or provider
```

This validates signature, expiry, and issuer but skips the provider hash check.

## CLI example

```bash
JWT_SECRET=my-secret cargo run --example token -- generate 42
JWT_SECRET=my-secret cargo run --example token -- verify eyJhbG...

# Decode a JWT to inspect claims (no verification)
cargo run --example decode -- eyJhbG...
```

## License

MIT — see [LICENSE](LICENSE).