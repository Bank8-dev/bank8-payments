// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Integrations - versioning, auth, healthchecks, retry, idempotency.
//! See `services/payments/DESIGN.md` §4.6 (Integrations).
//! An *integration* is a named configuration for connecting Payments to an
//! external system (a scheme gateway, a core banking API, an OAuth-secured
//! partner endpoint, …). Each integration owns one or more *versions*;
//! the `active_version_id` pointer on `integrations` selects the
//! version that is currently used for outbound traffic. Versions are
//! immutable once published (`status = 'ready'`).

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

// ── Story - Integration versioning ──────────────────────────────

/// Lifecycle status of an integration version.
/// Mirrors the `status` CHECK constraint on `integration_versions`:
/// `'pending' | 'ready' | 'errored' | 'user_action_required'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationVersionStatus {
    /// Newly created, not yet validated/published.
    Pending,
    /// Published and usable by outbound traffic.
    Ready,
    /// Validation or publish failed.
    Errored,
    /// A user must perform a manual step (e.g. complete OAuth consent).
    UserActionRequired,
}

impl IntegrationVersionStatus {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "errored" => Ok(Self::Errored),
            "user_action_required" => Ok(Self::UserActionRequired),
            other => Err(format!("unknown integration version status: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Errored => "errored",
            Self::UserActionRequired => "user_action_required",
        }
    }
}

/// Create a new integration version in `status = 'pending'`.
/// The version number is auto-incremented per integration. The caller is
/// expected to validate the configuration and then call
/// [`publish_integration_version`] to flip it to `ready` and point the
/// parent integration's `active_version_id` at it.
pub async fn create_integration_version(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    integration_id: Uuid,
    config: &serde_json::Value,
    auth_config: &serde_json::Value,
    healthcheck: &serde_json::Value,
    retry_policy: &serde_json::Value,
) -> Result<Uuid, String> {
    let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;
    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM integration_versions WHERE integration_id = $1",
    )
    .bind(integration_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| e.to_string())?;

    let row = sqlx::query(
        r#"INSERT INTO integration_versions
               (env_id, integration_id, version,
                config, auth_config, healthcheck, retry_policy, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(integration_id)
    .bind(next_version)
    .bind(config)
    .bind(auth_config)
    .bind(healthcheck)
    .bind(retry_policy)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(row.get("id"))
}

/// Publish a pending integration version: set `status = 'ready'` and point
/// the parent integration's `active_version_id` at it.
pub async fn publish_integration_version(
    pool: &sqlx::PgPool,
    integration_version_id: Uuid,
) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    let parent: Option<Uuid> = sqlx::query_scalar(
        "UPDATE integration_versions
            SET status = 'ready'
          WHERE id = $1
         RETURNING integration_id",
    )
    .bind(integration_version_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    let integration_id =
        parent.ok_or_else(|| format!("integration version {integration_version_id} not found"))?;

    sqlx::query(
        r#"UPDATE integrations
              SET active_version_id = $2,
                  version = (SELECT version FROM integration_versions WHERE id = $2),
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(integration_id)
    .bind(integration_version_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(())
}

// ── Story - Integration authentication ──────────────────────────

/// Authentication method used by an integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Static bearer token stored in `auth_config.token`.
    StaticToken,
    /// RFC 6749 §4.4 client credentials grant.
    OAuthClientCredentials,
    /// RFC 6749 §4.3 resource owner password grant.
    OAuthPasswordGrant,
}

impl AuthMethod {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "static_token" => Ok(Self::StaticToken),
            "oauth_client_credentials" => Ok(Self::OAuthClientCredentials),
            "oauth_password_grant" => Ok(Self::OAuthPasswordGrant),
            other => Err(format!("unknown auth method: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StaticToken => "static_token",
            Self::OAuthClientCredentials => "oauth_client_credentials",
            Self::OAuthPasswordGrant => "oauth_password_grant",
        }
    }
}

/// Authentication configuration for an integration.
/// Serialised to JSONB and stored in `integration_versions.auth_config`
/// (and, for the create-integration handler, on `integrations.auth_config`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub method: AuthMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

/// Resolve the `Authorization` header value for an integration's auth config.
/// For [`AuthMethod::StaticToken`] this returns `Bearer <token>` directly. For
/// the OAuth methods a token request would have to be performed against
/// `token_url`; that network flow is intentionally not implemented here yet
/// callers should refresh tokens out-of-band and store the result as a static
/// token, so we return an error for the OAuth methods for now.
pub fn resolve_auth_header(auth_config: &AuthConfig) -> Result<String, String> {
    match auth_config.method {
        AuthMethod::StaticToken => {
            let token = auth_config
                .token
                .as_ref()
                .filter(|t| !t.is_empty())
                .ok_or_else(|| "static_token auth requires a non-empty token".to_string())?;
            Ok(format!("Bearer {token}"))
        }
        AuthMethod::OAuthClientCredentials => {
            Err("oauth_client_credentials token exchange not yet implemented".into())
        }
        AuthMethod::OAuthPasswordGrant => {
            Err("oauth_password_grant token exchange not yet implemented".into())
        }
    }
}

// ── Story - Integration healthchecks ────────────────────────────

/// Configuration for probing an integration's health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthcheckConfig {
    pub endpoint: String,
    #[serde(default = "default_interval_seconds")]
    pub interval_seconds: u64,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

fn default_interval_seconds() -> u64 {
    30
}
fn default_timeout_seconds() -> u64 {
    10
}

impl Default for HealthcheckConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            interval_seconds: default_interval_seconds(),
            timeout_seconds: default_timeout_seconds(),
        }
    }
}

/// Perform a single healthcheck against `endpoint` using the given auth
/// header. Returns `true` if the endpoint responds 2xx, `false` otherwise.
pub async fn perform_healthcheck(
    http_client: &reqwest::Client,
    healthcheck_config: &HealthcheckConfig,
    auth_header: &str,
) -> Result<bool, String> {
    let resp = http_client
        .get(&healthcheck_config.endpoint)
        .header(reqwest::header::AUTHORIZATION, auth_header)
        .timeout(std::time::Duration::from_secs(
            healthcheck_config.timeout_seconds,
        ))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    Ok(resp.status().is_success())
}

// ── Story - Integration retry policies ──────────────────────────

/// Exponential-backoff retry policy for an integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_initial_delay_seconds")]
    pub initial_delay_seconds: u64,
    #[serde(default = "default_max_delay_seconds")]
    pub max_delay_seconds: u64,
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

fn default_max_attempts() -> u32 {
    5
}
fn default_initial_delay_seconds() -> u64 {
    30
}
fn default_max_delay_seconds() -> u64 {
    1800
}
fn default_backoff_multiplier() -> f64 {
    2.0
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_delay_seconds: default_initial_delay_seconds(),
            max_delay_seconds: default_max_delay_seconds(),
            backoff_multiplier: default_backoff_multiplier(),
        }
    }
}

/// Calculate the delay (in seconds) before the `attempt`-th retry.
/// `attempt` is 1-indexed (1 = first retry). The delay is
/// `initial_delay_seconds * backoff_multiplier^(attempt - 1)`, capped at
/// `max_delay_seconds`.
pub fn calculate_delay(policy: &RetryPolicy, attempt: u32) -> u64 {
    if attempt == 0 {
        return policy.initial_delay_seconds;
    }
    let exponent = (attempt - 1) as f64;
    let raw = policy.initial_delay_seconds as f64 * policy.backoff_multiplier.powf(exponent);
    let capped = raw.min(policy.max_delay_seconds as f64);
    capped as u64
}

// ── Story - Integration idempotency ─────────────────────────────

/// Fixed namespace UUID for Payments integration idempotency keys.
pub const BANK8_PAYMENTS_INTEGRATION_NAMESPACE: Uuid = Uuid::from_bytes([
    0xc1, 0xa8, 0x7e, 0x3b, 0x42, 0xd1, 0x4e, 0x9f, 0xa2, 0x6b, 0x7e, 0x11, 0xc0, 0x4a, 0x9d, 0x5f,
]);

/// Generate a deterministic idempotency key for an integration operation.
/// Uses UUIDv5 over a fixed namespace and the canonical string
/// `"<integration_id>:<operation>:<canonical_payload_json>"`. The same
/// (integration, operation, payload) triple always yields the same key,
/// which allows safe retries of mutating integration calls (e.g. posting a
/// payment to a scheme gateway) to be deduplicated by the remote system.
pub fn generate_integration_idempotency_key(
    integration_id: Uuid,
    operation: &str,
    payload: &serde_json::Value,
) -> String {
    // Canonicalise the payload so key ordering / whitespace does not affect
    // the derived key.
    let canonical = canonical_json(payload);
    let name = format!("{integration_id}:{operation}:{canonical}");
    Uuid::new_v5(&BANK8_PAYMENTS_INTEGRATION_NAMESPACE, name.as_bytes()).to_string()
}

/// Produce a canonical JSON string (sorted object keys, no whitespace).
fn canonical_json(value: &serde_json::Value) -> String {
    // serde_json's default serialisation already preserves insertion order
    // for maps. To get a stable canonical form we recursively sort object
    // keys into a BTreeMap representation.
    fn render(v: &serde_json::Value) -> String {
        match v {
            serde_json::Value::Null => "null".into(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => {
                serde_json::to_string(s).unwrap_or_else(|_| String::new())
            }
            serde_json::Value::Array(arr) => {
                let parts: Vec<String> = arr.iter().map(render).collect();
                format!("[{}]", parts.join(","))
            }
            serde_json::Value::Object(obj) => {
                let mut keys: Vec<&String> = obj.keys().collect();
                keys.sort();
                let parts: Vec<String> = keys
                    .into_iter()
                    .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), render(&obj[k])))
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
        }
    }
    render(value)
}

// ── Story - Integration connectivity ──────────────────────────────

/// How Payments reaches an integration endpoint.
/// `PrivateLink` corresponds to AWS PrivateLink (or equivalent private
/// networking); `PublicInternet` is the default routable path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityMode {
    /// AWS PrivateLink / VPC endpoint - traffic stays on private network.
    PrivateLink,
    /// Public internet over TLS.
    PublicInternet,
}

impl ConnectivityMode {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "private_link" => Ok(Self::PrivateLink),
            "public_internet" => Ok(Self::PublicInternet),
            other => Err(format!("unknown connectivity mode: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateLink => "private_link",
            Self::PublicInternet => "public_internet",
        }
    }
}

/// Connectivity configuration for an integration.
/// Stored as part of an integration version's `config` JSONB. The
/// `private_link_id` is required when `mode = PrivateLink` (it identifies
/// the VPC endpoint / service name).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityConfig {
    pub mode: ConnectivityMode,
    pub endpoint_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_link_id: Option<String>,
}

/// Validate a connectivity configuration.
/// Checks that:
/// - `endpoint_url` parses to a valid `http(s)` URL with a host.
/// - For `PrivateLink` mode, `private_link_id` is present and non-empty.
pub fn validate_connectivity(config: &ConnectivityConfig) -> Result<(), String> {
    if config.endpoint_url.trim().is_empty() {
        return Err("endpoint_url must not be empty".into());
    }
    let url = reqwest::Url::parse(config.endpoint_url.trim())
        .map_err(|e| format!("endpoint_url is not a valid URL: {e}"))?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "endpoint_url must use http or https scheme, got '{scheme}'"
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| "endpoint_url must have a host".to_string())?;
    if host.is_empty() {
        return Err("endpoint_url must have a non-empty host".into());
    }
    if config.mode == ConnectivityMode::PrivateLink {
        let id = config.private_link_id.as_deref().unwrap_or("").trim();
        if id.is_empty() {
            return Err("private_link_id is required for private_link connectivity".into());
        }
    }
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // - versioning
    #[test]
    fn integration_version_status_round_trip() {
        for s in ["pending", "ready", "errored", "user_action_required"] {
            let v = IntegrationVersionStatus::from_str(s).unwrap();
            assert_eq!(v.as_str(), s);
        }
        assert!(IntegrationVersionStatus::from_str("nope").is_err());
    }

    // - auth
    #[test]
    fn auth_method_round_trip() {
        for s in [
            "static_token",
            "oauth_client_credentials",
            "oauth_password_grant",
        ] {
            let m = AuthMethod::from_str(s).unwrap();
            assert_eq!(m.as_str(), s);
        }
        assert!(AuthMethod::from_str("basic").is_err());
    }

    #[test]
    fn resolve_static_token_header() {
        let cfg = AuthConfig {
            method: AuthMethod::StaticToken,
            token: Some("abc123".into()),
            token_url: None,
            client_id: None,
            client_secret: None,
            username: None,
            password: None,
            scopes: None,
        };
        assert_eq!(resolve_auth_header(&cfg).unwrap(), "Bearer abc123");
    }

    #[test]
    fn resolve_static_token_missing() {
        let cfg = AuthConfig {
            method: AuthMethod::StaticToken,
            token: None,
            token_url: None,
            client_id: None,
            client_secret: None,
            username: None,
            password: None,
            scopes: None,
        };
        assert!(resolve_auth_header(&cfg).is_err());
    }

    #[test]
    fn resolve_oauth_not_implemented() {
        let cfg = AuthConfig {
            method: AuthMethod::OAuthClientCredentials,
            token: None,
            token_url: Some("https://example.com/token".into()),
            client_id: Some("id".into()),
            client_secret: Some("secret".into()),
            username: None,
            password: None,
            scopes: Some(vec!["read".into()]),
        };
        assert!(resolve_auth_header(&cfg).is_err());
    }

    // - healthcheck defaults
    #[test]
    fn healthcheck_config_default() {
        let hc = HealthcheckConfig::default();
        assert_eq!(hc.interval_seconds, 30);
        assert_eq!(hc.timeout_seconds, 10);
        assert!(hc.endpoint.is_empty());
    }

    #[test]
    fn healthcheck_config_serde_uses_defaults() {
        let json = r#"{"endpoint":"https://example.com/health"}"#;
        let hc: HealthcheckConfig = serde_json::from_str(json).unwrap();
        assert_eq!(hc.endpoint, "https://example.com/health");
        assert_eq!(hc.interval_seconds, 30);
        assert_eq!(hc.timeout_seconds, 10);
    }

    // - retry policy
    #[test]
    fn retry_policy_default() {
        let p = RetryPolicy::default();
        assert_eq!(p.max_attempts, 5);
        assert_eq!(p.initial_delay_seconds, 30);
        assert_eq!(p.max_delay_seconds, 1800);
        assert_eq!(p.backoff_multiplier, 2.0);
    }

    #[test]
    fn calculate_delay_exponential() {
        let p = RetryPolicy::default();
        // attempt 1: 30 * 2^0 = 30
        assert_eq!(calculate_delay(&p, 1), 30);
        // attempt 2: 30 * 2^1 = 60
        assert_eq!(calculate_delay(&p, 2), 60);
        // attempt 3: 30 * 2^2 = 120
        assert_eq!(calculate_delay(&p, 3), 120);
        // attempt 4: 30 * 2^3 = 240
        assert_eq!(calculate_delay(&p, 4), 240);
    }

    #[test]
    fn calculate_delay_capped_at_max() {
        let p = RetryPolicy::default();
        // attempt 20 would be 30 * 2^19 which is huge; capped at 1800.
        assert_eq!(calculate_delay(&p, 20), 1800);
    }

    #[test]
    fn calculate_delay_attempt_zero() {
        let p = RetryPolicy::default();
        assert_eq!(calculate_delay(&p, 0), p.initial_delay_seconds);
    }

    // - idempotency
    #[test]
    fn idempotency_key_is_deterministic() {
        let id = Uuid::new_v4();
        let payload = serde_json::json!({ "amount": 100, "currency": "USD" });
        let k1 = generate_integration_idempotency_key(id, "post_payment", &payload);
        let k2 = generate_integration_idempotency_key(id, "post_payment", &payload);
        assert_eq!(k1, k2);
    }

    #[test]
    fn idempotency_key_independent_of_key_order() {
        let id = Uuid::new_v4();
        let a = serde_json::json!({ "amount": 100, "currency": "USD" });
        let b = serde_json::json!({ "currency": "USD", "amount": 100 });
        let ka = generate_integration_idempotency_key(id, "post_payment", &a);
        let kb = generate_integration_idempotency_key(id, "post_payment", &b);
        assert_eq!(ka, kb);
    }

    #[test]
    fn idempotency_key_differs_per_operation() {
        let id = Uuid::new_v4();
        let payload = serde_json::json!({ "x": 1 });
        let k1 = generate_integration_idempotency_key(id, "op_a", &payload);
        let k2 = generate_integration_idempotency_key(id, "op_b", &payload);
        assert_ne!(k1, k2);
    }

    #[test]
    fn idempotency_key_differs_per_integration() {
        let payload = serde_json::json!({ "x": 1 });
        let k1 = generate_integration_idempotency_key(Uuid::new_v4(), "op", &payload);
        let k2 = generate_integration_idempotency_key(Uuid::new_v4(), "op", &payload);
        assert_ne!(k1, k2);
    }

    #[test]
    fn idempotency_key_is_valid_uuid() {
        let id = Uuid::new_v4();
        let payload = serde_json::json!({ "x": 1 });
        let key = generate_integration_idempotency_key(id, "op", &payload);
        assert!(Uuid::parse_str(&key).is_ok());
    }

    // - connectivity
    #[test]
    fn connectivity_mode_round_trip() {
        for s in ["private_link", "public_internet"] {
            let m = ConnectivityMode::from_str(s).unwrap();
            assert_eq!(m.as_str(), s);
        }
        assert!(ConnectivityMode::from_str("vpn").is_err());
    }

    #[test]
    fn validate_connectivity_public_internet_valid() {
        let cfg = ConnectivityConfig {
            mode: ConnectivityMode::PublicInternet,
            endpoint_url: "https://gateway.example.com/scheme".into(),
            private_link_id: None,
        };
        assert!(validate_connectivity(&cfg).is_ok());
    }

    #[test]
    fn validate_connectivity_private_link_requires_id() {
        let cfg = ConnectivityConfig {
            mode: ConnectivityMode::PrivateLink,
            endpoint_url: "https://internal.gateway.example.com".into(),
            private_link_id: None,
        };
        assert!(validate_connectivity(&cfg).is_err());

        let cfg = ConnectivityConfig {
            mode: ConnectivityMode::PrivateLink,
            endpoint_url: "https://internal.gateway.example.com".into(),
            private_link_id: Some("pl-abc123".into()),
        };
        assert!(validate_connectivity(&cfg).is_ok());
    }

    #[test]
    fn validate_connectivity_rejects_non_https() {
        let cfg = ConnectivityConfig {
            mode: ConnectivityMode::PublicInternet,
            endpoint_url: "ftp://example.com".into(),
            private_link_id: None,
        };
        assert!(validate_connectivity(&cfg).is_err());
    }

    #[test]
    fn validate_connectivity_rejects_malformed() {
        let cfg = ConnectivityConfig {
            mode: ConnectivityMode::PublicInternet,
            endpoint_url: "not a url".into(),
            private_link_id: None,
        };
        assert!(validate_connectivity(&cfg).is_err());
    }

    #[test]
    fn validate_connectivity_rejects_empty() {
        let cfg = ConnectivityConfig {
            mode: ConnectivityMode::PublicInternet,
            endpoint_url: "".into(),
            private_link_id: None,
        };
        assert!(validate_connectivity(&cfg).is_err());
    }
}
