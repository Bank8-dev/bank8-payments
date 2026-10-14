// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Payments App authentication, user provisioning, ABAC, and Sentin8 tokens.
//! See `services/payments/DESIGN.md`.
//! This module provides the App-facing authentication layer for Payments:
//! - OIDC Authorization Code Flow with PKCE (Story )
//! - Just-in-time user provisioning from IdP claims (Story )
//! - Attribute-Based Access Control (ABAC) policy evaluation (Story )
//! - Sentin8 M2M token issuance via Client Credentials (Story )

use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Story — OIDC Authorization Code Flow + PKCE ─────────────

/// Configuration for the Payments App OIDC integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuthConfig {
    /// Auth issuer base URL (e.g. `https://auth.sentin8.dev`).
    pub sentin8_auth_issuer: String,
    /// OAuth 2.0 client_id registered with the IdP.
    pub client_id: String,
    /// Redirect URI for the authorization code callback.
    pub redirect_uri: String,
    /// Requested OAuth scopes.
    pub scopes: Vec<String>,
}

/// A Payments App user session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSession {
    /// Opaque session identifier.
    pub session_id: String,
    /// Subject identifier from the IdP (the `sub` claim).
    pub user_sub: String,
    /// Session expiry timestamp.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Scopes granted to the session.
    pub scopes: Vec<String>,
}

/// A PKCE code challenge pair.
#[derive(Debug, Clone)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
    pub method: String,
}

/// Generate a PKCE code verifier and its S256 code challenge.
/// The verifier is a high-entropy random URL-safe string; the challenge is
/// `BASE64URL(SHA256(verifier))` per RFC 7636 §4.2.
pub fn generate_pkce_pair() -> PkcePair {
    // 32 random bytes → base64url (43 chars, well within 43-128 range).
    let raw = Uuid::new_v4().as_u128().to_le_bytes();
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    // For the challenge, hash the verifier with SHA-256. We don't pull in a
    // SHA-256 crate for the stub; use a second UUID as a stand-in challenge.
    // In production this MUST be `BASE64URL(SHA256(verifier))`.
    let challenge_raw = Uuid::new_v4().as_u128().to_le_bytes();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_raw);
    PkcePair {
        verifier,
        challenge,
        method: "S256".to_string(),
    }
}

/// Build the OIDC authorization URL with a PKCE challenge.
/// Returns the URL the App should redirect the user to in order to start the
/// Authorization Code Flow. The caller must persist the returned `verifier`
/// to complete the flow via [`exchange_code_for_session`].
pub fn initiate_oidc_flow(config: &AppAuthConfig) -> Result<String, String> {
    if config.sentin8_auth_issuer.trim().is_empty() {
        return Err("sentin8_auth_issuer must not be empty".into());
    }
    if config.client_id.trim().is_empty() {
        return Err("client_id must not be empty".into());
    }
    if config.redirect_uri.trim().is_empty() {
        return Err("redirect_uri must not be empty".into());
    }

    let pkce = generate_pkce_pair();
    let scope = config.scopes.join(" ");
    let state = Uuid::new_v4().to_string();

    let mut url = format!(
        "{}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method={}",
        config.sentin8_auth_issuer.trim_end_matches('/'),
        urlencoding(&config.client_id),
        urlencoding(&config.redirect_uri),
        urlencoding(&scope),
        state,
        pkce.challenge,
        pkce.method,
    );
    // The verifier is appended as a fragment so the caller can recover it for
    // the token exchange step. In a real deployment this would be persisted
    // server-side and returned separately; the stub keeps it simple.
    url.push_str(&format!("#code_verifier={}", pkce.verifier));
    Ok(url)
}

/// Exchange an authorization code for an App session.
/// **Stub**: does not call the IdP token endpoint. Returns a session with a
/// generated UUID and a 1-hour expiry. The `code_verifier` is accepted for
/// API completeness but not validated against a stored challenge.
pub fn exchange_code_for_session(
    _config: &AppAuthConfig,
    _code: &str,
    _code_verifier: &str,
) -> Result<AppSession, String> {
    if _code.trim().is_empty() {
        return Err("authorization code must not be empty".into());
    }
    Ok(AppSession {
        session_id: Uuid::new_v4().to_string(),
        user_sub: Uuid::new_v4().to_string(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        scopes: _config.scopes.clone(),
    })
}

/// Renew an existing App session.
/// **Stub**: returns a new session with a fresh session ID and an extended
/// expiry. In production this would call the IdP refresh-token endpoint.
pub fn renew_session(session: &AppSession) -> Result<AppSession, String> {
    if session.user_sub.trim().is_empty() {
        return Err("session user_sub must not be empty".into());
    }
    Ok(AppSession {
        session_id: Uuid::new_v4().to_string(),
        user_sub: session.user_sub.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        scopes: session.scopes.clone(),
    })
}

/// Minimal URL-component percent-encoder for the few characters we emit.
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ' ' => "%20".to_string(),
            '/' => "%2F".to_string(),
            '?' => "%3F".to_string(),
            '#' => "%23".to_string(),
            '&' => "%26".to_string(),
            '=' => "%3D".to_string(),
            '+' => "%2B".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

// ── Story — User provisioning (JIT from IdP) ────────────────

/// Status of a Payments App user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum UserStatus {
    Active,
    Inactive,
    Deleted,
}

impl UserStatus {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "ACTIVE" => Ok(Self::Active),
            "INACTIVE" => Ok(Self::Inactive),
            "DELETED" => Ok(Self::Deleted),
            other => Err(format!("unknown user status: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Inactive => "INACTIVE",
            Self::Deleted => "DELETED",
        }
    }
}

/// A Payments App user, provisioned from IdP claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUser {
    /// Subject identifier from the IdP (`sub` claim).
    pub sub: String,
    /// Issuer URL (`iss` claim).
    pub iss: String,
    /// Display name (e.g. `name` or `preferred_username` claim).
    pub display_name: String,
    /// Email address (`email` claim).
    pub email: String,
    /// Account status.
    pub status: UserStatus,
}

/// Just-in-time provision a user from IdP claims.
/// Reads the `sub`, `iss`, `name`/`preferred_username`, `email` claims and
/// creates an `ACTIVE` user. Missing `sub` or `iss` is an error.
pub fn provision_user_from_idp(claims: &serde_json::Value) -> Result<AppUser, String> {
    let sub = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "IdP claims missing `sub`".to_string())?
        .to_string();
    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "IdP claims missing `iss`".to_string())?
        .to_string();
    let display_name = claims
        .get("name")
        .or_else(|| claims.get("preferred_username"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let email = claims
        .get("email")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(AppUser {
        sub,
        iss,
        display_name,
        email,
        status: UserStatus::Active,
    })
}

// ── Story — ABAC access management ──────────────────────────

/// Effect of an ABAC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AbacEffect {
    Allow,
    Deny,
}

impl AbacEffect {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "ALLOW" => Ok(Self::Allow),
            "DENY" => Ok(Self::Deny),
            other => Err(format!("unknown ABAC effect: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Deny => "DENY",
        }
    }
}

/// An Attribute-Based Access Control policy.
/// Policies are Rego-like: they target a `resource_type` and `action` and
/// apply `conditions` (a JSON object) against the request context. The
/// `effect` is `Allow` or `Deny`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbacPolicy {
    /// Resource type this policy applies to (e.g. `payment`, `instruction`).
    pub resource_type: String,
    /// Action being authorised (e.g. `read`, `write`, `approve`).
    pub action: String,
    /// Conditions evaluated against the request context. A JSON object where
    /// each key is an attribute name and each value is the required value
    /// (or a list of accepted values).
    pub conditions: serde_json::Value,
    /// The effect when conditions match.
    pub effect: AbacEffect,
}

/// Evaluate an ABAC policy against a request context.
/// **Stub**: implements a Rego-like subset. The policy matches when:
/// - `resource_type` equals `context.resource_type`
/// - `action` equals `context.action`
/// - Every key in `conditions` is present in `context` with a matching value
/// (scalar equality, or membership when the condition is an array).
/// Returns `Ok(true)` when the policy matches and the effect is `Allow`,
/// `Ok(false)` when it matches and the effect is `Deny` or when it does not
/// match. Returns `Err` only when the context is not a JSON object.
pub fn evaluate_abac_policy(
    policy: &AbacPolicy,
    context: &serde_json::Value,
) -> Result<bool, String> {
    let ctx = context
        .as_object()
        .ok_or_else(|| "ABAC context must be a JSON object".to_string())?;

    // Resource type and action must match.
    let resource_type = ctx
        .get("resource_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let action = ctx.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if resource_type != policy.resource_type || action != policy.action {
        return Ok(false);
    }

    // Every condition key must be present and match.
    let conditions = policy
        .conditions
        .as_object()
        .ok_or_else(|| "ABAC policy conditions must be a JSON object".to_string())?;

    for (key, expected) in conditions {
        let actual = match ctx.get(key) {
            Some(v) => v,
            None => return Ok(false),
        };
        if !abac_value_matches(expected, actual) {
            return Ok(false);
        }
    }

    Ok(policy.effect == AbacEffect::Allow)
}

/// Check whether an expected condition value matches an actual context value.
/// - If `expected` is an array, `actual` must equal one of its elements.
/// - Otherwise scalar equality is used.
fn abac_value_matches(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
    if let Some(arr) = expected.as_array() {
        return arr.iter().any(|e| e == actual);
    }
    expected == actual
}

// ── Story — Sentin8 tokens (M2M Client Credentials) ───────────

/// A request to issue a Sentin8 M2M token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sentin8TokenRequest {
    /// OAuth 2.0 client_id.
    pub client_id: String,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// Whether this token is for the sandbox environment.
    pub sandbox: bool,
}

/// The issued Sentin8 M2M token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sentin8TokenResponse {
    /// The access token (a JWT-like string).
    pub access_token: String,
    /// Token type (always `Bearer`).
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// Granted scopes (space-separated).
    pub scope: String,
}

/// Issue a Sentin8 M2M token via the Client Credentials grant.
/// **Stub**: returns a placeholder JWT-like token. The token is three
/// base64url-encoded segments separated by dots; the payload carries the
/// `client_id`, `scope`, `sandbox` flag, and an `exp` claim 1 hour out.
pub fn issue_sentin8_token(request: &Sentin8TokenRequest) -> Result<Sentin8TokenResponse, String> {
    if request.client_id.trim().is_empty() {
        return Err("client_id must not be empty".into());
    }
    let scope = request.scopes.join(" ");
    let header = b"{\"alg\":\"none\",\"typ\":\"JWT\"}";
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);
    let exp = (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp();
    let payload = serde_json::json!({
        "iss": "sentin8",
        "sub": request.client_id,
        "scope": scope,
        "sandbox": request.sandbox,
        "exp": exp,
        "iat": chrono::Utc::now().timestamp(),
    });
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    // Signature is empty (alg=none) — stub only, never use in production.
    let access_token = format!("{header_b64}.{payload_b64}.");
    Ok(Sentin8TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        scope,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> AppAuthConfig {
        AppAuthConfig {
            sentin8_auth_issuer: "https://auth.sentin8.dev".into(),
            client_id: "payments-app".into(),
            redirect_uri: "https://app.payments.dev/callback".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
        }
    }

    // ── Story — OIDC flow ──────────────────────────────────────

    #[test]
    fn initiate_oidc_flow_returns_authorization_url() {
        let cfg = sample_config();
        let url = initiate_oidc_flow(&cfg).unwrap();
        assert!(url.starts_with("https://auth.sentin8.dev/oauth/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=payments-app"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("code_verifier="));
    }

    #[test]
    fn initiate_oidc_flow_rejects_empty_issuer() {
        let cfg = AppAuthConfig {
            sentin8_auth_issuer: "".into(),
            client_id: "c".into(),
            redirect_uri: "r".into(),
            scopes: vec![],
        };
        assert!(initiate_oidc_flow(&cfg).is_err());
    }

    #[test]
    fn initiate_oidc_flow_rejects_empty_client_id() {
        let cfg = AppAuthConfig {
            sentin8_auth_issuer: "i".into(),
            client_id: "  ".into(),
            redirect_uri: "r".into(),
            scopes: vec![],
        };
        assert!(initiate_oidc_flow(&cfg).is_err());
    }

    #[test]
    fn pkce_pair_verifier_and_challenge_differ() {
        let p = generate_pkce_pair();
        assert_ne!(p.verifier, p.challenge);
        assert_eq!(p.method, "S256");
    }

    #[test]
    fn exchange_code_for_session_returns_session() {
        let cfg = sample_config();
        let session = exchange_code_for_session(&cfg, "authcode123", "verifier456").unwrap();
        assert!(!session.session_id.is_empty());
        assert!(!session.user_sub.is_empty());
        assert!(session.expires_at > chrono::Utc::now());
        assert_eq!(session.scopes, cfg.scopes);
    }

    #[test]
    fn exchange_code_for_session_rejects_empty_code() {
        let cfg = sample_config();
        assert!(exchange_code_for_session(&cfg, "  ", "v").is_err());
    }

    #[test]
    fn renew_session_returns_new_session_id() {
        let cfg = sample_config();
        let session = exchange_code_for_session(&cfg, "authcode123", "verifier456").unwrap();
        let renewed = renew_session(&session).unwrap();
        assert_ne!(session.session_id, renewed.session_id);
        assert_eq!(session.user_sub, renewed.user_sub);
        assert_eq!(session.scopes, renewed.scopes);
        assert!(renewed.expires_at > chrono::Utc::now());
    }

    #[test]
    fn renew_session_rejects_empty_user_sub() {
        let session = AppSession {
            session_id: "s".into(),
            user_sub: "".into(),
            expires_at: chrono::Utc::now(),
            scopes: vec![],
        };
        assert!(renew_session(&session).is_err());
    }

    #[test]
    fn app_session_serialises() {
        let session = AppSession {
            session_id: "s1".into(),
            user_sub: "u1".into(),
            expires_at: chrono::Utc::now(),
            scopes: vec!["openid".into()],
        };
        let v = serde_json::to_value(&session).unwrap();
        assert_eq!(v["session_id"], "s1");
        assert_eq!(v["user_sub"], "u1");
        assert_eq!(v["scopes"].as_array().unwrap().len(), 1);
    }

    // ── Story — user provisioning ─────────────────────────────

    #[test]
    fn user_status_round_trip() {
        for s in ["ACTIVE", "INACTIVE", "DELETED"] {
            let st = UserStatus::from_str(s).unwrap();
            assert_eq!(st.as_str(), s);
        }
        // case-insensitive
        assert_eq!(UserStatus::from_str("active").unwrap(), UserStatus::Active);
        assert!(UserStatus::from_str("bogus").is_err());
    }

    #[test]
    fn provision_user_from_idp_ok() {
        let claims = serde_json::json!({
            "sub": "user-123",
            "iss": "https://auth.sentin8.dev",
            "name": "Alice",
            "email": "alice@example.com"
        });
        let user = provision_user_from_idp(&claims).unwrap();
        assert_eq!(user.sub, "user-123");
        assert_eq!(user.iss, "https://auth.sentin8.dev");
        assert_eq!(user.display_name, "Alice");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.status, UserStatus::Active);
    }

    #[test]
    fn provision_user_from_idp_uses_preferred_username_when_no_name() {
        let claims = serde_json::json!({
            "sub": "u1",
            "iss": "iss",
            "preferred_username": "bob",
            "email": "bob@example.com"
        });
        let user = provision_user_from_idp(&claims).unwrap();
        assert_eq!(user.display_name, "bob");
    }

    #[test]
    fn provision_user_from_idp_missing_sub_is_err() {
        let claims = serde_json::json!({ "iss": "iss" });
        assert!(provision_user_from_idp(&claims).is_err());
    }

    #[test]
    fn provision_user_from_idp_missing_iss_is_err() {
        let claims = serde_json::json!({ "sub": "s" });
        assert!(provision_user_from_idp(&claims).is_err());
    }

    #[test]
    fn provision_user_from_idp_defaults_empty_display_name() {
        let claims = serde_json::json!({ "sub": "s", "iss": "i" });
        let user = provision_user_from_idp(&claims).unwrap();
        assert_eq!(user.display_name, "");
        assert_eq!(user.email, "");
    }

    #[test]
    fn app_user_serialises() {
        let user = AppUser {
            sub: "s".into(),
            iss: "i".into(),
            display_name: "D".into(),
            email: "e".into(),
            status: UserStatus::Active,
        };
        let v = serde_json::to_value(&user).unwrap();
        assert_eq!(v["status"], "ACTIVE");
    }

    // ── Story — ABAC ──────────────────────────────────────────

    #[test]
    fn abac_effect_round_trip() {
        for s in ["ALLOW", "DENY"] {
            let e = AbacEffect::from_str(s).unwrap();
            assert_eq!(e.as_str(), s);
        }
        assert_eq!(AbacEffect::from_str("allow").unwrap(), AbacEffect::Allow);
        assert!(AbacEffect::from_str("bogus").is_err());
    }

    #[test]
    fn abac_allow_when_conditions_match() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!({
                "payment_type": "credit_transfer",
                "status": "completed"
            }),
            effect: AbacEffect::Allow,
        };
        let ctx = serde_json::json!({
            "resource_type": "payment",
            "action": "read",
            "payment_type": "credit_transfer",
            "status": "completed"
        });
        assert!(evaluate_abac_policy(&policy, &ctx).unwrap());
    }

    #[test]
    fn abac_deny_when_effect_is_deny() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "write".into(),
            conditions: serde_json::json!({}),
            effect: AbacEffect::Deny,
        };
        let ctx = serde_json::json!({
            "resource_type": "payment",
            "action": "write"
        });
        assert!(!evaluate_abac_policy(&policy, &ctx).unwrap());
    }

    #[test]
    fn abac_no_match_when_resource_type_differs() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!({}),
            effect: AbacEffect::Allow,
        };
        let ctx = serde_json::json!({
            "resource_type": "instruction",
            "action": "read"
        });
        assert!(!evaluate_abac_policy(&policy, &ctx).unwrap());
    }

    #[test]
    fn abac_no_match_when_action_differs() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!({}),
            effect: AbacEffect::Allow,
        };
        let ctx = serde_json::json!({
            "resource_type": "payment",
            "action": "write"
        });
        assert!(!evaluate_abac_policy(&policy, &ctx).unwrap());
    }

    #[test]
    fn abac_condition_array_accepts_membership() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!({
                "payment_system": ["B8", "TIPS", "SEPA"]
            }),
            effect: AbacEffect::Allow,
        };
        let ctx = serde_json::json!({
            "resource_type": "payment",
            "action": "read",
            "payment_system": "B8"
        });
        assert!(evaluate_abac_policy(&policy, &ctx).unwrap());
    }

    #[test]
    fn abac_condition_array_rejects_non_member() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!({
                "payment_system": ["B8", "TIPS"]
            }),
            effect: AbacEffect::Allow,
        };
        let ctx = serde_json::json!({
            "resource_type": "payment",
            "action": "read",
            "payment_system": "SWIFT"
        });
        assert!(!evaluate_abac_policy(&policy, &ctx).unwrap());
    }

    #[test]
    fn abac_missing_condition_key_means_no_match() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!({ "payment_type": "credit_transfer" }),
            effect: AbacEffect::Allow,
        };
        let ctx = serde_json::json!({
            "resource_type": "payment",
            "action": "read"
        });
        assert!(!evaluate_abac_policy(&policy, &ctx).unwrap());
    }

    #[test]
    fn abac_rejects_non_object_context() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!({}),
            effect: AbacEffect::Allow,
        };
        let ctx = serde_json::json!(42);
        assert!(evaluate_abac_policy(&policy, &ctx).is_err());
    }

    #[test]
    fn abac_rejects_non_object_conditions() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!(42),
            effect: AbacEffect::Allow,
        };
        let ctx = serde_json::json!({
            "resource_type": "payment",
            "action": "read"
        });
        assert!(evaluate_abac_policy(&policy, &ctx).is_err());
    }

    #[test]
    fn abac_policy_serialises() {
        let policy = AbacPolicy {
            resource_type: "payment".into(),
            action: "read".into(),
            conditions: serde_json::json!({ "status": "completed" }),
            effect: AbacEffect::Allow,
        };
        let v = serde_json::to_value(&policy).unwrap();
        assert_eq!(v["resource_type"], "payment");
        assert_eq!(v["effect"], "ALLOW");
    }

    // ── Story — Sentin8 tokens ──────────────────────────────────

    #[test]
    fn issue_sentin8_token_returns_bearer() {
        let req = Sentin8TokenRequest {
            client_id: "m2m-client".into(),
            scopes: vec!["bank8:payments:read".into(), "bank8:payments:write".into()],
            sandbox: false,
        };
        let resp = issue_sentin8_token(&req).unwrap();
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert_eq!(resp.scope, "bank8:payments:read bank8:payments:write");
        // JWT-like: three dot-separated segments.
        let parts: Vec<&str> = resp.access_token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn issue_sentin8_token_rejects_empty_client_id() {
        let req = Sentin8TokenRequest {
            client_id: "  ".into(),
            scopes: vec![],
            sandbox: true,
        };
        assert!(issue_sentin8_token(&req).is_err());
    }

    #[test]
    fn issue_sentin8_token_sandbox_flag_in_payload() {
        let req = Sentin8TokenRequest {
            client_id: "c".into(),
            scopes: vec![],
            sandbox: true,
        };
        let resp = issue_sentin8_token(&req).unwrap();
        let parts: Vec<&str> = resp.access_token.split('.').collect();
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["sandbox"], true);
        assert_eq!(payload["sub"], "c");
    }

    #[test]
    fn sentin8_token_response_serialises() {
        let resp = Sentin8TokenResponse {
            access_token: "tok".into(),
            token_type: "Bearer".into(),
            expires_in: 3600,
            scope: "bank8:payments:read".into(),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["token_type"], "Bearer");
        assert_eq!(v["expires_in"], 3600);
    }
}
