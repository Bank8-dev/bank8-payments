// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for Payments.
//! Re-exports the shared types from the sentin8-auth-client SDK and
//! provides thin wrappers that match the original Payments call sites
//! (taking `&PaymentsConfig` + `&HeaderMap`).
//!  : step 5 is the ONLY gate (policy design §4.3). The
//! `require_scope`/`require_any_scope` helpers are gone — handlers verify
//! the token (steps 1–4) with [`verify_token`], then evaluate a
//! `bank8:payments:<resource>:<action>` Shield action via
//! `crate::policy::require`. Feature gates stay an availability check
//! (503 before authorization); they never authorize.

use axum::http::{HeaderMap, StatusCode};

use crate::config::{FeatureGate, PaymentsConfig};

pub use sentin8::auth::client::AuthContext;

/// Verify the Bearer token and return the auth context (steps 1–4: identity
/// + signature + expiry + tenant). NO scope check — step 5
/// (`crate::policy::require`) is the authorization decision.
pub async fn verify_token(
    config: &PaymentsConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token(&config.sentin8_auth_client, headers).await
}

/// Feature-gate check ONLY (availability, not authorization): returns 503
/// when the gate is disabled. Pair with `crate::policy::require` (step 5)
/// in the handler — the gate never substitutes for the policy decision.
pub fn require_feature(
    config: &PaymentsConfig,
    gate: FeatureGate,
) -> Result<(), (StatusCode, String)> {
    if !config.features.is_enabled(gate) {
        return Err((StatusCode::SERVICE_UNAVAILABLE, format!("feature gate {:?} is disabled", gate)));
    }
    Ok(())
}
