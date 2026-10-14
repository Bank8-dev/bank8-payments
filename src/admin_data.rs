// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Admin data endpoints (RFW data-plane, design §5.8).
//! Every `data_endpoint` advertised in `registration.rs` gets a GET handler
//! here so Sentin8:Dash never 404s. The RFW renderer only supports POST, so
//! form-submit pages additionally get a POST alias that forwards to the
//! matching public handler. All routes go through the standard authorization
//! pipeline and set tenant context before querying.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use sqlx::Row;
use uuid::Uuid;

use crate::handlers::{err_db, set_tenant_context, AppState};

/// Shared admin data-plane authorization: any payments read scope.
async fn require_admin_reader(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::auth::AuthContext, (StatusCode, String)> {
    // Step 5 — Shield decides (principles §5.2, policy design §4.3). The
    // admin data reads evaluate the read action; the scope-mirror set
    // permits it per-scope, and the read scopes above all mirror as
    // permits for `bank8:payments:payments:read`-style read actions.
    let a = crate::auth::verify_token(&state.config, headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payments:read"),
    )
    .await?;
    Ok(a)
}

/// `GET /v1/admin/overview` — counts for the overview dashboard.
pub async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = require_admin_reader(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let instructions_total: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM instructions")
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let payments_total: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM payments")
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "instructions_total": instructions_total,
        "payments_total": payments_total,
    })))
}

/// `GET /v1/admin/instructions` — recent instructions (admin view).
pub async fn list_instructions_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = require_admin_reader(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, state, correlation_id, created_at
             FROM instructions ORDER BY created_at DESC LIMIT 50"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<Uuid, _>("id"),
                "state": r.get::<String, _>("state"),
                "correlation_id": r.get::<Option<String>, _>("correlation_id"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

/// `GET /v1/admin/payments` — recent payments (admin view).
pub async fn list_payments_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = require_admin_reader(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, payment_type, amount, currency, status, created_at
             FROM payments ORDER BY created_at DESC LIMIT 50"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.get::<Uuid, _>("id"),
                "payment_type": r.get::<String, _>("payment_type"),
                "amount": r.get::<rust_decimal::Decimal, _>("amount"),
                "currency": r.get::<String, _>("currency"),
                "status": r.get::<String, _>("status"),
                "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "items": items })))
}

/// Generic bounded-list helper for the remaining admin resources.
macro_rules! admin_list {
    ($fn_name:ident, $table:expr, $cols:expr) => {
        pub async fn $fn_name(
            State(state): State<AppState>,
            headers: HeaderMap,
        ) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
            let a = require_admin_reader(&state, &headers).await?;
            let mut conn = state.pool.acquire().await.map_err(err_db)?;
            set_tenant_context(&mut conn, a.env_id()).await;
            let sql = format!("SELECT {} FROM {} ORDER BY created_at DESC LIMIT 50", $cols, $table);
            let rows = sqlx::query(&sql).fetch_all(&mut *conn).await.map_err(err_db)?;
            let items: Vec<serde_json::Value> = rows.iter().map(|r| {
                let mut obj = serde_json::Map::new();
                for col in $cols.split(", ") {
                    let name = col.split_whitespace().last().unwrap_or(col);
                    let v: Option<serde_json::Value> = r
                        .try_get::<Option<serde_json::Value>, _>(name)
                        .or_else(|_| r.try_get::<Option<String>, _>(name).map(|s| s.map(serde_json::Value::String)))
                        .unwrap_or(None);
                    if let Some(v) = v {
                        obj.insert(name.to_string(), v);
                    }
                }
                serde_json::Value::Object(obj)
            }).collect();
            Ok(Json(serde_json::json!({ "items": items })))
        }
    };
}

admin_list!(list_rules_admin, "rules", "id, name, status");
admin_list!(list_cards_admin, "cards", "id, status, card_type");
admin_list!(list_files_admin, "files", "id, filename, status");
admin_list!(list_integrations_admin, "integrations", "id, name, status");
admin_list!(list_parameters_admin, "parameters", "id, name, status");
admin_list!(list_cores_admin, "cores", "id, name");
admin_list!(list_mandates_admin, "mandates", "id, status, currency");
admin_list!(
    list_directories_admin,
    "membership_directories",
    "id, name, status"
);
admin_list!(list_calendars_admin, "calendars", "id, name, timezone");
admin_list!(
    list_decisions_admin,
    "manual_decisions",
    "id, status, decision_type"
);

/// `GET /v1/admin/settings` — service settings view.
pub async fn get_settings_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = require_admin_reader(&state, &headers).await?;
    Ok(Json(serde_json::json!({
        "service": "bank8:payments",
        "features": {
            "instructions_sync": state.config.features.instructions_sync,
            "instructions_async": state.config.features.instructions_async,
            "cards": state.config.features.cards,
            "cards_encrypted": state.config.features.cards_encrypted,
            "files": state.config.features.files,
            "mandates": state.config.features.mandates,
            "recurring": state.config.features.recurring,
            "manual_decisions": state.config.features.manual_decisions,
            "tasks": state.config.features.tasks,
            "templates": state.config.features.templates,
            "dashboards": state.config.features.dashboards,
            "membership_directories": state.config.features.membership_directories,
            "calendars": state.config.features.calendars,
            "sandbox": state.config.features.sandbox,
        },
    })))
}

/// `GET /v1/admin/simulator` — simulator availability (sandbox gate).
pub async fn get_simulator_admin(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let _a = require_admin_reader(&state, &headers).await?;
    let enabled = state.config.features.sandbox;
    Ok(Json(serde_json::json!({
        "simulator": { "enabled": enabled },
    })))
}
