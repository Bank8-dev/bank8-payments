// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Payments HTTP handlers — instructions, payments, logics, proxy-back.
//! .59 (P0 subset).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::config::PaymentsConfig;
use crate::event_streaming::{self, ResourceType};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<PaymentsConfig>,
    pub pool: sqlx::PgPool,
    /// Shield policy engine : step 5 is the ONLY gate
    /// handlers verify the token (steps 1–4) then evaluate a
    /// `bank8:payments:<resource>:<action>` target; no JWT scope check remains.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface (§3.6) — same engine
    /// instance the request path evaluates.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

pub(crate) async fn set_tenant_context(conn: &mut sqlx::PgConnection, env_id: Uuid) {
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, 'payments')")
        .bind(env_id).execute(conn).await;
}

/// Extract the caller's bearer token (compact serialization) from request
/// headers for the inbox `publisher_id_token` column . Returns
/// `None` when no Authorization header is present.
pub(crate) fn bearer_token_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string)
}

/// Extended tenant context — passes admin flags +
/// Auth user id for holder-scoped RLS on `cardholders`.
pub(crate) async fn set_tenant_context_ext(
    conn: &mut sqlx::PgConnection,
    auth: &crate::auth::AuthContext,
) {
    let _ = sqlx::query(
        "SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5, false, $6, $7, 'payments')",
    )
    .bind(auth.env_id())
    .bind(&auth.claims.sub)
    .bind(&auth.claims.token_tp)
    .bind(&auth.claims.scope)
    .bind(auth.is_platform_admin())
    .bind(auth.claims.is_env_admin())
    .bind(auth.claims.sentin8_auth_user_uuid())
    .execute(conn)
    .await;
}

/// Resolve the caller's `ledger.customers` id for holder callers (§4.3c).
/// Returns `None` for tokens carrying `holder:view-all` (staff/M2M). Used to
/// force `customer_id` in cardholder queries (service-layer
/// defence-in-depth for holder-scoped RLS, §4.3c). The read crosses
/// service schemas — the single declared grant in this service's
/// registration (`payments.cardholders` holder binding reads
/// `ledger.customers` by id, SELECT-only).
async fn resolve_caller_customer_id(
    conn: &mut sqlx::PgConnection,
    auth: &crate::auth::AuthContext,
) -> Option<Uuid> {
    if !auth.is_holder() {
        return None;
    }
    let user_id = auth.claims.sentin8_auth_user_uuid()?;
    // Cross-service read, schema-qualified: the declared cross_schema_grant
    // gives bank8_payments_service SELECT on ledger.customers (SCHEMA-1 —
    // schema-per-service, unprefixed table names). Never unqualified: with
    // search_path `{leaf}, public` an unqualified customers would not resolve.
    sqlx::query_scalar("SELECT id FROM ledger.customers WHERE sentin8_auth_user_id = $1 LIMIT 1")
        .bind(user_id)
        .fetch_optional(conn)
        .await
        .ok()
        .flatten()
}

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct InstructionResponse {
    pub id: Uuid,
    pub instruction_logic_id: Option<Uuid>,
    pub state: String,
    pub correlation_id: Option<String>,
    pub input: serde_json::Value,
    pub output: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// `POST /v1/instructions` body.
/// Note: `logic` is an optional inline `sentin8_flow_sdk::client::LogicVersion`
/// (external type, not included in the OpenAPI schema).
#[derive(Debug, Deserialize)]
pub struct CreateInstructionRequest {
    pub instruction_logic_id: Option<Uuid>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    pub input: serde_json::Value,
    /// Optional inline logic (if not using a stored logic by ID).
    #[serde(default)]
    pub logic: Option<sentin8_flow_sdk::client::LogicVersion>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentResponse {
    pub id: Uuid,
    pub instruction_id: Option<Uuid>,
    pub payment_type: String,
    pub amount: rust_decimal::Decimal,
    pub currency: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LogicResponse {
    pub id: Uuid,
    pub name: String,
    pub version: i32,
    pub steps: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLogicRequest {
    pub name: String,
    pub steps: serde_json::Value,
}

// ── Instruction API ──────────────────────────────────────────────────────

/// `POST /v1/instructions` — create and initiate an instruction.
/// Delegates workflow execution to Flow.
#[utoipa::path(
    post,
    path = "/v1/instructions",
    responses(
        (status = 200, description = "Instruction created", body = InstructionResponse),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn create_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateInstructionRequest>,
) -> Result<Json<InstructionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::InstructionsSync)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;

    // Idempotency check. If an explicit key is not provided, derive one from
    // the input payload using UUIDv5 (Story ).
    let idempotency_key = req
        .idempotency_key
        .clone()
        .unwrap_or_else(|| crate::idempotency::derive_from_payload(&req.input).to_string());

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM instructions WHERE idempotency_key = $1 AND env_id = $2",
    )
    .bind(&idempotency_key)
    .bind(a.env_id())
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?;
    if let Some(id) = existing {
        let row = sqlx::query(
            r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at
                 FROM instructions WHERE id = $1"#,
        ).bind(id).fetch_one(&mut *tx).await.map_err(err_db)?;
        tx.commit().await.map_err(err_db)?;
        return Ok(Json(row_to_instruction(&row)));
    }

    let row = sqlx::query(
        r#"INSERT INTO instructions (env_id, instruction_logic_id, state, idempotency_key, correlation_id, input)
           VALUES ($1, $2, 'pending', $3, $4, $5)
           RETURNING id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at"#,
    )
    .bind(a.env_id())
    .bind(req.instruction_logic_id)
    .bind(&idempotency_key)
    .bind(&req.correlation_id)
    .bind(&req.input)
    .fetch_one(&mut *tx).await.map_err(err_db)?;

    let instruction_id: Uuid = row.get("id");

    // Inbox-first: the event rides the same transaction as the
    // INSERT — a crash after commit cannot lose it. Publisher identity
    // carries the caller's bearer token + subject for subscriber-side
    // delegation.
    let _ = event_streaming::emit_event_tx(
        &mut *tx,
        a.env_id(),
        ResourceType::Instruction,
        &instruction_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    tx.commit().await.map_err(err_db)?;

    // Story — match or create payment for this instruction.
    let _payment_id = crate::payment_matching::match_or_create_payment(
        &state.pool,
        a.env_id(),
        instruction_id,
        req.correlation_id.as_deref(),
        &req.input,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // Story — interruption mode for urgent instructions.
    if crate::interruption::should_interrupt(&req.input) {
        let _ =
            crate::interruption::interrupt_pending(&state.pool, _payment_id, instruction_id).await;
    }

    // Delegate to Flow if inline logic provided.
    if let Some(logic) = req.logic {
        let client = match state.config.flow_http() {
            Some(http) => sentin8_flow_sdk::client::FlowClient::from_transport(
                &state.config.sentin8_flow_url,
                sentin8::middleware::http_client::Sentin8HttpClient::from_client(http.clone()),
            ),
            None => sentin8_flow_sdk::client::FlowClient::new_dev_plain(
                state.config.sentin8_flow_url.clone(),
            ),
        };
        let callback = sentin8_flow_sdk::client::CallbackConfig {
            base_url: format!("http://localhost:{}", state.config.port),
            auth_token: state.config.sentin8_flow_token.clone(),
            internal_path: "/v1/internal/steps".into(),
            host_functions: std::collections::HashMap::new(),
        };
        let sentin8_flow_req = sentin8_flow_sdk::client::CreateWorkflowRequest {
            domain: "payments".into(),
            logic,
            input: req.input.clone(),
            callback_config: callback,
            correlation_id: req.correlation_id.clone(),
        };
        let _ = client.create_workflow(&sentin8_flow_req).await;
    }

    let row = sqlx::query(
        r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at
             FROM instructions WHERE id = $1"#,
    )
    .bind(instruction_id)
    .fetch_one(&state.pool)
    .await.map_err(err_db)?;

    Ok(Json(row_to_instruction(&row)))
}

/// `GET /v1/instructions` — list instructions.
#[utoipa::path(
    get,
    path = "/v1/instructions",
    params(("state" = Option<String>, Query, description = "Filter by instruction state")),
    responses(
        (status = 200, description = "List of instructions", body = Vec<InstructionResponse>),
        (status = 403, description = "Missing bank8:payments:instructions:read scope"),
    ),
    security(("bank8:payments:instructions:read" = [])),
    tag = "payments",
)]
pub async fn list_instructions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListInstructionsQuery>,
) -> Result<Json<Vec<InstructionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at
             FROM instructions
            WHERE ($1::text IS NULL OR state = $1)
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .bind(q.state.as_deref())
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_instruction).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListInstructionsQuery {
    #[serde(default)]
    pub state: Option<String>,
}

/// `GET /v1/instructions/{id}` — instruction detail.
#[utoipa::path(
    get,
    path = "/v1/instructions/{id}",
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction detail", body = InstructionResponse),
        (status = 404, description = "Instruction not found"),
        (status = 403, description = "Missing bank8:payments:instructions:read scope"),
    ),
    security(("bank8:payments:instructions:read" = [])),
    tag = "payments",
)]
pub async fn get_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<InstructionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at
             FROM instructions WHERE id = $1"#,
    )
    .bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(row_to_instruction(&row)))
}

/// `POST /v1/instructions/{id}/retry` — failed → pending (Story ).
#[utoipa::path(
    post,
    path = "/v1/instructions/{id}/retry",
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction retried", body = InstructionResponse),
        (status = 409, description = "State transition conflict"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn retry_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<InstructionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    crate::state_machine::transition(
        &state.pool,
        id,
        crate::state_machine::InstructionState::Pending,
    )
    .await
    .map_err(|e| (StatusCode::CONFLICT, e))?;

    let row = sqlx::query(
        r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at
             FROM instructions WHERE id = $1"#,
    )
    .bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Instruction,
        &id.to_string(),
        "retried",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_instruction(&row)))
}

/// `POST /v1/instructions/{id}/cancel` — any state → cancelled (Story ).
#[utoipa::path(
    post,
    path = "/v1/instructions/{id}/cancel",
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction cancelled", body = InstructionResponse),
        (status = 409, description = "State transition conflict"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn cancel_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<InstructionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    crate::state_machine::transition_with_audit(
        &state.pool,
        id,
        crate::state_machine::InstructionState::Cancelled,
        Some(&a.subject()),
        Some("manual cancellation"),
    )
    .await
    .map_err(|e| (StatusCode::CONFLICT, e))?;

    let row = sqlx::query(
        r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at
             FROM instructions WHERE id = $1"#,
    )
    .bind(id).fetch_one(&mut *conn).await.map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Instruction,
        &id.to_string(),
        "cancelled",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_instruction(&row)))
}

// ── Payment API ──────────────────────────────────────────────────────────

/// `GET /v1/payments` — list payments.
#[utoipa::path(
    get,
    path = "/v1/payments",
    responses(
        (status = 200, description = "List of payments", body = Vec<PaymentResponse>),
        (status = 403, description = "Missing bank8:payments:payments:read scope"),
    ),
    security(("bank8:payments:payments:read" = [])),
    tag = "payments",
)]
pub async fn list_payments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PaymentResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payments:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, instruction_id, payment_type, amount, currency, status, created_at
             FROM payments ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_payment).collect()))
}

/// `GET /v1/payments/{id}` — payment detail.
#[utoipa::path(
    get,
    path = "/v1/payments/{id}",
    params(("id" = Uuid, Path, description = "Payment ID")),
    responses(
        (status = 200, description = "Payment detail", body = PaymentResponse),
        (status = 404, description = "Payment not found"),
        (status = 403, description = "Missing bank8:payments:payments:read scope"),
    ),
    security(("bank8:payments:payments:read" = [])),
    tag = "payments",
)]
pub async fn get_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PaymentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payments:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, instruction_id, payment_type, amount, currency, status, created_at
             FROM payments WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(row_to_payment(&row)))
}

// ── Logic API ────────────────────────────────────────────────────────────

/// `POST /v1/logics` — create a logic.
#[utoipa::path(
    post,
    path = "/v1/logics",
    request_body = CreateLogicRequest,
    responses(
        (status = 200, description = "Logic created", body = LogicResponse),
        (status = 403, description = "Missing bank8:payments:logics:write scope"),
    ),
    security(("bank8:payments:logics:write" = [])),
    tag = "payments",
)]
pub async fn create_logic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateLogicRequest>,
) -> Result<Json<LogicResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:logics:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO logics (env_id, name, steps, status)
           VALUES ($1, $2, $3, 'active')
           RETURNING id, name, version, steps, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(&req.steps)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let logic_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::InstructionLogic,
        &logic_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_logic(&row)))
}

/// `GET /v1/logics` — list logics.
#[utoipa::path(
    get,
    path = "/v1/logics",
    responses(
        (status = 200, description = "List of logics", body = Vec<LogicResponse>),
        (status = 403, description = "Missing bank8:payments:logics:read scope"),
    ),
    security(("bank8:payments:logics:read" = [])),
    tag = "payments",
)]
pub async fn list_logics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<LogicResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:logics:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, name, version, steps, status, created_at FROM logics ORDER BY created_at DESC"#,
    )
    .fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_logic).collect()))
}

// ── Routing: Payment Instruments (Story ) ──────────────────────

/// `POST /v1/payment-instruments` — create a payment instrument.
pub async fn create_payment_instrument(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::routing::CreatePaymentInstrumentRequest>,
) -> Result<Json<crate::routing::PaymentInstrumentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payment-instruments:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // Story — enforce uniqueness of active instruments.
    let existing: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM payment_instruments
            WHERE env_id = $1
              AND bank_identifier = $2 AND instrument_identifier = $3
              AND status = 'active'"#,
    )
    .bind(a.env_id())
    .bind(&req.bank_identifier)
    .bind(&req.instrument_identifier)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    if let Some(id) = existing {
        return Err((
            StatusCode::CONFLICT,
            format!("active payment instrument already exists: {id}"),
        ));
    }

    let row = sqlx::query(
        r#"INSERT INTO payment_instruments
               (env_id, account_id, bank_identifier,
                instrument_identifier, status, display_name, routing_information)
           VALUES ($1, $2, $3, $4, 'active', $5, $6)
           RETURNING id, account_id, bank_identifier, instrument_identifier,
                     status, display_name, routing_information, created_at, updated_at"#,
    )
    .bind(a.env_id())
    .bind(req.account_id)
    .bind(&req.bank_identifier)
    .bind(&req.instrument_identifier)
    .bind(&req.display_name)
    .bind(req.routing_information.unwrap_or(serde_json::json!({})))
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let instrument_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::PaymentInstrument,
        &instrument_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(crate::routing::row_to_payment_instrument(&row)))
}

/// `GET /v1/payment-instruments` — list payment instruments.
pub async fn list_payment_instruments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::routing::PaymentInstrumentResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payment-instruments:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, account_id, bank_identifier, instrument_identifier,
                  status, display_name, routing_information, created_at, updated_at
             FROM payment_instruments
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(crate::routing::row_to_payment_instrument)
            .collect(),
    ))
}

/// `GET /v1/payment-instruments/{id}` — get a payment instrument.
pub async fn get_payment_instrument(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::routing::PaymentInstrumentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payment-instruments:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, account_id, bank_identifier, instrument_identifier,
                  status, display_name, routing_information, created_at, updated_at
             FROM payment_instruments WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(crate::routing::row_to_payment_instrument(&row)))
}

/// `PATCH /v1/payment-instruments/{id}` — update a payment instrument.
pub async fn update_payment_instrument(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<crate::routing::UpdatePaymentInstrumentRequest>,
) -> Result<Json<crate::routing::PaymentInstrumentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payment-instruments:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE payment_instruments
              SET bank_identifier = COALESCE($2, bank_identifier),
                  instrument_identifier = COALESCE($3, instrument_identifier),
                  status = COALESCE($4, status),
                  display_name = COALESCE($5, display_name),
                  routing_information = COALESCE($6, routing_information),
                  resource_version = resource_version + 1,
                  updated_at = now()
            WHERE id = $1
            RETURNING id, account_id, bank_identifier, instrument_identifier,
                      status, display_name, routing_information, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.bank_identifier.as_deref())
    .bind(req.instrument_identifier.as_deref())
    .bind(req.status.as_deref())
    .bind(req.display_name.as_deref())
    .bind(req.routing_information.as_ref())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::PaymentInstrument,
        &id.to_string(),
        "updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(crate::routing::row_to_payment_instrument(&row)))
}

/// `DELETE /v1/payment-instruments/{id}` — deactivate a payment instrument.
pub async fn delete_payment_instrument(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payment-instruments:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    sqlx::query(
        r#"UPDATE payment_instruments SET status = 'inactive', updated_at = now()
           WHERE id = $1"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::PaymentInstrument,
        &id.to_string(),
        "deleted",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(serde_json::json!({ "id": id, "status": "inactive" })))
}

// ── Routing: Account Links (Story ) ─────────────────────────────

/// `POST /v1/account-links` — create an account link.
pub async fn create_account_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::routing::CreateAccountLinkRequest>,
) -> Result<Json<crate::routing::AccountLinkResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:account-links:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // Story — if is_default, unset other defaults for the same account.
    if req.is_default {
        sqlx::query(
            r#"UPDATE account_links SET is_default = false, updated_at = now()
               WHERE account_id = $1 AND env_id = $2"#,
        )
        .bind(req.account_id)
        .bind(a.env_id())
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;
    }

    let row = sqlx::query(
        r#"INSERT INTO account_links
               (env_id, account_id, payment_instrument_id,
                core_account_id, is_default, status, display_name)
           VALUES ($1, $2, $3, $4, $5, 'active', $6)
           RETURNING id, account_id, payment_instrument_id, core_account_id,
                     is_default, status, display_name, created_at, updated_at"#,
    )
    .bind(a.env_id())
    .bind(req.account_id)
    .bind(req.payment_instrument_id)
    .bind(&req.core_account_id)
    .bind(req.is_default)
    .bind(&req.display_name)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let account_link_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::AccountLink,
        &account_link_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(crate::routing::row_to_account_link(&row)))
}

/// `GET /v1/account-links` — list account links.
pub async fn list_account_links(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::routing::AccountLinkResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:account-links:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, account_id, payment_instrument_id, core_account_id,
                  is_default, status, display_name, created_at, updated_at
             FROM account_links
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(crate::routing::row_to_account_link)
            .collect(),
    ))
}

/// `GET /v1/account-links/{id}` — get an account link.
pub async fn get_account_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::routing::AccountLinkResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:account-links:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, account_id, payment_instrument_id, core_account_id,
                  is_default, status, display_name, created_at, updated_at
             FROM account_links WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(crate::routing::row_to_account_link(&row)))
}

/// `DELETE /v1/account-links/{id}` — deactivate an account link.
pub async fn delete_account_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:account-links:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    sqlx::query("UPDATE account_links SET status = 'inactive', updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::AccountLink,
        &id.to_string(),
        "deleted",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(serde_json::json!({ "id": id, "status": "inactive" })))
}

// ── Proxy-back: `POST /v1/internal/steps/execute` ────────────────────────
// Flow proxy-calls this during Payments instruction workflows.

// ── Rules Engine  ─────────────────────────

/// `POST /v1/rules` — create a rule.
#[utoipa::path(
    post,
    path = "/v1/rules",
    request_body = crate::rules::CreateRuleRequest,
    responses(
        (status = 200, description = "Rule created", body = crate::rules::RuleResponse),
        (status = 403, description = "Missing bank8:payments:rules:write scope"),
    ),
    security(("bank8:payments:rules:write" = [])),
    tag = "payments",
)]
pub async fn create_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::rules::CreateRuleRequest>,
) -> Result<Json<crate::rules::RuleResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:rules:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rule_type = req.rule_type.unwrap_or_else(|| "basic".into());
    let row = sqlx::query(
        r#"INSERT INTO rules (env_id, name, rule_type,
                                    expression, action, status, expected_parameters)
           VALUES ($1, $2, $3, $4, $5, 'active', $6)
           RETURNING id, name, rule_type, expression, action, status, version,
                     active_version_id, expected_parameters, created_at, updated_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(&rule_type)
    .bind(&req.expression)
    .bind(&req.action)
    .bind(req.expected_parameters.unwrap_or(serde_json::json!([])))
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let rule_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Rule,
        &rule_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(crate::rules::row_to_rule(&row)))
}

/// `GET /v1/rules` — list rules.
#[utoipa::path(
    get,
    path = "/v1/rules",
    responses(
        (status = 200, description = "List of rules", body = Vec<crate::rules::RuleResponse>),
        (status = 403, description = "Missing bank8:payments:rules:read scope"),
    ),
    security(("bank8:payments:rules:read" = [])),
    tag = "payments",
)]
pub async fn list_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::rules::RuleResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:rules:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, name, rule_type, expression, action, status, version,
                  active_version_id, expected_parameters, created_at, updated_at
             FROM rules ORDER BY created_at DESC"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(crate::rules::row_to_rule).collect()))
}

/// `POST /v1/rules/{id}/publish` — publish a new rule version (Story ).
#[utoipa::path(
    post,
    path = "/v1/rules/{id}/publish",
    params(("id" = Uuid, Path, description = "Rule ID")),
    request_body = crate::rules::PublishRuleVersionRequest,
    responses(
        (status = 200, description = "Rule version published", body = crate::rules::RuleVersionResponse),
        (status = 403, description = "Missing bank8:payments:rules:write scope"),
    ),
    security(("bank8:payments:rules:write" = [])),
    tag = "payments",
)]
pub async fn publish_rule_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<crate::rules::PublishRuleVersionRequest>,
) -> Result<Json<crate::rules::RuleVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:rules:publish"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // Get the next version number.
    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM rule_versions WHERE rule_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    let row = sqlx::query(
        r#"INSERT INTO rule_versions (env_id, rule_id, version,
                                             implementation, status)
           VALUES ($1, $2, $3, $4, $5, 'published')
           RETURNING id, rule_id, version, implementation, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(id)
    .bind(next_version)
    .bind(&req.implementation)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    // Update the active_version_id on the rule.
    let version_id: Uuid = row.get("id");
    sqlx::query(
        r#"UPDATE rules SET active_version_id = $2, version = $3, updated_at = now()
           WHERE id = $1"#,
    )
    .bind(id)
    .bind(version_id)
    .bind(next_version)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::RuleVersion,
        &version_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(crate::rules::RuleVersionResponse {
        id: row.get("id"),
        rule_id: row.get("rule_id"),
        version: row.get("version"),
        implementation: row.get("implementation"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

/// `POST /v1/rule-sets` — create a rule set (Story ).
pub async fn create_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::rules::CreateRuleSetRequest>,
) -> Result<Json<crate::rules::RuleSetResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:rules:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO rule_sets (env_id, name, description, status)
           VALUES ($1, $2, $3, 'active')
           RETURNING id, name, description, status, version, created_at, updated_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(&req.description)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let rule_set_id: Uuid = row.get("id");

    // Add rules to the rule set.
    if let Some(rule_ids) = req.rule_ids {
        for (i, rule_id) in rule_ids.iter().enumerate() {
            sqlx::query(
                "INSERT INTO rule_set_rules (rule_set_id, rule_id, sort_order) VALUES ($1, $2, $3)",
            )
            .bind(rule_set_id)
            .bind(rule_id)
            .bind(i as i32)
            .execute(&mut *conn)
            .await
            .ok();
        }
        // Create a version with these rule IDs.
        let _ = sqlx::query(
            r#"INSERT INTO rule_set_versions (env_id, rule_set_id, version, rule_ids, status)
               VALUES ($1, $2, 1, $3, 'published')"#,
        )
        .bind(a.env_id())
        .bind(rule_set_id)
        .bind(serde_json::json!(rule_ids))
        .execute(&mut *conn)
        .await;
    }

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::RuleSet,
        &rule_set_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(crate::rules::row_to_rule_set(&row)))
}

/// `GET /v1/rule-sets` — list rule sets.
pub async fn list_rule_sets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::rules::RuleSetResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:rules:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, name, description, status, version, created_at, updated_at
             FROM rule_sets ORDER BY created_at DESC"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter().map(crate::rules::row_to_rule_set).collect(),
    ))
}

// ── Parameters API (Story ) ──────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ParameterResponse {
    pub id: Uuid,
    pub name: String,
    pub parameter_type: String,
    pub value: String,
    pub payment_instrument_id: Option<Uuid>,
    pub description: Option<String>,
    pub status: String,
    pub version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateParameterRequest {
    pub name: String,
    pub parameter_type: String,
    pub value: String,
    #[serde(default)]
    pub payment_instrument_id: Option<Uuid>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateParameterRequest {
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub parameter_type: Option<String>,
    #[serde(default)]
    pub payment_instrument_id: Option<Uuid>,
    #[serde(default)]
    pub description: Option<String>,
}

fn row_to_parameter(row: &sqlx::postgres::PgRow) -> ParameterResponse {
    ParameterResponse {
        id: row.get("id"),
        name: row.get("name"),
        parameter_type: row.get("parameter_type"),
        value: row.get("value"),
        payment_instrument_id: row.get("payment_instrument_id"),
        description: row.get("description"),
        status: row.get("status"),
        version: row.get("version"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

const PARAM_COLUMNS: &str =
    "id, name, parameter_type, value, payment_instrument_id, description, status, version, created_at, updated_at";

/// `POST /v1/parameters` — create a parameter.
pub async fn create_parameter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateParameterRequest>,
) -> Result<Json<ParameterResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:parameters:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // Validate the parameter type.
    let ptype = crate::parameters::ParameterType::from_str(&req.parameter_type)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    // Validate the value against the parameter type. The value column is TEXT;
    // we parse it as JSON for validation when it represents a non-string type.
    let value_json = match ptype {
        crate::parameters::ParameterType::String | crate::parameters::ParameterType::DateTime => {
            serde_json::Value::String(req.value.clone())
        }
        crate::parameters::ParameterType::Decimal => serde_json::Value::String(req.value.clone()),
        _ => serde_json::from_str(&req.value)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON value: {e}")))?,
    };
    ptype
        .validate_value(&value_json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let sql = format!(
        r#"INSERT INTO parameters
               (env_id, name, value, parameter_type,
                payment_instrument_id, description, status, version)
           VALUES ($1, $2, $3, $4, $5, $6, 'active', 1)
           RETURNING {PARAM_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(&req.value)
        .bind(ptype.as_str())
        .bind(req.payment_instrument_id)
        .bind(&req.description)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let parameter_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Parameter,
        &parameter_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_parameter(&row)))
}

/// `GET /v1/parameters` — list parameters.
pub async fn list_parameters(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ParameterResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:parameters:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {PARAM_COLUMNS} FROM parameters WHERE status = 'active' ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_parameter).collect()))
}

/// `GET /v1/parameters/{id}` — get a parameter.
pub async fn get_parameter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ParameterResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:parameters:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {PARAM_COLUMNS} FROM parameters WHERE id = $1");
    // Note: returns the row even if soft-deleted, so callers can see the
    // status. Resolution queries (resolve_parameter) filter on status='active'.
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_parameter(&row)))
}

/// `PATCH /v1/parameters/{id}` — update a parameter.
pub async fn update_parameter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateParameterRequest>,
) -> Result<Json<ParameterResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:parameters:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // If updating the value and/or type, validate the new value against the
    // (new or existing) type.
    if let (Some(new_type), Some(new_value)) = (req.parameter_type.as_deref(), req.value.as_deref())
    {
        let ptype = crate::parameters::ParameterType::from_str(new_type)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let value_json = match ptype {
            crate::parameters::ParameterType::String
            | crate::parameters::ParameterType::DateTime
            | crate::parameters::ParameterType::Decimal => {
                serde_json::Value::String(new_value.to_string())
            }
            _ => serde_json::from_str(new_value)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON value: {e}")))?,
        };
        ptype
            .validate_value(&value_json)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    }

    let sql = format!(
        r#"UPDATE parameters
              SET value = COALESCE($2, value),
                  parameter_type = COALESCE($3, parameter_type),
                  payment_instrument_id = COALESCE($4, payment_instrument_id),
                  description = COALESCE($5, description),
                  version = version + 1,
                  updated_at = now()
            WHERE id = $1 AND status = 'active'
            RETURNING {PARAM_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(req.value.as_deref())
        .bind(req.parameter_type.as_deref())
        .bind(req.payment_instrument_id)
        .bind(req.description.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Parameter,
        &id.to_string(),
        "updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_parameter(&row)))
}

/// `DELETE /v1/parameters/{id}` — soft delete a parameter.
/// Sets `status = 'deleted'` so the row is retained for audit but excluded
/// from `resolve_parameter` and `list_parameters`.
pub async fn delete_parameter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:parameters:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    sqlx::query(
        r#"UPDATE parameters
              SET status = 'deleted',
                  payment_instrument_id = NULL,
                  version = version + 1,
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Parameter,
        &id.to_string(),
        "deleted",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(serde_json::json!({ "id": id, "status": "deleted" })))
}

// ── Files (Story ) ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct UploadFileRequest {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub sentin8_buck_path: String,
}

#[derive(Debug, Serialize)]
pub struct FileResponse {
    pub id: Uuid,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub sentin8_buck_path: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn row_to_file(row: &sqlx::postgres::PgRow) -> FileResponse {
    FileResponse {
        id: row.get("id"),
        filename: row.get("filename"),
        content_type: row.get("content_type"),
        size_bytes: row.get("size_bytes"),
        sentin8_buck_path: row.get("sentin8_buck_path"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

/// `POST /v1/files` — register an uploaded file.
pub async fn upload_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<UploadFileRequest>,
) -> Result<Json<FileResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Files)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO files (env_id, filename, content_type, size_bytes, sentin8_buck_path, status)
           VALUES ($1, $2, $3, $4, $5, 'uploaded')
           RETURNING id, filename, content_type, size_bytes, sentin8_buck_path, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.filename).bind(&req.content_type)
    .bind(req.size_bytes).bind(&req.sentin8_buck_path)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(row_to_file(&row)))
}

/// `GET /v1/files` — list uploaded files.
pub async fn list_files(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<FileResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Files)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, filename, content_type, size_bytes, sentin8_buck_path, status, created_at
             FROM files ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_file).collect()))
}

/// `GET /v1/files/{id}` — file detail.
pub async fn get_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<FileResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Files)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, filename, content_type, size_bytes, sentin8_buck_path, status, created_at
             FROM files WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(row_to_file(&row)))
}

#[derive(Debug, Serialize)]
pub struct InstructionFileResponse {
    pub id: Uuid,
    pub file_id: Option<Uuid>,
    pub name: String,
    pub direction: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) fn row_to_instruction_file(row: &sqlx::postgres::PgRow) -> InstructionFileResponse {
    InstructionFileResponse {
        id: row.get("id"),
        file_id: row.get("file_id"),
        name: row.get("name"),
        direction: row.get("direction"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateInstructionFileRequest {
    pub name: String,
    pub direction: String,
    pub file_id: Option<Uuid>,
}

/// `POST /v1/instruction-files` — create an instruction file.
pub async fn create_instruction_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateInstructionFileRequest>,
) -> Result<Json<InstructionFileResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Files)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    // Validate direction.
    let _ = crate::file_processing::FileDirection::from_str(&req.direction)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let row = sqlx::query(
        r#"INSERT INTO instruction_files (env_id, file_id, name, direction, status)
           VALUES ($1, $2, $3, $4, 'pending')
           RETURNING id, file_id, name, direction, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(req.file_id)
    .bind(&req.name)
    .bind(&req.direction)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(row_to_instruction_file(&row)))
}

/// `GET /v1/instruction-files` — list instruction files.
pub async fn list_instruction_files(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InstructionFileResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Files)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, file_id, name, direction, status, created_at
             FROM instruction_files ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_instruction_file).collect()))
}

#[derive(Debug, Serialize)]
pub struct InstructionFileSpecificationResponse {
    pub id: Uuid,
    pub name: String,
    pub capacity_limit: i32,
    pub calendar_id: Option<Uuid>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn row_to_specification(row: &sqlx::postgres::PgRow) -> InstructionFileSpecificationResponse {
    InstructionFileSpecificationResponse {
        id: row.get("id"),
        name: row.get("name"),
        capacity_limit: row.get("capacity_limit"),
        calendar_id: row.get("calendar_id"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateSpecificationRequest {
    pub name: String,
    #[serde(default = "default_capacity_limit")]
    pub capacity_limit: i32,
    pub calendar_id: Option<Uuid>,
}

fn default_capacity_limit() -> i32 {
    1000
}

/// `POST /v1/instruction-file-specifications` — create a specification.
pub async fn create_specification(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSpecificationRequest>,
) -> Result<Json<InstructionFileSpecificationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Files)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO instruction_file_specifications (env_id, name, capacity_limit, calendar_id, status)
           VALUES ($1, $2, $3, $4, 'active')
           RETURNING id, name, capacity_limit, calendar_id, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name).bind(req.capacity_limit).bind(req.calendar_id)
    .fetch_one(&mut *conn).await.map_err(err_db)?;
    Ok(Json(row_to_specification(&row)))
}

/// `GET /v1/instruction-file-specifications` — list specifications.
pub async fn list_specifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InstructionFileSpecificationResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Files)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, name, capacity_limit, calendar_id, status, created_at
             FROM instruction_file_specifications ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_specification).collect()))
}

// ── Manual Decisions  ───────────────

#[derive(Debug, Serialize)]
pub struct ManualDecisionResponse {
    pub id: Uuid,
    pub instruction_id: Option<Uuid>,
    pub decision_type: String,
    pub status: String,
    pub submitted_by: Option<String>,
    pub submitted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn row_to_manual_decision(row: &sqlx::postgres::PgRow) -> ManualDecisionResponse {
    ManualDecisionResponse {
        id: row.get("id"),
        instruction_id: row.get("instruction_id"),
        decision_type: row.get("decision_type"),
        status: row.get("status"),
        submitted_by: row.get("submitted_by"),
        submitted_at: row.get("submitted_at"),
        created_at: row.get("created_at"),
    }
}

/// `GET /v1/manual-decisions` — list manual decisions.
pub async fn list_manual_decisions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ManualDecisionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::ManualDecisions)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:manual-decisions:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, instruction_id, decision_type, status, submitted_by, submitted_at, created_at
             FROM manual_decisions ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_manual_decision).collect()))
}

/// `GET /v1/manual-decisions/{id}` — manual decision detail.
pub async fn get_manual_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ManualDecisionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::ManualDecisions)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:manual-decisions:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, instruction_id, decision_type, status, submitted_by, submitted_at, created_at
             FROM manual_decisions WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(row_to_manual_decision(&row)))
}

#[derive(Debug, Deserialize)]
pub struct SubmitManualDecisionRequest {
    pub decision: serde_json::Value,
}

/// `POST /v1/manual-decisions/{id}/submit` — submit a manual decision.
/// Records the submitter, the decision payload, and marks the decision as
/// `submitting`. The downstream task system picks up the row from there.
pub async fn submit_manual_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<SubmitManualDecisionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::ManualDecisions)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:manual-decisions:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    let result = sqlx::query(
        r#"UPDATE manual_decisions
              SET status = 'submitting',
                  submitted_by = $1,
                  submitted_at = now()
            WHERE id = $2
           RETURNING id, status"#,
    )
    .bind(a.subject())
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    // Create a task for the manual decision submission.
    let task_id = crate::manual_decisions::create_task(
        &state.pool,
        crate::manual_decisions::TaskType::ManualDecisionSubmission,
        None,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let status: String = result.get("status");
    Ok(Json(serde_json::json!({
        "id": id,
        "status": status,
        "submitted_by": a.subject(),
        "decision": req.decision,
        "task_id": task_id,
    })))
}

// ── Proxy-back: `POST /v1/internal/steps/execute` (continued) ───────────

#[derive(Debug, Deserialize)]
pub struct ProxyBackRequest {
    pub step_kind: String,
    pub workflow_id: Uuid,
    pub step_name: String,
    pub input: serde_json::Value,
    pub user_data: serde_json::Value,
    pub step_config: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ProxyBackResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<String>,
}

/// `POST /v1/internal/steps/execute` — Flow proxy-back for Payments domain steps.
pub async fn execute_step(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProxyBackRequest>,
) -> Result<Json<ProxyBackResponse>, (StatusCode, String)> {
    use sqlx::Row;
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:logics:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    // Use system context for proxy-back — the workflow ID carries the org/env.
    // In production, extract org_id/env_id from the Flow workflow record.
    match req.step_kind.as_str() {
        "MatchPaymentInstrumentStep" => {
            // Extract routing info from input, match against payment_instruments.
            let bank_id = req
                .input
                .get("bank_identifier")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let instrument_id = req
                .input
                .get("instrument_identifier")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let row = sqlx::query(
                r#"SELECT id, account_id FROM payment_instruments
                    WHERE status = 'active' AND (
                        bank_identifier = $1 OR instrument_identifier = $2
                    ) LIMIT 1"#,
            )
            .bind(bank_id)
            .bind(instrument_id)
            .fetch_optional(&mut *conn)
            .await;
            match row {
                Ok(Some(r)) => {
                    let id: Uuid = r.get("id");
                    let account_id: Uuid = r.get("account_id");
                    Ok(Json(ProxyBackResponse {
                        status: "success".into(),
                        output: Some(
                            serde_json::json!({ "instrument_id" : id, "account_id" : account_id }),
                        ),
                        error: None,
                        next_step: None,
                    }))
                }
                Ok(None) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some("no matching payment instrument found".into()),
                    next_step: None,
                })),
                Err(e) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!("db error: {e}")),
                    next_step: None,
                })),
            }
        }
        "Sentin8CorePostingsStep" => {
            // Build the posting batch from the step config and submit to
            // Bank8:Ledger `POST /v1/postings` (design §4.6).
            // Config shape (typed path):
            // { "posting_type": "OutboundHardSettlement",
            // "source_account": "<uuid>", "destination_account": "<uuid>",
            // "amount": "100.00", "denomination": "CAD",
            // "instruction_id": "<uuid>", "description": "..." }
            // The raw `instructions` array remains supported as a
            // pass-through for prebuilt batches.
            let config = req.step_config.clone().unwrap_or_default();
            let instruction_id = config
                .get("instruction_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok());

            let (batch_id, instructions) =
                if let (Some(pt), Some(src), Some(dst), Some(amount), Some(iid)) = (
                    config.get("posting_type").and_then(|v| v.as_str()),
                    config.get("source_account").and_then(|v| v.as_str()),
                    config.get("destination_account").and_then(|v| v.as_str()),
                    config.get("amount").and_then(|v| v.as_str()),
                    instruction_id,
                ) {
                    let parsed = crate::postings::PostingType::from_str(pt)
                        .and_then(|ptype| {
                            Uuid::parse_str(src)
                                .map(|s| (ptype, s))
                                .map_err(|e| e.to_string())
                        })
                        .and_then(|(ptype, s)| {
                            Uuid::parse_str(dst)
                                .map(|d| (ptype, s, d))
                                .map_err(|e| e.to_string())
                        });
                    match parsed {
                        Ok((ptype, src_id, dst_id)) => {
                            let denom = config
                                .get("denomination")
                                .and_then(|v| v.as_str())
                                .unwrap_or("CAD");
                            let desc = config.get("description").and_then(|v| v.as_str());
                            let instr = crate::postings::build_instruction(
                                ptype, src_id, dst_id, amount, denom, desc,
                            );
                            match serde_json::to_value(&instr) {
                                Ok(v) => (crate::postings::batch_id_for(iid, ptype), vec![v]),
                                Err(e) => {
                                    return Ok(Json(ProxyBackResponse {
                                        status: "failed".into(),
                                        output: None,
                                        error: Some(format!("serialize posting: {e}")),
                                        next_step: None,
                                    }))
                                }
                            }
                        }
                        Err(e) => {
                            return Ok(Json(ProxyBackResponse {
                                status: "failed".into(),
                                output: None,
                                error: Some(format!("invalid posting config: {e}")),
                                next_step: None,
                            }))
                        }
                    }
                } else {
                    // Fallback: prebuilt instruction array.
                    let batch = config
                        .get("batchId")
                        .and_then(|v| v.as_str())
                        .unwrap_or("payments-posting");
                    (
                        batch.to_string(),
                        config
                            .get("instructions")
                            .and_then(|v| v.as_array().cloned())
                            .unwrap_or_default(),
                    )
                };

            if instructions.is_empty() {
                return Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some("no posting instructions configured".into()),
                    next_step: None,
                }));
            }

            let http = match state.config.ledger_http.clone() {
                Some(c) => c,
                None => return Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(
                        "ledger posting transport absent (workload certificate not provisioned)"
                            .into(),
                    ),
                    next_step: None,
                })),
            };
            let resp = http
                .post(format!("{}/v1/postings", state.config.ledger_url))
                .json(&serde_json::json!({
                    "batch_id": batch_id,
                    "instructions": instructions,
                }))
                .send()
                .await;
            match resp {
                Ok(r) if r.status().is_success() => Ok(Json(ProxyBackResponse {
                    status: "success".into(),
                    output: Some(serde_json::json!({ "posted": true, "batch_id": batch_id })),
                    error: None,
                    next_step: None,
                })),
                Ok(r) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!("ledger posting: HTTP {}", r.status())),
                    next_step: None,
                })),
                Err(e) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!("ledger posting: {e}")),
                    next_step: None,
                })),
            }
        }

        "AccountLinkStep" => {
            // Find default account link.
            let row = sqlx::query(
                r#"SELECT id, account_id FROM account_links
                    WHERE status = 'active' AND is_default = true LIMIT 1"#,
            )
            .fetch_optional(&mut *conn)
            .await;
            match row {
                Ok(Some(r)) => {
                    let id: Uuid = r.get("id");
                    let account_id: Uuid = r.get("account_id");
                    Ok(Json(ProxyBackResponse {
                        status: "success".into(),
                        output: Some(
                            serde_json::json!({ "link_id" : id, "account_id" : account_id }),
                        ),
                        error: None,
                        next_step: None,
                    }))
                }
                _ => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some("no default account link found".into()),
                    next_step: None,
                })),
            }
        }
        "SchemeSubmissionStep" => {
            // Submit to the payment scheme through the scheme flow processors
            // (Story ). Config selects the scheme +
            // direction; the payload comes from the step input.
            let scheme = req
                .step_config
                .as_ref()
                .and_then(|c| c.get("scheme"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let flow = req
                .step_config
                .as_ref()
                .and_then(|c| c.get("flow"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            match (scheme.as_str(), flow.as_str()) {
                ("tips", "inbound") => Ok(crate::tips_flows::process_tips_inbound(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                ("tips", "outbound") => Ok(crate::tips_flows::process_tips_outbound(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                ("tips", "inbound_recall") => Ok(crate::tips_flows::process_tips_inbound_recall(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                ("tips", "outbound_recall") => Ok(crate::tips_flows::process_tips_outbound_recall(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                ("tips", "status_request") => Ok(crate::tips_flows::process_tips_status_request(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                ("sepa", "ct_outbound") => Ok(crate::sepa_flows::process_sepa_ct_outbound(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                ("sepa", "ct_inbound") => Ok(crate::sepa_flows::process_sepa_ct_inbound(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                ("sepa", "ct_outbound_rejection") => Ok(
                    crate::sepa_flows::process_sepa_ct_outbound_rejection(&state.pool, &req.input)
                        .await
                        .map(|r| submit_response(&r))
                        .unwrap_or_else(submit_failure),
                ),
                ("sepa", "ct_outbound_return") => Ok(
                    crate::sepa_flows::process_sepa_ct_outbound_return(&state.pool, &req.input)
                        .await
                        .map(|r| submit_response(&r))
                        .unwrap_or_else(submit_failure),
                ),
                ("sepa", "ct_inbound_automatic_return") => {
                    let original_id = req
                        .input
                        .get("original_instruction_id")
                        .or_else(|| req.input.get("originalInstructionId"))
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                        .ok_or_else(|| {
                            (
                                StatusCode::BAD_REQUEST,
                                "original_instruction_id is required".into(),
                            )
                        })?;
                    Ok(crate::sepa_flows::process_sepa_ct_inbound_automatic_return(
                        &state.pool,
                        original_id,
                    )
                    .await
                    .map(|r| submit_response(&r))
                    .unwrap_or_else(submit_failure))
                }
                ("sepa", "ct_recall") => {
                    let recall_type = crate::sepa_flows::SepaRecallType::from_str(
                        req.input
                            .get("recall_type")
                            .or_else(|| req.input.get("recallType"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("dupl"),
                    )
                    .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
                    Ok(crate::sepa_flows::process_sepa_ct_recall(
                        &state.pool,
                        &req.input,
                        recall_type,
                    )
                    .await
                    .map(|r| submit_response(&r))
                    .unwrap_or_else(submit_failure))
                }
                ("b8", "credit_transfer_outbound") => Ok(
                    crate::b8_flows::process_b8_credit_transfer_outbound(&state.pool, &req.input)
                        .await
                        .map(|r| submit_response(&r))
                        .unwrap_or_else(submit_failure),
                ),
                ("b8", "credit_transfer_inbound") => Ok(
                    crate::b8_flows::process_b8_credit_transfer_inbound(&state.pool, &req.input)
                        .await
                        .map(|r| submit_response(&r))
                        .unwrap_or_else(submit_failure),
                ),
                ("b8", "direct_debit_outbound") => Ok(
                    crate::b8_flows::process_b8_direct_debit_outbound(&state.pool, &req.input)
                        .await
                        .map(|r| submit_response(&r))
                        .unwrap_or_else(submit_failure),
                ),
                ("b8", "direct_debit_inbound") => Ok(
                    crate::b8_flows::process_b8_direct_debit_inbound(&state.pool, &req.input)
                        .await
                        .map(|r| submit_response(&r))
                        .unwrap_or_else(submit_failure),
                ),
                ("b8", "onus_a2a_outbound") => Ok(crate::b8_flows::process_b8_onus_a2a_outbound(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                ("b8", "onus_a2a_inbound") => Ok(crate::b8_flows::process_b8_onus_a2a_inbound(
                    &state.pool,
                    &req.input,
                )
                .await
                .map(|r| submit_response(&r))
                .unwrap_or_else(submit_failure)),
                (s, f) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!("unknown scheme/flow: {s}/{f}")),
                    next_step: None,
                })),
            }
        }
        // ── Story : MembershipDirectoryStep ─────────────────────
        "MembershipDirectoryStep" => {
            let bic = req.input.get("bic").and_then(|v| v.as_str()).unwrap_or("");
            let directory_type = req
                .input
                .get("directory_type")
                .or_else(|| req.input.get("directoryType"))
                .and_then(|v| v.as_str())
                .unwrap_or("tips");
            // Query the membership directory for BIC reachability.
            let row = sqlx::query(
                r#"SELECT id, entries FROM membership_directories
                    WHERE directory_type = $1 AND status = 'ready' LIMIT 1"#,
            )
            .bind(directory_type)
            .fetch_optional(&mut *conn)
            .await;
            match row {
                Ok(Some(r)) => {
                    let dir_id: Uuid = r.get("id");
                    let entries: serde_json::Value = r.get("entries");
                    // Check if BIC is in the directory entries.
                    let reachable = entries
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .any(|e| e.get("bic").and_then(|v| v.as_str()) == Some(bic))
                        })
                        .unwrap_or(false);
                    Ok(Json(ProxyBackResponse {
                        status: "success".into(),
                        output: Some(serde_json::json!({
                            "directory_id" : dir_id,
                            "bic": bic,
                            "reachable": reachable,
                        })),
                        error: None,
                        next_step: None,
                    }))
                }
                Ok(None) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!(
                        "no ready membership directory of type '{directory_type}'"
                    )),
                    next_step: None,
                })),
                Err(e) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!("db error: {e}")),
                    next_step: None,
                })),
            }
        }
        // ── Story : InstructionFileStep ─────────────────────────
        "InstructionFileStep" => {
            // Group instructions into a file/batch for outbound processing.
            let instruction_ids = req
                .input
                .get("instruction_ids")
                .or_else(|| req.input.get("instructionIds"))
                .cloned()
                .unwrap_or(serde_json::Value::Array(vec![]));
            let file_name = req
                .input
                .get("file_name")
                .or_else(|| req.input.get("fileName"))
                .and_then(|v| v.as_str())
                .unwrap_or("outbound.txt")
                .to_string();
            let direction = req
                .input
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("outbound")
                .to_string();

            let row = sqlx::query(
                r#"INSERT INTO instruction_files (name, direction, status)
                   VALUES ($1, $2, 'pending')
                   RETURNING id"#,
            )
            .bind(&file_name)
            .bind(&direction)
            .fetch_one(&mut *conn)
            .await;
            match row {
                Ok(r) => {
                    let file_id: Uuid = r.get("id");
                    // Create a batch linking the instruction IDs.
                    let _ = sqlx::query(
                        r#"INSERT INTO instruction_batches (instruction_file_id, name, instruction_ids, status)
                           VALUES ($1, $2, $3, 'pending')"#,
                    )
                    .bind(file_id)
                    .bind(&file_name)
                    .bind(&instruction_ids)
                    .execute(&mut *conn).await;
                    Ok(Json(ProxyBackResponse {
                        status: "success".into(),
                        output: Some(serde_json::json!({
                            "file_id" : file_id,
                            "file_name" : file_name,
                            "direction": direction,
                        })),
                        error: None,
                        next_step: None,
                    }))
                }
                Err(e) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!("create instruction file: {e}")),
                    next_step: None,
                })),
            }
        }
        // ── Story : CreateMandateStep ──────────────────────────
        "CreateMandateStep" => {
            let scheme_creditor_id = req
                .input
                .get("scheme_creditor_id")
                .or_else(|| req.input.get("schemeCreditorId"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let debtor_name = req
                .input
                .get("debtor_name")
                .or_else(|| req.input.get("debtorName"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let debtor_account = req
                .input
                .get("debtor_account")
                .or_else(|| req.input.get("debtorAccount"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let creditor_name = req
                .input
                .get("creditor_name")
                .or_else(|| req.input.get("creditorName"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let creditor_account = req
                .input
                .get("creditor_account")
                .or_else(|| req.input.get("creditorAccount"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let amount_limit = req
                .input
                .get("amount_limit")
                .or_else(|| req.input.get("amountLimit"))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<rust_decimal::Decimal>().ok());
            let currency = req
                .input
                .get("currency")
                .and_then(|v| v.as_str())
                .unwrap_or("CAD")
                .to_string();

            let row = sqlx::query(
                r#"INSERT INTO mandates (scheme_creditor_id, debtor_name, debtor_account,
                                          creditor_name, creditor_account, amount_limit, currency, status)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
                   RETURNING id, scheme_mandate_id"#,
            )
            .bind(&scheme_creditor_id)
            .bind(&debtor_name)
            .bind(&debtor_account)
            .bind(&creditor_name)
            .bind(&creditor_account)
            .bind(amount_limit)
            .bind(&currency)
            .fetch_one(&mut *conn).await;
            match row {
                Ok(r) => {
                    let mandate_id: Uuid = r.get("id");
                    let scheme_mandate_id: Option<String> = r.get("scheme_mandate_id");
                    Ok(Json(ProxyBackResponse {
                        status: "success".into(),
                        output: Some(serde_json::json!({
                            "mandate_id" : mandate_id,
                            "scheme_mandate_id" : scheme_mandate_id,
                            "status": "active",
                        })),
                        error: None,
                        next_step: None,
                    }))
                }
                Err(e) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!("create mandate: {e}")),
                    next_step: None,
                })),
            }
        }
        // ── Story : MatchMandateStep ────────────────────────────
        "MatchMandateStep" => {
            let debtor_account = req
                .input
                .get("debtor_account")
                .or_else(|| req.input.get("debtorAccount"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let creditor_account = req
                .input
                .get("creditor_account")
                .or_else(|| req.input.get("creditorAccount"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let row = sqlx::query(
                r#"SELECT id, scheme_mandate_id, status FROM mandates
                    WHERE status = 'active'
                      AND (debtor_account = $1 OR creditor_account = $2)
                    LIMIT 1"#,
            )
            .bind(debtor_account)
            .bind(creditor_account)
            .fetch_optional(&mut *conn)
            .await;
            match row {
                Ok(Some(r)) => {
                    let mandate_id: Uuid = r.get("id");
                    let scheme_mandate_id: Option<String> = r.get("scheme_mandate_id");
                    let status: String = r.get("status");
                    Ok(Json(ProxyBackResponse {
                        status: "success".into(),
                        output: Some(serde_json::json!({
                            "mandate_id" : mandate_id,
                            "scheme_mandate_id" : scheme_mandate_id,
                            "mandate_status" : status,
                        })),
                        error: None,
                        next_step: None,
                    }))
                }
                Ok(None) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some("no matching mandate found".into()),
                    next_step: None,
                })),
                Err(e) => Ok(Json(ProxyBackResponse {
                    status: "failed".into(),
                    output: None,
                    error: Some(format!("db error: {e}")),
                    next_step: None,
                })),
            }
        }
        _ => Ok(Json(ProxyBackResponse {
            status: "failed".into(),
            output: None,
            error: Some(format!("unknown step kind: {}", req.step_kind)),
            next_step: None,
        })),
    }
}

/// Map a TIPS/SEPA/B8 flow result to a proxy-back response.
fn submit_response(r: &impl Serialize) -> Json<ProxyBackResponse> {
    let v = serde_json::to_value(r).unwrap_or(serde_json::Value::Null);
    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
    let failed = status.is_empty() || status == "rejected";
    if v.get("error").and_then(|e| e.as_str()).is_some() && failed {
        Json(ProxyBackResponse {
            status: "failed".into(),
            output: None,
            error: v.get("error").and_then(|e| e.as_str()).map(str::to_string),
            next_step: None,
        })
    } else {
        Json(ProxyBackResponse {
            status: "success".into(),
            output: Some(v),
            error: None,
            next_step: None,
        })
    }
}

fn submit_failure(e: String) -> Json<ProxyBackResponse> {
    Json(ProxyBackResponse {
        status: "failed".into(),
        output: None,
        error: Some(e),
        next_step: None,
    })
}

// ── Repair: `POST /v1/instructions/{id}/repair` (Story ) ───────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct RepairRequest {
    /// Step index to rewind to (0 = restart from beginning).
    #[serde(default)]
    pub rewind_to: usize,
    /// Optional updated input for the instruction.
    #[serde(default)]
    pub input: Option<serde_json::Value>,
}

/// `POST /v1/instructions/{id}/repair` — rewind the instruction to a step and
/// re-process via Flow (Story ).
#[utoipa::path(
    post,
    path = "/v1/instructions/{id}/repair",
    params(("id" = Uuid, Path, description = "Instruction ID")),
    request_body = RepairRequest,
    responses(
        (status = 200, description = "Instruction repaired", body = InstructionResponse),
        (status = 404, description = "Instruction not found"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn repair_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<RepairRequest>,
) -> Result<Json<InstructionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    // Load current instruction row.
    let row = sqlx::query(
        r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at,
                  step_results, current_step
             FROM instructions WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "instruction not found".to_string()))?;

    let step_results: serde_json::Value = row.get("step_results");
    let current_input: serde_json::Value = row.get("input");
    let current_step: Option<String> = row.get("current_step");

    // Truncate step results to the rewind point.
    let truncated = match &step_results {
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().take(req.rewind_to).cloned().collect())
        }
        other => other.clone(),
    };
    let new_input = req.input.unwrap_or(current_input);

    // Update the instruction: reset state, rewind step results, bump retry count.
    let updated = sqlx::query(
        r#"UPDATE instructions
              SET state = 'pending',
                  step_results = $2,
                  current_step = $3,
                  input = $4,
                  error_message = NULL,
                  retry_count = retry_count + 1,
                  completed_at = NULL,
                  updated_at = now()
            WHERE id = $1
            RETURNING id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at"#,
    )
    .bind(id)
    .bind(&truncated)
    .bind(current_step.as_deref())
    .bind(&new_input)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    // Re-process via Flow — look up the associated workflow by correlation_id
    // and call the Flow repair endpoint. Best-effort: if the workflow is not
    // found or Flow is unavailable, the instruction is left in `pending` for
    // the worker or a retry to pick up.
    if let Some(corr) = row
        .try_get::<Option<String>, _>("correlation_id")
        .ok()
        .flatten()
    {
        let client = match state.config.flow_http() {
            Some(http) => sentin8_flow_sdk::client::FlowClient::from_transport(
                &state.config.sentin8_flow_url,
                sentin8::middleware::http_client::Sentin8HttpClient::from_client(http.clone()),
            ),
            None => sentin8_flow_sdk::client::FlowClient::new_dev_plain(
                state.config.sentin8_flow_url.clone(),
            ),
        };
        match client
            .repair_workflow(&corr, req.rewind_to, Some(&new_input))
            .await
        {
            Ok(_) => {
                // Mark as processing since Flow accepted the repair.
                let _ = crate::state_machine::transition_with_audit(
                    &state.pool,
                    id,
                    crate::state_machine::InstructionState::Processing,
                    Some(&a.subject()),
                    Some("repair: flow accepted"),
                )
                .await;
            }
            Err(e) => {
                tracing::warn!(error = %e, instruction_id = %id, "flow repair failed; instruction left pending");
            }
        }
    }

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Instruction,
        &id.to_string(),
        "repaired",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_instruction(&updated)))
}

// ── Audit: `GET /v1/audit` (Story ) ──────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventResponse {
    pub id: Uuid,
    pub actor_user_id: Option<String>,
    pub action: String,
    pub target_resource_type: Option<String>,
    pub target_resource_id: Option<String>,
    pub correlation_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListAuditQuery {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default, rename = "target_resource_type")]
    pub target_resource_type: Option<String>,
    #[serde(default)]
    pub page_size: Option<i64>,
    #[serde(default, rename = "page_token")]
    pub page_token: Option<String>,
}

/// `GET /v1/audit` — query audit events (Story ).
/// Returns a paginated list of audit events with filters by action,
/// target resource type, and date range. Requires `payments:admin` scope.
#[utoipa::path(
    get,
    path = "/v1/audit",
    params(
        ("action" = Option<String>, Query, description = "Filter by action"),
        ("target_resource_type" = Option<String>, Query, description = "Filter by target resource type"),
        ("page_size" = Option<i64>, Query, description = "Page size (max 1000)"),
        ("page_token" = Option<String>, Query, description = "Page token"),
    ),
    responses(
        (status = 200, description = "List of audit events", body = Vec<AuditEventResponse>),
        (status = 403, description = "Missing bank8:payments:audit:read scope"),
    ),
    security(("bank8:payments:audit:read" = [])),
    tag = "payments",
)]
pub async fn list_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListAuditQuery>,
) -> Result<Json<Vec<AuditEventResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:audit:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let limit = q.page_size.unwrap_or(200).clamp(1, 1000);
    let rows = sqlx::query(
        r#"SELECT id, actor_user_id, action, target_resource_type, target_resource_id, correlation_id, timestamp
             FROM audit_events
            WHERE ($1::text IS NULL OR action = $1)
              AND ($2::text IS NULL OR target_resource_type = $2)
            ORDER BY timestamp DESC LIMIT $3"#,
    )
    .bind(q.action.as_deref())
    .bind(q.target_resource_type.as_deref())
    .bind(limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| AuditEventResponse {
                id: r.get("id"),
                actor_user_id: r.get("actor_user_id"),
                action: r.get("action"),
                target_resource_type: r.get("target_resource_type"),
                target_resource_id: r.get("target_resource_id"),
                correlation_id: r.get("correlation_id"),
                timestamp: r.get("timestamp"),
            })
            .collect(),
    ))
}

// ── Metrics: `GET /v1/metrics` (Story ) ─────────────────────────

/// `GET /v1/metrics` — Prometheus/OpenMetrics text format (Story ).
/// Exports instruction counts, payment counts, and processing latency.
/// Requires `bank8:payments:metrics:read` scope.
pub async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:metrics:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    let instructions_total: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM instructions")
            .fetch_one(&mut *conn)
            .await
            .map_err(err_db)?;
    let instructions_completed: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM instructions WHERE state = 'completed'",
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let instructions_failed: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM instructions WHERE state = 'failed'",
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let payments_total: i64 = sqlx::query_scalar::<_, i64>("SELECT COUNT(*)::BIGINT FROM payments")
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let payments_completed: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM payments WHERE status = 'completed'",
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    // Average processing latency (seconds) for completed instructions.
    let avg_latency: Option<f64> = sqlx::query_scalar::<_, Option<f64>>(
        r#"SELECT AVG(EXTRACT(EPOCH FROM (completed_at - created_at)))::FLOAT8
             FROM instructions
            WHERE state = 'completed' AND completed_at IS NOT NULL"#,
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    let avg = avg_latency
        .map(|v| format!("{v:.4}"))
        .unwrap_or_else(|| "0".into());
    let body = format!(
        r#"# HELP instructions_total Total number of instructions.
# TYPE instructions_total counter
instructions_total {instructions_total}
# HELP instructions_completed_total Total completed instructions.
# TYPE instructions_completed_total counter
instructions_completed_total {instructions_completed}
# HELP instructions_failed_total Total failed instructions.
# TYPE instructions_failed_total counter
instructions_failed_total {instructions_failed}
# HELP payments_total Total number of payments.
# TYPE payments_total counter
payments_total {payments_total}
# HELP payments_completed_total Total completed payments.
# TYPE payments_completed_total counter
payments_completed_total {payments_completed}
# HELP payments_instruction_processing_latency_seconds_avg Average instruction processing latency in seconds.
# TYPE payments_instruction_processing_latency_seconds_avg gauge
payments_instruction_processing_latency_seconds_avg {avg}
"#
    );
    Ok(body)
}

// ── Integrations API (Story ) ─────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct IntegrationResponse {
    pub id: Uuid,
    pub name: String,
    pub integration_kind: String,
    pub config: serde_json::Value,
    pub auth_config: serde_json::Value,
    pub status: String,
    pub version: i32,
    pub active_version_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateIntegrationRequest {
    pub name: String,
    #[serde(default = "default_integration_kind")]
    pub integration_kind: String,
    #[serde(default = "default_empty_object")]
    pub config: serde_json::Value,
    #[serde(default = "default_empty_object")]
    pub auth_config: serde_json::Value,
}

fn default_integration_kind() -> String {
    "http".into()
}
fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateIntegrationRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub integration_kind: Option<String>,
    #[serde(default)]
    pub config: Option<serde_json::Value>,
    #[serde(default)]
    pub auth_config: Option<serde_json::Value>,
}

const INTEGRATION_COLUMNS: &str = "id, name, integration_kind, config, auth_config, status, version, active_version_id, created_at, updated_at";

fn row_to_integration(row: &sqlx::postgres::PgRow) -> IntegrationResponse {
    IntegrationResponse {
        id: row.get("id"),
        name: row.get("name"),
        integration_kind: row.get("integration_kind"),
        config: row.get("config"),
        auth_config: row.get("auth_config"),
        status: row.get("status"),
        version: row.get("version"),
        active_version_id: row.get("active_version_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// `POST /v1/integrations` — create an integration (Story ).
#[utoipa::path(
    post,
    path = "/v1/integrations",
    request_body = CreateIntegrationRequest,
    responses(
        (status = 200, description = "Integration created", body = IntegrationResponse),
        (status = 403, description = "Missing bank8:payments:integrations:write scope"),
    ),
    security(("bank8:payments:integrations:write" = [])),
    tag = "payments",
)]
pub async fn create_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateIntegrationRequest>,
) -> Result<Json<IntegrationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:integrations:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO integrations
               (env_id, name, integration_kind, config, auth_config, status, version)
           VALUES ($1, $2, $3, $4, $5, 'active', 1)
           RETURNING {INTEGRATION_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(&req.integration_kind)
        .bind(&req.config)
        .bind(&req.auth_config)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let integration_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Integration,
        &integration_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_integration(&row)))
}

/// `GET /v1/integrations` — list integrations (Story ).
#[utoipa::path(
    get,
    path = "/v1/integrations",
    responses(
        (status = 200, description = "List of integrations", body = Vec<IntegrationResponse>),
        (status = 403, description = "Missing bank8:payments:integrations:read scope"),
    ),
    security(("bank8:payments:integrations:read" = [])),
    tag = "payments",
)]
pub async fn list_integrations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<IntegrationResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:integrations:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {INTEGRATION_COLUMNS} FROM integrations WHERE status = 'active' ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_integration).collect()))
}

/// `GET /v1/integrations/{id}` — get an integration (Story ).
#[utoipa::path(
    get,
    path = "/v1/integrations/{id}",
    params(("id" = Uuid, Path, description = "Integration ID")),
    responses(
        (status = 200, description = "Integration detail", body = IntegrationResponse),
        (status = 404, description = "Integration not found"),
        (status = 403, description = "Missing bank8:payments:integrations:read scope"),
    ),
    security(("bank8:payments:integrations:read" = [])),
    tag = "payments",
)]
pub async fn get_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<IntegrationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:integrations:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {INTEGRATION_COLUMNS} FROM integrations WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_integration(&row)))
}

/// `PATCH /v1/integrations/{id}` — update an integration (Story ).
pub async fn update_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateIntegrationRequest>,
) -> Result<Json<IntegrationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:integrations:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"UPDATE integrations
              SET name = COALESCE($2, name),
                  integration_kind = COALESCE($3, integration_kind),
                  config = COALESCE($4, config),
                  auth_config = COALESCE($5, auth_config),
                  version = version + 1,
                  updated_at = now()
            WHERE id = $1 AND status = 'active'
            RETURNING {INTEGRATION_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(req.name.as_deref())
        .bind(req.integration_kind.as_deref())
        .bind(req.config.as_ref())
        .bind(req.auth_config.as_ref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Integration,
        &id.to_string(),
        "updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_integration(&row)))
}

/// `DELETE /v1/integrations/{id}` — soft delete an integration (Story ).
pub async fn delete_integration(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:integrations:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    sqlx::query(
        r#"UPDATE integrations
              SET status = 'inactive',
                  version = version + 1,
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Integration,
        &id.to_string(),
        "deleted",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(serde_json::json!({ "id": id, "status": "inactive" })))
}

// ── Cores API (Story ) ────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct CoreResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCoreRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCoreRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

const CORE_COLUMNS: &str = "id, name, description, status, created_at, updated_at";

fn row_to_core(row: &sqlx::postgres::PgRow) -> CoreResponse {
    CoreResponse {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        status: row.get("status"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// `POST /v1/cores` — create a core (Story ).
#[utoipa::path(
    post,
    path = "/v1/cores",
    request_body = CreateCoreRequest,
    responses(
        (status = 200, description = "Core created", body = CoreResponse),
        (status = 403, description = "Missing bank8:payments:cores:write scope"),
    ),
    security(("bank8:payments:cores:write" = [])),
    tag = "payments",
)]
pub async fn create_core(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCoreRequest>,
) -> Result<Json<CoreResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cores:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO cores
               (env_id, name, description, status)
           VALUES ($1, $2, $3, 'active')
           RETURNING {CORE_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(req.description.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let core_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Core,
        &core_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_core(&row)))
}

/// `GET /v1/cores` — list cores (Story ).
#[utoipa::path(
    get,
    path = "/v1/cores",
    responses(
        (status = 200, description = "List of cores", body = Vec<CoreResponse>),
        (status = 403, description = "Missing bank8:payments:cores:read scope"),
    ),
    security(("bank8:payments:cores:read" = [])),
    tag = "payments",
)]
pub async fn list_cores(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CoreResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cores:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {CORE_COLUMNS} FROM cores WHERE status = 'active' ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_core).collect()))
}

/// `GET /v1/cores/{id}` — get a core (Story ).
#[utoipa::path(
    get,
    path = "/v1/cores/{id}",
    params(("id" = Uuid, Path, description = "Core ID")),
    responses(
        (status = 200, description = "Core detail", body = CoreResponse),
        (status = 404, description = "Core not found"),
        (status = 403, description = "Missing bank8:payments:cores:read scope"),
    ),
    security(("bank8:payments:cores:read" = [])),
    tag = "payments",
)]
pub async fn get_core(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CoreResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cores:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {CORE_COLUMNS} FROM cores WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_core(&row)))
}

/// `PATCH /v1/cores/{id}` — update a core (Story ).
pub async fn update_core(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCoreRequest>,
) -> Result<Json<CoreResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cores:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"UPDATE cores
              SET name = COALESCE($2, name),
                  description = COALESCE($3, description),
                  status = COALESCE($4, status),
                  updated_at = now()
            WHERE id = $1
            RETURNING {CORE_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(req.name.as_deref())
        .bind(req.description.as_deref())
        .bind(req.status.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Core,
        &id.to_string(),
        "updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_core(&row)))
}

/// `DELETE /v1/cores/{id}` — soft delete a core (Story ).
pub async fn delete_core(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cores:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    sqlx::query(
        r#"UPDATE cores
              SET status = 'inactive',
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Core,
        &id.to_string(),
        "deleted",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(serde_json::json!({ "id": id, "status": "inactive" })))
}

// ── Core Versions API (Story ) ────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCoreVersionRequest {
    #[serde(default)]
    pub postings_integration_id: Option<Uuid>,
    #[serde(default)]
    pub balance_integration_id: Option<Uuid>,
}

/// `POST /v1/cores/{id}/versions` — create a core version (Story ).
pub async fn create_core_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(core_id): Path<Uuid>,
    Json(req): Json<CreateCoreVersionRequest>,
) -> Result<Json<crate::cores::CoreVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cores:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    let id = crate::cores::create_core_version(
        &state.pool,
        a.env_id(),
        core_id,
        req.postings_integration_id,
        req.balance_integration_id,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let row = sqlx::query(
        r#"SELECT id, core_id, version, postings_integration_id,
                  balance_integration_id, status, created_at
             FROM core_versions WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let core_version_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::CoreVersion,
        &core_version_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(crate::cores::CoreVersionResponse {
        id: row.get("id"),
        core_id: row.get("core_id"),
        version: row.get("version"),
        postings_integration_id: row.get("postings_integration_id"),
        balance_integration_id: row.get("balance_integration_id"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

// ── Card Issuing API (Story ) ─────────────────────────────────────
// CRUD handlers for cardholders, cards, card products and account ranges.
// Tables: cardholders, cards, card_products,
// account_ranges (see infra/postgres/init/14-payments.sql).

const CARDHOLDER_COLUMN_LIST: &str = "id, customer_id, first_name, last_name, status, created_at";

fn row_to_cardholder(row: &sqlx::postgres::PgRow) -> CardholderResponse {
    CardholderResponse {
        id: row.get("id"),
        customer_id: row.get("customer_id"),
        first_name: row.get("first_name"),
        last_name: row.get("last_name"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CardholderResponse {
    pub id: Uuid,
    pub customer_id: Uuid,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCardholderRequest {
    /// Ledger customer id (by value — Ledger's public API validated it).
    pub customer_id: Uuid,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
}

/// `POST /v1/cardholders` — create a cardholder.
/// .7: `customer_id` is a Ledger customer id (by value; existence is the
/// caller's contract — Ledger owns customer validation via its public API;
/// no cross-schema FK).
pub async fn create_cardholder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCardholderRequest>,
) -> Result<Json<CardholderResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, &a).await;
    let sql = format!(
        r#"INSERT INTO cardholders
               (env_id, customer_id, first_name, last_name, status)
           VALUES ($1, $2, $3, $4, 'active')
           RETURNING {CARDHOLDER_COLUMN_LIST}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(req.customer_id)
        .bind(req.first_name.as_deref())
        .bind(req.last_name.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let cardholder_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Cardholder,
        &cardholder_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_cardholder(&row)))
}

/// `GET /v1/cardholders` — list cardholders.
/// .7: holder callers see only their own cardholders
/// (forced here; RLS is the backstop). Staff/sys/M2M see all active
/// cardholders in the env.
pub async fn list_cardholders(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CardholderResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, &a).await;
    let forced_customer_id = resolve_caller_customer_id(&mut conn, &a).await;
    let sql = if a.is_holder() {
        format!(
            "SELECT {CARDHOLDER_COLUMN_LIST} FROM cardholders WHERE status = 'active' AND customer_id = $1 ORDER BY created_at DESC LIMIT 100"
        )
    } else {
        format!(
            "SELECT {CARDHOLDER_COLUMN_LIST} FROM cardholders WHERE status = 'active' ORDER BY created_at DESC LIMIT 100"
        )
    };
    let q = sqlx::query(&sql);
    let q = if a.is_holder() {
        q.bind(forced_customer_id)
    } else {
        q
    };
    let rows = q.fetch_all(&mut *conn).await.map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_cardholder).collect()))
}

/// `GET /v1/cardholders/{id}` — get a cardholder.
/// .7: holder callers can only fetch their own cardholders.
pub async fn get_cardholder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CardholderResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context_ext(&mut conn, &a).await;
    let sql = format!("SELECT {CARDHOLDER_COLUMN_LIST} FROM cardholders WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    // Defence-in-depth (§4.3c): holder callers can only see their own
    // cardholders.
    if a.is_holder() {
        let row_customer_id: Uuid = row.get("customer_id");
        let caller_customer_id = resolve_caller_customer_id(&mut conn, &a).await;
        if Some(row_customer_id) != caller_customer_id {
            return Err((StatusCode::NOT_FOUND, "cardholder not found".into()));
        }
    }
    Ok(Json(row_to_cardholder(&row)))
}

// ── Cards ──────────────────────────────────────────────────────────────

const CARD_COLUMN_LIST: &str =
    "id, cardholder_id, card_product_id, pan_last_digits, status, expiry_date, card_type, created_at";

fn row_to_card(row: &sqlx::postgres::PgRow) -> CardResponse {
    CardResponse {
        id: row.get("id"),
        cardholder_id: row.get("cardholder_id"),
        card_product_id: row.get("card_product_id"),
        pan_last_digits: row.get("pan_last_digits"),
        status: row.get("status"),
        expiry_date: row.get("expiry_date"),
        card_type: row.get("card_type"),
        created_at: row.get("created_at"),
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CardResponse {
    pub id: Uuid,
    pub cardholder_id: Uuid,
    pub card_product_id: Option<Uuid>,
    pub pan_last_digits: Option<String>,
    pub status: String,
    pub expiry_date: Option<String>,
    pub card_type: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCardRequest {
    pub cardholder_id: Uuid,
    #[serde(default)]
    pub card_product_id: Option<Uuid>,
    /// Full PAN. Only the last 4 digits are stored in `pan_last_digits`; the
    /// full PAN is obfuscated via `cards::CardEncryption` and stored in the
    /// `encrypted_pan` column.
    #[serde(default)]
    pub pan: Option<String>,
    #[serde(default)]
    pub expiry_date: Option<String>,
    #[serde(default)]
    pub card_type: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCardRequest {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub expiry_date: Option<String>,
}

// ── Card operations — encrypted sessions, PIN (Story ) ──────────

#[derive(Debug, Deserialize)]
pub struct CreateEncryptedSessionRequest {
    #[serde(default)]
    pub session_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EncryptedSessionResponse {
    pub session_id: Uuid,
    pub card_id: Uuid,
    pub session_type: String,
    pub session_token: String,
    pub public_key: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyPinRequest {
    pub pin_hash: String,
}

#[derive(Debug, Serialize)]
pub struct PinVerifyResponse {
    pub card_id: Uuid,
    pub verified: bool,
    pub attempts_remaining: i32,
}

#[derive(Debug, Deserialize)]
pub struct ChangePinRequest {
    pub old_pin_hash: String,
    pub new_pin_hash: String,
}

#[derive(Debug, Serialize)]
pub struct PinChangeResponse {
    pub card_id: Uuid,
    pub changed: bool,
}

/// `POST /v1/cards` — create a card.
/// Gated by `FeatureGate::Cards`. The PAN is obfuscated with the
/// placeholder `CardEncryption` before being stored in `encrypted_pan`.
#[utoipa::path(
    post,
    path = "/v1/cards",
    request_body = CreateCardRequest,
    responses(
        (status = 200, description = "Card created", body = CardResponse),
        (status = 403, description = "Missing bank8:payments:cards:write scope"),
    ),
    security(("bank8:payments:cards:write" = [])),
    tag = "payments",
)]
pub async fn create_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCardRequest>,
) -> Result<Json<CardResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Cards)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    let card_type = req.card_type.as_deref().unwrap_or("virtual");
    let pan_last_digits: Option<String> = req.pan.as_ref().map(|p| {
        p.chars()
            .rev()
            .take(4)
            .collect::<String>()
            .chars()
            .rev()
            .collect()
    });
    let encrypted_pan: Option<String> = match &req.pan {
        Some(pan) => {
            let (_, priv_key) = crate::cards::CardEncryption::generate_key_pair();
            crate::cards::CardEncryption::encrypt_pan(pan, priv_key.as_bytes()).ok()
        }
        None => None,
    };

    let sql = format!(
        r#"INSERT INTO cards
               (env_id, cardholder_id, card_product_id,
                pan_last_digits, status, expiry_date, card_type, encrypted_pan)
           VALUES ($1, $2, $3, $4, 'pending_creation', $5, $6, $7)
           RETURNING {CARD_COLUMN_LIST}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(req.cardholder_id)
        .bind(req.card_product_id)
        .bind(pan_last_digits.as_deref())
        .bind(req.expiry_date.as_deref())
        .bind(card_type)
        .bind(encrypted_pan.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let card_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Card,
        &card_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_card(&row)))
}

/// `GET /v1/cards` — list cards.
#[utoipa::path(
    get,
    path = "/v1/cards",
    responses(
        (status = 200, description = "List of cards", body = Vec<CardResponse>),
        (status = 403, description = "Missing bank8:payments:cards:read scope"),
    ),
    security(("bank8:payments:cards:read" = [])),
    tag = "payments",
)]
pub async fn list_cards(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CardResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {CARD_COLUMN_LIST} FROM cards WHERE status <> 'disabled' ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_card).collect()))
}

/// `GET /v1/cards/{id}` — get a card.
#[utoipa::path(
    get,
    path = "/v1/cards/{id}",
    params(("id" = Uuid, Path, description = "Card ID")),
    responses(
        (status = 200, description = "Card detail", body = CardResponse),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:cards:read scope"),
    ),
    security(("bank8:payments:cards:read" = [])),
    tag = "payments",
)]
pub async fn get_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CardResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {CARD_COLUMN_LIST} FROM cards WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_card(&row)))
}

/// `PATCH /v1/cards/{id}` — update a card (status / expiry).
/// When `status` is provided it is validated against the card state machine
/// (`cards::validate_card_transition`) before being applied.
pub async fn update_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCardRequest>,
) -> Result<Json<CardResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    if let Some(ref new_status) = req.status {
        let current: Option<String> = sqlx::query_scalar("SELECT status FROM cards WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?;
        let current =
            current.ok_or_else(|| (StatusCode::NOT_FOUND, format!("card {id} not found")))?;
        let from = crate::cards::CardState::from_str(&current)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let to = crate::cards::CardState::from_str(new_status)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        crate::cards::validate_card_transition(from, to).map_err(|e| (StatusCode::CONFLICT, e))?;
    }

    let sql = format!(
        r#"UPDATE cards
              SET status = COALESCE($2, status),
                  expiry_date = COALESCE($3, expiry_date),
                  updated_at = now()
            WHERE id = $1
            RETURNING {CARD_COLUMN_LIST}"#
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(req.status.as_deref())
        .bind(req.expiry_date.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Card,
        &id.to_string(),
        "updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_card(&row)))
}

/// `POST /v1/cards/{id}/encrypted-session` — create an encrypted card
/// session for sensitive operations (PIN verify/change, 3DS challenge).
/// Story.
pub async fn create_encrypted_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateEncryptedSessionRequest>,
) -> Result<Json<EncryptedSessionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    let session_type =
        crate::cards::EncryptedSessionType::from_str(req.session_type.as_deref().unwrap_or("3ds"))
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let session = crate::cards::create_encrypted_session(&state.pool, a.env_id(), id, session_type)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(EncryptedSessionResponse {
        session_id: session.session_id,
        card_id: session.card_id,
        session_type: session.session_type,
        session_token: session.session_token,
        public_key: session.public_key,
        expires_at: session.expires_at,
    }))
}

/// `POST /v1/cards/{id}/pin/verify` — verify a card PIN.
/// Story . The PIN is already hashed by the caller; Payments compares
/// it against the stored `pin_hash` and increments `pin_attempts` on
/// mismatch, suspending the card after 3 failures.
pub async fn verify_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<VerifyPinRequest>,
) -> Result<Json<PinVerifyResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    let result = crate::cards::verify_pin(&state.pool, id, &req.pin_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(PinVerifyResponse {
        card_id: result.card_id,
        verified: result.verified,
        attempts_remaining: result.attempts_remaining,
    }))
}

/// `POST /v1/cards/{id}/pin/change` — change a card PIN.
/// Story . Verifies `old_pin_hash` against the stored hash; on
/// success replaces it with `new_pin_hash` and resets `pin_attempts`.
pub async fn change_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ChangePinRequest>,
) -> Result<Json<PinChangeResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    let result = crate::cards::change_pin(&state.pool, id, &req.old_pin_hash, &req.new_pin_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(PinChangeResponse {
        card_id: result.card_id,
        changed: result.changed,
    }))
}

// ── Card Products ──────────────────────────────────────────────────────

const CARD_PRODUCT_COLUMN_LIST: &str = "id, name, type, status, account_range_id, created_at";

fn row_to_card_product(row: &sqlx::postgres::PgRow) -> CardProductResponse {
    CardProductResponse {
        id: row.get("id"),
        name: row.get("name"),
        r#type: row.get("type"),
        status: row.get("status"),
        account_range_id: row.get("account_range_id"),
        created_at: row.get("created_at"),
    }
}

#[derive(Debug, Serialize)]
pub struct CardProductResponse {
    pub id: Uuid,
    pub name: String,
    // `type` is a SQL keyword; renamed in JSON via `r#type`.
    #[serde(rename = "type")]
    pub r#type: String,
    pub status: String,
    pub account_range_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCardProductRequest {
    pub name: String,
    pub r#type: String,
    #[serde(default)]
    pub account_range_id: Option<Uuid>,
}

/// `POST /v1/card-products` — create a card product.
pub async fn create_card_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCardProductRequest>,
) -> Result<Json<CardProductResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO card_products
               (env_id, name, type, status, account_range_id)
           VALUES ($1, $2, $3, 'active', $4)
           RETURNING {CARD_PRODUCT_COLUMN_LIST}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(&req.r#type)
        .bind(req.account_range_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let card_product_id: Uuid = row.get("id");

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Card,
        &card_product_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_card_product(&row)))
}

/// `GET /v1/card-products` — list card products.
pub async fn list_card_products(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CardProductResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {CARD_PRODUCT_COLUMN_LIST} FROM card_products WHERE status = 'active' ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_card_product).collect()))
}

/// `GET /v1/card-products/{id}` — get a card product.
pub async fn get_card_product(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CardProductResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {CARD_PRODUCT_COLUMN_LIST} FROM card_products WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_card_product(&row)))
}

// ── Account Ranges ──────────────────────────────────────────────────────

const ACCOUNT_RANGE_COLUMN_LIST: &str =
    "id, card_product_id, bin_range, pan_length, status, created_at";

fn row_to_account_range(row: &sqlx::postgres::PgRow) -> AccountRangeResponse {
    AccountRangeResponse {
        id: row.get("id"),
        card_product_id: row.get("card_product_id"),
        bin_range: row.get("bin_range"),
        pan_length: row.get("pan_length"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

#[derive(Debug, Serialize)]
pub struct AccountRangeResponse {
    pub id: Uuid,
    pub card_product_id: Uuid,
    pub bin_range: String,
    pub pan_length: i32,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAccountRangeRequest {
    pub card_product_id: Uuid,
    pub bin_range: String,
    #[serde(default = "default_pan_length")]
    pub pan_length: i32,
}

fn default_pan_length() -> i32 {
    16
}

/// `POST /v1/account-ranges` — create an account range.
pub async fn create_account_range(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAccountRangeRequest>,
) -> Result<Json<AccountRangeResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO account_ranges
               (env_id, card_product_id, bin_range, pan_length, status)
           VALUES ($1, $2, $3, $4, 'active')
           RETURNING {ACCOUNT_RANGE_COLUMN_LIST}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(req.card_product_id)
        .bind(&req.bin_range)
        .bind(req.pan_length)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_account_range(&row)))
}

/// `GET /v1/account-ranges` — list account ranges.
pub async fn list_account_ranges(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AccountRangeResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {ACCOUNT_RANGE_COLUMN_LIST} FROM account_ranges WHERE status = 'active' ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_account_range).collect()))
}

// ── Health ───────────────────────────────────────────────────────────────

pub async fn health() -> Json<serde_json::Value> {
    Json(
        serde_json::json!({ "status": "ok", "service": "payments", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash() }),
    )
}

// ── Helpers ──────────────────────────────────────────────────────────────

pub(crate) fn row_to_instruction(row: &sqlx::postgres::PgRow) -> InstructionResponse {
    InstructionResponse {
        id: row.get("id"),
        instruction_logic_id: row.get("instruction_logic_id"),
        state: row.get("state"),
        correlation_id: row.get("correlation_id"),
        input: row.get("input"),
        output: row.get("output"),
        created_at: row.get("created_at"),
        completed_at: row.get("completed_at"),
    }
}

fn row_to_payment(row: &sqlx::postgres::PgRow) -> PaymentResponse {
    PaymentResponse {
        id: row.get("id"),
        instruction_id: row.get("instruction_id"),
        payment_type: row.get("payment_type"),
        amount: row.get("amount"),
        currency: row.get("currency"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

pub(crate) fn row_to_logic(row: &sqlx::postgres::PgRow) -> LogicResponse {
    LogicResponse {
        id: row.get("id"),
        name: row.get("name"),
        version: row.get("version"),
        steps: row.get("steps"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

// ── Mandates CRUD (Story ) ──────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct MandateResponse {
    pub id: Uuid,
    pub scheme_creditor_id: Option<String>,
    pub scheme_mandate_id: Option<String>,
    pub debtor_name: Option<String>,
    pub debtor_account: Option<String>,
    pub creditor_name: Option<String>,
    pub creditor_account: Option<String>,
    pub amount_limit: Option<String>,
    pub currency: Option<String>,
    pub status: String,
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateMandateRequest {
    #[serde(default)]
    pub scheme_creditor_id: Option<String>,
    #[serde(default)]
    pub scheme_mandate_id: Option<String>,
    #[serde(default)]
    pub debtor_name: Option<String>,
    #[serde(default)]
    pub debtor_account: Option<String>,
    #[serde(default)]
    pub creditor_name: Option<String>,
    #[serde(default)]
    pub creditor_account: Option<String>,
    #[serde(default)]
    pub amount_limit: Option<String>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMandateRequest {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub amount_limit: Option<String>,
    #[serde(default)]
    pub effective_from: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub effective_to: Option<chrono::DateTime<chrono::Utc>>,
}

const MANDATE_COLUMNS: &str = "id, scheme_creditor_id, scheme_mandate_id, debtor_name, debtor_account, creditor_name, creditor_account, amount_limit, currency, status, effective_from, effective_to, created_at, updated_at";

fn row_to_mandate(row: &sqlx::postgres::PgRow) -> MandateResponse {
    MandateResponse {
        id: row.get("id"),
        scheme_creditor_id: row.get("scheme_creditor_id"),
        scheme_mandate_id: row.get("scheme_mandate_id"),
        debtor_name: row.get("debtor_name"),
        debtor_account: row.get("debtor_account"),
        creditor_name: row.get("creditor_name"),
        creditor_account: row.get("creditor_account"),
        amount_limit: row.get("amount_limit"),
        currency: row.get("currency"),
        status: row.get("status"),
        effective_from: row.get("effective_from"),
        effective_to: row.get("effective_to"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// `POST /v1/mandates` — create a mandate.
#[utoipa::path(
    post,
    path = "/v1/mandates",
    request_body = CreateMandateRequest,
    responses(
        (status = 200, description = "Mandate created", body = MandateResponse),
        (status = 403, description = "Missing bank8:payments:mandates:write scope"),
    ),
    security(("bank8:payments:mandates:write" = [])),
    tag = "payments",
)]
pub async fn create_mandate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateMandateRequest>,
) -> Result<Json<MandateResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Mandates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:mandates:write"),
    )
    .await?;
    // Parse the amount limit once — 400 on invalid input before any DB work.
    let amount_limit: Option<rust_decimal::Decimal> = match req.amount_limit.as_deref() {
        None => None,
        Some(s) if s.trim().is_empty() => None,
        Some(s) => Some(s.trim().parse().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid amount_limit: {e}"),
            )
        })?),
    };
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO mandates
               (env_id, scheme_creditor_id, scheme_mandate_id,
                debtor_name, debtor_account, creditor_name, creditor_account,
                amount_limit, currency, status, effective_from, effective_to)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11)
           RETURNING {MANDATE_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(req.scheme_creditor_id.as_deref())
        .bind(req.scheme_mandate_id.as_deref())
        .bind(req.debtor_name.as_deref())
        .bind(req.debtor_account.as_deref())
        .bind(req.creditor_name.as_deref())
        .bind(req.creditor_account.as_deref())
        .bind(amount_limit)
        .bind(req.currency.as_deref())
        .bind(req.effective_from)
        .bind(req.effective_to)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_mandate(&row)))
}

/// `GET /v1/mandates` — list mandates.
#[utoipa::path(
    get,
    path = "/v1/mandates",
    responses(
        (status = 200, description = "List of mandates", body = Vec<MandateResponse>),
        (status = 403, description = "Missing bank8:payments:mandates:read scope"),
    ),
    security(("bank8:payments:mandates:read" = [])),
    tag = "payments",
)]
pub async fn list_mandates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<MandateResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Mandates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:mandates:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {MANDATE_COLUMNS} FROM mandates ORDER BY created_at DESC LIMIT 100");
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_mandate).collect()))
}

/// `GET /v1/mandates/{id}` — get a mandate.
#[utoipa::path(
    get,
    path = "/v1/mandates/{id}",
    params(("id" = Uuid, Path, description = "Mandate ID")),
    responses(
        (status = 200, description = "Mandate detail", body = MandateResponse),
        (status = 404, description = "Mandate not found"),
        (status = 403, description = "Missing bank8:payments:mandates:read scope"),
    ),
    security(("bank8:payments:mandates:read" = [])),
    tag = "payments",
)]
pub async fn get_mandate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<MandateResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Mandates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:mandates:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {MANDATE_COLUMNS} FROM mandates WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_mandate(&row)))
}

/// `PATCH /v1/mandates/{id}` — update a mandate.
pub async fn update_mandate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateMandateRequest>,
) -> Result<Json<MandateResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Mandates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:mandates:write"),
    )
    .await?;
    // Parse the amount limit once — 400 on invalid input before any DB work.
    let amount_limit: Option<rust_decimal::Decimal> = match req.amount_limit.as_deref() {
        None => None,
        Some(s) if s.trim().is_empty() => None,
        Some(s) => Some(s.trim().parse().map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid amount_limit: {e}"),
            )
        })?),
    };
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"UPDATE mandates
              SET status = COALESCE($2, status),
                  amount_limit = CASE WHEN $3 IS NULL THEN amount_limit ELSE $3 END,
                  effective_from = COALESCE($4, effective_from),
                  effective_to = COALESCE($5, effective_to),
                  updated_at = now()
            WHERE id = $1
            RETURNING {MANDATE_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .bind(req.status.as_deref())
        .bind(amount_limit)
        .bind(req.effective_from)
        .bind(req.effective_to)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_mandate(&row)))
}

// ── Membership Directories CRUD (Story ) ──────────────────────────

#[derive(Debug, Serialize)]
pub struct MembershipDirectoryResponse {
    pub id: Uuid,
    pub name: String,
    pub directory_type: String,
    pub file_id: Option<Uuid>,
    pub status: String,
    pub entries: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateMembershipDirectoryRequest {
    pub name: String,
    pub directory_type: String,
    #[serde(default)]
    pub file_id: Option<Uuid>,
}

const MD_COLUMNS: &str =
    "id, name, directory_type, file_id, status, entries, created_at, updated_at";

fn row_to_membership_directory(row: &sqlx::postgres::PgRow) -> MembershipDirectoryResponse {
    MembershipDirectoryResponse {
        id: row.get("id"),
        name: row.get("name"),
        directory_type: row.get("directory_type"),
        file_id: row.get("file_id"),
        status: row.get("status"),
        entries: row.get("entries"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

/// `POST /v1/membership-directories` — create a membership directory.
pub async fn create_membership_directory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateMembershipDirectoryRequest>,
) -> Result<Json<MembershipDirectoryResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(
        &state.config,
        crate::config::FeatureGate::MembershipDirectories,
    )?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:membership-directories:write"),
    )
    .await?;
    let dir_type = crate::membership_dirs::DirectoryType::from_str(&req.directory_type)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO membership_directories
               (env_id, name, directory_type, file_id, status, entries)
           VALUES ($1, $2, $3, $4, 'pending', '[]'::jsonb)
           RETURNING {MD_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(dir_type.as_str())
        .bind(req.file_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_membership_directory(&row)))
}

/// `GET /v1/membership-directories` — list membership directories.
pub async fn list_membership_directories(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<MembershipDirectoryResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(
        &state.config,
        crate::config::FeatureGate::MembershipDirectories,
    )?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:membership-directories:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {MD_COLUMNS} FROM membership_directories ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_membership_directory).collect()))
}

/// `GET /v1/membership-directories/{id}` — get a membership directory.
pub async fn get_membership_directory(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<MembershipDirectoryResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(
        &state.config,
        crate::config::FeatureGate::MembershipDirectories,
    )?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:membership-directories:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {MD_COLUMNS} FROM membership_directories WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_membership_directory(&row)))
}

// ── Internal API endpoints for proxy-back (Story ) ────
// These endpoints are called by Flow (domain steps) and Func (host
// functions) on behalf of WASM modules. Every endpoint verifies the
// caller's bearer token (the Flow/Func M2M identity or a platform admin)
// and sets the tenant context from the M2M token's `env_id` claim before
// querying — the same convention as Bank8:Ledger's `func-host` endpoint.
// RLS provides the backstop; unauthenticated callers are rejected with 401
// before any DB access.

/// Verify an internal proxy-back caller. Accepts:
/// - a platform-admin M2M token (`sys:admin`), or
/// - a service M2M token carrying the `bank8:payments:internal:read` scope
///
/// (granted to the Flow/Func identities at enrollment).
pub(crate) async fn require_internal_caller(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::auth::AuthContext, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        headers,
        sentin8::shield::EvalTarget::new("bank8:payments:internal:read"),
    )
    .await?;
    Ok(a)
}

/// `GET /v1/internal/instructions/{id}` — internal instruction lookup.
pub async fn get_instruction_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<InstructionResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at
             FROM instructions WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(row_to_instruction(&row)))
}

/// `PATCH /v1/internal/instructions/{id}` — internal instruction update.
/// Updates the instruction's `output` and/or `state` from a Func WASM
/// module. The body is a JSON object with optional `output` and `state`
/// fields; only the provided fields are updated.
#[derive(Debug, Deserialize)]
pub struct UpdateInstructionInternalRequest {
    #[serde(default)]
    pub output: Option<serde_json::Value>,
    #[serde(default)]
    pub state: Option<String>,
}

pub async fn update_instruction_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateInstructionInternalRequest>,
) -> Result<Json<InstructionResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE instructions
              SET output = COALESCE($2, output),
                  state = COALESCE($3, state),
                  completed_at = CASE WHEN $3::text IN ('completed', 'failed', 'cancelled')
                                      THEN now()
                                      ELSE completed_at END
            WHERE id = $1
            RETURNING id, instruction_logic_id, state, correlation_id,
                      input, output, created_at, completed_at"#,
    )
    .bind(id)
    .bind(req.output.as_ref())
    .bind(req.state.as_deref())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Instruction,
        &id.to_string(),
        "updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(row_to_instruction(&row)))
}

/// `GET /v1/internal/payments/{id}` — internal payment lookup.
pub async fn get_payment_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PaymentResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, instruction_id, payment_type, amount, currency, status, created_at
             FROM payments WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(row_to_payment(&row)))
}

/// `GET /v1/internal/payment-instruments/{id}` — internal lookup.
pub async fn get_payment_instrument_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::routing::PaymentInstrumentResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, account_id, bank_identifier, instrument_identifier,
                  status, display_name, routing_information, created_at, updated_at
             FROM payment_instruments WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(crate::routing::row_to_payment_instrument(&row)))
}

/// `GET /v1/internal/account-links/{id}` — internal lookup.
pub async fn get_account_link_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::routing::AccountLinkResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, account_id, payment_instrument_id, core_account_id,
                  is_default, status, display_name, created_at, updated_at
             FROM account_links WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(crate::routing::row_to_account_link(&row)))
}

/// `GET /v1/internal/parameters/{id}` — internal lookup.
pub async fn get_parameter_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ParameterResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {PARAM_COLUMNS} FROM parameters WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_parameter(&row)))
}

/// `GET /v1/internal/rules/{id}` — internal lookup.
pub async fn get_rule_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::rules::RuleResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, name, rule_type, expression, action, status, version,
                  active_version_id, expected_parameters, created_at, updated_at
             FROM rules WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(crate::rules::row_to_rule(&row)))
}

/// `GET /v1/internal/integrations/{id}` — internal lookup.
pub async fn get_integration_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<IntegrationResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {INTEGRATION_COLUMNS} FROM integrations WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_integration(&row)))
}

/// `GET /v1/internal/mandates/{id}` — internal lookup.
pub async fn get_mandate_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<MandateResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {MANDATE_COLUMNS} FROM mandates WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_mandate(&row)))
}

/// `GET /v1/internal/manual-decisions/{id}` — internal lookup.
pub async fn get_manual_decision_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ManualDecisionResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, instruction_id, decision_type, status, submitted_by, submitted_at, created_at
             FROM manual_decisions WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(row_to_manual_decision(&row)))
}

/// `GET /v1/internal/calendars/{id}` — internal lookup.
pub async fn get_calendar_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::calendars::CalendarResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = "SELECT id, name, calendar_type, business_day_definition_id, configuration, timezone, created_at, updated_at FROM calendars WHERE id = $1".to_string();
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(crate::calendars::row_to_calendar(&row)))
}

/// `GET /v1/internal/cards/{id}` — internal lookup.
pub async fn get_card_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CardResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {CARD_COLUMN_LIST} FROM cards WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_card(&row)))
}

/// `GET /v1/internal/cardholders/{id}` — internal lookup.
pub async fn get_cardholder_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CardholderResponse>, (StatusCode, String)> {
    let a = require_internal_caller(&state, &headers).await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {CARDHOLDER_COLUMN_LIST} FROM cardholders WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_cardholder(&row)))
}
// ── Story — Migrate Payments Instruction Logics to WASM via func-client ─

#[derive(Debug, Serialize)]
pub struct MigrateWasmResponse {
    pub logic_id: Uuid,
    pub modules: Vec<MigrationModule>,
}

#[derive(Debug, Serialize)]
pub struct MigrationModule {
    pub step_name: String,
    pub hook: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `POST /v1/logics/{id}/migrate-wasm` — migrate an instruction logic's inline
/// hooks to Func WASM modules (Story ).
/// Loads the logic, walks its steps, and for every `BasicStep` whose
/// `config.hook` is set and `config.wasmModuleId` is absent, creates a
/// Func module from the step's config and uploads it via `func_client`.
/// Returns the list of created module ids (and any per-step errors).
pub async fn migrate_logic_to_wasm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<MigrateWasmResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:logics:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // Load the logic's steps (stored as a JSON array of StepDef objects).
    let steps_json: serde_json::Value =
        sqlx::query_scalar(r#"SELECT steps FROM logics WHERE id = $1"#)
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .map_err(err_db)?;

    let steps = steps_json.as_array().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "logic steps is not an array".into(),
        )
    })?;

    let client = match state.config.func_client.clone() {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::BAD_GATEWAY,
                "Func transport absent (workload certificate not provisioned)".into(),
            ))
        }
    };
    let mut modules: Vec<MigrationModule> = Vec::new();

    for step in steps {
        let kind = step.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "BasicStep" {
            continue;
        }
        let config = step.get("config").and_then(|v| v.as_object());
        let hook = match config.and_then(|c| c.get("hook")).and_then(|v| v.as_str()) {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => continue,
        };
        // Skip steps that already reference a Func module.
        let already_has_module = config
            .and_then(|c| c.get("wasmModuleId"))
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        if already_has_module {
            continue;
        }

        let step_name = step
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Synthesise a Func module from the step's config. The wasm_binary
        // is a placeholder; in production the developer uploads a real WASM
        // artifact via the build-wasm.sh script (Story ) and this
        // endpoint records the module id on the step.
        let upload = sentin8_func_sdk::client::UploadRequest {
            domain: "payments".into(),
            product_id: format!("{}-{}", step_name, hook),
            version_label: "1.0.0".into(),
            wasm_binary: String::new(), // placeholder — real binary uploaded out-of-band
            wasm_language: "assemblyscript".into(),
            wasm_hash: None,
            hooks: vec![hook.clone()],
            parameters: serde_json::json!({}),
            description: Some(format!("Auto-migrated hook for step {step_name}")),
        };

        match client.upload(&upload).await {
            Ok(resp) => {
                let module_id = resp
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                modules.push(MigrationModule {
                    step_name,
                    hook,
                    module_id,
                    error: None,
                });
            }
            Err(e) => {
                modules.push(MigrationModule {
                    step_name,
                    hook,
                    module_id: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    Ok(Json(MigrateWasmResponse {
        logic_id: id,
        modules,
    }))
}

// ── Story — Payments internal endpoint for cron proxy-back ────────

/// `POST /v1/internal/schedules/trigger` — Cron proxy-back for recurring
/// payments and mandates (Story ).
/// Cron calls this endpoint when a registered Payments schedule fires. The
/// request carries the schedule id and the original instruction metadata;
/// Payments creates a new instruction for the recurring payment or mandate
/// collection.
#[derive(Debug, Deserialize)]
pub struct ScheduleTriggerRequest {
    /// The Payments schedule id (registered with Cron).
    pub schedule_id: Uuid,
    /// The logic id to run for this schedule fire.
    pub instruction_logic_id: Option<Uuid>,
    /// The input payload for the new instruction.
    pub input: serde_json::Value,
    /// Optional correlation id for the new instruction.
    #[serde(default)]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScheduleTriggerResponse {
    pub schedule_id: Uuid,
    pub instruction_id: Uuid,
    pub status: String,
}

pub async fn trigger_schedule_internal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ScheduleTriggerRequest>,
) -> Result<Json<ScheduleTriggerResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    // Step 5 — Shield decides. The Cron M2M identity evaluates against the
    // payments sets; the instruction-creating proxy-back is an
    // `instructions:write` action (uniform naming — never a bare `cron:write`).
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    // Create a new instruction for this schedule fire.
    let idempotency_key = crate::idempotency::derive_from_payload(&req.input).to_string();
    let row = sqlx::query(
        r#"INSERT INTO instructions
               (env_id, instruction_logic_id, state,
                idempotency_key, correlation_id, input)
           VALUES ($1, $2, 'pending', $3, $4, $5)
           RETURNING id, state"#,
    )
    .bind(a.env_id())
    .bind(req.instruction_logic_id)
    .bind(&idempotency_key)
    .bind(&req.correlation_id)
    .bind(&req.input)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;

    let instruction_id: Uuid = row.get("id");
    let status: String = row.get("state");
    tx.commit().await.map_err(err_db)?;

    Ok(Json(ScheduleTriggerResponse {
        schedule_id: req.schedule_id,
        instruction_id,
        status,
    }))
}

pub(crate) fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the Graviola PQ crypto provider once — reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    #[test]
    fn update_instruction_internal_request_has_optional_fields() {
        install_provider();
        let req = UpdateInstructionInternalRequest {
            output: None,
            state: None,
        };
        assert!(req.output.is_none());
        assert!(req.state.is_none());
    }

    #[test]
    fn migrate_wasm_response_serializes() {
        install_provider();
        let resp = MigrateWasmResponse {
            logic_id: Uuid::nil(),
            modules: vec![MigrationModule {
                step_name: "validate".into(),
                hook: "validate_pacs008".into(),
                module_id: Some("mod-1".into()),
                error: None,
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["logic_id"], Uuid::nil().to_string());
        assert_eq!(json["modules"][0]["step_name"], "validate");
        assert_eq!(json["modules"][0]["module_id"], "mod-1");
        assert!(json["modules"][0]["error"].is_null());
    }

    #[test]
    fn migrate_wasm_response_skips_none_fields() {
        install_provider();
        let resp = MigrateWasmResponse {
            logic_id: Uuid::nil(),
            modules: vec![MigrationModule {
                step_name: "validate".into(),
                hook: "validate_pacs008".into(),
                module_id: None,
                error: Some("upload failed".into()),
            }],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["modules"][0]["module_id"].is_null());
        assert_eq!(json["modules"][0]["error"], "upload failed");
    }

    #[test]
    fn update_instruction_internal_request_deserializes_partial() {
        install_provider();
        let json = r#"{"state": "completed"}"#;
        let req: UpdateInstructionInternalRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.state.as_deref(), Some("completed"));
        assert!(req.output.is_none());
    }
}
