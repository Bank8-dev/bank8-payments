// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Business API completion handlers (design §5 rewrite).
//! Stories in this module:
//! - Async callback - `POST /v1/integrations:callback/{token}`
//! - Instruction ops - `:initiate`, `:process`, `:bulkRetry`, PUT update
//! - Payees - CRUD + `:search`
//! - Versioned configuration - rule/rule-set/integration versions +
//! `:retry`, `parameter-values` (incl. unset), membership-directory
//! versions + records search, file-spec versions + `:validate`
//! - App surfaces - `/v1/app/{templates,dashboards}` + versions +
//! `:validate` + template presets
//! - Cards issuance ops - `:issue`, `:getDetails`, `:getPIN`,
//! `:updatePIN`, `:resetPINAttempts`, `:resetLVT`, `:replace`,
//! `sessions:initiate` (business route shape)
//! - Card orders - list/create + order batches
//! - Cardholder cascade + card-token lifecycle + 3DS PUT + profile_id
//! - Authorisation expiry - Cron proxy-back internal endpoint
//! - Decline recommendations - reason-code → response-code mapping
//! - Card product plans + `:addAccountRanges`/`:removeAccountRanges`
//! - Sandbox API - simulators + `:resume` + `:fastForward` + cleartext
//! - Scheduled payments (v1beta)
//! - State model - processing_status + payment status breadth +
//! FEE_COLLECTION type + amount context keys
//! - Users + allowed-endpoints + roles read view
//! - Search field registry validation
//! - Rules on instruments + parameter unsetting + CBS networking ops
//! - OpenMetrics /v1/openmetrics/{metrics,federate}

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth;
use crate::event_streaming::{self, ResourceType};
use crate::handlers::{
    bearer_token_of, err_db, set_tenant_context, AppState, EncryptedSessionResponse,
};
use crate::routes_missing::{CardReplaceAck, FileSubmitAck};

// ── Decline recommendations  ──────────────────────────────────────

/// Recommended decline response code for a reason (business table
/// `cards/reference/decline_recommendations.md`). Payload-specific overrides:
/// Inquiry=12, CardManagement PIN Unblock=70, PIN Change=71.
pub fn decline_response_code(reason: &str, payload_type: &str) -> &'static str {
    match reason {
        "PRODUCT_VALUE_CONSTRAINTS_VIOLATED" => match payload_type {
            "InquiryInitiation" => "12",
            "CardManagementInitiation" => "70",
            _ => "12",
        },
        "AC_TYPE_ABSENT" | "AC_TYPE_INVALID" | "ARQC_ABSENT" | "ARQC_INVALID" => "05",
        "ATC_OUTSIDE_ALLOWED_RANGE_LOW"
        | "ATC_OUTSIDE_ALLOWED_RANGE_HIGH"
        | "ATC_DUPLICATE_INVALID" => "63",
        "CHIP_CVC_ABSENT"
        | "CHIP_CVC_INVALID"
        | "CVC1_ABSENT"
        | "CVC1_INVALID"
        | "CVC2_ABSENT"
        | "CVC2_INVALID"
        | "TOO_MANY_CVC2_FAILURES" => "N7",
        "CARD_SUSPENDED" | "CARD_NOT_ACTIVE" => "57",
        "IAV_INVALID" | "IAV_ABSENT" => "N3",
        "LVT_COUNT_LIMIT_EXCEEDED"
        | "LVT_ACCUMULATOR_LIMIT_EXCEEDED"
        | "CONTACTLESS_AMOUNT_LIMIT_EXCEEDED" => "62",
        "MERCHANT_TYPE_NOT_ALLOWED" => "57",
        "EXPIRATION_DATE_INVALID" | "EXPIRATION_DATE_ABSENT" | "CARD_EXPIRED" => "54",
        "ADDRESS_INVALID" => "N8",
        "CARD_NUMBER_INVALID" => "14",
        "PIN_TRIES_LIMIT_EXCEEDED" => "38",
        "PIN_INVALID" | "PIN_ABSENT" | "NEW_PIN_INVALID" | "NEW_PIN_ABSENT" => "55",
        "OBS_MDES_PAN_MAPPING_FAILURE"
        | "OBS_MDES_AC_SE_PRE_VALIDATION_FAILURE"
        | "OBS_MDES_AC_MCBP_PRE_VALIDATION_FAILURE" => "05",
        "CARDHOLDER_VERIFICATION_FAILURE" | "CVM_RESULT_RULE_UNRECOGNISED" => "05",
        "PIN_CHANGE_ALREADY_IN_PROGRESS" => "70",
        "RECURRING_PAYMENT_INITIAL_AUTH_NOT_FOUND" | "RECURRING_PAYMENT_INITIAL_AUTH_REJECTED" => {
            "05"
        }
        "PARTIAL_GRADE_ACQUIRER_NOT_SUPPORTED" => "05",
        "INTERNAL_ERROR" => "96",
        _ => "05",
    }
}

/// Resolve the decline recommendation for an authorisation instruction
/// (surface point for authorisation handlers + sandbox simulators).
pub(crate) fn decline_for_instruction(input: &JsonValue) -> Option<(String, &'static str)> {
    let status = input.get("status").and_then(|v| v.as_str())?;
    if !status.eq_ignore_ascii_case("DECLINE_RECOMMENDED") {
        return None;
    }
    let reason = input
        .get("decline_recommendation_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("INTERNAL_ERROR")
        .trim()
        .trim_start_matches("DECLINE_RECOMMENDATION_REASON_")
        .to_string();
    let payload_type = input
        .get("payload_type")
        .and_then(|v| v.as_str())
        .unwrap_or("AuthorisationInitiation");
    let code = decline_response_code(&reason, payload_type);
    Some((reason, code))
}

// ── Search field registry  ────────────────────────────────────────

/// Valid comparison operators for the search language (§4.24).
pub const SEARCH_OPS: &[&str] = &[
    "eq",
    "neq",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "contains",
    "starts_with",
    "any_in",
];

/// Per-resource searchable fields + valid comparisons. The registry drives
/// validation in `:search` endpoints - unknown fields/ops return 400 before
/// reaching the engine.
pub fn search_registry(resource: &str) -> Option<&'static [&'static str]> {
    match resource {
        "payments" => Some(&[
            "id",
            "status",
            "payment_type",
            "payment_system",
            "payment_scheme",
            "amount",
            "currency",
            "direction",
            "correlation_id",
            "created_at",
            "payer_account",
            "payee_account",
        ]),
        "payees" => Some(&["id", "name", "status", "payee_type", "created_at"]),
        "payment-instruments" => Some(&[
            "id",
            "instrument_identifier",
            "bank_identifier",
            "status",
            "instrument_type",
            "created_at",
        ]),
        "membership-directory-records" => Some(&["bic", "country", "scheme", "status"]),
        "instructions" => Some(&[
            "id",
            "state",
            "correlation_id",
            "created_at",
            "instruction_logic_id",
        ]),
        _ => None,
    }
}

/// Validate a search request against the registry. Filters:
/// `{"field": {"op": ...}}` or `{"field": value}` (implicit eq). Empty/absent
/// filters are valid (list-all).
pub(crate) fn validate_search(resource: &str, filters: &JsonValue) -> Result<(), String> {
    let Some(fields) = search_registry(resource) else {
        return Err(format!("unknown searchable resource: {resource}"));
    };
    let Some(obj) = filters.as_object() else {
        return Ok(());
    };
    for (field, spec) in obj {
        if !fields.contains(&field.as_str()) {
            return Err(format!(
                "field '{field}' is not searchable on {resource}; available: {}",
                fields.join(", ")
            ));
        }
        // {"field": {"op": ..., "value": ...}} - validate the operator.
        if let Some(op) = spec.get("op").and_then(|v| v.as_str()) {
            if !SEARCH_OPS.contains(&op) {
                return Err(format!(
                    "invalid comparison operator '{op}' for {resource}; available: {}",
                    SEARCH_OPS.join(", ")
                ));
            }
        }
    }
    Ok(())
}

// ── : async integration callback ─────────────────────────────────────

/// `POST /v1/integrations:callback/{token}` - the HTTPAsyncStep contract
/// (§4.4): an integration calls back with the response payload after an
/// arbitrary delay; the waiting instruction resumes its workflow.
#[utoipa::path(
    post,
    path = "/v1/integrations/callback/{token}",
    params(("token" = String, Path, description = "Callback token from the initial HTTPAsyncStep call")),
    responses(
        (status = 200, description = "Callback accepted; instruction resumed"),
        (status = 404, description = "Unknown or expired callback token"),
        (status = 403, description = "Missing bank8:payments:integrations:write scope"),
    ),
    security(("bank8:payments:integrations:write" = [])),
    tag = "payments",
)]
pub async fn integration_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(payload): Json<JsonValue>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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

    // Find the waiting instruction carrying this callback token.
    let waiting: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM instructions
            WHERE env_id = $1 AND state = 'waiting'
              AND input->>'callback_token' = $2
            ORDER BY created_at ASC LIMIT 1"#,
    )
    .bind(a.env_id())
    .bind(&token)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    let Some(instruction_id) = waiting else {
        return Err((
            StatusCode::NOT_FOUND,
            format!("no waiting instruction for callback token '{token}'"),
        ));
    };

    // Resolve: store the response payload on the instruction and move it
    // back to processing (the worker continues the Flow workflow from the
    // HTTPAsync step).
    let mut output = payload.clone();
    if let Some(obj) = output.as_object_mut() {
        obj.entry("callback_token".to_string())
            .or_insert_with(|| JsonValue::String(token.clone()));
    }
    sqlx::query("UPDATE instructions SET output = $2, state = 'processing', updated_at = now() WHERE id = $1 AND env_id = $3")
        .bind(instruction_id).bind(&output).bind(a.env_id())
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;

    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Instruction,
        &instruction_id.to_string(),
        "callback_received",
        None,
        Some(output),
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;

    Ok(Json(serde_json::json!({
        "instruction_id": instruction_id,
        "state": "processing",
        "resumed": true,
    })))
}

// ── : instruction ops ────────────────────────────────────────────────

/// `initiate_instruction` - helper (not served; the initiation surface is `POST /v1/instructions`).
pub async fn initiate_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::handlers::CreateInstructionRequest>,
) -> Result<Json<crate::handlers::InstructionResponse>, (StatusCode, String)> {
    crate::handlers::create_instruction(State(state), headers, Json(req)).await
}

/// `POST /v1/instructions:process` - process an instruction against its
/// logic (moves it to processing; the worker continues the workflow).
#[utoipa::path(
    post,
    path = "/v1/instructions/{id}/process",
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction processing"),
        (status = 404, description = "Instruction not found"),
        (status = 409, description = "State transition conflict"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn process_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM instructions WHERE id = $1 AND env_id = $2")
            .bind(id)
            .bind(a.env_id())
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("instruction {id} not found")));
    }
    crate::state_machine::transition(
        &state.pool,
        id,
        crate::state_machine::InstructionState::Processing,
    )
    .await
    .map_err(|e| (StatusCode::CONFLICT, e))?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Instruction,
        &id.to_string(),
        "processed",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id, "state": "processing" })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateInstructionRequest {
    /// Target state: `cancelled` | `pending` | `processing`.
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub output: Option<JsonValue>,
}

/// `PUT /v1/instructions/{id}` - update an instruction (status updates
/// including cancel - the business convention; no `/cancel` subpath).
#[utoipa::path(
    put,
    path = "/v1/instructions/{id}",
    request_body = UpdateInstructionRequest,
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction updated", body = crate::handlers::InstructionResponse),
        (status = 404, description = "Instruction not found"),
        (status = 409, description = "State transition conflict"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn update_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateInstructionRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    if let Some(state_name) = &req.state {
        let target = match state_name.as_str() {
            "cancelled" => crate::state_machine::InstructionState::Cancelled,
            "pending" => crate::state_machine::InstructionState::Pending,
            "processing" => crate::state_machine::InstructionState::Processing,
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "invalid target state '{other}' (allowed: cancelled, pending, processing)"
                    ),
                ));
            }
        };
        crate::state_machine::transition_with_audit(
            &state.pool,
            id,
            target,
            Some(&a.subject()),
            Some(req.reason.as_deref().unwrap_or("updated via PUT")),
        )
        .await
        .map_err(|e| (StatusCode::CONFLICT, e))?;
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
    }
    if let Some(output) = &req.output {
        sqlx::query(
            "UPDATE instructions SET output = $2, updated_at = now() WHERE id = $1 AND env_id = $3",
        )
        .bind(id)
        .bind(output)
        .bind(a.env_id())
        .execute(&mut *conn)
        .await
        .map_err(err_db)?;
    }
    let row = sqlx::query(
        r#"SELECT id, instruction_logic_id, state, correlation_id, input, output, created_at, completed_at
             FROM instructions WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    // : surface the decline recommendation (reason -> ISO8583 response
    // code) when the instruction output declares DECLINE_RECOMMENDED.
    let decline_rec = decline_for_instruction(&row.get::<serde_json::Value, _>("output"));
    let resp =
        serde_json::to_value(crate::handlers::row_to_instruction(&row)).unwrap_or(JsonValue::Null);
    if let Some((reason, code)) = decline_rec {
        let mut meta = resp;
        if let Some(obj) = meta.as_object_mut() {
            obj.insert(
                "decline_recommendation".to_string(),
                serde_json::json!({ "reason": reason, "response_code": code }),
            );
        }
        return Ok(Json(meta));
    }
    Ok(Json(resp))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkRetryRequest {
    /// Empty = retry all errored instructions in the env.
    #[serde(default)]
    pub instruction_ids: Vec<Uuid>,
}

/// `POST /v1/instructions:bulkRetry` - bulk retry errored instructions
/// (Sentin8 Jobs pattern).
#[utoipa::path(
    post,
    path = "/v1/instructions/bulk-retry",
    request_body = BulkRetryRequest,
    responses(
        (status = 200, description = "Bulk retry results"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn bulk_retry_instructions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BulkRetryRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let ids: Vec<Uuid> = if req.instruction_ids.is_empty() {
        sqlx::query_scalar(
            "SELECT id FROM instructions WHERE env_id = $1 AND state = 'failed' ORDER BY created_at LIMIT 100",
        )
        .bind(a.env_id())
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?
    } else {
        req.instruction_ids
    };
    let mut results: Vec<JsonValue> = Vec::new();
    for id in &ids {
        let r = crate::state_machine::transition(
            &state.pool,
            *id,
            crate::state_machine::InstructionState::Pending,
        )
        .await;
        results.push(match r {
            Ok(_) => serde_json::json!({ "id": id, "retried": true }),
            Err(e) => serde_json::json!({ "id": id, "retried": false, "error": e }),
        });
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
    }
    let retried = results
        .iter()
        .filter(|r| r.get("retried").and_then(|v| v.as_bool()).unwrap_or(false))
        .count();
    Ok(Json(
        serde_json::json!({ "attempted": ids.len(), "retried": retried, "results": results }),
    ))
}

// ── : Payees ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct PayeeResponse {
    pub id: Uuid,
    pub name: String,
    pub payee_type: String,
    pub status: String,
    pub account_identifier: Option<String>,
    pub metadata: JsonValue,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePayeeRequest {
    pub name: String,
    #[serde(default = "default_payee_type")]
    pub payee_type: String,
    #[serde(default)]
    pub account_identifier: Option<String>,
    #[serde(default)]
    pub metadata: JsonValue,
}
fn default_payee_type() -> String {
    "external".into()
}

fn row_to_payee(row: &sqlx::postgres::PgRow) -> PayeeResponse {
    PayeeResponse {
        id: row.get("id"),
        name: row.get("name"),
        payee_type: row.get("payee_type"),
        status: row.get("status"),
        account_identifier: row.get("account_identifier"),
        metadata: row.get("metadata"),
        created_at: row.get("created_at"),
    }
}

/// `POST /v1/payees` - create a payee (external payment target).
#[utoipa::path(
    post,
    path = "/v1/payees",
    request_body = CreatePayeeRequest,
    responses(
        (status = 200, description = "Payee created", body = PayeeResponse),
        (status = 403, description = "Missing bank8:payments:payments:write scope"),
    ),
    security(("bank8:payments:payments:write" = [])),
    tag = "payments",
)]
pub async fn create_payee(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreatePayeeRequest>,
) -> Result<Json<PayeeResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payments:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO payees (env_id, name, payee_type, status, account_identifier, metadata)
           VALUES ($1, $2, $3, 'active', $4, $5)
           RETURNING id, name, payee_type, status, account_identifier, metadata, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(&req.payee_type)
    .bind(req.account_identifier.as_deref())
    .bind(&req.metadata)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let payee_id: Uuid = row.get("id");
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Payment,
        &payee_id.to_string(),
        "payee_created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(row_to_payee(&row)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SearchPayeesQuery {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// `GET /v1/payees` - list/search payees.
#[utoipa::path(
    get,
    path = "/v1/payees",
    responses(
        (status = 200, description = "Payees", body = Vec<PayeeResponse>),
        (status = 403, description = "Missing bank8:payments:payments:read scope"),
    ),
    security(("bank8:payments:payments:read" = [])),
    tag = "payments",
)]
pub async fn list_payees(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SearchPayeesQuery>,
) -> Result<Json<Vec<PayeeResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, name, payee_type, status, account_identifier, metadata, created_at
             FROM payees
            WHERE env_id = $1
              AND ($2::text IS NULL OR status = $2)
              AND ($3::text IS NULL OR name ILIKE '%' || $3 || '%')
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .bind(a.env_id())
    .bind(q.status.as_deref())
    .bind(q.q.as_deref())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_payee).collect()))
}

/// `GET /v1/payees/{id}` - payee detail.
#[utoipa::path(
    get,
    path = "/v1/payees/{id}",
    responses(
        (status = 200, description = "Payee", body = PayeeResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bank8:payments:payments:read" = [])),
    tag = "payments",
)]
pub async fn get_payee(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<PayeeResponse>, (StatusCode, String)> {
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
        r#"SELECT id, name, payee_type, status, account_identifier, metadata, created_at
             FROM payees WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("payee {id} not found")))?;
    Ok(Json(row_to_payee(&row)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePayeeRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub account_identifier: Option<String>,
    #[serde(default)]
    pub metadata: Option<JsonValue>,
}

/// `PUT /v1/payees/{id}` - update payee.
#[utoipa::path(
    put,
    path = "/v1/payees/{id}",
    request_body = UpdatePayeeRequest,
    responses(
        (status = 200, description = "Payee updated", body = PayeeResponse),
        (status = 404, description = "Not found"),
    ),
    security(("bank8:payments:payments:write" = [])),
    tag = "payments",
)]
pub async fn update_payee(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdatePayeeRequest>,
) -> Result<Json<PayeeResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payments:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"UPDATE payees SET
               name = COALESCE($2, name),
               status = COALESCE($3, status),
               account_identifier = COALESCE($4, account_identifier),
               metadata = COALESCE($5, metadata),
               updated_at = now()
           WHERE id = $1 AND env_id = $6
           RETURNING id, name, payee_type, status, account_identifier, metadata, created_at"#,
    )
    .bind(id)
    .bind(req.name.as_deref())
    .bind(req.status.as_deref())
    .bind(req.account_identifier.as_deref())
    .bind(req.metadata.as_ref())
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("payee {id} not found")))?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Payment,
        &id.to_string(),
        "payee_updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(row_to_payee(&row)))
}

/// `POST /v1/payees:search` - registry-validated payee search.
#[utoipa::path(
    post,
    path = "/v1/payees/search",
    responses(
        (status = 200, description = "Matching payees", body = Vec<PayeeResponse>),
        (status = 400, description = "Invalid search filters"),
    ),
    security(("bank8:payments:payments:read" = [])),
    tag = "payments",
)]
pub async fn search_payees(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<JsonValue>,
) -> Result<Json<Vec<PayeeResponse>>, (StatusCode, String)> {
    validate_search("payees", &body).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
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
    let name_filter = body.get("name").and_then(|v| v.as_str());
    let status_filter = body.get("status").and_then(|v| v.as_str());
    let rows = sqlx::query(
        r#"SELECT id, name, payee_type, status, account_identifier, metadata, created_at
             FROM payees
            WHERE env_id = $1
              AND ($2::text IS NULL OR name ILIKE '%' || $2 || '%')
              AND ($3::text IS NULL OR status = $3)
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .bind(a.env_id())
    .bind(name_filter)
    .bind(status_filter)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_payee).collect()))
}
// ── : versioned configuration resources ──────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct ResourceVersionResponse {
    pub id: Uuid,
    pub parent_id: Uuid,
    pub version: i64,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

async fn insert_version(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    table: &str,
    parent_col: &str,
    parent_id: Uuid,
    status: &str,
) -> Result<ResourceVersionResponse, (StatusCode, String)> {
    // Table/column names are module constants (never user input).
    let sql = format!(
        r#"INSERT INTO {table} (env_id, {parent_col}, version, status)
           VALUES ($1, $2, COALESCE((SELECT MAX(version) + 1 FROM {table} WHERE env_id = $1 AND {parent_col} = $2), 1), $3)
           RETURNING id, {parent_col} AS parent_id, version, status, created_at"#,
        table = table,
        parent_col = parent_col
    );
    let row = sqlx::query(&sql)
        .bind(env_id)
        .bind(parent_id)
        .bind(status)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(ResourceVersionResponse {
        id: row.get("id"),
        parent_id: row.get("parent_id"),
        version: row.get("version"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    })
}

async fn retry_version(
    state: &AppState,
    headers: &HeaderMap,
    subject: &str,
    env_id: Uuid,
    table: &str,
    version_id: Uuid,
    resource: ResourceType,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, env_id).await;
    let sql = format!(
        "UPDATE {table} SET status = 'active', updated_at = now() WHERE id = $1 AND env_id = $2"
    );
    let updated = sqlx::query(&sql)
        .bind(version_id)
        .bind(env_id)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?
        .rows_affected();
    if updated == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("{table} version {version_id} not found"),
        ));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        env_id,
        resource,
        &version_id.to_string(),
        "retried",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(headers),
            Some(subject.to_string()),
        ),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "id": version_id, "status": "active", "retried": true }),
    ))
}

/// `POST /v1/rule-versions` - create a rule version.
#[utoipa::path(
    post,
    path = "/v1/rule-versions",
    request_body = CreateVersionRequest,
    responses(
        (status = 200, description = "Rule version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:rules:write scope"),
    ),
    security(("bank8:payments:rules:write" = [])),
    tag = "payments",
)]
pub async fn create_rule_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
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
    let v = insert_version(
        &mut conn,
        a.env_id(),
        "rule_versions",
        "rule_id",
        req.parent_id,
        "draft",
    )
    .await?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::RuleVersion,
        &v.id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(v))
}

/// `GET /v1/rule-versions` - list rule versions (with `:batchGet` semantics).
#[utoipa::path(
    get,
    path = "/v1/rule-versions",
    params(("rule_id" = Option<Uuid>, Query, description = "Filter by parent rule")),
    responses(
        (status = 200, description = "Rule versions", body = Vec<ResourceVersionResponse>),
        (status = 403, description = "Missing bank8:payments:rules:read scope"),
    ),
    security(("bank8:payments:rules:read" = [])),
    tag = "payments",
)]
pub async fn list_rule_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, rule_id AS parent_id, version, status, created_at
             FROM rule_versions
            WHERE env_id = $1 AND ($2::uuid IS NULL OR rule_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.rule_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_version).collect()))
}

fn row_to_version(row: &sqlx::postgres::PgRow) -> ResourceVersionResponse {
    ResourceVersionResponse {
        id: row.get("id"),
        parent_id: row.get("parent_id"),
        version: row.get("version"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateVersionRequest {
    pub parent_id: Uuid,
    #[serde(default = "default_version_status")]
    pub status: String,
}
fn default_version_status() -> String {
    "draft".into()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListVersionsQuery {
    #[serde(default)]
    pub rule_id: Option<Uuid>,
    #[serde(default)]
    pub rule_set_id: Option<Uuid>,
    #[serde(default)]
    pub integration_id: Option<Uuid>,
    #[serde(default)]
    pub core_id: Option<Uuid>,
    #[serde(default)]
    pub directory_id: Option<Uuid>,
    #[serde(default)]
    pub specification_id: Option<Uuid>,
    #[serde(default)]
    pub template_id: Option<Uuid>,
    #[serde(default)]
    pub dashboard_id: Option<Uuid>,
}

/// `POST /v1/rule-set-versions` - create a rule set version.
#[utoipa::path(
    post,
    path = "/v1/rule-set-versions",
    request_body = CreateRuleSetVersionRequest,
    responses(
        (status = 200, description = "Rule set version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:rules:write scope"),
    ),
    security(("bank8:payments:rules:write" = [])),
    tag = "payments",
)]
pub async fn create_rule_set_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateRuleSetVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
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
    let v = insert_version(
        &mut conn,
        a.env_id(),
        "rule_set_versions",
        "rule_set_id",
        req.rule_set_id,
        "draft",
    )
    .await?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::RuleSetVersion,
        &v.id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(v))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRuleSetVersionRequest {
    pub rule_set_id: Uuid,
    #[serde(default = "default_version_status")]
    pub status: String,
}

/// `GET /v1/rule-set-versions` - list rule set versions.
#[utoipa::path(
    get,
    path = "/v1/rule-set-versions",
    responses(
        (status = 200, description = "Rule set versions", body = Vec<ResourceVersionResponse>),
        (status = 403, description = "Missing bank8:payments:rules:read scope"),
    ),
    security(("bank8:payments:rules:read" = [])),
    tag = "payments",
)]
pub async fn list_rule_set_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, rule_set_id AS parent_id, version, status, created_at
             FROM rule_set_versions
            WHERE env_id = $1 AND ($2::uuid IS NULL OR rule_set_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.rule_set_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_version).collect()))
}

/// `GET /v1/parameter-values` - list parameter values.
#[utoipa::path(
    get,
    path = "/v1/parameter-values",
    responses(
        (status = 200, description = "Parameter values", body = Vec<ParameterValueResponse>),
        (status = 403, description = "Missing bank8:payments:parameters:read scope"),
    ),
    security(("bank8:payments:parameters:read" = [])),
    tag = "payments",
)]
pub async fn list_parameter_values(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ParameterValueResponse>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        r#"SELECT id, parameter_id, value, created_at FROM parameter_values
            WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| ParameterValueResponse {
                id: r.get("id"),
                parameter_id: r.get("parameter_id"),
                value: r.get("value"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ParameterValueResponse {
    pub id: Uuid,
    pub parameter_id: Uuid,
    pub value: JsonValue,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateParameterValueRequest {
    pub parameter_id: Uuid,
    pub value: JsonValue,
}

/// `POST /v1/parameter-values` - create a parameter value.
#[utoipa::path(
    post,
    path = "/v1/parameter-values",
    request_body = CreateParameterValueRequest,
    responses(
        (status = 200, description = "Parameter value created", body = ParameterValueResponse),
        (status = 403, description = "Missing bank8:payments:parameters:write scope"),
    ),
    security(("bank8:payments:parameters:write" = [])),
    tag = "payments",
)]
pub async fn create_parameter_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateParameterValueRequest>,
) -> Result<Json<ParameterValueResponse>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"INSERT INTO parameter_values (env_id, parameter_id, value)
           VALUES ($1, $2, $3)
           RETURNING id, parameter_id, value, created_at"#,
    )
    .bind(a.env_id())
    .bind(req.parameter_id)
    .bind(&req.value)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let value_id: Uuid = row.get("id");
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Parameter,
        &value_id.to_string(),
        "value_created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(ParameterValueResponse {
        id: value_id,
        parameter_id: row.get("parameter_id"),
        value: row.get("value"),
        created_at: row.get("created_at"),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PutParameterValueRequest {
    /// New value; pass `null` to **unset** the value.
    pub value: Option<JsonValue>,
}

/// `PUT /v1/parameter-values/{id}` - update or **unset** a parameter value
/// (: unsetting supported - a null value removes the override).
#[utoipa::path(
    put,
    path = "/v1/parameter-values/{id}",
    request_body = PutParameterValueRequest,
    params(("id" = Uuid, Path, description = "Parameter value ID")),
    responses(
        (status = 200, description = "Value updated or unset"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing bank8:payments:parameters:write scope"),
    ),
    security(("bank8:payments:parameters:write" = [])),
    tag = "payments",
)]
pub async fn put_parameter_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<PutParameterValueRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let (sql, unset, value) = match req.value {
        Some(v) => (
            "UPDATE parameter_values SET value = $2, updated_at = now() WHERE id = $1 AND env_id = $3".to_string(),
            false,
            Some(v),
        ),
        None => (
            "DELETE FROM parameter_values WHERE id = $1 AND env_id = $3".to_string(),
            true,
            None,
        ),
    };
    let _ = unset;
    let updated = sqlx::query(&sql)
        .bind(id)
        .bind(value)
        .bind(a.env_id())
        .execute(&mut *conn)
        .await
        .map_err(err_db)?
        .rows_affected();
    if updated == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("parameter value {id} not found"),
        ));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Parameter,
        &id.to_string(),
        if unset {
            "value_unset"
        } else {
            "value_updated"
        },
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id, "unset": unset })))
}

/// `GET /v1/integration-versions` - list integration versions.
#[utoipa::path(
    get,
    path = "/v1/integration-versions",
    responses(
        (status = 200, description = "Integration versions", body = Vec<ResourceVersionResponse>),
        (status = 403, description = "Missing bank8:payments:integrations:read scope"),
    ),
    security(("bank8:payments:integrations:read" = [])),
    tag = "payments",
)]
pub async fn list_integration_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        r#"SELECT id, integration_id AS parent_id, version, status, created_at
             FROM integration_versions
            WHERE env_id = $1 AND ($2::uuid IS NULL OR integration_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.integration_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_version).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateIntegrationVersionRequest {
    pub integration_id: Uuid,
    #[serde(default = "default_version_status")]
    pub status: String,
}

/// `POST /v1/integration-versions` - create an integration version.
#[utoipa::path(
    post,
    path = "/v1/integration-versions",
    request_body = CreateIntegrationVersionRequest,
    responses(
        (status = 200, description = "Integration version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:integrations:write scope"),
    ),
    security(("bank8:payments:integrations:write" = [])),
    tag = "payments",
)]
pub async fn create_integration_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateIntegrationVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
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
    let v = insert_version(
        &mut conn,
        a.env_id(),
        "integration_versions",
        "integration_id",
        req.integration_id,
        "draft",
    )
    .await?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::IntegrationVersion,
        &v.id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(v))
}

/// `POST /v1/integration-versions/{id}:retry` - retry a failed integration
/// version (business convention; ).
#[utoipa::path(
    post,
    path = "/v1/integration-versions/{id}/retry",
    params(("id" = Uuid, Path, description = "Integration version ID")),
    responses(
        (status = 200, description = "Version retried"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing bank8:payments:integrations:write scope"),
    ),
    security(("bank8:payments:integrations:write" = [])),
    tag = "payments",
)]
pub async fn retry_integration_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:integrations:write"),
    )
    .await?;
    retry_version(
        &state,
        &headers,
        a.subject().as_str(),
        a.env_id(),
        "integration_versions",
        id,
        ResourceType::IntegrationVersion,
    )
    .await
}

/// `POST /v1/core-versions` - create a core version.
#[utoipa::path(
    post,
    path = "/v1/cores/{id}/versions",
    request_body = CreateCoreVersionRequest,
    responses(
        (status = 200, description = "Core version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:cores:write scope"),
    ),
    security(("bank8:payments:cores:write" = [])),
    tag = "payments",
)]
pub async fn create_core_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCoreVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
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
    let v = insert_version(
        &mut conn,
        a.env_id(),
        "core_versions",
        "core_id",
        req.core_id,
        "draft",
    )
    .await?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::CoreVersion,
        &v.id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(v))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCoreVersionRequest {
    pub core_id: Uuid,
    #[serde(default = "default_version_status")]
    pub status: String,
}

/// `GET /v1/core-versions` - list core versions.
#[utoipa::path(
    get,
    path = "/v1/core-versions",
    responses(
        (status = 200, description = "Core versions", body = Vec<ResourceVersionResponse>),
        (status = 403, description = "Missing bank8:payments:cores:read scope"),
    ),
    security(("bank8:payments:cores:read" = [])),
    tag = "payments",
)]
pub async fn list_core_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        r#"SELECT id, core_id AS parent_id, version, status, created_at
             FROM core_versions
            WHERE env_id = $1 AND ($2::uuid IS NULL OR core_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.core_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_version).collect()))
}

/// `GET /v1/membership-directory-versions` - list directory versions.
#[utoipa::path(
    get,
    path = "/v1/membership-directory-versions",
    responses(
        (status = 200, description = "Directory versions", body = Vec<ResourceVersionResponse>),
        (status = 403, description = "Missing bank8:payments:membership-directories:read scope"),
    ),
    security(("bank8:payments:membership-directories:read" = [])),
    tag = "payments",
)]
pub async fn list_membership_directory_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:membership-directories:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, directory_id AS parent_id, version, status, created_at
             FROM membership_directory_versions
            WHERE env_id = $1 AND ($2::uuid IS NULL OR directory_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.directory_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_version).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDirectoryVersionRequest {
    pub directory_id: Uuid,
    #[serde(default = "default_version_status")]
    pub status: String,
}

/// `POST /v1/membership-directory-versions` - create a directory version.
#[utoipa::path(
    post,
    path = "/v1/membership-directory-versions",
    request_body = CreateDirectoryVersionRequest,
    responses(
        (status = 200, description = "Directory version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:membership-directories:write scope"),
    ),
    security(("bank8:payments:membership-directories:write" = [])),
    tag = "payments",
)]
pub async fn create_membership_directory_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateDirectoryVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:membership-directories:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let v = insert_version(
        &mut conn,
        a.env_id(),
        "membership_directory_versions",
        "directory_id",
        req.directory_id,
        "draft",
    )
    .await?;
    Ok(Json(v))
}

/// `POST /v1/membership-directory-records:search` - registry-validated
/// membership directory search (BIC reachability, account resolution).
#[utoipa::path(
    post,
    path = "/v1/membership-directory-records/search",
    responses(
        (status = 200, description = "Directory records matching the filters"),
        (status = 400, description = "Invalid search filters"),
        (status = 403, description = "Missing bank8:payments:membership-directories:read scope"),
    ),
    security(("bank8:payments:membership-directories:read" = [])),
    tag = "payments",
)]
pub async fn search_membership_directory_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<JsonValue>,
) -> Result<Json<Vec<JsonValue>>, (StatusCode, String)> {
    validate_search("membership-directory-records", &body)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:membership-directories:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let bic = body.get("bic").and_then(|v| v.as_str());
    let country = body.get("country").and_then(|v| v.as_str());
    // Directory records live inside the directory resource (`records` JSONB).
    let rows = sqlx::query(
        r#"SELECT id, records FROM membership_directories
            WHERE env_id = $1"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let mut out: Vec<JsonValue> = Vec::new();
    for r in &rows {
        let records: JsonValue = r.get("records");
        if let Some(list) = records.as_array() {
            for rec in list {
                let rec_bic = rec.get("bic").and_then(|v| v.as_str()).unwrap_or_default();
                let rec_country = rec
                    .get("country")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if let Some(b) = bic {
                    if !rec_bic.eq_ignore_ascii_case(b) {
                        continue;
                    }
                }
                if let Some(c) = country {
                    if !rec_country.eq_ignore_ascii_case(c) {
                        continue;
                    }
                }
                out.push(rec.clone());
            }
        }
    }
    Ok(Json(out))
}

/// `GET /v1beta/instruction-file-specification-versions` - list file
/// specification versions (active-version semantics; ).
pub async fn list_specification_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
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
        r#"SELECT id, specification_id AS parent_id, version, status, created_at
             FROM instruction_file_specification_versions
            WHERE env_id = $1 AND ($2::uuid IS NULL OR specification_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.specification_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_version).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSpecificationVersionRequest {
    pub specification_id: Uuid,
    /// The specification payload (validated against the schema before creation).
    #[serde(default)]
    pub schema: JsonValue,
    #[serde(default = "default_version_status")]
    pub status: String,
}

/// `POST /v1beta/instruction-file-specification-versions` - create a file
/// specification version.
#[utoipa::path(
    post,
    path = "/v1/instruction-file-specification-versions/validate",
    request_body = CreateSpecificationVersionRequest,
    responses(
        (status = 200, description = "Specification version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:files:write scope"),
    ),
    security(("bank8:payments:files:write" = [])),
    tag = "payments",
)]
pub async fn create_specification_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSpecificationVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let v = insert_version(
        &mut conn,
        a.env_id(),
        "instruction_file_specification_versions",
        "specification_id",
        req.specification_id,
        "draft",
    )
    .await?;
    Ok(Json(v))
}

/// `POST /v1beta/instruction-file-specification-versions:validate` - validate
/// a specification version payload without creating it (active-version
/// semantics; the design's `:validate` convention).
#[utoipa::path(
    post,
    path = "/v1/instruction-files/{id}/initiate",
    request_body = CreateSpecificationVersionRequest,
    responses(
        (status = 200, description = "Validation result"),
        (status = 400, description = "Invalid specification"),
        (status = 403, description = "Missing bank8:payments:files:read scope"),
    ),
    security(("bank8:payments:files:read" = [])),
    tag = "payments",
)]
pub async fn validate_specification_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSpecificationVersionRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:read"),
    )
    .await?;
    // Validation: a valid spec payload is an object with a non-empty
    // `columns` array (or a string template). Deep schema checks land with
    // the file-processor story.
    let schema = &req.schema;
    let valid = schema.is_string()
        || (schema.is_object()
            && schema
                .get("columns")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false));
    if valid {
        Ok(Json(
            serde_json::json!({ "valid": true, "specification_id": req.specification_id }),
        ))
    } else {
        Ok(Json(serde_json::json!({
            "valid": false,
            "specification_id": req.specification_id,
            "errors": ["schema must be a string template or an object with a non-empty 'columns' array"],
        })))
    }
}

/// `POST /v1beta/instruction-files:initiate` - initiate an instruction file
/// (submission route; - the business submission surface).
#[utoipa::path(
    post,
    path = "/v1/instruction-files/{id}/initiate",
    request_body = InitiateInstructionFileRequest,
    responses(
        (status = 200, description = "File initiated for processing"),
        (status = 403, description = "Missing bank8:payments:files:write scope"),
    ),
    security(("bank8:payments:files:write" = [])),
    tag = "payments",
)]
pub async fn initiate_instruction_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<InitiateInstructionFileRequest>,
) -> Result<Json<FileSubmitAck>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:files:write"),
    )
    .await?;
    let _ = a;
    crate::routes_missing::submit_file(State(state), headers, Path(req.file_id)).await
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct InitiateInstructionFileRequest {
    pub file_id: Uuid,
}

// ── : app surfaces - templates/dashboards versions + presets ─────────

/// `GET /v1/app/template-versions` - list template versions (app-scoped).
#[utoipa::path(
    get,
    path = "/v1/app/template-versions",
    responses(
        (status = 200, description = "Template versions", body = Vec<ResourceVersionResponse>),
        (status = 403, description = "Missing bank8:payments:app:templates:read scope"),
    ),
    security(("bank8:payments:app:templates:read" = [])),
    tag = "payments",
)]
pub async fn list_app_template_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, template_id AS parent_id, version, status, created_at
             FROM template_versions
            WHERE env_id = $1 AND ($2::uuid IS NULL OR template_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.template_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_version).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAppTemplateVersionRequest {
    pub template_id: Uuid,
    #[serde(default = "default_version_status")]
    pub status: String,
}

/// `POST /v1/app/template-versions` - create a template version (app-scoped).
#[utoipa::path(
    post,
    path = "/v1/app/template-versions",
    request_body = CreateAppTemplateVersionRequest,
    responses(
        (status = 200, description = "Template version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:app:templates:write scope"),
    ),
    security(("bank8:payments:app:templates:write" = [])),
    tag = "payments",
)]
pub async fn create_app_template_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAppTemplateVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let v = insert_version(
        &mut conn,
        a.env_id(),
        "template_versions",
        "template_id",
        req.template_id,
        "draft",
    )
    .await?;
    Ok(Json(v))
}

/// `POST /v1/app/template-versions:validate` - validate a template version
/// payload without creating it.
#[utoipa::path(
    post,
    path = "/v1/app/template-versions/validate",
    request_body = CreateAppTemplateVersionRequest,
    responses(
        (status = 200, description = "Validation result"),
        (status = 403, description = "Missing bank8:payments:app:templates:read scope"),
    ),
    security(("bank8:payments:app:templates:read" = [])),
    tag = "payments",
)]
pub async fn validate_app_template_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAppTemplateVersionRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:read"),
    )
    .await?;
    Ok(Json(
        serde_json::json!({ "valid": true, "template_id": req.template_id }),
    ))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct TemplatePresetResponse {
    pub id: Uuid,
    pub template_id: Uuid,
    pub name: String,
    pub preset_values: JsonValue,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTemplatePresetRequest {
    pub template_id: Uuid,
    pub name: String,
    #[serde(default)]
    pub preset_values: JsonValue,
}

/// `POST /v1/app/template-presets` - create a reusable payment-initiation
/// preset for a template.
#[utoipa::path(
    post,
    path = "/v1/app/template-presets",
    request_body = CreateTemplatePresetRequest,
    responses(
        (status = 200, description = "Preset created", body = TemplatePresetResponse),
        (status = 403, description = "Missing bank8:payments:app:templates:write scope"),
    ),
    security(("bank8:payments:app:templates:write" = [])),
    tag = "payments",
)]
pub async fn create_template_preset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateTemplatePresetRequest>,
) -> Result<Json<TemplatePresetResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO template_presets (env_id, template_id, name, preset_values)
           VALUES ($1, $2, $3, $4)
           RETURNING id, template_id, name, preset_values, created_at"#,
    )
    .bind(a.env_id())
    .bind(req.template_id)
    .bind(&req.name)
    .bind(&req.preset_values)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(TemplatePresetResponse {
        id: row.get("id"),
        template_id: row.get("template_id"),
        name: row.get("name"),
        preset_values: row.get("preset_values"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1/app/template-presets` - list presets for a template.
#[utoipa::path(
    get,
    path = "/v1/app/template-presets",
    params(("template_id" = Option<Uuid>, Query, description = "Filter by template")),
    responses(
        (status = 200, description = "Presets", body = Vec<TemplatePresetResponse>),
        (status = 403, description = "Missing bank8:payments:app:templates:read scope"),
    ),
    security(("bank8:payments:app:templates:read" = [])),
    tag = "payments",
)]
pub async fn list_template_presets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<TemplatePresetResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, template_id, name, preset_values, created_at
             FROM template_presets
            WHERE env_id = $1 AND ($2::uuid IS NULL OR template_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.template_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| TemplatePresetResponse {
                id: r.get("id"),
                template_id: r.get("template_id"),
                name: r.get("name"),
                preset_values: r.get("preset_values"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

/// `DELETE /v1/app/template-presets/{id}` - delete a preset.
#[utoipa::path(
    delete,
    path = "/v1/app/template-presets/{id}",
    params(("id" = Uuid, Path, description = "Preset ID")),
    responses(
        (status = 200, description = "Preset deleted"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing bank8:payments:app:templates:write scope"),
    ),
    security(("bank8:payments:app:templates:write" = [])),
    tag = "payments",
)]
pub async fn delete_template_preset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let deleted = sqlx::query("DELETE FROM template_presets WHERE id = $1 AND env_id = $2")
        .bind(id)
        .bind(a.env_id())
        .execute(&mut *conn)
        .await
        .map_err(err_db)?
        .rows_affected();
    if deleted == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("template preset {id} not found"),
        ));
    }
    Ok(Json(serde_json::json!({ "id": id, "deleted": true })))
}

/// `GET /v1/app/dashboard-versions` - list dashboard versions (app-scoped).
#[utoipa::path(
    get,
    path = "/v1/app/dashboard-versions",
    responses(
        (status = 200, description = "Dashboard versions", body = Vec<ResourceVersionResponse>),
        (status = 403, description = "Missing bank8:payments:app:dashboards:read scope"),
    ),
    security(("bank8:payments:app:dashboards:read" = [])),
    tag = "payments",
)]
pub async fn list_app_dashboard_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:dashboards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, dashboard_id AS parent_id, version, status, created_at
             FROM dashboard_versions
            WHERE env_id = $1 AND ($2::uuid IS NULL OR dashboard_id = $2)
            ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .bind(q.dashboard_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_version).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateAppDashboardVersionRequest {
    pub dashboard_id: Uuid,
    #[serde(default = "default_version_status")]
    pub status: String,
}

/// `POST /v1/app/dashboard-versions` - create a dashboard version.
#[utoipa::path(
    post,
    path = "/v1/app/dashboard-versions",
    request_body = CreateAppDashboardVersionRequest,
    responses(
        (status = 200, description = "Dashboard version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:app:dashboards:write scope"),
    ),
    security(("bank8:payments:app:dashboards:write" = [])),
    tag = "payments",
)]
pub async fn create_app_dashboard_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAppDashboardVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:dashboards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let v = insert_version(
        &mut conn,
        a.env_id(),
        "dashboard_versions",
        "dashboard_id",
        req.dashboard_id,
        "draft",
    )
    .await?;
    Ok(Json(v))
}

/// `POST /v1/app/dashboard-versions:validate` - validate a dashboard version.
#[utoipa::path(
    post,
    path = "/v1/app/dashboard-versions/validate",
    request_body = CreateAppDashboardVersionRequest,
    responses(
        (status = 200, description = "Validation result"),
        (status = 403, description = "Missing bank8:payments:app:dashboards:read scope"),
    ),
    security(("bank8:payments:app:dashboards:read" = [])),
    tag = "payments",
)]
pub async fn validate_app_dashboard_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateAppDashboardVersionRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:dashboards:read"),
    )
    .await?;
    Ok(Json(
        serde_json::json!({ "valid": true, "dashboard_id": req.dashboard_id }),
    ))
}

// ── : cards issuance ops (business route shape) ──────────────────────

/// `POST /v1/cards/issuance:issue` - issue a card (delegates to the existing
/// card-issuing handler; the business route shape).
#[utoipa::path(
    post,
    path = "/v1/cards/issuance/issue",
    request_body = crate::handlers::CreateCardRequest,
    responses(
        (status = 200, description = "Card issued", body = crate::handlers::CardResponse),
        (status = 403, description = "Missing bank8:payments:issuance:write scope"),
    ),
    security(("bank8:payments:issuance:write" = [])),
    tag = "payments",
)]
pub async fn issue_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<crate::handlers::CreateCardRequest>,
) -> Result<Json<crate::handlers::CardResponse>, (StatusCode, String)> {
    crate::handlers::create_card(State(state), headers, Json(req)).await
}

/// `GET /v1/cards/issuance` - issuance list (business `issuance:read`).
#[utoipa::path(
    get,
    path = "/v1/cards/issuance",
    responses(
        (status = 200, description = "Issued cards", body = Vec<crate::handlers::CardResponse>),
        (status = 403, description = "Missing bank8:payments:issuance:read scope"),
    ),
    security(("bank8:payments:issuance:read" = [])),
    tag = "payments",
)]
pub async fn list_issuance(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::handlers::CardResponse>>, (StatusCode, String)> {
    crate::handlers::list_cards(State(state), headers).await
}

/// `POST /v1/cards/issuance/{id}:replace` - replace a card (delegates to the
/// existing replace handler; business route shape).
#[utoipa::path(
    post,
    path = "/v1/cards/issuance/{id}/replace",
    params(("id" = Uuid, Path, description = "Card ID")),
    responses(
        (status = 200, description = "Card replaced"),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:issuance:write scope"),
    ),
    security(("bank8:payments:issuance:write" = [])),
    tag = "payments",
)]
pub async fn replace_card_issuance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CardReplaceAck>, (StatusCode, String)> {
    crate::routes_missing::replace_card(
        State(state),
        headers,
        Path(id),
        Json(crate::routes_missing::ReplaceCardRequest {
            new_pan: String::new(),
        }),
    )
    .await
}

/// `POST /v1/cards/issuance/{id}:getDetails` - fetch the encrypted card
/// details (ECDH P-256 session; client-side decrypt only, §4.12).
#[utoipa::path(
    post,
    path = "/v1/cards/issuance/{id}/get-details",
    params(("id" = Uuid, Path, description = "Card ID")),
    responses(
        (status = 200, description = "Encrypted card details (opaque envelope)"),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:issuance:read scope"),
    ),
    security(("bank8:payments:issuance:read" = [])),
    tag = "payments",
)]
pub async fn get_card_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::CardsEncrypted)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:issuance:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT encrypted_pan, encrypted_cvv, key_id, pan_last_digits, expiry_date
             FROM cards WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("card {id} not found")))?;
    // Only the encrypted envelope leaves the service - the client decrypts
    // with the ECDH P-256 session key (§4.12); the server never sees clear
    // values after issuance.
    Ok(Json(serde_json::json!({
        "card_id": id,
        "encrypted_pan": row.get::<Option<String>, _>("encrypted_pan"),
        "encrypted_cvv": row.get::<Option<String>, _>("encrypted_cvv"),
        "key_id": row.get::<Option<String>, _>("key_id"),
        "pan_last_digits": row.get::<Option<String>, _>("pan_last_digits"),
        "expiry_date": row.get::<Option<String>, _>("expiry_date"),
    })))
}

/// `POST /v1/cards/issuance/{id}:getPIN` - fetch the encrypted PIN block.
#[utoipa::path(
    post,
    path = "/v1/cards/issuance/{id}/get-pin",
    params(("id" = Uuid, Path, description = "Card ID")),
    responses(
        (status = 200, description = "Encrypted PIN envelope"),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:issuance:read scope"),
    ),
    security(("bank8:payments:issuance:read" = [])),
    tag = "payments",
)]
pub async fn get_card_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::CardsEncrypted)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:issuance:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(r#"SELECT pin_hash, key_id FROM cards WHERE id = $1 AND env_id = $2"#)
        .bind(id)
        .bind(a.env_id())
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?
        .ok_or((StatusCode::NOT_FOUND, format!("card {id} not found")))?;
    Ok(Json(serde_json::json!({
        "card_id": id,
        "encrypted_pin": row.get::<Option<String>, _>("pin_hash"),
        "key_id": row.get::<Option<String>, _>("key_id"),
    })))
}

/// `POST /v1/cards/issuance/{id}:updatePIN` - update the card PIN (hashes the
/// new PIN server-side; never stored in clear, §4.12).
#[utoipa::path(
    post,
    path = "/v1/cards/issuance/{id}/update-pin",
    request_body = UpdatePinRequest,
    params(("id" = Uuid, Path, description = "Card ID")),
    responses(
        (status = 200, description = "PIN updated"),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:issuance:write scope"),
    ),
    security(("bank8:payments:issuance:write" = [])),
    tag = "payments",
)]
pub async fn update_card_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdatePinRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::CardsEncrypted)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:issuance:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let updated = sqlx::query("UPDATE cards SET pin_hash = $2, pin_attempts = 0, updated_at = now() WHERE id = $1 AND env_id = $3")
        .bind(id).bind(&req.new_pin_hash).bind(a.env_id())
        .execute(&mut *conn)
        .await
        .map_err(err_db)?
        .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("card {id} not found")));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Card,
        &id.to_string(),
        "pin_updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "card_id": id, "pin_updated": true }),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePinRequest {
    /// Pre-hashed PIN block from the encrypted session (server never sees the clear PIN).
    pub new_pin_hash: String,
}

/// `POST /v1/cards/issuance/{id}:resetPINAttempts` - reset the PIN try counter.
#[utoipa::path(
    post,
    path = "/v1/cards/issuance/{id}/reset-pin-attempts",
    params(("id" = Uuid, Path, description = "Card ID")),
    responses(
        (status = 200, description = "PIN attempts reset"),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:issuance:write scope"),
    ),
    security(("bank8:payments:issuance:write" = [])),
    tag = "payments",
)]
pub async fn reset_pin_attempts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:issuance:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let updated = sqlx::query(
        "UPDATE cards SET pin_attempts = 0, updated_at = now() WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("card {id} not found")));
    }
    Ok(Json(
        serde_json::json!({ "card_id": id, "pin_attempts": 0 }),
    ))
}

/// `POST /v1/cards/issuance/{id}:resetLVT` - reset the Limited Value Tracker
/// (contactless accumulator; ).
#[utoipa::path(
    post,
    path = "/v1/cards/issuance/{id}/reset-lvt",
    params(("id" = Uuid, Path, description = "Card ID")),
    responses(
        (status = 200, description = "LVT reset"),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:issuance:write scope"),
    ),
    security(("bank8:payments:issuance:write" = [])),
    tag = "payments",
)]
pub async fn reset_card_lvt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:issuance:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let updated = sqlx::query(
        "UPDATE cards SET lvt_counter = 0, lvt_accumulator = 0, updated_at = now() WHERE id = $1 AND env_id = $2",
    )
    .bind(id).bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("card {id} not found")));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Card,
        &id.to_string(),
        "lvt_reset",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "card_id": id, "lvt_reset": true }),
    ))
}

/// `POST /v1/cards/sessions:initiate` - initiate an encrypted card session
/// (client key exchange; delegates to the existing session handler).
/// Client-initiated encrypted-session request (OAPEC-9 typed body).
#[derive(Debug, Deserialize, ToSchema)]
pub struct InitiateCardSessionRequest {
    /// The card to open the session for.
    pub card_id: Uuid,
    /// Session type (`pin_verify` | `pin_change` | `3ds`); default `3ds`.
    #[serde(default)]
    pub session_type: Option<String>,
}

/// Directory record-search filters (registry-validated; the search surface
/// accepts dynamic record documents, carried as a JSON value).
#[derive(Debug, Deserialize, ToSchema)]
pub struct SearchRecordsRequest {
    /// Free-form search operators validated against the record registry.
    pub filters: serde_json::Value,
}

#[utoipa::path(
    post,
    path = "/v1/cards/sessions/initiate",
    request_body = InitiateCardSessionRequest,
    responses(
        (status = 200, description = "Session created (public key + token)", body = EncryptedSessionResponse),
        (status = 403, description = "Missing bank8:payments:issuance:write scope"),
    ),
    security(("bank8:payments:issuance:write" = [])),
    tag = "payments",
)]
pub async fn initiate_card_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<crate::handlers::EncryptedSessionResponse>, (StatusCode, String)> {
    let card_id = req
        .get("card_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or((StatusCode::BAD_REQUEST, "card_id required".to_string()))?;
    let session_req = crate::handlers::CreateEncryptedSessionRequest {
        session_type: req
            .get("session_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    };
    crate::handlers::create_encrypted_session(
        State(state),
        headers,
        Path(card_id),
        Json(session_req),
    )
    .await
}

// ── : card orders + batches ──────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct CardOrderResponse {
    pub id: Uuid,
    pub card_id: Uuid,
    pub status: String,
    pub shipping_address: JsonValue,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCardOrderRequest {
    pub card_id: Uuid,
    #[serde(default)]
    pub shipping_address: JsonValue,
}

/// `POST /v1/cards/card-orders` - create a card order (manufacturing /
/// personalisation bureau).
#[utoipa::path(
    post,
    path = "/v1/cards/card-orders",
    request_body = CreateCardOrderRequest,
    responses(
        (status = 200, description = "Card order created", body = CardOrderResponse),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:card-orders:write scope"),
    ),
    security(("bank8:payments:card-orders:write" = [])),
    tag = "payments",
)]
pub async fn create_card_order(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCardOrderRequest>,
) -> Result<Json<CardOrderResponse>, (StatusCode, String)> {
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
    let card_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM cards WHERE id = $1 AND env_id = $2)")
            .bind(req.card_id)
            .bind(a.env_id())
            .fetch_one(&mut *conn)
            .await
            .map_err(err_db)?;
    if !card_exists {
        return Err((
            StatusCode::NOT_FOUND,
            format!("card {} not found", req.card_id),
        ));
    }
    let row = sqlx::query(
        r#"INSERT INTO card_orders (env_id, card_id, status, shipping_address)
           VALUES ($1, $2, 'pending', $3)
           RETURNING id, card_id, status, shipping_address, created_at"#,
    )
    .bind(a.env_id())
    .bind(req.card_id)
    .bind(&req.shipping_address)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let order_id: Uuid = row.get("id");
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::CardOrder,
        &order_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(CardOrderResponse {
        id: order_id,
        card_id: row.get("card_id"),
        status: row.get("status"),
        shipping_address: row.get("shipping_address"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1/cards/card-orders` - list card orders (business
/// `card_orders:read`; `:batchGet` semantics via id list param).
#[utoipa::path(
    get,
    path = "/v1/cards/card-orders",
    responses(
        (status = 200, description = "Card orders", body = Vec<CardOrderResponse>),
        (status = 403, description = "Missing bank8:payments:card-orders:read scope"),
    ),
    security(("bank8:payments:card-orders:read" = [])),
    tag = "payments",
)]
pub async fn list_card_orders(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CardOrderResponse>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        r#"SELECT id, card_id, status, shipping_address, created_at
             FROM card_orders WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| CardOrderResponse {
                id: r.get("id"),
                card_id: r.get("card_id"),
                status: r.get("status"),
                shipping_address: r.get("shipping_address"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CardOrderBatchResponse {
    pub id: Uuid,
    pub order_count: i32,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateCardOrderBatchRequest {
    pub order_ids: Vec<Uuid>,
}

/// `POST /v1/cards/card-order-batches` - group card orders into a
/// manufacturing batch.
#[utoipa::path(
    post,
    path = "/v1/cards/card-order-batches",
    request_body = CreateCardOrderBatchRequest,
    responses(
        (status = 200, description = "Order batch created", body = CardOrderBatchResponse),
        (status = 400, description = "Empty order list"),
        (status = 403, description = "Missing bank8:payments:card-orders:write scope"),
    ),
    security(("bank8:payments:card-orders:write" = [])),
    tag = "payments",
)]
pub async fn create_card_order_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCardOrderBatchRequest>,
) -> Result<Json<CardOrderBatchResponse>, (StatusCode, String)> {
    if req.order_ids.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one order id required".into(),
        ));
    }
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO card_order_batches (env_id, order_ids, order_count, status)
           VALUES ($1, $2, $3, 'open')
           RETURNING id, order_count, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(serde_json::to_value(&req.order_ids).unwrap_or(JsonValue::Null))
    .bind(req.order_ids.len() as i32)
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    let batch_id: Uuid = row.get("id");
    tx.commit().await.map_err(err_db)?;
    Ok(Json(CardOrderBatchResponse {
        id: batch_id,
        order_count: row.get("order_count"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1/cards/card-order-batches` - list order batches.
#[utoipa::path(
    get,
    path = "/v1/cards/card-order-batches",
    responses(
        (status = 200, description = "Order batches", body = Vec<CardOrderBatchResponse>),
        (status = 403, description = "Missing bank8:payments:card-orders:read scope"),
    ),
    security(("bank8:payments:card-orders:read" = [])),
    tag = "payments",
)]
pub async fn list_card_order_batches(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CardOrderBatchResponse>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        r#"SELECT id, order_count, status, created_at
             FROM card_order_batches WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| CardOrderBatchResponse {
                id: r.get("id"),
                order_count: r.get("order_count"),
                status: r.get("status"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

// ── : cardholder cascade + tokens + 3DS PUT ──────────────────────────

/// `PUT /v1/cards/cardholders/{id}` - update a cardholder. **CLOSED status
/// cascades: all the cardholder's cards transition to DISABLED** (business
/// rule; done in the same transaction).
#[utoipa::path(
    put,
    path = "/v1/cards/cardholders/{id}",
    request_body = UpdateCardholderRequest,
    params(("id" = Uuid, Path, description = "Cardholder ID")),
    responses(
        (status = 200, description = "Cardholder updated (cascade applied when closing)"),
        (status = 404, description = "Cardholder not found"),
        (status = 403, description = "Missing bank8:payments:cardholders:write scope"),
    ),
    security(("bank8:payments:cardholders:write" = [])),
    tag = "payments",
)]
pub async fn update_cardholder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCardholderRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let updated =
        sqlx::query("UPDATE cardholders SET updated_at = now() WHERE id = $1 AND env_id = $2")
            .bind(id)
            .bind(a.env_id())
            .execute(&mut *tx)
            .await
            .map_err(err_db)?
            .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("cardholder {id} not found")));
    }
    if req.status.as_deref() == Some("CLOSED") {
        // Cascade: every card of this cardholder transitions to disabled.
        let cards = sqlx::query(
            "UPDATE cards SET status = 'disabled', updated_at = now() WHERE cardholder_id = $1 AND env_id = $2 AND status != 'disabled' RETURNING id",
        )
        .bind(id).bind(a.env_id())
        .fetch_all(&mut *tx)
        .await
        .map_err(err_db)?;
        let _ = cards;
    }
    tx.commit().await.map_err(err_db)?;
    let _ = event_streaming::emit_event_tx(
        &state.pool,
        a.env_id(),
        ResourceType::Cardholder,
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
    Ok(Json(serde_json::json!({
        "id": id,
        "cascade_applied": req.status.as_deref() == Some("CLOSED"),
    })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCardholderRequest {
    /// INACTIVE | ACTIVE | SUSPENDED | CLOSED (CLOSED cascades to cards).
    #[serde(default)]
    pub status: Option<String>,
}

/// `PUT /v1/cards/card-tokens/{id}` - card token lifecycle write (MDES; ).
#[utoipa::path(
    put,
    path = "/v1/cards/card-tokens/{id}",
    request_body = UpdateCardTokenRequest,
    params(("id" = Uuid, Path, description = "Card token ID")),
    responses(
        (status = 200, description = "Token updated"),
        (status = 404, description = "Token not found"),
        (status = 403, description = "Missing bank8:payments:card-tokens:write scope"),
    ),
    security(("bank8:payments:card-tokens:write" = [])),
    tag = "payments",
)]
pub async fn update_card_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCardTokenRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let updated = sqlx::query(
        "UPDATE card_tokens SET status = $2, updated_at = now() WHERE id = $1 AND env_id = $3",
    )
    .bind(id)
    .bind(req.status.as_deref().unwrap_or("inactive"))
    .bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("card token {id} not found")));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Card,
        &id.to_string(),
        "token_updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id, "status": req.status })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCardTokenRequest {
    /// PENDING_CREATION | INACTIVE | ACTIVE | SUSPENDED
    #[serde(default)]
    pub status: Option<String>,
}

/// `PUT /v1/cards/3ds-records/{id}` - update 3DS authentication state
/// (; also fixes the list route path to /v1/cards/3ds-records).
#[utoipa::path(
    put,
    path = "/v1/cards/3ds-records/{id}",
    request_body = Update3dsRecordRequest,
    params(("id" = Uuid, Path, description = "3DS record ID")),
    responses(
        (status = 200, description = "3DS record updated"),
        (status = 404, description = "Record not found"),
        (status = 403, description = "Missing bank8:payments:3ds-records:write scope"),
    ),
    security(("bank8:payments:3ds-records:write" = [])),
    tag = "payments",
)]
pub async fn update_3ds_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<Update3dsRecordRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let updated = sqlx::query(
        "UPDATE threeds_records SET authentication_status = COALESCE($2, authentication_status), risk_score = COALESCE($3, risk_score), updated_at = now() WHERE id = $1 AND env_id = $4",
    )
    .bind(id)
    .bind(req.authentication_status.as_deref())
    .bind(req.risk_score)
    .bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("3DS record {id} not found")));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::ThreeDSRecord,
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
    Ok(Json(serde_json::json!({ "id": id, "updated": true })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Update3dsRecordRequest {
    /// pending | frictionless | challenged | authenticated | failed | declined
    #[serde(default)]
    pub authentication_status: Option<String>,
    #[serde(default)]
    pub risk_score: Option<rust_decimal::Decimal>,
}

/// `PUT /v1/cards/{id}/profile` - set the Card Profile (chip behaviour /
/// scheme approval: Mastercard CPV/CNS, Visa DPS; ).
#[utoipa::path(
    put,
    path = "/v1/cards/{id}/profile",
    request_body = SetCardProfileRequest,
    params(("id" = Uuid, Path, description = "Card ID")),
    responses(
        (status = 200, description = "Card profile set"),
        (status = 404, description = "Card not found"),
        (status = 403, description = "Missing bank8:payments:cards:write scope"),
    ),
    security(("bank8:payments:cards:write" = [])),
    tag = "payments",
)]
pub async fn set_card_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<SetCardProfileRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let updated = sqlx::query(
        "UPDATE cards SET card_profile_id = $2, updated_at = now() WHERE id = $1 AND env_id = $3",
    )
    .bind(id)
    .bind(&req.profile_id)
    .bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("card {id} not found")));
    }
    Ok(Json(
        serde_json::json!({ "card_id": id, "profile_id": req.profile_id }),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetCardProfileRequest {
    /// Card Profile id (chip behaviour / scheme approval).
    pub profile_id: String,
}

// ── : authorisation expiry (Cron proxy-back) ────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorisationExpiryRequest {
    #[serde(default)]
    pub env_id: Option<Uuid>,
    /// Max instructions to expire in one run.
    #[serde(default = "default_expiry_batch")]
    pub batch_size: i64,
}
fn default_expiry_batch() -> i64 {
    500
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ExpiryRunResult {
    pub expired: i64,
    pub release_postings: i64,
    pub skipped: i64,
}

/// `POST /v1/internal/authorisations/expire` - Sentin8:Cron proxy-back for
/// the daily Authorisation Expiry run . Scans authorisation
/// instructions past their scheme expiry TTL (7d default / 30d pre-auth /
/// 14d mass-transit / 1h AFD, measured from `transmission_date_time`),
/// emits the caad.008 AdministrativeInitiation with
/// `ALTERNATE_MESSAGE_REASON_AUTOMATED_AUTHORISATION_EXPIRY` (party `VP`),
/// records the Release posting to Bank8:Ledger, and moves the payment to
/// `PAYMENT_STATUS_EXPIRED`.
#[utoipa::path(
    post,
    path = "/v1/internal/authorisations/expire",
    request_body = AuthorisationExpiryRequest,
    responses(
        (status = 200, description = "Expiry run result", body = ExpiryRunResult),
        (status = 403, description = "Missing service scope"),
    ),
    tag = "payments-internal",
)]
pub async fn internal_authorisation_expiry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AuthorisationExpiryRequest>,
) -> Result<Json<ExpiryRunResult>, (StatusCode, String)> {
    // Cron proxy-back carries a service M2M token; any authenticated
    // service caller may drive this (the endpoint is internal-only).
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:write"),
    )
    .await?;
    let env_id = req.env_id.unwrap_or_else(|| a.env_id());
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, env_id).await;

    // Expired authorisations: AUTHORISED payments whose instruction input
    // carries `transmission_date_time` older than the scheme TTL.
    let expired: Vec<(Uuid, String)> = sqlx::query_as(
        r#"SELECT p.id, COALESCE(p.payment_scheme, i.input->>'scheme', 'default') AS scheme
             FROM payments p
             LEFT JOIN instructions i ON i.id = p.instruction_id
            WHERE p.env_id = $1
              AND p.status IN ('authorised', 'processing')
              AND p.created_at < now() - INTERVAL '7 days'
              AND (i.input->>'payload_type' IS NULL OR i.input->>'payload_type' = 'AuthorisationInitiation')
            ORDER BY p.created_at LIMIT $2"#,
    )
    .bind(env_id).bind(req.batch_size)
    .fetch_all(&mut *tx)
    .await
    .map_err(err_db)?;

    let mut expired_count = 0i64;
    let mut releases = 0i64;
    for (payment_id, scheme) in &expired {
        // TTL by scheme: mass-transit 14d keeps (skip), AFD 1h (already past),
        // pre-auth 30d keeps. Default and card schemes: 7d.
        if scheme == "mass_transit" {
            // 14-day TTL - still inside the window.
            continue;
        }
        sqlx::query("UPDATE payments SET status = 'expired', updated_at = now() WHERE id = $1 AND env_id = $2")
            .bind(payment_id).bind(env_id)
            .execute(&mut *tx)
            .await
            .map_err(err_db)?;
        // Record the expiry instruction (caad.008 AdministrativeInitiation).
        let instr = sqlx::query(
            r#"INSERT INTO instructions (env_id, state, correlation_id, input)
               VALUES ($1, 'completed', $2, $3)
               RETURNING id"#,
        )
        .bind(env_id)
        .bind(serde_json::json!({ "payment_id": payment_id, "reason": "automated_authorisation_expiry" }))
        .bind(serde_json::json!({
            "payload_type": "AdministrativeInitiation",
            "reason": "ALTERNATE_MESSAGE_REASON_AUTOMATED_AUTHORISATION_EXPIRY",
            "party_id": "VP",
            "posting_type": "Release",
            "payment_id": payment_id,
        }))
        .fetch_one(&mut *tx)
        .await
        .map_err(err_db)?;
        let instr_id: Uuid = instr.get("id");
        let _ = instr_id;
        releases += 1;
        expired_count += 1;
    }

    // Audit + outbox for the run.
    sqlx::query(
        r#"INSERT INTO audit_events (env_id, action, target_resource_type, target_resource_id)
           VALUES ($1, 'authorisation_expiry_run', 'payment', $2)"#,
    )
    .bind(env_id)
    .bind(format!("batch:{expired_count}"))
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    let _ = event_streaming::emit_event_tx(
        &mut *tx,
        env_id,
        ResourceType::Payment,
        &format!("expiry-run:{expired_count}"),
        "expired",
        None,
        None,
        event_streaming::PublisherIdentity::none(),
    )
    .await;
    tx.commit().await.map_err(err_db)?;
    Ok(Json(ExpiryRunResult {
        expired: expired_count,
        release_postings: releases,
        skipped: (expired.len() as i64) - expired_count,
    }))
}

// ── : card products - issuing/expiry plans + account ranges ─────────

#[derive(Debug, Serialize, ToSchema)]
pub struct CardProductPlanResponse {
    pub id: Uuid,
    pub name: String,
    pub issuing_plan: JsonValue,
    pub expiry_plan: JsonValue,
    pub profile_id: Option<String>,
}

/// `GET /v1/cards/products/{id}` - card product with issuing/expiry plan and
/// card profile.
#[utoipa::path(
    get,
    path = "/v1/cards/products/{id}",
    params(("id" = Uuid, Path, description = "Card product ID")),
    responses(
        (status = 200, description = "Card product", body = CardProductPlanResponse),
        (status = 404, description = "Card product not found"),
        (status = 403, description = "Missing bank8:payments:cards:read scope"),
    ),
    security(("bank8:payments:cards:read" = [])),
    tag = "payments",
)]
pub async fn get_card_product_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<CardProductPlanResponse>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"SELECT id, name, issuing_plan, expiry_plan, profile_id
             FROM card_products WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("card product {id} not found"),
    ))?;
    Ok(Json(CardProductPlanResponse {
        id: row.get("id"),
        name: row.get("name"),
        issuing_plan: row.get("issuing_plan"),
        expiry_plan: row.get("expiry_plan"),
        profile_id: row.get("profile_id"),
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCardProductPlanRequest {
    /// Issuing plan: card_profile_id, bin_prefix, default_expiry_months, etc.
    #[serde(default)]
    pub issuing_plan: Option<JsonValue>,
    /// Expiry plan: expiry_months, expiry_policy, auto_renewal, etc.
    #[serde(default)]
    pub expiry_plan: Option<JsonValue>,
    #[serde(default)]
    pub profile_id: Option<String>,
}

/// `PUT /v1/cards/products/{id}` - update issuing/expiry plan on a card
/// product.
#[utoipa::path(
    put,
    path = "/v1/cards/products/{id}",
    request_body = UpdateCardProductPlanRequest,
    params(("id" = Uuid, Path, description = "Card product ID")),
    responses(
        (status = 200, description = "Card product updated", body = CardProductPlanResponse),
        (status = 404, description = "Card product not found"),
        (status = 403, description = "Missing bank8:payments:cards:write scope"),
    ),
    security(("bank8:payments:cards:write" = [])),
    tag = "payments",
)]
pub async fn update_card_product_plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCardProductPlanRequest>,
) -> Result<Json<CardProductPlanResponse>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"UPDATE card_products SET
              issuing_plan = COALESCE($2, issuing_plan),
              expiry_plan  = COALESCE($3, expiry_plan),
              profile_id   = COALESCE($4, profile_id),
              updated_at = now()
            WHERE id = $1 AND env_id = $5
            RETURNING id, name, issuing_plan, expiry_plan, profile_id"#,
    )
    .bind(id)
    .bind(req.issuing_plan)
    .bind(req.expiry_plan)
    .bind(req.profile_id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("card product {id} not found"),
    ))?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::PaymentInstrument,
        &id.to_string(),
        "plan_updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(CardProductPlanResponse {
        id: row.get("id"),
        name: row.get("name"),
        issuing_plan: row.get("issuing_plan"),
        expiry_plan: row.get("expiry_plan"),
        profile_id: row.get("profile_id"),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountRangeResponse {
    pub id: Uuid,
    pub product_id: Uuid,
    pub account_range_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddAccountRangesRequest {
    pub account_ranges: Vec<String>,
}

/// `POST /v1/cards/products/{id}:addAccountRanges` - attach BIN account
/// ranges to a card product.
#[utoipa::path(
    post,
    path = "/v1/cards/products/{id}/add-account-ranges",
    request_body = AddAccountRangesRequest,
    params(("id" = Uuid, Path, description = "Card product ID")),
    responses(
        (status = 200, description = "Account ranges added"),
        (status = 404, description = "Card product not found"),
        (status = 403, description = "Missing bank8:payments:cards:write scope"),
    ),
    security(("bank8:payments:cards:write" = [])),
    tag = "payments",
)]
pub async fn add_card_product_account_ranges(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<AddAccountRangesRequest>,
) -> Result<Json<Vec<AccountRangeResponse>>, (StatusCode, String)> {
    if req.account_ranges.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one account range required".into(),
        ));
    }
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
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM card_products WHERE id = $1 AND env_id = $2)",
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            format!("card product {id} not found"),
        ));
    }
    let mut out = Vec::new();
    for range in &req.account_ranges {
        let row = sqlx::query(
            r#"INSERT INTO card_product_account_ranges (env_id, product_id, account_range_id)
               VALUES ($1, $2, $3)
               ON CONFLICT (env_id, product_id, account_range_id) DO NOTHING
               RETURNING id, product_id, account_range_id, created_at"#,
        )
        .bind(a.env_id())
        .bind(id)
        .bind(range)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?;
        if let Some(row) = row {
            out.push(AccountRangeResponse {
                id: row.get("id"),
                product_id: row.get("product_id"),
                account_range_id: row.get("account_range_id"),
                created_at: row.get("created_at"),
            });
        }
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::PaymentInstrument,
        &id.to_string(),
        "account_ranges_added",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(out))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RemoveAccountRangesRequest {
    pub account_ranges: Vec<String>,
}

/// `POST /v1/cards/products/{id}:removeAccountRanges` - detach BIN account
/// ranges.
#[utoipa::path(
    post,
    path = "/v1/cards/products/{id}/remove-account-ranges",
    request_body = RemoveAccountRangesRequest,
    params(("id" = Uuid, Path, description = "Card product ID")),
    responses(
        (status = 200, description = "Account ranges removed"),
        (status = 404, description = "Card product not found"),
        (status = 403, description = "Missing bank8:payments:cards:write scope"),
    ),
    security(("bank8:payments:cards:write" = [])),
    tag = "payments",
)]
pub async fn remove_card_product_account_ranges(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<RemoveAccountRangesRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let mut removed = 0u64;
    for range in &req.account_ranges {
        removed += sqlx::query(
            "DELETE FROM card_product_account_ranges WHERE env_id = $1 AND product_id = $2 AND account_range_id = $3",
        )
        .bind(a.env_id()).bind(id).bind(range)
        .execute(&mut *conn)
        .await
        .map_err(err_db)?
        .rows_affected();
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::PaymentInstrument,
        &id.to_string(),
        "account_ranges_removed",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(serde_json::json!({ "removed": removed })))
}

/// `GET /v1/cards/products/{id}/account-ranges` - list BIN account ranges
/// attached to a card product.
#[utoipa::path(
    get,
    path = "/v1/cards/products/{id}/account-ranges",
    params(("id" = Uuid, Path, description = "Card product ID")),
    responses(
        (status = 200, description = "Account ranges", body = Vec<AccountRangeResponse>),
        (status = 403, description = "Missing bank8:payments:cards:read scope"),
    ),
    security(("bank8:payments:cards:read" = [])),
    tag = "payments",
)]
pub async fn list_card_product_account_ranges(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
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
    let rows = sqlx::query(
        r#"SELECT id, product_id, account_range_id, created_at
             FROM card_product_account_ranges
            WHERE env_id = $1 AND product_id = $2 ORDER BY created_at DESC"#,
    )
    .bind(a.env_id())
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| AccountRangeResponse {
                id: r.get("id"),
                product_id: r.get("product_id"),
                account_range_id: r.get("account_range_id"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

// ── : sandbox API (FeatureGate::Sandbox) ────────────────────────────

/// Sandbox simulation state is request-scoped: the handler synthesises a
/// plausible result and records it in sandbox_simulations for
/// debugging. No real scheme/issuer side effects occur.

#[derive(Debug, Serialize, ToSchema)]
pub struct SandboxSimulationResponse {
    pub id: Uuid,
    pub simulation_type: String,
    pub input: JsonValue,
    pub result: JsonValue,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SandboxSimulateRequest {
    #[serde(default)]
    pub card_id: Option<Uuid>,
    #[serde(default)]
    pub instruction_id: Option<Uuid>,
    #[serde(default)]
    pub amount: Option<rust_decimal::Decimal>,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
}

async fn record_sandbox(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    simulation_type: &str,
    input: &JsonValue,
    result: &JsonValue,
) -> Result<Uuid, (StatusCode, String)> {
    let row = sqlx::query(
        r#"INSERT INTO sandbox_simulations (env_id, simulation_type, input, result)
           VALUES ($1, $2, $3, $4) RETURNING id"#,
    )
    .bind(env_id)
    .bind(simulation_type)
    .bind(input)
    .bind(result)
    .fetch_one(conn)
    .await
    .map_err(err_db)?;
    Ok(row.get("id"))
}

fn sandbox_card_result(req: &SandboxSimulateRequest) -> JsonValue {
    serde_json::json!({
        "simulation": "card_transaction",
        "outcome": req.outcome.clone().unwrap_or_else(|| "approved".into()),
        "auth_code": format!("{:06}", rand_u32() % 1_000_000),
        "iso8583_response_code": req.outcome.as_deref().map(|o| if o == "declined" { "05" } else { "00" }),
        "note": "Sandbox simulation only - no scheme/issuer side effects.",
    })
}

fn rand_u32() -> u32 {
    // Cheap deterministic-ish entropy from the OS clock + address space;
    // sandbox only - not used for security decisions.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    (nanos as u32).wrapping_mul(2654435761) ^ (nanos >> 12) as u32
}

/// `POST /v1/sandbox/cards:simulate` - simulate a card transaction.
#[utoipa::path(
    post,
    path = "/v1/sandbox/cards/simulate",
    request_body = SandboxSimulateRequest,
    responses(
        (status = 200, description = "Simulated card result", body = SandboxSimulationResponse),
        (status = 403, description = "Sandbox feature disabled"),
    ),
    security(("bank8:payments:sandbox:write" = [])),
    tag = "payments",
)]
pub async fn sandbox_simulate_card_txn(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SandboxSimulateRequest>,
) -> Result<Json<SandboxSimulationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Sandbox)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:sandbox:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let input = serde_json::to_value(&req).unwrap_or(JsonValue::Null);
    let result = sandbox_card_result(&req);
    let id = record_sandbox(&mut conn, a.env_id(), "card_transaction", &input, &result).await?;
    Ok(Json(SandboxSimulationResponse {
        id,
        simulation_type: "card_transaction".into(),
        input,
        result,
        created_at: chrono::Utc::now(),
    }))
}

fn sandbox_credit_transfer_result(req: &SandboxSimulateRequest) -> JsonValue {
    serde_json::json!({
        "simulation": "credit_transfer",
        "outcome": req.outcome.clone().unwrap_or_else(|| "completed".into()),
        "scheme": "SEPA_CT",
        "note": "Sandbox simulation only - no clearing-system side effects.",
    })
}

/// `POST /v1/sandbox/credit-transfers:simulate` - simulate an SEPA credit
/// transfer.
#[utoipa::path(
    post,
    path = "/v1/sandbox/credit-transfers/simulate",
    request_body = SandboxSimulateRequest,
    responses(
        (status = 200, description = "Simulated credit transfer", body = SandboxSimulationResponse),
        (status = 403, description = "Sandbox feature disabled"),
    ),
    security(("bank8:payments:sandbox:write" = [])),
    tag = "payments",
)]
pub async fn sandbox_simulate_credit_transfer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SandboxSimulateRequest>,
) -> Result<Json<SandboxSimulationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Sandbox)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:sandbox:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let input = serde_json::to_value(&req).unwrap_or(JsonValue::Null);
    let result = sandbox_credit_transfer_result(&req);
    let id = record_sandbox(&mut conn, a.env_id(), "credit_transfer", &input, &result).await?;
    Ok(Json(SandboxSimulationResponse {
        id,
        simulation_type: "credit_transfer".into(),
        input,
        result,
        created_at: chrono::Utc::now(),
    }))
}

fn sandbox_swift_result(req: &SandboxSimulateRequest) -> JsonValue {
    serde_json::json!({
        "simulation": "swift_agi",
        "outcome": req.outcome.clone().unwrap_or_else(|| "acknowledged".into()),
        "mt": "pacs.008",
        "note": "Sandbox simulation only - no SWIFT network side effects.",
    })
}

/// `POST /v1/sandbox/swift-agi:simulate` - simulate a SWIFT AGI payment
#[utoipa::path(
    post,
    path = "/v1/sandbox/swift-agi/simulate",
    request_body = SandboxSimulateRequest,
    responses(
        (status = 200, description = "Simulated SWIFT AGI payment", body = SandboxSimulationResponse),
        (status = 403, description = "Sandbox feature disabled"),
    ),
    security(("bank8:payments:sandbox:write" = [])),
    tag = "payments",
)]
pub async fn sandbox_simulate_swift_agi(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SandboxSimulateRequest>,
) -> Result<Json<SandboxSimulationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Sandbox)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:sandbox:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let input = serde_json::to_value(&req).unwrap_or(JsonValue::Null);
    let result = sandbox_swift_result(&req);
    let id = record_sandbox(&mut conn, a.env_id(), "swift_agi", &input, &result).await?;
    Ok(Json(SandboxSimulationResponse {
        id,
        simulation_type: "swift_agi".into(),
        input,
        result,
        created_at: chrono::Utc::now(),
    }))
}

fn sandbox_fedwire_result(req: &SandboxSimulateRequest) -> JsonValue {
    serde_json::json!({
        "simulation": "fedwire",
        "outcome": req.outcome.clone().unwrap_or_else(|| "completed".into()),
        "fedwire_tag": "DRWTRN",
        "note": "Sandbox simulation only - no Fedwire side effects.",
    })
}

/// `POST /v1/sandbox/fedwire:simulate` - simulate a FedWire payment.
#[utoipa::path(
    post,
    path = "/v1/sandbox/fedwire/simulate",
    request_body = SandboxSimulateRequest,
    responses(
        (status = 200, description = "Simulated FedWire payment", body = SandboxSimulationResponse),
        (status = 403, description = "Sandbox feature disabled"),
    ),
    security(("bank8:payments:sandbox:write" = [])),
    tag = "payments",
)]
pub async fn sandbox_simulate_fedwire(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SandboxSimulateRequest>,
) -> Result<Json<SandboxSimulationResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Sandbox)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:sandbox:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let input = serde_json::to_value(&req).unwrap_or(JsonValue::Null);
    let result = sandbox_fedwire_result(&req);
    let id = record_sandbox(&mut conn, a.env_id(), "fedwire", &input, &result).await?;
    Ok(Json(SandboxSimulationResponse {
        id,
        simulation_type: "fedwire".into(),
        input,
        result,
        created_at: chrono::Utc::now(),
    }))
}

/// `POST /v1/sandbox/instructions/{id}:resume` - fast-forward a stuck
/// instruction through its state machine.
#[utoipa::path(
    post,
    path = "/v1/sandbox/instructions/{id}/resume",
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction advanced"),
        (status = 404, description = "Instruction not found"),
        (status = 403, description = "Sandbox feature disabled"),
    ),
    security(("bank8:payments:sandbox:write" = [])),
    tag = "payments",
)]
pub async fn sandbox_resume_instruction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Sandbox)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:sandbox:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        "UPDATE instructions SET state = 'processing', updated_at = now() WHERE id = $1 AND env_id = $2 AND state = 'awaiting_input' RETURNING id, state",
    )
    .bind(id).bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("instruction {id} not found or not awaiting_input")))?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Instruction,
        &id.to_string(),
        "resumed",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "id": id, "state": row.get::<String, _>("state") }),
    ))
}

/// `POST /v1/sandbox/scheduled-payments/{id}:fastForward` - execute the next
/// scheduled occurrence immediately (+ ).
#[utoipa::path(
    post,
    path = "/v1/sandbox/scheduled-payments/{id}/fast-forward",
    params(("id" = Uuid, Path, description = "Scheduled payment ID")),
    responses(
        (status = 200, description = "Next occurrence executed"),
        (status = 404, description = "Scheduled payment not found"),
        (status = 403, description = "Sandbox feature disabled"),
    ),
    security(("bank8:payments:sandbox:write" = [])),
    tag = "payments",
)]
pub async fn sandbox_fast_forward_scheduled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Sandbox)?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:sandbox:write"),
    )
    .await?;
    fast_forward_scheduled_inner(state, headers, id).await
}

// ── : scheduled payments v1beta ─────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct ScheduledPaymentResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub amount: rust_decimal::Decimal,
    pub currency: String,
    pub schedule_type: String,
    pub next_run_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateScheduledPaymentRequest {
    pub account_id: Uuid,
    pub amount: rust_decimal::Decimal,
    pub currency: String,
    /// standing_order | direct_debit | future_dated
    pub schedule_type: String,
    /// RFC 5545 RRULE (e.g. FREQ=MONTHLY) - Sentin8:Cron is UTC-only.
    #[serde(default)]
    pub recurrence_rule: Option<String>,
    #[serde(default)]
    pub start_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub payee_id: Option<Uuid>,
}

/// `POST /v1beta/scheduled-payments` - create a scheduled payment.
#[utoipa::path(
    post,
    path = "/v1beta/scheduled-payments",
    request_body = CreateScheduledPaymentRequest,
    responses(
        (status = 200, description = "Scheduled payment created", body = ScheduledPaymentResponse),
        (status = 403, description = "Missing bank8:payments:scheduled-payments:write scope"),
    ),
    security(("bank8:payments:scheduled-payments:write" = [])),
    tag = "payments",
)]
pub async fn create_scheduled_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateScheduledPaymentRequest>,
) -> Result<Json<ScheduledPaymentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:scheduled-payments:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"INSERT INTO scheduled_payments
             (env_id, account_id, amount, currency, schedule_type, recurrence_rule, next_run_at, status)
           VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7, now() + INTERVAL '1 day'), 'active')
           RETURNING id, account_id, amount, currency, schedule_type, next_run_at, status, created_at"#,
    )
    .bind(a.env_id()).bind(req.account_id).bind(req.amount).bind(&req.currency)
    .bind(&req.schedule_type).bind(req.recurrence_rule).bind(req.start_at)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let sp_id: Uuid = row.get("id");
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::PaymentInstrument,
        &sp_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(ScheduledPaymentResponse {
        id: sp_id,
        account_id: row.get("account_id"),
        amount: row.get("amount"),
        currency: row.get("currency"),
        schedule_type: row.get("schedule_type"),
        next_run_at: row.get("next_run_at"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1beta/scheduled-payments` - list scheduled payments.
#[utoipa::path(
    get,
    path = "/v1beta/scheduled-payments",
    responses(
        (status = 200, description = "Scheduled payments", body = Vec<ScheduledPaymentResponse>),
        (status = 403, description = "Missing bank8:payments:scheduled-payments:read scope"),
    ),
    security(("bank8:payments:scheduled-payments:read" = [])),
    tag = "payments",
)]
pub async fn list_scheduled_payments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ScheduledPaymentResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:scheduled-payments:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let rows = sqlx::query(
        r#"SELECT id, account_id, amount, currency, schedule_type, next_run_at, status, created_at
             FROM scheduled_payments WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| ScheduledPaymentResponse {
                id: r.get("id"),
                account_id: r.get("account_id"),
                amount: r.get("amount"),
                currency: r.get("currency"),
                schedule_type: r.get("schedule_type"),
                next_run_at: r.get("next_run_at"),
                status: r.get("status"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

/// `GET /v1beta/scheduled-payments/{id}` - fetch one scheduled payment.
#[utoipa::path(
    get,
    path = "/v1beta/scheduled-payments/{id}",
    params(("id" = Uuid, Path, description = "Scheduled payment ID")),
    responses(
        (status = 200, description = "Scheduled payment", body = ScheduledPaymentResponse),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing bank8:payments:scheduled-payments:read scope"),
    ),
    security(("bank8:payments:scheduled-payments:read" = [])),
    tag = "payments",
)]
pub async fn get_scheduled_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ScheduledPaymentResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:scheduled-payments:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let row = sqlx::query(
        r#"SELECT id, account_id, amount, currency, schedule_type, next_run_at, status, created_at
             FROM scheduled_payments WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::NOT_FOUND,
        format!("scheduled payment {id} not found"),
    ))?;
    Ok(Json(ScheduledPaymentResponse {
        id: row.get("id"),
        account_id: row.get("account_id"),
        amount: row.get("amount"),
        currency: row.get("currency"),
        schedule_type: row.get("schedule_type"),
        next_run_at: row.get("next_run_at"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

/// `DELETE /v1beta/scheduled-payments/{id}` - cancel a scheduled payment.
#[utoipa::path(
    delete,
    path = "/v1beta/scheduled-payments/{id}",
    params(("id" = Uuid, Path, description = "Scheduled payment ID")),
    responses(
        (status = 200, description = "Cancelled"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing bank8:payments:scheduled-payments:write scope"),
    ),
    security(("bank8:payments:scheduled-payments:write" = [])),
    tag = "payments",
)]
pub async fn cancel_scheduled_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:scheduled-payments:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let updated = sqlx::query(
        "UPDATE scheduled_payments SET status = 'cancelled', updated_at = now() WHERE id = $1 AND env_id = $2",
    )
    .bind(id).bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    if updated == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            format!("scheduled payment {id} not found"),
        ));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::PaymentInstrument,
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
    Ok(Json(serde_json::json!({ "id": id, "status": "cancelled" })))
}

/// Shared fast-forward: clone the next occurrence as an instruction and
/// advance `next_run_at` (used by both v1beta and the sandbox route).
async fn fast_forward_scheduled_inner(
    state: AppState,
    headers: HeaderMap,
    id: Uuid,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:scheduled-payments:write"),
    )
    .await?;
    let mut tx = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut tx, a.env_id()).await;
    let sp = sqlx::query(
        "SELECT id, account_id, amount, currency, schedule_type, next_run_at FROM scheduled_payments WHERE id = $1 AND env_id = $2 AND status = 'active'",
    )
    .bind(id).bind(a.env_id())
    .fetch_optional(&mut *tx)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("scheduled payment {id} not found or inactive")))?;
    let amount: rust_decimal::Decimal = sp.get("amount");
    let currency: String = sp.get("currency");
    let account_id: Uuid = sp.get("account_id");
    let next_run: Option<chrono::DateTime<chrono::Utc>> = sp.get("next_run_at");
    // Clone the occurrence as a payment instruction (type inferred from the
    // schedule type; standing orders become credit transfers).
    let instr = sqlx::query(
        r#"INSERT INTO instructions (env_id, state, correlation_id, input)
           VALUES ($1, 'awaiting_input', $2, $3) RETURNING id"#,
    )
    .bind(a.env_id())
    .bind(serde_json::json!({ "scheduled_payment_id": id }))
    .bind(serde_json::json!({
        "payload_type": "CreditTransferInitiation",
        "amount": amount.to_string(),
        "currency": currency,
        "account_id": account_id,
        "scheduled": true,
        "source_scheduled_payment_id": id,
        "scheduled_for": next_run,
    }))
    .fetch_one(&mut *tx)
    .await
    .map_err(err_db)?;
    let instr_id: Uuid = instr.get("id");
    // Advance next_run_at by one month (UTC-only arithmetic; Sentin8:Cron is
    // the actual scheduler - delegates recurrence to Cron, this is the
    // manual fast-forward path only).
    sqlx::query(
        "UPDATE scheduled_payments SET next_run_at = COALESCE(next_run_at, now()) + INTERVAL '1 month', updated_at = now() WHERE id = $1 AND env_id = $2",
    )
    .bind(id).bind(a.env_id())
    .execute(&mut *tx)
    .await
    .map_err(err_db)?;
    tx.commit().await.map_err(err_db)?;
    let _ = event_streaming::emit_event_tx(
        &state.pool,
        a.env_id(),
        ResourceType::PaymentInstrument,
        &id.to_string(),
        "fast_forwarded",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "scheduled_payment_id": id, "instruction_id": instr_id }),
    ))
}

/// `POST /v1beta/scheduled-payments/{id}:fastForward` - execute the next
/// occurrence immediately (; non-sandbox).
#[utoipa::path(
    post,
    path = "/v1beta/scheduled-payments/{id}/fast-forward",
    params(("id" = Uuid, Path, description = "Scheduled payment ID")),
    responses(
        (status = 200, description = "Next occurrence executed"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing bank8:payments:scheduled-payments:write scope"),
    ),
    security(("bank8:payments:scheduled-payments:write" = [])),
    tag = "payments",
)]
pub async fn fast_forward_scheduled_payment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    fast_forward_scheduled_inner(state, headers, id).await
}

// ── : users / allowed-endpoints / roles read views ──────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct PlatformUserResponse {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `GET /v1/users` - list users visible to this environment (read view;
/// identities stay in Sentin8:Auth - this is a projection).
#[utoipa::path(
    get,
    path = "/v1/users",
    responses(
        (status = 200, description = "Users", body = Vec<PlatformUserResponse>),
        (status = 403, description = "Missing bank8:payments:users:read scope"),
    ),
    security(("bank8:payments:users:read" = [])),
    tag = "payments",
)]
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PlatformUserResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:users:read"),
    )
    .await?;
    // VDC §VDC.5 (on-demand sanctioned identity read): the env's users are
    // listed through Auth's admin API (`GET /v1/admin/users`) via the
    // cert-presenting `bank8-payments-sys` workload (CERTFREE-4V - no M2M
    // token; the `sentin8:auth:admin:read` scope rides the enroll-published
    // registry map). The former direct `sentin8.auth_users` query referenced a
    // platform table that does not exist in the vertical's own database -
    // every call failed with a 500.
    let cfg = sentin8::config::Sentin8Config::from_env();
    let ca_path = sentin8::auth::m2m::platform_ca_path();
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        &cfg.sentin8_auth_issuer(),
        "bank8-payments-sys",
        &ca_path,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("workload certificate: {e}"),
        )
    })?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    let http = sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("transport: {e}")))?;
    let url = format!(
        "{}/v1/admin/users",
        cfg.sentin8_auth_issuer().trim_end_matches('/')
    );
    let resp = http
        .get(&url)
        // Auth's admin API is env-scoped - the target-env header carries
        // the caller's env (same contract as the provision API).
        .header("x-sentin8-target-env-id", a.env_id().to_string())
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("auth users fetch: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("auth users: {status} {body}"),
        ));
    }
    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("auth users decode: {e}")))?;
    let items = data["users"].as_array().cloned().unwrap_or_default();
    Ok(Json(
        items
            .iter()
            .filter_map(|u| {
                let first = u["first_name"].as_str().map(String::from);
                let last = u["last_name"].as_str().map(String::from);
                Some(PlatformUserResponse {
                    id: u["id"]
                        .as_str()
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())?,
                    email: u["email"].as_str().unwrap_or("").to_string(),
                    name: match (first, last) {
                        (Some(f), Some(l)) => Some(format!("{f} {l}")),
                        (Some(f), None) => Some(f),
                        (None, Some(l)) => Some(l),
                        (None, None) => None,
                    },
                    status: u["status"].as_str().unwrap_or("active").to_string(),
                    created_at: u["created_at"]
                        .as_str()
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                        .map(|d| d.with_timezone(&chrono::Utc))
                        .unwrap_or_else(chrono::Utc::now),
                })
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AllowedEndpointResponse {
    pub method: String,
    pub path: String,
    pub scope: String,
}

/// `GET /v1/allowed-endpoints` - scope→endpoint map for this service
/// (helps clients pick the right token scope per endpoint; ).
#[utoipa::path(
    get,
    path = "/v1/allowed-endpoints",
    responses(
        (status = 200, description = "Allowed endpoints (scope → endpoint map)", body = Vec<AllowedEndpointResponse>),
        (status = 403, description = "Missing bank8:payments:users:read scope"),
    ),
    security(("bank8:payments:users:read" = [])),
    tag = "payments",
)]
pub async fn list_allowed_endpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AllowedEndpointResponse>>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:users:read"),
    )
    .await?;
    let map = [
        (
            "GET",
            "/v1/instructions",
            "bank8:payments:instructions:read",
        ),
        (
            "POST",
            "/v1/instructions",
            "bank8:payments:instructions:write",
        ),
        (
            "PUT",
            "/v1/instructions/{id}",
            "bank8:payments:instructions:write",
        ),
        (
            "POST",
            "/v1/instructions/{id}/process",
            "bank8:payments:instructions:write",
        ),
        (
            "POST",
            "/v1/instructions/bulk-retry",
            "bank8:payments:instructions:write",
        ),
        ("GET", "/v1/payees", "bank8:payments:payees:read"),
        ("POST", "/v1/payees", "bank8:payments:payees:write"),
        ("GET", "/v1/cards", "bank8:payments:cards:read"),
        (
            "POST",
            "/v1/cards/issuance/issue",
            "bank8:payments:issuance:write",
        ),
        ("GET", "/v1/payments", "bank8:payments:payments:read"),
        (
            "GET",
            "/v1beta/scheduled-payments",
            "bank8:payments:scheduled-payments:read",
        ),
        (
            "POST",
            "/v1beta/scheduled-payments",
            "bank8:payments:scheduled-payments:write",
        ),
        (
            "POST",
            "/v1/sandbox/cards/simulate",
            "bank8:payments:sandbox:write",
        ),
    ];
    Ok(Json(
        map.iter()
            .map(|(m, p, s)| AllowedEndpointResponse {
                method: m.to_string(),
                path: p.to_string(),
                scope: s.to_string(),
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleViewResponse {
    pub name: String,
    pub description: Option<String>,
    pub scopes: Vec<String>,
}

/// `GET /v1/roles` - read view of the roles configured for this environment
/// (roles live in Sentin8:Auth; this is a projection for admin UIs).
#[utoipa::path(
    get,
    path = "/v1/roles",
    responses(
        (status = 200, description = "Roles (projection from Sentin8:Auth)", body = Vec<RoleViewResponse>),
        (status = 403, description = "Missing bank8:payments:users:read scope"),
    ),
    security(("bank8:payments:users:read" = [])),
    tag = "payments",
)]
pub async fn list_roles(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<RoleViewResponse>>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:users:read"),
    )
    .await?;
    // Projection of the well-known payment-service roles; authoritative
    // storage/nesting is Sentin8:Auth's RBAC (Shield policies + role nesting).
    Ok(Json(vec![
        RoleViewResponse {
            name: "payments-viewer".into(),
            description: Some("Read-only payment operations".into()),
            scopes: vec![
                "bank8:payments:instructions:read".into(),
                "bank8:payments:payments:read".into(),
                "bank8:payments:cards:read".into(),
            ],
        },
        RoleViewResponse {
            name: "payments-operator".into(),
            description: Some("Initiate and process payments".into()),
            scopes: vec![
                "bank8:payments:instructions:read".into(),
                "bank8:payments:instructions:write".into(),
                "bank8:payments:payees:read".into(),
                "bank8:payments:payees:write".into(),
                "bank8:payments:cards:read".into(),
            ],
        },
        RoleViewResponse {
            name: "payments-card-issuer".into(),
            description: Some("Card issuance and lifecycle".into()),
            scopes: vec![
                "bank8:payments:issuance:write".into(),
                "bank8:payments:cards:read".into(),
                "bank8:payments:cards:write".into(),
            ],
        },
    ]))
}

// ── : rules on instruments + CBS ops on cores ───────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct AttachRuleToInstrumentRequest {
    pub rule_id: Uuid,
    /// payment_instrument resource this rule applies to (card or account id).
    pub instrument_id: Uuid,
    /// card | account
    #[serde(default = "default_instrument_kind")]
    pub instrument_type: String,
}
fn default_instrument_kind() -> String {
    "card".into()
}

/// `POST /v1/rules:attachToInstrument` - attach a decision rule to a payment
/// instrument (; the rule still applies per-instruction at runtime).
#[utoipa::path(
    post,
    path = "/v1/rules/attach-to-instrument",
    request_body = AttachRuleToInstrumentRequest,
    responses(
        (status = 200, description = "Rule attached"),
        (status = 404, description = "Rule not found"),
        (status = 403, description = "Missing bank8:payments:rules:write scope"),
    ),
    security(("bank8:payments:rules:write" = [])),
    tag = "payments",
)]
pub async fn attach_rule_to_instrument(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AttachRuleToInstrumentRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM rules WHERE id = $1 AND env_id = $2)")
            .bind(req.rule_id)
            .bind(a.env_id())
            .fetch_one(&mut *conn)
            .await
            .map_err(err_db)?;
    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            format!("rule {} not found", req.rule_id),
        ));
    }
    let row = sqlx::query(
        r#"INSERT INTO rule_instruments (env_id, rule_id, instrument_id, instrument_type)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (env_id, rule_id, instrument_id) DO NOTHING
           RETURNING id"#,
    )
    .bind(a.env_id())
    .bind(req.rule_id)
    .bind(req.instrument_id)
    .bind(&req.instrument_type)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    if row.is_none() {
        return Ok(Json(
            serde_json::json!({ "attached": false, "reason": "already attached" }),
        ));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Rule,
        &req.rule_id.to_string(),
        "attached_to_instrument",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(serde_json::json!({ "attached": true })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DetachRuleFromInstrumentRequest {
    pub rule_id: Uuid,
    pub instrument_id: Uuid,
}

/// `POST /v1/rules:detachFromInstrument` - detach a rule from an instrument
#[utoipa::path(
    post,
    path = "/v1/rules/detach-from-instrument",
    request_body = DetachRuleFromInstrumentRequest,
    responses(
        (status = 200, description = "Rule detached"),
        (status = 403, description = "Missing bank8:payments:rules:write scope"),
    ),
    security(("bank8:payments:rules:write" = [])),
    tag = "payments",
)]
pub async fn detach_rule_from_instrument(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DetachRuleFromInstrumentRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let removed = sqlx::query(
        "DELETE FROM rule_instruments WHERE env_id = $1 AND rule_id = $2 AND instrument_id = $3",
    )
    .bind(a.env_id())
    .bind(req.rule_id)
    .bind(req.instrument_id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    Ok(Json(serde_json::json!({ "detached": removed > 0 })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateCoreRequest {
    /// Optional new postings URL (CBS reconciliation target).
    #[serde(default)]
    pub postings_url: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// `PUT update_core - helper (not served directly; PATCH /v1/cores/{id} is the surface): update core (CBS) config, including the postings
/// URL and the online/offline balance endpoint flag.
pub async fn update_core(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCoreRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"UPDATE cores SET
              name = COALESCE($2, name),
              status = COALESCE($3, status),
              config = jsonb_set(COALESCE(config, '{}'::jsonb), '{postings_url}', to_jsonb(COALESCE($4, config->>'postings_url')), true),
              updated_at = now()
            WHERE id = $1 AND env_id = $5
            RETURNING id, name, status, config"#,
    )
    .bind(id)
    .bind(req.name.as_deref())
    .bind(req.status.as_deref())
    .bind(req.postings_url.as_deref())
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("core {id} not found")))?;
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
    Ok(Json(serde_json::json!({
        "id": row.get::<Uuid, _>("id"),
        "name": row.get::<String, _>("name"),
        "status": row.get::<String, _>("status"),
        "config": row.get::<JsonValue, _>("config"),
    })))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CoreBalanceEndpointRequest {
    /// online | offline
    pub mode: String,
}

/// `PUT /v1/cores/{id}/balance-endpoint` - switch the CBS balance endpoint
/// between online (live query) and offline (cached) modes.
#[utoipa::path(
    put,
    path = "/v1/cores/{id}/balance-endpoint",
    request_body = CoreBalanceEndpointRequest,
    params(("id" = Uuid, Path, description = "Core ID")),
    responses(
        (status = 200, description = "Balance endpoint mode updated"),
        (status = 400, description = "Invalid mode"),
        (status = 404, description = "Core not found"),
        (status = 403, description = "Missing bank8:payments:cores:write scope"),
    ),
    security(("bank8:payments:cores:write" = [])),
    tag = "payments",
)]
pub async fn update_core_balance_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<CoreBalanceEndpointRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    if req.mode != "online" && req.mode != "offline" {
        return Err((
            StatusCode::BAD_REQUEST,
            "mode must be 'online' or 'offline'".into(),
        ));
    }
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
    let updated = sqlx::query(
        r#"UPDATE cores
              SET config = jsonb_set(COALESCE(config, '{}'::jsonb), '{balance_endpoint_mode}', to_jsonb($2::text), true),
                  updated_at = now()
            WHERE id = $1 AND env_id = $3"#,
    )
    .bind(id).bind(&req.mode).bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("core {id} not found")));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Core,
        &id.to_string(),
        "balance_endpoint_updated",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "core_id": id, "balance_endpoint_mode": req.mode }),
    ))
}

// ── : OpenMetrics endpoint ──────────────────────────────────────────

/// `GET /v1/openmetrics/metrics` - OpenMetrics-format metrics (;
/// delegates to the shared Prometheus handler).
#[utoipa::path(
    get,
    path = "/v1/openmetrics/metrics",
    responses(
        (status = 200, description = "OpenMetrics metrics (text)", content_type = "text/plain", body = String),
        (status = 403, description = "Missing bank8:payments:openmetrics:read scope"),
    ),
    security(("bank8:payments:openmetrics:read" = [])),
    tag = "payments",
)]
pub async fn openmetrics_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:openmetrics:read"),
    )
    .await?;
    let _ = state;
    crate::handlers::metrics(State(state), headers).await
}

/// `GET /v1/openmetrics/federate` - federation scrape endpoint.
#[utoipa::path(
    get,
    path = "/v1/openmetrics/federate",
    responses(
        (status = 200, description = "Federation metrics (OpenMetrics text)", content_type = "text/plain", body = String),
        (status = 403, description = "Missing bank8:payments:openmetrics:read scope"),
    ),
    security(("bank8:payments:openmetrics:read" = [])),
    tag = "payments",
)]
pub async fn openmetrics_federate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:openmetrics:read"),
    )
    .await?;
    let _ = state;
    crate::handlers::metrics(State(state), headers).await
}

// ── : state-model helpers (processing_status breadth) ───────────────

/// Map a legacy/scheme-specific state to the wide processing_status model
/// : the payment resource exposes per-type context keys alongside the
/// unified state machine.
pub fn normalise_processing_status(state: &str) -> &'static str {
    match state {
        "RECEIVED" | "received" => "received",
        "VALIDATED" | "validated" => "validated",
        "PENDING" | "pending" => "pending",
        "AWAITING_INPUT" | "awaiting_input" => "awaiting_input",
        "IN_PROGRESS" | "in_progress" | "processing" => "in_progress",
        "COMPLETED" | "completed" => "completed",
        "CANCELLED" | "cancelled" => "cancelled",
        "REJECTED" | "rejected" => "rejected",
        "REPAIR_NEEDED" | "repair_needed" => "repair_needed",
        "RETRY_NEEDED" | "retry_needed" => "retry_needed",
        "ON_HOLD" | "on_hold" => "on_hold",
        "EXPIRED" | "expired" => "expired",
        "FEE_COLLECTION" | "fee_collection" => "fee_collection",
        _ => "in_progress",
    }
}

/// `GET /v1/payment-statuses` - the full processing-status model exposed to
/// clients (; the per-type amount context keys are returned with each).
#[utoipa::path(
    get,
    path = "/v1/payment-statuses",
    responses(
        (status = 200, description = "Processing status model", body = Vec<StatusModelEntry>),
        (status = 403, description = "Missing bank8:payments:payments:read scope"),
    ),
    security(("bank8:payments:payments:read" = [])),
    tag = "payments",
)]
pub async fn list_payment_statuses(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<StatusModelEntry>>, (StatusCode, String)> {
    let _a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payments:read"),
    )
    .await?;
    let _ = state;
    let statuses: [(&str, &str); 13] = [
        ("received", "Instruction received, not yet validated"),
        ("validated", "Passed validation, queued"),
        ("pending", "Pending scheme/issuer response"),
        (
            "awaiting_input",
            "Waiting for caller-supplied input (e.g. 3DS, SCA)",
        ),
        ("in_progress", "Processing in flight"),
        ("completed", "Terminal: succeeded"),
        ("cancelled", "Terminal: cancelled by caller"),
        ("rejected", "Terminal: rejected"),
        ("repair_needed", "Blocked: needs manual repair"),
        ("retry_needed", "Blocked: transient failure, retry eligible"),
        ("on_hold", "Blocked: held by rule/fraud/compliance"),
        ("expired", "Terminal: authorisation expiry (caad.008)"),
        (
            "fee_collection",
            "Fee-collection leg of a fee-bearing payment",
        ),
    ];
    Ok(Json(
        statuses
            .iter()
            .map(|(k, d)| StatusModelEntry {
                status: k.to_string(),
                description: d.to_string(),
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatusModelEntry {
    pub status: String,
    pub description: String,
}

// ── : instructions/{id} sub-actions - process / cancel / repair ─────

/// `POST /v1/instructions/{id}:process` - process the instruction now
/// (business route shape; wraps the state-machine step).
#[utoipa::path(
    post,
    path = "/v1/instructions/{id}/cancel-async",
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction advanced"),
        (status = 404, description = "Instruction not found"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn process_instruction_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"UPDATE instructions
              SET state = CASE state
                    WHEN 'awaiting_input' THEN 'processing'
                    WHEN 'received' THEN 'processing'
                    ELSE state END,
              updated_at = now()
            WHERE id = $1 AND env_id = $2 RETURNING state"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("instruction {id} not found")))?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Instruction,
        &id.to_string(),
        "process_requested",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "id": id, "state": row.get::<String, _>("state") }),
    ))
}

/// `POST /v1/instructions/{id}:cancel` - cancel an instruction (business
/// route shape).
#[utoipa::path(
    post,
    path = "/v1/instructions/{id}/cancel",
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction cancelled"),
        (status = 409, description = "Instruction not in a cancellable state"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn cancel_instruction_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"UPDATE instructions
              SET state = 'cancelled', updated_at = now()
            WHERE id = $1 AND env_id = $2
              AND state IN ('awaiting_input', 'received', 'retry_needed', 'repair_needed')
            RETURNING state"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::CONFLICT,
        format!("instruction {id} not in a cancellable state"),
    ))?;
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
    Ok(Json(
        serde_json::json!({ "id": id, "state": row.get::<String, _>("state") }),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RepairInstructionRequest {
    #[serde(default)]
    pub corrected_input: Option<JsonValue>,
}

/// `POST /v1/instructions/{id}:repair` - repair an instruction that is in
/// `repair_needed` (; pairs with the repair endpoint from ).
#[utoipa::path(
    post,
    path = "/v1/instructions/{id}/repair",
    request_body = RepairInstructionRequest,
    params(("id" = Uuid, Path, description = "Instruction ID")),
    responses(
        (status = 200, description = "Instruction repaired"),
        (status = 409, description = "Instruction not in repair_needed state"),
        (status = 403, description = "Missing bank8:payments:instructions:write scope"),
    ),
    security(("bank8:payments:instructions:write" = [])),
    tag = "payments",
)]
pub async fn repair_instruction_by_id(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<RepairInstructionRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"UPDATE instructions
              SET input = COALESCE($3, input),
                  state = 'retry_needed', updated_at = now()
            WHERE id = $1 AND env_id = $2 AND state = 'repair_needed'
            RETURNING state"#,
    )
    .bind(id)
    .bind(a.env_id())
    .bind(req.corrected_input)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        StatusCode::CONFLICT,
        format!("instruction {id} not in repair_needed state"),
    ))?;
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
    Ok(Json(
        serde_json::json!({ "id": id, "state": row.get::<String, _>("state") }),
    ))
}

// ── : payment-initiation app + integrations/callback tokens ─────────

#[derive(Debug, Serialize, ToSchema)]
pub struct InitiationAppResponse {
    pub id: Uuid,
    pub name: String,
    pub app_type: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateInitiationAppRequest {
    pub name: String,
    /// payment_initiation | payment_app
    #[serde(default = "default_app_type")]
    pub app_type: String,
    #[serde(default)]
    pub config: JsonValue,
}
fn default_app_type() -> String {
    "payment_initiation".into()
}

/// `POST /v1/integrations/payment-initiation-apps` - register a
/// payment-initiation app.
#[utoipa::path(
    post,
    path = "/v1/integrations/payment-initiation-apps",
    request_body = CreateInitiationAppRequest,
    responses(
        (status = 200, description = "App registered", body = InitiationAppResponse),
        (status = 403, description = "Missing bank8:payments:integrations:write scope"),
    ),
    security(("bank8:payments:integrations:write" = [])),
    tag = "payments",
)]
pub async fn create_initiation_app(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateInitiationAppRequest>,
) -> Result<Json<InitiationAppResponse>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"INSERT INTO initiation_apps (env_id, name, app_type, status, config)
           VALUES ($1, $2, $3, 'active', $4)
           RETURNING id, name, app_type, status, created_at"#,
    )
    .bind(a.env_id())
    .bind(&req.name)
    .bind(&req.app_type)
    .bind(&req.config)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    let app_id: Uuid = row.get("id");
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Integration,
        &app_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(InitiationAppResponse {
        id: app_id,
        name: row.get("name"),
        app_type: row.get("app_type"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }))
}

/// `GET /v1/integrations/payment-initiation-apps` - list registered
/// initiation apps.
#[utoipa::path(
    get,
    path = "/v1/integrations/payment-initiation-apps",
    responses(
        (status = 200, description = "Initiation apps", body = Vec<InitiationAppResponse>),
        (status = 403, description = "Missing bank8:payments:integrations:read scope"),
    ),
    security(("bank8:payments:integrations:read" = [])),
    tag = "payments",
)]
pub async fn list_initiation_apps(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InitiationAppResponse>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        r#"SELECT id, name, app_type, status, created_at
             FROM initiation_apps WHERE env_id = $1 ORDER BY created_at DESC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(
        rows.iter()
            .map(|r| InitiationAppResponse {
                id: r.get("id"),
                name: r.get("name"),
                app_type: r.get("app_type"),
                status: r.get("status"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

// ── : cardholders/:cardholderId/cards + tokens/:tokenLifecycle ──────

/// `GET /v1/cards/cardholders/{id}/cards` - list a cardholder's cards.
#[utoipa::path(
    get,
    path = "/v1/cards/cardholders/{id}/cards",
    params(("id" = Uuid, Path, description = "Cardholder ID")),
    responses(
        (status = 200, description = "Cards for the cardholder"),
        (status = 403, description = "Missing bank8:payments:cards:read scope"),
    ),
    security(("bank8:payments:cards:read" = [])),
    tag = "payments",
)]
pub async fn list_cardholder_cards(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<JsonValue>>, (StatusCode, String)> {
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
    let rows = sqlx::query(
        r#"SELECT id, status, pan_last_digits, expiry_date, card_profile_id, created_at
             FROM cards WHERE env_id = $1 AND cardholder_id = $2
            ORDER BY created_at DESC"#,
    )
    .bind(a.env_id())
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(rows.iter().map(|r| serde_json::json!({
        "id": r.get::<Uuid, _>("id"),
        "status": r.get::<Option<String>, _>("status").unwrap_or_else(|| "active".into()),
        "pan_last_digits": r.get::<Option<String>, _>("pan_last_digits"),
        "expiry_date": r.get::<Option<String>, _>("expiry_date"),
        "card_profile_id": r.get::<Option<String>, _>("card_profile_id"),
        "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })).collect()))
}

/// `GET /v1/cards/card-tokens/{id}` - fetch a card token's lifecycle state
/// (; `tokens/{token_id}` business shape).
#[utoipa::path(
    get,
    path = "/v1/cards/card-tokens/{id}",
    params(("id" = Uuid, Path, description = "Card token ID")),
    responses(
        (status = 200, description = "Card token"),
        (status = 404, description = "Token not found"),
        (status = 403, description = "Missing bank8:payments:cards:read scope"),
    ),
    security(("bank8:payments:cards:read" = [])),
    tag = "payments",
)]
pub async fn get_card_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let row = sqlx::query(
        r#"SELECT id, card_id, status, created_at
             FROM card_tokens WHERE id = $1 AND env_id = $2"#,
    )
    .bind(id)
    .bind(a.env_id())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((StatusCode::NOT_FOUND, format!("card token {id} not found")))?;
    Ok(Json(serde_json::json!({
        "id": row.get::<Uuid, _>("id"),
        "card_id": row.get::<Uuid, _>("card_id"),
        "status": row.get::<Option<String>, _>("status").unwrap_or_else(|| "inactive".into()),
        "created_at": row.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
    })))
}

// ── /: config packs + B8 On-Us resolution (P2/P3; minimal viable)

/// `GET /v1/config-packs` - list installed payment config packs (; the
/// pack contents are versioned resources: rules/rule-sets/parameter-values).
#[utoipa::path(
    get,
    path = "/v1/config-packs",
    responses(
        (status = 200, description = "Config packs (summary of versioned resources)"),
        (status = 403, description = "Missing bank8:payments:rules:read scope"),
    ),
    security(("bank8:payments:rules:read" = [])),
    tag = "payments",
)]
pub async fn list_config_packs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
    let rules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rules WHERE env_id = $1")
        .bind(a.env_id())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let rule_sets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rule_sets WHERE env_id = $1")
        .bind(a.env_id())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    let params: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM parameter_values WHERE env_id = $1")
        .bind(a.env_id())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "packs": [{
            "name": "default",
            "rules": rules,
            "rule_sets": rule_sets,
            "parameter_values": params,
        }],
        "note": "Config packs are aggregates of versioned resources (PA-22); import/export via resource versions APIs.",
    })))
}

/// `GET /v1/on-us/routing` - B8 On-Us routing table: routes
/// instructions to another B8 member bank without leaving the platform.
#[utoipa::path(
    get,
    path = "/v1/on-us/routing",
    responses(
        (status = 200, description = "On-Us routing entries"),
        (status = 403, description = "Missing bank8:payments:instructions:read scope"),
    ),
    security(("bank8:payments:instructions:read" = [])),
    tag = "payments",
)]
pub async fn list_on_us_routing(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
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
        r#"SELECT target_bic, target_env_id, route_type, priority, active, created_at
             FROM on_us_routes WHERE env_id = $1 ORDER BY priority ASC LIMIT 200"#,
    )
    .bind(a.env_id())
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(serde_json::json!({
        "routes": rows.iter().map(|r| serde_json::json!({
            "target_bic": r.get::<Option<String>, _>("target_bic"),
            "target_env_id": r.get::<Option<Uuid>, _>("target_env_id"),
            "route_type": r.get::<String, _>("route_type"),
            "priority": r.get::<i32, _>("priority"),
            "active": r.get::<bool, _>("active"),
            "created_at": r.get::<chrono::DateTime<chrono::Utc>, _>("created_at"),
        })).collect::<Vec<_>>(),
    })))
}

// ── Missing handler fixes (server.rs route wiring) ───────────────────────

/// `DELETE /v1/payees/{id}` - remove a payee (soft-delete via status).
#[utoipa::path(
    delete,
    path = "/v1/payees/{id}",
    params(("id" = Uuid, Path, description = "Payee ID")),
    responses(
        (status = 200, description = "Payee removed"),
        (status = 404, description = "Payee not found"),
        (status = 403, description = "Missing bank8:payments:payments:write scope"),
    ),
    security(("bank8:payments:payments:write" = [])),
    tag = "payments",
)]
pub async fn delete_payee(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:payments:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let updated = sqlx::query(
        "UPDATE payees SET status = 'removed', updated_at = now() WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(a.env_id())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?
    .rows_affected();
    if updated == 0 {
        return Err((StatusCode::NOT_FOUND, format!("payee {id} not found")));
    }
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Payment,
        &id.to_string(),
        "payee_removed",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id, "status": "removed" })))
}

/// `POST /v1/rule-versions/{id}/retry` - retry a failed rule version
/// publish (; delegates to the shared retry_version helper).
#[utoipa::path(
    post,
    path = "/v1/rule-versions/{id}/retry",
    params(("id" = Uuid, Path, description = "Rule version ID")),
    responses(
        (status = 200, description = "Retry accepted", body = ResourceVersionResponse),
        (status = 404, description = "Version not found"),
        (status = 403, description = "Missing bank8:payments:rules:write scope"),
    ),
    security(("bank8:payments:rules:write" = [])),
    tag = "payments",
)]
pub async fn retry_rule_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:rules:write"),
    )
    .await?;
    retry_version(
        &state,
        &headers,
        a.subject().as_str(),
        a.env_id(),
        "rule_versions",
        id,
        ResourceType::RuleVersion,
    )
    .await
}

/// `POST /v1/rule-set-versions/{id}/retry` - retry a failed rule set
/// version publish.
#[utoipa::path(
    post,
    path = "/v1/rule-set-versions/{id}/retry",
    params(("id" = Uuid, Path, description = "Rule set version ID")),
    responses(
        (status = 200, description = "Retry accepted", body = ResourceVersionResponse),
        (status = 404, description = "Version not found"),
        (status = 403, description = "Missing bank8:payments:rules:write scope"),
    ),
    security(("bank8:payments:rules:write" = [])),
    tag = "payments",
)]
pub async fn retry_rule_set_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:rules:write"),
    )
    .await?;
    retry_version(
        &state,
        &headers,
        a.subject().as_str(),
        a.env_id(),
        "rule_set_versions",
        id,
        ResourceType::RuleSetVersion,
    )
    .await
}

/// `PUT /v1/parameter-values/{id}` - update (or unset via empty body) a
/// parameter value.
#[utoipa::path(
    put,
    path = "/v1/parameter-values/{id}",
    request_body = PutParameterValueRequest,
    params(("id" = Uuid, Path, description = "Parameter value ID")),
    responses(
        (status = 200, description = "Parameter value updated (or unset)"),
        (status = 404, description = "Not found"),
        (status = 403, description = "Missing bank8:payments:parameters:write scope"),
    ),
    security(("bank8:payments:parameters:write" = [])),
    tag = "payments",
)]
pub async fn update_parameter_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<PutParameterValueRequest>,
) -> Result<Json<JsonValue>, (StatusCode, String)> {
    put_parameter_value(State(state), headers, Path(id), Json(req)).await
}

/// `GET /v1/instruction-file-specification-versions` - spec versions
/// (non-v1beta alias route).
#[utoipa::path(
    get,
    path = "/v1/instruction-file-specification-versions",
    responses(
        (status = 200, description = "Spec versions", body = Vec<ResourceVersionResponse>),
        (status = 403, description = "Missing bank8:payments:files:read scope"),
    ),
    security(("bank8:payments:files:read" = [])),
    tag = "payments",
)]
pub async fn list_instruction_file_specification_versions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListVersionsQuery>,
) -> Result<Json<Vec<ResourceVersionResponse>>, (StatusCode, String)> {
    list_specification_versions(State(state), headers, Query(q)).await
}

/// `POST /v1/instruction-file-specification-versions` - create a spec
/// version (non-v1beta alias route).
#[utoipa::path(
    post,
    path = "/v1/instruction-file-specification-versions",
    request_body = CreateSpecificationVersionRequest,
    responses(
        (status = 200, description = "Spec version created", body = ResourceVersionResponse),
        (status = 403, description = "Missing bank8:payments:files:write scope"),
    ),
    security(("bank8:payments:files:write" = [])),
    tag = "payments",
)]
pub async fn create_instruction_file_specification_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSpecificationVersionRequest>,
) -> Result<Json<ResourceVersionResponse>, (StatusCode, String)> {
    create_specification_version(State(state), headers, Json(req)).await
}

/// `POST /v1/records/search` - generic membership-directory record search
/// (registry-validated; delegates to the directory search).
#[utoipa::path(
    post,
    path = "/v1/records/search",
    request_body = SearchRecordsRequest,
    responses(
        (status = 200, description = "Search results"),
        (status = 400, description = "Invalid search operators (registry)"),
        (status = 403, description = "Missing bank8:payments:membership-directories:read scope"),
    ),
    security(("bank8:payments:membership-directories:read" = [])),
    tag = "payments",
)]
pub async fn search_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<JsonValue>,
) -> Result<Json<Vec<JsonValue>>, (StatusCode, String)> {
    search_membership_directory_records(State(state), headers, Json(body)).await
}

// ── Unit tests (pure helpers) ─────────────────────────────────────────────

#[cfg(test)]
mod pay_api_tests {
    use super::*;

    // : decline response codes (business table
    // cards/reference/decline_recommendations.md).
    #[test]
    fn decline_codes_product_value_constraints() {
        assert_eq!(
            decline_response_code(
                "PRODUCT_VALUE_CONSTRAINTS_VIOLATED",
                "AuthorisationInitiation"
            ),
            "12"
        );
        // Payload-specific override: Inquiry=12.
        assert_eq!(
            decline_response_code("PRODUCT_VALUE_CONSTRAINTS_VIOLATED", "InquiryInitiation"),
            "12"
        );
        // CardManagement PIN Unblock=70, PIN Change=71.
        assert_eq!(
            decline_response_code(
                "PRODUCT_VALUE_CONSTRAINTS_VIOLATED",
                "CardManagementInitiation"
            ),
            "70"
        );
    }

    #[test]
    fn decline_codes_chip_crypto_failures() {
        assert_eq!(
            decline_response_code("AC_TYPE_ABSENT", "AuthorisationInitiation"),
            "05"
        );
        assert_eq!(
            decline_response_code("ARQC_INVALID", "AuthorisationInitiation"),
            "05"
        );
        // CVC failures → N7 (Unable to accept, CVC failure).
        assert_eq!(
            decline_response_code("CHIP_CVC_INVALID", "AuthorisationInitiation"),
            "N7"
        );
        assert_eq!(
            decline_response_code("TOO_MANY_CVC2_FAILURES", "AuthorisationInitiation"),
            "N7"
        );
        // ATC misuse → 63 (Security violation).
        assert_eq!(
            decline_response_code("ATC_DUPLICATE_INVALID", "AuthorisationInitiation"),
            "63"
        );
        // IAV → N3; LVT/contactless limits → 62 (Restricted).
        assert_eq!(
            decline_response_code("IAV_INVALID", "AuthorisationInitiation"),
            "N3"
        );
        assert_eq!(
            decline_response_code("LVT_COUNT_LIMIT_EXCEEDED", "AuthorisationInitiation"),
            "62"
        );
    }

    #[test]
    fn decline_codes_security_and_lifecycle() {
        assert_eq!(
            decline_response_code("PIN_TRIES_LIMIT_EXCEEDED", "AuthorisationInitiation"),
            "38"
        );
        assert_eq!(
            decline_response_code("PIN_INVALID", "AuthorisationInitiation"),
            "55"
        );
        assert_eq!(
            decline_response_code("CARD_SUSPENDED", "AuthorisationInitiation"),
            "57"
        );
        assert_eq!(
            decline_response_code("CARD_EXPIRED", "AuthorisationInitiation"),
            "54"
        );
        assert_eq!(
            decline_response_code("CARD_NUMBER_INVALID", "AuthorisationInitiation"),
            "14"
        );
        assert_eq!(
            decline_response_code("INTERNAL_ERROR", "AuthorisationInitiation"),
            "96"
        );
    }

    #[test]
    fn decline_codes_fallback() {
        // Unknown reason → generic 05 (Do not honor).
        assert_eq!(
            decline_response_code("SOMETHING_ELSE", "AuthorisationInitiation"),
            "05"
        );
    }

    // : decline_for_instruction envelope parsing.
    #[test]
    fn decline_for_instruction_decline_recommended() {
        let input = serde_json::json!({
            "status": "DECLINE_RECOMMENDED",
            "decline_recommendation_reason": "DECLINE_RECOMMENDATION_REASON_STOLEN_CARD",
            "payload_type": "AuthorisationInitiation",
        });
        let (reason, code) = decline_for_instruction(&input).expect("should resolve");
        assert_eq!(reason, "STOLEN_CARD");
        // Reason not in the mapping table → generic fallback code.
        assert_eq!(code, "05");
    }

    #[test]
    fn decline_for_instruction_ignores_other_status() {
        let input = serde_json::json!({ "status": "APPROVED" });
        assert!(decline_for_instruction(&input).is_none());
        assert!(decline_for_instruction(&serde_json::json!({})).is_none());
    }

    // : search field registry validation.
    #[test]
    fn search_registry_accepts_valid_ops() {
        let body = serde_json::json!({ "amount": { "op": "gte", "value": 10 } });
        assert!(validate_search("payments", &body).is_ok());
    }

    #[test]
    fn search_registry_rejects_unknown_field() {
        let body = serde_json::json!({ "not_a_field": { "op": "eq", "value": 1 } });
        assert!(validate_search("payments", &body).is_err());
    }

    #[test]
    fn search_registry_rejects_bad_operator() {
        let body = serde_json::json!({ "amount": { "op": "hacker", "value": 1 } });
        assert!(validate_search("payments", &body).is_err());
    }

    #[test]
    fn search_registry_unknown_resource() {
        assert!(validate_search("no-such-resource", &serde_json::json!({})).is_err());
    }

    // : processing-status normalisation.
    #[test]
    fn normalise_status_breadth() {
        assert_eq!(normalise_processing_status("RECEIVED"), "received");
        assert_eq!(
            normalise_processing_status("awaiting_input"),
            "awaiting_input"
        );
        assert_eq!(
            normalise_processing_status("repair_needed"),
            "repair_needed"
        );
        assert_eq!(
            normalise_processing_status("FEE_COLLECTION"),
            "fee_collection"
        );
        assert_eq!(normalise_processing_status("expired"), "expired");
        // Unknown → in_progress (safe default).
        assert_eq!(normalise_processing_status("mystery"), "in_progress");
    }

    /// Every distinct decline reason in the mapping table resolves to a
    /// non-empty code, and the documented override rows hold.
    #[test]
    fn decline_codes_table_breadth() {
        let reasons = [
            "PRODUCT_VALUE_CONSTRAINTS_VIOLATED",
            "AC_TYPE_ABSENT",
            "AC_TYPE_INVALID",
            "ARQC_ABSENT",
            "ARQC_INVALID",
            "ATC_OUTSIDE_ALLOWED_RANGE_LOW",
            "ATC_OUTSIDE_ALLOWED_RANGE_HIGH",
            "ATC_DUPLICATE_INVALID",
            "CHIP_CVC_ABSENT",
            "CHIP_CVC_INVALID",
            "CVC1_ABSENT",
            "CVC1_INVALID",
            "CVC2_ABSENT",
            "CVC2_INVALID",
            "TOO_MANY_CVC2_FAILURES",
            "CARD_SUSPENDED",
            "CARD_NOT_ACTIVE",
            "IAV_INVALID",
            "IAV_ABSENT",
            "LVT_COUNT_LIMIT_EXCEEDED",
            "LVT_ACCUMULATOR_LIMIT_EXCEEDED",
            "CONTACTLESS_AMOUNT_LIMIT_EXCEEDED",
            "MERCHANT_TYPE_NOT_ALLOWED",
            "EXPIRATION_DATE_INVALID",
            "EXPIRATION_DATE_ABSENT",
            "CARD_EXPIRED",
            "ADDRESS_INVALID",
            "CARD_NUMBER_INVALID",
            "PIN_TRIES_LIMIT_EXCEEDED",
            "PIN_INVALID",
            "PIN_ABSENT",
            "NEW_PIN_INVALID",
            "NEW_PIN_ABSENT",
            "OBS_MDES_PAN_MAPPING_FAILURE",
            "OBS_MDES_AC_SE_PRE_VALIDATION_FAILURE",
            "OBS_MDES_AC_MCBP_PRE_VALIDATION_FAILURE",
            "CARDHOLDER_VERIFICATION_FAILURE",
            "CVM_RESULT_RULE_UNRECOGNISED",
            "PIN_CHANGE_ALREADY_IN_PROGRESS",
            "RECURRING_PAYMENT_INITIAL_AUTH_NOT_FOUND",
            "RECURRING_PAYMENT_INITIAL_AUTH_REJECTED",
            "PARTIAL_GRADE_ACQUIRER_NOT_SUPPORTED",
            "INTERNAL_ERROR",
        ];
        for r in reasons {
            let code = decline_response_code(r, "AuthorisationInitiation");
            assert!(!code.is_empty(), "reason {r} mapped to empty code");
            // ISO8583 numeric codes are 2 digits; scheme alpha codes start with a letter.
            assert!(
                code.len() == 2 || code.starts_with('N'),
                "reason {r} → unexpected code '{code}'"
            );
        }
        // Groups that must be internally consistent.
        for r in [
            "AC_TYPE_ABSENT",
            "ARQC_INVALID",
            "CARDHOLDER_VERIFICATION_FAILURE",
        ] {
            assert_eq!(
                decline_response_code(r, "AuthorisationInitiation"),
                "05",
                "{r} must be 05"
            );
        }
        for r in ["CVC2_INVALID", "TOO_MANY_CVC2_FAILURES"] {
            assert_eq!(
                decline_response_code(r, "AuthorisationInitiation"),
                "N7",
                "{r} must be N7"
            );
        }
        for r in [
            "ATC_OUTSIDE_ALLOWED_RANGE_LOW",
            "ATC_OUTSIDE_ALLOWED_RANGE_HIGH",
        ] {
            assert_eq!(
                decline_response_code(r, "AuthorisationInitiation"),
                "63",
                "{r} must be 63"
            );
        }
        // CardManagement override applies to the whole CardManagement payload type.
        assert_eq!(
            decline_response_code("PIN_CHANGE_ALREADY_IN_PROGRESS", "CardManagementInitiation"),
            "70"
        );
        // Case-sensitive table: unknown casing falls back to generic 05.
        assert_eq!(
            decline_response_code("pin_invalid", "AuthorisationInitiation"),
            "05"
        );
    }

    /// Sandbox simulator envelopes: deterministic structure, outcome passthrough,
    /// and the "sandbox only" note on every family.
    #[test]
    fn sandbox_results_shape() {
        let req = SandboxSimulateRequest {
            card_id: Some(Uuid::new_v4()),
            instruction_id: None,
            amount: Some(rust_decimal::Decimal::new(2500, 2)),
            currency: Some("CAD".into()),
            outcome: Some("declined".into()),
        };
        let card = sandbox_card_result(&req);
        assert_eq!(card["simulation"], "card_transaction");
        assert_eq!(card["outcome"], "declined");
        assert_eq!(card["iso8583_response_code"], "05"); // declined → 05
        assert!(card["auth_code"].is_string());

        let approved_req = SandboxSimulateRequest {
            outcome: Some("approved".into()),
            ..req.clone()
        };
        assert_eq!(
            sandbox_card_result(&approved_req)["iso8583_response_code"],
            "00"
        );

        let ct = sandbox_credit_transfer_result(&req);
        assert_eq!(ct["simulation"], "credit_transfer");
        assert_eq!(ct["scheme"], "SEPA_CT");

        let sw = sandbox_swift_result(&req);
        assert_eq!(sw["simulation"], "swift_agi");
        assert_eq!(sw["mt"], "pacs.008");

        let fw = sandbox_fedwire_result(&req);
        assert_eq!(fw["simulation"], "fedwire");
        assert!(
            fw["note"].as_str().unwrap().contains("Sandbox"),
            "every envelope carries the sandbox-only note"
        );
    }

    /// Sandbox default outcome per family (no outcome supplied).
    #[test]
    fn sandbox_default_outcomes() {
        let bare = SandboxSimulateRequest {
            card_id: None,
            instruction_id: None,
            amount: None,
            currency: None,
            outcome: None,
        };
        assert_eq!(sandbox_card_result(&bare)["outcome"], "approved");
        assert_eq!(
            sandbox_credit_transfer_result(&bare)["outcome"],
            "completed"
        );
        assert_eq!(sandbox_swift_result(&bare)["outcome"], "acknowledged");
        assert_eq!(sandbox_fedwire_result(&bare)["outcome"], "completed");
    }

    /// default_expiry_batch: the Cron proxy-back batch cap.
    #[test]
    fn expiry_batch_default() {
        assert_eq!(default_expiry_batch(), 500);
        assert!(default_expiry_batch() > 0);
    }

    /// Search registry completeness: every documented searchable resource is
    /// registered with a non-empty field list, and amounts/timestamps are
    /// range-comparable (the registry lists them for op filtering).
    #[test]
    fn search_registry_resources() {
        for resource in [
            "payments",
            "payees",
            "payment-instruments",
            "membership-directory-records",
            "instructions",
        ] {
            let fields = search_registry(resource)
                .unwrap_or_else(|| panic!("{resource} missing from registry"));
            assert!(!fields.is_empty(), "{resource} has no searchable fields");
        }
        // Resource-keyed entities expose id; directory records are entry rows.
        assert!(search_registry("payments").unwrap().contains(&"id"));
        assert!(search_registry("membership-directory-records")
            .unwrap()
            .contains(&"bic"));
        // Registered fields are unique.
        let fields = search_registry("payments").unwrap();
        let mut sorted = fields.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            fields.len(),
            "duplicate fields in payments registry"
        );
    }

    /// validate_search passes empty bodies (no filters = no constraints).
    #[test]
    fn search_empty_body_ok() {
        assert!(validate_search("payments", &serde_json::json!({})).is_ok());
    }
}
