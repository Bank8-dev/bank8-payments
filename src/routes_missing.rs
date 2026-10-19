// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Missing designed endpoints (design §5.2/§5.4-§5.7).
//! These handlers route logic that already existed in `cards.rs`,
//! `manual_decisions.rs`, `file_processing.rs` and `dashboards.rs` but was
//! never wired to an HTTP route:
//! - Card lifecycle operations: activate / freeze / unfreeze / replace
//! - Card tokens list
//! - 3DS records list
//! - Files submit (inbound debatch)
//! - Instruction batches list
//! - Logics detail
//! - Tasks API: list / get / claim / approve / reject
//! - Aggregations query

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::event_streaming::{self, ResourceType};
use crate::handlers::{bearer_token_of, err_db, set_tenant_context, AppState};

// ── Card lifecycle operations (§5.4) ────────────────────────────────────

fn map_card_err(e: String) -> (StatusCode, String) {
    if e.contains("not found") {
        (StatusCode::NOT_FOUND, e)
    } else {
        (StatusCode::CONFLICT, e)
    }
}
#[utoipa::path(
    post,
    path = "/v1/cards/{id}/activate",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/cards/{id}/activate` - pending_creation/inactive → active.
pub async fn activate_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
    crate::cards::activate_card(&state.pool, id)
        .await
        .map_err(map_card_err)?;
    Ok(Json(serde_json::json!({ "id": id, "status": "active" })))
}
#[utoipa::path(
    post,
    path = "/v1/cards/{id}/freeze",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/cards/{id}/freeze` - active → suspended.
pub async fn freeze_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
    crate::cards::freeze_card(&state.pool, id)
        .await
        .map_err(map_card_err)?;
    Ok(Json(serde_json::json!({ "id": id, "status": "suspended" })))
}
#[utoipa::path(
    post,
    path = "/v1/cards/{id}/unfreeze",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/cards/{id}/unfreeze` - suspended → active.
pub async fn unfreeze_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
    crate::cards::unfreeze_card(&state.pool, id)
        .await
        .map_err(map_card_err)?;
    Ok(Json(serde_json::json!({ "id": id, "status": "active" })))
}

#[derive(Debug, Deserialize)]
pub struct ReplaceCardRequest {
    /// New (encrypted-at-rest) PAN for the replacement card.
    pub new_pan: String,
}
#[utoipa::path(
    post,
    path = "/v1/cards/{id}/replace",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/cards/{id}/replace` - create a replacement card, disable the old.
pub async fn replace_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ReplaceCardRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
    let new_id = crate::cards::replace_card(&state.pool, id, &req.new_pan)
        .await
        .map_err(map_card_err)?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::Card,
        &new_id.to_string(),
        "created",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": new_id, "replaces": id })))
}

// ── Card tokens (§5.4) ──────────────────────────────────────────────────

/// `GET /v1/card-tokens` - list card tokens for a card.
#[derive(Debug, Deserialize)]
pub struct ListCardTokensQuery {
    pub card_id: Uuid,
}
#[utoipa::path(
    get,
    path = "/v1/card-tokens",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

pub async fn list_card_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListCardTokensQuery>,
) -> Result<Json<Vec<crate::cards::CardTokenResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Cards)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:cards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let tokens = crate::cards::list_card_tokens(&state.pool, q.card_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(tokens))
}

// ── 3DS records (§5.4) ──────────────────────────────────────────────────

/// `GET /v1/3ds-records` - look up 3DS records by transaction id.
#[derive(Debug, Deserialize)]
pub struct Get3dsQuery {
    pub transaction_id: String,
}

#[derive(Debug, Serialize)]
pub struct ThreeDsRecordResponse {
    pub id: Uuid,
    pub card_id: Option<Uuid>,
    pub transaction_id: String,
    pub authentication_status: String,
    pub challenge_method: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
#[utoipa::path(
    get,
    path = "/v1/3ds-records",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

pub async fn get_3ds_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<Get3dsQuery>,
) -> Result<Json<Vec<ThreeDsRecordResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Cards)?;
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
        r#"SELECT id, card_id, transaction_id, authentication_status,
                  challenge_method, created_at
             FROM threeds_records
            WHERE transaction_id = $1
            ORDER BY created_at DESC
            LIMIT 50"#,
    )
    .bind(&q.transaction_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let records = rows
        .iter()
        .map(|r| ThreeDsRecordResponse {
            id: r.get("id"),
            card_id: r.get("card_id"),
            transaction_id: r.get("transaction_id"),
            authentication_status: r.get("authentication_status"),
            challenge_method: r.get("challenge_method"),
            created_at: r.get("created_at"),
        })
        .collect();
    Ok(Json(records))
}

// ── Files submit (§5.5) ─────────────────────────────────────────────────
#[utoipa::path(
    post,
    path = "/v1/files/{id}/submit",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/files/{id}/submit` - submit an uploaded file for debatch +
/// processing (inbound flow).
pub async fn submit_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
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
    // Debatch is a per-file Flow workflow (design §10): the file
    // row moves to `processing`, the workflow's debatch step chunks the
    // Storage object and creates instruction batches, and the final step
    // marks the file `processed` - each step idempotent on
    // `file_id:chunk_index`, retried per chunk via the worker re-drive.
    let batch_ids = crate::file_processing::process_inbound_file(&state.pool, &state.config, id)
        .await
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    let _ = event_streaming::emit_event_tx(
        &mut *conn,
        a.env_id(),
        ResourceType::InstructionFile,
        &id.to_string(),
        "submitted",
        None,
        None,
        event_streaming::PublisherIdentity::from_parts(
            bearer_token_of(&headers),
            Some(a.subject().to_string()),
        ),
    )
    .await;
    Ok(Json(
        serde_json::json!({ "id": id, "status": "processed", "batches": batch_ids }),
    ))
}

// ── Instruction batches (§5.5) ──────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct InstructionBatchResponse {
    pub id: Uuid,
    pub instruction_file_id: Uuid,
    pub name: String,
    pub instruction_ids: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
#[utoipa::path(
    get,
    path = "/v1/instruction-batches",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `GET /v1/instruction-batches` - list instruction batches.
pub async fn list_instruction_batches(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InstructionBatchResponse>>, (StatusCode, String)> {
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
        r#"SELECT id, instruction_file_id, name, instruction_ids, status, created_at
             FROM instruction_batches
            ORDER BY created_at DESC LIMIT 100"#,
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    let batches = rows
        .iter()
        .map(|r| InstructionBatchResponse {
            id: r.get("id"),
            instruction_file_id: r.get("instruction_file_id"),
            name: r.get("name"),
            instruction_ids: r.get("instruction_ids"),
            status: r.get("status"),
            created_at: r.get("created_at"),
        })
        .collect();
    Ok(Json(batches))
}

// ── Logics detail (§5.2) ────────────────────────────────────────────────
#[utoipa::path(
    get,
    path = "/v1/logics/{id}",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `GET /v1/logics/{id}` - logic detail.
pub async fn get_logic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::handlers::LogicResponse>, (StatusCode, String)> {
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
    let row = sqlx::query(
        "SELECT id, name, version, steps, status, created_at FROM logics WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(Json(crate::handlers::row_to_logic(&row)))
}

// ── Tasks API (§5.7) ────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TaskResponse {
    pub id: Uuid,
    pub task_type: String,
    pub status: String,
    pub assignee_id: Option<String>,
    pub reviewer_id: Option<String>,
    pub approval_stages: serde_json::Value,
    pub current_stage: i32,
    pub deadline: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

fn row_to_task(row: &sqlx::postgres::PgRow) -> TaskResponse {
    TaskResponse {
        id: row.get("id"),
        task_type: row.get("task_type"),
        status: row.get("status"),
        assignee_id: row.get("assignee_id"),
        reviewer_id: row.get("reviewer_id"),
        approval_stages: row.get("approval_stages"),
        current_stage: row.get("current_stage"),
        deadline: row.get("deadline"),
        created_at: row.get("created_at"),
    }
}

#[allow(dead_code)]
const TASK_COLUMNS: &str =
    "id, task_type, status, assignee_id, reviewer_id, approval_stages, current_stage, deadline, created_at";

/// `GET /v1/tasks` - list tasks.
#[derive(Debug, Deserialize)]
pub struct ListTasksQuery {
    #[serde(default)]
    pub status: Option<String>,
}
#[utoipa::path(
    get,
    path = "/v1/tasks",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

pub async fn list_tasks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ListTasksQuery>,
) -> Result<Json<Vec<TaskResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Tasks)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:tasks:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {TASK_COLUMNS} FROM tasks WHERE ($1::text IS NULL OR status = $1) ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .bind(q.status.as_deref())
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_task).collect()))
}
#[utoipa::path(
    get,
    path = "/v1/tasks/{id}",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `GET /v1/tasks/{id}` - task detail.
pub async fn get_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<TaskResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Tasks)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:tasks:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {TASK_COLUMNS} FROM tasks WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_task(&row)))
}

#[derive(Debug, Deserialize)]
pub struct ClaimTaskRequest {
    pub assignee_id: String,
}
#[utoipa::path(
    post,
    path = "/v1/tasks/{id}/claim",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/tasks/{id}/claim` - claim a task.
pub async fn claim_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ClaimTaskRequest>,
) -> Result<Json<TaskResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Tasks)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:tasks:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    crate::manual_decisions::claim_task(&state.pool, id, &req.assignee_id)
        .await
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    let sql = format!("SELECT {TASK_COLUMNS} FROM tasks WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_task(&row)))
}

#[derive(Debug, Deserialize)]
pub struct ReviewTaskRequest {
    pub reviewer_id: String,
}
#[utoipa::path(
    post,
    path = "/v1/tasks/{id}/approve",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/tasks/{id}/approve` - approve a task (advances approval stages).
pub async fn approve_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ReviewTaskRequest>,
) -> Result<Json<TaskResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Tasks)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:tasks:approve"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    crate::manual_decisions::approve_task(&state.pool, id, &req.reviewer_id)
        .await
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    let sql = format!("SELECT {TASK_COLUMNS} FROM tasks WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_task(&row)))
}
#[utoipa::path(
    post,
    path = "/v1/tasks/{id}/reject",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/tasks/{id}/reject` - reject a task.
pub async fn reject_task(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<ReviewTaskRequest>,
) -> Result<Json<TaskResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Tasks)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:tasks:approve"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;
    crate::manual_decisions::reject_task(&state.pool, id, &req.reviewer_id)
        .await
        .map_err(|e| (StatusCode::CONFLICT, e))?;
    let sql = format!("SELECT {TASK_COLUMNS} FROM tasks WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_task(&row)))
}

// ── Aggregations (§5.7) ─────────────────────────────────────────────────

/// `GET /v1/aggregations` - query aggregations over instructions and payments.
#[derive(Debug, Deserialize)]
pub struct AggregationQuery {
    /// `instructions` or `payments`.
    #[serde(default = "default_resource")]
    pub resource: String,
    /// `count`, `sum` or `average`.
    #[serde(default = "default_aggregation")]
    pub aggregation: String,
    /// Field to aggregate (required for sum/average).
    #[serde(default)]
    pub field: Option<String>,
    /// Grouping field, e.g. `state` / `payment_type`.
    #[serde(default)]
    pub group_by: Option<String>,
}

fn default_resource() -> String {
    "instructions".into()
}
fn default_aggregation() -> String {
    "count".into()
}
#[utoipa::path(
    get,
    path = "/v1/aggregations",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

pub async fn query_aggregations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AggregationQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Dashboards)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:dashboards:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id()).await;

    // Whitelist identifiers - the aggregation target is interpolated into
    // SQL, so only known-safe values are accepted.
    let (table, field_col) = match q.resource.as_str() {
        "instructions" => ("instructions", "state"),
        "payments" => ("payments", "status"),
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown resource: {other}"),
            ))
        }
    };
    let func = match q.aggregation.as_str() {
        "count" => "COUNT(*)::BIGINT",
        "sum" | "average" => {
            let f = q.field.as_deref().unwrap_or("amount");
            if f != "amount" {
                return Err((StatusCode::BAD_REQUEST, "field must be 'amount'".into()));
            }
            if q.aggregation == "sum" {
                "COALESCE(SUM(amount), 0)::TEXT"
            } else {
                "COALESCE(AVG(amount), 0)::TEXT"
            }
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown aggregation: {other}"),
            ))
        }
    };

    let sql = if let Some(group_by) = &q.group_by {
        if group_by != field_col && !(q.resource == "payments" && group_by == "payment_type") {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("cannot group by {group_by}"),
            ));
        }
        format!("SELECT {group_by} AS bucket, {func} AS value FROM {table} GROUP BY {group_by} ORDER BY bucket LIMIT 100")
    } else {
        format!("SELECT {func} AS value FROM {table}")
    };
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;

    if q.group_by.is_some() {
        let buckets: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "bucket": r.get::<Option<String>, _>("bucket"),
                    "value": r.get::<String, _>("value"),
                })
            })
            .collect();
        Ok(Json(
            serde_json::json!({ "aggregation": q.aggregation, "buckets": buckets }),
        ))
    } else {
        let value: String = rows
            .first()
            .map(|r| r.get("value"))
            .unwrap_or_else(|| "0".into());
        Ok(Json(
            serde_json::json!({ "aggregation": q.aggregation, "value": value }),
        ))
    }
}
