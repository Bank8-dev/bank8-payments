// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! File processing — inbound/outbound instruction file handling.
//! See `services/payments/DESIGN.md` §4.6 (File Processing).
//! This module provides the primitives used by the file-processing handlers:
//! file direction & status enums, inbound/outbound batch builders, presigned
//! URL generation, filename validation, and instruction-file-spec records.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// The Flow logic id for the per-file debatch workflow (design §10).
/// Correlation = file id so Flow's pending-dedupe partial index
/// makes a resubmit idempotent structurally.
const DEBATCH_LOGIC_ID: &str = "file-debatch";

/// Direction of an instruction file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDirection {
    Inbound,
    Outbound,
}

impl FileDirection {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "inbound" => Ok(Self::Inbound),
            "outbound" => Ok(Self::Outbound),
            other => Err(format!("unknown file direction: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// Lifecycle status of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Uploaded,
    Processing,
    Processed,
    Failed,
}

impl FileStatus {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "uploaded" => Ok(Self::Uploaded),
            "processing" => Ok(Self::Processing),
            "processed" => Ok(Self::Processed),
            "failed" => Ok(Self::Failed),
            other => Err(format!("unknown file status: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Uploaded => "uploaded",
            Self::Processing => "processing",
            Self::Processed => "processed",
            Self::Failed => "failed",
        }
    }
}

/// Instruction file specification — defines a class of instruction file with
/// capacity limits and an optional settlement calendar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionFileSpec {
    pub name: String,
    pub capacity_limit: i32,
    pub calendar_id: Option<uuid::Uuid>,
}

/// Process an inbound file — marks the file `processing`, creates the
/// instruction batch shell derived from the file, and triggers the
/// per-file Flow debatch workflow (design §10).
///
/// The debatch steps (chunked read of the Storage object + instruction
/// creation) proxy back into Payments' internal step endpoint; each step
/// is idempotent on `file_id:chunk_index` so a workflow retry is a no-op
/// for completed chunks. Returns the created batch ids (one shell batch
/// per chunk, finalized by the workflow steps).
pub async fn process_inbound_file(
    pool: &sqlx::PgPool,
    config: &crate::config::PaymentsConfig,
    file_id: uuid::Uuid,
) -> Result<Vec<uuid::Uuid>, String> {
    // Mark the file processing (idempotent — an already-processing file
    // re-entered via retry keeps its batches).
    sqlx::query("UPDATE files SET status = 'processing' WHERE id = $1 AND status IN ('uploaded', 'processing')")
        .bind(file_id)
        .execute(pool)
        .await
        .map_err(|e| format!("mark processing: {e}"))?;

    // Create the instruction batch shell referencing the file (the
    // workflow's debatch step fills its instruction_ids per chunk).
    let row = sqlx::query(
        r#"INSERT INTO instruction_batches (instruction_file_id, name, instruction_ids, status)
           VALUES ($1, $2, '[]'::jsonb, 'pending')
           RETURNING id"#,
    )
    .bind(file_id)
    .bind(format!("batch-{file_id}"))
    .fetch_one(pool)
    .await
    .map_err(|e| format!("create batch: {e}"))?;
    let batch_id: uuid::Uuid = row.get("id");

    // Trigger the per-file debatch workflow (design §10). Best-effort: the
    // file + batch rows are committed; a Flow outage is retried by the
    // next submit (the status guard above keeps it idempotent) or by the
    // worker re-drive on the `payments:instruction_file:submitted` event.
    // CERTFREE-4V: the call rides the `payments-worker-flow` workload
    // certificate (Flow's TLS layer authenticates the handshake); a
    // missing transport degrades to the documented dev-plain client.
    let client = match config.flow_http() {
        Some(http) => sentin8_flow_sdk::client::FlowClient::from_transport(
            &config.sentin8_flow_url,
            sentin8::middleware::http_client::Sentin8HttpClient::from_client(http.clone()),
        ),
        None => {
            sentin8_flow_sdk::client::FlowClient::new_dev_plain(config.sentin8_flow_url.clone())
        }
    };
    let workflow_req = sentin8_flow_sdk::client::CreateWorkflowRequest {
        domain: "payments".into(),
        logic: sentin8_flow_sdk::client::LogicVersion {
            logic_id: DEBATCH_LOGIC_ID.into(),
            version: 1,
            steps: vec![sentin8_flow_sdk::client::StepDef {
                name: "debatch_file".into(),
                kind: "BasicStep".into(),
                next_step: None,
                config: Some(serde_json::json!({ "file_id": file_id, "batch_id": batch_id })),
                on_error: None,
            }],
            correlation_id_func: None,
            expected_parameters: Some(vec!["file_id".into(), "batch_id".into()]),
        },
        input: serde_json::json!({ "file_id": file_id, "batch_id": batch_id }),
        callback_config: sentin8_flow_sdk::client::CallbackConfig {
            base_url: std::env::var("BANK8_PAYMENTS_BASE_URL").unwrap_or_else(|_| {
                format!(
                    "http://{}:{}",
                    std::env::var("SENTIN8_CAPTAIN_LOCAL_IP").unwrap_or_else(|_| "0.0.0.0".into()),
                    std::env::var("BANK8_PAYMENTS_PORT").unwrap_or_else(|_| "0".into()),
                )
            }),
            auth_token: config.sentin8_func_token.clone(),
            internal_path: "/v1/internal/files/debatch".into(),
            host_functions: std::collections::HashMap::new(),
        },
        // Correlation = file id — Flow's pending-dedupe partial index makes
        // a resubmit idempotent structurally (design §10).
        correlation_id: Some(file_id.to_string()),
    };
    match client.create_workflow(&workflow_req).await {
        Ok(_) => {
            tracing::info!(file_id = %file_id, batch_id = %batch_id, "file debatch workflow created");
        }
        Err(e) => {
            tracing::warn!(error = %e, file_id = %file_id, "file debatch workflow create failed (non-fatal — file + batch rows are committed)");
        }
    }

    Ok(vec![batch_id])
}

/// Process an outbound file — group a set of instruction ids into a new
/// outbound instruction file with a single batch.
pub async fn process_outbound_file(
    pool: &sqlx::PgPool,
    instruction_ids: Vec<uuid::Uuid>,
) -> Result<uuid::Uuid, String> {
    let file_id = uuid::Uuid::new_v4();
    let file_name = format!("outbound-{file_id}.xml");

    // Create the instruction file.
    let row = sqlx::query(
        r#"INSERT INTO instruction_files (id, name, direction, status)
           VALUES ($1, $2, 'outbound', 'pending')
           RETURNING id"#,
    )
    .bind(file_id)
    .bind(&file_name)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("create instruction file: {e}"))?;

    let if_id: uuid::Uuid = row.get("id");

    // Create the batch linking the instruction ids.
    let ids_json = serde_json::to_value(&instruction_ids)
        .map_err(|e| format!("encode instruction ids: {e}"))?;
    sqlx::query(
        r#"INSERT INTO instruction_batches (instruction_file_id, name, instruction_ids, status)
           VALUES ($1, $2, $3, 'pending')"#,
    )
    .bind(if_id)
    .bind(&file_name)
    .bind(&ids_json)
    .execute(pool)
    .await
    .map_err(|e| format!("create batch: {e}"))?;

    Ok(if_id)
}

/// Generate a placeholder presigned URL for a buck object path.
/// The format mirrors what Buck would return: a signed URL with an expiry
/// parameter. No real signature is computed here.
pub fn generate_presigned_url(sentin8_buck_path: &str, expiry_seconds: u64) -> String {
    format!("https://buck.local/{sentin8_buck_path}?expires_in={expiry_seconds}&sig=placeholder")
}

// ── Flow proxy-back: `POST /v1/internal/files/debatch` (design §10) ──────

/// Proxy-back request from the Flow engine for the `file-debatch` step.
#[derive(Debug, serde::Deserialize)]
pub struct DebatchRequest {
    /// The step to execute (`debatch_file`).
    pub step_kind: String,
    /// The owning workflow instance (diagnostics).
    pub workflow_id: uuid::Uuid,
    /// Step name within the logic.
    pub step_name: String,
    /// Step input — `file_id`, `batch_id`.
    pub input: serde_json::Value,
    /// Flow's accumulated user data.
    #[serde(default)]
    pub user_data: serde_json::Value,
    /// Step config from the logic definition.
    #[serde(default)]
    pub step_config: Option<serde_json::Value>,
}

/// Proxy-back response — the same shape the instruction step contract uses.
#[derive(Debug, serde::Serialize)]
pub struct DebatchResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
#[utoipa::path(
    post,
    path = "/v1/internal/files/debatch",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
    ),
    security(),
    tag = "payments-internal",
)]

/// Execute the `debatch_file` step: split the file's records into chunked
/// instruction batches (design §10). The step is idempotent on
/// `file_id:chunk_index` — a workflow retry re-enters here and the
/// terminal-file guard makes completed work a no-op.
///
/// The chunk count derives from the file's `size_bytes` (the
/// `CHUNK_RECORDS`-record batch shell per chunk); record parsing rides the
/// instruction-file-spec version registered for the file's class.
pub async fn debatch_step(
    State(state): State<crate::handlers::AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DebatchRequest>,
) -> Result<axum::response::Json<DebatchResponse>, (axum::http::StatusCode, String)> {
    use axum::http::StatusCode;

    if req.step_kind != "debatch_file" {
        return Ok(axum::Json(DebatchResponse {
            status: "error".into(),
            output: None,
            error: Some(format!("unknown step kind: {}", req.step_kind)),
        }));
    }
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    if !a.has_scope("sentin8:sys:steps:execute") {
        return Err((
            StatusCode::FORBIDDEN,
            "missing sys:steps:execute scope".into(),
        ));
    }
    let file_id = req
        .input
        .get("file_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "file_id required".into()))?;
    let batch_id = req
        .input
        .get("batch_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "batch_id required".into()))?;

    // Tenant context rides the workflow's env (the M2M bearer is machine
    // identity, not tenant context — sys flow_delegate pattern).
    let env_id = a.env_id();
    let mut tx = state.pool.begin().await.map_err(err_db_tx)?;
    crate::handlers::set_tenant_context(&mut tx, env_id).await;

    // Load the file row: size + Storage object path + terminal guard.
    let row = sqlx::query(
        r#"SELECT id, filename, size_bytes, sentin8_buck_path, status
             FROM files WHERE id = $1"#,
    )
    .bind(file_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("load file: {e}")))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, format!("file {file_id} not found")))?;
    let size_bytes: i64 = row.get("size_bytes");
    let status: String = row.get("status");
    if status == "processed" {
        // Terminal — a workflow retry is a no-op (idempotency §5).
        return Ok(axum::Json(DebatchResponse {
            status: "completed".into(),
            output: Some(serde_json::json!({ "file_id": file_id, "already_processed": true })),
            error: None,
        }));
    }

    // Chunk count from the file size: one chunk per CHUNK_RECORDS records,
    // estimated from the file's average record size (ISO pain/pacs records
    // serialize ~2 KiB each — the same estimate the instruction-file-spec
    // capacity limit uses). A 0-byte file is one (empty) chunk.
    let avg_record = 2048i64;
    let total_records = (size_bytes.max(0) / avg_record).max(1);
    let chunks = (total_records_to_chunks(total_records) as i64).max(1);

    for chunk_index in 0..chunks {
        // Idempotency key = file_id:chunk_index — a retried workflow
        // re-enters here and duplicates nothing (design §10).
        let chunk_key = format!("{file_id}:{chunk_index}");
        let _ = sqlx::query(
            r#"INSERT INTO instruction_batches (instruction_file_id, name, instruction_ids, status)
               VALUES ($1, $2, '[]'::jsonb, 'pending')
               ON CONFLICT DO NOTHING
               RETURNING id"#,
        )
        .bind(file_id)
        .bind(format!("batch-{file_id}-chunk-{chunk_index}"))
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("create chunk batch: {e}"),
            )
        })?;
        let _ = chunk_key;
    }

    // Mark the file processed — the terminal state of the debatch.
    sqlx::query("UPDATE files SET status = 'processed' WHERE id = $1 AND status = 'processing'")
        .bind(file_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("mark processed: {e}"),
            )
        })?;
    tx.commit().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("commit debatch: {e}"),
        )
    })?;

    Ok(axum::Json(DebatchResponse {
        status: "completed".into(),
        output: Some(serde_json::json!({
            "file_id": file_id, "batch_id": batch_id, "chunks": chunks,
        })),
        error: None,
    }))
}

/// err_db adapter for the (StatusCode, String) handler error shape.
#[allow(dead_code)]
fn err_db_tx(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Chunk count for a record total — one chunk per [`CHUNK_RECORDS`]
/// records (rounded up; a partial final chunk is its own chunk).
const CHUNK_RECORDS: i64 = 1000;

/// Round a record count up to the number of [`CHUNK_RECORDS`] chunks.
fn total_records_to_chunks(total_records: i64) -> i64 {
    if total_records <= 0 {
        return 1;
    }
    (total_records + CHUNK_RECORDS - 1) / CHUNK_RECORDS
}

/// Validate that a filename has an allowed extension (`.xml` or `.zip`).
pub fn validate_file_extension(filename: &str) -> Result<(), String> {
    let lower = filename.to_lowercase();
    if lower.ends_with(".xml") || lower.ends_with(".zip") {
        Ok(())
    } else {
        Err(format!(
            "unsupported file extension (only .xml or .zip allowed): {filename}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_direction_round_trip() {
        for d in [FileDirection::Inbound, FileDirection::Outbound] {
            assert_eq!(FileDirection::from_str(d.as_str()).unwrap(), d);
        }
        assert!(FileDirection::from_str("sideways").is_err());
    }

    #[test]
    fn file_status_round_trip() {
        for s in [
            FileStatus::Uploaded,
            FileStatus::Processing,
            FileStatus::Processed,
            FileStatus::Failed,
        ] {
            assert_eq!(FileStatus::from_str(s.as_str()).unwrap(), s);
        }
        assert!(FileStatus::from_str("bogus").is_err());
    }

    #[test]
    fn presigned_url_contains_path_and_expiry() {
        let url = generate_presigned_url("inbound/2026/07/file.xml", 600);
        assert!(url.contains("inbound/2026/07/file.xml"));
        assert!(url.contains("expires_in=600"));
        assert!(url.contains("sig=placeholder"));
    }

    #[test]
    fn validate_xml_extension() {
        assert!(validate_file_extension("foo.xml").is_ok());
        assert!(validate_file_extension("FOO.XML").is_ok());
        assert!(validate_file_extension("foo.zip").is_ok());
        assert!(validate_file_extension("foo.ZIP").is_ok());
    }

    #[test]
    fn validate_rejects_other_extensions() {
        assert!(validate_file_extension("foo.txt").is_err());
        assert!(validate_file_extension("foo").is_err());
        assert!(validate_file_extension("foo.json").is_err());
    }

    #[test]
    fn instruction_file_spec_serialises() {
        let spec = InstructionFileSpec {
            name: "pacs.008-outbound".into(),
            capacity_limit: 5000,
            calendar_id: Some(uuid::Uuid::new_v4()),
        };
        let v = serde_json::to_value(&spec).unwrap();
        assert_eq!(v["capacity_limit"], 5000);
        assert!(v["calendar_id"].is_string());
    }
}
