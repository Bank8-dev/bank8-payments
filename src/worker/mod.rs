// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Worker consume loop, process_instruction, ack/nack.
//! Story - async instruction processing. - the worker
//! re-drives the Flow workflow instead of unconditionally completing.
//! Consumes `bank8:payments:instruction:*` events from the Bus stream family
//! `payments`, looks up the corresponding instruction row, and re-drives
//! execution via Flow (for async instructions) or applies the recorded
//! step results. The worker is intentionally idempotent: an event may be
//! redelivered, so all DB mutations are guarded by the instruction state.

use std::sync::Arc;

use futures_util::StreamExt;
use sentin8::bus::client::BusClient;
use sqlx::Row;
use tokio::time::Duration;
use uuid::Uuid;
/// Reconnect delay when the Bus WS connection drops.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// The embedded worker's loop knobs (design §2). Read from the
/// `BANK8_PAYMENTS_WORKER_*` env names the standalone worker used, so a
/// deployment's env block survives the merge unchanged.
#[derive(Debug, Clone)]
pub struct WorkerLoopConfig {
    /// Bus consumer group name.
    pub consumer_group: String,
    /// Max nacks before the message lands in the Bus DLQ.
    pub max_retries: u32,
    /// Bus stream family to consume (the payments family).
    pub stream_family: String,
}

impl WorkerLoopConfig {
    pub fn from_env() -> Self {
        Self {
            consumer_group: std::env::var("BANK8_PAYMENTS_WORKER_CONSUMER_GROUP")
                .unwrap_or_else(|_| "payments-worker".into()),
            max_retries: std::env::var("BANK8_PAYMENTS_WORKER_MAX_RETRIES")
                .unwrap_or("3".into())
                .parse()
                .unwrap_or(3),
            stream_family: std::env::var("BANK8_PAYMENTS_STREAM_FAMILY")
                .unwrap_or_else(|_| "payments".into()),
        }
    }
}

/// Build a cert-presenting HTTP transport for `workload` (CERTFREE-4V,
/// auth DESIGN §4.3f): mint-or-load the Acme-issued pair and wrap it in
/// a reqwest client. The receiving service's TLS layer authenticates the
/// handshake and the enroll-published registry map authorizes the
/// scopes - no bearer token exists on this path.
///
/// # Errors
/// Returns the certificate-ensure or transport-build failure (the
/// caller logs and degrades).
async fn build_workload_http(auth_issuer: &str, workload: &str) -> anyhow::Result<reqwest::Client> {
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        auth_issuer,
        workload,
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("workload '{workload}' transport: {e}"))
}

/// Spawn the embedded re-drive worker (design §2 - the merged-in
/// payments-worker loop). Called once from `server::build_state`; the SSE
/// consume task runs until process shutdown and shares the service's
/// capped pool - the standalone binary's second pool is gone.
pub async fn spawn(pool: sqlx::PgPool, config: &crate::config::PaymentsConfig) {
    // Cert-presenting Bus client (CERTFREE-4V): the `payments-worker`
    // workload CERTIFICATE is the identity - no DCR, no token (auth DESIGN
    // §4.3f); the mint retries while the fleet boots.
    let bus = loop {
        match sentin8::bus::client::BusClient::for_workload(
            &config.sentin8_bus_url,
            &config.sentin8_auth_issuer,
            "payments-worker",
        )
        .await
        {
            Ok(c) => break c,
            Err(e) => {
                tracing::debug!(error = %e, "payments-worker bus client: certificate not ready yet");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    };
    // Cert-presenting Flow client for the re-drive (CERTFREE-4V): the
    // `payments-worker-flow` workload certificate re-drives workflows via
    // `resume`/`retry` - the TLS handshake IS the identity; the registry
    // map authorizes the flow scopes (registration.rs::M2M_GRANTS). A
    // mint failure falls back to the documented dev-plain client (Flow
    // rejects it loudly at the authorization gate - fail-closed, no
    // token fallback exists).
    let flow = match build_workload_http(&config.sentin8_auth_issuer, "payments-worker-flow").await
    {
        Ok(http) => sentin8_flow_sdk::client::FlowClient::from_transport(
            config.sentin8_flow_url.clone(),
            sentin8::middleware::http_client::Sentin8HttpClient::from_client(http),
        ),
        Err(e) => {
            tracing::warn!(error = %e, "payments-worker: Flow transport unavailable - Flow re-drive degraded (no fallback identity exists)");
            sentin8_flow_sdk::client::FlowClient::new_dev_plain(config.sentin8_flow_url.clone())
        }
    };
    let state = Arc::new(WorkerState {
        loop_config: WorkerLoopConfig::from_env(),
        pool,
        bus,
        flow,
    });

    // SSE consumer task - single Server-Sent Events connection to Bus
    // (no HTTP polling). One connection per stream family is enough;
    // Bus pushes messages as they arrive. Runs until process shutdown
    // (the shell owns graceful drain - no per-task lifecycle here).
    tokio::spawn(async move {
        sse_consume_loop(state).await;
    });
}

struct WorkerState {
    loop_config: WorkerLoopConfig,
    pool: sqlx::PgPool,
    bus: BusClient,
    /// Cert-presenting Flow client (payments-worker-flow workload)
    /// for re-driving instruction workflows.
    flow: sentin8_flow_sdk::client::FlowClient,
}

/// SSE consumer loop - connect to Bus via Server-Sent Events, receive
/// pushed messages, process each instruction, and ACK via the HTTP ack
/// endpoint. No HTTP polling. Reconnects on disconnect with a 2s backoff.
async fn sse_consume_loop(state: Arc<WorkerState>) {
    let consumer_group = state.loop_config.consumer_group.clone();
    let max_retries = state.loop_config.max_retries;
    let stream_family = state.loop_config.stream_family.clone();

    tracing::info!(
        stream_family = %stream_family,
        consumer_group = %consumer_group,
        "payments-worker: bus SSE consumer starting"
    );

    loop {
        let resp = match state.bus.sse_consume(&stream_family, &consumer_group).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "payments-worker: sse_consume failed; retrying in 2s");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        tracing::info!(stream_family = %stream_family, "payments-worker: bus SSE connected");

        let mut buffer = String::new();
        let mut stream = resp.bytes_stream();

        let mut stream_error = false;
        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "payments-worker: bus SSE stream error");
                    stream_error = true;
                    break;
                }
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete events (separated by \n\n)
            while let Some(pos) = buffer.find("\n\n") {
                let event_text = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                let mut data_line = String::new();
                for line in event_text.lines() {
                    if let Some(d) = parse_sse_data_line(line) {
                        data_line = d.to_string();
                    }
                    // `id:` lines and `:` comments (heartbeats) are skipped
                    // ACKs use message_id from the JSON data.
                }

                if data_line.is_empty() {
                    continue;
                }

                let msg: serde_json::Value = match serde_json::from_str(&data_line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let message_id = msg["message_id"].as_str().unwrap_or("").to_string();
                let payload = &msg["payload"];
                // The envelope carries the producer's tenant env - the RLS
                // context for this event's instruction writes (design §5).
                let env_id = msg["env_id"].as_str().unwrap_or("").to_string();

                match process_instruction(&state, &env_id, payload).await {
                    Ok(()) => {
                        let _ = state
                            .bus
                            .ack(&stream_family, &consumer_group, &message_id)
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            message_id = %message_id,
                            "process failed"
                        );
                        // Nack via HTTP so Bus tracks retries / DLQ.
                        let _ = nack_with_retry(&state, &message_id, max_retries).await;
                        // ACK to move on (DLQ handles poison messages).
                        let _ = state
                            .bus
                            .ack(&stream_family, &consumer_group, &message_id)
                            .await;
                    }
                }
            }
        }

        if !stream_error {
            tracing::info!(
                stream_family = %stream_family,
                "payments-worker: bus SSE stream ended; reconnecting in 2s"
            );
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Process one instruction event (- real re-drive semantics).
/// The event payload carries `instruction_id`. The worker:
/// 1. Skips terminal instructions (idempotent redelivery).
/// 2. Marks the instruction `processing` (guarded against terminal states).
/// 3. Looks up the Flow workflow for the `payments` domain and re-drives it:
/// - `waiting` → `resume_workflow` (async callback / manual decision path)
/// - `failed` → `retry_workflow` (engine re-runs from current_step)
/// 4. A pending/running Flow workflow is already executing in the engine
///
/// (spawned at workflow creation) - nothing to do.
/// 5. An instruction with **no** Flow workflow cannot progress by itself;
///
/// it is marked `failed` with a reason instead of being silently
/// completed (a fictional completion is the most dangerous state in a
/// payments system).
async fn process_instruction(
    state: &WorkerState,
    env_id: &str,
    payload: &serde_json::Value,
) -> Result<(), String> {
    let instruction_id = instruction_id_from_payload(payload)
        .ok_or_else(|| "missing instruction_id in event payload".to_string())?;

    // Tenant context is per-event, transaction-local: the Bus message
    // carries the producer's env, and the FORCE-RLS policies on
    // instructions require an initialized context equal to the
    // row's env - set it on the same transaction as the domain reads and
    // guarded updates (RLS rule: context + query share one connection).
    // A zero-row load after this fails loudly below - never silently
    // skipped (a context-less read would return zero rows once per-service
    // DSNs activate, and a silent skip would look like idempotent
    // redelivery while actually losing the re-drive).
    let env_uuid = Uuid::parse_str(env_id)
        .map_err(|_| format!("invalid env_id in event envelope: {env_id}"))?;
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| format!("begin tenant tx: {e}"))?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_uuid)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("set tenant context: {e}"))?;

    // Load the instruction row (same tx/connection as the context).
    let row = sqlx::query(
        r#"SELECT id, state, input, step_results, current_step
             FROM instructions WHERE id = $1"#,
    )
    .bind(instruction_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("load instruction: {e}"))?;
    let Some(row) = row else {
        return Err(format!("instruction {instruction_id} not found"));
    };

    let current_state: String = row.try_get("state").unwrap_or_else(|_| "pending".into());
    // Idempotency: skip terminal instructions.
    if is_terminal_instruction_state(&current_state) {
        tracing::debug!(instruction_id = %instruction_id, state = %current_state, "skipping terminal instruction");
        tx.commit().await.map_err(|e| format!("commit skip: {e}"))?;
        return Ok(());
    }

    // Mark as processing (guarded - never flips a terminal state).
    sqlx::query(
        r#"UPDATE instructions SET state = 'processing', updated_at = now()
            WHERE id = $1 AND state NOT IN ('completed', 'failed', 'cancelled')"#,
    )
    .bind(instruction_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("mark processing: {e}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("commit processing: {e}"))?;

    // Find the Flow workflow for the payments domain by its correlation
    // (instruction id - set at workflow creation). The correlation filter
    // rides Flow's `idx_flow_workflows_correlation` partial index; the
    // unfiltered list is `ORDER BY created_at DESC LIMIT 100`, which loses
    // targets once a tenant accumulates more workflows than one page.
    let correlation = instruction_id.to_string();
    let workflows = state
        .flow
        .list_workflows(Some("payments"), None, Some(&correlation))
        .await
        .map_err(|e| format!("list flow workflows: {e}"))?;

    let workflow = workflows
        .iter()
        .find(|w| w.correlation_id.as_deref() == Some(correlation.as_str()));

    match workflow.map(|w| (w.id, w.state)) {
        Some((workflow_id, sentin8_flow_sdk::contracts::WorkflowState::Waiting)) => {
            tracing::info!(instruction_id = %instruction_id, workflow_id = %workflow_id, "resuming waiting workflow");
            state
                .flow
                .resume_workflow(&workflow_id.to_string(), None)
                .await
                .map_err(|e| format!("resume workflow: {e}"))?;
        }
        Some((workflow_id, sentin8_flow_sdk::contracts::WorkflowState::Failed)) => {
            tracing::info!(instruction_id = %instruction_id, workflow_id = %workflow_id, "retrying failed workflow");
            state
                .flow
                .retry_workflow(&workflow_id.to_string())
                .await
                .map_err(|e| format!("retry workflow: {e}"))?;
        }
        // Pending / running workflows are already being executed by the
        // engine; completed/cancelled workflows leave the instruction's
        // terminal state to the proxy-back step callbacks.
        Some((_, _)) => {
            tracing::debug!(instruction_id = %instruction_id, "flow workflow already in flight");
        }
        None => {
            // No Flow workflow exists (e.g. an instruction created without
            // inline logic). It cannot execute without one - fail it
            // explicitly instead of marking it completed.
            let reason =
                "no flow workflow found for instruction; worker cannot re-drive without a workflow";
            tracing::warn!(instruction_id = %instruction_id, "failing instruction: {reason}");
            let mut tx = state
                .pool
                .begin()
                .await
                .map_err(|e| format!("begin fail tx: {e}"))?;
            sqlx::query("SELECT sentin8_set_tenant_context($1)")
                .bind(env_uuid)
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("set tenant context: {e}"))?;
            sqlx::query(
                r#"UPDATE instructions
                      SET state = 'failed', error_message = $2, updated_at = now()
                    WHERE id = $1 AND state NOT IN ('completed', 'failed', 'cancelled')"#,
            )
            .bind(instruction_id)
            .bind(reason)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("fail instruction: {e}"))?;
            tx.commit().await.map_err(|e| format!("commit fail: {e}"))?;
        }
    }

    Ok(())
}
/// Nack with retry - after max retries, the Bus DLQ handles poison messages.
async fn nack_with_retry(
    state: &WorkerState,
    message_id: &str,
    max_retries: u32,
) -> Result<(), String> {
    for _ in 0..max_retries {
        let res = state
            .bus
            .nack(
                &state.loop_config.stream_family,
                &state.loop_config.consumer_group,
                message_id,
                Some(1),
            )
            .await;
        if res.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(format!(
        "nack failed after {max_retries} retries for {message_id}"
    ))
}

// ── Pure seams (unit-tested; design §8.5.1) ────────────────────────────

/// Extract the `data:` payload from one SSE line. Returns `None` for
/// comments (heartbeats), `id:` lines, and non-data lines.
fn parse_sse_data_line(line: &str) -> Option<&str> {
    line.strip_prefix("data: ")
}

/// Extract and parse `instruction_id` from an event payload.
fn instruction_id_from_payload(payload: &serde_json::Value) -> Option<Uuid> {
    payload
        .get("instruction_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Terminal instruction states - events for these are acked without side
/// effects (idempotent redelivery). The worker's UPDATE guard uses the same
/// set so the SQL and this predicate cannot drift.
fn is_terminal_instruction_state(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "cancelled")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_terminal_instruction_state ────────────────────────────────────

    #[test]
    fn terminal_states_recognized() {
        assert!(is_terminal_instruction_state("completed"));
        assert!(is_terminal_instruction_state("failed"));
        assert!(is_terminal_instruction_state("cancelled"));
    }

    #[test]
    fn non_terminal_states_not_recognized() {
        assert!(!is_terminal_instruction_state("pending"));
        assert!(!is_terminal_instruction_state("processing"));
        assert!(!is_terminal_instruction_state(""));
        assert!(!is_terminal_instruction_state("COMPLETED")); // case-sensitive
        assert!(!is_terminal_instruction_state("complete"));
    }

    // ── instruction_id_from_payload ──────────────────────────────────────

    #[test]
    fn instruction_id_parsed_from_payload() {
        let id = uuid::Uuid::new_v4();
        let payload = serde_json::json!({"instruction_id": id.to_string()});
        assert_eq!(instruction_id_from_payload(&payload), Some(id));
    }

    #[test]
    fn instruction_id_missing_returns_none() {
        let payload = serde_json::json!({"other": "field"});
        assert_eq!(instruction_id_from_payload(&payload), None);
    }

    #[test]
    fn instruction_id_invalid_uuid_returns_none() {
        let payload = serde_json::json!({"instruction_id": "not-a-uuid"});
        assert_eq!(instruction_id_from_payload(&payload), None);
    }

    #[test]
    fn instruction_id_wrong_json_type_returns_none() {
        // Numeric id (not a string) must not panic - returns None.
        let payload = serde_json::json!({"instruction_id": 42});
        assert_eq!(instruction_id_from_payload(&payload), None);
    }

    // ── parse_sse_data_line ──────────────────────────────────────────────

    #[test]
    fn sse_data_line_extracted() {
        assert_eq!(
            parse_sse_data_line("data: {\"message_id\":\"m1\"}"),
            Some("{\"message_id\":\"m1\"}")
        );
    }

    #[test]
    fn sse_heartbeat_comment_ignored() {
        // SSE heartbeats are `:` comment lines.
        assert_eq!(parse_sse_data_line(": keep-alive"), None);
    }

    #[test]
    fn sse_id_line_ignored() {
        assert_eq!(parse_sse_data_line("id: 42"), None);
    }

    #[test]
    fn sse_data_without_space_not_matched() {
        // The protocol form is `data: <payload>` (with one space) - the
        // no-space variant is deliberately not matched (same behavior as the
        // pre-refactor strip_prefix).
        assert_eq!(parse_sse_data_line("data:{\"x\":1}"), None);
    }

    #[test]
    fn sse_empty_line_ignored() {
        assert_eq!(parse_sse_data_line(""), None);
    }
}
