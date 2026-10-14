// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Story — Seed default Payments schedules in Cron.
//! Payments owns a small set of well-known recurring schedules that must be
//! registered with Cron at startup so the scheduler can proxy back into
//! Payments's internal trigger endpoint (`POST /v1/internal/schedules/trigger`,
//! Story ).
//! The schedules are declared here as a static list (`DEFAULT_SCHEDULES`) and
//! materialised into Cron via [`seed_default_schedules`].
//! Story — E2E tests covering the default schedule catalog.

use sqlx::PgPool;

use sentin8_cron_sdk::client::{CreateScheduleRequest, CronClient};

/// A default Payments schedule (Story ).
/// Each entry maps a human-readable name to a cron expression, a
/// description, and the internal Payments endpoint Cron should call when the
/// schedule fires.
#[derive(Debug, Clone)]
pub struct PaymentsDefaultSchedule {
    /// Stable identifier used as the Cron `schedule_type`.
    pub name: &'static str,
    /// Cron expression. Cron uses a 6-field expression
    /// (sec min hour day-of-month month day-of-week).
    pub cron_expression: &'static str,
    /// Human-readable description of what the schedule does.
    pub description: &'static str,
    /// Internal Payments endpoint Cron proxies back into.
    pub endpoint: &'static str,
}

/// The well-known set of Payments schedules (Story ).
/// Order matters for the E2E tests (they index by position).
pub fn default_schedules() -> Vec<PaymentsDefaultSchedule> {
    vec![
        PaymentsDefaultSchedule {
            name: "tips_sweeper",
            cron_expression: "*/10 * * * * *",
            description: "Sweep pending TIPS instructions and reconcile state with the TIPS gateway.",
            endpoint: "/v1/internal/schedules/trigger",
        },
        PaymentsDefaultSchedule {
            name: "sepa_ct_daily_cutoff",
            cron_expression: "0 0 23 * * *",
            description: "SEPA Credit Transfer daily cutoff at 23:00 CET — finalises the SEPA CT batch for the day.",
            endpoint: "/v1/internal/schedules/trigger",
        },
        PaymentsDefaultSchedule {
            name: "b8_credit_transfer_daily",
            cron_expression: "0 0 18 * * *",
            description: "B8 (domestic) credit transfer daily run at 18:00 UTC — submits the domestic CT batch.",
            endpoint: "/v1/internal/schedules/trigger",
        },
        PaymentsDefaultSchedule {
            name: "authorisation_expiry_check",
            cron_expression: "0 * * * * *",
            description: "Every-minute check for expired card authorisations to release or capture.",
            endpoint: "/v1/internal/schedules/trigger",
        },
        PaymentsDefaultSchedule {
            name: "stale_instruction_cleanup",
            cron_expression: "0 0 * * * *",
            description: "Hourly cleanup of stale instructions stuck in a non-terminal state.",
            endpoint: "/v1/internal/schedules/trigger",
        },
    ]
}

/// Register the default Payments schedules with Cron (Story ).
/// This is idempotent in intent: each schedule is registered with a stable
/// `domain`/`schedule_type` pair so re-running on startup does not create
/// duplicates beyond what Cron's own deduplication provides. Failures are
/// logged but do not abort the seed (best-effort) — the returned `Result`
/// only surfaces the first error for callers that need to know.
pub async fn seed_default_schedules(
    _pool: &PgPool,
    sentin8_cron_url: &str,
    sentin8_cron_token: &str,
) -> Result<(), String> {
    let client = CronClient::new(sentin8_cron_url, sentin8_cron_token);
    let local_ip = std::env::var("SENTIN8_CAPTAIN_LOCAL_IP").unwrap_or_else(|_| "0.0.0.0".into());
    let payments_port =
        std::env::var("BANK8_PAYMENTS_PORT").expect("BANK8_PAYMENTS_PORT must be set by captain");
    let callbacks_base_url = std::env::var("BANK8_PAYMENTS_BASE_URL")
        .unwrap_or_else(|_| format!("http://{local_ip}:{payments_port}"));

    let schedules = default_schedules();
    let mut first_error: Option<String> = None;

    for sched in &schedules {
        // Cron ticker target_config contract:
        // baseUrl — the service to proxy back into (Payments)
        // internalPath — the path to POST to on each fire
        // authToken — bearer token Payments accepts on the internal endpoint
        let target_config = serde_json::json!({
            "base_url" : callbacks_base_url,
            "internal_path" : sched.endpoint,
            "auth_token" : sentin8_cron_token,
        });

        let req = CreateScheduleRequest::new(
            "payments",
            sched.name,
            sched.cron_expression,
            target_config,
        );

        match client.create_schedule(&req).await {
            Ok(resp) => {
                tracing::info!(
                    schedule = sched.name,
                    schedule_id = %resp.id,
                    "seeded default Payments schedule with Cron"
                );
            }
            Err(e) => {
                tracing::warn!(
                    schedule = sched.name,
                    error = %e,
                    "failed to seed default Payments schedule with Cron"
                );
                if first_error.is_none() {
                    first_error = Some(format!("schedule `{}`: {e}", sched.name));
                }
            }
        }
    }

    if let Some(e) = first_error {
        return Err(e);
    }
    Ok(())
}

// ── Tests (Story ) ───────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_schedules_not_empty() {
        let schedules = default_schedules();
        assert!(
            !schedules.is_empty(),
            "default schedule list must not be empty"
        );
        assert_eq!(
            schedules.len(),
            5,
            "expected exactly 5 default Payments schedules"
        );
    }

    #[test]
    fn test_tips_sweeper_schedule_interval() {
        let schedules = default_schedules();
        let tips = schedules
            .iter()
            .find(|s| s.name == "tips_sweeper")
            .expect("tips_sweeper schedule must exist");
        assert_eq!(
            tips.cron_expression, "*/10 * * * * *",
            "tips_sweeper must run every 10 seconds"
        );
        // Validate the seconds field is a 10-second interval.
        let sec_field = tips.cron_expression.split_whitespace().next().unwrap();
        assert!(
            sec_field.starts_with("*/10"),
            "tips_sweeper seconds field `{sec_field}` must be a 10-second interval"
        );
    }

    #[test]
    fn test_sepa_ct_cutoff_time() {
        let schedules = default_schedules();
        let sepa = schedules
            .iter()
            .find(|s| s.name == "sepa_ct_daily_cutoff")
            .expect("sepa_ct_daily_cutoff schedule must exist");
        // 6-field cron: sec min hour dom mon dow
        let fields: Vec<&str> = sepa.cron_expression.split_whitespace().collect();
        assert_eq!(fields.len(), 6, "expected 6-field cron expression");
        let hour = fields[2];
        let minute = fields[1];
        assert_eq!(hour, "23", "SEPA CT cutoff must be at 23:00");
        assert_eq!(minute, "0", "SEPA CT cutoff minute must be 0");
    }

    #[test]
    fn test_b8_credit_transfer_time() {
        let schedules = default_schedules();
        let b8 = schedules
            .iter()
            .find(|s| s.name == "b8_credit_transfer_daily")
            .expect("b8_credit_transfer_daily schedule must exist");
        let fields: Vec<&str> = b8.cron_expression.split_whitespace().collect();
        assert_eq!(fields.len(), 6, "expected 6-field cron expression");
        assert_eq!(fields[2], "18", "B8 credit transfer must be at 18:00 UTC");
        assert_eq!(fields[1], "0", "B8 credit transfer minute must be 0");
    }

    #[test]
    fn test_authorisation_expiry_interval() {
        let schedules = default_schedules();
        let auth = schedules
            .iter()
            .find(|s| s.name == "authorisation_expiry_check")
            .expect("authorisation_expiry_check schedule must exist");
        let fields: Vec<&str> = auth.cron_expression.split_whitespace().collect();
        assert_eq!(fields.len(), 6, "expected 6-field cron expression");
        // "0 * * * * *" — minute wildcard, second 0 → every minute
        assert_eq!(
            fields[0], "0",
            "authorisation expiry seconds field must be 0"
        );
        assert_eq!(fields[1], "*", "authorisation expiry must run every minute");
    }

    #[test]
    fn test_stale_instruction_cleanup_interval() {
        let schedules = default_schedules();
        let stale = schedules
            .iter()
            .find(|s| s.name == "stale_instruction_cleanup")
            .expect("stale_instruction_cleanup schedule must exist");
        let fields: Vec<&str> = stale.cron_expression.split_whitespace().collect();
        assert_eq!(fields.len(), 6, "expected 6-field cron expression");
        // "0 0 * * * *" — sec=0, min=0, hour=* → hourly at minute 0
        assert_eq!(fields[0], "0", "stale cleanup seconds field must be 0");
        assert_eq!(fields[1], "0", "stale cleanup minute field must be 0");
        assert_eq!(
            fields[2], "*",
            "stale cleanup must be hourly (hour wildcard)"
        );
    }

    #[test]
    fn test_all_schedules_have_endpoints() {
        let schedules = default_schedules();
        for s in &schedules {
            assert!(
                !s.endpoint.is_empty(),
                "schedule `{}` must have a non-empty endpoint",
                s.name
            );
            assert!(
                s.endpoint.starts_with('/'),
                "schedule `{}` endpoint must be an absolute path",
                s.name
            );
        }
    }

    #[test]
    fn test_all_cron_expressions_valid() {
        let schedules = default_schedules();
        for s in &schedules {
            assert!(
                !s.cron_expression.is_empty(),
                "schedule `{}` must have a non-empty cron expression",
                s.name
            );
            // Cron uses 6-field cron (sec min hour dom mon dow).
            let fields: Vec<&str> = s.cron_expression.split_whitespace().collect();
            assert_eq!(
                fields.len(),
                6,
                "schedule `{}` cron expression must have 6 fields (got `{}`)",
                s.name,
                s.cron_expression
            );
        }
    }
}
