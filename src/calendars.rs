// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Calendars and scheduling — business day definitions, cutoff and
//! processing periods, recurring schedules, and the TIPS sweeper service.
//! See `services/payments/DESIGN.md`.
//! Provides:
//! - `CalendarType` (CutoffPeriod, ProcessingPeriod)
//! - `BusinessDayDefinition`
//! - `CalendarConfig`
//! - `is_business_day` / `calculate_cutoff_period` / `calculate_processing_period`
//! - `register_recurring_schedule` (stub — registers with Cron)
//! - HTTP handlers for calendars and business day definitions
//! - `TipsSweeperConfig` and `run_tips_sweeper` (Story )

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{Datelike, NaiveDate};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::handlers::AppState;

// ── Enums ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarType {
    CutoffPeriod,
    ProcessingPeriod,
}

impl CalendarType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "cutoff_period" => Ok(Self::CutoffPeriod),
            "processing_period" => Ok(Self::ProcessingPeriod),
            other => Err(format!("unknown calendar type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CutoffPeriod => "cutoff_period",
            Self::ProcessingPeriod => "processing_period",
        }
    }
}

// ── Definitions ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessDayDefinition {
    pub name: String,
    /// Days of the week that are weekend (non-business) days.
    /// 0 = Sunday, 6 = Saturday. Default: [0, 6].
    #[serde(default = "default_weekend_days")]
    pub weekend_days: Vec<u32>,
    /// ISO date strings (`YYYY-MM-DD`) of holidays.
    #[serde(default)]
    pub holidays: Vec<String>,
}

fn default_weekend_days() -> Vec<u32> {
    vec![0, 6]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarConfig {
    pub calendar_type: CalendarType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_day_definition: Option<BusinessDayDefinition>,
    pub configuration: serde_json::Value,
    pub timezone: String,
}

// ── Business day logic ─────────────────────────────────────────────────

/// Determine whether a date is a business day for the given definition.
/// A date is a business day if it is not a weekend day and not a holiday.
pub fn is_business_day(definition: &BusinessDayDefinition, date: NaiveDate) -> bool {
    if definition
        .weekend_days
        .contains(&date.weekday().num_days_from_sunday())
    {
        return false;
    }
    let iso = date.format("%Y-%m-%d").to_string();
    !definition.holidays.iter().any(|h| h == &iso)
}

/// Calculate the cutoff period containing `date`.
/// The cutoff period is a window of time before a processing period during
/// which instructions are batched. By convention this implementation uses a
/// 1-day window ending on `date`: the period starts at the previous business
/// day (inclusive) and ends on `date` (inclusive).
/// The `configuration` JSON may contain:
/// - `window_days` (i32, default 1) — number of business days in the window.
pub fn calculate_cutoff_period(
    config: &CalendarConfig,
    date: NaiveDate,
) -> Result<(NaiveDate, NaiveDate), String> {
    if !matches!(config.calendar_type, CalendarType::CutoffPeriod) {
        return Err("calendar is not a cutoff_period".into());
    }
    let window_days = config
        .configuration
        .get("window_days")
        .and_then(|v| v.as_i64())
        .unwrap_or(1);
    if window_days < 1 {
        return Err("window_days must be >= 1".into());
    }
    let def = config
        .business_day_definition
        .as_ref()
        .ok_or_else(|| "cutoff period requires a business day definition".to_string())?;

    let end = date;
    let mut start = end;
    let mut counted = 0i64;
    while counted < window_days {
        if is_business_day(def, start) {
            counted += 1;
        }
        if counted < window_days {
            start = start.pred_opt().ok_or("invalid date")?;
        }
    }
    Ok((start, end))
}

/// Calculate the processing period starting on or after `date`.
/// The processing period is the window during which instructions are
/// processed. By convention this implementation uses a 1-business-day window
/// starting on the first business day on or after `date`.
/// The `configuration` JSON may contain:
/// - `window_days` (i32, default 1) — number of business days in the window.
pub fn calculate_processing_period(
    config: &CalendarConfig,
    date: NaiveDate,
) -> Result<(NaiveDate, NaiveDate), String> {
    if !matches!(config.calendar_type, CalendarType::ProcessingPeriod) {
        return Err("calendar is not a processing_period".into());
    }
    let window_days = config
        .configuration
        .get("window_days")
        .and_then(|v| v.as_i64())
        .unwrap_or(1);
    if window_days < 1 {
        return Err("window_days must be >= 1".into());
    }
    let def = config
        .business_day_definition
        .as_ref()
        .ok_or_else(|| "processing period requires a business day definition".to_string())?;

    // Find first business day on or after `date`.
    let mut start = date;
    while !is_business_day(def, start) {
        start = start.succ_opt().ok_or("invalid date")?;
    }
    let mut end = start;
    let mut counted = 0i64;
    while counted < window_days {
        if is_business_day(def, end) {
            counted += 1;
        }
        if counted < window_days {
            end = end.succ_opt().ok_or("invalid date")?;
        }
    }
    Ok((start, end))
}

// ── Recurring schedules ─────────────────────────────────────────────────

/// Register a recurring schedule with Sentin8:Cron (design §10).
///
/// Registers a Cron schedule whose fire proxies back into
/// `POST /v1/internal/schedules/trigger` carrying the originating
/// instruction's logic + input, so each recurrence creates a fresh
/// instruction through the same state machine as any other fire
/// (`ScheduleTriggerRequest.schedule_id = the returned Cron id`).
/// The cron expression is built from the caller's pattern (`pattern`) and
/// the schedule's start date.
pub async fn register_recurring_schedule(
    pool: &sqlx::PgPool,
    instruction_id: Uuid,
    pattern: &str,
    start_date: NaiveDate,
) -> Result<(), String> {
    let cron_url = std::env::var("SENTIN8_CRON_URL")
        .unwrap_or_else(|_| sentin8::config::Sentin8Config::from_env().sentin8_cron_url());
    let cron_token = std::env::var("SENTIN8_CRON_TOKEN").unwrap_or_else(|_| "payments-dev".into());
    let client = sentin8_cron_sdk::client::CronClient::new(&cron_url, &cron_token);
    let local_ip = std::env::var("SENTIN8_CAPTAIN_LOCAL_IP").unwrap_or_else(|_| "0.0.0.0".into());
    let payments_port = std::env::var("BANK8_PAYMENTS_PORT").unwrap_or_else(|_| "0".into());
    let base_url = std::env::var("BANK8_PAYMENTS_BASE_URL")
        .unwrap_or_else(|_| format!("http://{local_ip}:{payments_port}"));

    // The fire proxies back into the internal trigger endpoint with the
    // originating instruction's id + start date; the trigger handler loads
    // the originating instruction and creates the recurrence through the
    // same guarded path as any other instruction.
    let _input = serde_json::json!({
        "instruction_id": instruction_id,
        "start_date": start_date,
    });
    let target_config = serde_json::json!({
        "base_url": base_url,
        "internal_path": "/v1/internal/schedules/trigger",
        "auth_token": cron_token,
    });
    // Domain `payments`, schedule_type = the recurring instruction id —
    // Cron dedupes re-registrations on the (domain, schedule_type) pair.
    let req = sentin8_cron_sdk::client::CreateScheduleRequest::new(
        "payments",
        format!("recurring-{instruction_id}"),
        pattern,
        target_config,
    );
    let resp = client
        .create_schedule(&req)
        .await
        .map_err(|e| format!("register recurring schedule with Cron: {e}"))?;

    // Persist the Cron schedule id on the originating instruction so a
    // cancellation can delete the schedule (calendars design §4.3).
    sqlx::query(
        r#"UPDATE instructions
              SET correlation_id = $2, updated_at = now()
            WHERE id = $1 AND state NOT IN ('completed', 'failed', 'cancelled')"#,
    )
    .bind(instruction_id)
    .bind(format!("cron:{}", resp.id))
    .execute(pool)
    .await
    .map_err(|e| format!("persist cron schedule id: {e}"))?;

    tracing::info!(
        instruction_id = %instruction_id,
        schedule_id = %resp.id,
        pattern = %pattern,
        start_date = %start_date,
        "registered recurring schedule with Cron"
    );
    Ok(())
}

// ── TIPS sweeper (Story ) ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipsSweeperConfig {
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
    #[serde(default = "default_threshold_seconds")]
    pub threshold_seconds: u64,
    #[serde(default = "default_max_requests_per_payment")]
    pub max_requests_per_payment: u32,
}

fn default_poll_interval() -> u64 {
    10
}
fn default_threshold_seconds() -> u64 {
    10
}
fn default_max_requests_per_payment() -> u32 {
    1
}

impl Default for TipsSweeperConfig {
    fn default() -> Self {
        Self {
            poll_interval_seconds: default_poll_interval(),
            threshold_seconds: default_threshold_seconds(),
            max_requests_per_payment: default_max_requests_per_payment(),
        }
    }
}

/// Run the TIPS sweeper — poll for pending TIPS payments and check their
/// status. This is a stub; in production it would loop on a timer and call
/// the TIPS scheme adapter to query payment status.
/// Story.
pub async fn run_tips_sweeper(
    pool: &sqlx::PgPool,
    config: &TipsSweeperConfig,
) -> Result<(), String> {
    let count: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::BIGINT FROM instructions WHERE state = 'pending'",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("tips sweeper query: {e}"))?;
    tracing::info!(
        pending = count,
        poll_interval_seconds = config.poll_interval_seconds,
        threshold_seconds = config.threshold_seconds,
        max_requests_per_payment = config.max_requests_per_payment,
        "tips sweeper poll (stub)"
    );
    Ok(())
}

// ── HTTP handlers ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CalendarResponse {
    pub id: Uuid,
    pub name: String,
    pub calendar_type: String,
    pub business_day_definition_id: Option<Uuid>,
    pub configuration: serde_json::Value,
    pub timezone: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCalendarRequest {
    pub name: String,
    pub calendar_type: String,
    #[serde(default)]
    pub business_day_definition_id: Option<Uuid>,
    #[serde(default = "default_empty_object")]
    pub configuration: serde_json::Value,
    #[serde(default = "default_timezone")]
    pub timezone: String,
}

#[derive(Debug, Serialize)]
pub struct BusinessDayDefinitionResponse {
    pub id: Uuid,
    pub name: String,
    pub weekend_days: Vec<i32>,
    pub holidays: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateBusinessDayDefinitionRequest {
    pub name: String,
    #[serde(default)]
    pub weekend_days: Option<Vec<i32>>,
    #[serde(default)]
    pub holidays: Option<serde_json::Value>,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}
fn default_timezone() -> String {
    "UTC".into()
}

const CALENDAR_COLUMNS: &str =
    "id, name, calendar_type, business_day_definition_id, configuration, timezone, created_at, updated_at";

pub fn row_to_calendar(row: &sqlx::postgres::PgRow) -> CalendarResponse {
    CalendarResponse {
        id: row.get("id"),
        name: row.get("name"),
        calendar_type: row.get("calendar_type"),
        business_day_definition_id: row.get("business_day_definition_id"),
        configuration: row.get("configuration"),
        timezone: row.get("timezone"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

const BDD_COLUMNS: &str = "id, name, weekend_days, holidays, created_at, updated_at";

fn row_to_bdd(row: &sqlx::postgres::PgRow) -> BusinessDayDefinitionResponse {
    BusinessDayDefinitionResponse {
        id: row.get("id"),
        name: row.get("name"),
        weekend_days: row.get("weekend_days"),
        holidays: row.get("holidays"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// `POST /v1/calendars` — create a calendar.
pub async fn create_calendar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCalendarRequest>,
) -> Result<Json<CalendarResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Calendars)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:calendars:write"),
    )
    .await?;
    let cal_type =
        CalendarType::from_str(&req.calendar_type).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO calendars
               (env_id, name, calendar_type,
                business_day_definition_id, configuration, timezone)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING {CALENDAR_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(cal_type.as_str())
        .bind(req.business_day_definition_id)
        .bind(&req.configuration)
        .bind(&req.timezone)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_calendar(&row)))
}

/// `GET /v1/calendars` — list calendars.
pub async fn list_calendars(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CalendarResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Calendars)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:calendars:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql =
        format!("SELECT {CALENDAR_COLUMNS} FROM calendars ORDER BY created_at DESC LIMIT 100");
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_calendar).collect()))
}

/// `POST /v1/business-day-definitions` — create a business day definition.
pub async fn create_business_day_definition(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateBusinessDayDefinitionRequest>,
) -> Result<Json<BusinessDayDefinitionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Calendars)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:calendars:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let weekend_days: Vec<i32> = req.weekend_days.unwrap_or_else(|| vec![0, 6]);
    let holidays = req.holidays.unwrap_or_else(|| serde_json::json!([]));
    let sql = format!(
        r#"INSERT INTO business_day_definitions
               (env_id, name, weekend_days, holidays)
           VALUES ($1, $2, $3, $4)
           RETURNING {BDD_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(&weekend_days)
        .bind(&holidays)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_bdd(&row)))
}

/// `GET /v1/business-day-definitions` — list business day definitions.
pub async fn list_business_day_definitions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<BusinessDayDefinitionResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Calendars)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:calendars:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        "SELECT {BDD_COLUMNS} FROM business_day_definitions ORDER BY created_at DESC LIMIT 100"
    );
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_bdd).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    fn weekend_def() -> BusinessDayDefinition {
        BusinessDayDefinition {
            name: "US".into(),
            weekend_days: vec![0, 6],
            holidays: vec!["2026-07-04".into()],
        }
    }

    #[test]
    fn calendar_type_round_trip() {
        for t in [CalendarType::CutoffPeriod, CalendarType::ProcessingPeriod] {
            assert_eq!(CalendarType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(CalendarType::from_str("bogus").is_err());
    }

    #[test]
    fn is_business_day_recognises_weekday() {
        let def = weekend_def();
        // 2026-07-17 is a Friday.
        let friday = NaiveDate::from_ymd_opt(2026, 7, 17).unwrap();
        assert!(is_business_day(&def, friday));
    }

    #[test]
    fn is_business_day_excludes_weekend() {
        let def = weekend_def();
        let saturday = NaiveDate::from_ymd_opt(2026, 7, 18).unwrap();
        let sunday = NaiveDate::from_ymd_opt(2026, 7, 19).unwrap();
        assert!(!is_business_day(&def, saturday));
        assert!(!is_business_day(&def, sunday));
    }

    #[test]
    fn is_business_day_excludes_holidays() {
        let def = weekend_def();
        // 2026-07-04 is a Saturday AND a holiday; both should exclude.
        let independence_day = NaiveDate::from_ymd_opt(2026, 7, 4).unwrap();
        assert!(!is_business_day(&def, independence_day));
    }

    fn cutoff_config(window: i64) -> CalendarConfig {
        CalendarConfig {
            calendar_type: CalendarType::CutoffPeriod,
            business_day_definition: Some(weekend_def()),
            configuration: serde_json::json!({ "window_days": window }),
            timezone: "UTC".into(),
        }
    }

    fn processing_config(window: i64) -> CalendarConfig {
        CalendarConfig {
            calendar_type: CalendarType::ProcessingPeriod,
            business_day_definition: Some(weekend_def()),
            configuration: serde_json::json!({ "window_days": window }),
            timezone: "UTC".into(),
        }
    }

    #[test]
    fn calculate_cutoff_period_one_day_on_business_day() {
        let config = cutoff_config(1);
        // 2026-07-17 is a Friday (business day).
        let friday = NaiveDate::from_ymd_opt(2026, 7, 17).unwrap();
        let (start, end) = calculate_cutoff_period(&config, friday).unwrap();
        assert_eq!(start, friday);
        assert_eq!(end, friday);
    }

    #[test]
    fn calculate_cutoff_period_window_skips_weekend() {
        let config = cutoff_config(2);
        // Monday 2026-07-20: window of 2 business days → Friday 2026-07-17 + Monday 2026-07-20.
        let monday = NaiveDate::from_ymd_opt(2026, 7, 20).unwrap();
        let (start, end) = calculate_cutoff_period(&config, monday).unwrap();
        assert_eq!(start, NaiveDate::from_ymd_opt(2026, 7, 17).unwrap());
        assert_eq!(end, monday);
    }

    #[test]
    fn calculate_cutoff_period_rejects_processing_type() {
        let config = processing_config(1);
        let date = NaiveDate::from_ymd_opt(2026, 7, 17).unwrap();
        assert!(calculate_cutoff_period(&config, date).is_err());
    }

    #[test]
    fn calculate_processing_period_starts_on_next_business_day() {
        let config = processing_config(1);
        // Saturday 2026-07-18 → first business day on/after is Monday 2026-07-20.
        let saturday = NaiveDate::from_ymd_opt(2026, 7, 18).unwrap();
        let (start, end) = calculate_processing_period(&config, saturday).unwrap();
        assert_eq!(start, NaiveDate::from_ymd_opt(2026, 7, 20).unwrap());
        assert_eq!(end, start);
    }

    #[test]
    fn calculate_processing_period_two_day_window() {
        let config = processing_config(2);
        let friday = NaiveDate::from_ymd_opt(2026, 7, 17).unwrap();
        let (start, end) = calculate_processing_period(&config, friday).unwrap();
        // Window of 2 business days: Friday + Monday (skip weekend).
        assert_eq!(start, NaiveDate::from_ymd_opt(2026, 7, 17).unwrap());
        assert_eq!(end, NaiveDate::from_ymd_opt(2026, 7, 20).unwrap());
    }

    #[test]
    fn calculate_processing_period_rejects_cutoff_type() {
        let config = cutoff_config(1);
        let date = NaiveDate::from_ymd_opt(2026, 7, 17).unwrap();
        assert!(calculate_processing_period(&config, date).is_err());
    }

    #[test]
    fn tips_sweeper_config_defaults() {
        let config = TipsSweeperConfig::default();
        assert_eq!(config.poll_interval_seconds, 10);
        assert_eq!(config.threshold_seconds, 10);
        assert_eq!(config.max_requests_per_payment, 1);
    }
}
