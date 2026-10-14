// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Dashboards — versioned configuration with widgets, aggregations, and a
//! simplified search query language.
//! See `services/payments/DESIGN.md`.
//! A dashboard is a versioned collection of widgets. Each widget has a type
//! (Value, Table, PieChart, BarChart, LineChart) and a config that may
//! include aggregation settings and a search query.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::auth;
use crate::handlers::AppState;

// ── Enums ───────────────────────────────────────────────────────────────

/// Widget types supported by dashboards.
/// Story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WidgetType {
    Value,
    Table,
    PieChart,
    BarChart,
    LineChart,
}

impl WidgetType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "value" => Ok(Self::Value),
            "table" => Ok(Self::Table),
            "pie_chart" => Ok(Self::PieChart),
            "bar_chart" => Ok(Self::BarChart),
            "line_chart" => Ok(Self::LineChart),
            other => Err(format!("unknown widget type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Value => "value",
            Self::Table => "table",
            Self::PieChart => "pie_chart",
            Self::BarChart => "bar_chart",
            Self::LineChart => "line_chart",
        }
    }
}

/// Aggregation type for widget calculations.
/// Story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationType {
    Count,
    Sum,
    Average,
}

impl AggregationType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "count" => Ok(Self::Count),
            "sum" => Ok(Self::Sum),
            "average" => Ok(Self::Average),
            other => Err(format!("unknown aggregation type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Sum => "sum",
            Self::Average => "average",
        }
    }
}

/// Grouping type for aggregation buckets.
/// Story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupingType {
    Field,
    TimeInterval,
    Filter,
}

impl GroupingType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "field" => Ok(Self::Field),
            "time_interval" => Ok(Self::TimeInterval),
            "filter" => Ok(Self::Filter),
            other => Err(format!("unknown grouping type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Field => "field",
            Self::TimeInterval => "time_interval",
            Self::Filter => "filter",
        }
    }
}

/// Boolean operator for combining search conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BooleanOp {
    And,
    Or,
}

impl BooleanOp {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "AND" => Ok(Self::And),
            "OR" => Ok(Self::Or),
            other => Err(format!("unknown boolean op: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::And => "AND",
            Self::Or => "OR",
        }
    }
}

/// Search comparison operator.
/// Story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchOperator {
    Eq,
    Ne,
    Gt,
    Lt,
    Gte,
    Lte,
    Like,
    In,
    NotIn,
    IsNull,
    IsNotNull,
}

impl SearchOperator {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "=" | "==" => Ok(Self::Eq),
            "!=" | "<>" => Ok(Self::Ne),
            ">" => Ok(Self::Gt),
            "<" => Ok(Self::Lt),
            ">=" => Ok(Self::Gte),
            "<=" => Ok(Self::Lte),
            "like" | "LIKE" => Ok(Self::Like),
            "in" | "IN" => Ok(Self::In),
            "not_in" | "NOT_IN" | "NOT IN" => Ok(Self::NotIn),
            "is_null" | "IS_NULL" | "IS NULL" => Ok(Self::IsNull),
            "is_not_null" | "IS_NOT_NULL" | "IS NOT NULL" => Ok(Self::IsNotNull),
            other => Err(format!("unknown search operator: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Lt => "<",
            Self::Gte => ">=",
            Self::Lte => "<=",
            Self::Like => "LIKE",
            Self::In => "IN",
            Self::NotIn => "NOT IN",
            Self::IsNull => "IS NULL",
            Self::IsNotNull => "IS NOT NULL",
        }
    }
}

// ── Aggregation / Search ───────────────────────────────────────────────

/// Aggregation configuration for a widget.
/// Story.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    pub field_name: String,
    pub aggregation_type: AggregationType,
    pub grouping_type: GroupingType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grouping_config: Option<serde_json::Value>,
}

/// A single search condition (`field OP value`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchCondition {
    pub field: String,
    pub operator: SearchOperator,
    pub value: serde_json::Value,
}

/// A parsed search query: a list of conditions combined with a boolean op,
/// plus optional sort.
/// Story.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub conditions: Vec<SearchCondition>,
    pub boolean_op: BooleanOp,
    pub sort_by: Option<String>,
    pub sort_desc: bool,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            conditions: vec![],
            boolean_op: BooleanOp::And,
            sort_by: None,
            sort_desc: false,
        }
    }
}

/// Parse a simplified search query language.
/// Supported syntax:
/// - `field=value` — equality
/// - `field!=value` — inequality
/// - `field>value`, `field<value`, `field>=value`, `field<=value`
/// - `field LIKE value`
/// - `field IS NULL`, `field IS NOT NULL`
/// - `AND`, `OR` between conditions (default AND)
/// - `ORDER_BY field` or `ORDER_BY field DESC`
///
/// Story.
pub fn parse_search_query(query_str: &str) -> Result<SearchQuery, String> {
    let mut query = SearchQuery::default();
    let trimmed = query_str.trim();
    if trimmed.is_empty() {
        return Ok(query);
    }

    // Split off ORDER_BY clause if present.
    let (conditions_part, order_part) = match trimmed.split_once("ORDER_BY") {
        Some((c, o)) => (c, Some(o)),
        None => (trimmed, None),
    };

    if let Some(order) = order_part {
        let order = order.trim();
        if order.is_empty() {
            return Err("ORDER_BY requires a field name".into());
        }
        let (field, desc) = if let Some(stripped) = order.strip_suffix(" DESC") {
            (stripped.trim(), true)
        } else if let Some(stripped) = order.strip_suffix(" ASC") {
            (stripped.trim(), false)
        } else {
            (order, false)
        };
        if field.is_empty() {
            return Err("ORDER_BY requires a field name".into());
        }
        query.sort_by = Some(field.to_string());
        query.sort_desc = desc;
    }

    // Tokenise conditions: split on AND/OR (case-insensitive) at word boundaries.
    let tokens = tokenise_conditions(conditions_part);

    for (i, (op_token, condition_str)) in tokens.iter().enumerate() {
        if i == 0 {
            // First condition has no boolean prefix.
        } else {
            // Determine boolean op.
            let bo = BooleanOp::from_str(op_token)
                .map_err(|e| format!("invalid boolean operator: {e}"))?;
            if bo == BooleanOp::Or {
                query.boolean_op = BooleanOp::Or;
            }
        }
        let cond = parse_condition(condition_str.trim())?;
        query.conditions.push(cond);
    }

    Ok(query)
}

/// Split a condition string into tokens, respecting AND/OR separators.
fn tokenise_conditions(s: &str) -> Vec<(String, String)> {
    // We split on " AND " and " OR " (case-insensitive) keeping the operator.
    let mut out = Vec::new();
    let mut current = String::new();
    let mut current_op = String::new(); // empty for first
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut first = true;
    while i < bytes.len() {
        // Look ahead for AND / OR surrounded by spaces.
        if i + 1 < bytes.len() && bytes[i] == b' ' {
            let rest = &s[i + 1..];
            let upper = rest.to_ascii_uppercase();
            if upper.starts_with("AND ") || upper == "AND" {
                let cond = std::mem::take(&mut current);
                out.push((std::mem::take(&mut current_op), cond));
                // skip " AND "
                let skip = if upper == "AND" { 4 } else { 4 };
                i += 1 + skip;
                current_op = "AND".into();
                first = false;
                continue;
            } else if upper.starts_with("OR ") || upper == "OR" {
                let cond = std::mem::take(&mut current);
                out.push((std::mem::take(&mut current_op), cond));
                let skip = if upper == "OR" { 3 } else { 3 };
                i += 1 + skip;
                current_op = "OR".into();
                first = false;
                continue;
            }
        }
        current.push(bytes[i] as char);
        i += 1;
    }
    if !current.trim().is_empty() || first {
        out.push((current_op, current));
    }
    out
}

fn parse_condition(s: &str) -> Result<SearchCondition, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty condition".into());
    }

    // IS NULL / IS NOT NULL
    let upper = s.to_ascii_uppercase();
    if upper.ends_with(" IS NULL") {
        let field = s[..s.len() - " IS NULL".len()].trim();
        if field.is_empty() {
            return Err("IS NULL requires a field".into());
        }
        return Ok(SearchCondition {
            field: field.to_string(),
            operator: SearchOperator::IsNull,
            value: serde_json::Value::Null,
        });
    }
    if upper.ends_with(" IS NOT NULL") {
        let field = s[..s.len() - " IS NOT NULL".len()].trim();
        if field.is_empty() {
            return Err("IS NOT NULL requires a field".into());
        }
        return Ok(SearchCondition {
            field: field.to_string(),
            operator: SearchOperator::IsNotNull,
            value: serde_json::Value::Null,
        });
    }

    // LIKE
    if let Some(idx) = upper.find(" LIKE ") {
        let field = s[..idx].trim();
        let value = s[idx + " LIKE ".len()..].trim();
        if field.is_empty() || value.is_empty() {
            return Err("LIKE requires field and value".into());
        }
        return Ok(SearchCondition {
            field: field.to_string(),
            operator: SearchOperator::Like,
            value: serde_json::Value::String(value.to_string()),
        });
    }

    // Comparison operators: try two-char first (>=, <=, !=, ==), then one-char.
    for two in ["!=", ">=", "<=", "=="] {
        if let Some(idx) = s.find(two) {
            let field = s[..idx].trim();
            let value = s[idx + 2..].trim();
            if field.is_empty() || value.is_empty() {
                return Err(format!("operator {two} requires field and value"));
            }
            let op = SearchOperator::from_str(two)?;
            return Ok(SearchCondition {
                field: field.to_string(),
                operator: op,
                value: parse_value(value),
            });
        }
    }
    for one in ['>', '<', '='] {
        if let Some(idx) = s.find(one) {
            let field = s[..idx].trim();
            let value = s[idx + 1..].trim();
            if field.is_empty() || value.is_empty() {
                return Err(format!("operator {one} requires field and value"));
            }
            let op = SearchOperator::from_str(&one.to_string())?;
            return Ok(SearchCondition {
                field: field.to_string(),
                operator: op,
                value: parse_value(value),
            });
        }
    }

    Err(format!("could not parse condition: {s}"))
}

fn parse_value(s: &str) -> serde_json::Value {
    let s = s.trim();
    if s.eq_ignore_ascii_case("null") {
        return serde_json::Value::Null;
    }
    if s.eq_ignore_ascii_case("true") {
        return serde_json::Value::Bool(true);
    }
    if s.eq_ignore_ascii_case("false") {
        return serde_json::Value::Bool(false);
    }
    if let Ok(i) = s.parse::<i64>() {
        return serde_json::Value::Number(i.into());
    }
    if let Ok(f) = s.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return serde_json::Value::Number(n);
        }
    }
    // Strip surrounding quotes if present.
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        return serde_json::Value::String(s[1..s.len() - 1].to_string());
    }
    serde_json::Value::String(s.to_string())
}

// ── Widget ──────────────────────────────────────────────────────────────

/// A single widget in a dashboard version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    pub id: String,
    pub widget_type: WidgetType,
    pub title: String,
    pub config: serde_json::Value,
}

// ── Response types ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub active_version_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct DashboardVersionResponse {
    pub id: Uuid,
    pub dashboard_id: Uuid,
    pub version: i32,
    pub default_filter_values: serde_json::Value,
    pub layout: serde_json::Value,
    pub primary_widget_id: Option<String>,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Request types ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateDashboardRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDashboardVersionRequest {
    #[serde(default = "default_empty_object")]
    pub default_filter_values: serde_json::Value,
    #[serde(default = "default_empty_object")]
    pub layout: serde_json::Value,
    #[serde(default)]
    pub primary_widget_id: Option<String>,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}

// ── Row mappers ─────────────────────────────────────────────────────────

const DASHBOARD_COLUMNS: &str =
    "id, name, description, status, active_version_id, created_at, updated_at";

fn row_to_dashboard(row: &sqlx::postgres::PgRow) -> DashboardResponse {
    DashboardResponse {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        status: row.get("status"),
        active_version_id: row.get("active_version_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

const VERSION_COLUMNS: &str =
    "id, dashboard_id, version, default_filter_values, layout, primary_widget_id, status, created_at";

fn row_to_version(row: &sqlx::postgres::PgRow) -> DashboardVersionResponse {
    DashboardVersionResponse {
        id: row.get("id"),
        dashboard_id: row.get("dashboard_id"),
        version: row.get("version"),
        default_filter_values: row.get("default_filter_values"),
        layout: row.get("layout"),
        primary_widget_id: row.get("primary_widget_id"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ── Handlers ────────────────────────────────────────────────────────────

/// `POST /v1/dashboards` — create a dashboard.
pub async fn create_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateDashboardRequest>,
) -> Result<Json<DashboardResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Dashboards)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:dashboards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO dashboards (env_id, name, description, status)
           VALUES ($1, $2, $3, 'active')
           RETURNING {DASHBOARD_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(req.description.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_dashboard(&row)))
}

/// `GET /v1/dashboards` — list dashboards.
pub async fn list_dashboards(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<DashboardResponse>>, (StatusCode, String)> {
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
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql =
        format!("SELECT {DASHBOARD_COLUMNS} FROM dashboards ORDER BY created_at DESC LIMIT 100");
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_dashboard).collect()))
}

/// `GET /v1/dashboards/{id}` — get a dashboard.
pub async fn get_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<DashboardResponse>, (StatusCode, String)> {
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
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {DASHBOARD_COLUMNS} FROM dashboards WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_dashboard(&row)))
}

/// `POST /v1/dashboards/{id}/versions` — create a new dashboard version.
pub async fn create_dashboard_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(dashboard_id): Path<Uuid>,
    Json(req): Json<CreateDashboardVersionRequest>,
) -> Result<Json<DashboardVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Dashboards)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:dashboards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;

    let next_version: i32 = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM dashboard_versions WHERE dashboard_id = $1",
    )
    .bind(dashboard_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)? as i32;

    let sql = format!(
        r#"INSERT INTO dashboard_versions
               (env_id, dashboard_id, version,
                default_filter_values, layout, primary_widget_id, status)
           VALUES ($1, $2, $3, $4, $5, $6, 'draft')
           RETURNING {VERSION_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(dashboard_id)
        .bind(next_version)
        .bind(&req.default_filter_values)
        .bind(&req.layout)
        .bind(req.primary_widget_id.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_version(&row)))
}

/// `POST /v1/dashboards/{id}/publish` — publish the latest draft version.
pub async fn publish_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(dashboard_id): Path<Uuid>,
) -> Result<Json<DashboardVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Dashboards)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:dashboards:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;

    let row = sqlx::query(
        r#"UPDATE dashboard_versions
              SET status = 'published'
            WHERE dashboard_id = $1
              AND status = 'draft'
              AND version = (
                  SELECT MAX(version) FROM dashboard_versions WHERE dashboard_id = $1
              )
           RETURNING id, dashboard_id, version, default_filter_values, layout, primary_widget_id, status, created_at"#,
    )
    .bind(dashboard_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    let version_id: Uuid = row.get("id");
    sqlx::query(
        r#"UPDATE dashboards
              SET active_version_id = $2, updated_at = now()
            WHERE id = $1"#,
    )
    .bind(dashboard_id)
    .bind(version_id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    Ok(Json(row_to_version(&row)))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widget_type_round_trip() {
        for t in [
            WidgetType::Value,
            WidgetType::Table,
            WidgetType::PieChart,
            WidgetType::BarChart,
            WidgetType::LineChart,
        ] {
            assert_eq!(WidgetType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(WidgetType::from_str("bogus").is_err());
    }

    #[test]
    fn aggregation_type_round_trip() {
        for t in [
            AggregationType::Count,
            AggregationType::Sum,
            AggregationType::Average,
        ] {
            assert_eq!(AggregationType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(AggregationType::from_str("bogus").is_err());
    }

    #[test]
    fn grouping_type_round_trip() {
        for t in [
            GroupingType::Field,
            GroupingType::TimeInterval,
            GroupingType::Filter,
        ] {
            assert_eq!(GroupingType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(GroupingType::from_str("bogus").is_err());
    }

    #[test]
    fn search_operator_round_trip() {
        let cases = [
            (SearchOperator::Eq, "="),
            (SearchOperator::Ne, "!="),
            (SearchOperator::Gt, ">"),
            (SearchOperator::Lt, "<"),
            (SearchOperator::Gte, ">="),
            (SearchOperator::Lte, "<="),
            (SearchOperator::Like, "LIKE"),
            (SearchOperator::In, "IN"),
            (SearchOperator::NotIn, "NOT IN"),
            (SearchOperator::IsNull, "IS NULL"),
            (SearchOperator::IsNotNull, "IS NOT NULL"),
        ];
        for (op, _s) in cases {
            let s = op.as_str();
            assert_eq!(SearchOperator::from_str(s).unwrap(), op);
        }
        // alt spellings
        assert_eq!(SearchOperator::from_str("==").unwrap(), SearchOperator::Eq);
        assert_eq!(SearchOperator::from_str("<>").unwrap(), SearchOperator::Ne);
        assert_eq!(
            SearchOperator::from_str("IS NULL").unwrap(),
            SearchOperator::IsNull
        );
        assert!(SearchOperator::from_str("bogus").is_err());
    }

    #[test]
    fn parse_search_query_empty() {
        let q = parse_search_query("").unwrap();
        assert!(q.conditions.is_empty());
        assert_eq!(q.boolean_op, BooleanOp::And);
        assert!(q.sort_by.is_none());
    }

    #[test]
    fn parse_search_query_single_eq() {
        let q = parse_search_query("status=pending").unwrap();
        assert_eq!(q.conditions.len(), 1);
        assert_eq!(q.conditions[0].field, "status");
        assert_eq!(q.conditions[0].operator, SearchOperator::Eq);
        assert_eq!(q.conditions[0].value, "pending");
    }

    #[test]
    fn parse_search_query_ne() {
        let q = parse_search_query("state!=pending").unwrap();
        assert_eq!(q.conditions[0].operator, SearchOperator::Ne);
        assert_eq!(q.conditions[0].value, "pending");
    }

    #[test]
    fn parse_search_query_and() {
        let q = parse_search_query("status=pending AND amount>100").unwrap();
        assert_eq!(q.conditions.len(), 2);
        assert_eq!(q.boolean_op, BooleanOp::And);
        assert_eq!(q.conditions[0].field, "status");
        assert_eq!(q.conditions[1].field, "amount");
        assert_eq!(q.conditions[1].operator, SearchOperator::Gt);
        assert_eq!(q.conditions[1].value, 100);
    }

    #[test]
    fn parse_search_query_or() {
        let q = parse_search_query("status=pending OR status=completed").unwrap();
        assert_eq!(q.conditions.len(), 2);
        assert_eq!(q.boolean_op, BooleanOp::Or);
    }

    #[test]
    fn parse_search_query_order_by() {
        let q = parse_search_query("status=pending ORDER_BY created_at DESC").unwrap();
        assert_eq!(q.conditions.len(), 1);
        assert_eq!(q.sort_by.as_deref(), Some("created_at"));
        assert!(q.sort_desc);
    }

    #[test]
    fn parse_search_query_order_by_asc() {
        let q = parse_search_query("status=pending ORDER_BY name ASC").unwrap();
        assert_eq!(q.sort_by.as_deref(), Some("name"));
        assert!(!q.sort_desc);
    }

    #[test]
    fn parse_search_query_is_null() {
        let q = parse_search_query("correlation_id IS NULL").unwrap();
        assert_eq!(q.conditions[0].field, "correlation_id");
        assert_eq!(q.conditions[0].operator, SearchOperator::IsNull);
    }

    #[test]
    fn parse_search_query_is_not_null() {
        let q = parse_search_query("correlation_id IS NOT NULL").unwrap();
        assert_eq!(q.conditions[0].operator, SearchOperator::IsNotNull);
    }

    #[test]
    fn parse_search_query_like() {
        let q = parse_search_query("name LIKE payments%").unwrap();
        assert_eq!(q.conditions[0].operator, SearchOperator::Like);
        assert_eq!(q.conditions[0].value, "payments%");
    }

    #[test]
    fn parse_search_query_gte_lte() {
        let q = parse_search_query("amount>=10 AND amount<=100").unwrap();
        assert_eq!(q.conditions[0].operator, SearchOperator::Gte);
        assert_eq!(q.conditions[0].value, 10);
        assert_eq!(q.conditions[1].operator, SearchOperator::Lte);
        assert_eq!(q.conditions[1].value, 100);
    }

    #[test]
    fn parse_search_query_boolean_op_or_str() {
        assert_eq!(BooleanOp::from_str("or").unwrap(), BooleanOp::Or);
        assert_eq!(BooleanOp::from_str("AND").unwrap(), BooleanOp::And);
        assert!(BooleanOp::from_str("xor").is_err());
    }

    #[test]
    fn widget_serialisation() {
        let w = Widget {
            id: "w1".into(),
            widget_type: WidgetType::PieChart,
            title: "Counts".into(),
            config: serde_json::json!({ "field": "state" }),
        };
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["widget_type"], "pie_chart");
        assert_eq!(v["title"], "Counts");
    }
}
