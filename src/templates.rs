// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Templates - reusable instruction templates with versioning.
//! Story.
//! See `services/payments/DESIGN.md`.
//! A template is a reusable instruction definition with variables, a base
//! instruction, and a set of declared inputs. Templates are versioned; one
//! version is active at a time (`active_version_id`).

use utoipa::ToSchema;
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

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct TemplateResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub scheme: Option<String>,
    pub status: String,
    pub active_version_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTemplateRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TemplateVersionResponse {
    pub id: Uuid,
    pub template_id: Uuid,
    pub version: i32,
    pub variables: serde_json::Value,
    pub base_instruction: serde_json::Value,
    pub inputs: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTemplateVersionRequest {
    #[serde(default = "default_empty_array")]
    pub variables: serde_json::Value,
    #[serde(default = "default_empty_object")]
    pub base_instruction: serde_json::Value,
    #[serde(default = "default_empty_array")]
    pub inputs: serde_json::Value,
}

/// Input type for a template variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateInputType {
    Standard,
    Multi,
    Group,
    Track,
}

impl TemplateInputType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "standard" => Ok(Self::Standard),
            "multi" => Ok(Self::Multi),
            "group" => Ok(Self::Group),
            "track" => Ok(Self::Track),
            other => Err(format!("unknown template input type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Multi => "multi",
            Self::Group => "group",
            Self::Track => "track",
        }
    }
}

/// A declared input for a template version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInput {
    pub name: String,
    pub input_type: TemplateInputType,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,
}

fn default_empty_array() -> serde_json::Value {
    serde_json::json!([])
}
fn default_empty_object() -> serde_json::Value {
    serde_json::json!({})
}

// ── Row mappers ─────────────────────────────────────────────────────────

const TEMPLATE_COLUMNS: &str =
    "id, name, description, scheme, status, active_version_id, created_at, updated_at";

fn row_to_template(row: &sqlx::postgres::PgRow) -> TemplateResponse {
    TemplateResponse {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        scheme: row.get("scheme"),
        status: row.get("status"),
        active_version_id: row.get("active_version_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

const VERSION_COLUMNS: &str =
    "id, template_id, version, variables, base_instruction, inputs, status, created_at";

fn row_to_version(row: &sqlx::postgres::PgRow) -> TemplateVersionResponse {
    TemplateVersionResponse {
        id: row.get("id"),
        template_id: row.get("template_id"),
        version: row.get("version"),
        variables: row.get("variables"),
        base_instruction: row.get("base_instruction"),
        inputs: row.get("inputs"),
        status: row.get("status"),
        created_at: row.get("created_at"),
    }
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ── Handlers ────────────────────────────────────────────────────────────
#[utoipa::path(
    post,
    path = "/v1/templates",
    responses(
        (status = 200, description = "Created template", body = TemplateResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/templates` - create a template.
pub async fn create_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateTemplateRequest>,
) -> Result<Json<TemplateResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Templates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!(
        r#"INSERT INTO templates (env_id, name, description, scheme, status)
           VALUES ($1, $2, $3, $4, 'active')
           RETURNING {TEMPLATE_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(&req.name)
        .bind(req.description.as_deref())
        .bind(req.scheme.as_deref())
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_template(&row)))
}
#[utoipa::path(
    get,
    path = "/v1/templates",
    responses(
        (status = 200, description = "Template list", body = Vec<TemplateResponse>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `GET /v1/templates` - list templates.
pub async fn list_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TemplateResponse>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Templates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql =
        format!("SELECT {TEMPLATE_COLUMNS} FROM templates ORDER BY created_at DESC LIMIT 100");
    let rows = sqlx::query(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(rows.iter().map(row_to_template).collect()))
}
#[utoipa::path(
    get,
    path = "/v1/templates/{id}",
    responses(
        (status = 200, description = "OK", body = TemplateResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `GET /v1/templates/{id}` - get a template.
pub async fn get_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<TemplateResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Templates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:read"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;
    let sql = format!("SELECT {TEMPLATE_COLUMNS} FROM templates WHERE id = $1");
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_template(&row)))
}
#[utoipa::path(
    post,
    path = "/v1/templates/{id}/versions",
    responses(
        (status = 200, description = "OK", body = TemplateVersionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/templates/{id}/versions` - create a new template version.
pub async fn create_template_version(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(template_id): Path<Uuid>,
    Json(req): Json<CreateTemplateVersionRequest>,
) -> Result<Json<TemplateVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Templates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;

    let next_version: i32 = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM template_versions WHERE template_id = $1",
    )
    .bind(template_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)? as i32;

    let sql = format!(
        r#"INSERT INTO template_versions
               (env_id, template_id, version,
                variables, base_instruction, inputs, status)
           VALUES ($1, $2, $3, $4, $5, $6, 'draft')
           RETURNING {VERSION_COLUMNS}"#
    );
    let row = sqlx::query(&sql)
        .bind(a.env_id())
        .bind(template_id)
        .bind(next_version)
        .bind(&req.variables)
        .bind(&req.base_instruction)
        .bind(&req.inputs)
        .fetch_one(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(Json(row_to_version(&row)))
}
#[utoipa::path(
    post,
    path = "/v1/templates/{id}/publish",
    responses(
        (status = 200, description = "OK", body = TemplateVersionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// `POST /v1/templates/{id}/publish` - publish the latest draft version of
/// a template. Marks the latest draft version as `published` and sets it as
/// the template's `active_version_id`.
pub async fn publish_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(template_id): Path<Uuid>,
) -> Result<Json<TemplateVersionResponse>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    auth::require_feature(&state.config, crate::config::FeatureGate::Templates)?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:templates:write"),
    )
    .await?;
    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    crate::handlers::set_tenant_context(&mut conn, a.env_id()).await;

    let row = sqlx::query(
        r#"UPDATE template_versions
              SET status = 'published'
            WHERE template_id = $1
              AND status = 'draft'
              AND version = (
                  SELECT MAX(version) FROM template_versions WHERE template_id = $1
              )
           RETURNING id, template_id, version, variables, base_instruction, inputs, status, created_at"#,
    )
    .bind(template_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    let version_id: Uuid = row.get("id");
    sqlx::query(
        r#"UPDATE templates
              SET active_version_id = $2, updated_at = now()
            WHERE id = $1"#,
    )
    .bind(template_id)
    .bind(version_id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    Ok(Json(row_to_version(&row)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_input_type_round_trip() {
        for t in [
            TemplateInputType::Standard,
            TemplateInputType::Multi,
            TemplateInputType::Group,
            TemplateInputType::Track,
        ] {
            assert_eq!(TemplateInputType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(TemplateInputType::from_str("bogus").is_err());
    }

    #[test]
    fn template_input_serialises_with_default() {
        let input = TemplateInput {
            name: "amount".into(),
            input_type: TemplateInputType::Standard,
            required: false,
            default_value: Some(serde_json::json!(100)),
        };
        let v = serde_json::to_value(&input).unwrap();
        assert_eq!(v["name"], "amount");
        assert_eq!(v["input_type"], "standard");
        assert_eq!(v["required"], false);
        assert_eq!(v["default_value"], 100);
    }

    #[test]
    fn template_input_omits_default_when_none() {
        let input = TemplateInput {
            name: "amount".into(),
            input_type: TemplateInputType::Standard,
            required: true,
            default_value: None,
        };
        let v = serde_json::to_value(&input).unwrap();
        assert!(v.get("default_value").is_none());
    }
}
