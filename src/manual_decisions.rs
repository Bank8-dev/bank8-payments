// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Manual decisions — queue, validation, reason codes, and task system.
//! See `services/payments/DESIGN.md` §4.5 (Manual Decisions).
//! Provides:
//! - `ManualDecisionStatus` lifecycle enum
//! - `DecisionInputType` and `DecisionInput` for declaring decision inputs
//! - `DecisionConstraint` with `validate_decision_input`
//! - ISO 20022 reason codes (`ReasonCode`, `Iso20022ReasonCodes`)
//! - Task system (`TaskType`, `TaskStatus`, `Task`, transitions)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;

// ── Manual decision status ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualDecisionStatus {
    Queued,
    Submitting,
    Submitted,
    DeadlineExceeded,
    Errored,
}

impl ManualDecisionStatus {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "queued" => Ok(Self::Queued),
            "submitting" => Ok(Self::Submitting),
            "submitted" => Ok(Self::Submitted),
            "deadline_exceeded" => Ok(Self::DeadlineExceeded),
            "errored" => Ok(Self::Errored),
            other => Err(format!("unknown manual decision status: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Submitting => "submitting",
            Self::Submitted => "submitted",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Errored => "errored",
        }
    }
}

// ── Decision input types & validation ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionInputType {
    String,
    StringList,
    Decimal,
    Boolean,
    DateTime,
    ReasonCode,
}

impl DecisionInputType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "string" => Ok(Self::String),
            "string_list" => Ok(Self::StringList),
            "decimal" => Ok(Self::Decimal),
            "boolean" => Ok(Self::Boolean),
            "date_time" => Ok(Self::DateTime),
            "reason_code" => Ok(Self::ReasonCode),
            other => Err(format!("unknown decision input type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::StringList => "string_list",
            Self::Decimal => "decimal",
            Self::Boolean => "boolean",
            Self::DateTime => "date_time",
            Self::ReasonCode => "reason_code",
        }
    }
}

/// One declared input for a manual decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionInput {
    pub name: String,
    pub input_type: DecisionInputType,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,
}

/// Constraints that may apply to a decision input value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecisionConstraint {
    StringConstraint {
        min_len: usize,
        max_len: usize,
    },
    StringListConstraint {
        options: Vec<String>,
    },
    DecimalConstraint {
        min: rust_decimal::Decimal,
        max: rust_decimal::Decimal,
    },
    DateTimeConstraint {
        after: Option<DateTime<Utc>>,
        before: Option<DateTime<Utc>>,
    },
    ReasonCodeConstraint {
        allowed_codes: Vec<String>,
    },
    EnumerationConstraint {
        values: Vec<String>,
    },
}

impl DecisionConstraint {
    /// Validate a JSON value against this constraint. Returns `Ok ` when
    /// the value satisfies the constraint, or `Err(message)` otherwise.
    pub fn validate(&self, value: &serde_json::Value) -> Result<(), String> {
        match self {
            Self::StringConstraint { min_len, max_len } => {
                let s = value
                    .as_str()
                    .ok_or_else(|| "expected string".to_string())?;
                let len = s.chars().count();
                if len < *min_len {
                    return Err(format!("string length {len} < min {min_len}"));
                }
                if len > *max_len {
                    return Err(format!("string length {len} > max {max_len}"));
                }
                Ok(())
            }
            Self::StringListConstraint { options } => {
                let s = value
                    .as_str()
                    .ok_or_else(|| "expected string".to_string())?;
                if !options.iter().any(|o| o == s) {
                    return Err(format!("value '{s}' not in allowed options"));
                }
                Ok(())
            }
            Self::DecimalConstraint { min, max } => {
                let d = json_to_decimal(value)
                    .ok_or_else(|| "expected decimal".to_string())?;
                if d < *min {
                    return Err(format!("decimal {d} < min {min}"));
                }
                if d > *max {
                    return Err(format!("decimal {d} > max {max}"));
                }
                Ok(())
            }
            Self::DateTimeConstraint { after, before } => {
                let s = value
                    .as_str()
                    .ok_or_else(|| "expected ISO 8601 date string".to_string())?;
                let dt = DateTime::parse_from_rfc3339(s)
                    .map_err(|e| format!("invalid date: {e}"))?
                    .with_timezone(&Utc);
                if let Some(a) = after {
                    if dt < *a {
                        return Err(format!("date {dt} before lower bound {a}"));
                    }
                }
                if let Some(b) = before {
                    if dt > *b {
                        return Err(format!("date {dt} after upper bound {b}"));
                    }
                }
                Ok(())
            }
            Self::ReasonCodeConstraint { allowed_codes } => {
                let s = value
                    .as_str()
                    .ok_or_else(|| "expected reason code string".to_string())?;
                if !allowed_codes.iter().any(|c| c == s) {
                    return Err(format!("reason code '{s}' not allowed"));
                }
                Ok(())
            }
            Self::EnumerationConstraint { values } => {
                let s = value
                    .as_str()
                    .ok_or_else(|| "expected string".to_string())?;
                if !values.iter().any(|v| v == s) {
                    return Err(format!("value '{s}' not in enumeration"));
                }
                Ok(())
            }
        }
    }
}

/// Validate a decision input against a provided JSON value, applying the
/// declared input type and any optional constraint.
pub fn validate_decision_input(
    input: &DecisionInput,
    value: &serde_json::Value,
) -> Result<(), String> {
    if value.is_null() {
        if input.required {
            return Err(format!("input '{}' is required", input.name));
        }
        return Ok(());
    }

    match input.input_type {
        DecisionInputType::String => {
            if !value.is_string() {
                return Err(format!("input '{}' must be a string", input.name));
            }
        }
        DecisionInputType::StringList => {
            let arr = value
                .as_array()
                .ok_or_else(|| format!("input '{}' must be an array", input.name))?;
            for v in arr {
                if !v.is_string() {
                    return Err(format!(
                        "input '{}' must contain only strings",
                        input.name
                    ));
                }
            }
        }
        DecisionInputType::Decimal => {
            if json_to_decimal(value).is_none() {
                return Err(format!("input '{}' must be a decimal", input.name));
            }
        }
        DecisionInputType::Boolean => {
            if !value.is_boolean() {
                return Err(format!("input '{}' must be a boolean", input.name));
            }
        }
        DecisionInputType::DateTime => {
            if let Some(s) = value.as_str() {
                if DateTime::parse_from_rfc3339(s).is_err() {
                    return Err(format!(
                        "input '{}' must be an ISO 8601 date",
                        input.name
                    ));
                }
            } else {
                return Err(format!(
                    "input '{}' must be an ISO 8601 date string",
                    input.name
                ));
            }
        }
        DecisionInputType::ReasonCode => {
            if !value.is_string() {
                return Err(format!("input '{}' must be a reason code string", input.name));
            }
        }
    }

    Ok(())
}

fn json_to_decimal(value: &serde_json::Value) -> Option<rust_decimal::Decimal> {
    if let Some(s) = value.as_str() {
        return s.parse().ok();
    }
    if let Some(n) = value.as_i64() {
        return rust_decimal::Decimal::try_from(n).ok();
    }
    if let Some(n) = value.as_u64() {
        return rust_decimal::Decimal::try_from(n).ok();
    }
    if let Some(f) = value.as_f64() {
        return rust_decimal::Decimal::try_from(f).ok();
    }
    None
}

// ── ISO 20022 reason codes ───────────────────────────────────────────────

/// A single ISO 20022 reason code definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonCode {
    pub scheme: String,
    pub code_set: String,
    pub code: String,
    pub description: String,
}

/// Common ISO 20022 reason codes used by Payments (returned with `pain.002`,
/// `pacs.004`, `camt.056`, etc.).
/// Constructed at runtime (String conversions are not const-evaluable).
pub fn iso20022_reason_codes() -> Vec<ReasonCode> {
    vec![
        ReasonCode {
            scheme: "ISO20022".into(),
            code_set: "pain.002".into(),
            code: "AC01".into(),
            description: "Account identification incorrect".into(),
        },
        ReasonCode {
            scheme: "ISO20022".into(),
            code_set: "pain.002".into(),
            code: "AC04".into(),
            description: "Account closed".into(),
        },
        ReasonCode {
            scheme: "ISO20022".into(),
            code_set: "pain.002".into(),
            code: "AM04".into(),
            description: "Insufficient funds".into(),
        },
        ReasonCode {
            scheme: "ISO20022".into(),
            code_set: "pain.002".into(),
            code: "AG01".into(),
            description: "Transaction type not accepted".into(),
        },
        ReasonCode {
            scheme: "ISO20022".into(),
            code_set: "pain.002".into(),
            code: "FF01".into(),
            description: "File format not correct".into(),
        },
    ]
}

// ── Tasks (.115) ────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    ManualDecisionSubmission,
}

impl TaskType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "manual_decision_submission" => Ok(Self::ManualDecisionSubmission),
            other => Err(format!("unknown task type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ManualDecisionSubmission => "manual_decision_submission",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    InProgress,
    AwaitingApproval,
    Executing,
    Completed,
    Rejected,
    Errored,
    DeadlineExceeded,
    Abandoned,
}

impl TaskStatus {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "queued" => Ok(Self::Queued),
            "in_progress" => Ok(Self::InProgress),
            "awaiting_approval" => Ok(Self::AwaitingApproval),
            "executing" => Ok(Self::Executing),
            "completed" => Ok(Self::Completed),
            "rejected" => Ok(Self::Rejected),
            "errored" => Ok(Self::Errored),
            "deadline_exceeded" => Ok(Self::DeadlineExceeded),
            "abandoned" => Ok(Self::Abandoned),
            other => Err(format!("unknown task status: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::InProgress => "in_progress",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Executing => "executing",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Errored => "errored",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Role of an assignee in the task lifecycle (their relationship to a
/// particular approval stage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAssigneeRole {
    Approved,
    Rejected,
    Claimed,
    Unclaimed,
}

impl TaskAssigneeRole {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "claimed" => Ok(Self::Claimed),
            "unclaimed" => Ok(Self::Unclaimed),
            other => Err(format!("unknown task assignee role: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Claimed => "claimed",
            Self::Unclaimed => "unclaimed",
        }
    }
}

/// A manual decision task row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: uuid::Uuid,
    pub task_type: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_id: Option<String>,
    pub approval_stages: serde_json::Value,
    pub current_stage: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<DateTime<Utc>>,
}

/// Create a new task.
pub async fn create_task(
    pool: &sqlx::PgPool,
    task_type: TaskType,
    deadline: Option<DateTime<Utc>>,
) -> Result<uuid::Uuid, String> {
    let row = sqlx::query(
        r#"INSERT INTO tasks (task_type, status, approval_stages, current_stage, deadline)
           VALUES ($1, 'queued', '[]'::jsonb, 0, $2)
           RETURNING id"#,
    )
    .bind(task_type.as_str())
    .bind(deadline)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("create task: {e}"))?;
    let id: uuid::Uuid = row.get("id");
    Ok(id)
}

/// Claim a task — set the assignee and move to `in_progress`.
pub async fn claim_task(
    pool: &sqlx::PgPool,
    task_id: uuid::Uuid,
    assignee_id: &str,
) -> Result<(), String> {
    sqlx::query(
        r#"UPDATE tasks
              SET assignee_id = $1,
                  status = 'in_progress',
                  updated_at = now()
            WHERE id = $2"#,
    )
    .bind(assignee_id)
    .bind(task_id)
    .execute(pool)
    .await
    .map_err(|e| format!("claim task: {e}"))?;
    Ok(())
}

/// Approve a task — advance the current stage; when the final stage is
/// reached, mark the task `completed`.
pub async fn approve_task(
    pool: &sqlx::PgPool,
    task_id: uuid::Uuid,
    reviewer_id: &str,
) -> Result<(), String> {
    // Load the current task.
    let row = sqlx::query(
        r#"SELECT current_stage, approval_stages
             FROM tasks WHERE id = $1"#,
    )
    .bind(task_id)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("load task: {e}"))?;
    let current_stage: i32 = row.get("current_stage");
    let stages: serde_json::Value = row.get("approval_stages");

    let total_stages = stages
        .as_array()
        .map(|a| a.len() as i32)
        .unwrap_or(0);

    let next_stage = current_stage + 1;
    if total_stages > 0 && next_stage >= total_stages {
        // Final stage approved → complete.
        sqlx::query(
            r#"UPDATE tasks
                  SET reviewer_id = $1,
                      current_stage = $2,
                      status = 'completed',
                      updated_at = now()
                WHERE id = $3"#,
        )
        .bind(reviewer_id)
        .bind(next_stage)
        .bind(task_id)
        .execute(pool)
        .await
        .map_err(|e| format!("approve task: {e}"))?;
    } else {
        // More stages remain → await approval.
        sqlx::query(
            r#"UPDATE tasks
                  SET reviewer_id = $1,
                      current_stage = $2,
                      status = 'awaiting_approval',
                      updated_at = now()
                WHERE id = $3"#,
        )
        .bind(reviewer_id)
        .bind(next_stage)
        .bind(task_id)
        .execute(pool)
        .await
        .map_err(|e| format!("advance task: {e}"))?;
    }
    Ok(())
}

// ── Story — Task approval stages ──────────────────────────────

/// A single approval stage in a multi-stage approval workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStage {
    pub name: String,
    pub required_roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub criteria: Option<String>,
}

/// Configuration for a multi-stage approval workflow.
/// `current_stage` is a 0-based index into `stages`. A value of
/// `stages.len as i32` indicates the workflow has completed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStagesConfig {
    pub stages: Vec<ApprovalStage>,
    pub current_stage: i32,
}

/// Validate an approval stages configuration.
/// - At least one stage must be defined.
/// - Each stage must have a non-empty name.
pub fn validate_approval_stages(config: &ApprovalStagesConfig) -> Result<(), String> {
    if config.stages.is_empty() {
        return Err("approval stages config must define at least one stage".into());
    }
    for (i, stage) in config.stages.iter().enumerate() {
        if stage.name.trim().is_empty() {
            return Err(format!("approval stage {i} must have a non-empty name"));
        }
    }
    if config.current_stage < 0 || config.current_stage > config.stages.len() as i32 {
        return Err(format!(
            "current_stage {} is out of range for {} stages",
            config.current_stage,
            config.stages.len()
        ));
    }
    Ok(())
}

/// Advance the approval workflow to the next stage.
/// Returns `Ok(true)` when the workflow has completed (no further stages),
/// and `Ok(false)` when there are remaining stages. Returns an error if the
/// workflow is already complete or the configuration is invalid.
pub fn advance_approval_stage(config: &mut ApprovalStagesConfig) -> Result<bool, String> {
    validate_approval_stages(config)?;
    let total = config.stages.len() as i32;
    if config.current_stage >= total {
        return Err("approval workflow is already complete".into());
    }
    config.current_stage += 1;
    Ok(config.current_stage >= total)
}

/// Reject a task — set status to `rejected` and record the reviewer.
pub async fn reject_task(
    pool: &sqlx::PgPool,
    task_id: uuid::Uuid,
    reviewer_id: &str,
) -> Result<(), String> {
    sqlx::query(
        r#"UPDATE tasks
              SET reviewer_id = $1,
                  status = 'rejected',
                  updated_at = now()
            WHERE id = $2"#,
    )
    .bind(reviewer_id)
    .bind(task_id)
    .execute(pool)
    .await
    .map_err(|e| format!("reject task: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;
    use serde_json::json;

    #[test]
    fn manual_decision_status_round_trip() {
        for s in [
            ManualDecisionStatus::Queued,
            ManualDecisionStatus::Submitting,
            ManualDecisionStatus::Submitted,
            ManualDecisionStatus::DeadlineExceeded,
            ManualDecisionStatus::Errored,
        ] {
            assert_eq!(ManualDecisionStatus::from_str(s.as_str()).unwrap(), s);
        }
        assert!(ManualDecisionStatus::from_str("bogus").is_err());
    }

    #[test]
    fn decision_input_type_round_trip() {
        for t in [
            DecisionInputType::String,
            DecisionInputType::StringList,
            DecisionInputType::Decimal,
            DecisionInputType::Boolean,
            DecisionInputType::DateTime,
            DecisionInputType::ReasonCode,
        ] {
            assert_eq!(DecisionInputType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(DecisionInputType::from_str("nope").is_err());
    }

    #[test]
    fn validate_required_string_input() {
        let input = DecisionInput {
            name: "reason".into(),
            input_type: DecisionInputType::String,
            required: true,
            default_value: None,
        };
        assert!(validate_decision_input(&input, &json!(null)).is_err());
        assert!(validate_decision_input(&input, &json!("AC01")).is_ok());
        assert!(validate_decision_input(&input, &json!(42)).is_err());
    }

    #[test]
    fn validate_optional_input_accepts_null() {
        let input = DecisionInput {
            name: "reason".into(),
            input_type: DecisionInputType::String,
            required: false,
            default_value: None,
        };
        assert!(validate_decision_input(&input, &json!(null)).is_ok());
    }

    #[test]
    fn validate_decimal_input() {
        let input = DecisionInput {
            name: "amount".into(),
            input_type: DecisionInputType::Decimal,
            required: true,
            default_value: None,
        };
        assert!(validate_decision_input(&input, &json!("100.50")).is_ok());
        assert!(validate_decision_input(&input, &json!(100)).is_ok());
        assert!(validate_decision_input(&input, &json!(100.5)).is_ok());
        assert!(validate_decision_input(&input, &json!("not a number")).is_err());
        assert!(validate_decision_input(&input, &json!(null)).is_err());
    }

    #[test]
    fn validate_boolean_input() {
        let input = DecisionInput {
            name: "accept".into(),
            input_type: DecisionInputType::Boolean,
            required: true,
            default_value: None,
        };
        assert!(validate_decision_input(&input, &json!(true)).is_ok());
        assert!(validate_decision_input(&input, &json!("true")).is_err());
    }

    #[test]
    fn validate_string_list_input() {
        let input = DecisionInput {
            name: "codes".into(),
            input_type: DecisionInputType::StringList,
            required: true,
            default_value: None,
        };
        assert!(validate_decision_input(&input, &json!(["AC01", "AC04"])).is_ok());
        assert!(validate_decision_input(&input, &json!(["AC01", 42])).is_err());
        assert!(validate_decision_input(&input, &json!("AC01")).is_err());
    }

    #[test]
    fn validate_datetime_input() {
        let input = DecisionInput {
            name: "when".into(),
            input_type: DecisionInputType::DateTime,
            required: true,
            default_value: None,
        };
        assert!(validate_decision_input(&input, &json!("2026-07-18T12:00:00Z")).is_ok());
        assert!(validate_decision_input(&input, &json!("not-a-date")).is_err());
        assert!(validate_decision_input(&input, &json!(42)).is_err());
    }

    #[test]
    fn string_constraint_validates_length() {
        let c = DecisionConstraint::StringConstraint { min_len: 2, max_len: 4 };
        assert!(c.validate(&json!("ab")).is_ok());
        assert!(c.validate(&json!("abcd")).is_ok());
        assert!(c.validate(&json!("a")).is_err());
        assert!(c.validate(&json!("abcde")).is_err());
        assert!(c.validate(&json!(42)).is_err());
    }

    #[test]
    fn string_list_constraint_validates_options() {
        let c = DecisionConstraint::StringListConstraint {
            options: vec!["yes".into(), "no".into()],
        };
        assert!(c.validate(&json!("yes")).is_ok());
        assert!(c.validate(&json!("maybe")).is_err());
    }

    #[test]
    fn decimal_constraint_validates_range() {
        let c = DecisionConstraint::DecimalConstraint {
            min: Decimal::from(10),
            max: Decimal::from(100),
        };
        assert!(c.validate(&json!("50")).is_ok());
        assert!(c.validate(&json!("5")).is_err());
        assert!(c.validate(&json!("150")).is_err());
        assert!(c.validate(&json!("not-a-number")).is_err());
    }

    #[test]
    fn reason_code_constraint_validates_allowed() {
        let c = DecisionConstraint::ReasonCodeConstraint {
            allowed_codes: vec!["AC01".into(), "AC04".into()],
        };
        assert!(c.validate(&json!("AC01")).is_ok());
        assert!(c.validate(&json!("ZZ99")).is_err());
    }

    #[test]
    fn enumeration_constraint_validates_values() {
        let c = DecisionConstraint::EnumerationConstraint {
            values: vec!["a".into(), "b".into()],
        };
        assert!(c.validate(&json!("a")).is_ok());
        assert!(c.validate(&json!("z")).is_err());
    }

    #[test]
    fn datetime_constraint_validates_window() {
        let after = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let before = DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        let c = DecisionConstraint::DateTimeConstraint {
            after: Some(after),
            before: Some(before),
        };
        assert!(c.validate(&json!("2026-07-18T12:00:00Z")).is_ok());
        assert!(c.validate(&json!("2025-01-01T00:00:00Z")).is_err());
        assert!(c.validate(&json!("2027-01-01T00:00:00Z")).is_err());
    }

    #[test]
    fn iso20022_reason_codes_contain_known_codes() {
        let reason_codes = iso20022_reason_codes();
        let codes: Vec<&str> = reason_codes.iter().map(|r| r.code.as_str()).collect();
        for expected in ["AC01", "AC04", "AM04", "AG01", "FF01"] {
            assert!(codes.contains(&expected), "missing reason code {expected}");
        }
    }

    #[test]
    fn task_type_round_trip() {
        let t = TaskType::ManualDecisionSubmission;
        assert_eq!(TaskType::from_str(t.as_str()).unwrap(), t);
        assert!(TaskType::from_str("bogus").is_err());
    }

    #[test]
    fn task_status_round_trip() {
        for s in [
            TaskStatus::Queued,
            TaskStatus::InProgress,
            TaskStatus::AwaitingApproval,
            TaskStatus::Executing,
            TaskStatus::Completed,
            TaskStatus::Rejected,
            TaskStatus::Errored,
            TaskStatus::DeadlineExceeded,
            TaskStatus::Abandoned,
        ] {
            assert_eq!(TaskStatus::from_str(s.as_str()).unwrap(), s);
        }
        assert!(TaskStatus::from_str("bogus").is_err());
    }

    #[test]
    fn task_assignee_role_round_trip() {
        for r in [
            TaskAssigneeRole::Approved,
            TaskAssigneeRole::Rejected,
            TaskAssigneeRole::Claimed,
            TaskAssigneeRole::Unclaimed,
        ] {
            assert_eq!(TaskAssigneeRole::from_str(r.as_str()).unwrap(), r);
        }
        assert!(TaskAssigneeRole::from_str("bogus").is_err());
    }

    #[test]
    fn task_struct_serialises() {
        let task = Task {
            id: uuid::Uuid::new_v4(),
            task_type: "manual_decision_submission".into(),
            status: "queued".into(),
            assignee_id: None,
            reviewer_id: None,
            approval_stages: json!([]),
            current_stage: 0,
            deadline: None,
        };
        let v = serde_json::to_value(&task).unwrap();
        assert_eq!(v["current_stage"], 0);
        assert_eq!(v["task_type"], "manual_decision_submission");
    }

    // ── Story — approval stages tests ──────────────────────────

    #[test]
    fn approval_stages_validate_requires_at_least_one_stage() {
        let config = ApprovalStagesConfig { stages: vec![], current_stage: 0 };
        assert!(validate_approval_stages(&config).is_err());
    }

    #[test]
    fn approval_stages_validate_rejects_empty_names() {
        let config = ApprovalStagesConfig {
            stages: vec![ApprovalStage {
                name: "   ".into(),
                required_roles: vec!["approver".into()],
                criteria: None,
            }],
            current_stage: 0,
        };
        assert!(validate_approval_stages(&config).is_err());
    }

    #[test]
    fn approval_stages_validate_rejects_out_of_range_current_stage() {
        let config = ApprovalStagesConfig {
            stages: vec![ApprovalStage {
                name: "review".into(),
                required_roles: vec![],
                criteria: None,
            }],
            current_stage: 5,
        };
        assert!(validate_approval_stages(&config).is_err());
    }

    #[test]
    fn approval_stages_validate_accepts_valid_config() {
        let config = ApprovalStagesConfig {
            stages: vec![
                ApprovalStage {
                    name: "review".into(),
                    required_roles: vec!["reviewer".into()],
                    criteria: Some("amount > 1000".into()),
                },
                ApprovalStage {
                    name: "approve".into(),
                    required_roles: vec!["approver".into()],
                    criteria: None,
                },
            ],
            current_stage: 0,
        };
        assert!(validate_approval_stages(&config).is_ok());
    }

    #[test]
    fn approval_stages_advance_returns_false_when_more_stages() {
        let mut config = ApprovalStagesConfig {
            stages: vec![
                ApprovalStage { name: "review".into(), required_roles: vec![], criteria: None },
                ApprovalStage { name: "approve".into(), required_roles: vec![], criteria: None },
            ],
            current_stage: 0,
        };
        let completed = advance_approval_stage(&mut config).unwrap();
        assert!(!completed);
        assert_eq!(config.current_stage, 1);
    }

    #[test]
    fn approval_stages_advance_returns_true_on_completion() {
        let mut config = ApprovalStagesConfig {
            stages: vec![
                ApprovalStage { name: "review".into(), required_roles: vec![], criteria: None },
                ApprovalStage { name: "approve".into(), required_roles: vec![], criteria: None },
            ],
            current_stage: 1,
        };
        let completed = advance_approval_stage(&mut config).unwrap();
        assert!(completed);
        assert_eq!(config.current_stage, 2);
    }

    #[test]
    fn approval_stages_advance_errors_when_already_complete() {
        let mut config = ApprovalStagesConfig {
            stages: vec![ApprovalStage {
                name: "review".into(),
                required_roles: vec![],
                criteria: None,
            }],
            current_stage: 1,
        };
        assert!(advance_approval_stage(&mut config).is_err());
    }
}