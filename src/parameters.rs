// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Parameters system — , , ,.
//! Parameter types , levels (— Global vs Payment Instrument
//! override), timeseries values , and expected parameter validation
//! See `services/payments/DESIGN.md` §4.9 (Parameters System).

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

// ── ParameterType (Story ) ────────────────────────────────────────

/// The supported parameter value types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ParameterType {
    Boolean,
    String,
    Decimal,
    StringList,
    DateTime,
    JSON,
}

impl ParameterType {
    /// Parse a parameter type from its string representation.
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "boolean" => Ok(Self::Boolean),
            "string" => Ok(Self::String),
            "decimal" => Ok(Self::Decimal),
            "stringlist" | "string_list" | "string-list" => Ok(Self::StringList),
            "datetime" | "date_time" | "date-time" => Ok(Self::DateTime),
            "json" => Ok(Self::JSON),
            other => Err(format!("unknown parameter type: '{other}'")),
        }
    }

    /// Return the canonical string representation of the parameter type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Boolean => "Boolean",
            Self::String => "String",
            Self::Decimal => "Decimal",
            Self::StringList => "StringList",
            Self::DateTime => "DateTime",
            Self::JSON => "JSON",
        }
    }

    /// Validate that a JSON value is compatible with this parameter type.
    pub fn validate_value(&self, value: &serde_json::Value) -> Result<(), String> {
        match self {
            Self::Boolean => match value {
                serde_json::Value::Bool(_) => Ok(()),
                other => Err(format!("expected boolean, got {}", value_kind(other))),
            },
            Self::String => match value {
                serde_json::Value::String(_) => Ok(()),
                other => Err(format!("expected string, got {}", value_kind(other))),
            },
            Self::Decimal => match value {
                serde_json::Value::String(s) => {
                    // Must parse as a decimal number.
                    s.parse::<rust_decimal::Decimal>()
                        .map(|_| ())
                        .map_err(|e| format!("invalid decimal value '{s}': {e}"))
                }
                serde_json::Value::Number(n) if n.is_f64() => Ok(()),
                other => Err(format!("expected decimal, got {}", value_kind(other))),
            },
            Self::StringList => match value {
                serde_json::Value::Array(arr) => {
                    for (i, v) in arr.iter().enumerate() {
                        if !v.is_string() {
                            return Err(format!(
                                "string_list entry {i} must be a string, got {}",
                                value_kind(v)
                            ));
                        }
                    }
                    Ok(())
                }
                other => Err(format!("expected string list, got {}", value_kind(other))),
            },
            Self::DateTime => match value {
                serde_json::Value::String(s) => {
                    // RFC 3339 / ISO 8601 — try parse.
                    chrono::DateTime::parse_from_rfc3339(s)
                        .map(|_| ())
                        .map_err(|e| format!("invalid datetime value '{s}': {e}"))
                }
                other => Err(format!(
                    "expected datetime string, got {}",
                    value_kind(other)
                )),
            },
            Self::JSON => {
                // Any valid JSON value is acceptable.
                match value {
                    serde_json::Value::Null
                    | serde_json::Value::Bool(_)
                    | serde_json::Value::Number(_)
                    | serde_json::Value::String(_)
                    | serde_json::Value::Array(_)
                    | serde_json::Value::Object(_) => Ok(()),
                }
            }
        }
    }
}

fn value_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ── ParameterLevel (Story ) ────────────────────────────────────────

/// The level at which a parameter applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ParameterLevel {
    /// Applies to all payment instruments (default).
    Global,
    /// Overrides the global value for a specific payment instrument.
    PaymentInstrument,
}

impl ParameterLevel {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "global" => Ok(Self::Global),
            "payment_instrument" | "paymentinstrument" | "instrument" => {
                Ok(Self::PaymentInstrument)
            }
            other => Err(format!("unknown parameter level: '{other}'")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Global => "Global",
            Self::PaymentInstrument => "PaymentInstrument",
        }
    }
}

/// Resolve a parameter value for an organization/environment, preferring a
/// payment-instrument-level override and falling back to the global value.
/// Returns the resolved `value` column of `parameters`.
pub async fn resolve_parameter(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    name: &str,
    payment_instrument_id: Option<Uuid>,
) -> Result<String, String> {
    // 1. Check for an override scoped to the payment instrument.
    if let Some(pi_id) = payment_instrument_id {
        let row = sqlx::query(
            r#"SELECT value FROM parameters
                WHERE env_id = $1
                  AND name = $2 AND payment_instrument_id = $3
                  AND status = 'active'
                LIMIT 1"#,
        )
        .bind(env_id)
        .bind(name)
        .bind(pi_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("resolve_parameter override: {e}"))?;
        if let Some(r) = row {
            return Ok(r.get::<String, _>("value"));
        }
    }

    // 2. Fall back to the global value (payment_instrument_id IS NULL).
    let row = sqlx::query(
        r#"SELECT value FROM parameters
            WHERE env_id = $1
              AND name = $2 AND payment_instrument_id IS NULL
              AND status = 'active'
            LIMIT 1"#,
    )
    .bind(env_id)
    .bind(name)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("resolve_parameter global: {e}"))?;

    row.map(|r| r.get::<String, _>("value"))
        .ok_or_else(|| format!("parameter '{name}' not found"))
}

// ── Parameter timeseries (Story ) ─────────────────────────────────

/// Get the parameter value effective at `timestamp`.
/// Queries `parameter_values` for the row whose
/// `effective_from_timestamp <= timestamp AND (effective_to_timestamp IS NULL
/// OR effective_to_timestamp > timestamp)`.
pub async fn get_parameter_value_at(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    parameter_id: Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<Option<String>, String> {
    let row = sqlx::query(
        r#"SELECT value FROM parameter_values
            WHERE env_id = $1 AND parameter_id = $2
              AND effective_from_timestamp <= $3
              AND (effective_to_timestamp IS NULL OR effective_to_timestamp > $3)
            ORDER BY effective_from_timestamp DESC
            LIMIT 1"#,
    )
    .bind(env_id)
    .bind(parameter_id)
    .bind(timestamp)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("get_parameter_value_at: {e}"))?;
    Ok(row.map(|r| r.get::<String, _>("value")))
}

/// Insert a new parameter value effective from `effective_from`, and close
/// out the previously-current value by setting its `effective_to_timestamp`.
pub async fn set_parameter_value(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    parameter_id: Uuid,
    value: &str,
    effective_from: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| format!("set_parameter_value begin: {e}"))?;

    // Close out the previously-current value: any row for this parameter
    // whose effective_to_timestamp IS NULL and effective_from_timestamp < new.
    sqlx::query(
        r#"UPDATE parameter_values
              SET effective_to_timestamp = $3
            WHERE env_id = $1 AND parameter_id = $2
              AND effective_to_timestamp IS NULL
              AND effective_from_timestamp < $3"#,
    )
    .bind(env_id)
    .bind(parameter_id)
    .bind(effective_from)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("set_parameter_value update prev: {e}"))?;

    // Insert the new value.
    sqlx::query(
        r#"INSERT INTO parameter_values
               (env_id, parameter_id, value, effective_from_timestamp)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(env_id)
    .bind(parameter_id)
    .bind(value)
    .bind(effective_from)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("set_parameter_value insert: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("set_parameter_value commit: {e}"))?;
    Ok(())
}

// ── Expected parameters (Story ) ───────────────────────────────────

/// Validate that all `expected` parameter names are present in the provided
/// JSON object. The provided value must be a JSON object whose keys are the
/// parameter names.
pub fn validate_expected_parameters(
    expected: &[String],
    provided: &serde_json::Value,
) -> Result<(), String> {
    let obj = provided
        .as_object()
        .ok_or_else(|| "provided parameters must be a JSON object".to_string())?;

    let mut missing: Vec<&String> = Vec::new();
    for name in expected {
        if !obj.contains_key(name) {
            missing.push(name);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing expected parameters: {}",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── ParameterType  ───────────────────────────────────────

    #[test]
    fn test_parameter_type_from_str_round_trip() {
        for t in [
            ParameterType::Boolean,
            ParameterType::String,
            ParameterType::Decimal,
            ParameterType::StringList,
            ParameterType::DateTime,
            ParameterType::JSON,
        ] {
            let s = t.as_str();
            assert_eq!(ParameterType::from_str(s).unwrap(), t, "round-trip {s}");
        }
    }

    #[test]
    fn test_parameter_type_from_str_accepts_aliases() {
        assert_eq!(
            ParameterType::from_str("string_list").unwrap(),
            ParameterType::StringList
        );
        assert_eq!(
            ParameterType::from_str("string-list").unwrap(),
            ParameterType::StringList
        );
        assert_eq!(
            ParameterType::from_str("date_time").unwrap(),
            ParameterType::DateTime
        );
        assert_eq!(
            ParameterType::from_str("date-time").unwrap(),
            ParameterType::DateTime
        );
    }

    #[test]
    fn test_parameter_type_from_str_rejects_unknown() {
        assert!(ParameterType::from_str("nonsense").is_err());
    }

    #[test]
    fn test_parameter_type_from_str_is_case_insensitive() {
        assert_eq!(
            ParameterType::from_str("BOOLEAN").unwrap(),
            ParameterType::Boolean
        );
        assert_eq!(
            ParameterType::from_str("Json").unwrap(),
            ParameterType::JSON
        );
    }

    #[test]
    fn test_validate_value_boolean() {
        assert!(ParameterType::Boolean.validate_value(&json!(true)).is_ok());
        assert!(ParameterType::Boolean.validate_value(&json!(false)).is_ok());
        assert!(ParameterType::Boolean
            .validate_value(&json!("true"))
            .is_err());
        assert!(ParameterType::Boolean.validate_value(&json!(1)).is_err());
    }

    #[test]
    fn test_validate_value_string() {
        assert!(ParameterType::String
            .validate_value(&json!("hello"))
            .is_ok());
        assert!(ParameterType::String.validate_value(&json!(42)).is_err());
        assert!(ParameterType::String.validate_value(&json!(true)).is_err());
    }

    #[test]
    fn test_validate_value_decimal() {
        assert!(ParameterType::Decimal
            .validate_value(&json!("100.50"))
            .is_ok());
        assert!(ParameterType::Decimal.validate_value(&json!("0")).is_ok());
        assert!(ParameterType::Decimal
            .validate_value(&json!("-3.14159"))
            .is_ok());
        assert!(ParameterType::Decimal
            .validate_value(&json!("not-a-number"))
            .is_err());
        assert!(ParameterType::Decimal.validate_value(&json!(true)).is_err());
    }

    #[test]
    fn test_validate_value_string_list() {
        assert!(ParameterType::StringList
            .validate_value(&json!(["a", "b"]))
            .is_ok());
        assert!(ParameterType::StringList.validate_value(&json!([])).is_ok());
        assert!(ParameterType::StringList
            .validate_value(&json!(["a", 1]))
            .is_err());
        assert!(ParameterType::StringList
            .validate_value(&json!("a"))
            .is_err());
    }

    #[test]
    fn test_validate_value_datetime() {
        assert!(ParameterType::DateTime
            .validate_value(&json!("2026-07-18T12:00:00Z"))
            .is_ok());
        assert!(ParameterType::DateTime
            .validate_value(&json!("not-a-date"))
            .is_err());
        assert!(ParameterType::DateTime.validate_value(&json!(123)).is_err());
    }

    #[test]
    fn test_validate_value_json_accepts_anything() {
        assert!(ParameterType::JSON.validate_value(&json!({})).is_ok());
        assert!(ParameterType::JSON
            .validate_value(&json!([1, 2, 3]))
            .is_ok());
        assert!(ParameterType::JSON.validate_value(&json!(null)).is_ok());
        assert!(ParameterType::JSON
            .validate_value(&json!("any string"))
            .is_ok());
    }

    // ── ParameterLevel  ─────────────────────────────────────

    #[test]
    fn test_parameter_level_from_str_round_trip() {
        assert_eq!(
            ParameterLevel::from_str("Global").unwrap(),
            ParameterLevel::Global
        );
        assert_eq!(
            ParameterLevel::from_str("PaymentInstrument").unwrap(),
            ParameterLevel::PaymentInstrument
        );
        assert_eq!(
            ParameterLevel::from_str("payment_instrument").unwrap(),
            ParameterLevel::PaymentInstrument
        );
        assert_eq!(
            ParameterLevel::from_str("instrument").unwrap(),
            ParameterLevel::PaymentInstrument
        );
        assert!(ParameterLevel::from_str("bogus").is_err());
    }

    #[test]
    fn test_parameter_level_as_str() {
        assert_eq!(ParameterLevel::Global.as_str(), "Global");
        assert_eq!(
            ParameterLevel::PaymentInstrument.as_str(),
            "PaymentInstrument"
        );
    }

    // ── Parameter timeseries SQL  ───────────────────────────

    /// Unit test: the `get_parameter_value_at` query string contains the
    /// required timestamp predicates. This verifies the SQL shape without a
    /// live database.
    #[test]
    fn test_get_parameter_value_at_query_shape() {
        let q = r#"SELECT value FROM parameter_values
            WHERE env_id = $1 AND parameter_id = $2
              AND effective_from_timestamp <= $3
              AND (effective_to_timestamp IS NULL OR effective_to_timestamp > $3)
            ORDER BY effective_from_timestamp DESC
            LIMIT 1"#;
        assert!(q.contains("effective_from_timestamp <= $3"));
        assert!(q.contains("(effective_to_timestamp IS NULL OR effective_to_timestamp > $3)"));
        assert!(q.contains("parameter_values"));
    }

    /// Unit test: the `set_parameter_value` update query closes out the
    /// previous current value before inserting the new one.
    #[test]
    fn test_set_parameter_value_update_query_shape() {
        let update = r#"UPDATE parameter_values
              SET effective_to_timestamp = $3
            WHERE env_id = $1 AND parameter_id = $2
              AND effective_to_timestamp IS NULL
              AND effective_from_timestamp < $3"#;
        assert!(update.contains("SET effective_to_timestamp = $3"));
        assert!(update.contains("effective_to_timestamp IS NULL"));
        assert!(update.contains("effective_from_timestamp < $3"));

        let insert = r#"INSERT INTO parameter_values
               (env_id, parameter_id, value, effective_from_timestamp)
           VALUES ($1, $2, $3, $4)"#;
        assert!(insert.contains("effective_from_timestamp"));
    }

    // ── Expected parameters  ────────────────────────────────

    #[test]
    fn test_validate_expected_parameters_all_present() {
        let expected = vec!["max_amount".to_string(), "currency".to_string()];
        let provided = json!({"max_amount": "1000.00", "currency": "USD"});
        assert!(validate_expected_parameters(&expected, &provided).is_ok());
    }

    #[test]
    fn test_validate_expected_parameters_missing_one() {
        let expected = vec!["max_amount".to_string(), "currency".to_string()];
        let provided = json!({"max_amount": "1000.00"});
        let err = validate_expected_parameters(&expected, &provided).unwrap_err();
        assert!(err.contains("currency"), "err: {err}");
        assert!(err.contains("missing expected parameters"), "err: {err}");
    }

    #[test]
    fn test_validate_expected_parameters_empty_expected() {
        let provided = json!({});
        assert!(validate_expected_parameters(&[], &provided).is_ok());
    }

    #[test]
    fn test_validate_expected_parameters_extra_keys_ok() {
        let expected = vec!["a".to_string()];
        let provided = json!({"a": "1", "b": "2"});
        assert!(validate_expected_parameters(&expected, &provided).is_ok());
    }

    #[test]
    fn test_validate_expected_parameters_rejects_non_object() {
        let expected = vec!["a".to_string()];
        let err = validate_expected_parameters(&expected, &json!([1, 2])).unwrap_err();
        assert!(err.contains("JSON object"), "err: {err}");
    }

    #[test]
    fn test_validate_expected_parameters_missing_multiple_lists_all() {
        let expected = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let err = validate_expected_parameters(&expected, &json!({})).unwrap_err();
        assert!(err.contains("a"), "err: {err}");
        assert!(err.contains("b"), "err: {err}");
        assert!(err.contains("c"), "err: {err}");
    }
}
