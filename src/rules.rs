// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Rules engine - CRUD, publish, versioning, RuleSets - , -69.
//! See `services/payments/DESIGN.md` §4.8.
//! Rule Types:
//! - Basic: Returns restrictions (block/allow) and can edit instruction fields
//! - AccountLinkSelection: Returns true/false for account selection

use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleResponse {
    pub id: Uuid,
    pub name: String,
    pub rule_type: String,
    pub expression: String,
    pub action: String,
    pub status: String,
    pub version: i32,
    pub active_version_id: Option<Uuid>,
    pub expected_parameters: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRuleRequest {
    pub name: String,
    #[serde(default)]
    pub rule_type: Option<String>,
    pub expression: String,
    pub action: String,
    #[serde(default)]
    pub expected_parameters: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleVersionResponse {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub version: i32,
    pub implementation: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PublishRuleVersionRequest {
    pub implementation: String,
    #[serde(default)]
    pub expected_parameters: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct RuleSetResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleSetRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub rule_ids: Option<Vec<Uuid>>,
}

#[derive(Debug, Serialize)]
pub struct RuleSetVersionResponse {
    pub id: Uuid,
    pub rule_set_id: Uuid,
    pub version: i32,
    pub rule_ids: serde_json::Value,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ── Helpers ────────────────────────────────────────────────────────────

pub fn row_to_rule(row: &sqlx::postgres::PgRow) -> RuleResponse {
    RuleResponse {
        id: row.get("id"),
        name: row.get("name"),
        rule_type: row.get("rule_type"),
        expression: row.get("expression"),
        action: row.get("action"),
        status: row.get("status"),
        version: row.get("version"),
        active_version_id: row.get("active_version_id"),
        expected_parameters: row.get("expected_parameters"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

pub fn row_to_rule_set(row: &sqlx::postgres::PgRow) -> RuleSetResponse {
    RuleSetResponse {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        status: row.get("status"),
        version: row.get("version"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

// ── Rule-based Account Link Selection (Story ) ──────────────────
// When a RulesStep is used for account link selection, the rule function
// `account_link_selection(instr, matched_instr, params)` returns true/false
// for each candidate account link. Only links that return `true` are
// included in the result.
// In the current implementation, the rule is executed via Func. If Func
// is unavailable, the fallback is to return all active links (no filtering).

/// Evaluate account link selection rules against a set of candidate links.
/// This is called by the `AccountLinkStep` proxy-back handler when a
/// `RulesStep` is configured for selection. Each candidate link is evaluated
/// against the rule; only links that pass are returned.
pub fn filter_links_by_rule(
    candidates: &[serde_json::Value],
    rule_result: &serde_json::Value,
) -> Vec<serde_json::Value> {
    // If the rule result has a "selected" array, use it directly.
    if let Some(selected) = rule_result.get("selected").and_then(|v| v.as_array()) {
        return selected.clone();
    }

    // If the rule result is a boolean, filter all candidates (true = keep all,
    // false = reject all).
    if let Some(keep) = rule_result.as_bool() {
        return if keep { candidates.to_vec() } else { vec![] };
    }

    // If the rule result has "allowed_ids", filter by ID.
    if let Some(allowed) = rule_result.get("allowed_ids").and_then(|v| v.as_array()) {
        let allowed_ids: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
        return candidates
            .iter()
            .filter(|c| {
                c.get("id")
                    .and_then(|v| v.as_str())
                    .map(|id| allowed_ids.contains(&id))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
    }

    // Fallback: return all candidates (no filtering).
    candidates.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_filter_links_by_rule_boolean_true() {
        let candidates = vec![json!({"id": "1"}), json!({"id": "2"})];
        let result = filter_links_by_rule(&candidates, &json!(true));
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_links_by_rule_boolean_false() {
        let candidates = vec![json!({"id": "1"}), json!({"id": "2"})];
        let result = filter_links_by_rule(&candidates, &json!(false));
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_filter_links_by_rule_selected() {
        let candidates = vec![json!({"id": "1"}), json!({"id": "2"})];
        let rule = json!({"selected": [{"id": "1"}]});
        let result = filter_links_by_rule(&candidates, &rule);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["id"], "1");
    }

    #[test]
    fn test_filter_links_by_rule_allowed_ids() {
        let candidates = vec![json!({"id": "1"}), json!({"id": "2"}), json!({"id": "3"})];
        let rule = json!({"allowed_ids": ["1", "3"]});
        let result = filter_links_by_rule(&candidates, &rule);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_links_by_rule_fallback() {
        let candidates = vec![json!({"id": "1"})];
        let rule = json!({"unknown": "format"});
        let result = filter_links_by_rule(&candidates, &rule);
        assert_eq!(result.len(), 1);
    }
}
