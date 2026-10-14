// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Configuration packs — pre-built packs of instruction logics and parameters
//! for SEPA Instant (TIPS) and SEPA Credit Transfer schemes.
//! See `services/payments/DESIGN.md`.
//! A configuration pack is a declarative bundle that can be imported into a
//! Payments environment to provision the instruction logics and parameters
//! required for a particular scheme. Each pack contains:
//! - a name, version, and description
//! - a list of instruction logics (each with a message type and steps)
//! - a list of parameters (name, type, value)

use serde::{Deserialize, Serialize};

// ── Types ───────────────────────────────────────────────────────────────

/// A configuration pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPack {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub logics: Vec<ConfigPackLogic>,
    #[serde(default)]
    pub parameters: Vec<ConfigPackParameter>,
}

/// An instruction logic inside a configuration pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPackLogic {
    pub name: String,
    /// ISO 20022 message type this logic handles (e.g. `pacs.008`, `pain.001`).
    pub message_type: String,
    /// The logic steps (a JSON array of Flow step definitions).
    pub steps: serde_json::Value,
}

/// A parameter inside a configuration pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPackParameter {
    pub name: String,
    pub parameter_type: String,
    pub value: String,
}

// ── Validation ─────────────────────────────────────────────────────────

/// Validate a configuration pack.
/// Checks:
/// - name and version are non-empty
/// - every logic has a non-empty name, message type, and steps array
/// - every parameter has a non-empty name, type, and value
/// - parameter names are unique
/// - logic names are unique
pub fn validate_config_pack(pack: &ConfigPack) -> Result<(), String> {
    if pack.name.trim().is_empty() {
        return Err("config pack name must not be empty".into());
    }
    if pack.version.trim().is_empty() {
        return Err("config pack version must not be empty".into());
    }

    let mut logic_names = std::collections::HashSet::new();
    for logic in &pack.logics {
        if logic.name.trim().is_empty() {
            return Err("logic name must not be empty".into());
        }
        if logic.message_type.trim().is_empty() {
            return Err(format!("logic {} has empty message_type", logic.name));
        }
        if !logic.steps.is_array() {
            return Err(format!("logic {} steps must be a JSON array", logic.name));
        }
        if !logic_names.insert(logic.name.clone()) {
            return Err(format!("duplicate logic name: {}", logic.name));
        }
    }

    let mut param_names = std::collections::HashSet::new();
    for param in &pack.parameters {
        if param.name.trim().is_empty() {
            return Err("parameter name must not be empty".into());
        }
        if param.parameter_type.trim().is_empty() {
            return Err(format!("parameter {} has empty type", param.name));
        }
        if !param_names.insert(param.name.clone()) {
            return Err(format!("duplicate parameter name: {}", param.name));
        }
    }

    Ok(())
}

// ── SEPA Instant (TIPS) pack ────────────────────────────────────────────

/// Return the SEPA Instant (TIPS) configuration pack.
/// Contains 18 instruction logics covering all TIPS message flows.
/// Story.
pub fn sepa_instant_tips_pack() -> ConfigPack {
    let logics = vec![
        tips_logic("tips_inbound_pacs008", "pacs.008"),
        tips_logic("tips_inbound_settlement", "pacs.008"),
        tips_logic("tips_inbound_pacs002", "pacs.002"),
        tips_logic("tips_outbound_pain001", "pain.001"),
        tips_logic("tips_outbound_authorisation", "pain.001"),
        tips_logic("tips_outbound_pacs008", "pacs.008"),
        tips_logic("tips_outbound_settlement", "pacs.008"),
        tips_logic("tips_outbound_release", "pacs.008"),
        tips_logic("tips_inbound_recall_camt056", "camt.056"),
        tips_logic("tips_inbound_recall_pacs004", "pacs.004"),
        tips_logic("tips_inbound_recall_camt029", "camt.029"),
        tips_logic("tips_outbound_recall_camt056", "camt.056"),
        tips_logic("tips_outbound_recall_pacs004", "pacs.004"),
        tips_logic("tips_outbound_recall_camt029", "camt.029"),
        tips_logic("tips_status_request_pacs028", "pacs.028"),
        tips_logic("tips_timeout_sweeper", "internal"),
        tips_logic("tips_reconciliation", "internal"),
        tips_logic("tips_daily_cutoff", "internal"),
    ];

    let parameters = vec![
        ConfigPackParameter {
            name: "tips_target_seconds".into(),
            parameter_type: "integer".into(),
            value: "5".into(),
        },
        ConfigPackParameter {
            name: "tips_hard_deadline_seconds".into(),
            parameter_type: "integer".into(),
            value: "7".into(),
        },
        ConfigPackParameter {
            name: "tips_max_requests_per_payment".into(),
            parameter_type: "integer".into(),
            value: "1".into(),
        },
        ConfigPackParameter {
            name: "tips_scheme".into(),
            parameter_type: "string".into(),
            value: "TIPS".into(),
        },
        ConfigPackParameter {
            name: "tips_settlement_currency".into(),
            parameter_type: "string".into(),
            value: "EUR".into(),
        },
    ];

    ConfigPack {
        name: "sepa-instant-tips".into(),
        version: "1.0.0".into(),
        description: Some("SEPA Instant (TIPS) configuration pack — 18 instruction logics".into()),
        logics,
        parameters,
    }
}

fn tips_logic(name: &str, message_type: &str) -> ConfigPackLogic {
    ConfigPackLogic {
        name: name.to_string(),
        message_type: message_type.to_string(),
        steps: serde_json::json!([
            { "type": "validate", "message_type": message_type },
            { "type": "route", "scheme": "TIPS" },
            { "type": "settle" }
        ]),
    }
}

// ── SEPA Credit Transfer pack ──────────────────────────────────────────

/// Return the SEPA Credit Transfer configuration pack.
/// Configured for EBA Clearing, ICF file format, with a daily 23:00 CET
/// schedule.
/// Story.
pub fn sepa_credit_transfer_pack() -> ConfigPack {
    let logics = vec![
        ConfigPackLogic {
            name: "sepa_ct_outbound_pain001".into(),
            message_type: "pain.001".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pain.001" },
                { "type": "route", "csm": "EBA_Clearing" },
                { "type": "transform", "to": "pacs.008" },
                { "type": "settle" },
                { "type": "icf_file", "format": "ICF" }
            ]),
        },
        ConfigPackLogic {
            name: "sepa_ct_inbound_pacs008".into(),
            message_type: "pacs.008".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pacs.008" },
                { "type": "route", "csm": "EBA_Clearing" },
                { "type": "settle" }
            ]),
        },
        ConfigPackLogic {
            name: "sepa_ct_outbound_rejection_pacs002".into(),
            message_type: "pacs.002".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pacs.002" },
                { "type": "match", "by": "original_instruction_id" },
                { "type": "credit_back" },
                { "type": "notify", "with": "pain.002" }
            ]),
        },
        ConfigPackLogic {
            name: "sepa_ct_outbound_return_pacs004".into(),
            message_type: "pacs.004".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pacs.004" },
                { "type": "match", "by": "original_instruction_id" },
                { "type": "check_period", "max_days": 10 },
                { "type": "settle" },
                { "type": "notify", "with": "pain.002" }
            ]),
        },
        ConfigPackLogic {
            name: "sepa_ct_inbound_automatic_return".into(),
            message_type: "pacs.004".into(),
            steps: serde_json::json!([
                { "type": "check_postings_rejected" },
                { "type": "internal_transfers" },
                { "type": "transform", "to": "pacs.004" },
                { "type": "icf_file", "format": "ICF" }
            ]),
        },
        ConfigPackLogic {
            name: "sepa_ct_recall_dupl".into(),
            message_type: "camt.056".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "camt.056" },
                { "type": "check_deadline", "recall_type": "DUPL", "max_business_days": 10 },
                { "type": "submit_recall" }
            ]),
        },
        ConfigPackLogic {
            name: "sepa_ct_recall_tech".into(),
            message_type: "camt.056".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "camt.056" },
                { "type": "check_deadline", "recall_type": "TECH", "max_business_days": 10 },
                { "type": "submit_recall" }
            ]),
        },
        ConfigPackLogic {
            name: "sepa_ct_recall_frad".into(),
            message_type: "camt.056".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "camt.056" },
                { "type": "check_deadline", "recall_type": "FRAD", "max_months": 13 },
                { "type": "submit_recall" }
            ]),
        },
        ConfigPackLogic {
            name: "sepa_ct_daily_settlement".into(),
            message_type: "internal".into(),
            steps: serde_json::json!([
                { "type": "schedule", "cron": "0 0 23 * * *", "timezone": "CET" },
                { "type": "batch_settle" },
                { "type": "icf_file", "format": "ICF" }
            ]),
        },
    ];

    let parameters = vec![
        ConfigPackParameter {
            name: "sepa_ct_csm".into(),
            parameter_type: "string".into(),
            value: "EBA_Clearing".into(),
        },
        ConfigPackParameter {
            name: "sepa_ct_icf_format".into(),
            parameter_type: "string".into(),
            value: "ICF".into(),
        },
        ConfigPackParameter {
            name: "sepa_ct_settlement_schedule".into(),
            parameter_type: "string".into(),
            value: "0 0 23 * * *".into(),
        },
        ConfigPackParameter {
            name: "sepa_ct_settlement_timezone".into(),
            parameter_type: "string".into(),
            value: "CET".into(),
        },
        ConfigPackParameter {
            name: "sepa_ct_currency".into(),
            parameter_type: "string".into(),
            value: "EUR".into(),
        },
        ConfigPackParameter {
            name: "sepa_ct_return_period_days".into(),
            parameter_type: "integer".into(),
            value: "10".into(),
        },
    ];

    ConfigPack {
        name: "sepa-credit-transfer".into(),
        version: "1.0.0".into(),
        description: Some(
            "SEPA Credit Transfer configuration pack — EBA Clearing, ICF format, daily 23:00 CET"
                .into(),
        ),
        logics,
        parameters,
    }
}

// ── B8 Credit Transfer pack ────────────────────────────────────────────

/// Return the B8 Credit Transfer configuration pack.
/// B8 is the Sentin8-native payment scheme. This pack covers Credit Transfer
/// flows with example ACH configuration, UETR correlation, and a daily
/// 18:00 UTC settlement schedule.
/// Contains logics for:
/// - `credit_transfer_outbound` (pain.001 → pacs.008)
/// - `credit_transfer_inbound` (pacs.008)
/// - `credit_transfer_recall` (camt.056)
/// Story.
pub fn b8_credit_transfer_pack() -> ConfigPack {
    let logics = vec![
        ConfigPackLogic {
            name: "credit_transfer_outbound".into(),
            message_type: "pain.001".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pain.001" },
                { "type": "generate_uetr" },
                { "type": "transform", "to": "pacs.008", "attach_uetr": true },
                { "type": "route", "scheme": "B8", "example": "ACH" },
                { "type": "submit" },
                { "type": "schedule_settlement", "cron": "0 0 18 * * *", "timezone": "UTC" }
            ]),
        },
        ConfigPackLogic {
            name: "credit_transfer_inbound".into(),
            message_type: "pacs.008".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pacs.008" },
                { "type": "correlate_by_uetr" },
                { "type": "settle" }
            ]),
        },
        ConfigPackLogic {
            name: "credit_transfer_recall".into(),
            message_type: "camt.056".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "camt.056" },
                { "type": "match_original", "by": "uetr" },
                { "type": "check_recall_window", "max_business_days": 10 },
                { "type": "submit_recall" },
                { "type": "notify", "with": "camt.029" }
            ]),
        },
    ];

    let parameters = vec![
        ConfigPackParameter {
            name: "b8_ct_scheme".into(),
            parameter_type: "string".into(),
            value: "B8".into(),
        },
        ConfigPackParameter {
            name: "b8_ct_example".into(),
            parameter_type: "string".into(),
            value: "ACH".into(),
        },
        ConfigPackParameter {
            name: "b8_ct_settlement_schedule".into(),
            parameter_type: "string".into(),
            value: "0 0 18 * * *".into(),
        },
        ConfigPackParameter {
            name: "b8_ct_settlement_timezone".into(),
            parameter_type: "string".into(),
            value: "UTC".into(),
        },
        ConfigPackParameter {
            name: "b8_ct_settlement_currency".into(),
            parameter_type: "string".into(),
            value: "CAD".into(),
        },
        ConfigPackParameter {
            name: "b8_ct_uetr_required".into(),
            parameter_type: "boolean".into(),
            value: "true".into(),
        },
        ConfigPackParameter {
            name: "b8_ct_recall_window_days".into(),
            parameter_type: "integer".into(),
            value: "10".into(),
        },
    ];

    ConfigPack {
        name: "b8-credit-transfer".into(),
        version: "1.0.0".into(),
        description: Some(
            "B8 Credit Transfer configuration pack — example ACH, UETR correlation, daily 18:00 UTC".into(),
        ),
        logics,
        parameters,
    }
}

// ── B8 Direct Debit pack ──────────────────────────────────────────────

/// Return the B8 Direct Debit configuration pack.
/// Covers mandate flows and direct debit collections with D-1 submission
/// and next business day settlement. Contains logics for:
/// - `direct_debit_outbound` (pain.008 → pacs.003)
/// - `direct_debit_inbound` (pacs.003)
/// - `mandate_outbound` (pain.009)
/// - `mandate_inbound` (pain.009 received)
/// Story.
pub fn b8_direct_debit_pack() -> ConfigPack {
    let logics = vec![
        ConfigPackLogic {
            name: "direct_debit_outbound".into(),
            message_type: "pain.008".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pain.008" },
                { "type": "resolve_mandate" },
                { "type": "check_d_minus_1_submission", "days_before": 1 },
                { "type": "transform", "to": "pacs.003" },
                { "type": "submit" },
                { "type": "schedule_settlement", "mode": "next_business_day" }
            ]),
        },
        ConfigPackLogic {
            name: "direct_debit_inbound".into(),
            message_type: "pacs.003".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pacs.003" },
                { "type": "match_mandate", "by": "mandate_id" },
                { "type": "settle", "mode": "next_business_day" }
            ]),
        },
        ConfigPackLogic {
            name: "mandate_outbound".into(),
            message_type: "pain.009".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pain.009" },
                { "type": "register_mandate" },
                { "type": "notify", "with": "pain.012" }
            ]),
        },
        ConfigPackLogic {
            name: "mandate_inbound".into(),
            message_type: "pain.009".into(),
            steps: serde_json::json!([
                { "type": "validate", "message_type": "pain.009" },
                { "type": "store_mandate" },
                { "type": "confirm_receipt", "with": "pain.012" }
            ]),
        },
    ];

    let parameters = vec![
        ConfigPackParameter {
            name: "b8_dd_scheme".into(),
            parameter_type: "string".into(),
            value: "B8".into(),
        },
        ConfigPackParameter {
            name: "b8_dd_submission_offset_days".into(),
            parameter_type: "integer".into(),
            value: "1".into(),
        },
        ConfigPackParameter {
            name: "b8_dd_settlement_mode".into(),
            parameter_type: "string".into(),
            value: "next_business_day".into(),
        },
        ConfigPackParameter {
            name: "b8_dd_mandate_required".into(),
            parameter_type: "boolean".into(),
            value: "true".into(),
        },
        ConfigPackParameter {
            name: "b8_dd_currency".into(),
            parameter_type: "string".into(),
            value: "CAD".into(),
        },
    ];

    ConfigPack {
        name: "b8-direct-debit".into(),
        version: "1.0.0".into(),
        description: Some(
            "B8 Direct Debit configuration pack — mandate flows, D-1 submission, next business day settlement".into(),
        ),
        logics,
        parameters,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sepa_instant_tips_pack_has_18_logics() {
        let pack = sepa_instant_tips_pack();
        assert_eq!(pack.logics.len(), 18, "TIPS pack should have 18 logics");
        assert!(!pack.parameters.is_empty());
    }

    #[test]
    fn sepa_instant_tips_pack_validates() {
        let pack = sepa_instant_tips_pack();
        validate_config_pack(&pack).expect("TIPS pack should be valid");
    }

    #[test]
    fn sepa_credit_transfer_pack_validates() {
        let pack = sepa_credit_transfer_pack();
        validate_config_pack(&pack).expect("SEPA CT pack should be valid");
    }

    #[test]
    fn sepa_credit_transfer_pack_has_eba_clearing() {
        let pack = sepa_credit_transfer_pack();
        let csm = pack
            .parameters
            .iter()
            .find(|p| p.name == "sepa_ct_csm")
            .expect("missing sepa_ct_csm parameter");
        assert_eq!(csm.value, "EBA_Clearing");
    }

    #[test]
    fn sepa_credit_transfer_pack_has_icf_format() {
        let pack = sepa_credit_transfer_pack();
        let fmt = pack
            .parameters
            .iter()
            .find(|p| p.name == "sepa_ct_icf_format")
            .expect("missing sepa_ct_icf_format parameter");
        assert_eq!(fmt.value, "ICF");
    }

    #[test]
    fn sepa_credit_transfer_pack_has_daily_23_cet_schedule() {
        let pack = sepa_credit_transfer_pack();
        let sched = pack
            .parameters
            .iter()
            .find(|p| p.name == "sepa_ct_settlement_schedule")
            .expect("missing schedule parameter");
        assert_eq!(sched.value, "0 0 23 * * *");
        let tz = pack
            .parameters
            .iter()
            .find(|p| p.name == "sepa_ct_settlement_timezone")
            .expect("missing timezone parameter");
        assert_eq!(tz.value, "CET");
    }

    #[test]
    fn sepa_credit_transfer_pack_has_recall_logics() {
        let pack = sepa_credit_transfer_pack();
        let names: Vec<&str> = pack.logics.iter().map(|l| l.name.as_str()).collect();
        assert!(names.contains(&"sepa_ct_recall_dupl"));
        assert!(names.contains(&"sepa_ct_recall_tech"));
        assert!(names.contains(&"sepa_ct_recall_frad"));
    }

    #[test]
    fn validate_rejects_empty_name() {
        let pack = ConfigPack {
            name: "".into(),
            version: "1.0.0".into(),
            description: None,
            logics: vec![],
            parameters: vec![],
        };
        assert!(validate_config_pack(&pack).is_err());
    }

    #[test]
    fn validate_rejects_empty_version() {
        let pack = ConfigPack {
            name: "pack".into(),
            version: "  ".into(),
            description: None,
            logics: vec![],
            parameters: vec![],
        };
        assert!(validate_config_pack(&pack).is_err());
    }

    #[test]
    fn validate_rejects_logic_with_empty_message_type() {
        let pack = ConfigPack {
            name: "pack".into(),
            version: "1.0.0".into(),
            description: None,
            logics: vec![ConfigPackLogic {
                name: "logic1".into(),
                message_type: "".into(),
                steps: serde_json::json!([]),
            }],
            parameters: vec![],
        };
        assert!(validate_config_pack(&pack).is_err());
    }

    #[test]
    fn validate_rejects_logic_with_non_array_steps() {
        let pack = ConfigPack {
            name: "pack".into(),
            version: "1.0.0".into(),
            description: None,
            logics: vec![ConfigPackLogic {
                name: "logic1".into(),
                message_type: "pacs.008".into(),
                steps: serde_json::json!({}),
            }],
            parameters: vec![],
        };
        assert!(validate_config_pack(&pack).is_err());
    }

    #[test]
    fn validate_rejects_duplicate_logic_names() {
        let pack = ConfigPack {
            name: "pack".into(),
            version: "1.0.0".into(),
            description: None,
            logics: vec![
                ConfigPackLogic {
                    name: "logic1".into(),
                    message_type: "pacs.008".into(),
                    steps: serde_json::json!([]),
                },
                ConfigPackLogic {
                    name: "logic1".into(),
                    message_type: "pain.001".into(),
                    steps: serde_json::json!([]),
                },
            ],
            parameters: vec![],
        };
        assert!(validate_config_pack(&pack).is_err());
    }

    #[test]
    fn validate_rejects_duplicate_parameter_names() {
        let pack = ConfigPack {
            name: "pack".into(),
            version: "1.0.0".into(),
            description: None,
            logics: vec![],
            parameters: vec![
                ConfigPackParameter {
                    name: "p1".into(),
                    parameter_type: "string".into(),
                    value: "v1".into(),
                },
                ConfigPackParameter {
                    name: "p1".into(),
                    parameter_type: "string".into(),
                    value: "v2".into(),
                },
            ],
        };
        assert!(validate_config_pack(&pack).is_err());
    }

    #[test]
    fn validate_rejects_parameter_with_empty_type() {
        let pack = ConfigPack {
            name: "pack".into(),
            version: "1.0.0".into(),
            description: None,
            logics: vec![],
            parameters: vec![ConfigPackParameter {
                name: "p1".into(),
                parameter_type: "".into(),
                value: "v1".into(),
            }],
        };
        assert!(validate_config_pack(&pack).is_err());
    }

    #[test]
    fn validate_accepts_empty_pack() {
        let pack = ConfigPack {
            name: "pack".into(),
            version: "1.0.0".into(),
            description: None,
            logics: vec![],
            parameters: vec![],
        };
        assert!(validate_config_pack(&pack).is_ok());
    }

    #[test]
    fn config_pack_serialises() {
        let pack = sepa_instant_tips_pack();
        let v = serde_json::to_value(&pack).unwrap();
        assert_eq!(v["name"], "sepa-instant-tips");
        assert!(v["logics"].is_array());
        assert!(v["parameters"].is_array());
    }

    // ── Story — B8 Credit Transfer pack ───────────────────────

    #[test]
    fn b8_credit_transfer_pack_validates() {
        let pack = b8_credit_transfer_pack();
        validate_config_pack(&pack).expect("B8 CT pack should be valid");
    }

    #[test]
    fn b8_credit_transfer_pack_has_three_logics() {
        let pack = b8_credit_transfer_pack();
        let names: Vec<&str> = pack.logics.iter().map(|l| l.name.as_str()).collect();
        assert!(names.contains(&"credit_transfer_outbound"));
        assert!(names.contains(&"credit_transfer_inbound"));
        assert!(names.contains(&"credit_transfer_recall"));
        assert_eq!(pack.logics.len(), 3);
    }

    #[test]
    fn b8_credit_transfer_pack_has_example_ach() {
        let pack = b8_credit_transfer_pack();
        let example = pack
            .parameters
            .iter()
            .find(|p| p.name == "b8_ct_example")
            .expect("missing b8_ct_example parameter");
        assert_eq!(example.value, "ACH");
    }

    #[test]
    fn b8_credit_transfer_pack_has_daily_18_utc_schedule() {
        let pack = b8_credit_transfer_pack();
        let sched = pack
            .parameters
            .iter()
            .find(|p| p.name == "b8_ct_settlement_schedule")
            .expect("missing schedule parameter");
        assert_eq!(sched.value, "0 0 18 * * *");
        let tz = pack
            .parameters
            .iter()
            .find(|p| p.name == "b8_ct_settlement_timezone")
            .expect("missing timezone parameter");
        assert_eq!(tz.value, "UTC");
    }

    #[test]
    fn b8_credit_transfer_pack_has_uetr_required() {
        let pack = b8_credit_transfer_pack();
        let uetr = pack
            .parameters
            .iter()
            .find(|p| p.name == "b8_ct_uetr_required")
            .expect("missing uetr_required parameter");
        assert_eq!(uetr.value, "true");
        // The outbound logic attaches a UETR.
        let outbound = pack
            .logics
            .iter()
            .find(|l| l.name == "credit_transfer_outbound")
            .unwrap();
        let steps = outbound.steps.as_array().unwrap();
        let has_uetr_step = steps
            .iter()
            .any(|s| s.get("type").and_then(|v| v.as_str()) == Some("generate_uetr"));
        assert!(has_uetr_step, "outbound logic must generate a UETR");
    }

    #[test]
    fn b8_credit_transfer_pack_inbound_correlates_by_uetr() {
        let pack = b8_credit_transfer_pack();
        let inbound = pack
            .logics
            .iter()
            .find(|l| l.name == "credit_transfer_inbound")
            .unwrap();
        let steps = inbound.steps.as_array().unwrap();
        let has_correlate = steps
            .iter()
            .any(|s| s.get("type").and_then(|v| v.as_str()) == Some("correlate_by_uetr"));
        assert!(has_correlate, "inbound logic must correlate by UETR");
    }

    #[test]
    fn b8_credit_transfer_pack_serialises() {
        let pack = b8_credit_transfer_pack();
        let v = serde_json::to_value(&pack).unwrap();
        assert_eq!(v["name"], "b8-credit-transfer");
        assert_eq!(v["logics"].as_array().unwrap().len(), 3);
    }

    // ── Story — B8 Direct Debit pack ─────────────────────────

    #[test]
    fn b8_direct_debit_pack_validates() {
        let pack = b8_direct_debit_pack();
        validate_config_pack(&pack).expect("B8 DD pack should be valid");
    }

    #[test]
    fn b8_direct_debit_pack_has_four_logics() {
        let pack = b8_direct_debit_pack();
        let names: Vec<&str> = pack.logics.iter().map(|l| l.name.as_str()).collect();
        assert!(names.contains(&"direct_debit_outbound"));
        assert!(names.contains(&"direct_debit_inbound"));
        assert!(names.contains(&"mandate_outbound"));
        assert!(names.contains(&"mandate_inbound"));
        assert_eq!(pack.logics.len(), 4);
    }

    #[test]
    fn b8_direct_debit_pack_has_d_minus_1_submission() {
        let pack = b8_direct_debit_pack();
        let offset = pack
            .parameters
            .iter()
            .find(|p| p.name == "b8_dd_submission_offset_days")
            .expect("missing submission offset parameter");
        assert_eq!(offset.value, "1");
        // The outbound logic checks D-1 submission.
        let outbound = pack
            .logics
            .iter()
            .find(|l| l.name == "direct_debit_outbound")
            .unwrap();
        let steps = outbound.steps.as_array().unwrap();
        let has_d_minus_1 = steps
            .iter()
            .any(|s| s.get("type").and_then(|v| v.as_str()) == Some("check_d_minus_1_submission"));
        assert!(has_d_minus_1, "outbound logic must check D-1 submission");
    }

    #[test]
    fn b8_direct_debit_pack_has_next_business_day_settlement() {
        let pack = b8_direct_debit_pack();
        let mode = pack
            .parameters
            .iter()
            .find(|p| p.name == "b8_dd_settlement_mode")
            .expect("missing settlement mode parameter");
        assert_eq!(mode.value, "next_business_day");
        // The outbound logic schedules settlement with this mode.
        let outbound = pack
            .logics
            .iter()
            .find(|l| l.name == "direct_debit_outbound")
            .unwrap();
        let steps = outbound.steps.as_array().unwrap();
        let sched_step = steps
            .iter()
            .find(|s| s.get("type").and_then(|v| v.as_str()) == Some("schedule_settlement"))
            .expect("missing schedule_settlement step");
        assert_eq!(sched_step["mode"], "next_business_day");
    }

    #[test]
    fn b8_direct_debit_pack_mandate_flows_present() {
        let pack = b8_direct_debit_pack();
        let mandate_out = pack
            .logics
            .iter()
            .find(|l| l.name == "mandate_outbound")
            .unwrap();
        assert_eq!(mandate_out.message_type, "pain.009");
        let mandate_in = pack
            .logics
            .iter()
            .find(|l| l.name == "mandate_inbound")
            .unwrap();
        assert_eq!(mandate_in.message_type, "pain.009");
    }

    #[test]
    fn b8_direct_debit_pack_serialises() {
        let pack = b8_direct_debit_pack();
        let v = serde_json::to_value(&pack).unwrap();
        assert_eq!(v["name"], "b8-direct-debit");
        assert_eq!(v["logics"].as_array().unwrap().len(), 4);
    }
}
