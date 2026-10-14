// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! TIPS instant payment flows — inbound, outbound, recalls, timeouts, and
//! status requests.
//! See `services/payments/DESIGN.md`.
//! All functions accept the ISO 20022 message as a `serde_json::Value` (the
//! JSON representation of the XML message). They validate the message,
//! create an instruction in `instructions`, and return a
//! `TipsFlowResult`.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

// ── Types ───────────────────────────────────────────────────────────────

/// Result of a TIPS flow processing step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipsFlowResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TipsFlowResult {
    pub fn ok(instruction_id: Uuid, status: &str) -> Self {
        Self {
            status: status.to_string(),
            instruction_id: Some(instruction_id),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            status: "rejected".to_string(),
            instruction_id: None,
            error: Some(message.into()),
        }
    }
}

// ── Timeout ─────────────────────────────────────────────────────────────

/// TIPS timeout configuration. The target is the soft target (5s by default);
/// the hard deadline is the absolute maximum (7s by default).
/// Story.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TipsTimeoutConfig {
    #[serde(default = "default_target_seconds")]
    pub target_seconds: u64,
    #[serde(default = "default_hard_deadline_seconds")]
    pub hard_deadline_seconds: u64,
}

fn default_target_seconds() -> u64 {
    5
}
fn default_hard_deadline_seconds() -> u64 {
    7
}

impl Default for TipsTimeoutConfig {
    fn default() -> Self {
        Self {
            target_seconds: default_target_seconds(),
            hard_deadline_seconds: default_hard_deadline_seconds(),
        }
    }
}

/// Status of a TIPS instruction relative to its timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipsTimeoutStatus {
    /// Within the target SLA.
    WithinTarget,
    /// Past the target but before the hard deadline.
    WithinHardDeadline,
    /// Past the hard deadline.
    Expired,
}

/// Check the timeout status of a TIPS instruction given its creation time.
/// Story.
pub fn check_tips_timeout(
    created_at: DateTime<Utc>,
    config: &TipsTimeoutConfig,
) -> TipsTimeoutStatus {
    let now = Utc::now();
    let elapsed = now - created_at;
    let target = Duration::seconds(config.target_seconds as i64);
    let hard = Duration::seconds(config.hard_deadline_seconds as i64);
    if elapsed <= target {
        TipsTimeoutStatus::WithinTarget
    } else if elapsed <= hard {
        TipsTimeoutStatus::WithinHardDeadline
    } else {
        TipsTimeoutStatus::Expired
    }
}

// ── Validation helpers ─────────────────────────────────────────────────

/// Validate a pacs.008 (Customer Credit Transfer) message.
fn validate_pacs008(pacs008: &serde_json::Value) -> Result<(), String> {
    let doc = pacs008
        .get("Document")
        .ok_or_else(|| "pacs.008 missing Document".to_string())?;
    let cdt = doc
        .get("FIToFICstmrCdtTrf")
        .ok_or_else(|| "pacs.008 missing FIToFICstmrCdtTrf".to_string())?;
    let grp_hdr = cdt
        .get("GrpHdr")
        .ok_or_else(|| "pacs.008 missing GrpHdr".to_string())?;
    if grp_hdr.get("MsgId").is_none() {
        return Err("pacs.008 missing GrpHdr.MsgId".into());
    }
    let cdt_trf_tx_inf = cdt
        .get("CdtTrfTxInf")
        .ok_or_else(|| "pacs.008 missing CdtTrfTxInf".to_string())?;
    if cdt_trf_tx_inf.get("IntrBkSttlmAmt").is_none() {
        return Err("pacs.008 missing CdtTrfTxInf.IntrBkSttlmAmt".into());
    }
    Ok(())
}

/// Validate a pain.001 (Customer Credit Transfer Initiation) message.
fn validate_pain001(pain001: &serde_json::Value) -> Result<(), String> {
    let doc = pain001
        .get("Document")
        .ok_or_else(|| "pain.001 missing Document".to_string())?;
    let cstmr = doc
        .get("CstmrCdtTrfInitn")
        .ok_or_else(|| "pain.001 missing CstmrCdtTrfInitn".to_string())?;
    let grp_hdr = cstmr
        .get("GrpHdr")
        .ok_or_else(|| "pain.001 missing GrpHdr".to_string())?;
    if grp_hdr.get("MsgId").is_none() {
        return Err("pain.001 missing GrpHdr.MsgId".into());
    }
    let pmt_inf = cstmr
        .get("PmtInf")
        .ok_or_else(|| "pain.001 missing PmtInf".to_string())?;
    if pmt_inf.get("ReqdExctnDt").is_none() {
        return Err("pain.001 missing PmtInf.ReqdExctnDt".into());
    }
    Ok(())
}

/// Validate a camt.056 (FI to FI Payment Cancellation Request) message.
fn validate_camt056(camt056: &serde_json::Value) -> Result<(), String> {
    let doc = camt056
        .get("Document")
        .ok_or_else(|| "camt.056 missing Document".to_string())?;
    let cancell = doc
        .get("FIToFIPmtCxlReq")
        .ok_or_else(|| "camt.056 missing FIToFIPmtCxlReq".to_string())?;
    let grp_hdr = cancell
        .get("GrpHdr")
        .ok_or_else(|| "camt.056 missing GrpHdr".to_string())?;
    if grp_hdr.get("MsgId").is_none() {
        return Err("camt.056 missing GrpHdr.MsgId".into());
    }
    let cxl_inf = cancell
        .get("CxlInf")
        .ok_or_else(|| "camt.056 missing CxlInf".to_string())?;
    if cxl_inf.get("OrgnlTxId").is_none() {
        return Err("camt.056 missing CxlInf.OrgnlTxId".into());
    }
    Ok(())
}

/// Validate a pacs.028 (Payment Status Request) message.
fn validate_pacs028(pacs028: &serde_json::Value) -> Result<(), String> {
    let doc = pacs028
        .get("Document")
        .ok_or_else(|| "pacs.028 missing Document".to_string())?;
    let req = doc
        .get("PmtStsReq")
        .ok_or_else(|| "pacs.028 missing PmtStsReq".to_string())?;
    let grp_hdr = req
        .get("GrpHdr")
        .ok_or_else(|| "pacs.028 missing GrpHdr".to_string())?;
    if grp_hdr.get("MsgId").is_none() {
        return Err("pacs.028 missing GrpHdr.MsgId".into());
    }
    if req.get("OrgnlInstrInf").is_none() && req.get("TxInf").is_none() {
        return Err("pacs.028 missing OrgnlInstrInf or TxInf".into());
    }
    Ok(())
}

// ── Instruction creation ───────────────────────────────────────────────

/// Create a TIPS instruction and return its ID.
async fn create_tips_instruction(
    pool: &sqlx::PgPool,
    message_type: &str,
    input: &serde_json::Value,
) -> Result<Uuid, String> {
    let row = sqlx::query(
        r#"INSERT INTO instructions (state, input, correlation_id)
           VALUES ('pending', $1, $2)
           RETURNING id"#,
    )
    .bind(input)
    .bind(message_type)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;
    Ok(row.get("id"))
}

// ── Flows ───────────────────────────────────────────────────────────────

/// Process a TIPS inbound credit transfer (pacs.008).
/// Validates the pacs.008, creates an instruction, and returns the result.
/// Story.
pub async fn process_tips_inbound(
    pool: &sqlx::PgPool,
    pacs008: &serde_json::Value,
) -> Result<TipsFlowResult, String> {
    if let Err(e) = validate_pacs008(pacs008) {
        return Ok(TipsFlowResult::err(e));
    }
    let instruction_id = create_tips_instruction(pool, "tips_inbound", pacs008).await?;
    Ok(TipsFlowResult::ok(instruction_id, "accepted"))
}

/// Process a TIPS outbound credit transfer (pain.001).
/// Validates the pain.001, creates an instruction for authorisation and
/// pacs.008 submission.
/// Story.
pub async fn process_tips_outbound(
    pool: &sqlx::PgPool,
    pain001: &serde_json::Value,
) -> Result<TipsFlowResult, String> {
    if let Err(e) = validate_pain001(pain001) {
        return Ok(TipsFlowResult::err(e));
    }
    let instruction_id = create_tips_instruction(pool, "tips_outbound", pain001).await?;
    Ok(TipsFlowResult::ok(instruction_id, "accepted"))
}

/// Process a TIPS inbound recall (camt.056).
/// Validates the camt.056, creates a manual decision instruction.
/// Story.
pub async fn process_tips_inbound_recall(
    pool: &sqlx::PgPool,
    camt056: &serde_json::Value,
) -> Result<TipsFlowResult, String> {
    if let Err(e) = validate_camt056(camt056) {
        return Ok(TipsFlowResult::err(e));
    }
    let instruction_id = create_tips_instruction(pool, "tips_inbound_recall", camt056).await?;
    // Mark as manual decision required.
    Ok(TipsFlowResult::ok(instruction_id, "manual_decision_required"))
}

/// Process a TIPS outbound recall (camt.056).
/// Validates the camt.056, creates an instruction for submission.
/// Story.
pub async fn process_tips_outbound_recall(
    pool: &sqlx::PgPool,
    camt056: &serde_json::Value,
) -> Result<TipsFlowResult, String> {
    if let Err(e) = validate_camt056(camt056) {
        return Ok(TipsFlowResult::err(e));
    }
    let instruction_id = create_tips_instruction(pool, "tips_outbound_recall", camt056).await?;
    Ok(TipsFlowResult::ok(instruction_id, "accepted"))
}

/// Process a TIPS status request (pacs.028).
/// Creates a status request instruction.
/// Story.
pub async fn process_tips_status_request(
    pool: &sqlx::PgPool,
    pacs028: &serde_json::Value,
) -> Result<TipsFlowResult, String> {
    if let Err(e) = validate_pacs028(pacs028) {
        return Ok(TipsFlowResult::err(e));
    }
    let instruction_id = create_tips_instruction(pool, "tips_status_request", pacs028).await?;
    Ok(TipsFlowResult::ok(instruction_id, "accepted"))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pacs008_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "FIToFICstmrCdtTrf": {
                    "GrpHdr": { "MsgId": "MSG001", "CreDtTm": "2026-07-18T10:00:00Z" },
                    "CdtTrfTxInf": {
                        "TxId": "TX001",
                        "IntrBkSttlmAmt": { "value": "100.00", "ccy": "EUR" }
                    }
                }
            }
        })
    }

    fn pain001_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "CstmrCdtTrfInitn": {
                    "GrpHdr": { "MsgId": "PAIN001", "CreDtTm": "2026-07-18T10:00:00Z" },
                    "PmtInf": {
                        "ReqdExctnDt": "2026-07-18",
                        "Dbtr": { "Nm": "Alice" }
                    }
                }
            }
        })
    }

    fn camt056_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "FIToFIPmtCxlReq": {
                    "GrpHdr": { "MsgId": "CAMT056", "CreDtTm": "2026-07-18T10:00:00Z" },
                    "CxlInf": {
                        "OrgnlTxId": "TX001",
                        "CxlRsn": { "Rsn": "DUPL" }
                    }
                }
            }
        })
    }

    fn pacs028_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "PmtStsReq": {
                    "GrpHdr": { "MsgId": "PACS028", "CreDtTm": "2026-07-18T10:00:00Z" },
                    "OrgnlInstrInf": { "OrgnlInstrId": "TX001" }
                }
            }
        })
    }

    #[test]
    fn validate_pacs008_ok() {
        assert!(validate_pacs008(&pacs008_msg()).is_ok());
    }

    #[test]
    fn validate_pacs008_missing_document() {
        let msg = serde_json::json!({});
        assert!(validate_pacs008(&msg).is_err());
    }

    #[test]
    fn validate_pacs008_missing_msgid() {
        let mut msg = pacs008_msg();
        msg["Document"]["FIToFICstmrCdtTrf"]["GrpHdr"]["MsgId"] = serde_json::Value::Null;
        let _ = msg.as_object_mut().unwrap();
        msg["Document"]["FIToFICstmrCdtTrf"]["GrpHdr"]
            .as_object_mut()
            .unwrap()
            .remove("MsgId");
        assert!(validate_pacs008(&msg).is_err());
    }

    #[test]
    fn validate_pain001_ok() {
        assert!(validate_pain001(&pain001_msg()).is_ok());
    }

    #[test]
    fn validate_pain001_missing_pmtinf() {
        let msg = serde_json::json!({
            "Document": {
                "CstmrCdtTrfInitn": {
                    "GrpHdr": { "MsgId": "X" }
                }
            }
        });
        assert!(validate_pain001(&msg).is_err());
    }

    #[test]
    fn validate_camt056_ok() {
        assert!(validate_camt056(&camt056_msg()).is_ok());
    }

    #[test]
    fn validate_camt056_missing_orgnltxid() {
        let msg = serde_json::json!({
            "Document": {
                "FIToFIPmtCxlReq": {
                    "GrpHdr": { "MsgId": "X" },
                    "CxlInf": {}
                }
            }
        });
        assert!(validate_camt056(&msg).is_err());
    }

    #[test]
    fn validate_pacs028_ok() {
        assert!(validate_pacs028(&pacs028_msg()).is_ok());
    }

    #[test]
    fn validate_pacs028_missing_txinf() {
        let msg = serde_json::json!({
            "Document": {
                "PmtStsReq": {
                    "GrpHdr": { "MsgId": "X" }
                }
            }
        });
        assert!(validate_pacs028(&msg).is_err());
    }

    #[test]
    fn tips_timeout_config_default() {
        let cfg = TipsTimeoutConfig::default();
        assert_eq!(cfg.target_seconds, 5);
        assert_eq!(cfg.hard_deadline_seconds, 7);
    }

    #[test]
    fn check_tips_timeout_within_target() {
        let cfg = TipsTimeoutConfig::default();
        let created = Utc::now() - Duration::seconds(2);
        assert_eq!(check_tips_timeout(created, &cfg), TipsTimeoutStatus::WithinTarget);
    }

    #[test]
    fn check_tips_timeout_within_hard_deadline() {
        let cfg = TipsTimeoutConfig::default();
        let created = Utc::now() - Duration::seconds(6);
        assert_eq!(
            check_tips_timeout(created, &cfg),
            TipsTimeoutStatus::WithinHardDeadline
        );
    }

    #[test]
    fn check_tips_timeout_expired() {
        let cfg = TipsTimeoutConfig::default();
        let created = Utc::now() - Duration::seconds(10);
        assert_eq!(check_tips_timeout(created, &cfg), TipsTimeoutStatus::Expired);
    }

    #[test]
    fn check_tips_timeout_custom_config() {
        let cfg = TipsTimeoutConfig {
            target_seconds: 10,
            hard_deadline_seconds: 20,
        };
        let created = Utc::now() - Duration::seconds(15);
        assert_eq!(
            check_tips_timeout(created, &cfg),
            TipsTimeoutStatus::WithinHardDeadline
        );
    }

    #[test]
    fn tips_flow_result_ok_helper() {
        let r = TipsFlowResult::ok(Uuid::new_v4(), "accepted");
        assert_eq!(r.status, "accepted");
        assert!(r.instruction_id.is_some());
        assert!(r.error.is_none());
    }

    #[test]
    fn tips_flow_result_err_helper() {
        let r = TipsFlowResult::err("bad message");
        assert_eq!(r.status, "rejected");
        assert!(r.instruction_id.is_none());
        assert_eq!(r.error.as_deref(), Some("bad message"));
    }

    #[test]
    fn tips_flow_result_serialises() {
        let r = TipsFlowResult::err("oops");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "rejected");
        assert_eq!(v["error"], "oops");
        assert!(v.get("instruction_id").is_none());
    }
}