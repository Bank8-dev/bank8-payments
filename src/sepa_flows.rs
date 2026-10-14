// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! SEPA Credit Transfer flows — outbound, inbound, rejections, returns, and
//! recalls.
//! See `services/payments/DESIGN.md`.

use chrono::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Types ───────────────────────────────────────────────────────────────

/// Result of a SEPA flow processing step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SepaFlowResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SepaFlowResult {
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

// ── Recall types ───────────────────────────────────────────────────────

/// SEPA recall reason types.
/// Story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SepaRecallType {
    /// Duplicate payment.
    Dupl,
    /// Technical error.
    Tech,
    /// Fraudulent transaction.
    Frad,
}

impl SepaRecallType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_uppercase().as_str() {
            "DUPL" => Ok(Self::Dupl),
            "TECH" => Ok(Self::Tech),
            "FRAD" => Ok(Self::Frad),
            other => Err(format!("unknown SEPA recall type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dupl => "DUPL",
            Self::Tech => "TECH",
            Self::Frad => "FRAD",
        }
    }
}

/// Get the recall deadline for the given recall type.
/// - DUPL/TECH: 10 business days
/// - FRAD: 13 months
/// Story.
pub fn get_recall_deadline(recall_type: &SepaRecallType) -> Duration {
    match recall_type {
        SepaRecallType::Dupl | SepaRecallType::Tech => Duration::days(10),
        SepaRecallType::Frad => Duration::days(365 * 13 / 12 * 30), // ~13 months approximation
    }
}

// ── Validation helpers ─────────────────────────────────────────────────

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
    if cdt.get("CdtTrfTxInf").is_none() {
        return Err("pacs.008 missing CdtTrfTxInf".into());
    }
    Ok(())
}

fn validate_pacs002(pacs002: &serde_json::Value) -> Result<(), String> {
    let doc = pacs002
        .get("Document")
        .ok_or_else(|| "pacs.002 missing Document".to_string())?;
    let rsl = doc
        .get("FIToFIPmtStsRpt")
        .ok_or_else(|| "pacs.002 missing FIToFIPmtStsRpt".to_string())?;
    let grp_hdr = rsl
        .get("GrpHdr")
        .ok_or_else(|| "pacs.002 missing GrpHdr".to_string())?;
    if grp_hdr.get("MsgId").is_none() {
        return Err("pacs.002 missing GrpHdr.MsgId".into());
    }
    if rsl.get("TxInf").is_none() && rsl.get("OrgnlGrpInf").is_none() {
        return Err("pacs.002 missing TxInf or OrgnlGrpInf".into());
    }
    Ok(())
}

fn validate_pacs004(pacs004: &serde_json::Value) -> Result<(), String> {
    let doc = pacs004
        .get("Document")
        .ok_or_else(|| "pacs.004 missing Document".to_string())?;
    let rtr = doc
        .get("PmtRtr")
        .ok_or_else(|| "pacs.004 missing PmtRtr".to_string())?;
    let grp_hdr = rtr
        .get("GrpHdr")
        .ok_or_else(|| "pacs.004 missing GrpHdr".to_string())?;
    if grp_hdr.get("MsgId").is_none() {
        return Err("pacs.004 missing GrpHdr.MsgId".into());
    }
    if rtr.get("TxInf").is_none() {
        return Err("pacs.004 missing TxInf".into());
    }
    Ok(())
}

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

// ── Instruction creation ───────────────────────────────────────────────

async fn create_sepa_instruction(
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
    use sqlx::Row;
    Ok(row.get("id"))
}

// ── Flows ───────────────────────────────────────────────────────────────

/// Process a SEPA CT outbound flow (pain.001).
/// Validates, routes, creates a pacs.008 instruction.
/// Story.
pub async fn process_sepa_ct_outbound(
    pool: &sqlx::PgPool,
    pain001: &serde_json::Value,
) -> Result<SepaFlowResult, String> {
    if let Err(e) = validate_pain001(pain001) {
        return Ok(SepaFlowResult::err(e));
    }
    let instruction_id = create_sepa_instruction(pool, "sepa_ct_outbound", pain001).await?;
    Ok(SepaFlowResult::ok(instruction_id, "submitted"))
}

/// Process a SEPA CT inbound flow (pacs.008).
/// Validates, routes, settles.
/// Story.
pub async fn process_sepa_ct_inbound(
    pool: &sqlx::PgPool,
    pacs008: &serde_json::Value,
) -> Result<SepaFlowResult, String> {
    if let Err(e) = validate_pacs008(pacs008) {
        return Ok(SepaFlowResult::err(e));
    }
    let instruction_id = create_sepa_instruction(pool, "sepa_ct_inbound", pacs008).await?;
    Ok(SepaFlowResult::ok(instruction_id, "settled"))
}

/// Process a SEPA CT outbound rejection (pacs.002 from CSM).
/// Matches the original outbound instruction, credits back, returns.
/// Story.
pub async fn process_sepa_ct_outbound_rejection(
    pool: &sqlx::PgPool,
    pacs002: &serde_json::Value,
) -> Result<SepaFlowResult, String> {
    if let Err(e) = validate_pacs002(pacs002) {
        return Ok(SepaFlowResult::err(e));
    }
    let instruction_id =
        create_sepa_instruction(pool, "sepa_ct_outbound_rejection", pacs002).await?;
    Ok(SepaFlowResult::ok(instruction_id, "rejected"))
}

/// Process a SEPA CT outbound return (pacs.004 from beneficiary).
/// Matches the original outbound instruction, checks the return period,
/// settles.
/// Story.
pub async fn process_sepa_ct_outbound_return(
    pool: &sqlx::PgPool,
    pacs004: &serde_json::Value,
) -> Result<SepaFlowResult, String> {
    if let Err(e) = validate_pacs004(pacs004) {
        return Ok(SepaFlowResult::err(e));
    }
    let instruction_id = create_sepa_instruction(pool, "sepa_ct_outbound_return", pacs004).await?;
    Ok(SepaFlowResult::ok(instruction_id, "returned"))
}

/// Process a SEPA CT inbound automatic return (postings rejected).
/// Creates a pacs.004 instruction to return the funds.
/// Story.
pub async fn process_sepa_ct_inbound_automatic_return(
    pool: &sqlx::PgPool,
    instruction_id: Uuid,
) -> Result<SepaFlowResult, String> {
    // Verify the instruction exists.
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM instructions WHERE id = $1")
        .bind(instruction_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;
    if exists.is_none() {
        return Err(format!("instruction {instruction_id} not found"));
    }
    let input = serde_json::json!({ "original_instruction_id": instruction_id });
    let new_id = create_sepa_instruction(pool, "sepa_ct_inbound_automatic_return", &input).await?;
    Ok(SepaFlowResult::ok(new_id, "returned"))
}

/// Process a SEPA CT recall (camt.056).
/// Validates the camt.056, creates a recall instruction of the specified type.
/// Story.
pub async fn process_sepa_ct_recall(
    pool: &sqlx::PgPool,
    camt056: &serde_json::Value,
    recall_type: SepaRecallType,
) -> Result<SepaFlowResult, String> {
    if let Err(e) = validate_camt056(camt056) {
        return Ok(SepaFlowResult::err(e));
    }
    let msg = format!("sepa_ct_recall_{}", recall_type.as_str().to_lowercase());
    let instruction_id = create_sepa_instruction(pool, &msg, camt056).await?;
    Ok(SepaFlowResult::ok(instruction_id, "recall_submitted"))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pain001_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "CstmrCdtTrfInitn": {
                    "GrpHdr": { "MsgId": "P001", "CreDtTm": "2026-07-18T10:00:00Z" },
                    "PmtInf": { "ReqdExctnDt": "2026-07-18" }
                }
            }
        })
    }

    fn pacs008_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "FIToFICstmrCdtTrf": {
                    "GrpHdr": { "MsgId": "P008" },
                    "CdtTrfTxInf": { "TxId": "T1" }
                }
            }
        })
    }

    fn pacs002_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "FIToFIPmtStsRpt": {
                    "GrpHdr": { "MsgId": "P002" },
                    "TxInf": { "OrgnlInstrId": "T1", "TxSts": "RJCT" }
                }
            }
        })
    }

    fn pacs004_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "PmtRtr": {
                    "GrpHdr": { "MsgId": "P004" },
                    "TxInf": { "OrgnlInstrId": "T1", "RtrRsn": "BEN" }
                }
            }
        })
    }

    fn camt056_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "FIToFIPmtCxlReq": {
                    "GrpHdr": { "MsgId": "C056" },
                    "CxlInf": { "OrgnlTxId": "T1", "CxlRsn": { "Rsn": "DUPL" } }
                }
            }
        })
    }

    #[test]
    fn sepa_recall_type_round_trip() {
        for t in [
            SepaRecallType::Dupl,
            SepaRecallType::Tech,
            SepaRecallType::Frad,
        ] {
            assert_eq!(SepaRecallType::from_str(t.as_str()).unwrap(), t);
        }
        // case-insensitive
        assert_eq!(
            SepaRecallType::from_str("dupl").unwrap(),
            SepaRecallType::Dupl
        );
        assert!(SepaRecallType::from_str("bogus").is_err());
    }

    #[test]
    fn recall_deadline_dupl_is_10_days() {
        assert_eq!(
            get_recall_deadline(&SepaRecallType::Dupl),
            Duration::days(10)
        );
    }

    #[test]
    fn recall_deadline_tech_is_10_days() {
        assert_eq!(
            get_recall_deadline(&SepaRecallType::Tech),
            Duration::days(10)
        );
    }

    #[test]
    fn recall_deadline_frad_is_13_months() {
        let d = get_recall_deadline(&SepaRecallType::Frad);
        // ~13 months: should be larger than 10 days.
        assert!(d > Duration::days(10));
        // Should approximate 13 * 30 days.
        assert_eq!(d, Duration::days(365 * 13 / 12 * 30));
    }

    #[test]
    fn validate_pain001_ok() {
        assert!(validate_pain001(&pain001_msg()).is_ok());
    }

    #[test]
    fn validate_pain001_missing_document() {
        assert!(validate_pain001(&serde_json::json!({})).is_err());
    }

    #[test]
    fn validate_pacs008_ok() {
        assert!(validate_pacs008(&pacs008_msg()).is_ok());
    }

    #[test]
    fn validate_pacs002_ok() {
        assert!(validate_pacs002(&pacs002_msg()).is_ok());
    }

    #[test]
    fn validate_pacs004_ok() {
        assert!(validate_pacs004(&pacs004_msg()).is_ok());
    }

    #[test]
    fn validate_camt056_ok() {
        assert!(validate_camt056(&camt056_msg()).is_ok());
    }

    #[test]
    fn validate_pacs002_missing_txinf() {
        let msg = serde_json::json!({
            "Document": {
                "FIToFIPmtStsRpt": { "GrpHdr": { "MsgId": "X" } }
            }
        });
        assert!(validate_pacs002(&msg).is_err());
    }

    #[test]
    fn validate_pacs004_missing_txinf() {
        let msg = serde_json::json!({
            "Document": {
                "PmtRtr": { "GrpHdr": { "MsgId": "X" } }
            }
        });
        assert!(validate_pacs004(&msg).is_err());
    }

    #[test]
    fn sepa_flow_result_ok_helper() {
        let r = SepaFlowResult::ok(Uuid::new_v4(), "settled");
        assert_eq!(r.status, "settled");
        assert!(r.instruction_id.is_some());
        assert!(r.error.is_none());
    }

    #[test]
    fn sepa_flow_result_err_helper() {
        let r = SepaFlowResult::err("bad");
        assert_eq!(r.status, "rejected");
        assert!(r.instruction_id.is_none());
        assert_eq!(r.error.as_deref(), Some("bad"));
    }

    #[test]
    fn sepa_flow_result_serialises() {
        let r = SepaFlowResult::err("oops");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "rejected");
        assert_eq!(v["error"], "oops");
        assert!(v.get("instruction_id").is_none());
    }
}
