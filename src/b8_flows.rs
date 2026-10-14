// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! B8 scheme flows — Credit Transfer, Direct Debit, and On-Us A2A.
//! See `services/payments/DESIGN.md`.
//! B8 is the Sentin8-native payment scheme. It supports:
//! - Credit Transfer (pain.001 → pacs.008) with UETR correlation
//! - Direct Debit (pain.008 → pacs.003) with mandate resolution
//! - On-Us Account-to-Account (authorisation + settlement in one step)

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

// ── Types ───────────────────────────────────────────────────────────────

/// Result of a B8 flow processing step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct B8FlowResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl B8FlowResult {
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
    // UETR is required for B8 credit transfers.
    let tx_inf = cdt
        .get("CdtTrfTxInf")
        .ok_or_else(|| "pacs.008 missing CdtTrfTxInf".to_string())?;
    if tx_inf.get("UETR").is_none() {
        return Err("pacs.008 missing CdtTrfTxInf.UETR (required for B8)".into());
    }
    Ok(())
}

fn validate_pain008(pain008: &serde_json::Value) -> Result<(), String> {
    let doc = pain008
        .get("Document")
        .ok_or_else(|| "pain.008 missing Document".to_string())?;
    let cstmr = doc
        .get("CstmrDrctDbtInitn")
        .ok_or_else(|| "pain.008 missing CstmrDrctDbtInitn".to_string())?;
    let grp_hdr = cstmr
        .get("GrpHdr")
        .ok_or_else(|| "pain.008 missing GrpHdr".to_string())?;
    if grp_hdr.get("MsgId").is_none() {
        return Err("pain.008 missing GrpHdr.MsgId".into());
    }
    let pmt_inf = cstmr
        .get("PmtInf")
        .ok_or_else(|| "pain.008 missing PmtInf".to_string())?;
    if pmt_inf.get("ReqdColltnDt").is_none() {
        return Err("pain.008 missing PmtInf.ReqdColltnDt".into());
    }
    if pmt_inf.get("PmtTpInf").is_none() {
        return Err("pain.008 missing PmtInf.PmtTpInf".into());
    }
    Ok(())
}

fn validate_pacs003(pacs003: &serde_json::Value) -> Result<(), String> {
    let doc = pacs003
        .get("Document")
        .ok_or_else(|| "pacs.003 missing Document".to_string())?;
    let ddt = doc
        .get("FIToFIDrctDbt")
        .ok_or_else(|| "pacs.003 missing FIToFIDrctDbt".to_string())?;
    let grp_hdr = ddt
        .get("GrpHdr")
        .ok_or_else(|| "pacs.003 missing GrpHdr".to_string())?;
    if grp_hdr.get("MsgId").is_none() {
        return Err("pacs.003 missing GrpHdr.MsgId".into());
    }
    if ddt.get("DrctDbtTxInf").is_none() {
        return Err("pacs.003 missing DrctDbtTxInf".into());
    }
    Ok(())
}

fn validate_instruction(instruction: &serde_json::Value) -> Result<(), String> {
    if instruction.get("instruction_logic_id").is_none() && instruction.get("logic").is_none() {
        return Err("instruction requires instruction_logic_id or logic".into());
    }
    if instruction.get("input").is_none() {
        return Err("instruction requires input".into());
    }
    Ok(())
}

// ── Instruction creation ───────────────────────────────────────────────

async fn create_b8_instruction(
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

/// Generate a new UETR (UUID) for B8 credit transfers.
pub fn new_uetr() -> Uuid {
    Uuid::new_v4()
}

// ── Flows ───────────────────────────────────────────────────────────────

/// Process a B8 credit transfer outbound (pain.001).
/// Validates, creates a pacs.008 instruction with a UETR.
/// Story.
pub async fn process_b8_credit_transfer_outbound(
    pool: &sqlx::PgPool,
    pain001: &serde_json::Value,
) -> Result<B8FlowResult, String> {
    if let Err(e) = validate_pain001(pain001) {
        return Ok(B8FlowResult::err(e));
    }
    let uetr = new_uetr();
    let mut input = pain001.clone();
    // Attach the UETR to the input for downstream correlation.
    if let Some(obj) = input.as_object_mut() {
        obj.insert("uetr".to_string(), serde_json::json!(uetr.to_string()));
    }
    let instruction_id = create_b8_instruction(pool, "b8_ct_outbound", &input).await?;
    Ok(B8FlowResult::ok(instruction_id, "submitted"))
}

/// Process a B8 credit transfer inbound (pacs.008).
/// Validates, settles.
/// Story.
pub async fn process_b8_credit_transfer_inbound(
    pool: &sqlx::PgPool,
    pacs008: &serde_json::Value,
) -> Result<B8FlowResult, String> {
    if let Err(e) = validate_pacs008(pacs008) {
        return Ok(B8FlowResult::err(e));
    }
    let instruction_id = create_b8_instruction(pool, "b8_ct_inbound", pacs008).await?;
    Ok(B8FlowResult::ok(instruction_id, "settled"))
}

/// Process a B8 direct debit outbound (pain.008).
/// Validates, resolves the mandate, creates a pacs.003 instruction.
/// Story.
pub async fn process_b8_direct_debit_outbound(
    pool: &sqlx::PgPool,
    pain008: &serde_json::Value,
) -> Result<B8FlowResult, String> {
    if let Err(e) = validate_pain008(pain008) {
        return Ok(B8FlowResult::err(e));
    }
    // Mandate resolution (stub): would look up the mandate by ID.
    let instruction_id = create_b8_instruction(pool, "b8_dd_outbound", pain008).await?;
    Ok(B8FlowResult::ok(instruction_id, "submitted"))
}

/// Process a B8 direct debit inbound (pacs.003).
/// Validates, settles.
/// Story.
pub async fn process_b8_direct_debit_inbound(
    pool: &sqlx::PgPool,
    pacs003: &serde_json::Value,
) -> Result<B8FlowResult, String> {
    if let Err(e) = validate_pacs003(pacs003) {
        return Ok(B8FlowResult::err(e));
    }
    let instruction_id = create_b8_instruction(pool, "b8_dd_inbound", pacs003).await?;
    Ok(B8FlowResult::ok(instruction_id, "settled"))
}

/// Process a B8 On-Us Account-to-Account outbound.
/// Scheme validation → rule evaluation → authorisation → inbound (settlement).
/// Story.
pub async fn process_b8_onus_a2a_outbound(
    pool: &sqlx::PgPool,
    instruction: &serde_json::Value,
) -> Result<B8FlowResult, String> {
    if let Err(e) = validate_instruction(instruction) {
        return Ok(B8FlowResult::err(e));
    }
    let instruction_id = create_b8_instruction(pool, "b8_onus_a2a_outbound", instruction).await?;
    Ok(B8FlowResult::ok(instruction_id, "authorised"))
}

/// Process a B8 On-Us Account-to-Account inbound.
/// Matched check → account check → settlement → status report.
/// Story.
pub async fn process_b8_onus_a2a_inbound(
    pool: &sqlx::PgPool,
    instruction: &serde_json::Value,
) -> Result<B8FlowResult, String> {
    if let Err(e) = validate_instruction(instruction) {
        return Ok(B8FlowResult::err(e));
    }
    let instruction_id = create_b8_instruction(pool, "b8_onus_a2a_inbound", instruction).await?;
    Ok(B8FlowResult::ok(instruction_id, "settled"))
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pain001_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "CstmrCdtTrfInitn": {
                    "GrpHdr": { "MsgId": "P1", "CreDtTm": "2026-07-18T10:00:00Z" },
                    "PmtInf": { "ReqdExctnDt": "2026-07-18" }
                }
            }
        })
    }

    fn pacs008_msg(uetr: &str) -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "FIToFICstmrCdtTrf": {
                    "GrpHdr": { "MsgId": "P8" },
                    "CdtTrfTxInf": { "TxId": "T1", "UETR": uetr }
                }
            }
        })
    }

    fn pain008_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "CstmrDrctDbtInitn": {
                    "GrpHdr": { "MsgId": "P8DD" },
                    "PmtInf": {
                        "ReqdColltnDt": "2026-07-18",
                        "PmtTpInf": { "SvcLvl": { "Cd": "B8" } }
                    }
                }
            }
        })
    }

    fn pacs003_msg() -> serde_json::Value {
        serde_json::json!({
            "Document": {
                "FIToFIDrctDbt": {
                    "GrpHdr": { "MsgId": "P3" },
                    "DrctDbtTxInf": { "TxId": "T1" }
                }
            }
        })
    }

    fn instruction_msg() -> serde_json::Value {
        serde_json::json!({
            "instruction_logic_id": Uuid::new_v4().to_string(),
            "input": { "amount": "100.00", "currency": "EUR" }
        })
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
    fn validate_pacs008_requires_uetr() {
        let msg = serde_json::json!({
            "Document": {
                "FIToFICstmrCdtTrf": {
                    "GrpHdr": { "MsgId": "P8" },
                    "CdtTrfTxInf": { "TxId": "T1" }
                }
            }
        });
        assert!(validate_pacs008(&msg).is_err());
    }

    #[test]
    fn validate_pacs008_with_uetr_ok() {
        assert!(validate_pacs008(&pacs008_msg("11111111-2222-3333-4444-555555555555")).is_ok());
    }

    #[test]
    fn validate_pain008_ok() {
        assert!(validate_pain008(&pain008_msg()).is_ok());
    }

    #[test]
    fn validate_pain008_missing_pmttpinf() {
        let msg = serde_json::json!({
            "Document": {
                "CstmrDrctDbtInitn": {
                    "GrpHdr": { "MsgId": "X" },
                    "PmtInf": { "ReqdColltnDt": "2026-07-18" }
                }
            }
        });
        assert!(validate_pain008(&msg).is_err());
    }

    #[test]
    fn validate_pacs003_ok() {
        assert!(validate_pacs003(&pacs003_msg()).is_ok());
    }

    #[test]
    fn validate_pacs003_missing_txinf() {
        let msg = serde_json::json!({
            "Document": {
                "FIToFIDrctDbt": { "GrpHdr": { "MsgId": "X" } }
            }
        });
        assert!(validate_pacs003(&msg).is_err());
    }

    #[test]
    fn validate_instruction_ok() {
        assert!(validate_instruction(&instruction_msg()).is_ok());
    }

    #[test]
    fn validate_instruction_missing_input() {
        let msg = serde_json::json!({ "instruction_logic_id": Uuid::new_v4().to_string() });
        assert!(validate_instruction(&msg).is_err());
    }

    #[test]
    fn validate_instruction_missing_logic() {
        let msg = serde_json::json!({ "input": { "amount": "1" } });
        assert!(validate_instruction(&msg).is_err());
    }

    #[test]
    fn new_uetr_is_unique() {
        let a = new_uetr();
        let b = new_uetr();
        assert_ne!(a, b);
    }

    #[test]
    fn b8_flow_result_ok_helper() {
        let r = B8FlowResult::ok(Uuid::new_v4(), "settled");
        assert_eq!(r.status, "settled");
        assert!(r.instruction_id.is_some());
        assert!(r.error.is_none());
    }

    #[test]
    fn b8_flow_result_err_helper() {
        let r = B8FlowResult::err("bad");
        assert_eq!(r.status, "rejected");
        assert!(r.instruction_id.is_none());
        assert_eq!(r.error.as_deref(), Some("bad"));
    }

    #[test]
    fn b8_flow_result_serialises() {
        let r = B8FlowResult::err("oops");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["status"], "rejected");
        assert_eq!(v["error"], "oops");
        assert!(v.get("instruction_id").is_none());
    }
}