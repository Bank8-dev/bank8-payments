// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Mandates — direct debit mandate lifecycle (pain.009 / pain.008 / pain.012).
//! See `services/payments/DESIGN.md`.
//! Provides:
//! - `MandateStatus` lifecycle enum
//! - `MandateFlow` (Outbound / Inbound)
//! - `validate_mandate_pain009` — structural validation of a pain.009 message
//! - `process_outbound_mandate` — validate and submit to debtor PSP
//! - `process_inbound_mandate` — validate, create mandate, initiate pain.012
//! - `resolve_mandate` — look up a mandate by scheme IDs
//! - `process_direct_debit_collection` — match mandate, schedule pain.008

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

// ── Enums ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateStatus {
    Active,
    Suspended,
    Cancelled,
    Expired,
}

impl MandateStatus {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            other => Err(format!("unknown mandate status: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateFlow {
    Outbound,
    Inbound,
}

impl MandateFlow {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "outbound" => Ok(Self::Outbound),
            "inbound" => Ok(Self::Inbound),
            other => Err(format!("unknown mandate flow: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
        }
    }
}

// ── Validation ─────────────────────────────────────────────────────────

/// Validate the structure of a pain.009 (mandate) message.
/// A pain.009 message must contain:
/// - A top-level object with a `document` field, OR be the document itself
/// - A `CstmrDrctDbtMndgtn` (CustomerDirectDebitMandate) container
/// - At least one `Mndt` (mandate) entry
/// - Each mandate has a `MndtId` (mandate ID) and a `Cdtr` (creditor) block
/// This is a simplified structural validator; production deployments should
/// use a full ISO 20022 schema validator.
pub fn validate_mandate_pain009(pain009: &serde_json::Value) -> Result<(), String> {
    let document = pain009
        .get("document")
        .unwrap_or(pain009);

    let container = document
        .get("CstmrDrctDbtMndgtn")
        .ok_or_else(|| "pain.009 missing CstmrDrctDbtMndgtn container".to_string())?;

    let mandate_container = container
        .get("Mndt")
        .ok_or_else(|| "pain.009 missing Mndt block".to_string())?;

    // `Mndt` may be an array of mandates or a single mandate object.
    let mandates: Vec<&serde_json::Value> = match mandate_container {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        obj @ serde_json::Value::Object(_) => vec![obj],
        _ => return Err("pain.009 Mndt must be an object or array".into()),
    };

    if mandates.is_empty() {
        return Err("pain.009 must contain at least one mandate".into());
    }

    for (i, m) in mandates.iter().enumerate() {
        let mndt_id = m
            .get("MndtId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("pain.009 mandate {i} missing MndtId"))?;
        if mndt_id.is_empty() {
            return Err(format!("pain.009 mandate {i} has empty MndtId"));
        }
        if m.get("Cdtr").is_none() {
            return Err(format!("pain.009 mandate {i} missing Cdtr (creditor)"));
        }
        if m.get("Dbtr").is_none() {
            return Err(format!("pain.009 mandate {i} missing Dbtr (debtor)"));
        }
    }

    Ok(())
}

// ── Processing ─────────────────────────────────────────────────────────

/// Process an outbound mandate (pain.009) — validate then submit to the
/// debtor PSP. Returns the mandate ID.
/// Story.
pub async fn process_outbound_mandate(
    pool: &sqlx::PgPool,
    pain009: serde_json::Value,
) -> Result<Uuid, String> {
    validate_mandate_pain009(&pain009)?;

    let document = pain009.get("document").unwrap_or(&pain009);
    let container = document
        .get("CstmrDrctDbtMndgtn")
        .ok_or_else(|| "invalid pain.009".to_string())?;
    let mandate = match container.get("Mndt") {
        Some(serde_json::Value::Array(arr)) => arr
            .first()
            .ok_or_else(|| "pain.009 has no mandates".to_string())?,
        Some(v) => v,
        None => return Err("pain.009 missing Mndt".into()),
    };

    let scheme_mandate_id = mandate
        .get("MndtId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing MndtId".to_string())?
        .to_string();
    let scheme_creditor_id = mandate
        .get("Cdtr")
        .and_then(|c| c.get("Id"))
        .and_then(|i| i.get("OrgId"))
        .and_then(|o| o.get("OthrId"))
        .and_then(|o| o.get("Id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let debtor_name = mandate
        .get("Dbtr")
        .and_then(|d| d.get("Nm"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let debtor_account = mandate
        .get("DbtrAcct")
        .and_then(|a| a.get("Id"))
        .and_then(|i| i.get("Othr"))
        .and_then(|o| o.get("Id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let creditor_name = mandate
        .get("Cdtr")
        .and_then(|c| c.get("Nm"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let creditor_account = mandate
        .get("CdtrAcct")
        .and_then(|a| a.get("Id"))
        .and_then(|i| i.get("Othr"))
        .and_then(|o| o.get("Id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let amount_limit = mandate
        .get("Mndt")
        .and_then(|m| m.get("AmtLmt"))
        .and_then(|a| a.get("Amt"))
        .and_then(|v| v.as_str());
    let currency = mandate
        .get("Mndt")
        .and_then(|m| m.get("AmtLmt"))
        .and_then(|a| a.get("Ccy"))
        .and_then(|v| v.as_str())
        .unwrap_or("CAD")
        .to_string();

    let row = sqlx::query(
        r#"INSERT INTO mandates
               (scheme_creditor_id, scheme_mandate_id, debtor_name, debtor_account,
                creditor_name, creditor_account, amount_limit, currency, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active')
           RETURNING id"#,
    )
    .bind(&scheme_creditor_id)
    .bind(&scheme_mandate_id)
    .bind(&debtor_name)
    .bind(&debtor_account)
    .bind(&creditor_name)
    .bind(&creditor_account)
    .bind(amount_limit.and_then(|s| s.parse::<rust_decimal::Decimal>().ok()))
    .bind(&currency)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("create outbound mandate: {e}"))?;

    Ok(row.get("id"))
}

/// Process an inbound mandate (pain.009) — validate, create mandate, then
/// initiate a pain.012 (mandate acceptance) message. Returns the mandate ID.
/// Story.
pub async fn process_inbound_mandate(
    pool: &sqlx::PgPool,
    pain009: serde_json::Value,
) -> Result<Uuid, String> {
    validate_mandate_pain009(&pain009)?;
    let mandate_id = process_outbound_mandate(pool, pain009).await?;

    // Initiate pain.012 (mandate acceptance) — stub. In production this would
    // generate a pain.012 message and submit it to the creditor PSP.
    tracing::info!(mandate_id = %mandate_id, "initiated pain.012 mandate acceptance (stub)");

    Ok(mandate_id)
}

/// Look up a mandate by scheme creditor + scheme mandate IDs.
/// Story . Returns `Ok(Some(id))` if a matching active mandate is
/// found, `Ok(None)` otherwise.
pub async fn resolve_mandate(
    pool: &sqlx::PgPool,
    scheme_creditor_id: &str,
    scheme_mandate_id: &str,
) -> Result<Option<Uuid>, String> {
    let row = sqlx::query(
        r#"SELECT id FROM mandates
            WHERE scheme_creditor_id = $1
              AND scheme_mandate_id = $2
              AND status = 'active'
            LIMIT 1"#,
    )
    .bind(scheme_creditor_id)
    .bind(scheme_mandate_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("resolve mandate: {e}"))?;
    Ok(row.map(|r| r.get("id")))
}

/// Process a direct debit collection (pain.008) — match the mandate,
/// validate, determine the execution date, and schedule the instruction.
/// Returns the instruction ID.
/// Story.
pub async fn process_direct_debit_collection(
    pool: &sqlx::PgPool,
    pain008: serde_json::Value,
) -> Result<Uuid, String> {
    // Extract mandate reference from the pain.008 message.
    let document = pain008.get("document").unwrap_or(&pain008);
    let container = document
        .get("CstmrDrctDbtInitn")
        .ok_or_else(|| "pain.008 missing CstmrDrctDbtInitn container".to_string())?;
    let payment_info = container
        .get("PmtInf")
        .ok_or_else(|| "pain.008 missing PmtInf".to_string())?;
    let payments = match payment_info {
        serde_json::Value::Array(arr) => arr,
        v @ serde_json::Value::Object(_) => {
            // wrap a single PmtInf object in an array for uniform handling
            return process_pain008_pmt_info(pool, v).await;
        }
        _ => return Err("pain.008 PmtInf must be an object or array".into()),
    };
    if payments.is_empty() {
        return Err("pain.008 must contain at least one PmtInf".into());
    }
    process_pain008_pmt_info(pool, &payments[0]).await
}

async fn process_pain008_pmt_info(
    pool: &sqlx::PgPool,
    pmt_info: &serde_json::Value,
) -> Result<Uuid, String> {
    let direct_debit = pmt_info
        .get("DrctDbtTxInf")
        .ok_or_else(|| "pain.008 PmtInf missing DrctDbtTxInf".to_string())?;
    let tx = match direct_debit {
        serde_json::Value::Array(arr) => arr
            .first()
            .ok_or_else(|| "pain.008 DrctDbtTxInf empty".to_string())?,
        v => v,
    };

    let scheme_mandate_id = tx
        .get("DrctDbtTx")
        .and_then(|d| d.get("MndtRltdInf"))
        .and_then(|m| m.get("MndtId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "pain.008 missing MndtId".to_string())?;
    let scheme_creditor_id = pmt_info
        .get("Cdtr")
        .and_then(|c| c.get("Id"))
        .and_then(|i| i.get("OrgId"))
        .and_then(|o| o.get("OthrId"))
        .and_then(|o| o.get("Id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mandate_id = resolve_mandate(pool, scheme_creditor_id, scheme_mandate_id)
        .await?
        .ok_or_else(|| format!("no active mandate for creditor {scheme_creditor_id} mandate {scheme_mandate_id}"))?;

    // Determine the requested execution date; fall back to today (UTC).
    let reqd_colltn_dt = tx
        .get("ReqdColltnDt")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let execution_date = parse_iso_date(reqd_colltn_dt).unwrap_or_else(Utc::now);

    // Create an instruction row for the collection. This is a stub: in
    // production Payments would build a full instruction and submit it to the
    // scheme via Flow.
    let row = sqlx::query(
        r#"INSERT INTO instructions
               (env_id, state, idempotency_key, input)
           VALUES (
               COALESCE((SELECT env_id FROM mandates WHERE id = $1), '00000000-0000-0000-0000-000000000000'::uuid),
               'pending', $2, $3
           )
           RETURNING id"#,
    )
    .bind(mandate_id)
    .bind(scheme_mandate_id)
    .bind(serde_json::json!({
        "mandate_id": mandate_id,
        "scheme_mandate_id": scheme_mandate_id,
        "execution_date": execution_date.to_rfc3339(),
    }))
    .fetch_one(pool)
    .await
    .map_err(|e| format!("create direct debit instruction: {e}"))?;

    Ok(row.get("id"))
}

fn parse_iso_date(s: &str) -> Option<DateTime<Utc>> {
    if s.is_empty() {
        return None;
    }
    // Try full RFC3339 first, then plain date.
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.with_timezone(&Utc))
        .or_else(|| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok().map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mandate_status_round_trip() {
        for s in [
            MandateStatus::Active,
            MandateStatus::Suspended,
            MandateStatus::Cancelled,
            MandateStatus::Expired,
        ] {
            assert_eq!(MandateStatus::from_str(s.as_str()).unwrap(), s);
        }
        assert!(MandateStatus::from_str("bogus").is_err());
    }

    #[test]
    fn mandate_flow_round_trip() {
        for f in [MandateFlow::Outbound, MandateFlow::Inbound] {
            assert_eq!(MandateFlow::from_str(f.as_str()).unwrap(), f);
        }
        assert!(MandateFlow::from_str("bogus").is_err());
    }

    fn sample_pain009(mndt_id: &str) -> serde_json::Value {
        json!({
            "document": {
                "CstmrDrctDbtMndgtn": {
                    "Mndt": [{
                        "MndtId": mndt_id,
                        "Cdtr": { "Nm": "Acme Corp", "Id": { "OrgId": { "OthrId": { "Id": "ACME-CRED" } } } },
                        "Dbtr": { "Nm": "Jane Doe" },
                        "DbtrAcct": { "Id": { "Othr": { "Id": "DE9912345678" } } },
                        "CdtrAcct": { "Id": { "Othr": { "Id": "DE0098765432" } } },
                        "Mndt": { "AmtLmt": { "Amt": "1000.00", "Ccy": "EUR" } }
                    }]
                }
            }
        })
    }

    #[test]
    fn validate_pain009_accepts_valid_message() {
        let msg = sample_pain009("MNDT-1");
        assert!(validate_mandate_pain009(&msg).is_ok());
    }

    #[test]
    fn validate_pain009_accepts_single_mandate_object() {
        let mut msg = sample_pain009("MNDT-1");
        // Replace the array with a single object.
        if let Some(container) = msg
            .get_mut("document")
            .and_then(|d| d.get_mut("CstmrDrctDbtMndgtn"))
            .and_then(|c| c.get_mut("Mndt"))
        {
            if let serde_json::Value::Array(arr) = container {
                *container = arr.remove(0);
            }
        }
        assert!(validate_mandate_pain009(&msg).is_ok());
    }

    #[test]
    fn validate_pain009_rejects_missing_container() {
        let msg = json!({ "document": {} });
        assert!(validate_mandate_pain009(&msg).is_err());
    }

    #[test]
    fn validate_pain009_rejects_empty_mandate_id() {
        let mut msg = sample_pain009("");
        assert!(validate_mandate_pain009(&msg).is_err());
        // suppress unused warning
        let _ = &mut msg;
    }

    #[test]
    fn validate_pain009_rejects_missing_creditor() {
        let mut msg = sample_pain009("MNDT-1");
        if let Some(m) = msg
            .get_mut("document")
            .and_then(|d| d.get_mut("CstmrDrctDbtMndgtn"))
            .and_then(|c| c.get_mut("Mndt"))
            .and_then(|m| m.get_mut(0))
        {
            m.as_object_mut().unwrap().remove("Cdtr");
        }
        assert!(validate_mandate_pain009(&msg).is_err());
    }

    #[test]
    fn validate_pain009_rejects_missing_debtor() {
        let mut msg = sample_pain009("MNDT-1");
        if let Some(m) = msg
            .get_mut("document")
            .and_then(|d| d.get_mut("CstmrDrctDbtMndgtn"))
            .and_then(|c| c.get_mut("Mndt"))
            .and_then(|m| m.get_mut(0))
        {
            m.as_object_mut().unwrap().remove("Dbtr");
        }
        assert!(validate_mandate_pain009(&msg).is_err());
    }

    #[test]
    fn validate_pain009_rejects_empty_mandate_array() {
        let msg = json!({
            "document": { "CstmrDrctDbtMndgtn": { "Mndt": [] } }
        });
        assert!(validate_mandate_pain009(&msg).is_err());
    }

    #[test]
    fn parse_iso_date_handles_rfc3339_and_date_only() {
        assert!(parse_iso_date("2026-07-18T12:00:00Z").is_some());
        assert!(parse_iso_date("2026-07-18").is_some());
        assert!(parse_iso_date("").is_none());
        assert!(parse_iso_date("not-a-date").is_none());
    }
}