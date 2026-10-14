// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Mastercard MDES (Masterpass Digital Secure Remote Payment) integration.
//! See `services/payments/DESIGN.md` §4.6 (Integrations).
//! This module models the four-step MDES token lifecycle (card availability,
//! eligibility, authentication, tokenisation) and the T140 clearing cycle
//! summary report. The step processor is currently a stub — real integration
//! will call the Mastercard MDES API via `reqwest`.

use serde::{Deserialize, Serialize};
use sqlx::Row;

/// One of the four MDES token-lifecycle steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MdesStep {
    CardAvailability,
    Eligibility,
    Authentication,
    Tokenisation,
}

impl MdesStep {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "card_availability" => Ok(Self::CardAvailability),
            "eligibility" => Ok(Self::Eligibility),
            "authentication" => Ok(Self::Authentication),
            "tokenisation" => Ok(Self::Tokenisation),
            other => Err(format!("unknown MDES step: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CardAvailability => "card_availability",
            Self::Eligibility => "eligibility",
            Self::Authentication => "authentication",
            Self::Tokenisation => "tokenisation",
        }
    }
}

/// Request payload for an MDES step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdesRequest {
    pub step: MdesStep,
    pub card_id: uuid::Uuid,
    pub card_token_requestor_id: String,
    pub device_type: String,
}

/// Response from an MDES step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdesResponse {
    pub step: MdesStep,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Process one MDES step.
/// Stub implementation — always returns `success` and, for the final
/// (`Tokenisation`) step, generates a deterministic token reference derived
/// from the card id and requestor id.
pub fn process_mdes_step(request: &MdesRequest) -> MdesResponse {
    let token_reference = match request.step {
        MdesStep::Tokenisation => Some(generate_token_reference(
            request.card_id,
            &request.card_token_requestor_id,
        )),
        _ => None,
    };
    MdesResponse {
        step: request.step,
        status: "success".to_string(),
        token_reference,
        error: None,
    }
}

fn generate_token_reference(card_id: uuid::Uuid, requestor_id: &str) -> String {
    // Deterministic token reference: UUIDv5 over the card id and requestor id.
    let namespace = uuid::Uuid::NAMESPACE_URL;
    let payload = format!("{card_id}|{requestor_id}");
    uuid::Uuid::new_v5(&namespace, payload.as_bytes()).to_string()
}

// ── Story — T140 Clearing Cycle Summary ─────────────────────────

/// T140 clearing cycle summary report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct T140Report {
    pub report_id: uuid::Uuid,
    pub cycle_date: chrono::NaiveDate,
    pub total_amount: rust_decimal::Decimal,
    pub transaction_count: i64,
    pub summary_data: serde_json::Value,
}

/// Generate a T140 report for the given cycle date.
/// Queries `payments` for all payments created on `cycle_date` and
/// aggregates the total amount and transaction count. Caller is responsible
/// for having set the tenant context on the connection.
pub async fn generate_t140_report(
    pool: &sqlx::PgPool,
    cycle_date: chrono::NaiveDate,
) -> Result<T140Report, String> {
    let start = cycle_date
        .and_hms_opt(0, 0, 0)
        .ok_or("invalid cycle date")?;
    let end = cycle_date
        .succ_opt()
        .ok_or("invalid cycle date")?
        .and_hms_opt(0, 0, 0)
        .ok_or("invalid cycle date")?;

    let row = sqlx::query(
        r#"SELECT
               COALESCE(SUM(amount), 0) AS total_amount,
               COUNT(*)::bigint AS transaction_count
             FROM payments
            WHERE created_at >= $1 AND created_at < $2"#,
    )
    .bind(start)
    .bind(end)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("t140 query: {e}"))?;

    let total_amount: rust_decimal::Decimal = row.get("total_amount");
    let transaction_count: i64 = row.get("transaction_count");

    let summary_data = serde_json::json!({
        "cycle_date": cycle_date.to_string(),
        "transaction_count": transaction_count,
        "total_amount": total_amount.to_string(),
    });

    Ok(T140Report {
        report_id: uuid::Uuid::new_v4(),
        cycle_date,
        total_amount,
        transaction_count,
        summary_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mdes_step_round_trip() {
        for s in [
            MdesStep::CardAvailability,
            MdesStep::Eligibility,
            MdesStep::Authentication,
            MdesStep::Tokenisation,
        ] {
            let str = s.as_str();
            assert_eq!(MdesStep::from_str(str).unwrap(), s);
        }
        assert!(MdesStep::from_str("bogus").is_err());
    }

    fn req(step: MdesStep) -> MdesRequest {
        MdesRequest {
            step,
            card_id: uuid::Uuid::new_v4(),
            card_token_requestor_id: "REQ-123".into(),
            device_type: "Wearable".into(),
        }
    }

    #[test]
    fn process_card_availability_success() {
        let r = process_mdes_step(&req(MdesStep::CardAvailability));
        assert_eq!(r.status, "success");
        assert_eq!(r.step, MdesStep::CardAvailability);
        assert!(r.token_reference.is_none());
        assert!(r.error.is_none());
    }

    #[test]
    fn process_eligibility_success() {
        let r = process_mdes_step(&req(MdesStep::Eligibility));
        assert_eq!(r.status, "success");
        assert!(r.token_reference.is_none());
    }

    #[test]
    fn process_authentication_success() {
        let r = process_mdes_step(&req(MdesStep::Authentication));
        assert_eq!(r.status, "success");
        assert!(r.token_reference.is_none());
    }

    #[test]
    fn process_tokenisation_generates_token_reference() {
        let r = process_mdes_step(&req(MdesStep::Tokenisation));
        assert_eq!(r.status, "success");
        let token = r.token_reference.expect("token reference");
        assert!(uuid::Uuid::parse_str(&token).is_ok(), "token is a uuid");
    }

    #[test]
    fn token_reference_is_deterministic() {
        let card_id = uuid::Uuid::new_v4();
        let r1 = MdesRequest {
            step: MdesStep::Tokenisation,
            card_id,
            card_token_requestor_id: "REQ-1".into(),
            device_type: "Phone".into(),
        };
        let r2 = MdesRequest {
            step: MdesStep::Tokenisation,
            card_id,
            card_token_requestor_id: "REQ-1".into(),
            device_type: "Watch".into(),
        };
        let t1 = process_mdes_step(&r1).token_reference.unwrap();
        let t2 = process_mdes_step(&r2).token_reference.unwrap();
        assert_eq!(t1, t2, "device type must not affect token reference");
    }

    #[test]
    fn t140_report_serialises() {
        let report = T140Report {
            report_id: uuid::Uuid::new_v4(),
            cycle_date: chrono::NaiveDate::from_ymd_opt(2026, 7, 18).unwrap(),
            total_amount: rust_decimal::Decimal::from(12345),
            transaction_count: 42,
            summary_data: json!({ "cycle_date": "2026-07-18" }),
        };
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["transaction_count"], 42);
        assert_eq!(v["total_amount"], "12345");
    }
}
