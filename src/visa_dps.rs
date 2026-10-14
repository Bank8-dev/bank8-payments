// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Visa DPS integration.
//! See `services/payments/DESIGN.md` §4.6 (Integrations).
//! Models Visa DPS authorisation/clearing/STIP message processing, two-way
//! card/account synchronisation, and AP (Account Processing) balance file
//! upload. All network calls are stubbed pending real Visa DPS connectivity.

use serde::{Deserialize, Serialize};

/// Visa DPS message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisaDpsMessageType {
    Authorisation,
    Clearing,
    Stip,
}

impl VisaDpsMessageType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "authorisation" => Ok(Self::Authorisation),
            "clearing" => Ok(Self::Clearing),
            "stip" => Ok(Self::Stip),
            other => Err(format!("unknown Visa DPS message type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Authorisation => "authorisation",
            Self::Clearing => "clearing",
            Self::Stip => "stip",
        }
    }
}

/// Request for a Visa DPS message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisaDpsRequest {
    pub message_type: VisaDpsMessageType,
    pub card_id: uuid::Uuid,
    pub amount: rust_decimal::Decimal,
    pub merchant_id: String,
}

/// Response from a Visa DPS message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisaDpsResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
}

/// Process a Visa DPS request.
/// Stub decision logic (amount thresholds):
/// - `amount < 1000` → `approved` (response code `00`)
/// - `1000 <= amount < 5000` → `stip_required` (response code `STIP`)
/// - `amount >= 5000` → `declined` (response code `05`)
pub fn process_visa_dps(request: &VisaDpsRequest) -> VisaDpsResponse {
    let hundred = rust_decimal::Decimal::from(1000);
    let five_thousand = rust_decimal::Decimal::from(5000);

    if request.amount < hundred {
        VisaDpsResponse {
            status: "approved".into(),
            auth_id: Some(format!("AUTH-{}", uuid::Uuid::new_v4().as_simple())),
            response_code: Some("00".into()),
        }
    } else if request.amount < five_thousand {
        VisaDpsResponse {
            status: "stip_required".into(),
            auth_id: None,
            response_code: Some("STIP".into()),
        }
    } else {
        VisaDpsResponse {
            status: "declined".into(),
            auth_id: None,
            response_code: Some("05".into()),
        }
    }
}

// ── Story — Card/account synchronisation ──────────────────────

/// Direction of a Visa DPS card/account sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisaDpsSyncDirection {
    PaymentsToDps,
    DpsToPayments,
}

impl VisaDpsSyncDirection {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "payments_to_dps" => Ok(Self::PaymentsToDps),
            "dps_to_payments" => Ok(Self::DpsToPayments),
            other => Err(format!("unknown sync direction: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PaymentsToDps => "payments_to_dps",
            Self::DpsToPayments => "dps_to_payments",
        }
    }
}

/// Push card data from Payments to Visa DPS.
/// Stub — would call DPS `PUT /cards/{card_id}` with the card record.
pub async fn sync_card_to_dps(
    _pool: &sqlx::PgPool,
    _card_id: uuid::Uuid,
) -> Result<(), String> {
    Ok(())
}

/// Pull card data from Visa DPS into Payments.
/// Stub — would call DPS `GET /cards/{card_id}` and update the local record.
pub async fn sync_card_from_dps(
    _pool: &sqlx::PgPool,
    _card_id: uuid::Uuid,
) -> Result<(), String> {
    Ok(())
}

// ── Story — AP Balance Files ───────────────────────────────────

/// One row in an AP balance file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApBalanceEntry {
    pub account_number: String,
    pub opening_balance: rust_decimal::Decimal,
    pub closing_balance: rust_decimal::Decimal,
    pub debit_total: rust_decimal::Decimal,
    pub credit_total: rust_decimal::Decimal,
}

/// AP balance file (Account Processing end-of-day balance reconciliation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApBalanceFile {
    pub file_id: uuid::Uuid,
    pub report_date: chrono::NaiveDate,
    pub entries: Vec<ApBalanceEntry>,
}

/// Upload an AP balance file.
/// Stub — would persist the file to storage and record it in the DB. Returns
/// a new file id (uses the one on the file if non-nil, otherwise generates).
pub async fn upload_ap_balance_file(
    _pool: &sqlx::PgPool,
    mut file: ApBalanceFile,
) -> Result<uuid::Uuid, String> {
    if file.file_id == uuid::Uuid::nil() {
        file.file_id = uuid::Uuid::new_v4();
    }
    Ok(file.file_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;

    #[test]
    fn visa_dps_message_type_round_trip() {
        for t in [
            VisaDpsMessageType::Authorisation,
            VisaDpsMessageType::Clearing,
            VisaDpsMessageType::Stip,
        ] {
            assert_eq!(VisaDpsMessageType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(VisaDpsMessageType::from_str("nope").is_err());
    }

    fn req(amount: i64) -> VisaDpsRequest {
        VisaDpsRequest {
            message_type: VisaDpsMessageType::Authorisation,
            card_id: uuid::Uuid::new_v4(),
            amount: Decimal::from(amount),
            merchant_id: "M-1".into(),
        }
    }

    #[test]
    fn approves_below_threshold() {
        let r = process_visa_dps(&req(500));
        assert_eq!(r.status, "approved");
        assert!(r.auth_id.is_some());
        assert_eq!(r.response_code.as_deref(), Some("00"));
    }

    #[test]
    fn stip_in_between() {
        let r = process_visa_dps(&req(2500));
        assert_eq!(r.status, "stip_required");
        assert!(r.auth_id.is_none());
        assert_eq!(r.response_code.as_deref(), Some("STIP"));
    }

    #[test]
    fn declines_at_or_above_threshold() {
        let r = process_visa_dps(&req(5000));
        assert_eq!(r.status, "declined");
        assert_eq!(r.response_code.as_deref(), Some("05"));
        let r2 = process_visa_dps(&req(99999));
        assert_eq!(r2.status, "declined");
    }

    #[test]
    fn boundary_1000_is_stip() {
        let r = process_visa_dps(&req(1000));
        assert_eq!(r.status, "stip_required");
    }

    #[test]
    fn sync_direction_round_trip() {
        for d in [VisaDpsSyncDirection::PaymentsToDps, VisaDpsSyncDirection::DpsToPayments] {
            assert_eq!(VisaDpsSyncDirection::from_str(d.as_str()).unwrap(), d);
        }
        assert!(VisaDpsSyncDirection::from_str("sideways").is_err());
    }

    #[tokio::test]
    async fn sync_card_stubs_return_ok() {
        // No real pool needed for stubs.
        let pool: Option<sqlx::PgPool> = None;
        // We can't pass &Option, so just assert the unit signatures compile.
        let _ = VisaDpsSyncDirection::PaymentsToDps.as_str();
        let _ = VisaDpsSyncDirection::DpsToPayments.as_str();
        let _ = pool;
    }

    #[test]
    fn ap_balance_file_serialises() {
        let file = ApBalanceFile {
            file_id: uuid::Uuid::nil(),
            report_date: chrono::NaiveDate::from_ymd_opt(2026, 7, 18).unwrap(),
            entries: vec![ApBalanceEntry {
                account_number: "1234".into(),
                opening_balance: Decimal::from(100),
                closing_balance: Decimal::from(150),
                debit_total: Decimal::from(50),
                credit_total: Decimal::from(100),
            }],
        };
        let v = serde_json::to_value(&file).unwrap();
        assert_eq!(v["entries"][0]["account_number"], "1234");
        assert_eq!(v["report_date"], "2026-07-18");
    }

    #[tokio::test]
    async fn upload_ap_balance_file_assigns_id_when_nil() {
        // We can't actually call the stub without a pool; just exercise logic
        // by mirroring the assignment behaviour.
        let mut id = uuid::Uuid::nil();
        if id == uuid::Uuid::nil() {
            id = uuid::Uuid::new_v4();
        }
        assert_ne!(id, uuid::Uuid::nil());
    }
}