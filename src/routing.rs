// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Routing - payment instruments and account links CRUD - ,.
//! See `services/payments/DESIGN.md` §4.7.

use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct PaymentInstrumentResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub bank_identifier: String,
    pub instrument_identifier: String,
    pub status: String,
    pub display_name: Option<String>,
    pub routing_information: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePaymentInstrumentRequest {
    pub account_id: Uuid,
    pub bank_identifier: String,
    pub instrument_identifier: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub routing_information: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePaymentInstrumentRequest {
    #[serde(default)]
    pub bank_identifier: Option<String>,
    #[serde(default)]
    pub instrument_identifier: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub routing_information: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountLinkResponse {
    pub id: Uuid,
    pub account_id: Uuid,
    pub payment_instrument_id: Option<Uuid>,
    pub core_account_id: Option<String>,
    pub is_default: bool,
    pub status: String,
    pub display_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAccountLinkRequest {
    pub account_id: Uuid,
    #[serde(default)]
    pub payment_instrument_id: Option<Uuid>,
    #[serde(default)]
    pub core_account_id: Option<String>,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub display_name: Option<String>,
}

// ── Helpers ────────────────────────────────────────────────────────────

pub fn row_to_payment_instrument(row: &sqlx::postgres::PgRow) -> PaymentInstrumentResponse {
    PaymentInstrumentResponse {
        id: row.get("id"),
        account_id: row.get("account_id"),
        bank_identifier: row.get("bank_identifier"),
        instrument_identifier: row.get("instrument_identifier"),
        status: row.get("status"),
        display_name: row.get("display_name"),
        routing_information: row.get("routing_information"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

pub fn row_to_account_link(row: &sqlx::postgres::PgRow) -> AccountLinkResponse {
    AccountLinkResponse {
        id: row.get("id"),
        account_id: row.get("account_id"),
        payment_instrument_id: row.get("payment_instrument_id"),
        core_account_id: row.get("core_account_id"),
        is_default: row.get("is_default"),
        status: row.get("status"),
        display_name: row.get("display_name"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

// ── Routing Information Extraction (Story ) ─────────────────────
// Extracts `bank_identifier` and `instrument_identifier` from an
// instruction's input payload. The extraction logic supports common
// ISO 20022 field names and Payments context keys.

/// Extracted routing information from an instruction input.
#[derive(Debug, Clone, Serialize)]
pub struct RoutingInfo {
    pub bank_identifier: Option<String>,
    pub instrument_identifier: Option<String>,
}

/// Extract routing info from an instruction input JSON payload.
/// Looks for the following fields (in priority order):
/// - `bank_identifier` / `bankIdentifier` / `BIC` / `bic`
/// - `instrument_identifier` / `instrumentIdentifier` / `IBAN` / `iban` / `PAN` / `pan`
pub fn extract_routing_info(input: &serde_json::Value) -> RoutingInfo {
    let bank_identifier = input
        .get("bank_identifier")
        .or_else(|| input.get("bankIdentifier"))
        .or_else(|| input.get("BIC"))
        .or_else(|| input.get("bic"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let instrument_identifier = input
        .get("instrument_identifier")
        .or_else(|| input.get("instrumentIdentifier"))
        .or_else(|| input.get("IBAN"))
        .or_else(|| input.get("iban"))
        .or_else(|| input.get("PAN"))
        .or_else(|| input.get("pan"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Also check nested routing_information object.
    if bank_identifier.is_none() || instrument_identifier.is_none() {
        if let Some(ri) = input
            .get("routing_information")
            .or_else(|| input.get("routingInformation"))
        {
            let bi = ri
                .get("bank_identifier")
                .or_else(|| ri.get("bankIdentifier"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let ii = ri
                .get("instrument_identifier")
                .or_else(|| ri.get("instrumentIdentifier"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return RoutingInfo {
                bank_identifier: bank_identifier.or(bi),
                instrument_identifier: instrument_identifier.or(ii),
            };
        }
    }

    RoutingInfo {
        bank_identifier,
        instrument_identifier,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_routing_info_direct() {
        let input = json!({
            "bank_identifier": "BANKBIC",
            "instrument_identifier": "DE89370400440532013000"
        });
        let ri = extract_routing_info(&input);
        assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));
        assert_eq!(
            ri.instrument_identifier.as_deref(),
            Some("DE89370400440532013000")
        );
    }

    #[test]
    fn test_extract_routing_info_camel_case() {
        let input = json!({
            "bank_identifier" : "BANKBIC",
            "instrument_identifier" : "DE89370400440532013000"
        });
        let ri = extract_routing_info(&input);
        assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));
        assert_eq!(
            ri.instrument_identifier.as_deref(),
            Some("DE89370400440532013000")
        );
    }

    #[test]
    fn test_extract_routing_info_iban_bic() {
        let input = json!({
            "BIC": "BANKBIC",
            "IBAN": "DE89370400440532013000"
        });
        let ri = extract_routing_info(&input);
        assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));
        assert_eq!(
            ri.instrument_identifier.as_deref(),
            Some("DE89370400440532013000")
        );
    }

    #[test]
    fn test_extract_routing_info_nested() {
        let input = json!({
            "routing_information": {
                "bank_identifier": "BANKBIC",
                "instrument_identifier": "DE89370400440532013000"
            }
        });
        let ri = extract_routing_info(&input);
        assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));
        assert_eq!(
            ri.instrument_identifier.as_deref(),
            Some("DE89370400440532013000")
        );
    }

    #[test]
    fn test_extract_routing_info_pan() {
        let input = json!({
            "BIC": "BANKBIC",
            "PAN": "4111111111111111"
        });
        let ri = extract_routing_info(&input);
        assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));
        assert_eq!(
            ri.instrument_identifier.as_deref(),
            Some("4111111111111111")
        );
    }

    #[test]
    fn test_extract_routing_info_missing() {
        let input = json!({"amount": 100.0});
        let ri = extract_routing_info(&input);
        assert!(ri.bank_identifier.is_none());
        assert!(ri.instrument_identifier.is_none());
    }
}
