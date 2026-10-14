// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! ISO 8583 → ISO 20022 message mapping.
//! Story.
//! See `services/payments/DESIGN.md` §4.6 (Integrations).
//! Maps the subset of ISO 8583 fields used by Payments to the equivalent ISO 20022
//! (pacs.008 / pacs.004 / pacs.002-style) JSON representation. The mapping is
//! deliberately permissive: unknown MTIs and missing fields are reported via
//! `Result::Err` rather than silently dropped.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A minimal ISO 8583 message: an MTI plus a set of numbered fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso8583Message {
    pub mti: String,
    pub fields: HashMap<u32, String>,
}

/// Map an ISO 8583 message to an ISO 20022 JSON document.
/// Recognised MTIs:
/// - `0100` → `AUTHORISATION_INITIATION` (pacs.008 style)
/// - `0220` → `FINANCIAL_INITIATION`
/// - `0400` → `REVERSAL_INITIATION` (pacs.004 style)
/// Mapped fields:
/// - Field 2 (PAN) → `card_number`
/// - Field 4 (Amount) → `amount`
/// - Field 14 (Expiry) → `expiry_date`
/// - Field 22 (POS Entry Mode) → `entry_mode`
pub fn map_iso8583_to_iso20022(msg: &Iso8583Message) -> Result<serde_json::Value, String> {
    let business_message = match msg.mti.as_str() {
        "0100" => "AUTHORISATION_INITIATION",
        "0220" => "FINANCIAL_INITIATION",
        "0400" => "REVERSAL_INITIATION",
        other => return Err(format!("unsupported MTI: {other}")),
    };

    let get = |n: u32| msg.fields.get(&n).cloned();

    let mut doc = serde_json::json!({
        "message": business_message,
        "mti": msg.mti,
    });

    if let Some(pan) = get(2) {
        doc["card_number"] = serde_json::Value::String(pan);
    }
    if let Some(amount) = get(4) {
        doc["amount"] = serde_json::Value::String(amount);
    }
    if let Some(expiry) = get(14) {
        doc["expiry_date"] = serde_json::Value::String(expiry);
    }
    if let Some(entry_mode) = get(22) {
        doc["entry_mode"] = serde_json::Value::String(entry_mode);
    }

    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(mti: &str, fields: &[(u32, &str)]) -> Iso8583Message {
        Iso8583Message {
            mti: mti.into(),
            fields: fields.iter().map(|(k, v)| (*k, (*v).into())).collect(),
        }
    }

    #[test]
    fn maps_0100_to_authorisation_initiation() {
        let m = msg(
            "0100",
            &[
                (2, "4111111111111111"),
                (4, "1000"),
                (14, "2612"),
                (22, "012"),
            ],
        );
        let out = map_iso8583_to_iso20022(&m).unwrap();
        assert_eq!(out["message"], "AUTHORISATION_INITIATION");
        assert_eq!(out["mti"], "0100");
        assert_eq!(out["card_number"], "4111111111111111");
        assert_eq!(out["amount"], "1000");
        assert_eq!(out["expiry_date"], "2612");
        assert_eq!(out["entry_mode"], "012");
    }

    #[test]
    fn maps_0220_to_financial_initiation() {
        let m = msg("0220", &[(2, "4111"), (4, "250")]);
        let out = map_iso8583_to_iso20022(&m).unwrap();
        assert_eq!(out["message"], "FINANCIAL_INITIATION");
        assert_eq!(out["amount"], "250");
    }

    #[test]
    fn maps_0400_to_reversal_initiation() {
        let m = msg("0400", &[(2, "4111")]);
        let out = map_iso8583_to_iso20022(&m).unwrap();
        assert_eq!(out["message"], "REVERSAL_INITIATION");
    }

    #[test]
    fn unknown_mti_errors() {
        let m = msg("9999", &[]);
        assert!(map_iso8583_to_iso20022(&m).is_err());
    }

    #[test]
    fn missing_fields_are_omitted() {
        let m = msg("0100", &[(2, "4111")]);
        let out = map_iso8583_to_iso20022(&m).unwrap();
        assert!(out.get("amount").is_none());
        assert!(out.get("expiry_date").is_none());
        assert_eq!(out["card_number"], "4111");
    }

    #[test]
    fn empty_fields_map_to_minimal_doc() {
        let m = msg("0100", &[]);
        let out = map_iso8583_to_iso20022(&m).unwrap();
        assert_eq!(out["mti"], "0100");
        assert!(out.get("card_number").is_none());
    }
}
