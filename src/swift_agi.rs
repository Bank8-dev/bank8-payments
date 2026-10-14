// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Swift AGI (Application-to-Gateway Interface) integration.
//! Story.
//! See `services/payments/DESIGN.md` §4.6 (Integrations).
//! The Swift AGI gateway delivers *ReceiveIndication* messages when an
//! inbound FIN or ISO 20022 message arrives. We map each indication to a
//! Payments *instruction input* so that downstream processing (Flow logic
//! execution, ledger posting, …) can proceed uniformly.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A Swift AGI message wrapper.
/// `message_id` is the ISO 20022 `MessageHeader/MessageId` (or FIN MIR);
/// `message_type` is the business message type, e.g. `pacs.008`;
/// `payload` is the raw parsed JSON of the message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftAgiMessage {
    pub message_id: String,
    pub message_type: String,
    pub payload: Value,
}

/// Direction of a Swift AGI `ReceiveIndication`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveDirection {
    Inbound,
    Outbound,
}

impl ReceiveDirection {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "inbound" => Ok(Self::Inbound),
            "outbound" => Ok(Self::Outbound),
            other => Err(format!("unknown receive direction: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// A Swift AGI `ReceiveIndication` — emitted by the gateway whenever a
/// message is received.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveIndication {
    pub direction: ReceiveDirection,
    pub raw_message: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

/// The Payments-internal instruction input produced from a `ReceiveIndication`.
/// This mirrors the shape of `CreateInstructionRequest.input` used by the
/// `POST /v1/instructions` handler: a JSON object with the message type,
/// the parsed payload, and a deterministic idempotency key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInput {
    pub message_type: String,
    pub message_id: String,
    pub idempotency_key: String,
    pub direction: String,
    pub payload: Value,
    pub headers: HashMap<String, String>,
}

/// Map a Swift AGI `ReceiveIndication` to a Payments instruction input.
/// The idempotency key is derived using UUIDv5 over the raw message bytes
/// (via [`crate::idempotency::derive_from_payload`]) so that re-delivered
/// indications collapse to the same instruction.
pub fn map_receive_indication_to_instruction(indication: ReceiveIndication) -> InstructionInput {
    // Parse the raw message as JSON; fall back to a wrapper object if it is
    // not valid JSON (e.g. a FIN message).
    let payload: Value = serde_json::from_str(&indication.raw_message)
        .unwrap_or_else(|_| Value::String(indication.raw_message.clone()));

    // Extract message_id / message_type if present in the payload so that
    // the UUIDv5 derivation matches the canonical scheme-gateway form.
    let message_id = payload
        .get("message_id")
        .or_else(|| payload.get("MessageId"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            indication
                .headers
                .get("message_id")
                .cloned()
                .unwrap_or_default()
        });

    let message_type = payload
        .get("message_type")
        .or_else(|| payload.get("MessageType"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            indication
                .headers
                .get("message_type")
                .cloned()
                .unwrap_or_default()
        });

    let idempotency_key = crate::idempotency::derive_from_payload(&payload).to_string();

    InstructionInput {
        message_type: message_type.clone(),
        message_id: message_id.clone(),
        idempotency_key,
        direction: indication.direction.as_str().to_string(),
        payload,
        headers: indication.headers,
    }
}

/// Map a Swift AGI message to the Payments logic ID that should handle it.
/// Known mappings:
/// - `pacs.008` → `credit_transfer_logic`
/// - `pacs.004` → `payment_return_logic`
/// - `pain.001` → `pain001_initiation_logic`
/// - `camt.054` → `camt054_logic`
///
/// Unknown message types yield an error.
pub fn map_message_to_logic(message: &SwiftAgiMessage) -> Result<String, String> {
    let logic = match message.message_type.as_str() {
        "pacs.008" => "credit_transfer_logic",
        "pacs.004" => "payment_return_logic",
        "pain.001" => "pain001_initiation_logic",
        "camt.054" => "camt054_logic",
        other => return Err(format!("no logic mapping for message type: {other}")),
    };
    Ok(logic.to_string())
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn receive_direction_round_trip() {
        for s in ["inbound", "outbound"] {
            let d = ReceiveDirection::from_str(s).unwrap();
            assert_eq!(d.as_str(), s);
        }
        assert!(ReceiveDirection::from_str("sideways").is_err());
    }

    #[test]
    fn map_indication_to_instruction_json_payload() {
        let payload = json!({
            "message_id": "MSG-123",
            "message_type": "pacs.008",
            "amount": 100.0,
        });
        let mut headers = HashMap::new();
        headers.insert("x-swift-agi".to_string(), "v1".to_string());
        let indication = ReceiveIndication {
            direction: ReceiveDirection::Inbound,
            raw_message: payload.to_string(),
            headers,
        };
        let instruction = map_receive_indication_to_instruction(indication);
        assert_eq!(instruction.message_id, "MSG-123");
        assert_eq!(instruction.message_type, "pacs.008");
        assert_eq!(instruction.direction, "inbound");
        assert_eq!(instruction.headers.get("x-swift-agi").unwrap(), "v1");
        // idempotency key is a valid UUID
        assert!(uuid::Uuid::parse_str(&instruction.idempotency_key).is_ok());
    }

    #[test]
    fn map_indication_is_deterministic() {
        let payload = json!({
            "message_id": "MSG-456",
            "message_type": "pacs.008",
        });
        let raw = payload.to_string();
        let a = map_receive_indication_to_instruction(ReceiveIndication {
            direction: ReceiveDirection::Inbound,
            raw_message: raw.clone(),
            headers: HashMap::new(),
        });
        let b = map_receive_indication_to_instruction(ReceiveIndication {
            direction: ReceiveDirection::Inbound,
            raw_message: raw,
            headers: HashMap::new(),
        });
        assert_eq!(a.idempotency_key, b.idempotency_key);
    }

    #[test]
    fn map_indication_falls_back_for_non_json_raw() {
        let indication = ReceiveIndication {
            direction: ReceiveDirection::Outbound,
            raw_message: "FIN: not json".into(),
            headers: HashMap::new(),
        };
        let instruction = map_receive_indication_to_instruction(indication);
        // payload becomes a string; idempotency key still derivable
        assert!(uuid::Uuid::parse_str(&instruction.idempotency_key).is_ok());
        assert_eq!(instruction.direction, "outbound");
    }

    #[test]
    fn map_indication_uses_headers_when_payload_missing_fields() {
        let payload = json!({ "amount": 100.0 });
        let mut headers = HashMap::new();
        headers.insert("message_id".to_string(), "MSG-H".to_string());
        headers.insert("message_type".to_string(), "pacs.008".to_string());
        let indication = ReceiveIndication {
            direction: ReceiveDirection::Inbound,
            raw_message: payload.to_string(),
            headers,
        };
        let instruction = map_receive_indication_to_instruction(indication);
        assert_eq!(instruction.message_id, "MSG-H");
        assert_eq!(instruction.message_type, "pacs.008");
    }

    #[test]
    fn map_message_to_logic_known() {
        for (ty, expected) in [
            ("pacs.008", "credit_transfer_logic"),
            ("pacs.004", "payment_return_logic"),
            ("pain.001", "pain001_initiation_logic"),
            ("camt.054", "camt054_logic"),
        ] {
            let msg = SwiftAgiMessage {
                message_id: "M".into(),
                message_type: ty.into(),
                payload: json!({}),
            };
            assert_eq!(map_message_to_logic(&msg).unwrap(), expected);
        }
    }

    #[test]
    fn map_message_to_logic_unknown_errors() {
        let msg = SwiftAgiMessage {
            message_id: "M".into(),
            message_type: "unknown.type".into(),
            payload: json!({}),
        };
        assert!(map_message_to_logic(&msg).is_err());
    }
}
