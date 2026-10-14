// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Idempotency via UUIDv5 — Story.
//! Scheme gateway messages use UUIDv5-based idempotency keys derived from
//! a deterministic namespace + the message content. This ensures that
//! re-delivered messages produce the same idempotency key and are deduplicated.
//! See `services/payments/DESIGN.md` §4.20.
//! UUIDv5(namespace, name) = UUIDv5(SHA1(namespace_bytes || name_bytes))

use uuid::Uuid;

/// The canonical namespace UUID for Payments scheme gateway messages.
/// Generated once and fixed — this ensures reproducibility across restarts.
pub const BANK8_PAYMENTS_SCHEME_NAMESPACE: Uuid = Uuid::from_bytes([
    0x8a, 0x4b, 0x2c, 0x1e, 0xf7, 0x93, 0x4e, 0xa1, 0x9b, 0x6d, 0xc0, 0x4f, 0x3a, 0x82, 0x5e, 0x11,
]);

/// Derive a UUIDv5 idempotency key from a scheme gateway message.
/// The `name` is typically a concatenation of:
/// - message_id (from the ISO 20022 message header)
/// - message_type (e.g., pacs.008)
/// - sender BIC
/// - creation timestamp (message-level, not delivery-level)
///
/// This ensures that the same logical message always produces the same
/// idempotency key, regardless of how many times it is delivered.
pub fn derive_idempotency_key(name: &str) -> Uuid {
    Uuid::new_v5(&BANK8_PAYMENTS_SCHEME_NAMESPACE, name.as_bytes())
}

/// Derive a UUIDv5 idempotency key from structured message fields.
/// Convenience for the common case of message_id + message_type.
pub fn derive_from_message(message_id: &str, message_type: &str) -> Uuid {
    derive_idempotency_key(&format!("{message_type}:{message_id}"))
}

/// Derive a UUIDv5 idempotency key from a raw ISO 20022 JSON payload.
/// Extracts `message_id` and `message_type` from the payload and derives
/// the key. Falls back to the entire serialized payload if fields are
/// missing.
pub fn derive_from_payload(payload: &serde_json::Value) -> Uuid {
    let msg_id = payload
        .get("message_id")
        .or_else(|| payload.get("MessageId"))
        .and_then(|v| v.as_str());
    let msg_type = payload
        .get("message_type")
        .or_else(|| payload.get("MessageType"))
        .and_then(|v| v.as_str());

    match (msg_id, msg_type) {
        (Some(id), Some(ty)) => derive_from_message(id, ty),
        _ => {
            // Fall back to a hash of the entire payload.
            derive_idempotency_key(&payload.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_derive_idempotency_key_deterministic() {
        let key1 = derive_idempotency_key("pacs.008:MSG-12345");
        let key2 = derive_idempotency_key("pacs.008:MSG-12345");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_inputs_different_keys() {
        let key1 = derive_idempotency_key("pacs.008:MSG-12345");
        let key2 = derive_idempotency_key("pacs.008:MSG-67890");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_from_message() {
        let key = derive_from_message("MSG-001", "pain.001");
        assert_eq!(key, derive_from_message("MSG-001", "pain.001"));
        assert_ne!(key, derive_from_message("MSG-002", "pain.001"));
    }

    #[test]
    fn test_derive_from_payload_with_fields() {
        let payload = json!({
            "message_id": "MSG-123",
            "message_type": "pacs.008",
            "amount": 100.0,
        });
        let key = derive_from_payload(&payload);
        // Same fields → same key.
        let payload2 = json!({
            "message_id": "MSG-123",
            "message_type": "pacs.008",
            "amount": 200.0,
        });
        assert_eq!(key, derive_from_payload(&payload2));
    }

    #[test]
    fn test_derive_from_payload_fallback() {
        let payload = json!({ "foo": "bar" });
        let key = derive_from_payload(&payload);
        assert_eq!(key, derive_from_payload(&payload));
        let payload2 = json!({ "foo": "baz" });
        assert_ne!(key, derive_from_payload(&payload2));
    }

    #[test]
    fn test_namespace_is_uuid() {
        // The namespace must be a valid UUID.
        let _ = BANK8_PAYMENTS_SCHEME_NAMESPACE.as_simple();
    }
}
