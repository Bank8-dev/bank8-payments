// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Bus event streaming - domain events emitted when Payments resources change.
//! .135, (publisher identity token),
//! (outbox-first emission).
//! See `services/payments/DESIGN.md` and
//! `sentin8/design/sentin8-sentin8-bus-technical-design.md`.
//! Provides:
//! - `EventPayload` - the canonical Payments event payload
//! - `ResourceType` - all Payments resources that emit events
//! - `emit_event_tx` - insert an event into the LOCAL `payments.outbox`
//! table **on the same transaction/connection as the domain change**
//! (outbox-first, atomic) carrying the publisher identity token
//! - `emit_event` - same insert via the pool helper (system-context events
//! only - e.g. internal proxy-back with no auth context)
//! - `consumer_group_name` - derive a Bus consumer group name from tenant + group
//! - `validate_sentin8_bus_jwt` - stub JWT validation for Bus OAuth 2.0 consumers

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── ResourceType ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    AccountLink,
    Card,
    Cardholder,
    CardOrder,
    Core,
    CoreVersion,
    File,
    Integration,
    IntegrationVersion,
    Instruction,
    InstructionFile,
    InstructionLogic,
    ManualDecision,
    MembershipDirectory,
    Parameter,
    Payment,
    PaymentInstrument,
    Rule,
    RuleSet,
    RuleSetVersion,
    RuleVersion,
    ThreeDSRecord,
    Template,
    TemplateVersion,
}

impl ResourceType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "account_link" => Ok(Self::AccountLink),
            "card" => Ok(Self::Card),
            "cardholder" => Ok(Self::Cardholder),
            "card_order" => Ok(Self::CardOrder),
            "core" => Ok(Self::Core),
            "core_version" => Ok(Self::CoreVersion),
            "file" => Ok(Self::File),
            "integration" => Ok(Self::Integration),
            "integration_version" => Ok(Self::IntegrationVersion),
            "instruction" => Ok(Self::Instruction),
            "instruction_file" => Ok(Self::InstructionFile),
            "instruction_logic" => Ok(Self::InstructionLogic),
            "manual_decision" => Ok(Self::ManualDecision),
            "membership_directory" => Ok(Self::MembershipDirectory),
            "parameter" => Ok(Self::Parameter),
            "payment" => Ok(Self::Payment),
            "payment_instrument" => Ok(Self::PaymentInstrument),
            "rule" => Ok(Self::Rule),
            "rule_set" => Ok(Self::RuleSet),
            "rule_set_version" => Ok(Self::RuleSetVersion),
            "rule_version" => Ok(Self::RuleVersion),
            "three_ds_record" => Ok(Self::ThreeDSRecord),
            "template" => Ok(Self::Template),
            "template_version" => Ok(Self::TemplateVersion),
            other => Err(format!("unknown resource type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountLink => "account_link",
            Self::Card => "card",
            Self::Cardholder => "cardholder",
            Self::CardOrder => "card_order",
            Self::Core => "core",
            Self::CoreVersion => "core_version",
            Self::File => "file",
            Self::Integration => "integration",
            Self::IntegrationVersion => "integration_version",
            Self::Instruction => "instruction",
            Self::InstructionFile => "instruction_file",
            Self::InstructionLogic => "instruction_logic",
            Self::ManualDecision => "manual_decision",
            Self::MembershipDirectory => "membership_directory",
            Self::Parameter => "parameter",
            Self::Payment => "payment",
            Self::PaymentInstrument => "payment_instrument",
            Self::Rule => "rule",
            Self::RuleSet => "rule_set",
            Self::RuleSetVersion => "rule_set_version",
            Self::RuleVersion => "rule_version",
            Self::ThreeDSRecord => "three_ds_record",
            Self::Template => "template",
            Self::TemplateVersion => "template_version",
        }
    }
}

// ── EventPayload ───────────────────────────────────────────────────────

/// The canonical Payments event payload, produced to Bus by the
/// shell's outbox relay (drained from the local `payments.outbox`
/// table - DBX §6.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventPayload {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub change_id: String,
    pub resource_id: String,
    pub resource_type: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub update_mask: Vec<String>,
}

// ── Emit ───────────────────────────────────────────────────────────────

/// Stream family for Payments events. Must match the family the
/// payments-worker consumes (WorkerConfig default) and the Bus stream the
/// shell's outbox relay produces into.
pub const STREAM_FAMILY: &str = "payments";

/// Publisher identity carried on an inbox row.
#[derive(Debug, Clone, Default)]
pub struct PublisherIdentity {
    /// The caller's bearer token (compact serialization) - the JWT that
    /// authenticated the request which triggered the event.
    pub id_token: Option<String>,
    /// The `sub` claim extracted from that token.
    pub subject: Option<String>,
}

impl PublisherIdentity {
    pub fn from_parts(id_token: Option<String>, subject: Option<String>) -> Self {
        Self { id_token, subject }
    }

    pub fn none() -> Self {
        Self::default()
    }
}

/// Build the event payload + event_type for a resource change.
pub fn build_payload(
    resource_type: ResourceType,
    resource_id: &str,
    operation: &str,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) -> Result<(Uuid, String, serde_json::Value), String> {
    let event_id = Uuid::new_v4();
    let timestamp = Utc::now();
    let update_mask = compute_update_mask(&before, &after);

    let payload = EventPayload {
        event_id,
        timestamp,
        change_id: event_id.to_string(),
        resource_id: resource_id.to_string(),
        resource_type: resource_type.as_str().to_string(),
        operation: operation.to_string(),
        before,
        after,
        update_mask,
    };

    let payload_json =
        serde_json::to_value(&payload).map_err(|e| format!("serialise event payload: {e}"))?;
    let event_type = format!("bank8:payments:{}:{}", resource_type.as_str(), operation);
    Ok((event_id, event_type, payload_json))
}

/// Insert the outbox row on an **existing** transaction/connection.
/// This is the outbox-first path (DBX §6.7): the caller passes the same
/// transaction that performs the domain change, so the event is committed
/// atomically with it - a crash between commit and produce cannot lose the
/// event. The shell's post-commit relay pushes the row to Bus
/// `POST /v1/produce` (idempotency_key = row id). The tenant context must
/// already be set on this connection.
pub async fn emit_event_tx<'e, E>(
    conn: E,
    env_id: Uuid,
    resource_type: ResourceType,
    resource_id: &str,
    operation: &str,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
    publisher: PublisherIdentity,
) -> Result<(), String>
where
    E: sqlx::PgExecutor<'e> + Send,
{
    let (_, event_type, payload_json) =
        build_payload(resource_type, resource_id, operation, before, after)?;

    sentin8::bus::outbox::insert_outbox_row_with_publisher(
        conn,
        env_id,
        STREAM_FAMILY,
        &event_type,
        &payload_json,
        publisher.id_token.as_deref(),
        publisher.subject.as_deref(),
    )
    .await
    .map_err(|e| format!("insert outbox event: {e}"))?;

    Ok(())
}

/// Insert an event into the LOCAL `payments.outbox` table on a fresh
/// connection. Only for system-scoped operations with no in-flight
/// transaction (e.g. internal proxy-back with no auth context); handlers
/// performing a domain change MUST use `emit_event_tx` instead.
/// `env_id` - tenant context. Use `Uuid::nil ` for system context.
pub async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    resource_type: ResourceType,
    resource_id: &str,
    operation: &str,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) -> Result<(), String> {
    let (_, event_type, payload_json) =
        build_payload(resource_type, resource_id, operation, before, after)?;

    // The pool helper acquires a connection and sets the RLS tenant
    // context on it before the INSERT (the outbox is FORCE-RLS'd).
    sentin8::bus::outbox::insert_outbox_row_pool(
        pool,
        env_id,
        STREAM_FAMILY,
        &event_type,
        &payload_json,
    )
    .await
    .map_err(|e| format!("insert outbox event: {e}"))?;

    Ok(())
}

/// Compute the list of top-level field names that differ between `before`
/// and `after`. Used to populate `update_mask` for `updated` operations.
fn compute_update_mask(
    before: &Option<serde_json::Value>,
    after: &Option<serde_json::Value>,
) -> Vec<String> {
    let (Some(b), Some(a)) = (before.as_ref(), after.as_ref()) else {
        return Vec::new();
    };
    let (Some(b_obj), Some(a_obj)) = (b.as_object(), a.as_object()) else {
        return Vec::new();
    };
    let mut mask = Vec::new();
    for (key, a_val) in a_obj {
        match b_obj.get(key) {
            Some(b_val) if b_val == a_val => {}
            _ => mask.push(key.clone()),
        }
    }
    for key in b_obj.keys() {
        if !a_obj.contains_key(key) {
            mask.push(key.clone());
        }
    }
    mask
}

/// Derive a Bus consumer group name from a tenant ID and a group name.
/// Story . The format is `${tenant_id}.${group}`.
pub fn consumer_group_name(tenant_id: &str, group: &str) -> String {
    format!("{tenant_id}.{group}")
}

/// Validate a Bus JWT token (stub).
/// Story . In production this would verify the token signature
/// against the Bus OAuth 2.0 JWKS and check the required scopes.
pub fn validate_sentin8_bus_jwt(token: &str) -> Result<(), String> {
    if token.trim().is_empty() {
        return Err("missing Bus JWT".into());
    }
    if !token.contains('.') {
        return Err("invalid JWT format".into());
    }
    // Stub: in production, verify signature + claims against Bus JWKS.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resource_type_round_trip() {
        for t in [
            ResourceType::AccountLink,
            ResourceType::Card,
            ResourceType::Cardholder,
            ResourceType::CardOrder,
            ResourceType::Core,
            ResourceType::CoreVersion,
            ResourceType::File,
            ResourceType::Integration,
            ResourceType::IntegrationVersion,
            ResourceType::Instruction,
            ResourceType::InstructionFile,
            ResourceType::InstructionLogic,
            ResourceType::ManualDecision,
            ResourceType::MembershipDirectory,
            ResourceType::Parameter,
            ResourceType::Payment,
            ResourceType::PaymentInstrument,
            ResourceType::Rule,
            ResourceType::RuleSet,
            ResourceType::RuleSetVersion,
            ResourceType::RuleVersion,
            ResourceType::ThreeDSRecord,
            ResourceType::Template,
            ResourceType::TemplateVersion,
        ] {
            assert_eq!(ResourceType::from_str(t.as_str()).unwrap(), t);
        }
        assert!(ResourceType::from_str("bogus").is_err());
    }

    #[test]
    fn consumer_group_name_formats_correctly() {
        assert_eq!(
            consumer_group_name("org_123", "payments-consumer"),
            "org_123.payments-consumer"
        );
    }

    #[test]
    fn event_payload_serialises_round_trip() {
        let payload = EventPayload {
            event_id: Uuid::new_v4(),
            timestamp: DateTime::parse_from_rfc3339("2026-07-18T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            change_id: "change-1".into(),
            resource_id: "res-1".into(),
            resource_type: "instruction".into(),
            operation: "created".into(),
            before: None,
            after: Some(json!({ "id": "res-1", "state": "pending" })),
            update_mask: vec![],
        };
        let s = serde_json::to_string(&payload).unwrap();
        let parsed: EventPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.event_id, payload.event_id);
        assert_eq!(parsed.operation, "created");
        assert!(parsed.before.is_none());
        assert!(parsed.after.is_some());
        // `update_mask` is empty → skipped during serialisation.
        assert!(parsed.update_mask.is_empty());
    }

    #[test]
    fn event_payload_includes_update_mask_when_present() {
        let payload = EventPayload {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            change_id: "change-2".into(),
            resource_id: "res-2".into(),
            resource_type: "payment".into(),
            operation: "updated".into(),
            before: Some(json!({ "status": "pending" })),
            after: Some(json!({ "status": "completed" })),
            update_mask: vec!["status".into()],
        };
        let v = serde_json::to_value(&payload).unwrap();
        assert_eq!(v["update_mask"], json!(["status"]));
    }

    #[test]
    fn compute_update_mask_detects_changed_fields() {
        let before = json!({ "a": 1, "b": 2, "c": 3 });
        let after = json!({ "a": 1, "b": 99 });
        let mask = compute_update_mask(&Some(before), &Some(after));
        assert!(mask.contains(&"b".to_string()));
        assert!(mask.contains(&"c".to_string()));
        assert!(!mask.contains(&"a".to_string()));
    }

    #[test]
    fn compute_update_mask_returns_empty_without_both_snapshots() {
        assert!(compute_update_mask(&None, &Some(json!({}))).is_empty());
        assert!(compute_update_mask(&Some(json!({})), &None).is_empty());
    }

    #[test]
    fn validate_sentin8_bus_jwt_rejects_empty_token() {
        assert!(validate_sentin8_bus_jwt("").is_err());
        assert!(validate_sentin8_bus_jwt("   ").is_err());
    }

    #[test]
    fn validate_sentin8_bus_jwt_rejects_non_jwt_string() {
        assert!(validate_sentin8_bus_jwt("not-a-jwt").is_err());
    }

    #[test]
    fn validate_sentin8_bus_jwt_accepts_dotted_token_stub() {
        // Stub only checks for presence of dots.
        assert!(validate_sentin8_bus_jwt("header.payload.signature").is_ok());
    }

    #[test]
    fn stream_family_matches_bus_role_derivation() {
        // `sentin8_bus_current_stream_family ` maps the `bank8_payments_service`
        // PostgreSQL role to `payments` (strip the vertical prefix). The
        // producer constant and the worker default must match - a mismatch
        // fails the inbox RLS INSERT policy / starves the worker.
        assert_eq!(STREAM_FAMILY, "payments");
    }

    #[test]
    fn build_payload_uses_colon_event_names() {
        let (_, event_type, payload) =
            build_payload(ResourceType::Instruction, "abc", "created", None, None).unwrap();
        assert_eq!(event_type, "bank8:payments:instruction:created");
        assert_eq!(payload["resource_type"], "instruction");
        assert_eq!(payload["operation"], "created");
        assert_eq!(payload["resource_id"], "abc");
        assert!(payload["change_id"].is_string());
    }

    #[test]
    fn publisher_identity_defaults_to_none() {
        let p = PublisherIdentity::none();
        assert!(p.id_token.is_none());
        assert!(p.subject.is_none());
        let p2 = PublisherIdentity::from_parts(Some("tok".into()), Some("sub".into()));
        assert_eq!(p2.id_token.as_deref(), Some("tok"));
        assert_eq!(p2.subject.as_deref(), Some("sub"));
    }
}
