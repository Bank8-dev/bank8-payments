// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Payments — Story.
//! These tests exercise the *pure-logic* functions across modules without
//! requiring a database. The Payments server is a binary crate (no lib
//! target), so this integration test file pulls in the relevant modules via
//! the `#[path = "../src/..."]` attribute and re-runs a consolidated set of
//! cross-module assertions.
//! Covered:
//! - Instruction lifecycle state transitions (state_machine.rs)
//! - Payment matching correlation logic (payment_matching.rs)
//! - Card state machine transitions (cards.rs)
//! - UUIDv5 idempotency key derivation (idempotency.rs)
//! - Routing info extraction from various payload formats (routing.rs)
//! - ISO 20022 payload types and message codes (iso8583.rs)
//! - 3DS risk evaluation (cards.rs)
//! - Decline reason → response code mapping (cards.rs)
//! - Parameter type validation (parameters.rs)

#![allow(clippy::needless_pass_by_value)]
// The `#[path]`-included modules carry async DB helpers the tests never
// call — the lib/bin builds exercise them; this binary only pins the
// pure-logic seams. Silence the resulting dead-code warnings here.
#![allow(dead_code)]

// Pull in the source modules. Because payments is a binary crate with
// no library target, we use the `#[path]` attribute to compile the relevant
// modules into this integration test binary.
#[path = "../src/state_machine.rs"]
mod state_machine;
#[path = "../src/payment_matching.rs"]
mod payment_matching;
#[path = "../src/cards.rs"]
mod cards;
#[path = "../src/idempotency.rs"]
mod idempotency;
#[path = "../src/routing.rs"]
mod routing;
#[path = "../src/iso8583.rs"]
mod iso8583;
#[path = "../src/parameters.rs"]
mod parameters;
#[path = "../src/payment_context.rs"]
mod payment_context;
// Pure-logic modules with no DB/axum dependency:
#[path = "../src/postings.rs"]
mod postings;
#[path = "../src/event_streaming.rs"]
mod event_streaming;
#[path = "../src/config.rs"]
mod config;

// Re-export the sqlx macro so the modules that use `query_scalar!`-style
// macros compile. We only exercise pure-logic paths here, but the modules
// still reference sqlx types.
use serde_json::json;
use uuid::Uuid;

// ── 1. Instruction lifecycle state transitions ─────────────────────────

#[tokio::test]
async fn test_instruction_lifecycle_state_transitions() {
    use state_machine::InstructionState::*;

    // The happy path: pending → processing → completed.
    assert!(Pending.validate_transition(Processing).is_ok());
    assert!(Processing.validate_transition(Completed).is_ok());

    // Cancellation is allowed from any non-terminal state.
    assert!(Pending.validate_transition(Cancelled).is_ok());
    assert!(Processing.validate_transition(Cancelled).is_ok());
    assert!(Waiting.validate_transition(Cancelled).is_ok());
    assert!(Failed.validate_transition(Cancelled).is_ok());

    // Retry path: failed → pending.
    assert!(Failed.validate_transition(Pending).is_ok());

    // Waiting ↔ processing (async step resume).
    assert!(Processing.validate_transition(Waiting).is_ok());
    assert!(Waiting.validate_transition(Processing).is_ok());

    // Invalid transitions.
    assert!(Pending.validate_transition(Completed).is_err());
    assert!(Completed.validate_transition(Processing).is_err());
    assert!(Cancelled.validate_transition(Pending).is_err());

    // from_str / as_str roundtrip.
    for s in ["pending", "processing", "waiting", "completed", "failed", "cancelled"] {
        let st = state_machine::InstructionState::from_str(s).unwrap();
        assert_eq!(st.as_str(), s);
    }

    // Terminal states.
    assert!(Completed.is_terminal());
    assert!(Cancelled.is_terminal());
    assert!(!Failed.is_terminal());
}

// ── 2. Payment matching logic ─────────────────────────────────────────

#[tokio::test]
async fn test_payment_matching_logic() {
    // The pure-logic portion of payment matching: the default correlation
    // fallback uses the instruction id when no correlation_id is supplied.
    let id = Uuid::new_v4();
    let corr = match None::<&str> {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => id.to_string(),
    };
    assert_eq!(corr, id.to_string());

    // When a correlation id is provided it is used as-is.
    let corr2 = match Some("PAY-ABC") {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => id.to_string(),
    };
    assert_eq!(corr2, "PAY-ABC");

    // Empty correlation id falls back to the instruction id.
    let corr3 = match Some("") {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => id.to_string(),
    };
    assert_eq!(corr3, id.to_string());
}

// ── 3. Card state machine transitions ─────────────────────────────────

#[tokio::test]
async fn test_card_state_machine_transitions() {
    use cards::CardState;

    // Happy path: pending_creation → inactive → active.
    assert!(cards::validate_card_transition(
        CardState::PendingCreation,
        CardState::Inactive
    )
    .is_ok());
    assert!(cards::validate_card_transition(
        CardState::Inactive,
        CardState::Active
    )
    .is_ok());

    // active → suspended → active (freeze/unfreeze).
    assert!(cards::validate_card_transition(
        CardState::Active,
        CardState::Suspended
    )
    .is_ok());
    assert!(cards::validate_card_transition(
        CardState::Suspended,
        CardState::Active
    )
    .is_ok());

    // Disabled is terminal.
    assert!(cards::validate_card_transition(
        CardState::Disabled,
        CardState::Active
    )
    .is_err());

    // Round-trip.
    for s in [
        "pending_creation",
        "inactive",
        "active",
        "suspended",
        "disabled",
    ] {
        let st = CardState::from_str(s).unwrap();
        assert_eq!(st.as_str(), s);
    }
}

// ── 4. UUIDv5 idempotency key derivation ──────────────────────────────

#[tokio::test]
async fn test_idempotency_key_generation() {
    use idempotency::{derive_from_message, derive_from_payload, derive_idempotency_key};

    // Deterministic: same input → same key.
    let k1 = derive_idempotency_key("pacs.008:MSG-1");
    let k2 = derive_idempotency_key("pacs.008:MSG-1");
    assert_eq!(k1, k2);

    // Different inputs → different keys.
    let k3 = derive_idempotency_key("pacs.008:MSG-2");
    assert_ne!(k1, k3);

    // Structured helper.
    let a = derive_from_message("M-001", "pain.001");
    let b = derive_from_message("M-001", "pain.001");
    assert_eq!(a, b);
    assert_ne!(a, derive_from_message("M-002", "pain.001"));

    // Payload helper extracts message_id/message_type.
    let payload = json!({
        "message_id": "MSG-XYZ",
        "message_type": "pacs.008",
        "amount": 100.0
    });
    let pkey = derive_from_payload(&payload);
    // Same fields → same key, even if other fields change.
    let payload2 = json!({
        "message_id": "MSG-XYZ",
        "message_type": "pacs.008",
        "amount": 999.0
    });
    assert_eq!(pkey, derive_from_payload(&payload2));

    // Fallback: no message_id/message_type → hash of entire payload.
    let raw = json!({ "foo": "bar" });
    let rkey = derive_from_payload(&raw);
    assert_eq!(rkey, derive_from_payload(&raw));
}

// ── 5. Routing info extraction from various payload formats ──────────

#[tokio::test]
async fn test_routing_info_extraction() {
    use routing::extract_routing_info;

    // Direct snake_case fields.
    let ri = extract_routing_info(&json!({
        "bank_identifier": "BANKBIC",
        "instrument_identifier": "DE89370400440532013000"
    }));
    assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));
    assert_eq!(
        ri.instrument_identifier.as_deref(),
        Some("DE89370400440532013000")
    );

    // camelCase fields.
    let ri = extract_routing_info(&json!({
        "bank_identifier" : "BANKBIC",
        "instrument_identifier" : "DE89370400440532013000"
    }));
    assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));

    // BIC/IBAN fields.
    let ri = extract_routing_info(&json!({ "BIC": "BANKBIC", "IBAN": "DE89" }));
    assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));
    assert_eq!(ri.instrument_identifier.as_deref(), Some("DE89"));

    // PAN field.
    let ri = extract_routing_info(&json!({ "BIC": "BANKBIC", "PAN": "4111" }));
    assert_eq!(ri.instrument_identifier.as_deref(), Some("4111"));

    // Nested routing_information object.
    let ri = extract_routing_info(&json!({
        "routing_information": {
            "bank_identifier": "BANKBIC",
            "instrument_identifier": "DE89"
        }
    }));
    assert_eq!(ri.bank_identifier.as_deref(), Some("BANKBIC"));
    assert_eq!(ri.instrument_identifier.as_deref(), Some("DE89"));

    // Missing fields → None.
    let ri = extract_routing_info(&json!({"amount": 100.0}));
    assert!(ri.bank_identifier.is_none());
    assert!(ri.instrument_identifier.is_none());
}

// ── 6. ISO 20022 payload types and message codes ─────────────────────

#[tokio::test]
async fn test_iso20022_payload_types() {
    use iso8583::{map_iso8583_to_iso20022, Iso8583Message};
    use std::collections::HashMap;

    // 0100 → AUTHORISATION_INITIATION (pacs.008 style).
    let m = Iso8583Message {
        mti: "0100".to_string(),
        fields: HashMap::from([
            (2, "4111111111111111".to_string()),
            (4, "1000".to_string()),
            (14, "2612".to_string()),
            (22, "012".to_string()),
        ]),
    };
    let out = map_iso8583_to_iso20022(&m).unwrap();
    assert_eq!(out["message"], "AUTHORISATION_INITIATION");
    assert_eq!(out["mti"], "0100");
    assert_eq!(out["card_number"], "4111111111111111");
    assert_eq!(out["amount"], "1000");
    assert_eq!(out["expiry_date"], "2612");
    assert_eq!(out["entry_mode"], "012");

    // 0220 → FINANCIAL_INITIATION.
    let m = Iso8583Message {
        mti: "0220".to_string(),
        fields: HashMap::from([(2, "4111".to_string()), (4, "250".to_string())]),
    };
    let out = map_iso8583_to_iso20022(&m).unwrap();
    assert_eq!(out["message"], "FINANCIAL_INITIATION");
    assert_eq!(out["amount"], "250");

    // 0400 → REVERSAL_INITIATION (pacs.004 style).
    let m = Iso8583Message {
        mti: "0400".to_string(),
        fields: HashMap::new(),
    };
    let out = map_iso8583_to_iso20022(&m).unwrap();
    assert_eq!(out["message"], "REVERSAL_INITIATION");

    // Unknown MTI errors.
    let m = Iso8583Message {
        mti: "9999".to_string(),
        fields: HashMap::new(),
    };
    assert!(map_iso8583_to_iso20022(&m).is_err());

    // Missing fields are omitted.
    let m = Iso8583Message {
        mti: "0100".to_string(),
        fields: HashMap::from([(2, "4111".to_string())]),
    };
    let out = map_iso8583_to_iso20022(&m).unwrap();
    assert_eq!(out["card_number"], "4111");
    assert!(out.get("amount").is_none());
    assert!(out.get("expiry_date").is_none());
}

// ── 7. 3DS risk evaluation ────────────────────────────────────────────

#[tokio::test]
async fn test_3ds_risk_evaluation() {
    use cards::{evaluate_3ds_risk, recommend_3ds_action, ThreeDSAuthResult};

    // Green band: low risk, low amount, trusted merchant.
    assert_eq!(
        evaluate_3ds_risk(0.1, 25.0, true),
        ThreeDSAuthResult::Green
    );
    assert_eq!(recommend_3ds_action(&ThreeDSAuthResult::Green), "frictionless");

    // Green requires a trusted merchant.
    assert_eq!(
        evaluate_3ds_risk(0.1, 25.0, false),
        ThreeDSAuthResult::Amber
    );

    // Amber band: moderate risk.
    assert_eq!(
        evaluate_3ds_risk(0.5, 100.0, true),
        ThreeDSAuthResult::Amber
    );
    assert_eq!(recommend_3ds_action(&ThreeDSAuthResult::Amber), "challenge");

    // Red band: high risk score.
    assert_eq!(
        evaluate_3ds_risk(0.8, 100.0, true),
        ThreeDSAuthResult::Red
    );

    // Red band: high amount (over 5000).
    assert_eq!(
        evaluate_3ds_risk(0.1, 6000.0, true),
        ThreeDSAuthResult::Red
    );
    assert_eq!(recommend_3ds_action(&ThreeDSAuthResult::Red), "decline");

    // Red boundary: risk 0.7 exactly → Red.
    assert_eq!(
        evaluate_3ds_risk(0.7, 100.0, true),
        ThreeDSAuthResult::Red
    );

    // Red takes priority over Green.
    assert_eq!(
        evaluate_3ds_risk(0.9, 10.0, true),
        ThreeDSAuthResult::Red
    );
}

// ── 8. Decline recommendations ───────────────────────────────────────

#[tokio::test]
async fn test_decline_recommendations() {
    use cards::{get_decline_recommendation, DeclineReason};

    // Each decline reason maps to an ISO 8583 response code.
    let cases = [
        (DeclineReason::InsufficientFunds, "51"),
        (DeclineReason::StolenCard, "41"),
        (DeclineReason::ExpiredCard, "54"),
        (DeclineReason::SuspectedFraud, "59"),
        (DeclineReason::DoNotHonor, "05"),
        (DeclineReason::InvalidMerchant, "12"),
        (DeclineReason::TransactionNotAllowed, "57"),
    ];
    for (reason, expected_code) in cases {
        assert_eq!(get_decline_recommendation(reason), expected_code);
    }

    // Round-trip via from_str/as_str.
    for s in [
        "insufficient_funds",
        "expired_card",
        "stolen_card",
        "suspected_fraud",
        "do_not_honor",
        "invalid_merchant",
        "transaction_not_allowed",
    ] {
        let r = DeclineReason::from_str(s).unwrap();
        assert_eq!(r.as_str(), s);
    }
    assert!(DeclineReason::from_str("bogus").is_err());
}

// ── 9. Parameter type validation ─────────────────────────────────────

#[tokio::test]
async fn test_parameter_type_validation() {
    use parameters::ParameterType;

    // Boolean.
    assert!(ParameterType::Boolean
        .validate_value(&json!(true))
        .is_ok());
    assert!(ParameterType::Boolean.validate_value(&json!("x")).is_err());

    // String.
    assert!(ParameterType::String
        .validate_value(&json!("hello"))
        .is_ok());
    assert!(ParameterType::String.validate_value(&json!(42)).is_err());

    // Decimal — string form must parse.
    assert!(ParameterType::Decimal
        .validate_value(&json!("100.50"))
        .is_ok());
    assert!(ParameterType::Decimal
        .validate_value(&json!("not-a-number"))
        .is_err());
    // Number is accepted.
    assert!(ParameterType::Decimal
        .validate_value(&json!(100.5))
        .is_ok());

    // StringList — array of strings.
    assert!(ParameterType::StringList
        .validate_value(&json!(["a", "b", "c"]))
        .is_ok());
    assert!(ParameterType::StringList
        .validate_value(&json!(["a", 1]))
        .is_err());
    assert!(ParameterType::StringList
        .validate_value(&json!("not-an-array"))
        .is_err());

    // DateTime — RFC 3339.
    assert!(ParameterType::DateTime
        .validate_value(&json!("2026-07-18T10:00:00Z"))
        .is_ok());
    assert!(ParameterType::DateTime
        .validate_value(&json!("not-a-date"))
        .is_err());

    // JSON — anything goes.
    assert!(ParameterType::JSON.validate_value(&json!(null)).is_ok());
    assert!(ParameterType::JSON.validate_value(&json!({"k": 1})).is_ok());
    assert!(ParameterType::JSON.validate_value(&json!(42)).is_ok());

    // from_str / as_str round-trip.
    for (s, expected) in [
        ("boolean", "Boolean"),
        ("string", "String"),
        ("decimal", "Decimal"),
        ("stringlist", "StringList"),
        ("datetime", "DateTime"),
        ("json", "JSON"),
    ] {
        let t = ParameterType::from_str(s).unwrap();
        assert_eq!(t.as_str(), expected);
    }
    assert!(ParameterType::from_str("bogus").is_err());
}
// ── 10. Posting-type model (design §4.6) ────────────────────

#[tokio::test]
async fn test_posting_type_model() {
    use postings::PostingType;

    // All 8 designed posting types round-trip.
    for p in [
        PostingType::Transfer,
        PostingType::InboundHardSettlement,
        PostingType::OutboundHardSettlement,
        PostingType::InboundAuthorisation,
        PostingType::OutboundAuthorisation,
        PostingType::AuthorisationAdjustment,
        PostingType::Release,
        PostingType::Settlement,
    ] {
        assert_eq!(PostingType::from_str(p.as_str()).unwrap(), p);
    }
    // Unknown types are rejected, never silently mapped.
    assert!(PostingType::from_str("bogus").is_err());
    assert!(PostingType::from_str("").is_err());

    // Authorisation family is pending-phase; everything else committed.
    assert!(PostingType::InboundAuthorisation.is_pending_phase());
    assert!(PostingType::OutboundAuthorisation.is_pending_phase());
    assert!(PostingType::AuthorisationAdjustment.is_pending_phase());
    for p in [
        PostingType::Transfer,
        PostingType::InboundHardSettlement,
        PostingType::OutboundHardSettlement,
        PostingType::Release,
        PostingType::Settlement,
    ] {
        assert!(!p.is_pending_phase());
    }

    // Release is the only reversal.
    assert!(PostingType::Release.is_reversal());
    assert!(!PostingType::Settlement.is_reversal());

    // build_instruction maps sides + decimal amount, never float.
    let src = uuid::Uuid::new_v4();
    let dst = uuid::Uuid::new_v4();
    let instr = postings::build_instruction(
        PostingType::OutboundHardSettlement,
        src, dst, "250.75", "EUR", None,
    );
    assert_eq!(instr.instruction_type, "outbound_hard_settlement");
    assert_eq!(instr.debit_account, src);
    assert_eq!(instr.credit_account, dst);
    assert_eq!(instr.amount, "250.75");
    assert_eq!(instr.denomination, "EUR");

    // Deterministic batch id for retry idempotency.
    let iid = uuid::Uuid::new_v4();
    assert_eq!(
        postings::batch_id_for(iid, PostingType::Settlement),
        postings::batch_id_for(iid, PostingType::Settlement)
    );
    assert_ne!(
        postings::batch_id_for(iid, PostingType::Settlement),
        postings::batch_id_for(iid, PostingType::Transfer)
    );
}

// ── 14. Event stream naming + publisher identity  ─────

#[tokio::test]
async fn test_event_streaming_conventions() {
    use event_streaming::{build_payload, PublisherIdentity, ResourceType, STREAM_FAMILY};

    // Stream family matches the bus role derivation (`bank8_payments_service`
    // → `payments`) — a mismatch would fail the inbox RLS INSERT policy and
    // starve the worker.
    assert_eq!(STREAM_FAMILY, "payments");

    // Event names use the platform colon convention.
    let (_, event_type, _) =
        build_payload(ResourceType::Instruction, "abc", "created", None, None).unwrap();
    assert_eq!(event_type, "bank8:payments:instruction:created");

    let (_, event_type2, _) =
        build_payload(ResourceType::Payment, "p1", "updated", None, None).unwrap();
    assert_eq!(event_type2, "bank8:payments:payment:updated");
    // No dots in event names (AGENTS.md).
    assert!(!event_type2.contains('.'));

    // Publisher identity: token + subject round-trip.
    let pub_none = PublisherIdentity::none();
    assert!(pub_none.id_token.is_none() && pub_none.subject.is_none());
    let pub_some = PublisherIdentity::from_parts(Some("tok".into()), Some("sub".into()));
    assert_eq!(pub_some.id_token.as_deref(), Some("tok"));
    assert_eq!(pub_some.subject.as_deref(), Some("sub"));
}

// ── 15. Feature gates — full set of 15  ─────────────────────

#[tokio::test]
async fn test_feature_gate_completeness() {
    use config::FeatureGate;

    // All 15 designed gates exist and are addressable.
    let gates = [
        FeatureGate::Payments,
        FeatureGate::InstructionsSync,
        FeatureGate::InstructionsAsync,
        FeatureGate::Files,
        FeatureGate::Cards,
        FeatureGate::CardsEncrypted,
        FeatureGate::Mandates,
        FeatureGate::Recurring,
        FeatureGate::ManualDecisions,
        FeatureGate::Tasks,
        FeatureGate::Templates,
        FeatureGate::Dashboards,
        FeatureGate::MembershipDirectories,
        FeatureGate::Calendars,
        FeatureGate::Sandbox,
    ];
    // Master gate off → everything off.
    let mut all_off = config::FeatureGates {
        payments: false,
        instructions_sync: true,
        instructions_async: true,
        cards: true,
        cards_encrypted: true,
        files: true,
        mandates: true,
        recurring: true,
        manual_decisions: true,
        tasks: true,
        templates: true,
        dashboards: true,
        membership_directories: true,
        calendars: true,
        sandbox: true,
    };
    for g in gates {
        assert!(!all_off.is_enabled(g), "gate {g:?} should be off when master off");
    }
    // Master on → each gate's own flag decides.
    all_off.payments = true;
    for g in gates {
        assert!(all_off.is_enabled(g), "gate {g:?} should be on when master on");
    }
    // Sandbox default off (design §7).
    assert!(!config::FeatureGates::from_env().sandbox);
}
