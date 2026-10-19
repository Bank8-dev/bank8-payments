// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Card issuing & lifecycle - state machine, encryption, tokens, orders,
//! LVT/ATC counters, simulator, decline recommendations, authorisation
//! expiry, encrypted sessions, PIN operations, 3-D Secure records, risk
//! evaluation, challenge methods, Outseer risk analysis integration.
//!
//! See `services/payments/DESIGN.md` §4.7 (Card Issuing).
//! The encryption helpers in this module are **placeholders**. They perform
//! a deterministic base64+XOR obfuscation so the rest of the card lifecycle
//! can be exercised end-to-end in tests without pulling in AES/P-256
//! dependencies. Production deployments MUST replace `CardEncryption` with
//! a real HSM/KMS-backed implementation.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

// ── Story - Card lifecycle state machine ────────────────────────

/// Lifecycle state of an issued card.
/// States follow the card-issuing lifecycle described in
/// `services/payments/DESIGN.md`:
/// - `PendingCreation` - card record created but not yet confirmed by the
///
/// issuer.
/// - `Inactive` - card exists but is not usable for transactions.
/// - `Active` - card may authorise.
/// - `Suspended` - temporarily blocked (freeze).
/// - `Disabled` - terminal state; the card can no longer transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardState {
    PendingCreation,
    Inactive,
    Active,
    Suspended,
    Disabled,
}

impl CardState {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "pending_creation" => Ok(Self::PendingCreation),
            "inactive" => Ok(Self::Inactive),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "disabled" => Ok(Self::Disabled),
            other => Err(format!("unknown card state: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PendingCreation => "pending_creation",
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Disabled => "disabled",
        }
    }
}

/// Validate that a transition from one card state to another is permitted.
/// Permitted transitions (Story ):
/// - `PendingCreation → Inactive | Active`
/// - `Inactive → Active | Disabled`
/// - `Active → Suspended | Inactive | Disabled`
/// - `Suspended → Active | Disabled`
/// - `Disabled` is terminal - no outgoing transitions.
pub fn validate_card_transition(from: CardState, to: CardState) -> Result<(), String> {
    if from == to {
        // No-op transitions are always allowed (idempotent re-activation, etc.).
        return Ok(());
    }
    let ok = match from {
        CardState::PendingCreation => matches!(to, CardState::Inactive | CardState::Active),
        CardState::Inactive => matches!(to, CardState::Active | CardState::Disabled),
        CardState::Active => matches!(
            to,
            CardState::Suspended | CardState::Inactive | CardState::Disabled
        ),
        CardState::Suspended => matches!(to, CardState::Active | CardState::Disabled),
        CardState::Disabled => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid card state transition: {} -> {}",
            from.as_str(),
            to.as_str()
        ))
    }
}

/// Load the current state of a card.
async fn load_card_state(pool: &sqlx::PgPool, card_id: Uuid) -> Result<CardState, String> {
    let row = sqlx::query("SELECT status FROM cards WHERE id = $1")
        .bind(card_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("card {card_id} not found"))?;
    let status: String = row.get("status");
    CardState::from_str(&status)
}

/// Transition a card to a new state.
/// Loads the current state, validates the transition, updates `cards`
/// and records an audit event. Returns `Ok(true)` when the state was
/// changed, `Ok(false)` when the card was already in the target state
/// (idempotent no-op).
pub async fn transition_card_state(
    pool: &sqlx::PgPool,
    card_id: Uuid,
    to: CardState,
) -> Result<bool, String> {
    let from = load_card_state(pool, card_id).await?;
    if from == to {
        return Ok(false);
    }
    validate_card_transition(from, to)?;

    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    let rows = sqlx::query("UPDATE cards SET status = $2, updated_at = now() WHERE id = $1")
        .bind(card_id)
        .bind(to.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?
        .rows_affected();
    if rows == 0 {
        tx.rollback().await.map_err(|e| e.to_string())?;
        return Err(format!("card {card_id} not found"));
    }

    sqlx::query(
        r#"INSERT INTO audit_events
               (action, target_resource_type, target_resource_id, timestamp)
           VALUES ('card.state_transition', 'card', $1, now())"#,
    )
    .bind(card_id.to_string())
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(true)
}

// ── Story - Card encryption (PLACEHOLDER) ───────────────────────

/// Placeholder card encryption helper.
/// `generate_key_pair` returns *simulated* ECDH P-256 key material - the
/// "public" and "private" keys are random-looking base64 strings rather
/// than real P-256 points. `encrypt_pan` / `decrypt_pan` perform a
/// deterministic base64+XOR obfuscation. This is NOT secure; it exists so
/// the rest of the card lifecycle can be exercised in tests without
/// requiring the `p256` / `aes-gcm` crates in this crate. Replace with a
/// real HSM/KMS-backed implementation before production use.
pub struct CardEncryption;

impl CardEncryption {
    /// Simulate ECDH P-256 key pair generation.
    /// Returns `(public_key, private_key)` as base64-encoded placeholder
    /// strings. The "private" key is 32 random-ish bytes derived from the
    /// current time and a UUID; the "public" key is derived from it. This
    /// is NOT a real key pair.
    pub fn generate_key_pair() -> (String, String) {
        let seed = Uuid::new_v4().as_u128();
        let now = Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128;
        let mut private_bytes = [0u8; 32];
        let combined = seed ^ now;
        for (i, b) in private_bytes.iter_mut().enumerate() {
            *b = ((combined >> ((i % 16) * 8)) & 0xff) as u8;
        }
        let private_key = B64.encode(private_bytes);
        // Derive a "public" placeholder by XOR-ing the private bytes with a
        // fixed mask - purely so the two keys differ.
        let mut public_bytes = private_bytes;
        for b in public_bytes.iter_mut() {
            *b ^= 0x5a;
        }
        let public_key = B64.encode(public_bytes);
        (public_key, private_key)
    }

    /// Obfuscate a PAN using XOR + base64.
    /// `key` must be non-empty; if shorter than the PAN it is repeated. The
    /// output is base64 of the XOR-ed bytes so it is safe to store in a TEXT
    /// column. Deterministic: `decrypt_pan(encrypt_pan(p, k), k) == p`.
    pub fn encrypt_pan(pan: &str, key: &[u8]) -> Result<String, String> {
        if key.is_empty() {
            return Err("encryption key must not be empty".into());
        }
        let bytes = pan.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        for (i, b) in bytes.iter().enumerate() {
            out.push(b ^ key[i % key.len()]);
        }
        Ok(B64.encode(out))
    }

    /// Reverse `encrypt_pan`.
    pub fn decrypt_pan(encrypted: &str, key: &[u8]) -> Result<String, String> {
        if key.is_empty() {
            return Err("encryption key must not be empty".into());
        }
        let bytes = B64
            .decode(encrypted.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut out = Vec::with_capacity(bytes.len());
        for (i, b) in bytes.iter().enumerate() {
            out.push(b ^ key[i % key.len()]);
        }
        String::from_utf8(out).map_err(|e| e.to_string())
    }
}

// ── Story - Card activation/deactivation ────────────────────────

/// Activate a card - transition to `Active`.
pub async fn activate_card(pool: &sqlx::PgPool, card_id: Uuid) -> Result<(), String> {
    transition_card_state(pool, card_id, CardState::Active).await?;
    Ok(())
}

/// Freeze a card - transition to `Suspended`.
pub async fn freeze_card(pool: &sqlx::PgPool, card_id: Uuid) -> Result<(), String> {
    transition_card_state(pool, card_id, CardState::Suspended).await?;
    Ok(())
}

/// Unfreeze a card - transition from `Suspended` to `Active`.
pub async fn unfreeze_card(pool: &sqlx::PgPool, card_id: Uuid) -> Result<(), String> {
    let from = load_card_state(pool, card_id).await?;
    if from != CardState::Suspended {
        return Err(format!(
            "card {card_id} is not suspended (current: {})",
            from.as_str()
        ));
    }
    transition_card_state(pool, card_id, CardState::Active).await?;
    Ok(())
}

// ── Story - Card replacement flow ───────────────────────────────

/// Replace a card.
/// Loads the old card's `cardholder_id` and `card_product_id`, creates a
/// new card row with the (encrypted) `new_pan`, and marks the old card as
/// `Disabled`. Returns the new card id.
/// Note: in a real implementation `new_pan` would be encrypted before being
/// passed here or before being stored. This function stores the last 4
/// digits only in `pan_last_digits` and leaves the full PAN handling to the
/// caller.
pub async fn replace_card(
    pool: &sqlx::PgPool,
    card_id: Uuid,
    new_pan: &str,
) -> Result<Uuid, String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    let row = sqlx::query("SELECT env_id, cardholder_id, card_product_id FROM cards WHERE id = $1")
        .bind(card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("card {card_id} not found"))?;

    let env_id: Uuid = row.get("env_id");
    let cardholder_id: Uuid = row.get("cardholder_id");
    let card_product_id: Option<Uuid> = row.get("card_product_id");

    let pan_last_digits: String = new_pan
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();

    let new_row = sqlx::query(
        r#"INSERT INTO cards
               (env_id, cardholder_id, card_product_id,
                pan_last_digits, status)
           VALUES ($1, $2, $3, $4, 'inactive')
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(cardholder_id)
    .bind(card_product_id)
    .bind(&pan_last_digits)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let new_id: Uuid = new_row.get("id");

    sqlx::query("UPDATE cards SET status = 'disabled', updated_at = now() WHERE id = $1")
        .bind(card_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(new_id)
}

// ── Story - Card tokens ─────────────────────────────────────────

/// API response for a card token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardTokenResponse {
    pub id: Uuid,
    pub card_id: Uuid,
    pub token_requestor_id: Option<String>,
    pub token_status: String,
    pub token_reference: Option<String>,
    pub device_type: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Provision a new card token (insert into `card_tokens`).
pub async fn provision_card_token(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    card_id: Uuid,
    token_requestor_id: Option<String>,
    device_type: Option<String>,
) -> Result<Uuid, String> {
    let row = sqlx::query(
        r#"INSERT INTO card_tokens
               (env_id, card_id, token_requestor_id,
                token_status, device_type)
           VALUES ($1, $2, $3, 'active', $4)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(card_id)
    .bind(token_requestor_id.as_deref())
    .bind(device_type.as_deref())
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(row.get("id"))
}

/// List all tokens for a card.
pub async fn list_card_tokens(
    pool: &sqlx::PgPool,
    card_id: Uuid,
) -> Result<Vec<CardTokenResponse>, String> {
    let rows = sqlx::query(
        r#"SELECT id, card_id, token_requestor_id, token_status,
                  token_reference, device_type, created_at
             FROM card_tokens
            WHERE card_id = $1
            ORDER BY created_at DESC"#,
    )
    .bind(card_id)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok(rows
        .into_iter()
        .map(|r| CardTokenResponse {
            id: r.get("id"),
            card_id: r.get("card_id"),
            token_requestor_id: r.get("token_requestor_id"),
            token_status: r.get("token_status"),
            token_reference: r.get("token_reference"),
            device_type: r.get("device_type"),
            created_at: r.get("created_at"),
        })
        .collect())
}

// ── Story - Card orders ─────────────────────────────────────────

/// Create a card order (manufacturing/fulfilment request) with
/// `status = 'pending'`.
pub async fn create_card_order(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    card_id: Uuid,
    shipping_address: serde_json::Value,
) -> Result<Uuid, String> {
    let row = sqlx::query(
        r#"INSERT INTO card_orders
               (env_id, card_id, status, shipping_address)
           VALUES ($1, $2, 'pending', $3)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(card_id)
    .bind(&shipping_address)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(row.get("id"))
}

/// Update a card order's status. Allowed values are constrained by the
/// `card_orders.status` CHECK constraint
/// (`pending|manufacturing|shipped|delivered|cancelled`).
pub async fn update_card_order_status(
    pool: &sqlx::PgPool,
    order_id: Uuid,
    status: &str,
) -> Result<(), String> {
    let rows = sqlx::query("UPDATE card_orders SET status = $2, updated_at = now() WHERE id = $1")
        .bind(order_id)
        .bind(status)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?
        .rows_affected();
    if rows == 0 {
        return Err(format!("card order {order_id} not found"));
    }
    Ok(())
}

// ── Story - LVT counter ────────────────────────────────────────

/// Low-Value Transaction (LVT) status for a card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LvtStatus {
    pub card_id: Uuid,
    pub lvt_counter: i32,
    pub lvt_accumulator: rust_decimal::Decimal,
}

/// Increment the LVT counter by 1 and add `amount` to the LVT accumulator.
pub async fn increment_lvt(
    pool: &sqlx::PgPool,
    card_id: Uuid,
    amount: rust_decimal::Decimal,
) -> Result<(), String> {
    let rows = sqlx::query(
        r#"UPDATE cards
              SET lvt_counter = lvt_counter + 1,
                  lvt_accumulator = lvt_accumulator + $2,
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(card_id)
    .bind(amount)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?
    .rows_affected();
    if rows == 0 {
        return Err(format!("card {card_id} not found"));
    }
    Ok(())
}

/// Return the current LVT counter and accumulator for a card.
pub async fn get_lvt_status(pool: &sqlx::PgPool, card_id: Uuid) -> Result<LvtStatus, String> {
    let row = sqlx::query("SELECT id, lvt_counter, lvt_accumulator FROM cards WHERE id = $1")
        .bind(card_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("card {card_id} not found"))?;
    Ok(LvtStatus {
        card_id: row.get("id"),
        lvt_counter: row.get("lvt_counter"),
        lvt_accumulator: row.get("lvt_accumulator"),
    })
}

// ── Story - ATC (Application Transaction Counter) ───────────────

/// Increment the ATC counter by 1 and return the new value.
pub async fn increment_atc(pool: &sqlx::PgPool, card_id: Uuid) -> Result<i32, String> {
    let row = sqlx::query(
        r#"UPDATE cards
              SET atc_counter = atc_counter + 1,
                  updated_at = now()
            WHERE id = $1
            RETURNING atc_counter"#,
    )
    .bind(card_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(row.get("atc_counter"))
}

// ── Story - Card simulator ─────────────────────────────────────

/// Result of a simulated card transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub approved: bool,
    pub auth_id: String,
    pub response_code: String,
}

/// In-memory card simulator for sandbox/testing.
/// The simulator does not touch the database; it returns deterministic
/// results based on the card id and amount. Approvals are granted when the
/// amount is positive and the (deterministic) "balance" covers it; large
/// amounts are declined with `51` (insufficient funds).
pub struct CardSimulator;

impl CardSimulator {
    /// Simulate an authorisation request.
    pub fn simulate_authorisation(card_id: Uuid, amount: f64, merchant: &str) -> SimulationResult {
        let auth_id = format!("auth-{}-{}", card_id, Uuid::new_v4());
        if amount <= 0.0 {
            return SimulationResult {
                approved: false,
                auth_id,
                response_code: "12".into(), // invalid transaction
            };
        }
        // Deterministic pseudo-balance derived from the card id.
        let seed = card_id.as_u128() % 100_000;
        let balance = (seed as f64) * 10.0;
        if amount > balance {
            return SimulationResult {
                approved: false,
                auth_id,
                response_code: "51".into(), // insufficient funds
            };
        }
        let _ = merchant; // merchant name is accepted but not used in the simple model
        SimulationResult {
            approved: true,
            auth_id,
            response_code: "00".into(), // approved
        }
    }

    /// Simulate a presentment (clearing) against an existing authorisation.
    pub fn simulate_presentment(card_id: Uuid, amount: f64, merchant: &str) -> SimulationResult {
        // Presentment follows the same approval logic as the authorisation;
        // in a real system it would match against the auth id.
        let auth_id = format!("pres-{}-{}", card_id, Uuid::new_v4());
        if amount <= 0.0 {
            return SimulationResult {
                approved: false,
                auth_id,
                response_code: "12".into(),
            };
        }
        let seed = card_id.as_u128() % 100_000;
        let balance = (seed as f64) * 10.0;
        if amount > balance {
            return SimulationResult {
                approved: false,
                auth_id,
                response_code: "51".into(),
            };
        }
        let _ = merchant;
        SimulationResult {
            approved: true,
            auth_id,
            response_code: "00".into(),
        }
    }
}

// ── Story - Decline recommendations ─────────────────────────────

/// Reason a card transaction was declined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclineReason {
    InsufficientFunds,
    ExpiredCard,
    StolenCard,
    SuspectedFraud,
    DoNotHonor,
    InvalidMerchant,
    TransactionNotAllowed,
}

impl DeclineReason {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "insufficient_funds" => Ok(Self::InsufficientFunds),
            "expired_card" => Ok(Self::ExpiredCard),
            "stolen_card" => Ok(Self::StolenCard),
            "suspected_fraud" => Ok(Self::SuspectedFraud),
            "do_not_honor" => Ok(Self::DoNotHonor),
            "invalid_merchant" => Ok(Self::InvalidMerchant),
            "transaction_not_allowed" => Ok(Self::TransactionNotAllowed),
            other => Err(format!("unknown decline reason: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InsufficientFunds => "insufficient_funds",
            Self::ExpiredCard => "expired_card",
            Self::StolenCard => "stolen_card",
            Self::SuspectedFraud => "suspected_fraud",
            Self::DoNotHonor => "do_not_honor",
            Self::InvalidMerchant => "invalid_merchant",
            Self::TransactionNotAllowed => "transaction_not_allowed",
        }
    }
}

/// Map a decline reason to an ISO 8583 response code.
/// Reference: ISO 8583:1987 response codes.
pub fn get_decline_recommendation(reason: DeclineReason) -> &'static str {
    match reason {
        DeclineReason::InsufficientFunds => "51",
        // `41` and `43` are both "stolen card" variants in different schemes;
        // the spec asks for either - we return `41` (lost card) for
        // `StolenCard` consistently.
        DeclineReason::StolenCard => "41",
        DeclineReason::ExpiredCard => "54",
        DeclineReason::SuspectedFraud => "59",
        DeclineReason::DoNotHonor => "05",
        DeclineReason::InvalidMerchant => "12",
        DeclineReason::TransactionNotAllowed => "57",
    }
}

// ── Story - Authorisation expiry ───────────────────────────────

/// Maximum age of an un-presented authorisation before it is expired.
pub const AUTH_MAX_AGE: Duration = Duration::days(7);

/// Check whether an authorisation has expired.
/// An authorisation is considered expired when it was created more than 7
/// days ago. The `presented` flag distinguishes authorisations that have
/// already been cleared (and so should not be expired).
/// `created_at` is the authorisation creation timestamp; `presented` is
/// `true` when a matching presentment has been received.
pub fn check_authorisation_expiry_at(
    created_at: DateTime<Utc>,
    presented: bool,
    now: DateTime<Utc>,
) -> bool {
    if presented {
        return false;
    }
    now - created_at > AUTH_MAX_AGE
}

/// Check whether an authorisation has expired (DB-backed).
/// Loads the authorisation by id and applies `check_authorisation_expiry_at`.
/// Authorisations are stored in `payments` with `payment_type =
/// 'authorisation'` and a `completed_at`/`created_at` timestamp; a presentment
/// is signalled by the presence of a matching presentment row. This simple
/// implementation treats any non-null `completed_at` as "presented".
pub async fn check_authorisation_expiry(
    pool: &sqlx::PgPool,
    auth_id: Uuid,
) -> Result<bool, String> {
    let row = sqlx::query(
        r#"SELECT created_at, completed_at
             FROM payments
            WHERE id = $1 AND payment_type = 'authorisation'"#,
    )
    .bind(auth_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| format!("authorisation {auth_id} not found"))?;

    let created_at: DateTime<Utc> = row.get("created_at");
    let completed_at: Option<DateTime<Utc>> = row.get("completed_at");
    Ok(check_authorisation_expiry_at(
        created_at,
        completed_at.is_some(),
        Utc::now(),
    ))
}

/// Find and expire all stale authorisations.
/// A stale authorisation is one with `payment_type = 'authorisation'`,
/// `completed_at IS NULL` (not yet presented), and `created_at` older than
/// 7 days. This function marks them as expired (sets `status = 'expired'`
/// and `completed_at = now `) and returns their ids.
pub async fn expire_stale_authorisations(pool: &sqlx::PgPool) -> Result<Vec<String>, String> {
    let cutoff = Utc::now() - AUTH_MAX_AGE;
    let rows = sqlx::query(
        r#"UPDATE payments
              SET status = 'expired', completed_at = now()
            WHERE payment_type = 'authorisation'
              AND completed_at IS NULL
              AND created_at < $1
            RETURNING id"#,
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok(rows
        .into_iter()
        .map(|r| r.get::<Uuid, _>("id").to_string())
        .collect())
}

// ── Story - Card operations: encrypted sessions, PIN, card tokens, 3DS ─

/// Type of encrypted card session.
/// Sessions are short-lived cryptographic contexts negotiated between the
/// cardholder client and Payments so that sensitive operations (PIN verify,
/// PIN change, secure 3DS challenge delivery) never transmit the clear
/// values over a plain channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedSessionType {
    PinVerify,
    PinChange,
    ThreeDs,
}

impl EncryptedSessionType {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "pin_verify" => Ok(Self::PinVerify),
            "pin_change" => Ok(Self::PinChange),
            "3ds" | "three_ds" => Ok(Self::ThreeDs),
            other => Err(format!("unknown encrypted session type: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PinVerify => "pin_verify",
            Self::PinChange => "pin_change",
            Self::ThreeDs => "3ds",
        }
    }
}

/// Response returned when an encrypted card session is created.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSessionResponse {
    pub session_id: Uuid,
    pub card_id: Uuid,
    pub session_type: String,
    pub session_token: String,
    pub public_key: String,
    pub expires_at: DateTime<Utc>,
}
#[utoipa::path(
    post,
    path = "/v1/cards/{id}/encrypted-session",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// Create a new encrypted card session.
/// Inserts a row in `card_sessions` (defined by migration
/// `14-payments.sql`) with `status = 'active'` and returns
/// the session id together with a short-lived session token (a UUID) and
/// the placeholder public key the client should use to encrypt the
/// sensitive payload. The session expires after 5 minutes by default.
pub async fn create_encrypted_session(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    card_id: Uuid,
    session_type: EncryptedSessionType,
) -> Result<EncryptedSessionResponse, String> {
    // Validate that the card exists and belongs to the same tenant.
    let card_row = sqlx::query("SELECT id FROM cards WHERE id = $1 AND env_id = $2")
        .bind(card_id)
        .bind(env_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("card {card_id} not found"))?;

    let _ = card_row;
    let (public_key, _private_key) = CardEncryption::generate_key_pair();
    let session_token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::minutes(5);

    let row = sqlx::query(
        r#"INSERT INTO card_sessions
               (env_id, card_id, session_type,
                session_token, public_key, status, expires_at)
           VALUES ($1, $2, $3, $4, $5, 'active', $6)
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(card_id)
    .bind(session_type.as_str())
    .bind(&session_token)
    .bind(&public_key)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    let session_id: Uuid = row.get("id");

    Ok(EncryptedSessionResponse {
        session_id,
        card_id,
        session_type: session_type.as_str().to_string(),
        session_token,
        public_key,
        expires_at,
    })
}

/// Result of a PIN verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinVerifyResult {
    pub card_id: Uuid,
    pub verified: bool,
    pub attempts_remaining: i32,
}
#[utoipa::path(
    post,
    path = "/v1/cards/{id}/pin/verify",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// Verify a card PIN.
/// `pin_hash` is the (already hashed) PIN the client sent, encrypted with
/// the session public key. Payments never stores or sees the clear PIN. The
/// stored `pin_hash` column on `cards` is compared against the
/// provided value; on mismatch `pin_attempts` is incremented and the
/// card is suspended when it reaches 3.
pub async fn verify_pin(
    pool: &sqlx::PgPool,
    card_id: Uuid,
    pin_hash: &str,
) -> Result<PinVerifyResult, String> {
    let row = sqlx::query("SELECT pin_hash, pin_attempts FROM cards WHERE id = $1")
        .bind(card_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("card {card_id} not found"))?;

    let stored_hash: Option<String> = row.get("pin_hash");
    let attempts: i32 = row.get("pin_attempts");

    let verified = stored_hash
        .as_deref()
        .map(|h| !h.is_empty() && h == pin_hash)
        .unwrap_or(false);

    if verified {
        // Reset attempts on success.
        let _ = sqlx::query("UPDATE cards SET pin_attempts = 0, updated_at = now() WHERE id = $1")
            .bind(card_id)
            .execute(pool)
            .await;
        return Ok(PinVerifyResult {
            card_id,
            verified: true,
            attempts_remaining: 3,
        });
    }

    // Increment attempts and suspend the card after 3 failures.
    let new_attempts = attempts + 1;
    let attempts_remaining = (3 - new_attempts).max(0);
    if new_attempts >= 3 {
        let _ = sqlx::query(
            r#"UPDATE cards
                  SET pin_attempts = $2,
                      status = 'suspended',
                      updated_at = now()
                WHERE id = $1"#,
        )
        .bind(card_id)
        .bind(new_attempts)
        .execute(pool)
        .await;
    } else {
        let _ = sqlx::query("UPDATE cards SET pin_attempts = $2, updated_at = now() WHERE id = $1")
            .bind(card_id)
            .bind(new_attempts)
            .execute(pool)
            .await;
    }

    Ok(PinVerifyResult {
        card_id,
        verified: false,
        attempts_remaining,
    })
}

/// Result of a PIN change operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinChangeResult {
    pub card_id: Uuid,
    pub changed: bool,
}
#[utoipa::path(
    post,
    path = "/v1/cards/{id}/pin/change",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "payments",
)]

/// Change a card PIN.
/// Verifies `old_pin_hash` against the stored `pin_hash`; on success the
/// stored hash is replaced with `new_pin_hash` and `pin_attempts` is
/// reset. On failure `pin_attempts` is incremented (same policy as
/// `verify_pin`).
pub async fn change_pin(
    pool: &sqlx::PgPool,
    card_id: Uuid,
    old_pin_hash: &str,
    new_pin_hash: &str,
) -> Result<PinChangeResult, String> {
    if new_pin_hash.is_empty() {
        return Err("new pin hash must not be empty".into());
    }

    let row = sqlx::query("SELECT pin_hash, pin_attempts FROM cards WHERE id = $1")
        .bind(card_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("card {card_id} not found"))?;

    let stored_hash: Option<String> = row.get("pin_hash");
    let attempts: i32 = row.get("pin_attempts");

    let matches = stored_hash
        .as_deref()
        .map(|h| !h.is_empty() && h == old_pin_hash)
        .unwrap_or(false);

    if !matches {
        let new_attempts = attempts + 1;
        if new_attempts >= 3 {
            let _ = sqlx::query(
                r#"UPDATE cards
                      SET pin_attempts = $2,
                          status = 'suspended',
                          updated_at = now()
                    WHERE id = $1"#,
            )
            .bind(card_id)
            .bind(new_attempts)
            .execute(pool)
            .await;
        } else {
            let _ =
                sqlx::query("UPDATE cards SET pin_attempts = $2, updated_at = now() WHERE id = $1")
                    .bind(card_id)
                    .bind(new_attempts)
                    .execute(pool)
                    .await;
        }
        return Ok(PinChangeResult {
            card_id,
            changed: false,
        });
    }

    let rows = sqlx::query(
        r#"UPDATE cards
              SET pin_hash = $2,
                  pin_attempts = 0,
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(card_id)
    .bind(new_pin_hash)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?
    .rows_affected();
    if rows == 0 {
        return Err(format!("card {card_id} not found"));
    }
    Ok(PinChangeResult {
        card_id,
        changed: true,
    })
}

// ── Story - 3DS Records ─────────────────────────────────────────

/// Lifecycle status of a 3DS authentication record.
/// States follow the `threeds_records.authentication_status` CHECK
/// constraint defined in `infra/postgres/init/14-payments.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreeDSAuthenticationStatus {
    Pending,
    Frictionless,
    Challenged,
    Authenticated,
    Failed,
    Declined,
}

impl ThreeDSAuthenticationStatus {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "pending" => Ok(Self::Pending),
            "frictionless" => Ok(Self::Frictionless),
            "challenged" => Ok(Self::Challenged),
            "authenticated" => Ok(Self::Authenticated),
            "failed" => Ok(Self::Failed),
            "declined" => Ok(Self::Declined),
            other => Err(format!("unknown 3DS authentication status: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Frictionless => "frictionless",
            Self::Challenged => "challenged",
            Self::Authenticated => "authenticated",
            Self::Failed => "failed",
            Self::Declined => "declined",
        }
    }
}

/// A 3DS authentication record.
/// Tracks the authentication state for a single card transaction. The
/// record is created when a 3DS authentication is initiated and updated
/// as the authentication progresses (frictionless, challenge, completed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreeDSRecord {
    pub id: Uuid,
    pub card_id: Option<Uuid>,
    pub transaction_id: String,
    pub authentication_status: String,
    pub challenge_method: Option<String>,
    pub risk_score: Option<f64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Create a 3DS record with status = 'pending'.
/// Inserts into `threeds_records` and returns the new record id. The
/// caller is responsible for setting the tenant context before invoking
/// this function.
pub async fn create_3ds_record(
    pool: &sqlx::PgPool,
    card_id: Option<Uuid>,
    transaction_id: &str,
) -> Result<Uuid, String> {
    if transaction_id.is_empty() {
        return Err("transaction_id must not be empty".into());
    }
    let row = sqlx::query(
        r#"INSERT INTO threeds_records
               (card_id, transaction_id, authentication_status)
           VALUES ($1, $2, 'pending')
           RETURNING id"#,
    )
    .bind(card_id)
    .bind(transaction_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    Ok(row.get("id"))
}

/// Update the status (and optional challenge method) of a 3DS record.
pub async fn update_3ds_status(
    pool: &sqlx::PgPool,
    record_id: Uuid,
    status: ThreeDSAuthenticationStatus,
    challenge_method: Option<&str>,
) -> Result<(), String> {
    let rows = sqlx::query(
        r#"UPDATE threeds_records
              SET authentication_status = $2,
                  challenge_method = COALESCE($3, challenge_method),
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(record_id)
    .bind(status.as_str())
    .bind(challenge_method)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?
    .rows_affected();
    if rows == 0 {
        return Err(format!("3DS record {record_id} not found"));
    }
    Ok(())
}

/// Look up a 3DS record by its `transaction_id`.
pub async fn get_3ds_record(
    pool: &sqlx::PgPool,
    transaction_id: &str,
) -> Result<Option<ThreeDSRecord>, String> {
    let row = sqlx::query(
        r#"SELECT id, card_id, transaction_id, authentication_status,
                  challenge_method, risk_score::float8 AS risk_score,
                  created_at, updated_at
             FROM threeds_records
            WHERE transaction_id = $1
            ORDER BY created_at DESC
            LIMIT 1"#,
    )
    .bind(transaction_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok(row.map(|r| ThreeDSRecord {
        id: r.get("id"),
        card_id: r.get("card_id"),
        transaction_id: r.get("transaction_id"),
        authentication_status: r.get("authentication_status"),
        challenge_method: r.get("challenge_method"),
        risk_score: r.get("risk_score"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }))
}

// ── Story - 3DS authentication logics ───────────────────────────

/// Outcome of a 3DS risk evaluation.
/// The bands correspond to the frictionless/challenge/decline flow
/// described in `services/payments/DESIGN.md` §3-D Secure:
/// - `Green` - frictionless (no challenge).
/// - `Amber` - challenge required.
/// - `Red` - decline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreeDSAuthResult {
    Green,
    Amber,
    Red,
}

impl ThreeDSAuthResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Amber => "amber",
            Self::Red => "red",
        }
    }
}

/// Evaluate the 3DS risk of a transaction.
/// Rules (Story ):
/// - **Green** (frictionless) - `risk_score < 0.2` AND `amount < 50` AND
///
/// `merchant_trusted`.
/// - **Amber** (challenge) - `risk_score < 0.7` (and not Green).
/// - **Red** (decline) - `risk_score >= 0.7` OR `amount > 5000`.
///
/// `Red` takes priority over the other bands.
pub fn evaluate_3ds_risk(
    risk_score: f64,
    amount: f64,
    merchant_trusted: bool,
) -> ThreeDSAuthResult {
    // Decline band has the highest priority.
    if risk_score >= 0.7 || amount > 5000.0 {
        return ThreeDSAuthResult::Red;
    }
    if risk_score < 0.2 && amount < 50.0 && merchant_trusted {
        return ThreeDSAuthResult::Green;
    }
    ThreeDSAuthResult::Amber
}

/// Recommend a 3DS action based on the risk evaluation result.
pub fn recommend_3ds_action(result: &ThreeDSAuthResult) -> &'static str {
    match result {
        ThreeDSAuthResult::Green => "frictionless",
        ThreeDSAuthResult::Amber => "challenge",
        ThreeDSAuthResult::Red => "decline",
    }
}

// ── Story - 3DS challenge methods ───────────────────────────────

/// Delivery method for a 3DS challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeMethod {
    Sms,
    MobileApp,
}

impl ChallengeMethod {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "sms" => Ok(Self::Sms),
            "mobile_app" => Ok(Self::MobileApp),
            other => Err(format!("unknown challenge method: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sms => "sms",
            Self::MobileApp => "mobile_app",
        }
    }
}

/// Configuration for a 3DS challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConfig {
    pub method: ChallengeMethod,
    pub phone_number: Option<String>,
    pub app_id: Option<String>,
    #[serde(default = "default_challenge_timeout")]
    pub timeout_seconds: u32,
}

fn default_challenge_timeout() -> u32 {
    300
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            method: ChallengeMethod::Sms,
            phone_number: None,
            app_id: None,
            timeout_seconds: 300,
        }
    }
}

/// Initiate a 3DS challenge for a 3DS record.
/// Generates a UUID-based challenge token, persists it on the record
/// (`challenge_token` column) and updates the record status to
/// `challenged` with the chosen challenge method. Returns the challenge
/// token the client must present to complete the challenge.
pub async fn initiate_challenge(
    pool: &sqlx::PgPool,
    record_id: Uuid,
    method: ChallengeMethod,
) -> Result<String, String> {
    let challenge_token = format!("ch-{}-{}", record_id, Uuid::new_v4());
    let rows = sqlx::query(
        r#"UPDATE threeds_records
              SET authentication_status = 'challenged',
                  challenge_method = $2,
                  challenge_token = $3,
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(record_id)
    .bind(method.as_str())
    .bind(&challenge_token)
    .execute(pool)
    .await
    .map_err(|e| e.to_string())?
    .rows_affected();
    if rows == 0 {
        return Err(format!("3DS record {record_id} not found"));
    }
    Ok(challenge_token)
}

// ── Story - Outseer risk analysis integration ──────────────────

/// Request sent to Outseer for risk analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutseerRiskRequest {
    pub card_id: Uuid,
    pub transaction_id: String,
    pub amount: f64,
    pub merchant_id: String,
    pub acquirer_id: String,
}

/// Response returned by Outseer risk analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutseerRiskResponse {
    pub risk_score: f64,
    pub risk_band: String,
    pub recommendation: String,
}

/// Stub call to Outseer risk analysis.
/// A real deployment would POST the request to the Outseer Risk Engine
/// endpoint and parse the returned risk score and recommendation. This
/// stub returns a deterministic score based on the amount so that the
/// 3DS flow can be exercised end-to-end in tests without a live Outseer
/// endpoint.
/// Mapping:
/// - `amount < 100` → score 0.1, band "LOW", recommendation "frictionless"
/// - `amount < 1000` → score 0.4, band "MEDIUM", recommendation "challenge"
/// - `amount >= 1000` → score 0.8, band "HIGH", recommendation "decline"
pub fn call_outseer_risk_analysis(
    request: &OutseerRiskRequest,
) -> Result<OutseerRiskResponse, String> {
    if request.amount < 0.0 {
        return Err("amount must not be negative".into());
    }
    let (risk_score, risk_band, recommendation) = if request.amount < 100.0 {
        (0.1, "LOW", "frictionless")
    } else if request.amount < 1000.0 {
        (0.4, "MEDIUM", "challenge")
    } else {
        (0.8, "HIGH", "decline")
    };
    Ok(OutseerRiskResponse {
        risk_score,
        risk_band: risk_band.to_string(),
        recommendation: recommendation.to_string(),
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Story - state machine ---------------------------------------

    #[test]
    fn card_state_round_trip() {
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
        assert!(CardState::from_str("pending").is_err());
    }

    #[test]
    fn valid_transitions_succeed() {
        assert!(validate_card_transition(CardState::PendingCreation, CardState::Inactive).is_ok());
        assert!(validate_card_transition(CardState::PendingCreation, CardState::Active).is_ok());
        assert!(validate_card_transition(CardState::Inactive, CardState::Active).is_ok());
        assert!(validate_card_transition(CardState::Inactive, CardState::Disabled).is_ok());
        assert!(validate_card_transition(CardState::Active, CardState::Suspended).is_ok());
        assert!(validate_card_transition(CardState::Active, CardState::Inactive).is_ok());
        assert!(validate_card_transition(CardState::Active, CardState::Disabled).is_ok());
        assert!(validate_card_transition(CardState::Suspended, CardState::Active).is_ok());
        assert!(validate_card_transition(CardState::Suspended, CardState::Disabled).is_ok());
    }

    #[test]
    fn invalid_transitions_fail() {
        // Disabled is terminal.
        assert!(validate_card_transition(CardState::Disabled, CardState::Active).is_err());
        assert!(validate_card_transition(CardState::Disabled, CardState::Suspended).is_err());
        assert!(validate_card_transition(CardState::Disabled, CardState::Inactive).is_err());
        // PendingCreation cannot go to Suspended/Disabled directly.
        assert!(
            validate_card_transition(CardState::PendingCreation, CardState::Suspended).is_err()
        );
        assert!(validate_card_transition(CardState::PendingCreation, CardState::Disabled).is_err());
        // Inactive cannot go back to PendingCreation or to Suspended.
        assert!(validate_card_transition(CardState::Inactive, CardState::PendingCreation).is_err());
        assert!(validate_card_transition(CardState::Inactive, CardState::Suspended).is_err());
        // Active cannot go back to PendingCreation.
        assert!(validate_card_transition(CardState::Active, CardState::PendingCreation).is_err());
        // Suspended cannot go to Inactive or PendingCreation.
        assert!(validate_card_transition(CardState::Suspended, CardState::Inactive).is_err());
        assert!(
            validate_card_transition(CardState::Suspended, CardState::PendingCreation).is_err()
        );
    }

    #[test]
    fn same_state_transition_is_idempotent() {
        for s in [
            CardState::PendingCreation,
            CardState::Inactive,
            CardState::Active,
            CardState::Suspended,
            CardState::Disabled,
        ] {
            assert!(validate_card_transition(s, s).is_ok());
        }
    }

    // Story - encryption -----------------------------------------

    #[test]
    fn generate_key_pair_yields_distinct_keys() {
        let (pubk, privk) = CardEncryption::generate_key_pair();
        assert!(!pubk.is_empty());
        assert!(!privk.is_empty());
        assert_ne!(pubk, privk);
    }

    #[test]
    fn encrypt_decrypt_pan_round_trip() {
        let key = b"test-key-0123456789";
        let pan = "4111111111111111";
        let enc = CardEncryption::encrypt_pan(pan, key).unwrap();
        assert_ne!(enc, pan);
        let dec = CardEncryption::decrypt_pan(&enc, key).unwrap();
        assert_eq!(dec, pan);
    }

    #[test]
    fn encrypt_pan_is_deterministic() {
        let key = b"k";
        let a = CardEncryption::encrypt_pan("4111", key).unwrap();
        let b = CardEncryption::encrypt_pan("4111", key).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn encrypt_pan_rejects_empty_key() {
        assert!(CardEncryption::encrypt_pan("4111", &[]).is_err());
        assert!(CardEncryption::decrypt_pan("aaaa", &[]).is_err());
    }

    #[test]
    fn encrypt_pan_wraps_long_pan_with_short_key() {
        let key = b"k";
        let pan = "4111111111111111111111111111111111";
        let enc = CardEncryption::encrypt_pan(pan, key).unwrap();
        let dec = CardEncryption::decrypt_pan(&enc, key).unwrap();
        assert_eq!(dec, pan);
    }

    // Story - decline recommendations ----------------------------

    #[test]
    fn decline_reason_round_trip() {
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
        assert!(DeclineReason::from_str("unknown").is_err());
    }

    #[test]
    fn decline_recommendation_codes() {
        assert_eq!(
            get_decline_recommendation(DeclineReason::InsufficientFunds),
            "51"
        );
        assert_eq!(get_decline_recommendation(DeclineReason::StolenCard), "41");
        assert_eq!(get_decline_recommendation(DeclineReason::ExpiredCard), "54");
        assert_eq!(
            get_decline_recommendation(DeclineReason::SuspectedFraud),
            "59"
        );
        assert_eq!(get_decline_recommendation(DeclineReason::DoNotHonor), "05");
        assert_eq!(
            get_decline_recommendation(DeclineReason::InvalidMerchant),
            "12"
        );
        assert_eq!(
            get_decline_recommendation(DeclineReason::TransactionNotAllowed),
            "57"
        );
    }

    // Story - simulator ------------------------------------------

    #[test]
    fn simulator_approves_small_amount() {
        // Balance is (card_id % 100_000) * 10. For a card with seed 0 the
        // balance is 0, so any positive amount is declined; use a card id
        // whose seed is large enough.
        let big = Uuid::from_u128(99_999);
        let res = CardSimulator::simulate_authorisation(big, 5.0, "acme");
        assert!(res.approved);
        assert_eq!(res.response_code, "00");
        assert!(res.auth_id.starts_with("auth-"));
    }

    #[test]
    fn simulator_declines_zero_amount() {
        let res = CardSimulator::simulate_authorisation(Uuid::new_v4(), 0.0, "acme");
        assert!(!res.approved);
        assert_eq!(res.response_code, "12");
    }

    #[test]
    fn simulator_declines_excessive_amount() {
        let res = CardSimulator::simulate_authorisation(Uuid::new_v4(), 1_000_000.0, "acme");
        assert!(!res.approved);
        assert_eq!(res.response_code, "51");
    }

    #[test]
    fn simulator_presentment_works() {
        let big = Uuid::from_u128(50_000);
        let res = CardSimulator::simulate_presentment(big, 10.0, "acme");
        assert!(res.approved);
        assert!(res.auth_id.starts_with("pres-"));
    }

    // Story - authorisation expiry -------------------------------

    #[test]
    fn fresh_unpresented_auth_not_expired() {
        let now = Utc::now();
        let created = now - Duration::days(1);
        assert!(!check_authorisation_expiry_at(created, false, now));
    }

    #[test]
    fn old_unpresented_auth_expired() {
        let now = Utc::now();
        let created = now - Duration::days(8);
        assert!(check_authorisation_expiry_at(created, false, now));
    }

    #[test]
    fn old_presented_auth_not_expired() {
        let now = Utc::now();
        let created = now - Duration::days(30);
        assert!(!check_authorisation_expiry_at(created, true, now));
    }

    #[test]
    fn exactly_seven_days_not_expired() {
        let now = Utc::now();
        let created = now - Duration::seconds(7 * 24 * 60 * 60);
        // 7 days exactly is NOT > 7 days, so not expired.
        assert!(!check_authorisation_expiry_at(created, false, now));
    }

    // Story - encrypted sessions, PIN ----------------------------

    #[test]
    fn encrypted_session_type_round_trip() {
        for s in ["pin_verify", "pin_change", "3ds"] {
            let t = EncryptedSessionType::from_str(s).unwrap();
            assert_eq!(t.as_str(), s);
        }
        // `three_ds` is accepted as an alias of `3ds`.
        let alias = EncryptedSessionType::from_str("three_ds").unwrap();
        assert_eq!(alias.as_str(), "3ds");
        assert!(EncryptedSessionType::from_str("unknown").is_err());
    }

    // Story - 3DS records ----------------------------------------

    #[test]
    fn three_ds_status_round_trip() {
        for s in [
            "pending",
            "frictionless",
            "challenged",
            "authenticated",
            "failed",
            "declined",
        ] {
            let st = ThreeDSAuthenticationStatus::from_str(s).unwrap();
            assert_eq!(st.as_str(), s);
        }
        assert!(ThreeDSAuthenticationStatus::from_str("done").is_err());
    }

    // Story - 3DS authentication logics ---------------------------

    #[test]
    fn green_band_frictionless() {
        // Low risk, small amount, trusted merchant.
        assert_eq!(evaluate_3ds_risk(0.1, 25.0, true), ThreeDSAuthResult::Green);
    }

    #[test]
    fn green_band_requires_trusted_merchant() {
        // Same numbers but untrusted merchant → not Green.
        assert_ne!(
            evaluate_3ds_risk(0.1, 25.0, false),
            ThreeDSAuthResult::Green
        );
    }

    #[test]
    fn green_band_requires_low_amount() {
        // Amount >= 50 disqualifies Green even with low risk and trusted merchant.
        assert_ne!(evaluate_3ds_risk(0.1, 50.0, true), ThreeDSAuthResult::Green);
        assert_ne!(evaluate_3ds_risk(0.1, 75.0, true), ThreeDSAuthResult::Green);
    }

    #[test]
    fn green_band_requires_low_risk() {
        // risk_score >= 0.2 disqualifies Green.
        assert_ne!(evaluate_3ds_risk(0.2, 25.0, true), ThreeDSAuthResult::Green);
    }

    #[test]
    fn amber_band_challenge() {
        // risk_score < 0.7 and not Green.
        assert_eq!(
            evaluate_3ds_risk(0.3, 100.0, true),
            ThreeDSAuthResult::Amber
        );
        assert_eq!(
            evaluate_3ds_risk(0.69, 1000.0, false),
            ThreeDSAuthResult::Amber
        );
    }

    #[test]
    fn red_band_high_risk() {
        assert_eq!(evaluate_3ds_risk(0.7, 10.0, true), ThreeDSAuthResult::Red);
        assert_eq!(evaluate_3ds_risk(0.95, 10.0, true), ThreeDSAuthResult::Red);
    }

    #[test]
    fn red_band_high_amount() {
        // amount > 5000 forces Red even with low risk.
        assert_eq!(evaluate_3ds_risk(0.1, 5001.0, true), ThreeDSAuthResult::Red);
    }

    #[test]
    fn red_takes_priority_over_green() {
        // Would be Green by risk+amount, but high amount forces Red.
        assert_eq!(evaluate_3ds_risk(0.1, 6000.0, true), ThreeDSAuthResult::Red);
        // High risk forces Red even when amount is small and merchant trusted.
        assert_eq!(evaluate_3ds_risk(0.9, 10.0, true), ThreeDSAuthResult::Red);
    }

    #[test]
    fn red_boundary_amount_5000_is_amber_or_green() {
        // amount == 5000 is NOT > 5000, so it is not Red by amount.
        // With low risk and trusted merchant but amount >= 50 it is Amber.
        assert_eq!(
            evaluate_3ds_risk(0.1, 5000.0, true),
            ThreeDSAuthResult::Amber
        );
    }

    #[test]
    fn red_boundary_risk_07_is_red() {
        // risk_score == 0.7 is >= 0.7 → Red.
        assert_eq!(evaluate_3ds_risk(0.7, 100.0, true), ThreeDSAuthResult::Red);
    }

    #[test]
    fn recommend_action_matches_band() {
        assert_eq!(
            recommend_3ds_action(&ThreeDSAuthResult::Green),
            "frictionless"
        );
        assert_eq!(recommend_3ds_action(&ThreeDSAuthResult::Amber), "challenge");
        assert_eq!(recommend_3ds_action(&ThreeDSAuthResult::Red), "decline");
    }

    // Story - challenge methods -----------------------------------

    #[test]
    fn challenge_method_round_trip() {
        for s in ["sms", "mobile_app"] {
            let m = ChallengeMethod::from_str(s).unwrap();
            assert_eq!(m.as_str(), s);
        }
        assert!(ChallengeMethod::from_str("email").is_err());
    }

    #[test]
    fn challenge_config_default_timeout() {
        let c = ChallengeConfig::default();
        assert_eq!(c.method, ChallengeMethod::Sms);
        assert_eq!(c.timeout_seconds, 300);
        assert!(c.phone_number.is_none());
        assert!(c.app_id.is_none());
    }

    #[test]
    fn challenge_config_custom() {
        let c = ChallengeConfig {
            method: ChallengeMethod::MobileApp,
            phone_number: None,
            app_id: Some("com.example.app".to_string()),
            timeout_seconds: 120,
        };
        assert_eq!(c.method.as_str(), "mobile_app");
        assert_eq!(c.timeout_seconds, 120);
        assert_eq!(c.app_id.as_deref(), Some("com.example.app"));
    }

    // Story - Outseer risk analysis ------------------------------

    #[test]
    fn outseer_low_amount() {
        let req = OutseerRiskRequest {
            card_id: Uuid::new_v4(),
            transaction_id: "tx-1".into(),
            amount: 50.0,
            merchant_id: "m".into(),
            acquirer_id: "a".into(),
        };
        let resp = call_outseer_risk_analysis(&req).unwrap();
        assert_eq!(resp.risk_score, 0.1);
        assert_eq!(resp.risk_band, "LOW");
        assert_eq!(resp.recommendation, "frictionless");
    }

    #[test]
    fn outseer_medium_amount() {
        let req = OutseerRiskRequest {
            card_id: Uuid::new_v4(),
            transaction_id: "tx-2".into(),
            amount: 500.0,
            merchant_id: "m".into(),
            acquirer_id: "a".into(),
        };
        let resp = call_outseer_risk_analysis(&req).unwrap();
        assert_eq!(resp.risk_score, 0.4);
        assert_eq!(resp.risk_band, "MEDIUM");
        assert_eq!(resp.recommendation, "challenge");
    }

    #[test]
    fn outseer_high_amount() {
        let req = OutseerRiskRequest {
            card_id: Uuid::new_v4(),
            transaction_id: "tx-3".into(),
            amount: 1500.0,
            merchant_id: "m".into(),
            acquirer_id: "a".into(),
        };
        let resp = call_outseer_risk_analysis(&req).unwrap();
        assert_eq!(resp.risk_score, 0.8);
        assert_eq!(resp.risk_band, "HIGH");
        assert_eq!(resp.recommendation, "decline");
    }

    #[test]
    fn outseer_boundary_100_is_medium() {
        // amount == 100 is NOT < 100, so it falls in the medium band.
        let req = OutseerRiskRequest {
            card_id: Uuid::new_v4(),
            transaction_id: "tx-4".into(),
            amount: 100.0,
            merchant_id: "m".into(),
            acquirer_id: "a".into(),
        };
        let resp = call_outseer_risk_analysis(&req).unwrap();
        assert_eq!(resp.risk_band, "MEDIUM");
    }

    #[test]
    fn outseer_boundary_1000_is_high() {
        // amount == 1000 is NOT < 1000, so it falls in the high band.
        let req = OutseerRiskRequest {
            card_id: Uuid::new_v4(),
            transaction_id: "tx-5".into(),
            amount: 1000.0,
            merchant_id: "m".into(),
            acquirer_id: "a".into(),
        };
        let resp = call_outseer_risk_analysis(&req).unwrap();
        assert_eq!(resp.risk_band, "HIGH");
    }

    #[test]
    fn outseer_rejects_negative_amount() {
        let req = OutseerRiskRequest {
            card_id: Uuid::new_v4(),
            transaction_id: "tx-6".into(),
            amount: -1.0,
            merchant_id: "m".into(),
            acquirer_id: "a".into(),
        };
        assert!(call_outseer_risk_analysis(&req).is_err());
    }
}
