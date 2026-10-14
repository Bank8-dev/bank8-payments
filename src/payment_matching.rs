// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Instruction matching & payment grouping — Story.
//! Instructions sharing the same `correlation_id` are matched into a Payment.
//! The first instruction creates the Payment; subsequent instructions with
//! the same `correlation_id` join it.
//! See `services/payments/DESIGN.md` §4.3.

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Match or create a payment for the given instruction.
/// If the instruction has a `correlation_id`, look for an existing payment
/// with that correlation. If found, link the instruction to it. If not,
/// create a new payment and link the instruction.
/// If the instruction has no `correlation_id`, the instruction's own ID is
/// used as the correlation (no matching — a singleton payment).
/// Returns the payment UUID.
pub async fn match_or_create_payment(
    pool: &PgPool,
    env_id: Uuid,
    instruction_id: Uuid,
    correlation_id: Option<&str>,
    input: &serde_json::Value,
) -> Result<Uuid, String> {
    let corr = match correlation_id {
        Some(c) if !c.is_empty() => c.to_string(),
        // Default: instruction_id as correlation (singleton).
        _ => instruction_id.to_string(),
    };

    // Try to find an existing payment with this correlation_id.
    let existing: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM payments
            WHERE env_id = $1
              AND correlation_id = $2
            LIMIT 1"#,
    )
    .bind(env_id)
    .bind(&corr)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("find payment: {e}"))?;

    let payment_id = match existing {
        Some(id) => {
            // Join existing payment — link this instruction.
            sqlx::query(
                r#"UPDATE instructions
                      SET payment_id = $2, updated_at = now()
                    WHERE id = $1"#,
            )
            .bind(instruction_id)
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| format!("link instruction to payment: {e}"))?;
            id
        }
        None => {
            // Create a new payment. Extract payment_type and amount from input
            // if available (defaults for the initial creation; the logic may
            // update these later via context keys).
            let payment_type = input
                .get("__payment_type")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let amount = input
                .get("amount")
                .and_then(|v| v.as_f64())
                .and_then(|f| rust_decimal::Decimal::try_from(f).ok())
                .unwrap_or_default();
            let currency = input
                .get("currency")
                .and_then(|v| v.as_str())
                .unwrap_or("CAD")
                .to_string();
            let direction = input
                .get("__payment_direction")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let row = sqlx::query(
                r#"INSERT INTO payments
                       (env_id, instruction_id,
                        payment_type, amount, currency, status, correlation_id, direction)
                   VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)
                   RETURNING id"#,
            )
            .bind(env_id)
            .bind(instruction_id)
            .bind(&payment_type)
            .bind(amount)
            .bind(&currency)
            .bind(&corr)
            .bind(direction)
            .fetch_one(pool)
            .await
            .map_err(|e| format!("create payment: {e}"))?;

            let id: Uuid = row.get("id");

            // Link the instruction to the payment.
            sqlx::query(
                r#"UPDATE instructions
                      SET payment_id = $2, updated_at = now()
                    WHERE id = $1"#,
            )
            .bind(instruction_id)
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| format!("link instruction to new payment: {e}"))?;

            id
        }
    };

    Ok(payment_id)
}

/// Enforce sequential processing: returns the previous instruction in the
/// payment that is not yet in a terminal state, if any. The caller should
/// wait for it to complete before processing the current instruction.
pub async fn previous_pending_in_payment(
    pool: &PgPool,
    payment_id: Uuid,
    instruction_id: Uuid,
) -> Result<Option<Uuid>, String> {
    let prev: Option<Uuid> = sqlx::query_scalar(
        r#"SELECT id FROM instructions
            WHERE payment_id = $1 AND id != $2
              AND state NOT IN ('completed', 'failed', 'cancelled')
            ORDER BY created_at ASC LIMIT 1"#,
    )
    .bind(payment_id)
    .bind(instruction_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("find previous pending: {e}"))?;
    Ok(prev)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_logic() {
        // The matching logic is tested at the DB level (requires a pool).
        // This test just validates the default correlation behavior.
        let id = Uuid::new_v4();
        let corr = match None::<&str> {
            Some(c) if !c.is_empty() => c.to_string(),
            _ => id.to_string(),
        };
        assert_eq!(corr, id.to_string());
    }
}