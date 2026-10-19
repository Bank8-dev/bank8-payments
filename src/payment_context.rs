// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Payment context keys - Story.
//! These keys are set by logic writers on the instruction context and are
//! auto-managed by Payments for `__payment_status` (INITIATED, CANCELLED, ERRORED).
//! See `services/payments/DESIGN.md` §4.3.
//! | Key | Example | Source |
//! | `__payment_type` | CREDIT_TRANSFER, DIRECT_DEBIT | Logic writer |
//! | `__payment_direction`| INBOUND, OUTBOUND | Logic writer |
//! | `__payment_status` | INITIATED, CANCELLED, ERRORED | Auto / Logic |
//! | `__payment_system` | TIPS, SEPA, VISA | Logic writer |
//! | `__payment_scheme` | sepa_instant_tips | Logic writer |

use sqlx::PgPool;
use uuid::Uuid;

/// Well-known payment context key names.
pub const PAYMENT_TYPE: &str = "__payment_type";
pub const PAYMENT_DIRECTION: &str = "__payment_direction";
pub const PAYMENT_STATUS: &str = "__payment_status";
pub const PAYMENT_SYSTEM: &str = "__payment_system";
pub const PAYMENT_SCHEME: &str = "__payment_scheme";

/// Auto-set payment status values.
pub const STATUS_INITIATED: &str = "INITIATED";
pub const STATUS_CANCELLED: &str = "CANCELLED";
pub const STATUS_ERRORED: &str = "ERRORED";

/// Extract a context key from an instruction's input JSON.
pub fn extract_key(input: &serde_json::Value, key: &str) -> Option<String> {
    input
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Auto-set `__payment_status` based on the instruction state.
/// Called after a state transition to keep the payment status in sync.
/// - `pending` / `processing` / `waiting` → `INITIATED`
/// - `cancelled` → `CANCELLED`
/// - `failed` → `ERRORED`
/// - `completed` → no auto-update (logic may set a final status)
pub fn auto_status_for_state(state: &str) -> Option<&'static str> {
    match state {
        "pending" | "processing" | "waiting" => Some(STATUS_INITIATED),
        "cancelled" => Some(STATUS_CANCELLED),
        "failed" => Some(STATUS_ERRORED),
        "completed" => None,
        _ => None,
    }
}

/// Update the payment status based on the instruction's new state.
/// This is called by the state machine after a successful transition.
/// It updates the `payments.status` column for the payment associated
/// with the instruction.
pub async fn sync_payment_status(
    pool: &PgPool,
    instruction_id: Uuid,
    new_state: &str,
) -> Result<bool, String> {
    let status = match auto_status_for_state(new_state) {
        Some(s) => s,
        None => return Ok(false), // no auto-update
    };

    let result = sqlx::query(
        r#"UPDATE payments
              SET status = $2, updated_at = now()
            WHERE id = (
                SELECT payment_id FROM instructions WHERE id = $1
            )"#,
    )
    .bind(instruction_id)
    .bind(status)
    .execute(pool)
    .await
    .map_err(|e| format!("update payment status: {e}"))?;

    Ok(result.rows_affected() > 0)
}

/// Merge payment context keys from the instruction input into the payment row.
/// Extracts `__payment_type`, `__payment_direction`, `__payment_system`,
/// `__payment_scheme` from the instruction input and updates the corresponding
/// columns on the payment row.
pub async fn merge_context_keys(
    pool: &PgPool,
    instruction_id: Uuid,
    input: &serde_json::Value,
) -> Result<bool, String> {
    let payment_type = extract_key(input, PAYMENT_TYPE);
    let direction = extract_key(input, PAYMENT_DIRECTION);
    let payment_system = extract_key(input, PAYMENT_SYSTEM);
    let payment_scheme = extract_key(input, PAYMENT_SCHEME);

    if payment_type.is_none()
        && direction.is_none()
        && payment_system.is_none()
        && payment_scheme.is_none()
    {
        return Ok(false);
    }

    let result = sqlx::query(
        r#"UPDATE payments
              SET payment_type = COALESCE($2, payment_type),
                  direction = COALESCE($3, direction),
                  payment_system = COALESCE($4, payment_system),
                  payment_scheme = COALESCE($5, payment_scheme),
                  updated_at = now()
            WHERE id = (
                SELECT payment_id FROM instructions WHERE id = $1
            )"#,
    )
    .bind(instruction_id)
    .bind(payment_type)
    .bind(direction)
    .bind(payment_system)
    .bind(payment_scheme)
    .execute(pool)
    .await
    .map_err(|e| format!("merge context keys: {e}"))?;

    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_key() {
        let input = json!({
            "__payment_type": "CREDIT_TRANSFER",
            "__payment_direction": "OUTBOUND",
            "__payment_system": "SEPA",
            "__payment_scheme": "sepa_instant_tips",
        });
        assert_eq!(
            extract_key(&input, PAYMENT_TYPE),
            Some("CREDIT_TRANSFER".into())
        );
        assert_eq!(
            extract_key(&input, PAYMENT_DIRECTION),
            Some("OUTBOUND".into())
        );
        assert_eq!(extract_key(&input, PAYMENT_SYSTEM), Some("SEPA".into()));
        assert_eq!(
            extract_key(&input, PAYMENT_SCHEME),
            Some("sepa_instant_tips".into())
        );
        assert_eq!(extract_key(&input, "missing"), None);
    }

    #[test]
    fn test_auto_status_for_state() {
        assert_eq!(auto_status_for_state("pending"), Some(STATUS_INITIATED));
        assert_eq!(auto_status_for_state("processing"), Some(STATUS_INITIATED));
        assert_eq!(auto_status_for_state("waiting"), Some(STATUS_INITIATED));
        assert_eq!(auto_status_for_state("cancelled"), Some(STATUS_CANCELLED));
        assert_eq!(auto_status_for_state("failed"), Some(STATUS_ERRORED));
        assert_eq!(auto_status_for_state("completed"), None);
        assert_eq!(auto_status_for_state("unknown"), None);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PAYMENT_TYPE, "__payment_type");
        assert_eq!(PAYMENT_DIRECTION, "__payment_direction");
        assert_eq!(PAYMENT_STATUS, "__payment_status");
        assert_eq!(PAYMENT_SYSTEM, "__payment_system");
        assert_eq!(PAYMENT_SCHEME, "__payment_scheme");
    }
}
