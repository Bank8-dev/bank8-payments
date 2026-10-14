// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Interruption mode for urgent instructions — Story.
//! Normally, matched instructions within a payment are processed sequentially.
//! Interruption mode allows an urgent instruction to jump the queue and be
//! processed immediately, interrupting any pending instruction.
//! The interrupted instruction is moved back to `pending` and resumes after
//! the urgent instruction completes.
//! See `services/payments/DESIGN.md` §4.3.
//! > Sequential processing guarantee: Matched instructions are processed
//! > sequentially within a payment. Interruption mode available for urgent
//! > instructions.

use sqlx::PgPool;
use uuid::Uuid;

/// Priority levels for instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// Normal priority — processed sequentially within the payment.
    Normal = 0,
    /// High priority — interrupts the current pending instruction.
    High = 1,
    /// Urgent — preempts everything (e.g., recall/cancellation).
    Urgent = 2,
}

impl Priority {
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "high" => Self::High,
            "urgent" => Self::Urgent,
            _ => Self::Normal,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::High => "high",
            Self::Urgent => "urgent",
        }
    }

    /// Returns true if this priority should interrupt pending instructions
    /// in the same payment.
    pub fn should_interrupt(self) -> bool {
        self > Self::Normal
    }
}

/// Interrupt any pending instructions in the same payment, moving them back
/// to `pending` (if currently `processing` or `waiting`).
/// This is called when a high/urgent priority instruction is created and
/// needs to jump the sequential processing queue.
/// Returns the list of interrupted instruction IDs.
pub async fn interrupt_pending(
    pool: &PgPool,
    payment_id: Uuid,
    exclude_instruction_id: Uuid,
) -> Result<Vec<Uuid>, String> {
    let rows = sqlx::query(
        r#"UPDATE instructions
              SET state = 'pending', updated_at = now()
            WHERE payment_id = $1
              AND id != $2
              AND state IN ('processing', 'waiting')
            RETURNING id"#,
    )
    .bind(payment_id)
    .bind(exclude_instruction_id)
    .fetch_all(pool)
    .await
    .map_err(|e| format!("interrupt pending: {e}"))?;

    let interrupted: Vec<Uuid> = rows.iter().map(|r| r.get("id")).collect();

    if !interrupted.is_empty() {
        tracing::info!(
            payment_id = %payment_id,
            urgent_instruction = %exclude_instruction_id,
            interrupted_count = interrupted.len(),
            "interrupted pending instructions for urgent processing"
        );
    }

    Ok(interrupted)
}

/// Check if an instruction should use interruption mode based on its input.
/// The instruction input may contain `__priority` or `__interruption` keys.
/// If `__interruption` is `true` or `__priority` is `high`/`urgent`, the
/// instruction should interrupt pending instructions.
pub fn should_interrupt(input: &serde_json::Value) -> bool {
    if let Some(v) = input.get("__interruption").and_then(|v| v.as_bool()) {
        return v;
    }
    if let Some(p) = input.get("__priority").and_then(|v| v.as_str()) {
        return Priority::from_str(p).should_interrupt();
    }
    false
}

use sqlx::Row;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Urgent > Priority::High);
        assert!(Priority::High > Priority::Normal);
        assert!(Priority::Urgent > Priority::Normal);
    }

    #[test]
    fn test_priority_from_str() {
        assert_eq!(Priority::from_str("normal"), Priority::Normal);
        assert_eq!(Priority::from_str("high"), Priority::High);
        assert_eq!(Priority::from_str("urgent"), Priority::Urgent);
        assert_eq!(Priority::from_str("HIGH"), Priority::High);
        assert_eq!(Priority::from_str("unknown"), Priority::Normal);
    }

    #[test]
    fn test_should_interrupt() {
        assert!(should_interrupt(&json!({"__interruption": true})));
        assert!(!should_interrupt(&json!({"__interruption": false})));
        assert!(should_interrupt(&json!({"__priority": "urgent"})));
        assert!(should_interrupt(&json!({"__priority": "high"})));
        assert!(!should_interrupt(&json!({"__priority": "normal"})));
        assert!(!should_interrupt(&json!({})));
    }

    #[test]
    fn test_priority_should_interrupt() {
        assert!(!Priority::Normal.should_interrupt());
        assert!(Priority::High.should_interrupt());
        assert!(Priority::Urgent.should_interrupt());
    }
}