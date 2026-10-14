// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Instruction state machine — Story.
//! Implements the full instruction lifecycle:
//! ```text
//! pending → processing → completed
//! ↘ failed → pending (retry)
//! ↘ waiting → processing (resume)
//! any → cancelled
//! See `services/payments/DESIGN.md` §4.2.

use sqlx::PgPool;

/// Instruction states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionState {
    Pending,
    Processing,
    Waiting,
    Completed,
    Failed,
    Cancelled,
}

impl InstructionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Waiting => "waiting",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "processing" => Some(Self::Processing),
            "waiting" => Some(Self::Waiting),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// Returns true if the state is terminal (no further transitions except
    /// `failed → pending` via retry).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }

    /// Validate a transition from `self` to `to`. Returns `Ok ` if valid,
    /// `Err(message)` otherwise.
    pub fn validate_transition(self, to: Self) -> Result<(), String> {
        use InstructionState::*;
        let valid = match (self, to) {
            // pending → processing (worker picks up)
            (Pending, Processing) => true,
            // processing → completed
            (Processing, Completed) => true,
            // processing → failed
            (Processing, Failed) => true,
            // processing → waiting (async step)
            (Processing, Waiting) => true,
            // waiting → processing (callback / manual decision)
            (Waiting, Processing) => true,
            // failed → pending (retry)
            (Failed, Pending) => true,
            // any → cancelled
            (Pending, Cancelled) => true,
            (Processing, Cancelled) => true,
            (Waiting, Cancelled) => true,
            (Failed, Cancelled) => true,
            // idempotent self-transitions (no-op)
            (Pending, Pending) => true,
            (Processing, Processing) => true,
            (Waiting, Waiting) => true,
            (Completed, Completed) => true,
            (Failed, Failed) => true,
            (Cancelled, Cancelled) => true,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(format!(
                "invalid state transition: {} → {}",
                self.as_str(),
                to.as_str()
            ))
        }
    }
}

/// Transition an instruction to a new state, validating the transition.
/// Records an audit event and an outbox event on success. Idempotent: a
/// self-transition is a no-op (returns true without writing).
pub async fn transition(
    pool: &PgPool,
    instruction_id: uuid::Uuid,
    to: InstructionState,
) -> Result<bool, String> {
    transition_with_audit(pool, instruction_id, to, None, None).await
}

/// Transition with an optional audit message and actor.
pub async fn transition_with_audit(
    pool: &PgPool,
    instruction_id: uuid::Uuid,
    to: InstructionState,
    actor: Option<&str>,
    message: Option<&str>,
) -> Result<bool, String> {
    let mut tx = pool.begin().await.map_err(|e| format!("begin: {e}"))?;

    // Load current state.
    let current: String =
        sqlx::query_scalar("SELECT state FROM instructions WHERE id = $1 FOR UPDATE")
            .bind(instruction_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("load state: {e}"))?;

    let from =
        InstructionState::from_str(&current).ok_or_else(|| format!("unknown state: {current}"))?;

    // Self-transition is idempotent no-op.
    if from == to {
        tx.rollback().await.ok();
        return Ok(false);
    }

    from.validate_transition(to)?;

    // Update the instruction state.
    let now = chrono::Utc::now();
    let completed_at = if to == InstructionState::Completed {
        Some(now)
    } else {
        None
    };

    sqlx::query(
        r#"UPDATE instructions
              SET state = $2,
                  completed_at = COALESCE($3, completed_at),
                  updated_at = now()
            WHERE id = $1"#,
    )
    .bind(instruction_id)
    .bind(to.as_str())
    .bind(completed_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("update state: {e}"))?;

    // Record audit event.
    let audit_payload = serde_json::json!({
        "instruction_id": instruction_id,
        "from": from.as_str(),
        "to": to.as_str(),
        "actor": actor,
        "message": message,
    });
    let _ = sqlx::query(
        r#"INSERT INTO audit_events (event_type, payload)
           VALUES ('instruction.state_transition', $1)"#,
    )
    .bind(&audit_payload)
    .execute(&mut *tx)
    .await;

    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    tracing::info!(
        instruction_id = %instruction_id,
        from = %from.as_str(),
        to = %to.as_str(),
        "instruction state transition"
    );

    // Story — auto-sync payment status based on the new state.
    let _ = crate::payment_context::sync_payment_status(pool, instruction_id, to.as_str()).await;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_transitions() {
        use InstructionState::*;
        assert!(Pending.validate_transition(Processing).is_ok());
        assert!(Processing.validate_transition(Completed).is_ok());
        assert!(Processing.validate_transition(Failed).is_ok());
        assert!(Processing.validate_transition(Waiting).is_ok());
        assert!(Waiting.validate_transition(Processing).is_ok());
        assert!(Failed.validate_transition(Pending).is_ok());
        // any → cancelled
        assert!(Pending.validate_transition(Cancelled).is_ok());
        assert!(Processing.validate_transition(Cancelled).is_ok());
        assert!(Waiting.validate_transition(Cancelled).is_ok());
        assert!(Failed.validate_transition(Cancelled).is_ok());
    }

    #[test]
    fn test_invalid_transitions() {
        use InstructionState::*;
        // cannot go back from completed
        assert!(Completed.validate_transition(Processing).is_err());
        assert!(Completed.validate_transition(Pending).is_err());
        // cannot go from pending directly to completed
        assert!(Pending.validate_transition(Completed).is_err());
        // cannot go from waiting to completed directly
        assert!(Waiting.validate_transition(Completed).is_err());
        // cannot go from cancelled to anything
        assert!(Cancelled.validate_transition(Pending).is_err());
        assert!(Cancelled.validate_transition(Processing).is_err());
        // cannot skip processing
        assert!(Pending.validate_transition(Waiting).is_err());
        assert!(Pending.validate_transition(Failed).is_err());
    }

    #[test]
    fn test_is_terminal() {
        assert!(InstructionState::Completed.is_terminal());
        assert!(InstructionState::Cancelled.is_terminal());
        assert!(!InstructionState::Pending.is_terminal());
        assert!(!InstructionState::Processing.is_terminal());
        assert!(!InstructionState::Waiting.is_terminal());
        assert!(!InstructionState::Failed.is_terminal());
    }

    #[test]
    fn test_idempotent_self_transition() {
        use InstructionState::*;
        assert!(Pending.validate_transition(Pending).is_ok());
        assert!(Processing.validate_transition(Processing).is_ok());
        assert!(Waiting.validate_transition(Waiting).is_ok());
        assert!(Completed.validate_transition(Completed).is_ok());
        assert!(Failed.validate_transition(Failed).is_ok());
        assert!(Cancelled.validate_transition(Cancelled).is_ok());
    }

    #[test]
    fn test_from_str_roundtrip() {
        for s in [
            "pending",
            "processing",
            "waiting",
            "completed",
            "failed",
            "cancelled",
        ] {
            let state = InstructionState::from_str(s).unwrap();
            assert_eq!(state.as_str(), s);
        }
        assert!(InstructionState::from_str("unknown").is_none());
    }
}
