// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Cores & Core Versions — core banking system mappings.
//! See `services/payments/DESIGN.md` §4.6 (Cores).
//! A *core* is a named core banking system (e.g. "Temenos T24"). Each core
//! owns one or more *versions*; the active version points at the
//! postings & balance integration that actually serve traffic. Core
//! migration strategies govern how traffic is shifted from one core to
//! another.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use utoipa::ToSchema;
use uuid::Uuid;

// ── Story — CoreVersions ────────────────────────────────────────

/// API response for a core version.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CoreVersionResponse {
    pub id: Uuid,
    pub core_id: Uuid,
    pub version: i32,
    pub postings_integration_id: Option<Uuid>,
    pub balance_integration_id: Option<Uuid>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Create a new core version in `status = 'active'`.
/// The version number is auto-incremented per core. If `postings_integration_id`
/// and `balance_integration_id` are both `None`, the version is still created
/// but callers should configure integrations before routing traffic.
pub async fn create_core_version(
    pool: &sqlx::PgPool,
    env_id: Uuid,
    core_id: Uuid,
    postings_integration_id: Option<Uuid>,
    balance_integration_id: Option<Uuid>,
) -> Result<Uuid, String> {
    let mut conn = pool.acquire().await.map_err(|e| e.to_string())?;

    let next_version: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM core_versions WHERE core_id = $1",
    )
    .bind(core_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| e.to_string())?;

    let row = sqlx::query(
        r#"INSERT INTO core_versions
               (env_id, core_id, version,
                postings_integration_id, balance_integration_id, status)
           VALUES ($1, $2, $3, $4, $5, 'active')
           RETURNING id"#,
    )
    .bind(env_id)
    .bind(core_id)
    .bind(next_version)
    .bind(postings_integration_id)
    .bind(balance_integration_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| e.to_string())?;

    Ok(row.get("id"))
}

/// Return the active version for a core, if any.
/// A core has at most one row with `status = 'active'`; if multiple exist
/// the most recently created is returned.
pub async fn get_active_core_version(
    pool: &sqlx::PgPool,
    core_id: Uuid,
) -> Result<Option<CoreVersionResponse>, String> {
    let row = sqlx::query(
        r#"SELECT id, core_id, version, postings_integration_id,
                  balance_integration_id, status, created_at
             FROM core_versions
            WHERE core_id = $1 AND status = 'active'
            ORDER BY created_at DESC
            LIMIT 1"#,
    )
    .bind(core_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| e.to_string())?;

    Ok(row.map(|r| CoreVersionResponse {
        id: r.get("id"),
        core_id: r.get("core_id"),
        version: r.get("version"),
        postings_integration_id: r.get("postings_integration_id"),
        balance_integration_id: r.get("balance_integration_id"),
        status: r.get("status"),
        created_at: r.get("created_at"),
    }))
}

// ── Story — Core migration patterns ────────────────────────────

/// Strategy for migrating traffic from a source core to a target core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreMigrationStrategy {
    /// Run both cores in parallel; both serve the same traffic until
    /// cutover.
    DualWrite,
    /// Shift traffic gradually (e.g. 1% → 10% → 50% → 100%) over time.
    Gradual,
    /// Cut over entirely at a fixed point in time.
    BigBang,
}

impl CoreMigrationStrategy {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "dual_write" => Ok(Self::DualWrite),
            "gradual" => Ok(Self::Gradual),
            "big_bang" => Ok(Self::BigBang),
            other => Err(format!("unknown core migration strategy: {other}")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DualWrite => "dual_write",
            Self::Gradual => "gradual",
            Self::BigBang => "big_bang",
        }
    }
}

/// Configuration for a core migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreMigrationConfig {
    pub strategy: CoreMigrationStrategy,
    pub source_core_id: Uuid,
    pub target_core_id: Uuid,
    /// Optional scheduled cutover time. Required for `BigBang` migrations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutover_at: Option<DateTime<Utc>>,
}

/// Validate a core migration configuration.
/// Rules:
/// - `source_core_id` and `target_core_id` must differ.
/// - `BigBang` requires a `cutover_at` timestamp in the future.
/// - `Gradual` may optionally specify a `cutover_at`.
/// - `DualWrite` should not set `cutover_at` (it has no single cutover
/// point); if set, validation still passes.
pub fn validate_migration(config: &CoreMigrationConfig) -> Result<(), String> {
    if config.source_core_id == config.target_core_id {
        return Err("source_core_id and target_core_id must differ".into());
    }
    match config.strategy {
        CoreMigrationStrategy::BigBang => {
            let cutover = config
                .cutover_at
                .ok_or_else(|| "big_bang migration requires cutover_at".to_string())?;
            if cutover <= Utc::now() {
                return Err("big_bang cutover_at must be in the future".into());
            }
        }
        CoreMigrationStrategy::Gradual => {
            if let Some(cutover) = config.cutover_at {
                if cutover <= Utc::now() {
                    return Err("gradual cutover_at must be in the future".into());
                }
            }
        }
        CoreMigrationStrategy::DualWrite => {
            // No required cutover; future cutover is allowed but ignored.
        }
    }
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_strategy_round_trip() {
        for s in ["dual_write", "gradual", "big_bang"] {
            let m = CoreMigrationStrategy::from_str(s).unwrap();
            assert_eq!(m.as_str(), s);
        }
        assert!(CoreMigrationStrategy::from_str("forklift").is_err());
    }

    #[test]
    fn validate_migration_rejects_same_source_target() {
        let id = Uuid::new_v4();
        let cfg = CoreMigrationConfig {
            strategy: CoreMigrationStrategy::DualWrite,
            source_core_id: id,
            target_core_id: id,
            cutover_at: None,
        };
        assert!(validate_migration(&cfg).is_err());
    }

    #[test]
    fn validate_migration_big_bang_requires_cutover() {
        let cfg = CoreMigrationConfig {
            strategy: CoreMigrationStrategy::BigBang,
            source_core_id: Uuid::new_v4(),
            target_core_id: Uuid::new_v4(),
            cutover_at: None,
        };
        assert!(validate_migration(&cfg).is_err());
    }

    #[test]
    fn validate_migration_big_bang_future_cutover_ok() {
        let cfg = CoreMigrationConfig {
            strategy: CoreMigrationStrategy::BigBang,
            source_core_id: Uuid::new_v4(),
            target_core_id: Uuid::new_v4(),
            cutover_at: Some(Utc::now() + chrono::Duration::days(1)),
        };
        assert!(validate_migration(&cfg).is_ok());
    }

    #[test]
    fn validate_migration_big_bang_past_cutover_rejected() {
        let cfg = CoreMigrationConfig {
            strategy: CoreMigrationStrategy::BigBang,
            source_core_id: Uuid::new_v4(),
            target_core_id: Uuid::new_v4(),
            cutover_at: Some(Utc::now() - chrono::Duration::days(1)),
        };
        assert!(validate_migration(&cfg).is_err());
    }

    #[test]
    fn validate_migration_gradual_no_cutover_ok() {
        let cfg = CoreMigrationConfig {
            strategy: CoreMigrationStrategy::Gradual,
            source_core_id: Uuid::new_v4(),
            target_core_id: Uuid::new_v4(),
            cutover_at: None,
        };
        assert!(validate_migration(&cfg).is_ok());
    }

    #[test]
    fn validate_migration_dual_write_ok() {
        let cfg = CoreMigrationConfig {
            strategy: CoreMigrationStrategy::DualWrite,
            source_core_id: Uuid::new_v4(),
            target_core_id: Uuid::new_v4(),
            cutover_at: None,
        };
        assert!(validate_migration(&cfg).is_ok());
    }

    #[test]
    fn validate_migration_gradual_past_cutover_rejected() {
        let cfg = CoreMigrationConfig {
            strategy: CoreMigrationStrategy::Gradual,
            source_core_id: Uuid::new_v4(),
            target_core_id: Uuid::new_v4(),
            cutover_at: Some(Utc::now() - chrono::Duration::hours(1)),
        };
        assert!(validate_migration(&cfg).is_err());
    }

    #[test]
    fn core_version_response_serde_round_trip() {
        let id = Uuid::new_v4();
        let core_id = Uuid::new_v4();
        let now = Utc::now();
        let resp = CoreVersionResponse {
            id,
            core_id,
            version: 3,
            postings_integration_id: Some(Uuid::new_v4()),
            balance_integration_id: None,
            status: "active".into(),
            created_at: now,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: CoreVersionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, id);
        assert_eq!(back.core_id, core_id);
        assert_eq!(back.version, 3);
        assert!(back.postings_integration_id.is_some());
        assert!(back.balance_integration_id.is_none());
        assert_eq!(back.status, "active");
    }
}
