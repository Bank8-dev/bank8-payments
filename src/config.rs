// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Payments configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

/// Feature gates for Payments (Story , - full set of 15).
/// Each gate is loaded from an env var (`BANK8_PAYMENTS_FEATURE_*`) and defaults
/// to enabled (`true`) unless explicitly set to `0`/`false`/`off`. A disabled
/// master gate (`payments`) disables the entire service; handlers return 503.
#[derive(Debug, Clone)]
pub struct FeatureGates {
    /// Master gate - when false, the entire Payments service is disabled.
    pub payments: bool,
    /// Sync instruction path (POST /v1/instructions without async flag).
    pub instructions_sync: bool,
    /// Async instruction path (worker-driven).
    pub instructions_async: bool,
    /// Card features (cards, cardholders, card products, tokens, 3DS).
    pub cards: bool,
    /// Encrypted PCI-scoped card operations (sessions, PIN).
    pub cards_encrypted: bool,
    /// File-based payment processing.
    pub files: bool,
    /// Direct debit mandates.
    pub mandates: bool,
    /// Scheduled/recurring payments.
    pub recurring: bool,
    /// Manual decision workflows.
    pub manual_decisions: bool,
    /// Task management and approval workflows.
    pub tasks: bool,
    /// Manual payment initiation templates.
    pub templates: bool,
    /// Dashboard and aggregation queries.
    pub dashboards: bool,
    /// Scheme membership directory queries.
    pub membership_directories: bool,
    /// Calendar and scheduling operations.
    pub calendars: bool,
    /// Sandbox-only simulators.
    pub sandbox: bool,
}

impl FeatureGates {
    pub fn from_env() -> Self {
        let flag = |key: &str, default: bool| -> bool {
            match env::var(key) {
                Ok(v) if v.is_empty() => default,
                Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "on" | "yes"),
                Err(_) => default,
            }
        };
        Self {
            payments: flag("BANK8_PAYMENTS_FEATURE_PAYM8", true),
            instructions_sync: flag("BANK8_PAYMENTS_FEATURE_INSTRUCTIONS_SYNC", true),
            instructions_async: flag("BANK8_PAYMENTS_FEATURE_INSTRUCTIONS_ASYNC", true),
            cards: flag("BANK8_PAYMENTS_FEATURE_CARDS", true),
            cards_encrypted: flag("BANK8_PAYMENTS_FEATURE_CARDS_ENCRYPTED", true),
            files: flag("BANK8_PAYMENTS_FEATURE_FILES", true),
            mandates: flag("BANK8_PAYMENTS_FEATURE_MANDATES", true),
            recurring: flag("BANK8_PAYMENTS_FEATURE_RECURRING", true),
            manual_decisions: flag("BANK8_PAYMENTS_FEATURE_MANUAL_DECISIONS", true),
            tasks: flag("BANK8_PAYMENTS_FEATURE_TASKS", true),
            templates: flag("BANK8_PAYMENTS_FEATURE_TEMPLATES", true),
            dashboards: flag("BANK8_PAYMENTS_FEATURE_DASHBOARDS", true),
            membership_directories: flag("BANK8_PAYMENTS_FEATURE_MEMBERSHIP_DIRECTORIES", true),
            calendars: flag("BANK8_PAYMENTS_FEATURE_CALENDARS", true),
            sandbox: flag("BANK8_PAYMENTS_FEATURE_SANDBOX", false),
        }
    }

    /// Check a named feature gate. Returns true if the gate is enabled.
    pub fn is_enabled(&self, gate: FeatureGate) -> bool {
        if !self.payments {
            return false;
        }
        match gate {
            FeatureGate::Payments => self.payments,
            FeatureGate::InstructionsSync => self.instructions_sync,
            FeatureGate::InstructionsAsync => self.instructions_async,
            FeatureGate::Cards => self.cards,
            FeatureGate::CardsEncrypted => self.cards_encrypted,
            FeatureGate::Files => self.files,
            FeatureGate::Mandates => self.mandates,
            FeatureGate::Recurring => self.recurring,
            FeatureGate::ManualDecisions => self.manual_decisions,
            FeatureGate::Tasks => self.tasks,
            FeatureGate::Templates => self.templates,
            FeatureGate::Dashboards => self.dashboards,
            FeatureGate::MembershipDirectories => self.membership_directories,
            FeatureGate::Calendars => self.calendars,
            FeatureGate::Sandbox => self.sandbox,
        }
    }
}

/// Named feature gates for Payments (Story ).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureGate {
    Payments,
    InstructionsSync,
    InstructionsAsync,
    Cards,
    CardsEncrypted,
    Files,
    Mandates,
    Recurring,
    ManualDecisions,
    Tasks,
    Templates,
    Dashboards,
    MembershipDirectories,
    Calendars,
    Sandbox,
}

/// Manual `Debug` - `FuncClient` (and the token fields) carry transport
/// internals that must never log.
#[derive(Clone)]
pub struct PaymentsConfig {
    pub port: u16,
    pub database_url: String,
    pub sentin8_auth_issuer: String,
    pub sentin8_auth_jwks_url: String,
    pub sentin8_bus_url: String,
    pub sentin8_flow_url: String,
    pub sentin8_flow_token: String,
    pub sentin8_func_url: String,
    /// Certificate-presenting Func client (CERTFREE-4F - the `payments`
    /// workload certificate presents in the TLS handshake). Built at
    /// boot; `None` degrades the Func lanes loudly.
    pub func_client: Option<sentin8_func_sdk::client::FuncClient>,
    /// Static token for Flow's CallbackConfig (Flow's per-execution
    /// proxy-back contract - the token Flow presents BACK to this
    /// service's internal API; NOT the Func client's own auth).
    pub sentin8_func_token: String,
    /// Sentin8:Cron base URL - recurring-payment schedule registration
    /// (design §10) and the default-schedules seed at boot.
    pub sentin8_cron_url: String,
    /// Dev-only override token for Cron; production sources the token from
    /// the DCR-registered `payments` workload (mirrors `func_token`).
    pub sentin8_cron_token: String,
    pub ledger_url: String,
    /// Certificate-presenting transport for the payments→ledger posting
    /// proxy (workload `bank8-payments-ledger`; CERTFREE-8V - no static
    /// token).
    pub ledger_http: Option<reqwest::Client>,
    pub stream_family: String,
    /// Story - Stat config for Payments telemetry.
    pub sentin8_stat_url: String,
    pub sentin8_stat_property_id: uuid::Uuid,
    /// Story - feature gates.
    pub features: FeatureGates,
    /// Certificate-presenting transport for the `payments-worker-flow`
    /// workload (CERTFREE-4V - no M2M token exists): request-time Flow
    /// calls (instruction logic delegation, repair, file debatch) ride
    /// it - Flow's TLS layer authenticates the handshake and the
    /// registry map authorizes the flow scopes. `None` until boot mints
    /// it (callers degrade to the documented dev-plain client).
    pub flow_http: Option<reqwest::Client>,
    /// Shared Auth client - constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    pub sentin8_auth_client: AuthClient,
}

impl PaymentsConfig {
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("BANK8_PAYMENTS_PORT")
                .expect("BANK8_PAYMENTS_PORT must be set by captain")
                .parse()
                .expect("BANK8_PAYMENTS_PORT must be a valid u16"),
            database_url: env::var("BANK8_PAYMENTS_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            sentin8_flow_url: env::var("SENTIN8_FLOW_URL")
                .unwrap_or_else(|_| cfg.sentin8_flow_url()),
            sentin8_flow_token: env::var("SENTIN8_FLOW_TOKEN")
                .unwrap_or_else(|_| "payments-dev".into()),
            sentin8_func_url: env::var("SENTIN8_FUNC_URL")
                .unwrap_or_else(|_| cfg.sentin8_func_url()),
            func_client: None,
            sentin8_func_token: env::var("SENTIN8_FUNC_TOKEN")
                .unwrap_or_else(|_| "payments-dev".into()),
            sentin8_cron_url: env::var("SENTIN8_CRON_URL")
                .unwrap_or_else(|_| cfg.sentin8_cron_url()),
            sentin8_cron_token: env::var("SENTIN8_CRON_TOKEN")
                .unwrap_or_else(|_| "payments-dev".into()),
            ledger_url: env::var("BANK8_LEDGER_URL")
                .unwrap_or_else(|_| format!("https://{}", cfg.platform_domain("bank8:ledger"))),
            ledger_http: None,
            stream_family: env::var("BANK8_PAYMENTS_STREAM_FAMILY")
                .unwrap_or_else(|_| crate::event_streaming::STREAM_FAMILY.into()),
            sentin8_stat_url: env::var("SENTIN8_STAT_URL")
                .unwrap_or_else(|_| cfg.sentin8_stat_url()),
            sentin8_stat_property_id: env::var("BANK8_PAYMENTS_STAT_PROPERTY_ID")
                .ok()
                .and_then(|s| uuid::Uuid::parse_str(&s).ok())
                .unwrap_or_else(|| {
                    uuid::Uuid::parse_str("a0000000-0000-0000-0000-000000000003").unwrap()
                }),
            features: FeatureGates::from_env(),
            flow_http: None,
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }

    /// The request-time Flow transport (CERTFREE-4V): the
    /// `payments-worker-flow` workload certificate presents in the TLS
    /// handshake. `None` until `server::build_state` mints it.
    pub fn flow_http(&self) -> Option<&reqwest::Client> {
        self.flow_http.as_ref()
    }
}
impl std::fmt::Debug for PaymentsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaymentsConfig")
            .field("port", &self.port)
            .field("database_url", &"<redacted>")
            .field("sentin8_auth_issuer", &self.sentin8_auth_issuer)
            .field("func_client", &self.func_client.is_some())
            .field("ledger_http", &self.ledger_http.is_some())
            .finish_non_exhaustive()
    }
}
