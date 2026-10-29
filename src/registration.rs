// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Bank8:Payments.
//! Output via `--print-registration` flag. See `sentin8/design/sentin8-service-self-registration-design.md`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, CrossSchemaGrant, ErrorCode, M2mGrant, PgRole, PolicySetDecl,
    Registration, RelationDecl, ScheduleDecl, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "bank8:payments:read,bank8:payments:write",
    role: "bank8_payments_service",
    bypass_rls: false,
    // Grants live in the bank8 vertical database only (DBX §6.6
    // database-per-vertical, schema-per-service).
    database: "bank8",
    // One declared cross-schema read: the cardholder holder binding
    // resolves the caller's Ledger customer id - SELECT-only, no
    // write path, no blanket schema grant (payments DESIGN.md §3).
    cross_schema_grants: &[CrossSchemaGrant {
        schema: "ledger",
        table: "customers",
        privilege: "SELECT",
    }],
}];

/// M2M DCR scope grants (self-registration design §3.11). One entry per
/// workload this service registers via DCR; `vertical enroll` upserts
/// `certless:<workload>` rows into `sentin8.auth_m2m_scope_grants`. Scopes
/// use the full vocabulary form (bare forms + missing grants fail-closed
/// every bus/policy/stat DCR).
/// - `bank8:payments` - inbox-first event emission via the shared inbox
///
/// (bus produce) + Shield hot-reload transport.
/// - `bank8:payments-policy` - Shield hot-reload consumer
///
/// (policy_bus_client, full colon identity).
/// - `payments-policy` - Shield stat emitter (stat_emit short form).
const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "bank8:payments",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
            "sentin8:cron:write",
        ],
    },
    // Payments emits outbox-first (the shell's 8b relay holds the bus
    // client), but grant the bare short form too so the telemetry DCR
    // call site (`payments` - payments/src/telemetry.rs) is pre-authorized;
    // the gate looks up the exact client_name.
    M2mGrant {
        workload: "payments",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
            "sentin8:cron:write",
        ],
    },
    // CERTFREE-8V: the payments→ledger posting proxy workload - the
    // flow step-handler posts batches through the ledger public API (the
    // static BANK8_LEDGER_TOKEN dev convention is retired; the ledger
    // side's scope-mirror policy set admits the posting scope).
    M2mGrant {
        workload: "bank8-payments-ledger",
        scopes: &["bank8:ledger:postings:write"],
    },
    // Shell audit-journal pusher workload (audit crate §6.8; boot step 8c).
    M2mGrant {
        workload: "payments-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    M2mGrant {
        workload: "bank8:payments-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "payments-policy",
        scopes: &["sentin8:stat:measure"],
    },
    // Embedded re-drive worker (payments DESIGN.md §2 - the merged-in
    // payments-worker): the SSE consumer's DCR workload (bus consume) and
    // the Flow re-drive source (read for the correlation-filtered lookup,
    // write for resume/retry). The DCR call sites live in worker/mod.rs;
    // the gate looks up the exact client_name.
    M2mGrant {
        workload: "payments-worker",
        scopes: &["sentin8:bus:consume"],
    },
    M2mGrant {
        workload: "payments-worker-flow",
        scopes: &["sentin8:flow:read", "sentin8:flow:write"],
    },
    // (design/sentin8-vertical-data-plane-contract.md §VDC.7):
    // the database-free HostContextResolver’s resolve workload - cache
    // miss calls Sys `GET /v1/resolve/hostname`.
    M2mGrant {
        workload: "bank8-payments-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
    // VDC §VDC.5 (on-demand sanctioned identity read): `GET /v1/users`
    // lists the env's users through Auth's admin API - never a direct
    // `sentin8.auth_users` query (that platform table does not exist in
    // the vertical's own database).
    M2mGrant {
        workload: "bank8-payments-sys",
        scopes: &["sentin8:auth:admin:read"],
    },
];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:instructions:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:instructions:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:internal:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:payments:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:logics:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:logics:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:payment-instruments:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:payment-instruments:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:account-links:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:account-links:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:rules:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:rules:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:rules:publish",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:parameters:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:parameters:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:files:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:files:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:manual-decisions:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:manual-decisions:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:admin",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:integrations:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:integrations:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:cores:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:cores:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:cards:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:cards:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:mandates:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:mandates:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:membership-directories:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:membership-directories:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:templates:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:templates:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:calendars:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:calendars:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:dashboards:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:dashboards:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:audit:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:metrics:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:tasks:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:tasks:write",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:tasks:approve",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:cards:encrypted",
    },
    // Policy-admin surface (policy design §3.6; principles §6.0b per-service scope).
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:policy:read",
    },
    AdminScope::Typed {
        role: "bank8:payments:admin",
        scope: "bank8:payments:policy:write",
    },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode {
        enum_name: "PaymentsInstructionNotFound",
        error_code: "payments_instruction_not_found",
        status_code: 404,
    },
    ErrorCode {
        enum_name: "PaymentsInstructionFailed",
        error_code: "payments_instruction_failed",
        status_code: 500,
    },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "instructions",
        label: "Instructions",
        ui_endpoint: "/v1/admin/ui/instructions",
        data_endpoint: "/v1/admin/instructions",
        icon: "0xe896",
    },
    AdminUiPage {
        route: "payments",
        label: "Payments",
        ui_endpoint: "/v1/admin/ui/payments",
        data_endpoint: "/v1/admin/payments",
        icon: "0xe482",
    },
    AdminUiPage {
        route: "rules",
        label: "Rules",
        ui_endpoint: "/v1/admin/ui/rules",
        data_endpoint: "/v1/admin/rules",
        icon: "0xe547",
    },
    AdminUiPage {
        route: "cards",
        label: "Cards",
        ui_endpoint: "/v1/admin/ui/cards",
        data_endpoint: "/v1/admin/cards",
        icon: "0xe19f",
    },
    AdminUiPage {
        route: "files",
        label: "Files",
        ui_endpoint: "/v1/admin/ui/files",
        data_endpoint: "/v1/admin/files",
        icon: "0xe2a4",
    },
    AdminUiPage {
        route: "integrations",
        label: "Integrations",
        ui_endpoint: "/v1/admin/ui/integrations",
        data_endpoint: "/v1/admin/integrations",
        icon: "0xe348",
    },
    AdminUiPage {
        route: "parameters",
        label: "Parameters",
        ui_endpoint: "/v1/admin/ui/parameters",
        data_endpoint: "/v1/admin/parameters",
        icon: "0xe683",
    },
    AdminUiPage {
        route: "cores",
        label: "Cores",
        ui_endpoint: "/v1/admin/ui/cores",
        data_endpoint: "/v1/admin/cores",
        icon: "0xe1e5",
    },
    AdminUiPage {
        route: "mandates",
        label: "Mandates",
        ui_endpoint: "/v1/admin/ui/mandates",
        data_endpoint: "/v1/admin/mandates",
        icon: "0xe88f",
    },
    AdminUiPage {
        route: "directories",
        label: "Directories",
        ui_endpoint: "/v1/admin/ui/directories",
        data_endpoint: "/v1/admin/directories",
        icon: "0xe2a3",
    },
    AdminUiPage {
        route: "calendars",
        label: "Calendars",
        ui_endpoint: "/v1/admin/ui/calendars",
        data_endpoint: "/v1/admin/calendars",
        icon: "0xe122",
    },
    AdminUiPage {
        route: "decisions",
        label: "Decisions",
        ui_endpoint: "/v1/admin/ui/decisions",
        data_endpoint: "/v1/admin/decisions",
        icon: "0xe547",
    },
    AdminUiPage {
        route: "simulator",
        label: "Simulator",
        ui_endpoint: "/v1/admin/ui/simulator",
        data_endpoint: "/v1/admin/simulator",
        icon: "0xe4cc",
    },
    AdminUiPage {
        route: "settings",
        label: "Settings",
        ui_endpoint: "/v1/admin/ui/settings",
        data_endpoint: "/v1/admin/settings",
        icon: "0xe57f",
    },
    // Sentin8:Policy admin surface (§3.6, post pattern).
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
    AdminUiPage {
        route: "relations",
        label: "Relations",
        ui_endpoint: "/v1/admin/ui/relations",
        data_endpoint: "/v1/admin/relations",
        icon: "0xe572",
    },
    AdminUiPage {
        route: "attributes",
        label: "Attributes",
        ui_endpoint: "/v1/admin/ui/attributes",
        data_endpoint: "/v1/admin/attributes",
        icon: "0xe8d3",
    },
];

/// Default declarative policy set (Sentin8:Policy design §3.2/§3.4,
/// seeded by `vertical enroll` as `origin='platform'`, `mode='enforced'`):
/// action-granular scope permits over the LIVE effective scope set - the
/// exact mirror of the gates this service's handlers evaluate in step 5
/// (policy design §4.3). Step 5 is the only
/// gate; shadow is the emergency one-UPDATE rollback lever only.
/// The Shield text of the declared scope-mirror set - public so the
/// policy wiring tests assert against the REAL seed.
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"bank8:payments:account-links:read\", resource) when { principal.scopes.contains(\"bank8:payments:account-links:read\") };\npermit(principal, action == Action::\"bank8:payments:account-links:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:account-links:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:account-links:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:account-links:write\", resource) when { principal.scopes.contains(\"bank8:payments:account-links:write\") };\npermit(principal, action == Action::\"bank8:payments:account-links:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:account-links:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:account-links:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:audit:read\", resource) when { principal.scopes.contains(\"bank8:payments:audit:read\") };\npermit(principal, action == Action::\"bank8:payments:audit:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:audit:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:audit:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:calendars:read\", resource) when { principal.scopes.contains(\"bank8:payments:calendars:read\") };\npermit(principal, action == Action::\"bank8:payments:calendars:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:calendars:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:calendars:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:calendars:write\", resource) when { principal.scopes.contains(\"bank8:payments:calendars:write\") };\npermit(principal, action == Action::\"bank8:payments:calendars:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:calendars:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:calendars:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:cards:read\", resource) when { principal.scopes.contains(\"bank8:payments:cards:read\") };\npermit(principal, action == Action::\"bank8:payments:cards:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:cards:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:cards:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"bank8:payments:cards:read\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"bank8:payments:cards:write\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"created\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"id\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"payments\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"virtual\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:cards:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:cores:read\", resource) when { principal.scopes.contains(\"bank8:payments:cores:read\") };\npermit(principal, action == Action::\"bank8:payments:cores:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:cores:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:cores:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:cores:write\", resource) when { principal.scopes.contains(\"bank8:payments:cores:write\") };\npermit(principal, action == Action::\"bank8:payments:cores:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:cores:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:cores:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:dashboards:read\", resource) when { principal.scopes.contains(\"bank8:payments:dashboards:read\") };\npermit(principal, action == Action::\"bank8:payments:dashboards:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:dashboards:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:dashboards:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:dashboards:write\", resource) when { principal.scopes.contains(\"bank8:payments:dashboards:write\") };\npermit(principal, action == Action::\"bank8:payments:dashboards:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:dashboards:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:dashboards:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:files:read\", resource) when { principal.scopes.contains(\"bank8:payments:files:read\") };\npermit(principal, action == Action::\"bank8:payments:files:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:files:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:files:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:files:write\", resource) when { principal.scopes.contains(\"bank8:payments:files:write\") };\npermit(principal, action == Action::\"bank8:payments:files:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:files:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:files:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:admin\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:calendars:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:cards:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:cores:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:files:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:instructions:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:integrations:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:mandates:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:manual-decisions:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:membership-directories:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:parameters:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:payments:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"bank8:payments:rules:read\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:instructions:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:instructions:write\", resource) when { principal.scopes.contains(\"bank8:payments:instructions:write\") };\npermit(principal, action == Action::\"bank8:payments:instructions:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:instructions:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:instructions:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:integrations:read\", resource) when { principal.scopes.contains(\"bank8:payments:integrations:read\") };\npermit(principal, action == Action::\"bank8:payments:integrations:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:integrations:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:integrations:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:integrations:write\", resource) when { principal.scopes.contains(\"bank8:payments:integrations:write\") };\npermit(principal, action == Action::\"bank8:payments:integrations:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:integrations:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:integrations:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:internal:read\", resource) when { principal.scopes.contains(\"bank8:payments:internal:read\") };\npermit(principal, action == Action::\"bank8:payments:internal:read\", resource) when { principal.scopes.contains(\"bank8:payments:logics:write\") };\npermit(principal, action == Action::\"bank8:payments:internal:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:internal:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:internal:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:issuance:read\", resource) when { principal.scopes.contains(\"bank8:payments:issuance:read\") };\npermit(principal, action == Action::\"bank8:payments:issuance:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:issuance:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:issuance:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:issuance:write\", resource) when { principal.scopes.contains(\"bank8:payments:issuance:write\") };\npermit(principal, action == Action::\"bank8:payments:issuance:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:issuance:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:issuance:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:logics:read\", resource) when { principal.scopes.contains(\"bank8:payments:logics:read\") };\npermit(principal, action == Action::\"bank8:payments:logics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:logics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:logics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:logics:write\", resource) when { principal.scopes.contains(\"bank8:payments:logics:write\") };\npermit(principal, action == Action::\"bank8:payments:logics:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:logics:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:logics:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:mandates:read\", resource) when { principal.scopes.contains(\"bank8:payments:mandates:read\") };\npermit(principal, action == Action::\"bank8:payments:mandates:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:mandates:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:mandates:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:mandates:write\", resource) when { principal.scopes.contains(\"bank8:payments:mandates:write\") };\npermit(principal, action == Action::\"bank8:payments:mandates:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:mandates:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:mandates:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:manual-decisions:read\", resource) when { principal.scopes.contains(\"bank8:payments:manual-decisions:read\") };\npermit(principal, action == Action::\"bank8:payments:manual-decisions:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:manual-decisions:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:manual-decisions:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:manual-decisions:write\", resource) when { principal.scopes.contains(\"bank8:payments:manual-decisions:write\") };\npermit(principal, action == Action::\"bank8:payments:manual-decisions:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:manual-decisions:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:manual-decisions:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:membership-directories:read\", resource) when { principal.scopes.contains(\"bank8:payments:membership-directories:read\") };\npermit(principal, action == Action::\"bank8:payments:membership-directories:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:membership-directories:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:membership-directories:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:membership-directories:write\", resource) when { principal.scopes.contains(\"bank8:payments:membership-directories:write\") };\npermit(principal, action == Action::\"bank8:payments:membership-directories:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:membership-directories:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:membership-directories:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:metrics:read\", resource) when { principal.scopes.contains(\"bank8:payments:metrics:read\") };\npermit(principal, action == Action::\"bank8:payments:metrics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:metrics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:metrics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:openmetrics:read\", resource) when { principal.scopes.contains(\"bank8:payments:openmetrics:read\") };\npermit(principal, action == Action::\"bank8:payments:openmetrics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:openmetrics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:openmetrics:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:parameters:read\", resource) when { principal.scopes.contains(\"bank8:payments:parameters:read\") };\npermit(principal, action == Action::\"bank8:payments:parameters:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:parameters:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:parameters:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:parameters:write\", resource) when { principal.scopes.contains(\"bank8:payments:parameters:write\") };\npermit(principal, action == Action::\"bank8:payments:parameters:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:parameters:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:parameters:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:payment-instruments:read\", resource) when { principal.scopes.contains(\"bank8:payments:payment-instruments:read\") };\npermit(principal, action == Action::\"bank8:payments:payment-instruments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:payment-instruments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:payment-instruments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:payment-instruments:write\", resource) when { principal.scopes.contains(\"bank8:payments:payment-instruments:write\") };\npermit(principal, action == Action::\"bank8:payments:payment-instruments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:payment-instruments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:payment-instruments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:payments:read\", resource) when { principal.scopes.contains(\"bank8:payments:payments:read\") };\npermit(principal, action == Action::\"bank8:payments:payments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:payments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:payments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:payments:write\", resource) when { principal.scopes.contains(\"bank8:payments:payments:write\") };\npermit(principal, action == Action::\"bank8:payments:payments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:payments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:payments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:publish\", resource) when { principal.scopes.contains(\"bank8:payments:rules:publish\") };\npermit(principal, action == Action::\"bank8:payments:rules:publish\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:publish\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:publish\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:read\", resource) when { principal.scopes.contains(\"bank8:payments:rules:read\") };\npermit(principal, action == Action::\"bank8:payments:rules:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:write\", resource) when { principal.scopes.contains(\"bank8:payments:rules:write\") };\npermit(principal, action == Action::\"bank8:payments:rules:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:rules:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:sandbox:write\", resource) when { principal.scopes.contains(\"bank8:payments:sandbox:write\") };\npermit(principal, action == Action::\"bank8:payments:sandbox:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:sandbox:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:sandbox:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:scheduled-payments:read\", resource) when { principal.scopes.contains(\"bank8:payments:scheduled-payments:read\") };\npermit(principal, action == Action::\"bank8:payments:scheduled-payments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:scheduled-payments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:scheduled-payments:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:scheduled-payments:write\", resource) when { principal.scopes.contains(\"bank8:payments:scheduled-payments:write\") };\npermit(principal, action == Action::\"bank8:payments:scheduled-payments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:scheduled-payments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:scheduled-payments:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:approve\", resource) when { principal.scopes.contains(\"bank8:payments:tasks:approve\") };\npermit(principal, action == Action::\"bank8:payments:tasks:approve\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:approve\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:approve\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:read\", resource) when { principal.scopes.contains(\"bank8:payments:tasks:read\") };\npermit(principal, action == Action::\"bank8:payments:tasks:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:write\", resource) when { principal.scopes.contains(\"bank8:payments:tasks:write\") };\npermit(principal, action == Action::\"bank8:payments:tasks:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:tasks:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:templates:read\", resource) when { principal.scopes.contains(\"bank8:payments:templates:read\") };\npermit(principal, action == Action::\"bank8:payments:templates:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:templates:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:templates:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:templates:write\", resource) when { principal.scopes.contains(\"bank8:payments:templates:write\") };\npermit(principal, action == Action::\"bank8:payments:templates:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:templates:write\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:templates:write\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };\npermit(principal, action == Action::\"bank8:payments:users:read\", resource) when { principal.scopes.contains(\"bank8:payments:users:read\") };\npermit(principal, action == Action::\"bank8:payments:users:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bank8:payments:users:read\", resource) when { principal.scopes.contains(\"sentin8:sys:org:admin\") };\npermit(principal, action == Action::\"bank8:payments:users:read\", resource) when { principal.scopes.contains(\"sentin8:sys:env:admin\") };";

const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for bank8:payments over the LIVE effective scope set (design §3.1d). Step 5 is the only gate.",
    // Shield text lives in SCOPE_MIRROR_POLICIES (single source).
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples (design §3.1c) - none declared by this
/// service today; env admins author their own graph via the relations
/// admin API (approver↔payment edges for payments, holder edges for
/// fdx consents are tenant-authored).
const RELATIONS: &[RelationDecl] = &[];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::PaymentsOpenApi::openapi())
        .unwrap_or(serde_json::Value::Null)
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "bank8:payments",
        subdomain: "bank8-payments",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        // Declarative default schedules (SDD §2.4): the well-known
        // Payments set, previously seeded at boot via
        // `schedules::seed_default_schedules`, now provisioned by
        // `vertical enroll`. All fire `/v1/internal/schedules/trigger`
        // with `scheduleType` distinguishing the run.
        schedules: &[
            ScheduleDecl {
                schedule_type: "tips_sweeper",
                cron_expression: "*/10 * * * *",
                timezone: "UTC",
                target_config: r#"{"internalPath": "/v1/internal/schedules/trigger", "scheduleType": "tips_sweeper"}"#,
                max_retries: 3,
            },
            ScheduleDecl {
                schedule_type: "sepa_ct_daily_cutoff",
                cron_expression: "0 23 * * *",
                timezone: "UTC",
                target_config: r#"{"internalPath": "/v1/internal/schedules/trigger", "scheduleType": "sepa_ct_daily_cutoff"}"#,
                max_retries: 3,
            },
            ScheduleDecl {
                schedule_type: "b8_credit_transfer_daily",
                cron_expression: "0 18 * * *",
                timezone: "UTC",
                target_config: r#"{"internalPath": "/v1/internal/schedules/trigger", "scheduleType": "b8_credit_transfer_daily"}"#,
                max_retries: 3,
            },
            ScheduleDecl {
                schedule_type: "authorisation_expiry_check",
                cron_expression: "* * * * *",
                timezone: "UTC",
                target_config: r#"{"internalPath": "/v1/internal/schedules/trigger", "scheduleType": "authorisation_expiry_check"}"#,
                max_retries: 3,
            },
            ScheduleDecl {
                schedule_type: "stale_instruction_cleanup",
                cron_expression: "0 * * * *",
                timezone: "UTC",
                target_config: r#"{"internalPath": "/v1/internal/schedules/trigger", "scheduleType": "stale_instruction_cleanup"}"#,
                max_retries: 3,
            },
        ],
        admin_ui: Some(AdminUi {
            label: "Payments",
            icon: "0xe482",
            service_flag: "payments",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
