// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Payments — payment orchestration, delegates to Flow.
//! See `services/payments/DESIGN.md`.
//! Boot runs on the platform `sentin8-shell` crate (design
//! `sentin8/design/sentin8-sentin8-shell-technical-design.md`): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

// allocation in the process routes through it). Rationale in the workspace
// Cargo.toml: glibc's per-thread arenas fragment under the many-worker tokio
// runtime and never return memory; measured 4 MB+ RSS growth per request
#[allow(dead_code)]
mod admin_data;
#[allow(dead_code)]
mod app_auth;
#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod b8_flows;
#[allow(dead_code)]
mod calendars;
#[allow(dead_code)]
mod cards;
#[allow(dead_code)]
mod clu;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod config_packs;
#[allow(dead_code)]
mod cores;
#[allow(dead_code)]
mod dashboards;
#[allow(dead_code)]
mod event_streaming;
#[allow(dead_code)]
mod file_processing;
#[allow(dead_code)]
mod handlers;
mod worker;

#[allow(dead_code)]
mod admin_ui;
#[allow(dead_code)]
mod host_functions;
#[allow(dead_code)]
mod idempotency;
#[allow(dead_code)]
mod integrations;
#[allow(dead_code)]
mod interruption;
#[allow(dead_code)]
mod iso8583;
#[allow(dead_code)]
mod load_test;
#[allow(dead_code)]
mod mandates;
#[allow(dead_code)]
mod manual_decisions;
#[allow(dead_code)]
mod mdes;
#[allow(dead_code)]
mod membership_dirs;
mod openapi;
#[allow(dead_code)]
mod parameters;
pub mod policy;
#[allow(dead_code)]
mod postings;
mod registration;

#[allow(dead_code)]
mod pay_api;
#[allow(dead_code)]
mod payment_context;
#[allow(dead_code)]
mod payment_matching;
#[allow(dead_code)]
mod routes_missing;
#[allow(dead_code)]
mod routing;
#[allow(dead_code)]
mod rule_execution;
#[allow(dead_code)]
mod rules;
#[allow(dead_code)]
mod schedules;
#[allow(dead_code)]
mod sepa_flows;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod state_machine;
#[allow(dead_code)]
mod swift_agi;
#[allow(dead_code)]
mod templates;
#[allow(dead_code)]
mod tips_flows;
#[allow(dead_code)]
mod visa_dps;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("bank8:payments", "BANK8_PAYMENTS")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::PaymentsOpenApi::openapi()),
    )
    .await
}
