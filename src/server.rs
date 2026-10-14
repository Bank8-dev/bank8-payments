// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Payments.

use std::sync::Arc;

use axum::routing::{delete, get, post, put};

use crate::handlers::{self, AppState};

/// Build a cert-presenting HTTP transport for `workload` (CERTFREE-4V,
/// auth DESIGN §4.3f): mint-or-load the Acme-issued pair and wrap it in
/// a reqwest client. The receiving service's TLS layer authenticates the
/// handshake and the enroll-published registry map authorizes the
/// scopes — no bearer token exists on this path.
///
/// # Errors
/// Returns the certificate-ensure or transport-build failure (the
/// caller logs and degrades).
async fn build_workload_http(
    auth_issuer: &str,
    workload: &str,
) -> anyhow::Result<reqwest::Client> {
    let cert = sentin8::auth::m2m::ensure_workload_certificate(
        auth_issuer,
        workload,
        &sentin8::auth::m2m::platform_ca_path(),
    )
    .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("workload '{workload}' transport: {e}"))
}

pub async fn build_state(core: sentin8::shell::ServiceCore)
    -> anyhow::Result<crate::handlers::AppState> {
    let mut config = crate::config::PaymentsConfig::from_env();

    // Request-time Flow transport (CERTFREE-4V): instruction logic
    // delegation, repair, and file debatch call Flow with the
    // `payments-worker-flow` workload CERTIFICATE — the TLS handshake IS
    // the identity; the registry map authorizes the flow scopes
    // (registration.rs::M2M_GRANTS). Non-fatal — those calls degrade to
    // the documented dev-plain client until the next boot.
    match build_workload_http(&config.sentin8_auth_issuer, "payments-worker-flow").await {
        Ok(http) => config.flow_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "payments-worker-flow transport unavailable — request-time Flow calls degraded"),
    }
    // CERTFREE-8V: the ledger posting proxy transport — the
    // `bank8-payments-ledger` workload certificate presents in the TLS
    // handshake (the static BANK8_LEDGER_TOKEN dev convention is
    // retired). None → the posting step 503s loudly at the site gate.
    match build_workload_http(&config.sentin8_auth_issuer, "bank8-payments-ledger").await {
        Ok(http) => config.ledger_http = Some(http),
        Err(e) => tracing::warn!(error = %e, "payments ledger posting transport unavailable — posting steps degraded"),
    }
    // CERTFREE-4F: the direct Func lanes (module migration + rule
    // execution) present the `payments` workload certificate — Func's
    // cert-first gate resolves it against the registry map. None → the
    // lanes 503 loudly. (Flow's CallbackConfig token is a separate
    // contract — the token Flow presents BACK to this service's
    // internal API — and stays.)
    if !config.sentin8_func_url.is_empty() {
        match sentin8::auth::m2m::ensure_workload_certificate(
            &config.sentin8_auth_issuer,
            "payments",
            &sentin8::auth::m2m::platform_ca_path(),
        )
        .await
        {
            Ok(cert) => {
                match sentin8_func_sdk::client::FuncClient::with_workload_identity(
                    &config.sentin8_func_url,
                    &cert.ca_cert_path,
                    &cert.cert_path,
                    &cert.key_path,
                ) {
                    Ok(c) => config.func_client = Some(c),
                    Err(e) => tracing::warn!(error = %e, "payments func transport build failed — Func lanes degraded"),
                }
            }
            Err(e) => tracing::warn!(error = %e, "payments func certificate not ready — Func lanes degraded"),
        }
    }    // Default schedules (SDD §2.4) are declarative — the registration's
    // `schedules` section provisions them at enroll time; payments makes
    // no boot-time cron calls. The ticker proxy-backs into
    // `/v1/internal/schedules/trigger` on each fire.

    // Embedded re-drive worker (payments DESIGN.md §2 — the merged-in
    // payments-worker loop): spawn the Bus SSE consumer that turns
    // `bank8:payments:instruction:*` events into Flow resume/retry. Shares
    // the service's capped pool; runs until process shutdown.
    crate::worker::spawn(core.pool.clone(), &config).await;

    // ── Sentin8:Policy ──────────────────────────────
    // Load the service's policy sets; an unparsable policy text REFUSES TO
    // START (fail-closed at boot, design §3.3). Hot-reload consumes the
    // `policy` stream as a direct consumer (design §3.2); deny/would-deny
    // decisions emit to Stat (§4.2f). The engine is stored in AppState so
    // handlers gate via `policy::require` (step 5 is the ONLY gate).
    // ── Sentin8:Policy (§4.2b — shell-owned boot): consume the
    // engine the shell booted in step 8 — no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        config: Arc::new(config),
        pool: core.pool.clone(),
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "bank8:payments".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine,
            auth_client: Arc::new(core.config.sentin8_auth_client.clone()),
        },
    };

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` — custom payload).
pub fn routes(router: axum::Router<crate::handlers::AppState>)
    -> axum::Router<crate::handlers::AppState> {
   router
        .route("/v1/health", get(handlers::health))
        // Instruction API
        .route("/v1/instructions", post(handlers::create_instruction).get(handlers::list_instructions))
        .route("/v1/instructions/{id}", get(handlers::get_instruction))
        .route("/v1/instructions/{id}/retry", post(handlers::retry_instruction))
        .route("/v1/instructions/{id}/cancel", post(handlers::cancel_instruction))
        // Payment API
        .route("/v1/payments", get(handlers::list_payments))
        .route("/v1/payments/{id}", get(handlers::get_payment))
        // Logic API
        .route("/v1/logics", post(handlers::create_logic).get(handlers::list_logics))
        .route("/v1/logics/{id}", get(crate::routes_missing::get_logic))
        // Logic API — WASM migration (Story )
        .route("/v1/logics/{id}/migrate-wasm", post(handlers::migrate_logic_to_wasm))
        // Routing — Payment Instruments (Story )
        .route("/v1/payment-instruments", post(handlers::create_payment_instrument).get(handlers::list_payment_instruments))
        .route("/v1/payment-instruments/{id}", get(handlers::get_payment_instrument).patch(handlers::update_payment_instrument).delete(handlers::delete_payment_instrument))
        // Routing — Account Links (Story )
        .route("/v1/account-links", post(handlers::create_account_link).get(handlers::list_account_links))
        .route("/v1/account-links/{id}", get(handlers::get_account_link).delete(handlers::delete_account_link))
        // Card operations — Story
        .route("/v1/cards/{id}/replace", post(crate::routes_missing::replace_card))
        .route("/v1/cards/{id}/activate", post(crate::routes_missing::activate_card))
        .route("/v1/cards/{id}/freeze", post(crate::routes_missing::freeze_card))
        .route("/v1/cards/{id}/unfreeze", post(crate::routes_missing::unfreeze_card))
        .route("/v1/card-tokens", get(crate::routes_missing::list_card_tokens))
        .route("/v1/3ds-records", get(crate::routes_missing::get_3ds_records))
        // Tasks API
        .route("/v1/tasks", get(crate::routes_missing::list_tasks))
        .route("/v1/tasks/{id}", get(crate::routes_missing::get_task))
        .route("/v1/tasks/{id}/claim", post(crate::routes_missing::claim_task))
        .route("/v1/tasks/{id}/approve", post(crate::routes_missing::approve_task))
        .route("/v1/tasks/{id}/reject", post(crate::routes_missing::reject_task))
        // Aggregations
        .route("/v1/aggregations", get(crate::routes_missing::query_aggregations))
        // Rules Engine
        .route("/v1/rules", post(handlers::create_rule).get(handlers::list_rules))
        .route("/v1/rules/{id}/publish", post(handlers::publish_rule_version))
        .route("/v1/rule-sets", post(handlers::create_rule_set).get(handlers::list_rule_sets))
        // Parameters (Story )
        .route("/v1/parameters", post(handlers::create_parameter).get(handlers::list_parameters))
        .route("/v1/parameters/{id}", get(handlers::get_parameter).patch(handlers::update_parameter).delete(handlers::delete_parameter))
        // Integrations (Story )
        .route("/v1/integrations", post(handlers::create_integration).get(handlers::list_integrations))
        .route("/v1/integrations/{id}", get(handlers::get_integration).patch(handlers::update_integration).delete(handlers::delete_integration))
        // Cores (Story )
        .route("/v1/cores", post(handlers::create_core).get(handlers::list_cores))
        .route("/v1/cores/{id}", get(handlers::get_core).patch(handlers::update_core).delete(handlers::delete_core))
        // Core Versions (Story )
        .route("/v1/cores/{id}/versions", post(handlers::create_core_version))
        // Card Issuing CRUD (Story )
        .route("/v1/cardholders", post(handlers::create_cardholder).get(handlers::list_cardholders))
        .route("/v1/cardholders/{id}", get(handlers::get_cardholder))
        .route("/v1/cards", post(handlers::create_card).get(handlers::list_cards))
        .route("/v1/cards/{id}", get(handlers::get_card).patch(handlers::update_card))
        // Card operations — encrypted sessions, PIN (Story )
        .route("/v1/cards/{id}/encrypted-session", post(handlers::create_encrypted_session))
        .route("/v1/cards/{id}/pin/verify", post(handlers::verify_pin))
        .route("/v1/cards/{id}/pin/change", post(handlers::change_pin))
        .route("/v1/card-products", post(handlers::create_card_product).get(handlers::list_card_products))
        .route("/v1/card-products/{id}", get(handlers::get_card_product))
        .route("/v1/account-ranges", post(handlers::create_account_range).get(handlers::list_account_ranges))
        // Audit API (Story )
        .route("/v1/audit", get(handlers::list_audit_events))
        // OpenMetrics (Story )
        .route("/v1/metrics", get(handlers::metrics))
        // Files & Instruction Files (Story )
        .route("/v1/files", post(handlers::upload_file).get(handlers::list_files))
        .route("/v1/files/{id}", get(handlers::get_file))
        .route("/v1/files/{id}/submit", post(crate::routes_missing::submit_file))
        // ── Internal: Flow proxy-back (file debatch, design §10) ─────────
        .route("/v1/internal/files/debatch", post(crate::file_processing::debatch_step))
        .route("/v1/instruction-files", post(handlers::create_instruction_file).get(handlers::list_instruction_files))
        .route("/v1/instruction-batches", get(crate::routes_missing::list_instruction_batches))
        .route("/v1/instruction-file-specifications", post(handlers::create_specification).get(handlers::list_specifications))
        // Manual Decisions (Story )
        .route("/v1/manual-decisions", get(handlers::list_manual_decisions))
        .route("/v1/manual-decisions/{id}", get(handlers::get_manual_decision))
        .route("/v1/manual-decisions/{id}/submit", post(handlers::submit_manual_decision))
        // Templates (Story )
        .route("/v1/templates", post(crate::templates::create_template).get(crate::templates::list_templates))
        .route("/v1/templates/{id}", get(crate::templates::get_template))
        .route("/v1/templates/{id}/versions", post(crate::templates::create_template_version))
        .route("/v1/templates/{id}/publish", post(crate::templates::publish_template))
        // Mandates (Story )
        .route("/v1/mandates", post(handlers::create_mandate).get(handlers::list_mandates))
        .route("/v1/mandates/{id}", get(handlers::get_mandate).patch(handlers::update_mandate))
        // Membership Directories (Story )
        .route("/v1/membership-directories", post(handlers::create_membership_directory).get(handlers::list_membership_directories))
        .route("/v1/membership-directories/{id}", get(handlers::get_membership_directory))
        // Calendars (Story )
        .route("/v1/calendars", post(crate::calendars::create_calendar).get(crate::calendars::list_calendars))
        .route("/v1/business-day-definitions", post(crate::calendars::create_business_day_definition).get(crate::calendars::list_business_day_definitions))
        // Dashboards (.143)
        .route("/v1/dashboards", post(crate::dashboards::create_dashboard).get(crate::dashboards::list_dashboards))
        .route("/v1/dashboards/{id}", get(crate::dashboards::get_dashboard))
        .route("/v1/dashboards/{id}/versions", post(crate::dashboards::create_dashboard_version))
        .route("/v1/dashboards/{id}/publish", post(crate::dashboards::publish_dashboard))
        // Proxy-back (Flow calls this)
        .route("/v1/internal/steps/execute", post(handlers::execute_step))
        // Internal API endpoints for proxy-back (Story )
        // These are called by Func on behalf of WASM modules (host
        // functions). They do NOT perform auth-scope checks.
        .route("/v1/internal/instructions/{id}", get(handlers::get_instruction_internal).patch(handlers::update_instruction_internal))
        .route("/v1/internal/payments/{id}", get(handlers::get_payment_internal))
        .route("/v1/internal/payment-instruments/{id}", get(handlers::get_payment_instrument_internal))
        .route("/v1/internal/account-links/{id}", get(handlers::get_account_link_internal))
        .route("/v1/internal/parameters/{id}", get(handlers::get_parameter_internal))
        .route("/v1/internal/rules/{id}", get(handlers::get_rule_internal))
        .route("/v1/internal/integrations/{id}", get(handlers::get_integration_internal))
        .route("/v1/internal/mandates/{id}", get(handlers::get_mandate_internal))
        .route("/v1/internal/manual-decisions/{id}", get(handlers::get_manual_decision_internal))
        .route("/v1/internal/calendars/{id}", get(handlers::get_calendar_internal))
        .route("/v1/internal/cards/{id}", get(handlers::get_card_internal))
        .route("/v1/internal/cardholders/{id}", get(handlers::get_cardholder_internal))
        // Cron proxy-back (Story )
        .route("/v1/internal/schedules/trigger", post(handlers::trigger_schedule_internal))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        // Admin data endpoints (RFW data plane)
        .route("/v1/admin/overview", get(crate::admin_data::overview))
        .route("/v1/admin/instructions", get(crate::admin_data::list_instructions_admin))
        .route("/v1/admin/payments", get(crate::admin_data::list_payments_admin))
        .route("/v1/admin/rules", get(crate::admin_data::list_rules_admin))
        .route("/v1/admin/cards", get(crate::admin_data::list_cards_admin))
        .route("/v1/admin/files", get(crate::admin_data::list_files_admin))
        .route("/v1/admin/integrations", get(crate::admin_data::list_integrations_admin))
        .route("/v1/admin/parameters", get(crate::admin_data::list_parameters_admin))
        .route("/v1/admin/cores", get(crate::admin_data::list_cores_admin))
        .route("/v1/admin/mandates", get(crate::admin_data::list_mandates_admin))
        .route("/v1/admin/directories", get(crate::admin_data::list_directories_admin))
        .route("/v1/admin/calendars", get(crate::admin_data::list_calendars_admin))
        .route("/v1/admin/decisions", get(crate::admin_data::list_decisions_admin))
        .route("/v1/admin/settings", get(crate::admin_data::get_settings_admin))
        .route("/v1/admin/simulator", get(crate::admin_data::get_simulator_admin))
        // Business API handlers.
        // : async integration callback (token URL; no auth scope).
        .route("/v1/integrations/callback/{token}", post(crate::pay_api::integration_callback))
        // : instruction ops.
        .route("/v1/instructions/{id}", put(crate::pay_api::update_instruction))
        .route("/v1/instructions/{id}/process", post(crate::pay_api::process_instruction_by_id))
        .route("/v1/instructions/{id}/cancel-async", post(crate::pay_api::cancel_instruction_by_id))
        .route("/v1/instructions/{id}/repair", post(crate::pay_api::repair_instruction_by_id))
        .route("/v1/instructions/bulk-retry", post(crate::pay_api::bulk_retry_instructions))
        // : payees.
        .route("/v1/payees", post(crate::pay_api::create_payee).get(crate::pay_api::list_payees))
        .route("/v1/payees/{id}", get(crate::pay_api::get_payee).put(crate::pay_api::update_payee).delete(crate::pay_api::delete_payee))
        .route("/v1/payees/search", post(crate::pay_api::search_payees))
        // : versioned configuration.
        .route("/v1/rule-versions", get(crate::pay_api::list_rule_versions))
        .route("/v1/rule-versions", post(crate::pay_api::create_rule_version))
        .route("/v1/rule-versions/{id}/retry", post(crate::pay_api::retry_rule_version))
        .route("/v1/rule-set-versions", get(crate::pay_api::list_rule_set_versions))
        .route("/v1/rule-set-versions", post(crate::pay_api::create_rule_set_version))
        .route("/v1/rule-set-versions/{id}/retry", post(crate::pay_api::retry_rule_set_version))
        .route("/v1/integration-versions", get(crate::pay_api::list_integration_versions))
        .route("/v1/integration-versions", post(crate::pay_api::create_integration_version))
        .route("/v1/integration-versions/{id}/retry", post(crate::pay_api::retry_integration_version))
        .route("/v1/parameter-values", get(crate::pay_api::list_parameter_values))
        .route("/v1/parameter-values", post(crate::pay_api::create_parameter_value))
        .route("/v1/parameter-values/{id}", put(crate::pay_api::update_parameter_value))
        .route("/v1/core-versions", get(crate::pay_api::list_core_versions))
        .route("/v1/membership-directory-versions", get(crate::pay_api::list_membership_directory_versions))
        .route("/v1/membership-directory-versions", post(crate::pay_api::create_membership_directory_version))
        .route("/v1/membership-directory-records/search", post(crate::pay_api::search_membership_directory_records))
        .route("/v1/instruction-file-specification-versions", get(crate::pay_api::list_instruction_file_specification_versions))
        .route("/v1/instruction-file-specification-versions", post(crate::pay_api::create_instruction_file_specification_version))
        .route("/v1/instruction-file-specification-versions/validate", post(crate::pay_api::validate_specification_version))
        .route("/v1/instruction-files/{id}/initiate", post(crate::pay_api::initiate_instruction_file))
        .route("/v1/records/search", post(crate::pay_api::search_records))
        // : app surfaces.
        .route("/v1/app/template-versions", get(crate::pay_api::list_app_template_versions))
        .route("/v1/app/template-versions", post(crate::pay_api::create_app_template_version))
        .route("/v1/app/template-versions/validate", post(crate::pay_api::validate_app_template_version))
        .route("/v1/app/template-presets", post(crate::pay_api::create_template_preset).get(crate::pay_api::list_template_presets))
        .route("/v1/app/template-presets/{id}", delete(crate::pay_api::delete_template_preset))
        .route("/v1/app/dashboard-versions", get(crate::pay_api::list_app_dashboard_versions))
        .route("/v1/app/dashboard-versions", post(crate::pay_api::create_app_dashboard_version))
        .route("/v1/app/dashboard-versions/validate", post(crate::pay_api::validate_app_dashboard_version))
        // : cards issuance ops.
        .route("/v1/cards/issuance", get(crate::pay_api::list_issuance))
        .route("/v1/cards/issuance/issue", post(crate::pay_api::issue_card))
        .route("/v1/cards/issuance/{id}/replace", post(crate::pay_api::replace_card_issuance))
        .route("/v1/cards/issuance/{id}/get-details", post(crate::pay_api::get_card_details))
        .route("/v1/cards/issuance/{id}/get-pin", post(crate::pay_api::get_card_pin))
        .route("/v1/cards/issuance/{id}/update-pin", post(crate::pay_api::update_card_pin))
        .route("/v1/cards/issuance/{id}/reset-pin-attempts", post(crate::pay_api::reset_pin_attempts))
        .route("/v1/cards/issuance/{id}/reset-lvt", post(crate::pay_api::reset_card_lvt))
        .route("/v1/cards/sessions/initiate", post(crate::pay_api::initiate_card_session))
        // : card orders + batches.
        .route("/v1/cards/card-orders", post(crate::pay_api::create_card_order).get(crate::pay_api::list_card_orders))
        .route("/v1/cards/card-order-batches", post(crate::pay_api::create_card_order_batch).get(crate::pay_api::list_card_order_batches))
        // : cardholders/tokens/3DS/profile.
        .route("/v1/cards/cardholders/{id}", put(crate::pay_api::update_cardholder))
        .route("/v1/cards/cardholders/{id}/cards", get(crate::pay_api::list_cardholder_cards))
        .route("/v1/cards/card-tokens/{id}", get(crate::pay_api::get_card_token).put(crate::pay_api::update_card_token))
        .route("/v1/cards/3ds-records/{id}", put(crate::pay_api::update_3ds_record))
        .route("/v1/cards/{id}/profile", put(crate::pay_api::set_card_profile))
        // : authorisation expiry (Cron proxy-back).
        .route("/v1/internal/authorisations/expire", post(crate::pay_api::internal_authorisation_expiry))
        // : card product plans + account ranges.
        .route("/v1/cards/products/{id}", get(crate::pay_api::get_card_product_plan).put(crate::pay_api::update_card_product_plan))
        .route("/v1/cards/products/{id}/add-account-ranges", post(crate::pay_api::add_card_product_account_ranges))
        .route("/v1/cards/products/{id}/remove-account-ranges", post(crate::pay_api::remove_card_product_account_ranges))
        .route("/v1/cards/products/{id}/account-ranges", get(crate::pay_api::list_card_product_account_ranges))
        // : sandbox (FeatureGate::Sandbox).
        .route("/v1/sandbox/cards/simulate", post(crate::pay_api::sandbox_simulate_card_txn))
        .route("/v1/sandbox/credit-transfers/simulate", post(crate::pay_api::sandbox_simulate_credit_transfer))
        .route("/v1/sandbox/swift-agi/simulate", post(crate::pay_api::sandbox_simulate_swift_agi))
        .route("/v1/sandbox/fedwire/simulate", post(crate::pay_api::sandbox_simulate_fedwire))
        .route("/v1/sandbox/instructions/{id}/resume", post(crate::pay_api::sandbox_resume_instruction))
        .route("/v1/sandbox/scheduled-payments/{id}/fast-forward", post(crate::pay_api::sandbox_fast_forward_scheduled))
        // : scheduled payments (v1beta).
        .route("/v1beta/scheduled-payments", post(crate::pay_api::create_scheduled_payment).get(crate::pay_api::list_scheduled_payments))
        .route("/v1beta/scheduled-payments/{id}", get(crate::pay_api::get_scheduled_payment).delete(crate::pay_api::cancel_scheduled_payment))
        .route("/v1beta/scheduled-payments/{id}/fast-forward", post(crate::pay_api::fast_forward_scheduled_payment))
        // : state model.
        .route("/v1/payment-statuses", get(crate::pay_api::list_payment_statuses))
        // : instruction sub-actions (process/cancel covered above).
        // : users/allowed-endpoints/roles.
        .route("/v1/users", get(crate::pay_api::list_users))
        .route("/v1/allowed-endpoints", get(crate::pay_api::list_allowed_endpoints))
        .route("/v1/roles", get(crate::pay_api::list_roles))
        // : payment-initiation apps.
        .route("/v1/integrations/payment-initiation-apps", post(crate::pay_api::create_initiation_app).get(crate::pay_api::list_initiation_apps))
        // : rules on instruments + CBS ops.
        .route("/v1/rules/attach-to-instrument", post(crate::pay_api::attach_rule_to_instrument))
        .route("/v1/rules/detach-from-instrument", post(crate::pay_api::detach_rule_from_instrument))
        .route("/v1/cores/{id}/balance-endpoint", put(crate::pay_api::update_core_balance_endpoint))
        // /: config packs + On-Us routing.
        .route("/v1/config-packs", get(crate::pay_api::list_config_packs))
        .route("/v1/on-us/routing", get(crate::pay_api::list_on_us_routing))
        // : OpenMetrics.
        .route("/v1/openmetrics/metrics", get(crate::pay_api::openmetrics_metrics))
        .route("/v1/openmetrics/federate", get(crate::pay_api::openmetrics_federate))
        // ── Sentin8:Policy admin API (§3.6 — shared
        // implementation; handlers generic over this AppState).
        .route("/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>))
        .route("/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>))
        .route("/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>))
        .route("/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>))
        .route("/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>))
        .route("/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>))
        .route("/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>))
        .route("/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>))
        .route("/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>))
        // Traffic counter — counts every inbound request (excludes health checks).
}

/// Shared policy-admin surface accessor (§3.6) — the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for handlers::AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
