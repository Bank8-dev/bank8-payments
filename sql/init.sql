-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
-- SPDX-License-Identifier: Apache-2.0

-- Bank8:Payments - the service's own schema `payments` (schema-per-service):
-- payments_* domain tables + payments.outbox / payments.audit_journal
-- producer tables, all FORCE-RLS env-scoped.
--
-- The parameters status/version columns + active-name partial unique index
-- and the card sessions + PIN columns + 3DS challenge token are defined
-- directly in the CREATE TABLE statements below (canonical schema -
-- no migration code, re-run `vertical init` to recreate).

-- RLS policy helper for payments tables
CREATE SCHEMA IF NOT EXISTS payments;
CREATE OR REPLACE FUNCTION payments.enable_rls(tbl TEXT) RETURNS VOID AS $$
DECLARE
    pol_name TEXT;
BEGIN
    -- Derive policy name from the table part (after the schema dot).
    pol_name := split_part(tbl, '.', 2);
    EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', tbl);
    EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', tbl);
    EXECUTE format('DROP POLICY IF EXISTS %1$I ON %2$s;
CREATE POLICY %1$I ON %2$s FOR SELECT USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', pol_name || '_select', tbl);
    EXECUTE format('DROP POLICY IF EXISTS %1$I ON %2$s;
CREATE POLICY %1$I ON %2$s FOR INSERT WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', pol_name || '_insert', tbl);
    EXECUTE format('DROP POLICY IF EXISTS %1$I ON %2$s;
CREATE POLICY %1$I ON %2$s FOR UPDATE USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', pol_name || '_update', tbl);
    EXECUTE format('DROP POLICY IF EXISTS %1$I ON %2$s;
CREATE POLICY %1$I ON %2$s FOR DELETE USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())', pol_name || '_delete', tbl);
END;
$$ LANGUAGE plpgsql;

-- Bank8:Payments instructions table
CREATE TABLE IF NOT EXISTS payments.instructions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    instruction_logic_id UUID,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'processing', 'waiting', 'completed', 'failed', 'cancelled', 'received', 'validated', 'awaiting_input', 'in_progress', 'rejected', 'repair_needed', 'retry_needed', 'on_hold', 'expired', 'fee_collection')),
    idempotency_key TEXT,
    correlation_id  TEXT,
    input           JSONB NOT NULL DEFAULT '{}',
    output          JSONB,
    payment_id      UUID,
    instruction_logic_version_id UUID,
    current_step    TEXT,
    step_results    JSONB NOT NULL DEFAULT '[]',
    error_message   TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    scheduled_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    resource_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_payments_instructions_env ON payments.instructions (env_id);
CREATE INDEX IF NOT EXISTS idx_payments_instructions_idempotency ON payments.instructions (idempotency_key) WHERE idempotency_key IS NOT NULL;
SELECT payments.enable_rls('payments.instructions');

-- Bank8:Payments payments table
CREATE TABLE IF NOT EXISTS payments.payments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    instruction_id  UUID REFERENCES payments.instructions(id),
    payment_type    TEXT NOT NULL,
    amount          DECIMAL(20,2) NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'CAD',
    status          TEXT NOT NULL DEFAULT 'pending',
    payer_account   TEXT,
    payee_account   TEXT,
    direction       TEXT,
    payment_system  TEXT,
    payment_scheme  TEXT,
    correlation_id  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_payments_payments_env ON payments.payments (env_id);
SELECT payments.enable_rls('payments.payments');

-- Bank8:Payments rules table
CREATE TABLE IF NOT EXISTS payments.rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    expression      TEXT NOT NULL,
    action          TEXT NOT NULL,
    rule_type       TEXT NOT NULL DEFAULT 'basic',
    active_version_id UUID,
    expected_parameters JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'active',
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.rules');

-- Bank8:Payments parameters table
-- Story 11.2.18: status + version columns merged in. The original
-- unconditional UNIQUE (env_id, name) constraint
-- from the base table is NOT defined here; instead a partial unique index
-- scoped to active rows is created below so soft-deleted rows don't block
-- re-creation with the same name.
CREATE TABLE IF NOT EXISTS payments.parameters (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id           UUID NOT NULL,
    name                     TEXT NOT NULL,
    value                    TEXT NOT NULL,
    parameter_type           TEXT NOT NULL DEFAULT 'string',
    payment_instrument_id    UUID,
    description              TEXT,
    status                   TEXT NOT NULL DEFAULT 'active',
    version                  INTEGER NOT NULL DEFAULT 1,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for active parameter lookup (used by resolve_parameter).
CREATE INDEX IF NOT EXISTS idx_payments_parameters_active
    ON payments.parameters (env_id, name, payment_instrument_id)
    WHERE status = 'active';

-- Partial unique index: only active rows enforce name uniqueness per
-- (env, payment_instrument_id). COALESCE handles NULL payment_instrument_id.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_payments_parameters_active_name
    ON payments.parameters (env_id, name, COALESCE(payment_instrument_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE status = 'active';
SELECT payments.enable_rls('payments.parameters');

-- Bank8:Payments logics table
CREATE TABLE IF NOT EXISTS payments.logics (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    steps           JSONB NOT NULL DEFAULT '[]',
    correlation_id_func TEXT,
    expected_parameters JSONB NOT NULL DEFAULT '[]',
    active_version_id UUID,
    version         INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'draft',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.logics');

-- Bank8:Payments integrations table
CREATE TABLE IF NOT EXISTS payments.integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    config          JSONB NOT NULL DEFAULT '{}',
    active_version_id UUID,
    integration_kind TEXT NOT NULL DEFAULT 'http',
    auth_config     JSONB NOT NULL DEFAULT '{}',
    version         INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.integrations');

-- Bank8:Payments routing tables
CREATE TABLE IF NOT EXISTS payments.payment_instruments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    identifier      TEXT NOT NULL,
    type            TEXT NOT NULL,
    account_link_id UUID,
    routing_information JSONB NOT NULL DEFAULT '{}',
    display_name    TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    resource_version INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.payment_instruments');

CREATE TABLE IF NOT EXISTS payments.account_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id      TEXT NOT NULL,
    core_id         UUID,
    core_account_id TEXT,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    display_name    TEXT,
    resource_version INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.account_links');

-- Bank8:Payments card tables
CREATE TABLE IF NOT EXISTS payments.cardholders (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    -- Customer party: a plain UUID pointing at the Bank8:Ledger customer
    -- (resolved via Ledger's public API - never an FK or a table grant;
    -- cross-service identity is by value, payments DESIGN.md §1).
    customer_id     UUID NOT NULL,
    first_name      TEXT,
    last_name       TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Idempotent migration for upgraded databases: TEXT → UUID FK.
-- 1. Drop the old payments.enable_rls policies (they reference the old column
-- Holder-scoped RLS (§4.3c; Option A revision) - ALL human callers see only
-- their own cardholders. `holder:view-all` is M2M-ONLY: the branch is gated
-- on token_tp = 'm2m' (staff access goes through CIBA delegation, §4.3f).
-- The customer binding is by value (customer_id, resolved via Ledger's
-- public API at write time) - the holder subquery reads the caller's
-- customer id from the tenant context (set_tenant_context stamps it from
-- the verified token claims); no cross-schema read.
ALTER TABLE payments.cardholders ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments.cardholders FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cardholders_select ON payments.cardholders;
CREATE POLICY cardholders_select ON payments.cardholders FOR SELECT USING (
            sentin8_context_initialized()
            AND (
                (sentin8_has_scope('holder:view-all') = FALSE
                    AND env_id = sentin8_current_env_id()
                    AND customer_id IN (
                      SELECT id FROM ledger.customers
                      WHERE sentin8_auth_user_id = sentin8_current_sentin8_auth_user_id()
                    ))
                OR (sentin8_has_scope('holder:view-all')
                    AND sentin8_current_token_tp() = 'm2m'
                    AND env_id = sentin8_current_env_id())
            )
        );
DROP POLICY IF EXISTS cardholders_insert ON payments.cardholders;
CREATE POLICY cardholders_insert ON payments.cardholders FOR INSERT WITH CHECK (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS cardholders_update ON payments.cardholders;
CREATE POLICY cardholders_update ON payments.cardholders FOR UPDATE USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );
DROP POLICY IF EXISTS cardholders_delete ON payments.cardholders;
CREATE POLICY cardholders_delete ON payments.cardholders FOR DELETE USING (
            sentin8_context_initialized()
            AND env_id = sentin8_current_env_id()
        );

-- Story 11.2.22: pin_hash + pin_attempts merged in here.
CREATE TABLE IF NOT EXISTS payments.cards (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    cardholder_id   UUID NOT NULL REFERENCES payments.cardholders(id),
    card_product_id UUID,
    pan_last_digits TEXT,
    card_type       TEXT NOT NULL DEFAULT 'virtual',
    encrypted_pan   TEXT,
    encrypted_cvv   TEXT,
    key_id          TEXT,
    card_token_id   UUID,
    lvt_counter     INTEGER NOT NULL DEFAULT 0,
    lvt_accumulator DECIMAL(20,2) NOT NULL DEFAULT 0,
    atc_counter     INTEGER NOT NULL DEFAULT 0,
    pin_hash        TEXT,
    pin_attempts    INTEGER NOT NULL DEFAULT 0,
    resource_version INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'active',
    expiry_date     TEXT,
    card_profile_id TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.cards');

CREATE TABLE IF NOT EXISTS payments.card_products (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    account_range_id UUID,
    limits          JSONB NOT NULL DEFAULT '{}',
    configuration   JSONB NOT NULL DEFAULT '{}',
    issuing_plan    JSONB,
    expiry_plan     JSONB,
    profile_id      TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.card_products');

-- Bank8:Payments manual decisions
CREATE TABLE IF NOT EXISTS payments.manual_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    instruction_id  UUID,
    decision_type   TEXT NOT NULL,
    decisions       JSONB NOT NULL DEFAULT '[]',
    decision_inputs JSONB NOT NULL DEFAULT '[]',
    constraints     JSONB NOT NULL DEFAULT '[]',
    reason_codes    JSONB NOT NULL DEFAULT '[]',
    deadline        TIMESTAMPTZ,
    submitted_decision JSONB,
    task_id         UUID,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    submitted_by    TEXT,
    submitted_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.manual_decisions');

-- Bank8:Payments audit events
CREATE TABLE IF NOT EXISTS payments.audit_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID,
    actor_user_id       TEXT,
    action              TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id  TEXT,
    correlation_id      TEXT,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT now(),
    schema_version      TEXT NOT NULL DEFAULT '1.0'
);
SELECT payments.enable_rls('payments.audit_events');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Rule Sets and Rule Versions
CREATE TABLE IF NOT EXISTS payments.rule_sets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    version         INTEGER NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.rule_sets');

CREATE TABLE IF NOT EXISTS payments.rule_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    rule_id         UUID NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    implementation  TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_id, version)
);
SELECT payments.enable_rls('payments.rule_versions');

CREATE TABLE IF NOT EXISTS payments.rule_set_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    rule_set_id     UUID NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    rule_ids        JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_set_id, version)
);
SELECT payments.enable_rls('payments.rule_set_versions');

CREATE TABLE IF NOT EXISTS payments.rule_set_rules (
    rule_set_id     UUID NOT NULL,
    rule_id         UUID NOT NULL,
    sort_order      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_set_id, rule_id)
);

-- ──────────────────────────────────────────────────────────────────────────
-- New: Parameter Values (timeseries)
CREATE TABLE IF NOT EXISTS payments.parameter_values (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id           UUID NOT NULL,
    parameter_id             UUID NOT NULL,
    value                    TEXT NOT NULL,
    effective_from_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_to_timestamp  TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.parameter_values');
CREATE INDEX IF NOT EXISTS idx_payments_param_values_param ON payments.parameter_values (parameter_id, effective_from_timestamp);

-- ──────────────────────────────────────────────────────────────────────────
-- New: Integration Versions
CREATE TABLE IF NOT EXISTS payments.integration_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    integration_id  UUID NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    config          JSONB NOT NULL DEFAULT '{}',
    auth_config     JSONB NOT NULL DEFAULT '{}',
    healthcheck     JSONB NOT NULL DEFAULT '{}',
    retry_policy    JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ready', 'errored', 'user_action_required')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (integration_id, version)
);
SELECT payments.enable_rls('payments.integration_versions');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Cores and Core Versions
CREATE TABLE IF NOT EXISTS payments.cores (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.cores');

CREATE TABLE IF NOT EXISTS payments.core_versions (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id           UUID NOT NULL,
    core_id                  UUID NOT NULL,
    version                  INTEGER NOT NULL DEFAULT 1,
    postings_integration_id  UUID,
    balance_integration_id   UUID,
    status                   TEXT NOT NULL DEFAULT 'active',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (core_id, version)
);
SELECT payments.enable_rls('payments.core_versions');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Card extensions
CREATE TABLE IF NOT EXISTS payments.account_ranges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    card_product_id UUID NOT NULL,
    bin_range        TEXT NOT NULL,
    pan_length       INTEGER NOT NULL DEFAULT 16,
    status           TEXT NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.account_ranges');

CREATE TABLE IF NOT EXISTS payments.card_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    card_id         UUID NOT NULL,
    token_requestor_id TEXT,
    token_status    TEXT NOT NULL DEFAULT 'active' CHECK (token_status IN ('active', 'suspended', 'deleted')),
    token_reference TEXT,
    device_type     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.card_tokens');

CREATE TABLE IF NOT EXISTS payments.card_orders (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    card_id         UUID NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'manufacturing', 'shipped', 'delivered', 'cancelled')),
    shipping_address JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.card_orders');

-- Story 11.2.22: challenge_token column merged in here.
CREATE TABLE IF NOT EXISTS payments.threeds_records (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    card_id         UUID,
    transaction_id  TEXT NOT NULL,
    authentication_status TEXT NOT NULL DEFAULT 'pending' CHECK (authentication_status IN ('pending', 'frictionless', 'challenged', 'authenticated', 'failed', 'declined')),
    challenge_method TEXT,
    challenge_token TEXT,
    risk_score      DECIMAL(5,2),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.threeds_records');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Tasks
CREATE TABLE IF NOT EXISTS payments.tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    task_type       TEXT NOT NULL DEFAULT 'manual_decision_submission',
    status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'in_progress', 'awaiting_approval', 'executing', 'completed', 'rejected', 'errored', 'deadline_exceeded', 'abandoned')),
    assignee_id     TEXT,
    reviewer_id     TEXT,
    approval_stages JSONB NOT NULL DEFAULT '[]',
    current_stage   INTEGER NOT NULL DEFAULT 0,
    related_resource_type TEXT,
    related_resource_id   UUID,
    deadline        TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.tasks');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Files and Instruction Files
CREATE TABLE IF NOT EXISTS payments.files (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    filename        TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL DEFAULT 0,
    sentin8_buck_path      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'uploaded' CHECK (status IN ('uploaded', 'processing', 'processed', 'failed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.files');

CREATE TABLE IF NOT EXISTS payments.instruction_files (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    file_id         UUID,
    name            TEXT NOT NULL,
    direction        TEXT NOT NULL DEFAULT 'outbound' CHECK (direction IN ('inbound', 'outbound')),
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.instruction_files');

CREATE TABLE IF NOT EXISTS payments.instruction_batches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    instruction_file_id UUID NOT NULL,
    name            TEXT NOT NULL,
    instruction_ids JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.instruction_batches');

CREATE TABLE IF NOT EXISTS payments.instruction_file_specifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    capacity_limit  INTEGER NOT NULL DEFAULT 1000,
    calendar_id     UUID,
    batch_builder_code TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.instruction_file_specifications');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Mandates
CREATE TABLE IF NOT EXISTS payments.mandates (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id      UUID NOT NULL,
    scheme_creditor_id  TEXT,
    scheme_mandate_id   TEXT,
    debtor_name          TEXT,
    debtor_account       TEXT,
    creditor_name        TEXT,
    creditor_account     TEXT,
    amount_limit         DECIMAL(20,2),
    currency             TEXT,
    status               TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'cancelled', 'expired')),
    effective_from       TIMESTAMPTZ,
    effective_to         TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.mandates');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Membership Directories
CREATE TABLE IF NOT EXISTS payments.membership_directories (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    directory_type  TEXT NOT NULL CHECK (directory_type IN ('tips', 'fedach', 'fedwire')),
    file_id         UUID,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ready', 'errored')),
    entries         JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.membership_directories');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Calendars and Business Day Definitions
CREATE TABLE IF NOT EXISTS payments.business_day_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    weekend_days    INTEGER[] NOT NULL DEFAULT '{6,0}',
    holidays        JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.business_day_definitions');

CREATE TABLE IF NOT EXISTS payments.calendars (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    calendar_type   TEXT NOT NULL CHECK (calendar_type IN ('cutoff_period', 'processing_period')),
    business_day_definition_id UUID,
    configuration   JSONB NOT NULL DEFAULT '{}',
    timezone        TEXT NOT NULL DEFAULT 'UTC',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.calendars');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Templates
CREATE TABLE IF NOT EXISTS payments.templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    scheme          TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    active_version_id UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.templates');

CREATE TABLE IF NOT EXISTS payments.template_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    template_id     UUID NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    variables        JSONB NOT NULL DEFAULT '[]',
    base_instruction JSONB NOT NULL DEFAULT '{}',
    inputs           JSONB NOT NULL DEFAULT '[]',
    status           TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (template_id, version)
);
SELECT payments.enable_rls('payments.template_versions');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Dashboards
CREATE TABLE IF NOT EXISTS payments.dashboards (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    active_version_id UUID,
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.dashboards');

CREATE TABLE IF NOT EXISTS payments.dashboard_versions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    dashboard_id            UUID NOT NULL,
    version                 INTEGER NOT NULL DEFAULT 1,
    default_filter_values   JSONB NOT NULL DEFAULT '{}',
    layout                  JSONB NOT NULL DEFAULT '[]',
    primary_widget_id       TEXT,
    status                  TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (dashboard_id, version)
);
SELECT payments.enable_rls('payments.dashboard_versions');

-- ──────────────────────────────────────────────────────────────────────────
-- New: Logic Versions
CREATE TABLE IF NOT EXISTS payments.logic_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    logic_id        UUID NOT NULL,
    version         INTEGER NOT NULL DEFAULT 1,
    steps           JSONB NOT NULL DEFAULT '[]',
    correlation_id_func TEXT,
    expected_parameters JSONB NOT NULL DEFAULT '[]',
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (logic_id, version)
);
SELECT payments.enable_rls('payments.logic_versions');

-- ──────────────────────────────────────────────────────────────────────────
-- Story 11.2.22 - Card operations: encrypted sessions, PIN, card tokens, 3DS.
-- Encrypted card sessions for sensitive card operations (PIN verify/change,
-- 3DS challenge delivery).
CREATE TABLE IF NOT EXISTS payments.card_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    card_id         UUID NOT NULL REFERENCES payments.cards(id),
    session_type    TEXT NOT NULL CHECK (session_type IN ('pin_verify', 'pin_change', '3ds')),
    session_token   TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'expired', 'consumed', 'revoked')),
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payments_card_sessions_card ON payments.card_sessions (card_id);
CREATE INDEX IF NOT EXISTS idx_payments_card_sessions_token ON payments.card_sessions (session_token);
SELECT payments.enable_rls('payments.card_sessions');
-- ──────────────────────────────────────────────────────────────────────────
-- PAY-API epic (2026-09-06) - business API completion tables.
-- PA-4: Payees (payment recipients, reusable).
CREATE TABLE IF NOT EXISTS payments.payees (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    payee_type      TEXT NOT NULL DEFAULT 'external' CHECK (payee_type IN ('external', 'internal', 'bill')),
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'removed')),
    account_identifier TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payments_payees_env ON payments.payees (env_id);
SELECT payments.enable_rls('payments.payees');

-- PA-6: Template presets (reusable payment-initiation presets per template).
CREATE TABLE IF NOT EXISTS payments.template_presets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    template_id     UUID NOT NULL REFERENCES payments.templates(id),
    name            TEXT NOT NULL,
    preset_values   JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payments_template_presets_tpl ON payments.template_presets (template_id);
SELECT payments.enable_rls('payments.template_presets');

-- PA-5: Membership directory versions (versioned membership directories).
CREATE TABLE IF NOT EXISTS payments.membership_directory_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    directory_id    UUID NOT NULL REFERENCES payments.membership_directories(id),
    version         INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (directory_id, version)
);
SELECT payments.enable_rls('payments.membership_directory_versions');

-- PA-5: Instruction file specification versions + validation.
CREATE TABLE IF NOT EXISTS payments.instruction_file_specification_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    specification_id UUID NOT NULL REFERENCES payments.instruction_file_specifications(id),
    version         INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (specification_id, version)
);
SELECT payments.enable_rls('payments.instruction_file_specification_versions');

-- PA-14: Scheduled payments (v1beta) - standing orders / direct debits /
-- future-dated transfers. Recurrence follows RFC 5545 RRULE (UTC-only;
-- Sentin8:Cron is the scheduler).
CREATE TABLE IF NOT EXISTS payments.scheduled_payments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    account_id      UUID NOT NULL,
    amount          DECIMAL(20,2) NOT NULL,
    currency        TEXT NOT NULL,
    schedule_type   TEXT NOT NULL CHECK (schedule_type IN ('standing_order', 'direct_debit', 'future_dated')),
    recurrence_rule TEXT,
    next_run_at     TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'cancelled', 'completed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payments_scheduled_payments_env ON payments.scheduled_payments (env_id, next_run_at);
SELECT payments.enable_rls('payments.scheduled_payments');

-- PA-8: Card order batches (manufacturing batch grouping).
CREATE TABLE IF NOT EXISTS payments.card_order_batches (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    order_ids       JSONB NOT NULL DEFAULT '[]',
    order_count     INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'submitted', 'manufactured', 'closed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.card_order_batches');

-- PA-12: Card product BIN account ranges (multi-range attach/detach).
CREATE TABLE IF NOT EXISTS payments.card_product_account_ranges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    product_id      UUID NOT NULL REFERENCES payments.card_products(id),
    account_range_id TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, product_id, account_range_id)
);
SELECT payments.enable_rls('payments.card_product_account_ranges');

-- PA-13: Sandbox simulation audit trail.
CREATE TABLE IF NOT EXISTS payments.sandbox_simulations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    simulation_type TEXT NOT NULL,
    input           JSONB NOT NULL DEFAULT '{}',
    result          JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.sandbox_simulations');

-- PA-20: Payment-initiation apps (registered B8 apps driving instructions).
CREATE TABLE IF NOT EXISTS payments.initiation_apps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    app_type        TEXT NOT NULL DEFAULT 'payment_initiation',
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    config          JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.initiation_apps');

-- PA-21: Rule ↔ payment-instrument attachments (rules scoped to cards/accounts).
CREATE TABLE IF NOT EXISTS payments.rule_instruments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    rule_id         UUID NOT NULL REFERENCES payments.rules(id),
    instrument_id   UUID NOT NULL,
    instrument_type TEXT NOT NULL DEFAULT 'card' CHECK (instrument_type IN ('card', 'account')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, rule_id, instrument_id)
);
SELECT payments.enable_rls('payments.rule_instruments');

-- PA-23: B8 On-Us routing (route instructions to another B8 member bank).
CREATE TABLE IF NOT EXISTS payments.on_us_routes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    target_bic      TEXT,
    target_env_id   UUID,
    route_type      TEXT NOT NULL DEFAULT 'bic' CHECK (route_type IN ('bic', 'env')),
    priority        INTEGER NOT NULL DEFAULT 100,
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
SELECT payments.enable_rls('payments.on_us_routes');

-- PA-9: Card Profile (chip behaviour / scheme approval: Mastercard CPV/CNS,
-- Visa DPS). Column on cards + card products.
-- NOTE: new platform - columns are added to the CREATE TABLE above in the
-- canonical schema; re-run `make infra-up` / vertical init to recreate.

-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: payments rows are appended to the outbox in the SAME
-- transaction as the domain change; the shell's post-commit relay pushes
-- them to Bus POST /v1/produce (idempotency_key = row id).
-- Generated from sentin8-outbox::outbox_table_sql("payments") - the outbox
-- lives in the service's OWN leaf schema (`payments`), matching the relay's
-- notify channel (`payments_outbox_changed`) and the search_path-derived
-- resolution; the payments_* domain tables live in the SAME schema
-- `payments` (schema-per-service - the leaf schema is the service's
-- primary schema).
CREATE TABLE IF NOT EXISTS payments.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payments_outbox_unrelayed
    ON payments.outbox (created_at) WHERE relayed = false;
ALTER TABLE payments.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON payments.outbox;
CREATE POLICY outbox_select ON payments.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON payments.outbox;
CREATE POLICY outbox_insert ON payments.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON payments.outbox;
CREATE POLICY outbox_update ON payments.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION payments.payments_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('payments_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS payments_outbox_notify_trigger ON payments.outbox;
CREATE TRIGGER payments_outbox_notify_trigger
    AFTER INSERT ON payments.outbox
    FOR EACH ROW
    EXECUTE FUNCTION payments.payments_notify_outbox();

-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit.
-- Generated from sentin8-audit::audit_journal_sql("payments").
CREATE TABLE IF NOT EXISTS payments.audit_journal (
    id              UUID PRIMARY KEY,
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_payments_audit_journal_unpushed
    ON payments.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE payments.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON payments.audit_journal;
CREATE POLICY audit_journal_dml ON payments.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

-- ── Per-service role grants + search_path (F1 - §4.3e) ──────────────────
-- The payments service and its worker connect via the bank8_payments_service
-- role (created + granted by `sentin8-cli vertical init/enroll` from this
-- service's --print-registration --section=pg_roles). RLS only ENFORCES when
-- the service does NOT bypass it. These grants give the role table access;
-- the RLS policies scope the rows.
-- The search_path puts the service's OWN schema FIRST (outbox/audit_journal
-- resolution for the shell's relay + journal pusher; unqualified payments_*
-- domain tables resolve here too), then public (RLS helpers). The
-- `vertical enroll` never-clobber block preserves this role-level setting.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bank8_payments_service') THEN
        ALTER ROLE bank8_payments_service SET search_path = payments, public;
        GRANT USAGE ON SCHEMA payments TO bank8_payments_service;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA payments TO bank8_payments_service;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA payments TO bank8_payments_service;
    END IF;
END $$;
