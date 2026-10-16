# Bank8:Payments — Detailed Design Document

## 1. Scope & Context

Bank8:Payments owns: the payments domain schema `payments`
(schema-per-service — 55 domain tables + the `payments.outbox` /
`payments.audit_journal` producer tables in the same schema), the
instruction/payment REST API (90 utoipa-declared endpoints across ~45
families), the scheme flow implementations (B8, SEPA, TIPS, SWIFT AGI
over the typed ISO 20022 catalogue), card issuing + lifecycle + 3-D
Secure + card sessions, mandates, payees, on-us routing, the rule
engine and its versioned configuration library (parameters, rules,
logics, integrations, cores, templates, dashboards, config packs,
membership directories), file processing (ISO file specs, batches),
manual decisions/tasks, sandbox simulators, and the
`bank8:payments:*` event family (25 resource types). The **async
re-drive loop is embedded** (`worker` module — an in-process Bus SSE
consumer that turns `bank8:payments:instruction:*` events into Flow
workflow resume/retry; the former standalone `payments-worker` binary,
merged following the platform's stat-worker precedent).

It does NOT own: workflow execution (Sentin8:Flow), scheduling
(Sentin8:Cron), tenant hooks (Sentin8:Func), or balances/postings
(Bank8:Ledger — called via its public API).

```mermaid
graph TD
    subgraph platform["Sentin8 platform"]
        AUTH["Sentin8:Auth"]
        FLOW["Sentin8:Flow"]
        CRON["Sentin8:Cron"]
        FUNC["Sentin8:Func"]
        BUS["Sentin8:Bus"]
        STAT["Sentin8:Stat"]
        STOR["Sentin8:Storage"]
    end
    subgraph vertical["bank8 vertical"]
        PAY["Bank8:Payments<br/>(API + embedded re-drive worker)"]
        LEDGER["Bank8:Ledger"]
        PG[("bank8 database")]
    end
    subgraph clients
        BFF["Sentin8:BFF /proxy/payments/*"]
        APPS["ebank · efintech · eteller · admin"]
    end
    APPS --> BFF -->|"user tokens"| PAY
    PAY <-->|"verify / certificate identity (CERTFREE-4V)"| AUTH
    PAY -->|"create workflows + step profiles"| FLOW
    FLOW -->|"M2M / v1/internal/steps/execute"| PAY
    PAY -->|"re-drive via Flow<br/>(embedded worker)"| FLOW
    CRON -->|"M2M / internal schedules"| PAY
    PAY -->|"posting steps / public API"| LEDGER
    PAY -->|"payments.outbox relay"| BUS
    BUS -->|"family payments<br/>(worker SSE consume)"| PAY
    PAY -->|"files (ISO archives, confirmations)"| STOR
    PAY -->|"daily telemetry"| STAT
    PAY <-->|"schema payments: payments_*"| PG
```

## 2. Runtime Architecture

Shell-owned boot (pool, Shield engine, outbox relay on
`payments_outbox_changed`, journal pusher via `payments-audit`) plus
**one service-spawned task**: the embedded re-drive worker (`worker::spawn`
— a Bus SSE consumer on the `payments` family that turns
`bank8:payments:instruction:*` events into Flow resume/retry calls).

```mermaid
graph TD
    subgraph L["API layer"]
        RT["server.rs router (190 routes)"]
        MW["auth.rs verify + policy.rs require"]
    end
    subgraph D["Domain"]
        IN["instructions / state_machine"]
        FL["scheme flows (b8, sepa, tips, swift)"]
        CD["cards / 3DS / mdes / visa_dps"]
        MD["mandates / payees"]
        RE["rules engine + versions"]
        FP["files / batches / CLU"]
        TS["tasks / manual decisions"]
    end
    subgraph WK["Embedded re-drive worker (worker/)"]
        SSE["sse_consume_loop<br/>family payments, group payments-worker"]
        PR["process_instruction<br/>terminal-skip + guarded UPDATE<br/>+ Flow resume/retry"]
    end
    subgraph S["Storage"]
        PG[("schema payments: payments_*")]
        OB[("payments.outbox")]
        AJ[("payments.audit_journal")]
    end
    subgraph X["External calls"]
        FLW["Flow client (cert-presenting payments-worker-flow)"]
        LED["Ledger client"]
        STO["Storage client"]
        BUSC["Bus client (cert-presenting payments-worker, consume)"]
    end
    RT --> MW --> D
    D --> PG
    D -- "same-tx" --> OB
    D -- "same-tx" --> AJ
    D --> FLW
    D --> LED
    FP --> STO
    SSE --> PR --> PG
    PR --> FLW
    SSE --> BUSC
```

**Request lifecycle — instruction creation (async execution family)**:

```mermaid
sequenceDiagram
    participant C as Client (BFF)
    participant P as Bank8:Payments
    participant SH as Shield (step 5)
    participant DB as PostgreSQL
    participant F as Sentin8:Flow
    participant L as Bank8:Ledger
    C->>P: POST /v1/instructions (bearer)
    P->>SH: EvalTarget bank8:payments:instructions:write
    SH-->>P: ALLOW
    P->>DB: BEGIN + tenant context + idempotency check
    P->>DB: INSERT instructions (pending)
    P->>DB: INSERT payments.outbox (event: instruction:created)
    P->>F: create workflow (logic_id, correlation = instruction id)
    alt workflow created
        P->>DB: instruction → processing · COMMIT
        P-->>C: accepted
    else Flow unavailable
        P-->>C: 5xx — nothing committed
    end
    Note over C,L: Flow drives steps, posting steps call Ledger public API
    F->>P: POST /v1/internal/steps/execute (M2M)
    P->>SH: step gate (payments enforced set)
    P->>L: POST /v1/postings (M2M/steps)
    L-->>P: posting id
    P->>DB: step_results + state transition (guarded)
```

**Sync schemes (B8 on-us, SEPA instant)** follow the same pipeline with
inline step execution and no Flow round-trip.

## 3. Data Model

55 domain tables in the service's own schema `payments` (all
env-scoped, FORCE-RLS via `payments.enable_rls()`), plus the
producer tables `payments.outbox` / `payments.audit_journal` in the
same schema. Complete inventory by family:

| Family | Tables |
|---|---|
| Instructions | `instructions` (state machine, idempotency_key, input/output JSONB, step_results), `instruction_batches`, `instruction_files`, `instruction_file_specifications` + `_versions` |
| Payments | `payments` (scheme result records) |
| Logics | `logics`, `logic_versions` (WASM migration path) |
| Routing | `payment_instruments`, `account_links`, `rule_instruments`, `on_us_routes` |
| Cards | `cardholders` (holder-scoped), `cards` (LVT/ATC accumulators), `card_products`, `card_product_account_ranges`, `card_tokens`, `card_sessions`, `card_orders`, `card_order_batches`, `threeds_records`, `sandbox_simulations` |
| Mandates | `mandates` (amount_limit), `payees` |
| Rules | `rules`, `rule_versions`, `rule_sets`, `rule_set_versions`, `rule_set_rules` |
| Parameters | `parameters`, `parameter_values` |
| Integrations | `integrations`, `integration_versions`, `initiation_apps` |
| Cores | `cores`, `core_versions`, `account_ranges` |
| Config library | `templates`, `template_versions`, `template_presets`, `dashboards`, `dashboard_versions`, `payments_config_packs` |
| Directories | `membership_directories`, `membership_directory_versions` |
| Time | `business_day_definitions`, `calendars`, `scheduled_payments` |
| Workflow | `manual_decisions`, `tasks` |
| Files | `files` (ISO archives, confirmations — payload in Storage) |
| Audit | `audit_events` (OCSF-shaped) |
| Producer | `payments.outbox`, `payments.audit_journal` (same schema, FORCE-RLS) |

Core relationships:

```mermaid
erDiagram
    instructions ||--o{ payments : "produces"
    instructions }o--|| logics : "executes"
    logics ||--o{ logic_versions : "versions"
    instructions ||--o{ instruction_batches : "batched"
    instruction_batches }o--|| instruction_files : "carried by"
    instruction_files }o--|| instruction_file_specifications : "formatted by"
    payments }o--|| payment_instruments : "routed via"
    payment_instruments }o--|| account_links : "linked to"
    account_links }o--|| cardholders : "held by"
    cardholders ||--o{ cards : "owns"
    cards }o--|| card_products : "typed by"
    card_products ||--o{ card_product_account_ranges : "BIN ranges"
    cards ||--o{ card_tokens : "tokenized"
    cards ||--o{ threeds_records : "challenged"
    cards ||--o{ card_sessions : "sessions"
    card_order_batches ||--o{ card_orders : "batched"
    mandates }o--|| payment_instruments : "draws on"
    rules ||--o{ rule_versions : "versions"
    rule_sets ||--o{ rule_set_versions : "versions"
    rule_set_versions ||--o{ rule_set_rules : "contains"
    parameters ||--o{ parameter_values : "values"
    integrations ||--o{ integration_versions : "versions"
    cores ||--o{ core_versions : "versions"
    cores ||--o{ account_ranges : "ranges"
    templates ||--o{ template_versions : "versions"
    dashboards ||--o{ dashboard_versions : "versions"
    manual_decisions }o--|| tasks : "decides"
    membership_directories ||--o{ membership_directory_versions : "versions"
    scheduled_payments ||--o{ payments : "occurrences"
    on_us_routes }o--|| cores : "target"
```

**Instruction state machine** (mirrored by the worker's predicate):

```mermaid
stateDiagram-v2
    [*] --> pending : create (idempotent)
    pending --> processing : execute / embedded-worker re-drive
    processing --> awaiting_decision : manual decision step
    awaiting_decision --> processing : approve/reject
    processing --> completed : all steps done
    processing --> failed : step error
    pending --> cancelled : cancel request
    processing --> cancelled : cancel request
    completed --> [*]
    failed --> processing : retry (guarded)
    cancelled --> [*]
```

## 4. API Surface

All 90 utoipa-declared endpoints by family with gates (Shield step-5
targets; `security()` annotations declare the scope per endpoint):

| Family | Endpoints | Gate |
|---|---|---|
| Instructions | `GET/POST /v1/instructions`, `POST /v1/instructions/initiate`, `GET …/{id}`, `POST …/{id}/process|retry|cancel|repair`, `POST /v1/instructions/bulk-retry`, `GET /v1/payment-statuses` | `bank8:payments:instructions:read` / `:write` |
| Payments | `GET /v1/payments`, `GET …/{id}` | `bank8:payments:payments:read` |
| Logics | `GET/POST /v1/logics`, `GET …/{id}`, `POST …/{id}/migrate-wasm` | `bank8:payments:logics:read` / `:write` |
| Routing | `/v1/payment-instruments`, `/v1/account-links` (CRUD), `/v1/on-us/routing` | `bank8:payments:cards:*` / instruments |
| Rules engine | `GET/POST /v1/rules`, `POST …/{id}/publish`, `POST /v1/rules/attach-to-instrument|detach-from-instrument`, `/v1/rule-versions` + `/{id}/retry`, `/v1/rule-set-versions` + `/{id}/retry`, `/v1/rule-sets` | `bank8:payments:rules:read` / `:write` |
| Parameters | `/v1/parameters`, `/v1/parameter-values` + `/{id}` | `bank8:payments:parameters:read` |
| Integrations | `/v1/integrations` + `/{id}`, `/v1/integration-versions` + `/{id}/retry`, `/v1/integrations/callback/{token}`, `/v1/integrations/payment-initiation-apps` | `bank8:payments:integrations:read` / `:write` |
| Cores | `/v1/cores` + `/{id}`, `/v1/cores/{id}/balance-endpoint`, `/v1/core-versions`, account-ranges | `bank8:payments:cores:read` / `:write` |
| Cards | `GET/POST /v1/cards`, `GET /v1/cards/{id}`, `…/profile`, `/v1/cards/cardholders/{id}` + `/cards`, `/v1/cards/products/{id}` + `/account-ranges|add-account-ranges|remove-account-ranges`, `/v1/cards/issuance/issue|{id}/replace|get-details|get-pin|update-pin|reset-lvt|reset-pin-attempts`, `/v1/cards/sessions/initiate`, `/v1/cards/card-tokens/{id}`, `/v1/cards/3ds-records/{id}`, `/v1/cards/card-orders`, `/v1/cards/card-order-batches` | `bank8:payments:cards:read` / `:write`, `bank8:payments:issuance:read` / `:write`, `bank8:payments:cardholders:write` |
| Mandates | `GET/POST /v1/mandates` + `/{id}` | `bank8:payments:mandates:read` / `:write` |
| Payees | `/v1/payees`, `/v1/payees/{id}`, `/v1/payees/search` | mandates-family |
| Files | `GET/POST /v1/files`, `GET …/{id}`, `POST …/{id}/submit`, `/v1/instruction-files`, `/v1beta/instruction-files/initiate` | `bank8:payments:files:read` / `:write` |
| File specs | `/v1/instruction-file-specifications`, `/v1beta/instruction-file-specification-versions` + `/validate` | files-family |
| Tasks/decisions | `GET /v1/tasks` + `/{id}`, `POST …/{id}/claim|approve|reject`, `GET/POST /v1/manual-decisions` + `/{id}`, `POST …/{id}/submit` | decisions-family |
| Config library | `/v1/templates` + `/{id}/versions|publish`, `/v1/dashboards` + `/{id}/versions`, `/v1/config-packs`, `/v1/app/template-versions|template-presets|dashboard-versions` + `/validate`, `/v1/business-day-definitions`, `/v1/calendars`, `/v1/membership-directory-versions`, `/v1/membership-directory-records/search`, `/v1/records/search` | templates/dashboards/parameters scopes |
| Recurring | `/v1beta/scheduled-payments` + `/{id}` + `/fast-forward` | mandates-family |
| Sandbox | `/v1/sandbox/cards|credit-transfers|fedwire|swift-agi/simulate`, `/v1/sandbox/instructions/{id}/resume`, `/v1/sandbox/scheduled-payments/{id}/fast-forward` | sandbox surface |
| Self-describing | `GET /v1/allowed-endpoints`, `/v1/roles`, `/v1/users`, `/v1/audit`, `/v1/metrics`, `/v1/openmetrics/metrics|federate` | `bank8:payments:audit:read`, `:metrics:read`, `:openmetrics:read` |
| Health | `GET /v1/health` | none |

Internal (M2M proxy-back, the Flow contract):

| Endpoint | Caller | Contract |
|---|---|---|
| `POST /v1/internal/steps/execute` | Sentin8:Flow | domain step functions (MatchPaymentInstrument, Sentin8CorePostings, scheme calls, …) — step-5-gated, env from workflow |
| `GET/PATCH /v1/internal/instructions/{id}` | Flow / embedded worker | guarded state reads/updates |
| `GET /v1/internal/{payments,payment-instruments,account-links,parameters,rules,integrations}/{id}` | Flow steps | data access for step execution |
| `POST /v1/internal/authorisations/expire` | Cron/scheme callbacks | authorisation expiry sweep |

Admin/RFW: `/v1/admin/ui/{page}` + `/v1/admin/{resource}` (policy-sets/
relations/attributes shared pages + payments data plane).

**Event families** (family `payments`, DBX producer path): the
`ResourceType` catalogue drives `bank8:payments:{resource}:{operation}`
events for all 25 resource types — `instruction`, `payment`,
`instruction_logic`, `payment_instrument`, `account_link`, `card`,
`cardholder`, `card_order`, `three_ds_record`, `core`, `core_version`,
`file`, `instruction_file`, `integration`, `integration_version`,
`manual_decision`, `membership_directory`, `parameter`, `rule`,
`rule_set`, `rule_version`, `rule_set_version`, `template`,
`template_version`, `dashboard` — each with `created`/`updated`
operations plus the specific flows (`instruction:retried`, `:cancelled`,
`:repaired`, `instruction_logic:wasmmigrated`, `cards:encrypted`).

```mermaid
sequenceDiagram
    participant H as handler (domain tx)
    participant O as payments.outbox
    participant R as shell relay
    participant B as Sentin8:Bus
    participant W as embedded worker
    H->>O: emit_event_tx (same-tx, publisher token)
    O-->>R: NOTIFY payments_outbox_changed
    R->>B: POST /v1/produce (M2M, idempotency_key = row id)
    B-->>W: SSE push bank8:payments:instruction:*
    W->>W: terminal-state skip (idempotent)
    W-->>B: ACK
    Note over B,R: produce failure → attempts+1, ≤10, then manual replay
```

## 5. Cross-Cutting Concerns

- **Auth**: platform pipeline; step 5 Shield gate on every handler;
  the proxy-back endpoints verify the Flow/Func M2M bearer and
  cross-check the workflow env.
- **Tenant**: token claims + RLS context per connection; explicit
  `WHERE env_id` clauses everywhere.
- **Idempotency**: instruction `(env_id, idempotency_key)` unique
  (duplicates return the original); outbox row id = produce key;
  state-machine guards make re-drive effectively-once.
- **Audit**: `audit_events` (OCSF-shaped) for domain audit +
  `payments.audit_journal` pushed to Sys by the shell pusher
  (`payments-audit` workload).
- **Feature gates**: availability (503) vs authorization (403) are
  separate — feature flags gate availability, Shield gates access.
- **Drain/TLS**: platform-standard (health gauge + in-process PQ-TLS).

## 6. Failure Modes & Recovery

```mermaid
flowchart TD
    I["POST /v1/instructions"] -->|"Flow create fails"| AB["no commit — 5xx<br/>client retries (idempotent)"]
    I -->|"commit ok"| ST["instruction pending/processing"]
    ST -->|"worker event lost (Bus outage)"| ROW["outbox row unrelayed"]
    ROW --> RELAY["relay retry ≤10 → produce"]
    ST -->|"step fails"| FAILED["state=failed + error_message"]
    FAILED -->|"retry"| PROC["re-drive via Flow (guarded)"]
    ST -->|"poison event"| DLQ["Bus DLQ after max_retries"]
    DLQ --> REPLAY["manual replay"]
    DEC["manual decision"] -->|"timeout"| INTERRUPT["interruption handling"]
```

- **Crash mid-transaction**: domain + outbox rows roll back together.
- **Flow outage at creation**: request fails, nothing committed.
- **Step failure**: state=failed with reason; retry re-drives via the
  embedded worker → Flow `retry_workflow`.
- **Worker task death**: messages stay pending in the consumer group;
  redelivery after process restart.

## 7. Concurrency & Performance Model

- **Background tasks**: shell owns the relay + journal pusher; the
  service spawns the embedded re-drive worker (one SSE consume loop on
  the `payments` family).
- Capped pool (≤3) shared by the API and the embedded worker — the
  worker adds no second pool (the merge removed the standalone binary's
  pool; the platform stat merge is the precedent).
- Hot paths: instruction state updates (single-row, indexed on id +
  state), routing lookups (payment instruments by
  `bank_identifier`/`instrument_identifier` indexes), rule evaluation
  (versioned rules loaded per instruction).
- LVT/ATC accumulators update via single-column guarded UPDATEs (no
  read-modify-write races).

## 8. Invariants, Insecure-Defaults Rejected, Unsafe Rationale

- Terminal instruction states are immutable; every transition is
  state-machine-guarded.
- Drafts never execute: only published rule/logic/integration versions
  are eligible for instruction routing.
- Money is never float; card session crypto uses the documented
  deterministic placeholder layer (production HSM integration is a
  deployment concern, not code).
- The API and the embedded worker share the terminal-state predicate via
  the same guarded-SQL contract (one crate now — the two can't drift).
- No `unsafe` code.
- Rejected defaults: shadow-writing ledger balances; per-handler scope
  checks (step 5 is the only gate); unauthenticated internal endpoints.

## 9. Testing Strategy

```mermaid
graph TD
    U["Unit — pure logic<br/>state machine, ISO payload parsing,<br/>rule engine, routing extraction,<br/>config defaults, SDK contracts"] --> I["Integration<br/>posting-type model, event naming,<br/>feature gates, policy suites<br/>(engine semantics + mirror parity)"]
    I --> E["E2E — e2e-ts via BFF proxy<br/>instruction lifecycle incl.<br/>worker re-drive"]
```

- **Unit** (425 tests): the money/path logic is pure-function tested —
  state machine transitions, ISO 20022 payload handling, rule
  evaluation, routing extraction.
- **Integration**: posting-type model, event-stream naming + publisher
  identity, the 15 feature gates, policy wiring suites.
- **Deliberately not tested**: live scheme-gateway calls (simulator
  adapters cover the paths), platform transport layers.

## 10. Open Questions

- **Production scheme certification (Visa DPS, MDES, SWIFT) is external by
  design** — closed as a code question. The adapter seams (versioned
  `integrations` published per scheme, simulator parity) are the
  certification inputs; the vertical's remaining deliverable is a
  certification runbook (register an integration version, point it at a
  scheme test bed, collect evidence) so tenants can drive it.
- ~~File processing~~ — **implemented** (design §10): `submit` marks the
  file `processing`, creates the batch shell, and triggers the per-file
  Flow debatch workflow (`logic_id: file-debatch`, `correlation_id =
  file_id`) whose step proxies back into
  `POST /v1/internal/files/debatch` to chunk the batch and mark the file
  `processed`; the step is idempotent on the terminal-file guard, so a
  workflow retry is a no-op.
- ~~`v1beta/scheduled-payments`~~ — **Cron wiring implemented** (design
  §10): `register_recurring_schedule` registers a real Cron schedule
  (`domain: payments`, `schedule_type: recurring-{instruction_id}`) whose
  fire proxies back into `POST /v1/internal/schedules/trigger` with the
  originating instruction's id; the Cron schedule id is persisted on the
  instruction for cancellation. The `v1beta` prefix stays until the
  recurring e2e spec lands (create → sandbox fast-forward → instruction +
  posting visible).

---

**Design attribution:** bank8:payments and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
