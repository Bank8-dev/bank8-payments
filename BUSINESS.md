# Bank8:Payments - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Bank8:Payments **does for the business**. For architecture read
> `README.md`; for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Bank8:Payments is the **payment orchestration layer** of the bank8
vertical. It delivers:

- **Payment execution that survives reality** - instructions become
  multi-step workflows with retries, wait states, and manual decisions;
  a payment can span minutes or days without anyone babysitting it.
- **Scheme breadth out of the box** - B8 on-us, SEPA, TIPS, and SWIFT
  AGI scheme flows over a typed ISO 20022 message catalogue, plus card
  issuing with full card lifecycle and 3-D Secure.
- **One rule engine for routing & eligibility** - versioned rules,
  parameters, logics, integrations, and cores drive how each payment is
  routed and what it may do; drafts never execute, so change is safe.
- **Straight-through processing with human escalation** - the
  manual-decision task loop (claim / approve / reject) inserts human
  judgement exactly where the scheme or risk policy requires it.
- **File-based banking** - ISO 20022 file intake, debatch, and
  confirmation handling for corporate volume payment flows.
- **A sandbox that mirrors production** - built-in simulators for cards,
  credit transfers, FedNow, and SWIFT AGI let tenants develop and test
  payment journeys without external scheme dependencies.

## 2. Business Scope (What the Service Provides)

| # | Capability area | What the business gets |
|---|---|---|
| 1 | Payment instructions | Create/initiate payments, retry, cancel, repair, bulk-retry; full status tracking through a guarded state machine |
| 2 | Scheme flows | B8, SEPA, TIPS, SWIFT AGI payment flows over the typed ISO 20022 catalogue |
| 3 | Payments records | Scheme result records per instruction with queryable status history |
| 4 | Cards | Card issuing, replace, details/PIN management (get/update PIN, reset LVT, reset PIN attempts), card sessions, tokens, orders and order batches |
| 5 | Cardholders | Cardholder registry with holder-scoped data protection |
| 6 | Card products | Card product definitions with BIN/account-range management |
| 7 | 3-D Secure | 3DS challenge records for card-not-present authentication |
| 8 | Mandates | Direct-debit mandates with amount limits |
| 9 | Payees | Payee registry with search |
| 10 | Routing | Payment instruments, account links, on-us routing, and rule-attach/detach per instrument |
| 11 | Rule engine | Versioned rules, rule sets, rule versions with publish, retry, and instrument binding |
| 12 | Parameters | Versioned payment parameters and parameter values |
| 13 | Logics | Instruction logics (per-instruction execution definitions) with WASM migration path |
| 14 | Integrations | Scheme gateway integrations (versioned), integration callbacks, payment-initiation apps |
| 15 | Cores | Core banking connections with versions, account ranges, and balance endpoints |
| 16 | Files | ISO payment file intake/submit, instruction files, per-file debatch processing |
| 17 | File specifications | Instruction file specification + versions, with validation |
| 18 | Tasks & manual decisions | Task queue with claim/approve/reject; manual decisions with submit |
| 19 | Config library | Templates (versions, presets, publish), dashboards (versions), config packs, app template/dashboard validation |
| 20 | Membership directories | Membership directory versions and record search |
| 21 | Calendars | Business-day definitions and calendars for payment timing |
| 22 | Recurring payments | Scheduled payments with occurrence generation and sandbox fast-forward |
| 23 | Sandbox | Simulators: cards, credit transfers, FedNow, SWIFT AGI, instruction resume, scheduled-payment fast-forward |
| 24 | Self-describing ops | Allowed-endpoints, roles, users, audit, metrics (Prometheus + OpenMetrics) |
| 25 | Admin console | Remote admin pages over the payments data plane (accounts → cards → instructions → rules) |
| 26 | Domain events | 25 resource types × lifecycle operations (`created`/`updated` + specific flows) on the `bank8:payments:*` family |
| 27 | Health | Service health endpoint for fleet supervision |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Workflow step execution & retries (the engine) | Sentin8:Flow (Payments implements the step functions) |
| Timing of scheduled/recurring work | Sentin8:Cron |
| Tenant-authored executable hooks | Sentin8:Func |
| Balances, postings, accounts (the money record) | Bank8:Ledger (Payments calls its public API - never writes balances itself) |
| Customer identity, sign-in, sessions | Sentin8:Auth |
| Event transport, durability, consumer DLQ | Sentin8:Bus |
| Analytics dashboards / KPI computation | Sentin8:Stat |
| File/object payload storage (ISO archives) | Sentin8:Storage |
| API proxying to client apps | Sentin8:BFF |
| Scheme certification (Visa DPS, MDES, SWIFT test beds) | External / tenant-driven - the service ships the adapter seams and simulator parity |

## 3. Business Capabilities

### 3.1 Payment instructions

| Capability | Business rule |
|---|---|
| Create / initiate a payment | Every payment starts as an instruction with an idempotency key; the same request twice yields the same instruction, never two payments |
| Execution model | Async instructions become Flow workflows (multi-step with retries); sync schemes (B8 on-us, SEPA instant) execute inline without a workflow round-trip |
| Instruction states | `pending → processing → completed` is the happy path; `processing → failed` captures step errors; `waiting` parks an instruction for a callback or human decision; `failed → pending` is the guarded retry; **any non-terminal state may go to `cancelled`**; `completed` and `cancelled` are terminal and immutable |
| Status tracking | Payment statuses are auto-synced on every state transition; operators always see the true state |
| Retry / cancel / repair | Failed instructions can be retried (guarded - terminal states never change); pending/processing/waiting instructions can be cancelled; repair corrects stuck instructions |
| Bulk retry | Failed instructions are retried in bulk from the ops surface |
| Money movement | Every financial movement is a posting step that calls Bank8:Ledger's public API - Payments never writes balances itself |
| Fee collection | `FEE_COLLECTION` is a first-class processing status - scheme/transfer fees are collected as their own posting flow, not silently netted off the payment |

### 3.2 Scheme flows (ISO 20022)

| Capability | Business rule |
|---|---|
| B8 on-us | In-house transfers between the bank's own accounts execute synchronously - credit transfers and direct debits, each with outbound/inbound legs, plus dedicated account-to-account (a2a) on-us flows |
| SEPA / TIPS | European instant payment flows over the typed ISO 20022 catalogue: credit-transfer outbound/inbound, outbound rejection, outbound return, inbound automatic return, and **recall** handling with per-recall-type deadlines |
| SWIFT AGI | Cross-border SWIFT flows with the same step model |
| Scheme adapters | Visa DPS and MDES adapters for card traffic; ISO 8583 message handling for card-present authorization flows |
| UETR tracking | Every cross-border instruction carries a UETR (unique end-to-end transaction reference) generated at creation |
| Message correctness | The ISO 20022 catalogue is typed end-to-end - message codes are compile-checked, not stringly-typed |
| Decline mapping | Decline reasons map to ISO 8583 response codes (e.g. card-suspended → 57, velocity/accumulator breaches → 62, ATC range violations → 63, product constraint violations per payload type) so scheme responses are standardized |
| Sandbox parity | The same code paths run against built-in simulators, so dev/test behaviour mirrors production |

### 3.3 Cards

| Capability | Business rule |
|---|---|
| Issue a card | Cards are issued per card product, with BIN/account-range validation |
| Card lifecycle | Five states: `pending_creation → inactive → active`, `active ↔ suspended` (freeze/unfreeze), `→ disabled` (terminal). Only legal transitions pass: e.g. a suspended card can reactivate or retire, but a disabled card never transitions again |
| Idempotent transitions | Re-asserting the current state is a no-op - re-activating an active card never errors or double-audits |
| Replace | Lost/damaged cards are replaced with lifecycle continuity |
| PIN management | Get/update PIN, verify PIN, reset PIN attempts - PIN operations are separate, audited actions |
| Velocity control | LVT (low-value/contactless transactions) counters + accumulators and ATM (ATC) transaction counters; reset on demand; accumulator updates are race-free guarded updates |
| Velocity decline reasons | Contactless amount exceeded, LVT count/accumulator limits, ATC outside allowed range, duplicate ATC - each maps to the standard "Restricted" decline family |
| Card sessions | Session initiation for card interactions (challenge flows), with encrypted session types |
| Tokens | Card tokens (device wallet tokenization) are tracked per card |
| 3-D Secure | 3DS records track card-not-present authentication through `pending → frictionless | challenged → authenticated`, with `failed`/`declined` outcomes and challenge-method configuration |
| Card details | PAN/CVV are stored only encrypted (per-card key material, `pan_last_digits` + expiry for safe display); card-id is the PCI-safe token for external systems |
| Orders & batches | Card orders (individual + batch) cover bulk issuance (e.g. corporate fleet); batches group orders into manufacturing runs |
| Profiles | Each card binds a card profile; products carry issuing plans (`card_profile_id`, `bin_prefix`, `default_expiry_months`) and expiry plans (`expiry_months`, `expiry_policy`, `auto_renewal`) |
| Cardholder protection | Cardholder data is holder-scoped: only the holder (or authorized staff) sees it |

### 3.4 Mandates & payees

| Capability | Business rule |
|---|---|
| Mandates | Direct-debit mandates (ISO 20022 pain.009 structure) carry creditor identity (scheme creditor + mandate IDs) and amount limits; drawing beyond the mandate is a rule-engine decision, never silent |
| Mandate lifecycle | `active → suspended → cancelled`, plus `expired`; only an active mandate can be drawn against - mandate lookup enforces it |
| Mandate flow direction | Each mandate is `outbound` (we debit) or `inbound` (we are debited) - direction is explicit, never inferred |
| Payees | Payee registry with search; payees are the beneficiary catalogue for retail transfers |
| Recurring payments | Scheduled payments generate occurrences on a calendar; sandbox fast-forward advances time for testing |

### 3.5 Routing & the rule engine

| Capability | Business rule |
|---|---|
| Payment instruments | The routing catalogue (cards, IBANs, aliases) resolves which instrument a payment uses |
| Account links | Instruments link to ledger accounts via account links - routing never guesses an account |
| On-us routing | On-us routes decide which payments stay in-house vs. leave to a scheme |
| Rules & rule sets | Versioned rules/rule sets with publish; drafts never execute - only published versions route |
| Instrument binding | Rules attach to/detach from specific instruments for per-instrument policy |
| Parameters | Versioned parameters configure routing/eligibility thresholds |
| Logics | Per-instruction execution logics, versioned, with a WASM migration path |
| Integrations & cores | Scheme gateways and core connections are versioned, published entities - swapping a gateway is a configuration change, not a release |

Integration/gateway settings a tenant configures per version:

| Setting | Options |
|---|---|
| Version lifecycle | `pending → ready` (published & active for traffic), `errored` (validation failed), `user_action_required` (e.g. pending OAuth consent) - the parent integration holds an `active_version_id` pointer, and published versions are immutable |
| Authentication | Static bearer token, OAuth client-credentials grant, or OAuth password grant - credentials live in the version's auth config, not in code |
| Healthchecks | Endpoint + interval (default 30 s) + timeout (default 10 s) so dead gateways are detected, not discovered by customers |
| Retry policy | Per-integration retry policy governs outbound gateway calls |
| Connectivity | Per-integration connectivity configuration (e.g. mode) for the target system |

### 3.6 Files (corporate volume payments)

| Capability | Business rule |
|---|---|
| File intake | ISO payment files are registered, submitted, and processed through a per-file debatch workflow |
| Idempotent debatch | The debatch step is idempotent on the terminal-file guard - a workflow retry never duplicates batch chunks |
| Specifications | File specifications + versions define the accepted formats; validation catches bad files before processing |
| Confirmations | Confirmation files close the loop on processed payments |

### 3.7 Tasks & manual decisions

| Capability | Business rule |
|---|---|
| Task queue | Work that needs a human lands in a task list with claim/approve/reject |
| Manual decisions | Risk/compliance decisions are recorded as manual decisions with submit; decision timeout has defined interruption handling |
| Audit | Every decision carries the actor - human intervention is fully auditable |

### 3.8 Config library & operations

| Capability | Business rule |
|---|---|
| Templates & dashboards | Template versions/presets and dashboard versions drive app-facing payment surfaces; publish makes them live |
| Config packs | Bundled configuration ships as packs for repeatability |
| Membership directories | Directory versions + record search resolve scheme membership (e.g. bank identifier lookups) |
| Calendars & business days | Business-day definitions and calendars govern when payments are due/processed |
| Metrics | Prometheus and OpenMetrics endpoints (incl. federation) expose operational health |
| Audit | OCSF-shaped audit events for every domain action |
| Self-describing | Allowed endpoints, roles, and users surfaces let apps render what the caller can do |

## 4. Business Events (Outbound)

Event names are the business contract - consumers subscribe on these.
Family prefix: `bank8:payments:`; resource types × `created`/`updated`
operations plus specific flows:

| Resource / event | Fires when |
|---|---|
| `instruction:created` / `:updated` / `:retried` / `:cancelled` / `:repaired` | Instruction lifecycle changes |
| `payment:created` / `:updated` | A scheme result record appears/changes |
| `instruction_logic:created` / `:updated` / `:wasmmigrated` | Logic lifecycle + WASM migration |
| `payment_instrument` / `account_link` | Routing catalogue changes |
| `card` (+ `cards:encrypted`) / `cardholder` / `card_order` / `three_ds_record` | Card domain changes |
| `core` / `core_version` | Core banking connection changes |
| `file` / `instruction_file` | File intake/processing changes |
| `integration` / `integration_version` | Scheme gateway configuration changes |
| `manual_decision` | A human decision is recorded |
| `membership_directory` | Directory version changes |
| `parameter` | Payment parameter changes |
| `rule` / `rule_version` / `rule_set` / `rule_set_version` | Rule engine changes |
| `template` / `template_version` / `dashboard` | Config library changes |

**Inbound (consumed):**

| Event | Consumer behaviour |
|---|---|
| `bank8:payments:instruction:*` (own family, SSE) | The embedded re-drive worker turns instruction events into Flow resume/retry - terminal states are skipped (idempotent) |

## 5. Business Rules & Invariants

1. **A payment is idempotent.** The same instruction request twice yields
   the original instruction - money never moves twice for one request.
2. **Terminal states are final.** A completed, failed, or cancelled
   instruction never silently changes state; every transition is
   state-machine-guarded.
3. **Payments never touch the books directly.** All money movement goes
   through Bank8:Ledger's public API - balance truth has exactly one
   writer.
4. **Drafts never execute.** Only published rule/logic/integration/core
   versions are eligible for routing; configuration change is safe by
   construction.
5. **Async instructions are never pending without a workflow.** Creation
   commits only when the Flow workflow exists; a Flow outage fails the
   request with nothing committed.
6. **Money is never approximate.** All money values are exact decimals
   end-to-end.
7. **Every domain change emits its event.** Events ride the outbox in the
   same transaction as the domain change - a crash between commit and
   delivery loses nothing (at-least-once with idempotent consumers).
8. **Human decisions are auditable.** Claims, approvals, and rejections
   carry the actor and land in the audit trail.
9. **Tenant isolation is absolute.** Every record is environment-scoped
   with row-level security; cardholder data is additionally holder-scoped.
10. **Availability and authorization are distinct.** A disabled feature
    returns 503 (availability); an unauthorized caller gets 403 - never
    conflated.
11. **Re-drive is effectively-once.** The worker's terminal-state skip plus
    guarded SQL means a redelivered instruction event can never
    double-execute a step.

## 6. Target-User Roles & Use Cases

| Persona | What they do with Bank8:Payments |
|---|---|
| Retail customer (via eBank) | Initiates transfers, sees payment status, manages payees and mandates, uses card details/PIN via secure flows |
| Corporate treasurer (via eFinTech) | Uploads ISO payment files, tracks batch processing, monitors task queue outcomes |
| Bank operations staff (via eTeller) | Claims tasks, makes/approves/rejects manual decisions, retries or repairs stuck instructions, issues/replaces cards |
| Card product manager | Defines card products, BIN ranges, velocity rules; resets LVT/ATC accumulators |
| Payments product owner | Authors rules/rule sets/parameters/logics, publishes versions, manages templates & dashboards |
| Integration engineer | Registers scheme gateway integrations, points them at scheme test beds, runs certification evidence collection |
| Compliance / auditor | Reads the OCSF-shaped audit trail, traces instruction state history, verifies decision records |
| Downstream services / apps | Subscribe to `bank8:payments:*` events; query instructions/payments through the public API |
| Developer / QA | Uses the sandbox simulators (cards, credit transfers, FedNow, SWIFT AGI, fast-forward) to exercise production-parity flows |

## 7. KPIs / Success Criteria

- **Straight-through processing rate**: share of instructions completing
  with no manual intervention.
- **Payment success rate**: instructions reaching `completed` per scheme,
  with failure reasons classified (validation, scheme, posting).
- **Idempotency integrity**: zero duplicate money movements under client
  retry or event redelivery.
- **STP latency**: sync schemes (B8 on-us, SEPA instant) complete inline
  within the platform SLA.
- **Task turnaround**: manual decisions claimed/resolved within the
  business SLA; decision-timeout interruptions rare and handled.
- **File processing reliability**: debatch workflows complete without
  duplicate chunks; confirmations reconcile.
- **Card operations**: issuance/replace/PIN flows succeed; accumulator
  resets are race-free under load.
- **Event delivery**: 100% of domain changes reach Sentin8:Bus (relay
  retry budget + manual replay backstop).

## 8. Dependencies & Reliance on Other Services

| Relies on | For |
|---|---|
| Sentin8:Flow | The workflow engine: async instruction execution, retries, wait states, per-file debatch workflows |
| Sentin8:Cron | Firing recurring schedules (proxy-back trigger per instruction) |
| Sentin8:Bus | Durable event delivery; the SSE stream the embedded worker consumes |
| Sentin8:Auth | Token verification; certificate identity (CERTFREE-4V) for machine calls |
| Sentin8:Policy (Shield) | The authorization decision on every request and step execution |
| Bank8:Ledger | Every posting/money movement (public API only) |
| Sentin8:Storage | ISO file archives and confirmation payloads |
| Sentin8:Stat | Metric ingest / telemetry |
| Sentin8:Sys | Central audit ingest via the journal pusher |
| Sentin8:BFF | All client traffic (`/proxy/payments/*`) |

## 9. Acceptance Criteria

1. Creating an instruction twice with the same idempotency key returns the
   original instruction; a single payment results.
2. An async instruction only commits when its Flow workflow was created;
   a Flow outage leaves nothing committed and the client may retry.
3. A failed instruction can be retried and completes; a terminal
   (completed/cancelled) instruction rejects any state-changing request.
4. Every money movement appears as a Bank8:Ledger posting initiated
   through the ledger's public API - Payments holds no balance-writing
   path.
5. A rule/logic/integration/core version in draft state is never used for
   routing; only published versions are.
6. An instruction that requires human intervention lands in the task
   queue; claim → approve/reject is auditable with actor attribution.
7. A card can be issued, replaced, PIN-managed, velocity-reset, and
   3DS-challenged through the API; cardholder data is visible only to
   the holder and authorized staff.
8. An ISO payment file can be registered, submitted, debatched (idempotent
   on retry), and confirmed; validation rejects malformed files before
   processing.
9. A recurring payment generates occurrences via the Cron wiring and can
   be fast-forwarded in the sandbox.
10. All tenant data is invisible to other tenants; every domain change
    emits its `bank8:payments:*` event; the audit trail (OCSF-shaped)
    records every action.
11. Each capability in §2 is operable through the dashboard admin pages
    and/or the BFF-proxied API - no operator needs direct database access.

## 10. Open Business Questions

- Recurring payments (`v1beta/scheduled-payments`) remain beta until the
  end-to-end recurring spec (create → fast-forward → instruction + posting
  visible) lands - when does the business want GA?
- Which schemes are next in the certification pipeline, and what is the
  tenant-driven certification runbook cadence?
- Should manual-decision timeout policies be per-tenant configurable
  (currently one defined interruption handling path)?
- Is there business demand for additional sandbox scheme simulators
  beyond cards / credit transfers / FedNow / SWIFT AGI?
- What is the business appetite for card crypto HSM production
  integration (the current crypto layer is a documented placeholder seam)?

---

**Design attribution:** bank8:payments and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
