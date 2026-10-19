# SIEM integration — the enforcement feed and the lockdown seam

> Companion to `docs/design/architecture/mandu.md` (architecture),
> `docs/design/ui/dashboard.md` (the other observability consumer) and
> `docs/design/confidentiality/confidentiality.md` (the secret-label doctrine
> the export rule extends). Terminology pairs the paper term with the repo
> term — *T-LLM (privileged LLM)*, *AgentView (repo: Agent File System)*.
>
> **Status: the public seam is BUILT.** This document covers only the parts in
> this repository: the arbiter's event feed (§2), the contract an external
> exporter must keep (§4.2, §5), the wire format (§4.4, §4.5), the
> SIEM-triggered lockdown posture (§4.3) and the audit signals the arbiter
> emits for a SIEM to key on (§6). A redacting exporter and a SIEM rule set
> built on this seam exist as enterprise components and are not part of the
> public repository (`docs/design/distribution/licensing.md`).

---

## 1. Purpose

Feed Mandu's **deterministic enforcement facts** — blocked or allowed egress
with full symbol lineage, human verdicts, posture changes — into a fleet-level
SIEM, and let a SIEM detection tighten the per-host defense.

The division of labor: Mandu **prevents** (inline, per session, fail-closed);
the SIEM **correlates, retains and responds** (fleet-wide, after the fact).
The SIEM adds no prevention. What it adds is what a per-session defense lacks:
cross-session correlation (the same injected payload hitting several
sessions), a durable audit tier, and governance over human decisions (for
example a burst of approvals granted faster than anyone could review them,
which Mandu, judging each approval on its own, cannot see).

## 2. The seams the arbiter provides

- **Per-session append-only NDJSON.** The arbiter's event store
  (`arbiter/events/event-store.ts`) writes one `<sessionId>.ndjson` per session
  under the Mandu home's `events/` (`${MANDU_HOME:-~/.mandu}/events`,
  on-disk-layout.md §3; a per-launch arbiter writes its scope dir's
  `events/` instead — runtime-instances.md §12), one `ManduEvent` per line,
  append-atomic, torn-tail-tolerant. Any log shipper can tail it, but the raw
  files carry `DualRepr.original` and must not be shipped as they are (§5).
- **`events` / `subscribe` IPC.** The arbiter's Unix-socket NDJSON IPC
  (`arbiter/ipc/protocol.ts`) exposes `events` (poll since seq) and `subscribe`
  (backlog replay, then live push) — the same ops the dashboard's event source
  uses. An exporter is just another client; the arbiter-client pattern
  applies.
- **The canonical schema** (`dashboard/src/event-model.ts`) carries what SIEM
  rules key on: `kind` (`tool_result` / `net_action` / `fs_action` /
  `exec_action` / `tllm_call` / `ullm_call` / …), `view` (AgentView /
  HumanView / Quarantine), `policy.usage` (allow / deny / needs_approval),
  `policy.trust`, `policy.ruleRef` (a stable, catalog-keyed rule id on every
  usage-gate decision, policy-surface.md §9), `sessionId`, `ts`/`seq`, and
  `DualRepr` symbol refs.
- **The fingerprint tripwire** (`arbiter/policy/egress-fingerprint.ts`,
  confidentiality.md §4): blocked `net_action` events from the net-proxy carry
  `fingerprintTripwire: true` when raw secret bytes were spotted on an egress
  surface — a ready-made critical-severity key. The tripwire is deliberately
  fail-open (defense in depth under the watermark, not the guarantee), so its
  scan *errors* are events too: a SIEM is the right place to watch a
  fail-open layer.
- **The `arbiter-admin` audit stream.** Approvals are arbiter-global, not
  per-session, so the arbiter lands its audit events (verdicts, consumed
  once-grants, posture and configuration changes) in a reserved
  `arbiter-admin` session (§6).

## 4. Integration design

### 4.2 The exporter contract

An exporter is a standalone consumer of the event stream: it reads the
arbiter's events through the IPC (polling `sessions()` + `events(sessionId,
sinceSeq)` past a persisted per-session cursor is restart-resumable and
discovers new sessions; `subscribe` is the lower-latency alternative), and
writes **redacted, enriched** NDJSON to an append-only spool a SIEM shipper
tails. The reference exporter is an enterprise component; its code is not in
the public repository. Whatever implements it must keep:

- **Redaction (§5)** — the exporter's reason to exist.
- **Utility-only posture, like `reply-filter`.** Observability is off the
  security path (mandu.md): an exporter degrades to *dropping events*, never
  to blocking enforcement, and is never a dependency of any chokepoint. An
  exporter outage loses telemetry, not protection — the dashboard has the
  same property.
- **Enrichment** that fleet correlation needs and the raw files lack: host,
  OS user, arbiter instance id (runtime-instances.md), and a payload
  fingerprint (a hash of each UNTRUSTED span, computed before the span is
  stripped) for cross-session campaign correlation.

### 4.3 The SIEM-triggered lockdown posture

A SIEM response can ask the arbiter to tighten: one arbiter IPC op,
`setSessionPosture { posture: "lockdown", requestedBy }`, makes
`decideDesymWithApprovals` return `needs_approval` for **every** network
egress while the posture is lockdown. Mandu is then a policy *actuator*, not
only a sensor.

- **Enforcement stays in the arbiter.** The op only sets a
  `SessionPostureStore` (`arbiter/policy/session-posture.ts`); the egress gate
  consults it. The SIEM is a *requester* of a posture the hub already knows how
  to enforce — no policy logic leaves the arbiter. The check sits AFTER the
  prior-human-verdict short-circuit, so a human can still relax a specific
  egress per approval under lockdown (the one sanctioned relaxation); a fresh
  egress the pure gate would have allowed is queued. An applied change emits a
  `posture_change` audit event, which confirms to the SOC that its response
  took effect.
- **TIGHTEN-ONLY, enforced server-side.** `requestGlobal` refuses any request
  that would *lower* the posture — a SIEM rule can never relax policy;
  relaxation is a human act. The one sanctioned relax path is the op's explicit
  `allowRelax` flag, sent only by the dashboard's human-driven ▶ Resume route
  (the developer view's `posture-routes.ts`, policy-surface.md §9.8.6); an
  un-flagged loosen is a refused no-op. An applied relax audits through the
  same `posture_change` event (`posture=normal`), so engage and release are
  disjoint by the `posture` value and a human resume is visible beside the
  engage rather than inferred from silence.
- **GLOBAL scope.** The `DesymbolizationRequest` carries no `sessionId`, so
  only a global — campaign-wide — lockdown is enforceable at the network egress
  gate, which is what a cross-session campaign response wants. A per-session
  `sessionId` is *refused* by the op, not silently stored (the "posture nobody
  runs" bug class, confidentiality.md §12). Per-session lockdown awaits a
  sessionId at the egress gate.
- **Local-socket trust model.** The SIEM never touches the arbiter socket. Its
  active response may only append a lockdown *request* to a shared spool; a
  host-side applier, running as the socket-owning unprivileged user, reads the
  request and calls the op — the only component with arbiter access,
  consistent with the non-root principle (privilege-model.md).
  `setSessionPosture` (like `resolveEgressApproval`) is an admin-only op
  (policy-surface.md §2.6), refused on the data socket. In a
  supervised stack the admin channel is an fd only the supervisor holds, so a
  deployed applier goes through the dashboard's posture route; no such
  applier ships in this repository.

Tests: `arbiter/test/unit/session-posture.test.ts` (tighten-only, the
`allowRelax` path, global scope, and the end-to-end wiring through the egress
gate, not a mock).

### 4.4 Wire format

Keep the **native event schema as the wire format** — do not contort
`ManduEvent` toward a SIEM taxonomy; map it (native → ECS, → OCSF) in the
pipeline that normalizes.

**The chain head.** Every stored event carries `chain`, a SHA-256 link over
the previous line's link and this line's JSON (`events/event-store.ts`,
`chainLink` / `verifyChainText`, op `verifyEvents`). An exporter forwards it
untouched (redaction leaves it), so the SIEM holds each session's chain head
as it goes: a log later rewritten on the host no longer matches what the SIEM
received. Lines written before the chain existed are an unchained prefix the
verifier skips.

### 4.5 Claimed events

The arbiter marks every event it did not get from a channel the agent's
programs cannot reach `claimed: true` (arbiter-human-plane.md §10.2): its
`emitter` and every field are the sender's word. An exporter ships the field
as is; a rule may show a claim, but correlation rules and anything that can
trigger the lockdown (§4.3) must never act on one.

## 5. What may leave the host — the export redaction rule

The stored events' `DualRepr` carries `original` — raw untrusted payloads and,
on some paths, secret material. Bulk-copying that into a SIEM index would be a
confidentiality regression (secrets sprayed into a second, differently-secured
data store — the confidentiality.md doctrine applies to *every* egress of
labeled data, and an exporter is an egress) and a second-order **IPI
regression**: raw injection payloads sitting in a SIEM index are attack input
to the SOC's own tooling — an analyst-side LLM assistant reading the index
would ingest the very payload Mandu symbolized. The SIEM sits in HumanView
organizationally, but it must receive **AgentView-shaped data**:

> **Export rule: an exporter ships `symbolized` forms, symbol refs, and
> content hashes — never `DualRepr.original`.** The dashboard remains the sole
> original-viewing surface; an analyst pivots from a SIEM alert to the
> dashboard (by `sessionId` + `seq`) to see originals under Mandu's own
> access model.

The redaction walk is structural: top-level scalars a rule keys on (`posture`,
`axis`/`from`/`to`/`requestedBy` on a `config_change`, `promptAnswer`, …) pass
through untouched; `original` and symbol values do not. The rule is an oracle:
a test feeds events whose `original` differs from `symbolized` through the
exporter and asserts that no original byte sequence appears in any spool line.

The prompt filter's events are held to more than this rule: they are
allowlisted field by field, because the found text in a human's prompt has no
`original` to null, only fields a buggy or claimed emitter could put it in
(§6.6).

## 6. Audit signals for a SIEM

The arbiter emits these into the `arbiter-admin` stream; each carries names,
destinations and decisions, never a resolved value.

### 6.3 Human verdicts and standing grants

- **`approval_resolved`** — one event per human verdict on the approval queue
  (symbol names + destination only). A human *deny* is distinct from the
  automatic fail-closed block and should alert separately. Approvals are
  arbiter-global, so a burst of grants faster than any could be reviewed
  (rubber-stamping) is visible in this one stream.
- **Standing grants.** A persisted *standing* (`scope: "always"`) approval
  never expires and its reuse emits no event, so a SIEM-side governance sweep
  lists the standing queue and flags grants older than a review horizon.
- **Once-scoped grants are excluded from that sweep**
  (policy-surface.md §9.8.7): an "Allow once" verdict is not standing authority — unspent it is
  worth exactly one use, spent it grants nothing — and its consumption emits
  `approval_consumed`, so its whole lifecycle is already in the stream.
- **`posture_change`** (§4.3) and **`config_change`** — the dashboard emits one
  `config_change` per protection axis whose effective next-boot value flipped
  (top-level `axis`/`from`/`to`/`requestedBy`); turning protection off is the
  consequential act and leaves an attributable who/when trail.

### 6.6 The prompt filter

The prompt filter (confidentiality-plan-15-prompt-filter.md) scans the
human's own prompt for registered values, key shapes and an organization's
patterns, and maps each finding's category to `log`, `redact`, `mask`, `ask`
or `block`. The SIEM's job here: an organization that turns on `log` for every
category first sees what would be caught before it enforces.

- **Findings.** The model proxies emit one `prompt_filter` event per segment
  with a finding. An exporter forwards it under an **allowlist**, not the §5
  structural walk alone: only the fields the event model names
  (`PromptFilterDetail`), each checked for its shape, with any summary sentence
  rebuilt from them (the proxy's own sentence is free text, where a value
  would hide). A finding's filter id and category can be checked against what
  the policy declares through the arbiter's data-plane `promptFilters` op
  (filter ids and their categories, never a pattern or a keyword); anything
  unknown goes as unverified (fail closed: counts and outcomes still flow).
- **The hold and its answers.** An `ask` files a row in the approval queue
  (`prompt:<category>#<ref>` × `model:<session>#turn:<turn>`), and the human's
  answer lands in `approval_resolved` like any verdict. The row's status cannot
  tell "send masked" from "cancel", so the arbiter stamps `promptAnswer`
  (`send`, `mask`, `cancel`, `let-through`) and `promptScope` (`once`,
  `session`) on the event (`arbiter/ipc/server.ts`). A prompt answer is not an
  egress approval: rules on denied egress or approval fatigue must not count
  it. A pending hold nobody answered past the hold deadline is visible only to
  a sweep of the queue (a proxy restart kills the held request, so the proxy
  may never report it).
- **What never leaves.** The event model carries no found text, and an
  allowlisting exporter drops every field it does not name, so neither a
  `prompt_filter` event, a hold's answer, nor a queue row can carry one into
  the spool even when a buggy or claimed emitter adds one. `promptRef` and
  `promptTurn` are keyed HMACs (plan 15 §13.6), so a SIEM can correlate one
  span across events without holding a dictionary-reversible hash of it.
