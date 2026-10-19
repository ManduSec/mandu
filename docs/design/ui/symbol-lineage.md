# Mandu — Symbol lineage: the provenance view in the dashboard

> **Status: IMPLEMENTED (2026-07-15) — phases 0–3 + the §9 test plan, in one
> change.** Phase 0 closed G1 (fs-sync mints emit birth events; the launcher
> passes `--session` to `fs-sync-cli init` so seed-time births land in the
> scope), G2 (`derivedFrom` — and `lineRange`, an addition over this design —
> ride the `symbolize` op into `derived_from`/`line_range`; inspect-mcp and
> the split path pass them), and G3 (`tool_use` AND `exec_action` events carry
> structured mined refs). Phase 1 is `dashboard/src/view-model/lineage.ts`
> (`toSessionLineage`, §3 as specified; dashboard.md §4.15). Phase 2 is the
> third dv-mode + the SVG evidence graph + the §5.3 entry points. Phase 3 is
> the per-flow *⧉ copy evidence JSON* + `verdictCopy`/`flowsSummaryLine`
> (enforcement-mode wording). §9's checks (`evalLineage*`, category
> `fidelity`, `tests/lib/assertions-lineage.ts`) ride replay-e2e and
> claude-e2e. Two catalog deviations found at build time: `egress_request`/
> `egress_decision` are kind names no emitter produces yet (the builder and
> the egress edge support them — dormant, §3.2), and `declassified` likewise
> awaits a declassify emission. G5 (death events) and UC6 (cross-session
> stored-IPI) stay deferred as designed.
> Companion to
> [`mandu.md`](../architecture/mandu.md) (architecture),
> [`symbol-quality.md`](../integrity/symbol-quality.md) (the
> `content_kind` verdict this view surfaces), and
> [`fs-provenance.md`](../integrity/fs-provenance.md) (the process/file
> **taint** layer — a different lineage system; §7 relates the two). Paper
> terms are paired with repo terms per `mandu.md` §8.
>
> In one line: the dashboard gains a **data-lineage view** — for any
> untrusted datum, the recorded chain *origin → symbol (`$MDU:*`) → model
> context → tool-call echo → egress verdict* — rendered on the existing
> two-view geometry so that a blocked exfiltration is literally an edge that
> **dies at the trust wall**. Lineage is built as *evidence*, not
> illustration: every edge carries the id of the event that proves it, and an
> edge with no event does not render.

## 1. Why: four uses shape the design

Four uses of this feature each impose a design constraint:

| Use | What it needs from lineage | Design consequence |
|---|---|---|
| Per-action provenance in the trace | an auditable, replayable record of where each action's data came from | every rendered edge must be **backed by a stored event** (assessor can replay it) |
| Shadow mode: "14 flows last week where a poisoned page could have steered your agent" | that sentence **is** a lineage query: count complete origin→model→egress paths | a first-class **flow** unit + per-session aggregate counts, with enforcement-mode-aware wording ("blocked" vs "would have been gated") |
| the deferred injection-contrast demo ([`mandu-demo.md`](../distribution/mandu-demo.md) §9; the built `mandu demo` shows the `secrets` mode (hide, use, stop) and has no trace step) | the key frame: poisoned page → symbol → `curl` echo → **⛔ blocked** | the per-symbol graph must read at a glance, unlabeled, to a first-time viewer |
| Per-session provenance ships now; SIEM export comes later | lineage should become the exportable evidence unit later without rework | the graph is a serializable JSON value (`SymbolLineage`) before it is pixels |

The standing rule that *claims must not outrun the build* becomes this doc's
core principle:

> **Evidence rule.** The lineage view renders only edges derivable from
> recorded `ManduEvent`s; every `LineageEdge` carries `{eventId, seq}`. No
> inferred edges, no interpolation. Where the system does not yet record an
> event for a real flow step (§2.4 gaps), the fix is to **record the event**
> (phase 0), never to synthesize the edge in the view.

## 2. What the system records today (inventory)

Verified 2026-07-15 against the tree; file:line refs are to that state.

### 2.1 The symbol table (arbiter, persisted)

`arbiter/symbol-table/symbol-table.ts` — `symbols` rows carry, besides the
token and raw value: `tool` (origin tool, full name), `field`, `origin`
(URL / dir / channel — **or a parent symbol name**, see §2.2), `session_key`,
`call_id` (originating `tool_use.id`), `created_at`, `confidentiality`,
`bindings`, `integrity`, `obsoleted_at` / `obsoleted_by` (death), and
`derived_from` + `line_range` (split lineage). The dashboard **never opens
this DB** (`dashboard/src/event-model.ts:415-417`) — by design, and this
feature keeps that.

### 2.2 Four fragmented lineage notions

1. **Split lineage** — `derived_from` + `line_range` columns, written only by
   `allocateDerivedSymbol` (`symbol-table.ts:745`). The only true
   parent→child edge *inside* the table.
2. **Inspect (U-LLM) re-symbolization lineage** — `inspect-mcp` mints the
   result symbol via plain `symbolize({tool:"inspect", origin: <parent
   symbol>})` (`interceptors/inspect-mcp/src/inspect-symbol.ts:391-397`):
   parent is in the **`origin` column**, not `derived_from`; the emitted
   `ullm_call` event carries it as `SymbolRef.derivedFrom`. A view that
   follows only `derived_from` misses every U-LLM-derived symbol.
3. **Tool-call provenance** — `symbols.call_id → toolCalls` (in-memory map,
   `arbiter/ipc/server.ts:164`), surfaced by the `symbolProvenance` op. Lost
   on arbiter restart (persistence explicitly deferred, `symbol-quality.md`
   §4.7).
4. **Process/file taint** — `arbiter/provenance/provenance-store.ts`
   (`process_taint`, `process_lineage`, `file_taint`): host-level byte/process
   ancestry, keyed on hosts and paths, not symbols. See §7.

### 2.3 The event stream already carries most of the journey

Events are per-session append-only NDJSON (`arbiter/events/event-store.ts`),
schema `dashboard/src/event-model.ts`. Every event payload is a `DualRepr`
with **structured `SymbolRef[]`** (`name`, `tool`, `field`, `origin`,
`value`, `derivedFrom`, `lineRange`, `confidentiality`) — so a symbol's
references are discoverable both structurally and by the token grammar
(`$MDU:<tool>[<hash>](.<field>)*`). The view-model already reconstructs a
per-symbol cross-event trace: `toSymbolInspector`
(`dashboard/src/view-model/symbols.ts:70-113`) computes `flow:
SymbolFlowStep[]` (`created` → `seen`…) plus birth anchors — but it renders
as display-only prose in the symbol table's Flow column. `toDualLanes` computes
per-tool translation bands (`downSyms`/`upSyms`) and first-mint markers
(`newSymbols`). Lineage is therefore largely **net-new rendering plus a graph
builder over data that already exists.**

### 2.4 Gaps (each is a phase-0 or deferred item, never view-side inference)

| # | Gap | Where | Disposition |
|---|---|---|---|
| G1 | **Non-proxy births emit no event.** The arbiter `symbolize` op does not emit (`server.ts` dispatch, verified); emission is caller-side — the model proxies (`anthropic-proxy/src/events.ts` `makeSymbolize`) and, since phase 0, fs-sync: whole-file mints (`fs-sync/src/symbolize.ts`) and split mints (human-edit flow) emit `symbolize` birth events (`fs-sync/src/events.ts`), and those births now render in the trace as the batch birth card with ⊕ mint markers (dashboard.md §4.2e). | fs-sync, arbiter | **CLOSED** — phase 0 emits at the mint call sites (caller-emits pattern, D1); trace rendering 2026-07-30 |
| G2 | Inspect lineage never reaches the `derived_from` column (§2.2.2); `SymbolizeArgs` in inspect-mcp's arbiter client has no `derivedFrom` field. Event-side lineage exists (`ullm_call` → `SymbolRef.derivedFrom`), so the *view* is unblocked; the table is inconsistent. | inspect-mcp, arbiter | **Phase 0** (hygiene) — plumb `derivedFrom` through `symbolize`; keep `origin` for back-compat |
| G3 | `tool_use` events carry the echoed token only embedded in `input.symbolized` text — no structured `symbols[]`; readers regex-mine it (the regex is already twinned in 4+ places). | anthropic-proxy `makeToolUse` | **Phase 0 (optional)** — mine once at emit, attach `symbols[]`; regex stays as fallback |
| G4 | `SymbolRef.confidentiality` / `EventPolicy.confidentiality` are emitted but **never rendered** in the trace, inspector, or symbol table modal (only the Secrets panel + seed banner read them). | dashboard | **Phase 2** — badge on lineage nodes (reuse `confBadge`) |
| G5 | Symbol death (`obsoleted_at`/`obsoleted_by`) is never evented and not projected into any view-model. | arbiter, dashboard | **Deferred** — un-defer when a use-case needs death rendered (e.g. human-edit review flows) |
| G6 | `content_kind` (the 7-token quality verdict) is per-symbol metadata but never persisted (deliberate — `symbol-quality.md` §4.7 owns that deferral). It **is** captured in the triage `ullm_call` event. | inspect-mcp | Consume opportunistically from events (phase 2 chip); no persistence change here |
| G7 | Events are per-session files; a **cross-session** chain (stored IPI: session A writes poisoned data to disk, session B re-reads it) cannot be joined today. | event store | **Deferred** (UC6) — the join key exists (`file_taint` rows + symbol `origin` path) |

## 3. The lineage model

### 3.1 Shape

A pure function in the dashboard view-model (same pattern as
`toSymbolInspector` — server-computed, unit-testable, no client logic):

```
toSessionLineage(events: ManduEvent[]): SessionLineage

LineageNode = {
  id: string                        // symbol name, or synthesized origin/sink id
  kind: "origin" | "symbol" | "context" | "action" | "sink"
  lane: "External" | View           // View = AgentView | HumanView | Quarantine
  label: string                     // short display form
  symbol?: SymbolRef                // for kind "symbol": full provenance
  verdict?: Verdict                 // for kind "sink"/"action": terminal outcome
  eventId: string; seq: number      // the event that establishes the node
}

LineageEdge = {
  from: string; to: string
  kind: "fetched_by" | "minted" | "entered_context" | "echoed"
      | "derived_inspect" | "derived_split" | "gated"
      | "egress" | "revealed_reply" | "declassified"
  verdict?: "allowed" | "approved" | "denied" | "blocked" | "pending"
  eventId: string; seq: number      // EVIDENCE — mandatory (§1)
  askId?: string                    // gated/egress edge that stopped the data: the
                                    //   Approvals row its event filed (dashboard.md §4.15)
}

SymbolLineage  = { root: string; nodes: LineageNode[]; edges: LineageEdge[]; summary: FlowSummary }
SessionLineage = { flows: SymbolLineage[]; stats: SessionFlowStats }
```

A **complete flow** (the §9.1 shadow-sentence unit) is a `SymbolLineage`
containing at least one `minted` edge, one `entered_context` edge, and one
`egress`/`gated`/`revealed_reply` edge — i.e. untrusted data that entered the
trust boundary and later touched an egress surface. `SessionFlowStats` counts
flows by terminal verdict (`egressAllowed`/`egressBlocked`/`egressPending`,
for the badges). Its `outcomes` counts flows per outcome their edges recorded.
A flow counts under every outcome it had, so a token sent to its bound host
and blocked at another is in both counts. `FlowSummary.secret` marks a secret
flow (`isSecretFlow`). Every count is over the masked items only: a flow
rooted at a token the model composed itself (`summary.modelAuthored`, §9.1
*Model-authored tokens are not symbols*) stays in `flows`, for its card and
graph, but `stats.flows` and the rest leave it out, and `stats.composed`
counts it (2026-10-09, dashboard.md §4.15 *A token the AI composed is not
masked*).

### 3.2 Edge catalog — every edge names its source event

| Edge | Meaning | Source event(s) | Notes |
|---|---|---|---|
| `fetched_by` | the T-LLM-authored tool call that produced the datum | `tool_use` ↔ `tool_result` joined on `callId` | gives the graph its left-most cause ("the agent ran WebFetch on X") |
| `minted` | origin → symbol birth | `symbolize` (`output.symbols`) | G1: fs-sync/split births need phase 0 |
| `entered_context` | symbol present in a privileged-model request | `tllm_call` (`input.symbols`, fallback token-regex over `input.symbolized`) | collapse consecutive turns into one node with a `×N` count |
| `echoed` | model wrote the token into tool args — the attack-relevant step | `tool_use` (regex today; structured after G3) **or the gate event's own refs** | this is the edge detection products cannot see. On a BLOCKED exec the recorded `tool_use` carries the gate's *rewritten* command (token stripped on the wire), so the `exec_action`'s structured refs are the only surviving echo evidence — the builder joins from them when no `tool_use` echo exists (live shape, claude-e2e exec-symbol-command-blocked) |
| `derived_inspect` | parent symbol → U-LLM result symbol | `ullm_call` (`output.symbols[].derivedFrom`) | Quarantine-lane node; carries `content_kind` chip when the triage event exists |
| `derived_split` | parent symbol → split child | `symbolize` w/ `derivedFrom` + `lineRange` (after G1/G2) | |
| `gated` | symbol-bearing action hit an OS chokepoint | `fs_action` / `net_action` / `exec_action` joined on `callId` | boundary = filesystem/network/shell |
| `egress` | desymbolization requested/decided at an egress | `egress_request` + `egress_decision` + `desymbolize` | verdict from `policy.usage` / decision outcome; `egress_approvals` adds count/firstSeen for the tooltip |
| `revealed_reply` | symbol desymbolized into the human-facing reply | `desymbolize` (emitter `reply-filter`; token-mined) | terminal sink "👤 human", HumanView lane (any other emitter's `desymbolize`: the sink `snk:fill`, read as a release, 2026-10-06) |
| `declassified` | in-context read granted/refused (confidentiality axis) | the `declassifySymbol` emission | terminal sink "model context" |

### 3.3 Two granularities, one model

- **Per-symbol lineage** (UC1, UC3, UC4): the full small DAG for one root
  symbol — typically 5–20 nodes. Follows *both* derivation edge types (§2.2)
  transitively, so an inspect-derived symbol's graph includes its parent.
- **Session flow map** (UC2, UC5): one **strip per flow** — a horizontal
  "subway map" of stations `origin → 🔒 sealed → 🤖 AI read the seal ×N →
  terminal verdict`, in the plain-language register (dashboard.md §4.16
  vocabulary rule: sealed / blocked / waiting, never symbolized / egress), the
  rail into a blocked verdict visibly cut — a linear summary that scales to
  hundreds of symbols where a full graph would not, readable by a non-expert.
  Clicking a strip opens the per-symbol graph (the expert evidence surface,
  which keeps its precise vocabulary).

## 4. Use-cases

- **UC1 — the blocked exfiltration, at a glance.** The injection-contrast
  demo's final frame (deferred, `mandu-demo.md` §9): *poisoned page →
  `$MDU:WebFetch[a1b2].text` → model echoed it into `curl -d` → ⛔ blocked at
  the wall*. Published prompt-injection exfiltrations (EchoLeak, CamoLeak,
  ForcedLeak) have exactly this shape and were reconstructed after the fact;
  the lineage view renders the chain live, with the block.
- **UC2 — shadow-mode counting.** The flows counter states, per session, "N
  flows where untrusted data reached the model and touched an egress."
  Verdict wording keys off enforcement mode: enforced → "blocked/approved";
  observe-only → "would have required approval". No new machinery — the same
  graph, different copy.
- **UC3 — audit / incident forensics.** For an assessor: pick any symbol →
  the full evidence chain, every node/edge click-through to the underlying
  event in the trace; "Copy evidence JSON" exports the `SymbolLineage` (event
  ids included) as the pre-SIEM evidence unit.
- **UC4 — DLP / confidentiality lineage.** The same graph for the *secrets*
  direction: a `nomodel_`/`anymodel_` symbol's egress attempts, destinations,
  and human verdicts (`egress_approvals` provides per-(symbol, destination)
  count/firstSeen/lastSeen for the tooltip). Confidentiality badges (G4) make
  the two label axes visible in one place.
- **UC5 — operator utility triage.** The `content_kind` chip on
  inspect-derived nodes shows *why* a workflow failed: "this symbol triaged
  `auth_wall` — the fetch hit a login page" — the symbol-quality blindness
  class, made legible at a glance.
- **UC6 — stored-IPI persistence chain** (deferred, G7). Persistence across
  sessions: session A ingress → disk → session B re-ingress, joined via
  `file_taint` + symbol `origin` path. Un-defer when cross-session forensics
  is needed or a demo gains a stored-IPI act.

## 5. UI design

### 5.1 The organizing idea: lineage on the two-view geometry

The trace already renders two lanes separated by the hatched **trust wall**
(AgentView left, HumanView right, Quarantine as accented cards). The lineage
graph reuses that exact geometry — it is the same mental model at a
different zoom:

- **x-axis = trust.** External origins outside the right edge; HumanView
  (originals) right lane; AgentView (symbols, model context, tool-call
  echoes) left lane; Quarantine/U-LLM nodes carry the existing pink accent.
- **y-axis = time**, flowing down like the trace: event `seq`, in the
  order it happened (dashboard.md §4.17 *In the order it happened*,
  2026-10-13). An edge's target is never drawn above its source, and a
  model call that carried the item is drawn above every command the AI
  wrote with it in that call's answer or later: the anthropic-proxy records
  a call when its answer ends, so by `seq` alone a gate's row sat above
  its command's and the call's below both. The lineage's nodes keep their
  `seq` and evidence; only the drawing order changes.
- **Wall crossings are the translation events**: a `minted` edge crosses
  right→left (raw became a symbol); an allowed `egress` crosses left→right
  (symbol became raw at the boundary); a **denied egress edge terminates AT
  the wall with ⛔** — prevention rendered literally: the wall the trace
  already draws becomes the place a block happens on screen.

### 5.2 Rendering

Hand-rolled **SVG** (D2): with x fixed by lane and y fixed by the story's
order (§5.1), the layout is a trivial layered DAG — no force simulation, no
dependency, no build step, consistent with the plain-ES-module stack. The server computes
the `SessionLineage` into `SessionViewModel` (new `lineage` field beside
`symbols`/`egress`); the client renders it like every other panel.

**The graph is not the first thing a reader sees** (since 2026-09-05). In
use, the SVG confused everyone who was not already fluent in the two-view
geometry (truncated node labels, same-lane bows, no visible time axis), and
the session map's variable-length "subway" strips hid their verdict behind a
horizontal scroll whenever the origin was a long command. Both surfaces were
rebuilt on the SAME model (dashboard.md §4.15 v2 / §4.17 v2): the session
map is a four-column **tracker** (origin · symbol · model context · egress
verdict, one aligned row per flow, the outcome always on screen), and the
per-flow surface leads with a **numbered story** — the graph's nodes in `seq`
order, one plain sentence each, every step keeping its `{eventId, seq}` jump
(§1's evidence rule is unchanged: a sentence with no event does not exist).
The SVG graph stays, folded inside the card's "Details for experts" block,
as the operator's evidence picture (and UC1's frame) — the geometry above
is still how it is drawn.

### 5.3 Entry points

1. **Any symbol token, anywhere** — as landed (2026-07-17, dashboard.md
   §4.17) the token click opens the unified SYMBOL CARD — provenance + value
   + this lineage graph on one surface — rather than the bare value popup
   gaining a "lineage →" action.
2. **Symbol table** (formerly "symbol inspector", dashboard.md §4.5) — the
   Flow column (today display-only prose) becomes the click target for the
   per-symbol graph. Since 2026-10-09 the table also lists the lineage's
   "birth unrecorded" symbols that no event carries as a typed symbol
   (secret placeholders masked at launch, which only a send or the AI's
   writing names; never a `modelAuthored` token), so the Secrets tab counts
   what *Where each went* and the session's row count (dashboard.md §4.33
   *A masked value with no masking step in the session*).
3. **The inline lineage panel** — as landed (2026-07-17, dashboard.md
   §4.15): the session flow map (strips, §3.3) is a foldable `#lineage-fold`
   panel below the trace whose always-visible summary line is the §3.3 flows
   summary. (It began as a third topbar dv-mode; that segment is retired.)
4. **Egress queue / approvals** — each row gains "how did this get here →",
   opening the symbol's lineage anchored at that egress edge.

### 5.4 Interactions

- **Click node/edge → the proving event**: reuse `selectEvent` scroll+flash
  into the trace. The evidence rule (§1) guarantees the target exists.
- **Hover → provenance card**: tool · field · origin, confidentiality badge
  (reuse `confBadge` 🔒/🤖/🔓), integrity accent, `content_kind` chip when
  known, emitter attribution (reuse `dvTechChip`).
- **Verdict styling**: ✅ allowed · ⏸ pending approval · ⛔ denied/blocked on
  egress edges; the ⛔ edge stops at the wall (§5.1).
- **Flows summary strip** (top of the lineage mode): "7 untrusted items · all
  masked before reaching the AI · 2 left with permission · 1 left with your
  approval · 1 blocked from leaving". This is the UC2 sentence, always visible.
  It was reworded into the plain-language register on 2026-07-16
  (`flowsSummaryLine`). Since 2026-10-05 it tallies `outcomes`, by item, in
  the tracker chips' words, where it used to say "N attempts to send data out"
  over each item's worst outcome (dashboard.md §4.15). The enforced/shadow
  flip is untouched: `outcomeCopy(…, false)` reads "would have been
  blocked". An item the AI read as it was before it was masked
  (`withReadFirst`: a result re-masked once its file was labelled,
  `stats.readFirst`) is never "masked before reaching the AI": "2 masked
  before reaching the AI · 1 read by the AI before it was masked" (dashboard.md
  §4.15, "Read before it was masked"). A `revealed_reply` edge into
  `snk:human` (the reply filter showing the value on the person's screen) is
  not a release: it
  counts as "N shown to you in replies", last, and a flow whose only
  release it is ends in the `shown` terminal (dashboard.md §4.15, "Shown to
  you is not a send", 2026-10-06).

### 5.5 Scale rules

Full graphs render per-symbol only. The session map is linear strips with a
cap + "show more". Consecutive `entered_context` turns collapse to one node
(`context ×N`). No silent truncation: a capped list says what was dropped.

## 6. Implementation plan

**Phase 0 — evidence hygiene** (arbiter, fs-sync, inspect-mcp; small):
close G1 (emit `symbolize` birth events at the fs-sync mint and split call
sites — keep the caller-emits pattern, D1), G2 (plumb `derivedFrom` through
`SymbolizeArgs` → `symbols.derived_from`; inspect-mcp passes its parent),
optionally G3 (structured `symbols[]` on `tool_use`). Each with unit + e2e
coverage per [`CONTRIBUTING.md`](../../../CONTRIBUTING.md).

**Phase 1 — the graph builder** (dashboard view-model; pure TS): 
`view-model/lineage.ts` with `toSessionLineage`; wire into
`toSessionViewModel`. Tests: §9.2.

**Phase 2 — the UI**: SVG lineage renderer + the four entry points + event
jumps + badges (G4 closes here) + the flows summary strip.

**Phase 3 — evidence export + shadow wording**: "Copy evidence JSON"
(`SymbolLineage` serialization — the §2.1 pre-SIEM unit) and
enforcement-mode-aware verdict copy (UC2).

**Deferred, with un-defer triggers**: UC6 cross-session stored-IPI join
(trigger: a cross-session forensics need, or a stored-IPI demo act); death
events G5 (trigger: a flow that needs obsoletion rendered); `content_kind`
persistence stays owned by `symbol-quality.md` §4.7; fleet/SIEM aggregation
(trigger: a deployment that feeds a SOC; see `siem-integration.md`).

**Demo integration** (after phase 2): the deferred injection-contrast demo
([`mandu-demo.md`](../distribution/mandu-demo.md) §9) would end on UC1; the built `mandu demo`
(the `secrets` mode) does not open the trace.

## 7. Relation to fs-provenance (process/file taint)

Two lineage systems, deliberately distinct layers: **symbol lineage** (this
doc) tracks the `$MDU` dataflow across the trust boundary — model-facing,
per-session, evidence-grade for the IPI story. **Process/file taint**
(`fs-provenance*.md`, `provenance-store.ts`) tracks byte/process ancestry on
the host — symbol-blind, cross-process. They meet exactly once: the UC6
stored-IPI chain joins a symbol's `origin` path to `file_taint` rows to
bridge sessions. Until then, neither renders the other's edges.

## 8. Decisions

All four were taken as recommended, except D3, which the UI later revised.

- **D1 — who emits non-proxy birth events (G1).** *Keep the caller-emits
  pattern* (fs-sync and the split path gain `emit` calls) —
  callers have the correlation context (turn, callId, DualRepr spans) the
  arbiter lacks at op-handling time. The alternative (arbiter-side emission
  inside the `symbolize` op) is one chokepoint but produces thin,
  turn-less events and double-emits for proxy callers.
- **D2 — graph rendering.** *Hand-rolled SVG* — the lane/seq layout makes
  the DAG trivial; a graph library adds a dependency and a build step the
  dashboard deliberately does not have.
- **D3 — where lineage lives in the UI.** First built as a third dv-mode for
  the session flow map plus an overlay for per-symbol graphs; now the
  foldable `#lineage-fold` panel below the trace and the symbol card (§5.3),
  which keep the trace as the home view without a mode switch.
- **D4 — G3 timing.** *Do it in phase 0* — it is a few lines at
  `makeToolUse`, and it removes the reader-side regex twin from the new
  builder; the regex fallback stays for old sessions.

## 9. Testing plan

The suites this feature slots into, cheapest first: per-package unit tests;
the dashboard's JSDOM `app.js` harness (`dashboard/test/unit/ui/app-js-harness.ts`
— esbuild-bundled `app.js` booted in jsdom with mocked `fetch`/`EventSource`);
dashboard e2e (real arbiter socket → `/api/events`/SSE); **replay-e2e**
(`tests/stack/proxy-replay.test.ts` — canned transcripts through the
real components, deterministic, CI); **claude-e2e live**
(`claude-e2e.test.ts` — a real `claude`, real budget).
The shared check library `tests/lib/assertions.ts` (lineage checks in
`assertions-lineage.ts`) feeds both e2e
classes, and every check lands in the per-session `assertion` event
(categories `security`/`utility`/`fidelity`) that the dashboard renders.

### 9.1 The strategic move: the lineage builder becomes an oracle

`toSessionLineage` is a pure function over the same `ManduEvent[]` the
assertion checks already consume. So the deepest coverage is not "tests for
the lineage feature" but **lineage-shaped checks added to `assertions.ts`**
— they then run in *both* replay-e2e (deterministic, blocking) and claude-e2e
(live) by riding **existing** scenarios, honoring the suite's retirement
doctrine (*"a live scenario earns its slot only by proving something no
cheaper suite proves"* — lineage proves nothing a new scenario is needed
for; it re-reads sessions the suite already pays for). New checks, category
`fidelity` (the block itself stays asserted by the existing `security`
checks; lineage asserts the *representation* of it):

| Existing scenario | Expected lineage shape asserted |
|---|---|
| `net-exfil-blocked` (E28) | exactly one complete flow, terminal `egress` edge verdict `denied`, boundary network — the UC1 shape, deterministic because the command is pinned |
| `exec-symbol-command-blocked` (E19) | flow terminates `blocked` at the shell boundary |
| `inspect-extract` / `inspect-compare` / `inspect-verdict-retry` (E18/E21/E25) | `derived_inspect` edge parent→child; `content_kind` present on the derived node (from the triage `ullm_call`) |
| `interactive-reply-filter-live` (E24) | terminal `revealed_reply` edge into the 👤 sink |
| `stored-ipi` / `bash-ipi` / `chain-*` | `minted` + `entered_context` edges present; **no** egress edge |
| `CONF-*` (conf-smoke fold, retired 2026-10-18; the frozen `full` cut runs them) | UC4: secret symbol's lineage carries the confidentiality level and the egress verdicts the conf oracle already grades |
| fsSync-fold scenarios, post-phase-0 | *the live proof G1 closed*: every symbol referenced anywhere in the session has a `minted` birth edge — fails before phase 0, passes after |

**Model-authored tokens are not symbols (G1 over-breadth fix, 2026-07-16).**
The builder mines `$MDU:*`-shaped strings from every text surface, including
the model's own reply prose — and the model can *compose* token-shaped
strings that were never minted (seen live: `stored-ipi@opus` appended an
invented `.content` suffix to a real token in its final reply, and the hard
G1 check failed a run whose event pipeline was flawless). The builder now
classifies a token as **`modelAuthored`** when it is unminted and was never
*system-witnessed*: no structured `symbols` ref anywhere, no sighting on a
system-written text surface (`symbolize`/`classify`/`tool_result`/
`ullm_call`/`fs_action`/`path_rewrite`), no net-proxy loose field, and no
*first* entry via `tllm_call` input (a later input sighting is just
conversation history echoing the model's own prose — it does not launder the
token). Secret twins (`$MDU:nomodel_*`/`$MDU:anymodel_*`) are system-witnessed by
construction: their names reach the model via the system prompt, a surface
the DualRepr mining cannot see, so their first visible sighting is often the
model echoing them — they stay in the documented soft "birth unrecorded"
class. `lineage-birth-complete` excludes `modelAuthored` nodes (its reason
says how many were ignored); a genuinely lost birth — the regression G1
exists to catch — still fails, because a real symbol always enters through a
system-witnessed surface first. The UI renders these nodes "model-authored
token" instead of the misleading "birth unrecorded".

A twin's name is the model's own after all when it extends, by a field path,
a symbol minted in this session (2026-10-09, `composedByModel`). Seen live
at Secrets: `cat .env` masked as `$MDU:nomodel_Bash[93d1]`, then the reply
"I will send `$MDU:nomodel_Bash[93d1].value` to the API". The system-prompt
reason does not apply: the model learned the symbol from a recorded result,
and a real field of it would have reached the model in that result, a
system-witnessed surface. A field on a twin the session never minted (a
`.env` registered at launch, with no event) keeps the twin exemption. So
`lineage-birth-complete` also ignores an invented field on a minted twin,
which it used to report as a symbol with no recorded birth. The stats count
neither (§3.1).

Fold-group rule (the *"chokepoint wired to a posture nobody runs"* defense):
the lineage checks run in the **default-posture** groups (int-smoke + full),
with the conf-lineage checks in conf-smoke until it retired on 2026-10-18
(the `full` cut still runs the `CONF-*` scenarios). Live flake policy: assert only
what each scenario's existing oracle already makes deterministic (E28 pins
the command, so its flow shape is plumbing, not a model bet); where the model
may legitimately detour (direct echo vs `inspect_symbol`), the check is
conditional/WARN, following the `expectTypeahead` precedent.

### 9.2 Per-phase tests

**Phase 0** (producer packages — unit + e2e per
[`CONTRIBUTING.md`](../../../CONTRIBUTING.md)):
- *fs-sync unit*: each mint call site emits a `symbolize` event (mock arbiter
  captures `emit`); the split path emits `derivedFrom` + `lineRange`.
- *inspect-mcp unit*: `symbolize` is called with `derivedFrom` = the parent
  symbol; *arbiter unit*: the op persists `derived_from`, protocol
  round-trips the new field.
- *anthropic-proxy unit*: `makeToolUse` attaches structured `symbols[]`
  (extend the existing tool-coverage oracle).
- *integration e2e (deterministic)*: a full-stack assertion that an
  fs-sync-minted symbol appears as a `symbolize` event in the session NDJSON.
- Cross-package caution: `SymbolizeRequest` has **mirrors** (anthropic-proxy
  `events.ts`, inspect-mcp `arbiter-client.ts`, fs-sync `arbiter-client.ts`,
  dashboard `event-model.ts`) — typecheck every dependent package, not just
  the one edited (integration imports some launcher/service types directly).

**Phase 1** (dashboard unit — `test/unit/view-model/lineage.test.ts`, the
`dual-lanes.test.ts` pattern):
- one minimal synthetic fixture per **edge kind** (§3.2 catalog = the test
  matrix), plus: a reuse-heavy session (context collapsing to `×N`), a
  derivation chain crossing both edge types, and a **legacy session with no
  birth events** — the builder must degrade to a "birth unrecorded" node
  marker, never an inferred edge (back-compat for pre-phase-0 sessions).
- the **evidence-rule test**: every emitted edge's `eventId` resolves to an
  input event; no orphan nodes.
- a **consistency oracle** against the existing view-model: every
  `toSymbolInspector` row appears as a lineage flow and the per-symbol event
  counts agree — the two reconstructions can never drift apart silently.
- a **golden fixture**: run the builder over
  `tests/fixtures/incident-events-1783711204.ndjson` (a real
  captured incident session) and snapshot the `SymbolLineage` JSON — this
  doubles as the phase-3 export-stability test.
- *(planned, not built)* a lineage lint in the **render-lint sweep**
  (`render-lint-sweep.test.ts` pattern), so every session the dashboard loads
  gets the evidence rule checked continuously and surfaces a "jump →" like
  render lint. `view-model/render-lint.ts` has no lineage rule today.

**Phase 2** (UI): a new `app-js-lineage.test.ts` on the JSDOM harness — boot
with a mocked `/api/events` whose `viewModel.lineage` is a fixture graph;
assert the SVG renders nodes per lane, the ⛔ edge terminates at the wall
element, badges appear, the lineage panel opens (first written for the
third dv-mode, since retired, §5.3), and node-click invokes the
`selectEvent` jump. Dashboard e2e asserts `viewModel.lineage` ships over
`/api/events` and updates over SSE.

**Phase 3**: the export JSON is the same snapshot as phase 1's golden
fixture (serialization stability = export stability); shadow wording is a
pure function of enforcement mode — unit-test both copies.

### 9.3 What is deliberately NOT tested live

No new live scenario is added for lineage itself — every live property rides
an existing session (§9.1), keeping live budget flat. A dedicated live
scenario becomes justified only with UC6 (cross-session stored-IPI), which
no existing scenario shapes.
