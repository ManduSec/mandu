/**
 * view-model/policy-panel — the pure view-model for the Policy panel
 * (docs/design/ui/policy-surface.md §9.4, §9.8 — the 2026-07-24 consistency
 * redesign: one row grammar, gate-grouped rules, per-row detail).
 *
 * Mandu-new (no reference origin). Same split as view-model/secrets.ts: this
 * module is the render LOGIC (server projects), `public/js/egress.js` is the
 * thin DOM shell (browser paints) — which keeps the §4/§8 claims unit-testable
 * rather than assertions about a DOM.
 *
 * ── THE INVARIANTS THIS MODULE ENCODES ──────────────────────────────────────
 *
 * 1. UNKNOWN IS NOT OFF, OFF IS NOT EMPTY. An arbiter predating a snapshot
 *    field reports NO value — rendered "unknown", never "off"/"normal" (the
 *    posture-guard trap). This now covers the SIEM lockdown posture and the
 *    law source too: absent ⇒ unknown/omitted, never invented.
 *
 * 2. EVERY QUEUE ROW IS VISIBLE. One merged list carries pending AND
 *    approved/denied rows — the standing law that flipped the
 *    fs-denied-cwd-note gate for a day (egr-2) renders in the same table as
 *    the questions still waiting; the shell's status checkboxes only FILTER,
 *    never re-shape.
 *
 * 3. NEVER A VALUE. Verdict rows carry symbol NAMES, destinations, paths,
 *    signatures — never resolved bytes. This module copies fields explicitly
 *    (no spread of its input), same defense as secrets.ts.
 *
 * 4. ONE ROW GRAMMAR (§8). Verdict and rule rows share the vocabulary that
 *    ALIGNS (a chokepoint `where` label, an `outcome` chip kind, a structured
 *    `detail` payload for the ⓘ drawer) while keeping the columns that
 *    genuinely differ (a rule is a compiled pattern, a verdict a subject ×
 *    target fact — forcing them into one table would be false consistency).
 *
 * 5. RULES GROUP BY GATE, NOT BOUNDARY (§8). Within a gate, catalog order IS
 *    evaluation order; the old per-boundary grouping interleaved unrelated
 *    gates' chains into one list that READ like a precedence order and wasn't.
 *    Gate citations (definedIn / doc / evaluation) come from the arbiter's
 *    gate catalog — when an older arbiter omits it, the citation lines are
 *    OMITTED, never reconstructed dashboard-side (they would drift).
 */

import { hasLocalModel, NO_OWN_MODEL_WARNING, toModelEndpointRows } from "./model-endpoints.js";
import { ADMITS_NOTHING, READS_PLACEHOLDER, codeRunningReadersWarning, judgedAdmitsNothing, judgedCopyOf, judgedReadsTwin, readerRunsCode, type ArbiterReaderJudgment } from "./reader-runs-code.js";
import { answerWords, holderAnswerWords, noLongerAppliesWords, promptAnswerWords, sessionAnswerWords, levelWords, opensWords, pathReach, perValueParts, perValueWords, programWords, sendRuleReach, sendRuleReachParts, sendWords, sourceReach, builtinName, TERMS } from "./rule-words.js";
import type {
  PolicySnapshot,
  ToolRule,
  UsageGateRow,
  UsageRuleRow,
  VerdictEntry,
} from "../policy-model.js";
import type { DetailItem, DetailSection } from "./detail.js";
import { describeAsk, holderSendOf } from "./ask-words.js";
import { pathOpeners } from "./rules-by-who.js";
import { connectWords } from "./policy-proposals.js";
import {
  lawSourceVM, postureChips, ruleDetail, ruleOutcome, verdictDetail, verdictFamily, verdictOutcome, whereLabel,
} from "./policy-panel-detail.js";
export { whereLabel, verdictFamily } from "./policy-panel-detail.js";

export type {
  PostureState,
  LockdownState,
  VerdictFamily,
  OutcomeKind,
  QueueRowVM,
  RuleRowVM,
  GateGroupVM,
  PostureChipVM,
  PolicyPanelVM,
  YourRuleKind,
  YourRuleRowVM,
  RuleRowActions,
  RelaxationRowVM,
  PolicyFileVM,
  InboundToolRowVM,
  InboundVM,
} from "./policy-panel-types.js";
import type {
  QueueRowVM, GateGroupVM, PostureChipVM, PolicyPanelVM, YourRuleKind, YourRuleRowVM, RuleRowActions,
  InboundToolRowVM, InboundVM,
} from "./policy-panel-types.js";

/** The ⓘ-drawer vocabulary (DetailItem/DetailSection) now lives in
 * view-model/detail.ts, shared with the trace's per-event drawers
 * (dual-lanes.ts) — re-exported here for the panel's existing importers. */
export type { DetailItem, DetailSection } from "./detail.js";

/** Which buttons a row gets. Mirrors what rule-actions.ts can plan. */
export function ruleRowActions(row: { id: string; kind: YourRuleKind }): RuleRowActions {
  if (row.id.startsWith("app:") || row.kind === "untrusted-origin") return { remove: false, flip: null };
  return {
    remove: true,
    flip: row.kind === "release-allow" ? "block" : row.kind === "release-block" ? "allow" : null,
  };
}

// ── §8.8 inbound-trust builders ───────────────────────────────────────────────

/** One field-trust line, in the per-call ⚖ modal's vocabulary (app.js
 * outputFieldRow): TRUSTED (+ category key), conditional = UNTRUSTED unless
 * its origin category is trusted, else UNTRUSTED. */
function inboundFieldLine(f: { field: string; trust: string; category: string | null; detail: string }): string {
  const verdict =
    f.trust === "TRUSTED"
      ? `TRUSTED${f.category ? ` (${f.category} key)` : ""}`
      : f.trust === "conditional"
        ? `UNTRUSTED unless ${f.category ?? "its origin"} is trusted`
        : "UNTRUSTED";
  return `${f.field}: ${verdict}${f.detail ? ` — ${f.detail}` : ""}`;
}

function inboundToolRow(rule: ToolRule, specId: string): InboundToolRowVM {
  const fields = rule.inbound?.fields ?? [];
  const trusted = fields.filter((f) => f.trust === "TRUSTED").length;
  const what: DetailItem[] = [
    {
      text: `The data-trust (inbound) rule for ${rule.tool} — how this tool's results are classified before the model sees them. UNTRUSTED spans are symbolized ($MDU:*); the model never reads their raw bytes.`,
    },
  ];
  const fieldItems: DetailItem[] = rule.inbound
    ? fields.length
      ? fields.map((f) => ({ text: inboundFieldLine(f) }))
      : [{ text: "no per-field schema — the tool-level summary above is the whole rule" }]
    : [{ text: "no inbound spec — results fail closed to UNTRUSTED (everything is symbolized)" }];
  const specified: DetailItem[] = [
    { text: `spec: ${specId} (arbiter/policy — the same objects classify() enforces; the snapshot cannot diverge from enforcement)` },
  ];
  return {
    tool: rule.tool,
    summary: rule.inbound
      ? rule.inbound.summary
      : "no inbound spec — results fail closed to UNTRUSTED",
    trustedFields: trusted,
    untrustedFields: fields.length - trusted,
    detail: [
      { label: "What this is", items: what },
      { label: "Field trust", items: fieldItems },
      { label: "Where it's specified", items: specified },
    ],
  };
}

function inboundVM(snapshot: PolicySnapshot): InboundVM {
  return {
    specId: snapshot.specId,
    fallbackLine: `tools not described by the spec: whole result ${snapshot.fallbackTrust} (fail-closed)${snapshot.mcpPrefix ? `; ${snapshot.mcpPrefix}* MCP tools use the ${snapshot.mcpPrefix}* entry when one exists` : ""}`,
    originLines: (snapshot.origins ?? []).map(
      (o) => `${o.id}: ${o.mode} of ${o.listSize} — anything else defaults ${o.defaultTrust}`,
    ),
    tools: Object.values(snapshot.tools ?? {}).map((t) => inboundToolRow(t, snapshot.specId)),
  };
}

// ── Row + group builders ──────────────────────────────────────────────────────

function toQueueRow(v: VerdictEntry, readFirst?: string, home = ""): QueueRowVM | null {
  if (v.status !== "pending" && v.status !== "approved" && v.status !== "denied") return null;
  // A masked value asked to be shown to the model as it is (the arbiter's
  // `declassifySymbol`, keyed to the act `model_context:in-context-read`,
  // not to a host) is no send: until 2026-10-11 its card read "wants to
  // send a secret to model_context:in-context-read" (dashboard.md §4.34
  // "After you answer").
  const where = v.symbol.startsWith("$") && v.destination.startsWith("model_context:")
    ? "model context"
    : whereLabel(verdictFamily(v.symbol));
  // The question in the product's words (dashboard.md §4.34): the same
  // describeAsk the product home uses, so the developer view's Approvals card
  // and the product's say the same thing. A waiting row carries the card's
  // three cells; an answered one only its sentence (the "Answered earlier"
  // table), which keeps the bytes an answer adds small (§4.30).
  // Plan 15 §12 (2026-10-04): a held message under a locked administrator's
  // `ask` row is answered for this message only (the arbiter says so).
  const onceOnly = v.onceOnly === true && v.status === "pending" && verdictFamily(v.symbol) === "prompt";
  // Which secret a send carries comes from where it came from: a file or an
  // environment variable only (dashboard.md §4.34 "A send names its secret").
  const from = v.source?.origin;
  const origin = typeof from === "string" && (from.startsWith("/") || from.startsWith("env:")) ? from : undefined;
  // The AI read its item as it was before it was masked (§4.34 "Read before
  // it was marked"): a waiting row's words only; an answer changes nothing.
  const early = v.status === "pending" && readFirst ? readFirst : undefined;
  // A HIGH session's ask (confidentiality.md §4, 2026-10-11): what that
  // session read, copied field by field (never a value), for the card.
  const session = /^session-(?:net|exec):./.test(v.symbol);
  const reads = session && Array.isArray(v.sessionReads)
    ? v.sessionReads.filter((r) => r && typeof r.symbol === "string").map((r) => ({ symbol: r.symbol, origin: typeof r.origin === "string" ? r.origin : null }))
    : undefined;
  const readsMore = session && typeof v.sessionReadsMore === "number" && v.sessionReadsMore > 0 ? v.sessionReadsMore : undefined;
  // A command's card: held by the guard (and where it may reach) or not.
  // Absent ⇒ not held (the card never overstates the confinement).
  const confined = session && v.symbol.startsWith("session-exec:") ? v.sessionConfined === true : undefined;
  // A network ask filed by a HELD command's refused connection (§4,
  // 2026-10-12): the card speaks of the command's request and its next try.
  const heldNet = session && v.symbol.startsWith("session-net:") && v.sessionHeld === true;
  const bindings = (confined === true || heldNet) && Array.isArray(v.sessionBindings) ? v.sessionBindings.filter((b): b is string => typeof b === "string") : undefined;
  const sessionFacts = {
    ...(reads ? { sessionReads: reads } : {}), ...(readsMore ? { sessionReadsMore: readsMore } : {}),
    ...(confined !== undefined ? { sessionConfined: confined } : {}), ...(bindings ? { sessionBindings: bindings } : {}),
    ...(heldNet ? { sessionHeld: true } : {}),
  };
  // A holder's send question (confidentiality plan 13 §5.4): the files the
  // arbiter attached to the pending row, copied field by field.
  const holder = holderSendOf(v.symbol);
  const holderSources = holder !== null && v.status === "pending" && Array.isArray(v.holderSources)
    ? v.holderSources.filter((s) => s && typeof s.path === "string").map((s) => ({
      path: s.path, ...(typeof s.via === "string" ? { via: s.via } : {}), ...(s.rule === true ? { rule: true as const } : {}),
      level: String(s.level), bindings: Array.isArray(s.bindings) ? s.bindings.filter((b): b is string => typeof b === "string") : [],
      blocks: s.blocks === true, always: s.always === true, ...(typeof s.noAlways === "string" ? { noAlways: s.noAlways } : {}),
    }))
    : undefined;
  // A file's card (egress-hold.md "One card per file"): how many of its
  // values the answer covers.
  const fileValues = typeof v.fileValues === "number" && Number.isInteger(v.fileValues) && v.fileValues > 1 ? v.fileValues : undefined;
  const said = describeAsk({ where, subject: v.symbol, target: v.destination, reason: v.reason, ...(onceOnly ? { onceOnly } : {}), ...(origin ? { origin } : {}), ...(early ? { readFirst: early } : {}), ...sessionFacts, ...(holderSources ? { holderSources } : {}), ...(fileValues ? { fileValues } : {}) }, "The agent");
  return {
    id: v.id,
    family: verdictFamily(v.symbol),
    where,
    subject: v.symbol,
    target: v.destination,
    status: v.status,
    outcome: verdictOutcome(v.status),
    reason: v.reason,
    count: v.count,
    firstSeen: v.firstSeen,
    lastSeen: v.lastSeen,
    resolvedAt: v.status === "pending" ? null : (v.resolvedAt ?? null),
    sessions: [...(v.sessions ?? [])],
    scope: v.scope === "once" ? "once" : "always",
    consumedAt: v.consumedAt ?? null,
    actions:
      // Plan 15 §7: a held prompt is answered send / mask / cancel, for the
      // message or the session (the prompt hold route); the generic verbs
      // still map (Approve = send, Deny = the default).
      verdictFamily(v.symbol) === "prompt" && v.status === "pending"
        ? [
            { approve: true, scope: "once" as const, prompt: "send" as const, promptScope: "once" as const, label: "Send as written" },
            ...(onceOnly ? [] : [{ approve: true, prompt: "send" as const, promptScope: "session" as const, label: "Send as written for this session" }]),
            { approve: false, prompt: "mask" as const, promptScope: "once" as const, label: "Send masked" },
            { approve: false, prompt: "cancel" as const, promptScope: "once" as const, label: "Cancel the message" },
          ]
        : v.status === "pending"
        // Plan 13 §8 decision (c): a row about one run of a program that
        // runs code no pin names takes no standing answer (the arbiter keeps
        // an Always as once), so none is offered.
        // The product's three answers in its order (dashboard.md §4.34):
        // Allow once (approve-once), Always allow (approve: a standing
        // answer), Block (deny: a standing answer).
        ? holder !== null
          // A holder's send (plan 13 §5.4): the standing answer on its row
          // covers its session ("Allow this session"); a row with no session
          // takes none (the arbiter keeps it as once). Its *Always* is one
          // per file, a rule change (`always-source`), never a verdict.
          ? [
              { approve: true, scope: "once" as const, label: "Allow once" },
              ...(holder.session !== null ? [{ approve: true, label: "Allow this session" }] : []),
              { approve: false, label: "Block" },
            ]
          : [
            { approve: true, scope: "once" as const, label: "Allow once" },
            // A HIGH session's ask (confidentiality.md §4) covers one request
            // or one command of one session: the arbiter keeps an Always as
            // once, so none is offered either.
            ...(/^(?:open|write):.*#run:[^#]*$/.test(v.symbol) || session ? [] : [{ approve: true, label: "Always allow" }]),
            { approve: false, label: "Block" },
          ]
        // A HIGH session's answered row takes no one-click reversal: its
        // labels say "Always", and the arbiter keeps an allow on it as once.
        // Removing the answer (Rules) makes the next request ask again.
        : session
          ? []
        // "Send without it" answered (§4.34): an answer about one request, so
        // no reversal; the next such request asks again once it is used.
        : v.strip === true
          ? []
        // A held message's answer (dashboard.md §4.34 "A held message's
        // answer"): an answer about one message has no reversal, since the
        // message went, and the generic Allow on it would file a standing
        // verdict for the whole session (holds.ts afterResolve), which "Allow
        // instead" never said. A session's answer flips as itself.
        // An answer that applies to nothing any more (§4.34 "Answers that
        // no longer apply"): changing it would change nothing, so no button.
        : v.noLongerApplies !== undefined
          ? []
        : verdictFamily(v.symbol) === "prompt"
          ? v.destination.includes("#turn:")
            ? []
            : v.status === "approved"
              ? [{ approve: false, label: "Send masked instead" }]
              : [{ approve: true, label: "Send as written instead" }]
        : v.status === "approved"
          ? [{ approve: false, label: "Block instead" }]
          : [{ approve: true, label: "Allow instead" }],
    ruleRefId: v.status === "pending" ? null : `verdict:${v.id}`,
    ...(v.strip === true && v.status === "denied" ? { strip: true as const } : {}),
    // "Send without it" (§4.34): a waiting card the arbiter marks (a
    // secret's placeholder in a request to a host), never a content-agnostic
    // one (a HIGH session's, a program's send), whose request may hold the
    // value itself. Only the product's card offers it (home.ts
    // `sendWithoutActions`); these `actions` stay the three answers.
    ...(v.stripOffered === true && v.status === "pending" && !session && holder === null && verdictFamily(v.symbol) !== "prompt" ? { stripOffered: true as const } : {}),
    originHost: v.originHost ?? null,
    ...(origin ? { origin } : {}),
    ...(early ? { readFirst: early } : {}),
    ...sessionFacts,
    ...(holderSources ? { holderSources } : {}),
    ...(fileValues ? { fileValues } : {}),
    // The rule-shaped answer (policy-surface.md §2.5) is offered only
    // when the ORIGIN is known: "anything from <origin> → <destination>". With
    // no origin the only mintable rule is "from anywhere" — too broad to be a
    // one-click verb (the Add-rule form still allows it, deliberately typed).
    mintable:
      v.status === "pending" && verdictFamily(v.symbol) === "network" && v.destination && v.originHost
        ? { from: v.originHost, to: v.destination }
        : null,
    plain: verdictFamily(v.symbol) === "prompt" ? promptAnswerWords(v.symbol, v.destination, v.status) : session ? sessionAnswerWords(v.symbol, v.destination, v.status) : holder !== null ? holderAnswerWords(holder.files, v.destination, v.status, home) : answerWords(verdictFamily(v.symbol), v.destination, v.source, v.status, home),
    words: v.status === "pending" ? said : { family: said.family, sentence: said.sentence },
    ...(onceOnly ? { onceOnly } : {}),
    ...(v.status !== "pending" && v.noLongerApplies !== undefined ? { noLongerApplies: v.noLongerApplies, staleNote: noLongerAppliesWords(v.noLongerApplies) } : {}),
  };
}

/** Group the catalog by GATE (§8), preserving catalog order within each group
 * — that order IS the gate's evaluation order, which the old per-boundary
 * grouping destroyed by interleaving unrelated gates. Group order = first
 * appearance in the catalog. An arbiter predating the `gate` field gets the
 * same grouping via the id prefix (identical by construction arbiter-side). */
function groupRules(
  rules: UsageRuleRow[],
  gates: UsageGateRow[] | undefined,
  sensitivePaths: string[],
  hits?: PolicySnapshot["hits"],
  dispositions?: Record<string, { mode: string }>,
): GateGroupVM[] {
  const gateById = new Map<string, UsageGateRow>();
  for (const g of gates ?? []) gateById.set(g.id, g);
  const groups = new Map<string, GateGroupVM>();
  for (const r of rules) {
    const gateId = r.gate ?? (r.id.includes(":") ? r.id.slice(0, r.id.indexOf(":")) : "?");
    let group = groups.get(gateId);
    if (!group) {
      const meta = gateById.get(gateId);
      group = {
        id: gateId,
        // No invented citations: absent gate catalog ⇒ the honest prefix name
        // and no evaluation caption.
        title: meta ? meta.title : `${gateId} gate`,
        evaluation: meta ? meta.evaluation : null,
        rules: [],
      };
      groups.set(gateId, group);
    }
    const hit = hits?.[r.id];
    group.rules.push({
      id: r.id,
      source: r.source,
      boundary: r.boundary,
      where: whereLabel(r.boundary),
      outcome: ruleOutcome(r.outcome),
      summary: r.summary,
      detail: ruleDetail(r, gateById.get(gateId), sensitivePaths),
      hits: hits ? (hit?.hits ?? 0) : null,
      lastHit: hit?.lastHit ?? null,
      disposition: dispositions?.[r.id]?.mode === "block" ? "block" : dispositions?.[r.id]?.mode === "ask" ? "ask" : null,
    });
  }
  return [...groups.values()];
}

/** How many spent single-use answers the queue lists (dashboard.md §4.30). */
export const SPENT_HISTORY_LIMIT = 50;

/** A single-use answer already used: it decides nothing any more (the same
 *  test as the drawer's "spent", policy-panel-detail.ts verdictDetail). */
function isSpent(row: QueueRowVM): boolean {
  return row.status !== "pending" && row.scope === "once" && typeof row.consumedAt === "number";
}

/** One queue row's ⓘ drawer (the fixed §8 template), for
 *  GET /api/policy/verdict?id=<id>: the panel's rows do not carry it, it is
 *  built when the drawer opens. Any verdict the snapshot holds, an omitted
 *  history row included; null for an unknown id or a status the queue does
 *  not show. */
export function verdictDetailOf(snapshot: PolicySnapshot | null | undefined, id: string): DetailSection[] | null {
  const v = (snapshot?.verdicts ?? []).find((e) => e.id === id);
  if (!v || (v.status !== "pending" && v.status !== "approved" && v.status !== "denied")) return null;
  return verdictDetail(v, v.status);
}

/** `readFirst`: by verdict id, when the AI first read that row's item as it
 *  was, before it was masked (the loader's reading of the row's sessions,
 *  api-routes.ts `loadPolicyPanel`; dashboard.md §4.34). Absent: none known.
 *  `home`: the dashboard's home folder, the only one an answer's words call
 *  `~` (§4.34 "`~` is the dashboard's home"); absent, paths as recorded.
 *  `files`: the rule paths that are files on disk (server/path-kinds.ts),
 *  so a rule reaching everything inside a file is worded as that file
 *  (§4.25f *A rule on a file reads as a file*); absent, none known. */
export function toPolicyPanelViewModel(snapshot: PolicySnapshot | null | undefined, readFirst?: ReadonlyMap<string, string>, home = "", files: ReadonlySet<string> = new Set()): PolicyPanelVM {
  if (!snapshot) {
    const unknownChip = (detail: DetailSection[]): PostureChipVM => ({ state: "unknown", detail });
    return {
      available: false, extended: false, verdictsKnown: false,
      posture: {
        integrity: unknownChip([]),
        confidentiality: unknownChip([]),
        egress: unknownChip([]),
      },
      lawSource: null,
      queue: [], queueCounts: { pending: 0, approved: 0, denied: 0 }, queueOmitted: 0, gateGroups: [], sensitivePaths: [],
      inbound: null,
      yourRules: null, relaxations: null, lists: null, policyFile: null, models: null, modelsAdmin: null, perimeter: null,
    };
  }
  const extended = snapshot.posture !== undefined;
  const verdictsKnown = snapshot.verdicts !== undefined;
  const queue: QueueRowVM[] = [];
  // Newest activity first (what an operator audits first): resolvedAt when
  // recorded, falling back to lastSeen (pending rows and pre-column rows).
  const entries = [...(snapshot.verdicts ?? [])].sort(
    (a, b) => (b.resolvedAt ?? b.lastSeen) - (a.resolvedAt ?? a.lastSeen),
  );
  const queueCounts = { pending: 0, approved: 0, denied: 0 };
  let spent = 0;
  let queueOmitted = 0;
  for (const v of entries) {
    const row = toQueueRow(v, readFirst?.get(v.id), home);
    if (!row) continue;
    queueCounts[row.status]++;
    // The history window (dashboard.md §4.30): a spent single-use answer
    // decides nothing any more, and the arbiter keeps every one. The newest
    // SPENT_HISTORY_LIMIT are listed (entries run newest first); the rest
    // are counted. Every row that still decides something is listed.
    if (isSpent(row) && ++spent > SPENT_HISTORY_LIMIT) {
      queueOmitted++;
      continue;
    }
    queue.push(row);
  }
  const sensitivePaths = [...(snapshot.usage?.sensitivePaths ?? [])];
  return {
    available: true,
    extended,
    verdictsKnown,
    posture: postureChips(snapshot),
    lawSource: lawSourceVM(snapshot.lawSource, snapshot.specId),
    queue,
    queueCounts,
    queueOmitted,
    gateGroups: groupRules(snapshot.usage?.rules ?? [], snapshot.usage?.gates, sensitivePaths, snapshot.hits, snapshot.document?.rules),
    sensitivePaths,
    inbound: inboundVM(snapshot),
    yourRules: snapshot.document ? yourRulesVM(snapshot, files) : null,
    relaxations: snapshot.relaxations ? snapshot.relaxations.map((r) => ({ kind: r.kind, subject: r.subject, detail: r.detail })) : null,
    lists: snapshot.document ? Object.fromEntries(Object.entries(snapshot.document.lists ?? {}).map(([k, v]) => [k, [...v]])) : null,
    policyFile: snapshot.policyFile ? { ...snapshot.policyFile, problems: [...snapshot.policyFile.problems] } : null,
    models: snapshot.document ? toModelEndpointRows(snapshot.document.models, snapshot.document.modelVersions) : null,
    modelsAdmin: snapshot.document?.modelsAdmin ? modelsAdminVM(snapshot.document.modelsAdmin) : null,
    perimeter: snapshot.document?.perimeter ? perimeterVM(snapshot.document.perimeter) : null,
  };
}

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

/** Plan 12 D5, copied field by field (an older arbiter sends files and the
 *  lock only). */
function modelsAdminVM(a: NonNullable<NonNullable<PolicySnapshot["document"]>["modelsAdmin"]>): NonNullable<PolicyPanelVM["modelsAdmin"]> {
  return {
    files: strings(a.files),
    locked: a.locked === true,
    conflicts: strings(a.conflicts),
    refused: strings(a.refused),
    removed: (Array.isArray(a.removed) ? a.removed : [])
      .filter((r) => r && typeof r.name === "string" && typeof r.file === "string")
      .map((r) => ({ name: r.name, file: r.file })),
  };
}

/** Plan 12 D4: the perimeter in force, copied field by field. */
function perimeterVM(p: NonNullable<NonNullable<PolicySnapshot["document"]>["perimeter"]>): NonNullable<PolicyPanelVM["perimeter"]> {
  return {
    networks: p.networks === null ? null : strings(p.networks),
    domains: strings(p.domains),
    by: p.by === "administrator" || p.by === "narrowed" ? p.by : "you",
  };
}

// ── "Your rules" (stage 5b): the operator's law from policy.yaml, one row grammar ──

// Never a promise that the file stays here: a "may go to" host (shown on the
// same row), an Always-allow or a locked row sends the real value with no
// question asked (dashboard.md §4.25d).
const LEVEL_EFFECT: Record<string, string> = {
  "no-model": "the AI can't read it",
  "any-model": "the AI may read it — sent only where a rule or your OK allows",
  "local-model": "only your own model may read it; sent only where a rule or your OK allows",
  public: "released — not treated as secret",
};

function hitsFor(hits: PolicySnapshot["hits"], id: string): { hits: number | null; auditHits: number | null; lastHit: number | null } {
  if (!hits) return { hits: null, auditHits: null, lastHit: null };
  const h = hits[id];
  return { hits: h?.hits ?? 0, auditHits: h?.auditHits ?? 0, lastHit: h?.lastHit ?? null };
}

function yourRulesVM(snapshot: PolicySnapshot, files: ReadonlySet<string>): YourRuleRowVM[] {
  return yourRuleRowsVM(snapshot, files).map((r) => ({ ...r, actions: ruleRowActions(r) }));
}

function yourRuleRowsVM(snapshot: PolicySnapshot, files: ReadonlySet<string>): Array<Omit<YourRuleRowVM, "actions">> {
  const doc = snapshot.document!;
  const relaxed = new Set((snapshot.relaxations ?? []).map((r) => `${r.kind} ${r.subject}`));
  const rows: Array<Omit<YourRuleRowVM, "actions">> = [];
  const none = { hits: null, auditHits: null, lastHit: null };
  const where = (s: string): DetailSection => ({
    label: "Where it's specified",
    items: [{ text: `policy.yaml — ${s}` }, ...(snapshot.policyFile?.path ? [{ text: snapshot.policyFile.path }] : [])],
  });

  const ownModel = hasLocalModel(toModelEndpointRows(doc.models));
  for (const p of doc.paths) {
    const effect = LEVEL_EFFECT[p.level] ?? p.level;
    const relaxes = relaxed.has(`public-path ${p.path}`);
    // Plan 10 §2.1: who may open the raw file. A pinned reader shows its name;
    // the pin itself (path + hash) is detail, not the row.
    // Plan 13 D3: an entry's own output rule (this file only) shows beside it.
    // Plan 13 R5: an interpreter pinned with its script is that program.
    const outputNote = (r: { app: string; output?: string; script?: string }): string =>
      r.output === "clear" && (r.script !== undefined || !readerRunsCode(r.app)) ? ", output shown to the AI"
      : r.output === "mask" && (r.script !== undefined || !readerRunsCode(r.app)) ? ", output partly masked"
      : "";
    // Plan 13 §8 decision (b): a shell or an interpreter with no script pin
    // admits nothing, and the row says so (the warning names the fix).
    // Plan 13 D8 (13), P0 item 14: as the arbiter judges each entry (a
    // pin's hash: a renamed copy is its program), the name rule only for an
    // older arbiter's snapshot.
    const judged: ArbiterReaderJudgment = {
      ...(p.readersAdmitNothing ? { admitNothing: p.readersAdmitNothing } : {}),
      ...(p.readersReadTwin ? { readTwin: p.readersReadTwin } : {}),
      ...(p.readersCopyOf ? { copyOf: p.readersCopyOf } : {}),
    };
    const readerNames = (p.readers ?? []).map((r, i) => {
      const app = typeof r === "string" ? r : r.app;
      const copy = judgedCopyOf(i, judged);
      if (judgedAdmitsNothing(r, i, judged)) return `${app}${copy !== null ? ` (a copy of ${copy})` : ""}${ADMITS_NOTHING}`;
      return `${typeof r === "string" ? r : `${r.app}${r.script ? ` running ${r.script}` : ""}${r.sha256 ? " (pinned)" : ""}${outputNote(r) ? ` (${outputNote(r).slice(2)})` : ""}`}${judgedReadsTwin(r, i, judged) ? READS_PLACEHOLDER : ""}`;
    });
    const readersEffect = p.readers ? ` · raw readers: ${readerNames.join(", ") || "none"}${p.others === "twin" ? " (others get the twin)" : " (others are refused)"}` : "";
    const glob = (p as { glob?: boolean }).glob === true || /[*?[]/.test(p.path);
    // A rule reaching everything inside a FILE (no `recursive:` key, as a
    // saved suggestion writes it) is worded as that file; `covers` keeps
    // what the rule says, so an edit made on the page keeps its reach.
    const isFile = p.recursive && !glob && files.has(p.path);
    rows.push({
      id: `lock:${p.path}`, kind: "lock", icon: "🔒", subject: p.path,
      covers: glob ? "pattern" : p.recursive ? "subtree" : "exact",
      ...(isFile ? { pathIsFile: true as const } : {}),
      level: p.level,
      bindings: [...p.bindings],
      // The rule's version as read (policy-surface.md §8.4.6): a label
      // chosen on it sends this back, refused once the rule changed.
      ...(typeof doc.pathVersions?.[p.path] === "string" && /^[0-9a-f]{32}$/.test(doc.pathVersions[p.path]!) ? { version: doc.pathVersions[p.path]! } : {}),
      ...(p.values?.length ? { values: p.values.map((v) => ({ key: v.key, bindings: [...v.bindings] })) } : {}),
      plain: {
        subject: p.path,
        reach: pathReach({ recursive: p.recursive && !isFile, glob }),
        effect: p.values?.length && p.level !== "public" ? levelWords(p.level) : levelWords(p.level, p.bindings),
        // Plan 13 §5.2/§5.3: where each value may be sent.
        ...(p.values?.length && p.level !== "public" ? { send: perValueWords(p.values, p.bindings, p.wholeBindings ?? []), sendParts: perValueParts(p.values, p.bindings, p.wholeBindings ?? []) } : {}),
        ...(p.level === "public" ? {} : {
          // The same judgment the per-program view reads (rules-by-who.ts).
          opens: opensWords(pathOpeners(p)?.map((o) => ({ name: o.name, how: o.how })) ?? null, p.others),
        }),
      },
      effect: effect + (p.recursive ? "" : " (this file only)") + (p.bindings.length ? ` · may go to ${p.bindings.join(", ")}` : "")
        + (p.values?.length ? ` · per value: ${p.values.map((v) => `${v.key} → ${v.bindings.join(", ") || "nowhere"}`).join("; ")}` : "") + readersEffect,
      ...(() => {
        // Plan 13 D8: a shell or interpreter reader runs the agent's code.
        const warnings = [
          ...(p.level === "local-model" && !ownModel ? [NO_OWN_MODEL_WARNING] : []),
          ...[codeRunningReadersWarning(p.readers, judged)].filter((w): w is string => w !== null),
        ];
        return warnings.length ? { warning: warnings.join(" ") } : {};
      })(),
      source: "policy.yaml", reach: null, relaxes, ...none, expires: null, expired: false,
      detail: [
        { label: "What this is", items: [{ text: relaxes ? "A secret-file label at public — a declassification wherever the secret catalog would have said otherwise." : "A secret-file label declared in the policy file — the same act as the dashboard's \"Lock it\", as law on disk." }] },
        { label: "What it does", items: [{ text: `${p.path}${p.recursive && !isFile ? " and everything under it" : ""}: ${effect}.` }] },
        ...(p.readers
          ? [{ label: "Raw readers (plan 10)", items: [
              { text: readerNames.length ? `${readerNames.join(", ")} may open the real file; each is tainted by it and what it prints to the AI is masked, unless its entry here says \`output: clear\` or \`mask\` (for this file only; a process holding another secret stays masked).` : "An empty list: every program is refused the raw file." },
              { text: p.others === "twin" ? "Every other program reads the structured twin." : "Every other program is refused (EACCES); the AI itself always reads the twin." },
            ] }]
          : []),
        where("paths:"),
      ],
    });
  }
  for (const a of doc.apps ?? []) {
    // Plan 13 D3: the program-wide rule is deprecated and clears nothing (it
    // applied to every file the program read). The row says what is in force:
    // the output is masked, and where the rule belongs now.
    const written = a.output === "clear" ? "its output not masked"
      : a.output === "mask" ? `only spans matching ${(a.mask ?? []).join(", ")} masked`
      : "its whole output masked";
    const what = "its whole output is masked for the AI once it has read a secret";
    rows.push({
      id: `app:${a.app}`, kind: "lock", icon: "🧰", subject: a.app,
      plain: { subject: a.app, reach: "a program", effect: programWords("secret") },
      effect: `program rule: ${what}`,
      ...(a.output !== "secret" ? { warning: `This program-wide rule (${written}) no longer applies: it covered every file ${a.app} reads, not only the one you meant. Put \`output: ${a.output}\` on ${a.app}'s entry under that file's readers: in policy.yaml.` } : {}),
      source: "policy.yaml", reach: null, relaxes: false, ...none, expires: null, expired: false,
      detail: [
        { label: "What this is", items: [{ text: "A per-program output rule (plan 10 §2.2), deprecated since 2026-10-02 (plan 13 D3): the output rule is now written on the reader entry of one file." }] },
        { label: "What it does", items: [{ text: `${a.app}: ${what}.` }] },
        where("apps:"),
      ],
    });
  }

  const lists = doc.lists;
  const expand = (v: string): string[] => (v.startsWith("@") ? lists[v.slice(1)] ?? [] : [v]);
  const originRows = (cat: "url" | "channel" | "dir", icon: string, list: string[] | undefined, trusted: boolean): void => {
    for (const raw of list ?? []) {
      for (const v of expand(raw)) {
        const kind = trusted ? "trusted-origin" : "untrusted-origin";
        rows.push({
          id: `${kind}:${cat}:${v}`, kind, icon, subject: v,
          plain: { subject: v, reach: sourceReach(cat), effect: trusted ? `${TERMS.trusted}, reaches the AI unmasked` : `Always ${TERMS.masked.toLowerCase()}` },
          effect: trusted ? "trusted source — what it returns enters the AI unmasked" : "untrusted source — what it returns is masked",
          source: "policy.yaml", reach: null, relaxes: trusted, ...none, expires: null, expired: false,
          detail: [
            { label: "What this is", items: [{ text: trusted ? `An allow-listed ${cat.toUpperCase()} origin: data from it is classified TRUSTED and reaches the AI as-is. A RELAXATION of the fail-closed default.` : `A block-listed ${cat.toUpperCase()} origin: data from it is classified UNTRUSTED and masked.` }] },
            where(`inbound.${cat}${raw.startsWith("@") ? ` via list ${raw}` : ""}`),
          ],
        });
      }
    }
  };
  // The document snapshot does not carry the origin lists themselves (they
  // live in the compiled categories); the arbiter's inbound `origins` rows
  // carry counts only. Relaxations DO name each trusted origin — use them.
  for (const r of snapshot.relaxations ?? []) {
    if (r.kind !== "trusted-origin") continue;
    const [cat, ...rest] = r.subject.split(":");
    const value = rest.join(":");
    const c = (cat ?? "URL").toLowerCase() as "url" | "channel" | "dir";
    originRows(c, c === "url" ? "🌐" : c === "dir" ? "📁" : "💬", [value], true);
  }

  for (const r of doc.userRules) {
    const kind = (`release-${r.mode}`) as YourRuleKind;
    const from = r.from ? r.from.join(", ") : "any source";
    const to = r.to.join(", ");
    const expired = r.expires ? Date.parse(r.expires) <= Date.now() : false;
    const effect =
      r.mode === "allow" ? "sending allowed — no ask" :
      r.mode === "block" ? "sending blocked — no ask" :
      r.mode === "audit" ? "watching — counts what it would have decided" :
      "off — kept, not applied";
    const h = hitsFor(snapshot.hits, `user:${r.id}`);
    rows.push({
      id: r.id, kind, icon: r.mode === "block" ? "⛔" : r.mode === "audit" ? "🧪" : r.mode === "off" ? "⏸" : "📤",
      subject: to === "*" ? "anywhere" : to,
      // "anywhere" is a word, not a host, and each source a code (§4.25u,
      // *Rules names what a send covers*).
      plain: {
        subject: to === "*" ? "anywhere" : to,
        ...(to === "*" ? { subjectParts: [{ kind: "text" as const, text: "anywhere" }] } : {}),
        reach: sendRuleReach(r.from ? from : null),
        ...(r.from && r.from.length ? { reachParts: sendRuleReachParts(r.from) } : {}),
        effect: sendWords(r.mode, expired),
      },
      effect, source: "policy.yaml", reach: `from ${from} to ${to === "*" ? "any destination" : to}`,
      relaxes: r.mode === "allow" && !expired,
      ...h, expires: r.expires ?? null, expired,
      detail: [
        { label: "What this is", items: [{ text: r.mode === "allow" ? "A user release rule: masked data from the named source may be sent to the named destination without asking you. A RELAXATION — it appears in the Relaxations list." : r.mode === "block" ? "A user release rule that forbids sending masked data from the named source to the named destination — nothing is asked, nothing is queued." : r.mode === "audit" ? "An audit-mode rule: evaluated on every matching send and counted, but never decides. Use it to test a rule before trusting it." : "A rule kept in the file but switched off — it decides nothing." }] },
        { label: "What it decides", items: [{ text: `from ${from} to ${to === "*" ? "any destination" : to}: ${effect}` }, ...(r.reason ? [{ text: `reason: ${r.reason}` }] : []), ...(r.by ? [{ text: `by: ${r.by}` }] : []), ...(r.added ? [{ text: `added: ${r.added}` }] : []), ...(r.expires ? [{ text: `expires: ${r.expires}${expired ? " (expired — ignored)" : ""}` }] : [])] },
        { label: "Activity", items: [{ text: h.hits === null ? "not tracked by this arbiter" : `decided ${h.hits}× · would have decided ${h.auditHits}× (audit)` }] },
        where(`user_rules id ${r.id}`),
      ],
    });
  }

  // Reachability (policy-surface.md §2.3): where the agent's
  // processes may CONNECT — the launcher's connect-guard half, applied at the
  // next launch. Always a relaxation (it widens what strict/curated admit).
  for (const d of doc.destinations ?? []) {
    if (d.connect !== "allow") continue;
    const spec = `${d.proto}:${d.host}:${d.port}`;
    // In the words the Approvals card used when the rule was asked for
    // (dashboard.md §4.25u, *Rules names a connection in words*).
    const target = connectWords(d.host, d.port, d.proto);
    rows.push({
      id: `connect:${spec}`, kind: "connect-allow", icon: "🔌",
      subject: `${d.host}:${d.port}${d.proto === "udp" ? " (udp)" : ""}`,
      plain: { subject: target.map((p) => p.text).join(""), subjectParts: target, reach: "your agent's programs connecting", effect: `${TERMS.allowed}, from the agent's next start` },
      effect: "the agent may connect there — from the next launch, in every posture",
      source: "policy.yaml", reach: null, relaxes: true, ...none, expires: null, expired: false,
      detail: [
        { label: "What this is", items: [{ text: "A destination the agent's processes may reach. The launcher adds it to the connection check as an extra allowance that keeps the default fallback — it never narrows anything else. A RELAXATION: under a strict or curated launch this host would otherwise be unreachable." }] },
        { label: "What it does", items: [{ text: `connect-guard spec ${spec} — applies at the next mandu launch (running agents keep their set)` }, ...(d.reason ? [{ text: `reason: ${d.reason}` }] : [])] },
        { label: "What it does NOT do", items: [{ text: "It does not release masked data toward that host — sending is decided live by your release rules and the built-in rules." }] },
        where("destinations:"),
      ],
    });
  }

  for (const [ruleId, d] of Object.entries(doc.rules)) {
    // `mode: ask` restates the built-in default — not a rule of the user's, so
    // not a row (the screenshot review: "set to Ask (the default)" was noise).
    if (d.mode !== "block") continue;
    const h = hitsFor(snapshot.hits, ruleId);
    rows.push({
      id: `disposition:${ruleId}`, kind: "disposition", icon: "⚙", subject: ruleId,
      plain: { subject: builtinName(ruleId), reach: "a built-in protection", effect: `${TERMS.blocked}, instead of asking you` },
      effect: d.mode === "block" ? "set to Block — the built-in ask is denied without asking" : "set to Ask (the default)",
      source: "policy.yaml", reach: null, relaxes: false, ...h, expires: null, expired: false,
      detail: [
        { label: "What this is", items: [{ text: "An operator disposition on a built-in rule that asks by default. Block denies outright and queues nothing — a TIGHTENING." }] },
        where(`rules: ${ruleId}`),
      ],
    });
  }
  return rows;
}
