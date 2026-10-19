/**
 * server/prompt-filter-routes — the developer inspector's Prompt filters
 * panel (docs/design/confidentiality/confidentiality-plan-15-prompt-filter.md §8.1; dashboard.md
 * §4.31). Mandu-new (no reference origin).
 *
 *   GET  /api/prompt-filters/filters           → the filters, who set them, the
 *        actions, the exceptions, the packs (counts), the digest
 *   GET  /api/prompt-filters/findings?session= → the session's `prompt_filter` events
 *   POST /api/prompt-filters/reveal  {session, symbol} → one finding's original
 *   POST /api/prompt-filters/bench   {text, origin}    → a DRY RUN of the filter
 *
 * PHASE 2, THE EDITING (plan 15 §8.1, §13.4):
 *   POST /api/prompt-filters/change {edit, expected?}
 *        One typed `PolicyEdit` (set-prompt-filter, set-prompt-action,
 *        remove-prompt-action, add-prompt-exception, remove-prompt-exception)
 *        through the ONE policy write path: previewed, a relaxation answered
 *        `{confirm: true, expected, rows, wouldLet}` until the person resends
 *        it with `expected`, then proposed on the ADMIN channel and approved
 *        at once (`applyAsHuman`, as Settings › Models does). A lock the
 *        administrator set is refused by the arbiter's validator, with who
 *        set it.
 *   GET  /api/prompt-filters/packs  → every pack in full (patterns, plain
 *        keywords; hashed keywords as a count): the arbiter's HUMAN-plane
 *        `promptFilterPacks`. Served like the Suggested view's listing (CSRF
 *        header AND the admin session, server.ts).
 *   POST /api/prompt-filters/pack-edit {edits, dryRun?, sample?}
 *        Typed edits to one of the person's own packs (`promptPackEdit`,
 *        ADMIN channel): a dry run validates (RE2) and counts each pattern's
 *        matches over a fixed corpus of ordinary prose and the bench text.
 *
 * PHASE 3, THE PLUGINS (plan 15 §4.3, §8.1, §13.5): the filters route
 * carries each plugin's pin, model, last run and confinement legs, and the
 * models a classifier may name (`clearedModels`: declared `local: true`, not
 * cloud-backed). `set-prompt-filter` takes `endpoint` (a model's name, or
 * null): any change is a relaxation, so it always asks first. A plugin pack
 * is a file only; the pack editor never offers it.
 *
 * PHASE 3, ASK AND "LET IT THROUGH" (plan 15 §7, §13.6):
 *   GET  /api/prompt-filters/holds → the prompts held for the human's answer,
 *        with the found text (the arbiter's HUMAN-plane `promptHolds`):
 *        served like the packs GET (CSRF header AND the admin session).
 *   POST /api/prompt-filters/holds/answer {approvalId, answer, scope}
 *        send (as written), mask (the default) or cancel; once (this
 *        message) or session: `resolvePromptHold` on the ADMIN channel.
 *        A hold under a LOCKED administrator's `ask` row is listed with
 *        `onceOnly: true`, and a session answer to it is refused with 409
 *        and the arbiter's reason (plan 15 §12, 2026-10-04).
 *   POST /api/prompt-filters/let-through {session, eventId, index, scope}
 *        one past finding goes as written (once: in its message; session):
 *        only a finding one of the session's own (proxy-recorded, never
 *        claimed) `prompt_filter` events names, by its opaque reference:
 *        `letPromptFindingThrough` on the ADMIN channel. A finding the
 *        arbiter marked `onceOnly` (its event, copied by the proxy: a locked
 *        administrator's `ask` row) is listed with `onceOnly: true`, and the
 *        arbiter's refusal of a session let-through is a 409 with its reason.
 *        The findings route reads the locks in force too (`promptLocks`, the
 *        `promptFilters` rows): a finding under a locked administrator's row
 *        that is not `ask` is listed with no `canLet` and its `locked`
 *        action (the arbiter refuses it, 422), and a locked `ask` row in
 *        force marks `onceOnly` as the event would.
 *
 * PHASE 4, THE PRODUCT PAGE (plan 15 §11, §13.7; dashboard.md §4.25y):
 *   GET  /api/policy/prompt-filters → Settings › Prompt filters: the SAME
 *        projection (`promptFiltersProjection`) in the product's words
 *        (view-model/prompt-settings.ts). Served with the CSRF header AND
 *        the admin session (an exception may hold the person's own words).
 *   POST /api/policy/prompt-filters/change {edit, expected?}
 *        The SAME typed edit and write path (`applyPromptEdit`), narrowed to
 *        set-prompt-action, remove-prompt-action, add-prompt-exception and
 *        remove-prompt-exception; recorded as requested by `settings`.
 *   POST /api/prompt-filters/reveal {session, eventId, index}
 *        The transcript note's "Show what was hidden": the panel's reveal,
 *        naming the finding instead of the symbol (the product's data has
 *        none), and only for a span the filter minted on its own outside the
 *        secret kinds (`noteRevealSymbol`).
 *
 * WHAT NEVER LEAVES WITHOUT A HUMAN ASKING: an original. The findings list
 * carries symbols, categories and counts (the events carry nothing else); a
 * row's original is resolved on demand through the SAME human-plane read the
 * transcript's reveal uses (`EventSource.desymbolize`, the arbiter's
 * `desymbolize` on the human socket), and only for a symbol that one of the
 * session's own `prompt_filter` findings names. The two POSTs sit behind the
 * server's global POST gate (CSRF header + admin session).
 *
 * THE TEST BENCH is the arbiter's `filterPrompt` with `dryRun: true`, which
 * the arbiter accepts only on the HUMAN plane (a dry run on the data socket
 * would let the agent's processes test guesses against the registered values
 * without a trace): no symbol is minted, nothing is cached, no event is
 * written, and this route neither stores nor logs the text.
 */

import { type IncomingMessage, type ServerResponse } from "node:http";

import { isAdminBoundaryError, json, readJson } from "./http-util.js";
import { applyAsHuman, type PolicyAssistantArbiter } from "./policy-assistant-routes.js";
import { SETTINGS_APPROVER } from "./model-routes.js";
import { relaxKey } from "../policy-assistant.js";
import { editRow, relaxLine } from "../view-model/policy-proposals.js";
import { type EventSource } from "../event-source.js";
import { isCloudBackedModel } from "../model-probe.js";
import type { ManduEvent, PromptFilterDetail } from "../event-model.js";
import { lockOf, promptSettingsVM, READ_ONLY_SETTINGS, SETTINGS_PROMPT_OPS, type PromptFiltersProjection } from "../view-model/prompt-settings.js";
import type { PromptLocks } from "../view-model/prompt-notes.js";

export type PromptFilterOrigin = "human" | "harness" | "side-call";

/** The arbiter's `promptFilters` answer (arbiter/ipc/protocol.ts
 *  PromptFiltersResultWire), structurally. No value anywhere in it. */
export interface PromptFiltersWire {
  filters: Array<{
    id: string;
    kind: string;
    on: boolean;
    setBy: string;
    locked?: boolean;
    file?: string;
    onError: string;
    onErrorSet?: boolean;
    available?: boolean;
    problem?: string;
    categories: Array<{ category: string; action: string }>;
    origins: Array<{ origin: PromptFilterOrigin; floor: string }>;
    /** Phase 3: a classifier plugin's model (its switch's `endpoint:`). */
    endpoint?: string;
    /** Phase 3: a plugin's pin, model and last run (PromptPluginWire). */
    plugin?: PromptPluginWire;
  }>;
  /** Phase 2 (absent on a phase-1 arbiter). */
  actions?: Array<{ category: string; action: string; setBy: string; locked: boolean; file?: string }>;
  fallback?: string;
  /** With `match` once the adapter put the human plane's patterns back in
   *  (arbiter-adapter.ts; the data-socket answer carries none, plan 15
   *  §13.7 item 4). */
  exceptions?: Array<{ category: string; match: string; setBy: string; file?: string; inForce: boolean }>;
  signedOnly?: boolean;
  packs?: Array<{ id: string; source: string; file: string; version: string; description?: string; signedBy: string | null; ignored?: string; patterns: number; keywordGroups: number; keywords: number; hashedKeywords: number; categories: string[] }>;
  packProblems?: Array<{ file: string; source: string; pack?: string; problems: string[] }>;
  conflicts?: string[];
  userPackDir?: string | null;
  enforcing: boolean;
  digest: { policy: string; packs: string; values: string };
  registeredValues: number;
}

/** A prompt filter plugin as the arbiter reports it (plan 15 §4.3, §13.5
 *  item 12; arbiter/ipc/protocol.ts PromptPluginWire), structurally. Never
 *  a prompt. */
export interface PromptPluginWire {
  exec: string;
  sha256: string;
  script?: string;
  scriptSha256?: string;
  /** The other files it loads, pinned (plan 15 §13.5 item 6). */
  modules?: Array<{ path: string; sha256: string }>;
  cost: string;
  needsEndpoint: boolean;
  deadlineMs: number;
  runs: number;
  errors: number;
  lastMs?: number;
  lastAt?: string;
  lastError?: string;
  lastErrorAt?: string;
  lastEndpoint?: string;
  confinement?: { guard: boolean; landlock: boolean; seccomp: boolean; namespaces: boolean; notes: string[] };
}

/** A declared model as the arbiter's `modelEndpoints` answers it (the
 *  fields the endpoint choice needs). */
export interface DeclaredModelWire {
  name: string;
  local: boolean;
  model?: string;
}

/** The models a classifier may name (plan 15 §5): declared `local: true`
 *  and not cloud-backed, the arbiter's own rule (`resolveLocalEndpoint`),
 *  which judges the edit again. Pure. */
export function clearedModels(models: readonly DeclaredModelWire[], isCloudBacked: (model: string) => boolean): Array<{ name: string; model?: string }> {
  return models
    .filter((m) => m && m.local === true && typeof m.name === "string" && !(typeof m.model === "string" && isCloudBacked(m.model)))
    .map((m) => ({ name: m.name, ...(typeof m.model === "string" ? { model: m.model } : {}) }));
}

/** The plugin part of a filter row, field by field (never a prompt). Pure. */
export function pluginView(p: PromptPluginWire | undefined): PromptPluginWire | undefined {
  if (!p || typeof p !== "object") return undefined;
  const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
  const c = p.confinement;
  return {
    exec: str(p.exec), sha256: str(p.sha256),
    ...(typeof p.script === "string" ? { script: p.script, scriptSha256: str(p.scriptSha256) } : {}),
    ...(Array.isArray(p.modules) && p.modules.length > 0
      ? { modules: p.modules.filter((m) => m && typeof m === "object").map((m) => ({ path: str(m.path), sha256: str(m.sha256) })) }
      : {}),
    cost: str(p.cost), needsEndpoint: p.needsEndpoint === true, deadlineMs: num(p.deadlineMs) ?? 0,
    runs: num(p.runs) ?? 0, errors: num(p.errors) ?? 0,
    ...(num(p.lastMs) !== undefined ? { lastMs: num(p.lastMs)! } : {}),
    ...(typeof p.lastAt === "string" ? { lastAt: p.lastAt } : {}),
    ...(typeof p.lastError === "string" ? { lastError: p.lastError } : {}),
    ...(typeof p.lastErrorAt === "string" ? { lastErrorAt: p.lastErrorAt } : {}),
    ...(typeof p.lastEndpoint === "string" ? { lastEndpoint: p.lastEndpoint } : {}),
    ...(c && typeof c === "object"
      ? { confinement: { guard: c.guard === true, landlock: c.landlock === true, seccomp: c.seccomp === true, namespaces: c.namespaces === true, notes: (Array.isArray(c.notes) ? c.notes : []).map((n) => str(n)) } }
      : {}),
  };
}

/** The arbiter's `promptFilterPacks` answer (human plane), structurally. */
export interface PromptFilterPacksWire {
  packs: Array<{
    id: string; source: string; file: string; version: string; description?: string; signedBy: string | null; editable: boolean;
    patterns: Array<{ id: string; category: string; regex: string; check?: string; level?: string }>;
    keywords: Array<{ category: string; match: string; hashed: boolean; count: number; words?: string[]; level?: string }>;
  }>;
  packProblems: Array<{ file: string; source: string; pack?: string; problems: string[] }>;
}

/** The arbiter's `promptPackEdit` answer, structurally. */
export interface PromptPackEditWire {
  ok: boolean;
  problems?: string[];
  pack?: string;
  file?: string;
  created?: boolean;
  changes?: Array<{ direction: "relax" | "tighten"; subject: string; detail: string }>;
  counts?: Array<{ id: string; corpus: number; sample: number }>;
  dryRun: boolean;
}

/** The arbiter's `filterPrompt` answer (FilterPromptResultWire), structurally. */
export interface FilterPromptWire {
  segments: Array<{
    id: string;
    origin: PromptFilterOrigin;
    action: "pass" | "rewrite" | "hold" | "block";
    text?: string;
    reason?: string;
    findings: Array<{ start: number; end: number; category: string; filterId: string; action: string; symbol?: string; how?: string }>;
    skipped: number;
    cached: boolean;
  }>;
  enforcing: boolean;
  dryRun: boolean;
  digest: { policy: string; packs: string; values: string };
}

/** The NARROW arbiter surface (the arbiter-client pattern): server-main wires
 *  the real client (arbiter-adapter.ts: `promptFilters` on the data socket,
 *  the dry run on the HUMAN socket); tests inject a fake. Both optional: an
 *  arbiter predating plan 15 answers 501. */
export interface PromptFiltersArbiter {
  promptFilters?(): Promise<PromptFiltersWire>;
  /** `filterPrompt` with `dryRun: true`, on the human plane. */
  filterPromptDryRun?(args: { agent: string; segments: Array<{ id: string; origin: PromptFilterOrigin; text: string }> }): Promise<FilterPromptWire>;
  /** Phase 2: every pack in full, on the human plane. */
  promptFilterPacks?(): Promise<PromptFilterPacksWire>;
  /** Phase 2: typed edits to one of the person's packs, on the ADMIN channel. */
  promptPackEdit?(args: { edits: unknown; dryRun?: boolean; sample?: string; requestedBy?: string }): Promise<PromptPackEditWire>;
  /** Phase 3: the declared models (the classifier's endpoint choice). */
  modelEndpoints?(): Promise<DeclaredModelWire[]>;
  /** Phase 3: the held prompts with their found text, on the HUMAN plane. */
  promptHolds?(): Promise<PromptHoldsWire>;
  /** Phase 3: the human's answer to a hold, on the ADMIN channel. */
  resolvePromptHold?(args: { approvalId: string; answer: PromptHoldAnswer; scope?: PromptVerdictScope }): Promise<{ approval: unknown }>;
  /** Phase 3: let one past finding through, on the ADMIN channel. */
  letPromptFindingThrough?(args: { session: string; category: string; ref: string; turn?: string; scope: PromptVerdictScope }): Promise<{ approval: unknown }>;
}

export type PromptHoldAnswer = "send" | "mask" | "cancel";
export type PromptVerdictScope = "once" | "session";

/** The arbiter's `promptHolds` answer (PromptHoldsResultWire), structurally. */
export interface PromptHoldsWire {
  holds: Array<{
    approvalId: string; session: string; category: string; filterId?: string;
    /** The human's own found text (human plane). */
    span?: string; fallback?: "mask" | "redact";
    firstSeen: number; lastSeen: number; timeoutMs: number;
    /** A locked administrator's `ask` row: this message only. */
    onceOnly?: boolean;
  }>;
  timeoutMs: number;
}

/** The ops the panel's change route accepts (plan 15 §6), and their keys. */
export const PROMPT_EDIT_KEYS: Readonly<Record<string, readonly string[]>> = {
  "set-prompt-filter": ["op", "filter", "on", "on_error", "endpoint"],
  "set-prompt-action": ["op", "category", "action"],
  "remove-prompt-action": ["op", "category"],
  "add-prompt-exception": ["op", "category", "match"],
  "remove-prompt-exception": ["op", "category", "match"],
};

/** The pack editor's ops (arbiter/prompt-filter/pack-edit.ts). */
export const PACK_EDIT_OPS: readonly string[] = ["set-prompt-pattern", "remove-prompt-pattern", "add-prompt-keyword", "remove-prompt-keyword"];

/** Who the arbiter records for a change made here, and the approver. */
export const PANEL_REQUESTER = "prompt-filters-panel";
const MOVED = "The prompt filter policy changed while you were deciding. Nothing was changed. Try again.";

/** The longest bench text accepted (characters). */
export const BENCH_MAX_CHARS = 64 * 1024;
/** How many findings rows the list ships (newest first). */
export const FINDINGS_LIMIT = 200;
/** What the panel says when this dashboard cannot write the policy (an
 *  arbiter predating phase 2, or no policy write path). */
export const READ_ONLY_NOTE = "Read-only: this arbiter cannot change prompt_filters: from here (restart the Mandu stack on the current build).";
/** What the panel says when it can. */
export const EDIT_NOTE = "Changes go to policy.yaml prompt_filters: (switches, actions, exceptions) or to your own pack in the packs folder, and apply on the next request. A change that lets findings through asks you first.";

/** One row of the Recent findings list. Copied field by field from the
 *  event's `promptFilter` detail: never the event's input/output panes. */
export interface FindingRow {
  eventId: string;
  ts: string;
  emitter: string;
  agent: string;
  origin: PromptFilterOrigin;
  segmentId: string;
  action: "pass" | "rewrite" | "block";
  enforcing: boolean;
  skipped: number;
  /** Phase 3: the message's opaque reference (a "let it through, once"). */
  turn: string | null;
  findings: Array<{
    filterId: string; category: string; action: string; symbol: string | null; how: string | null;
    /** Phase 3: its position in the event (the let-through route names it). */
    index: number;
    /** Phase 3: may be let through (an opaque reference, an enforced action,
     *  not a registered value, not already let through). */
    canLet: boolean;
    /** The arbiter's word on the event (plan 15 §12, 2026-10-04), or the
     *  locks in force: a locked administrator's `ask` row covers it, so it
     *  is let through in its message only; the panel offers no session
     *  button. */
    onceOnly: boolean;
    /** A locked administrator's row that is not `ask` covers it (the locks
     *  in force): its action, and the arbiter refuses any let-through, so
     *  `canLet` is false. Absent otherwise. */
    locked?: string;
    let: "once" | "session" | null;
    hold: string | null;
  }>;
}

/** The actions a "let it through" may cover (§7). */
const LETTABLE: ReadonlySet<string> = new Set(["redact", "mask", "ask", "block"]);
const REF_RE = /^[0-9a-f]{32}$/;

const ORIGINS: readonly PromptFilterOrigin[] = ["human", "harness", "side-call"];
const str = (v: unknown, d = ""): string => (typeof v === "string" ? v : d);

function detailOf(e: ManduEvent): PromptFilterDetail | null {
  if (e.kind !== "prompt_filter") return null;
  const d = (e as { promptFilter?: unknown }).promptFilter;
  return d && typeof d === "object" ? (d as PromptFilterDetail) : null;
}

/** The session's `prompt_filter` events as findings rows, newest first.
 *  `locks`: the administrator's locks in force (null: the events alone
 *  decide what may be let through). Pure. */
export function toFindingRows(events: readonly ManduEvent[], limit = FINDINGS_LIMIT, locks: PromptLocks | null = null): FindingRow[] {
  const rows: FindingRow[] = [];
  for (const e of events) {
    const d = detailOf(e);
    if (!d) continue;
    const origin = ORIGINS.includes(d.origin) ? d.origin : "harness";
    rows.push({
      eventId: e.id,
      ts: e.ts,
      emitter: str(e.emitter),
      agent: str(d.agent),
      origin,
      segmentId: str(d.segmentId),
      action: d.action === "rewrite" || d.action === "block" ? d.action : "pass",
      enforcing: d.enforcing === true,
      skipped: typeof d.skipped === "number" && d.skipped > 0 ? Math.floor(d.skipped) : 0,
      turn: typeof d.turn === "string" && REF_RE.test(d.turn) ? d.turn : null,
      findings: (Array.isArray(d.findings) ? d.findings : []).map((f, index) => {
        const open = e.claimed !== true && origin === "human" && typeof f?.ref === "string" && REF_RE.test(f.ref) && LETTABLE.has(str(f?.action))
          && f?.let === undefined && !str(f?.category).startsWith("secret.registered");
        // The lock in force now: one that is not `ask` refuses both scopes.
        const lock = open && locks ? locks(str(f?.category)) : null;
        const locked = lock !== null && lock.action !== "ask" ? lock.action : null;
        return {
          filterId: str(f?.filterId),
          category: str(f?.category),
          action: str(f?.action),
          symbol: typeof f?.symbol === "string" && f.symbol.startsWith("$MDU:") ? f.symbol : null,
          how: typeof f?.how === "string" ? f.how : null,
          index,
          canLet: open && locked === null,
          onceOnly: f?.onceOnly === true || lock?.ask === true,
          ...(locked !== null ? { locked } : {}),
          let: f?.let === "once" || f?.let === "session" ? f.let : null,
          hold: typeof f?.hold?.state === "string" ? f.hold.state : null,
        };
      }),
    });
  }
  rows.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
  return rows.slice(0, limit);
}

/** The symbols a session's findings name (what `reveal` may resolve). Pure. */
export function findingSymbols(events: readonly ManduEvent[]): Set<string> {
  const out = new Set<string>();
  for (const e of events) {
    // Only the proxies' own findings open a reveal: a claimed event
    // (arbiter-human-plane.md §10.2) is the sender's word.
    if (e.claimed === true) continue;
    const d = detailOf(e);
    for (const f of d && Array.isArray(d.findings) ? d.findings : []) {
      if (typeof f?.symbol === "string" && f.symbol.startsWith("$MDU:")) out.add(f.symbol);
    }
  }
  return out;
}

function noArbiter(res: ServerResponse): void {
  json(res, 404, { error: "arbiter not connected" });
}

/** Can this dashboard write the prompt filter policy through `arbiter`? */
function canEdit(arbiter: PromptFiltersArbiter & Partial<PolicyAssistantArbiter>): boolean {
  return !!(arbiter.policyPreview && arbiter.policyPropose && arbiter.resolvePolicyProposal);
}

/** The panel's Filters projection, field by field from the arbiter's
 *  `promptFilters` (no value in it), or the status and error that answer
 *  instead. Settings › Prompt filters on the product page reads the SAME
 *  projection (plan 15 §13.7). */
export async function promptFiltersProjection(
  arbiter: (PromptFiltersArbiter & Partial<PolicyAssistantArbiter>) | undefined,
): Promise<{ ok: true; body: Record<string, unknown> } | { ok: false; status: number; error: string }> {
  if (!arbiter) return { ok: false, status: 404, error: "arbiter not connected" };
  if (!arbiter.promptFilters) return { ok: false, status: 501, error: "this arbiter predates the prompt filter (plan 15): no 'promptFilters' op" };
  let w: PromptFiltersWire;
  try {
    w = await arbiter.promptFilters();
  } catch (err) {
    return { ok: false, status: 502, error: `promptFilters failed: ${(err as Error).message}` };
  }
  const phase2 = Array.isArray(w.actions);
  const editable = phase2 && canEdit(arbiter);
  let models: Array<{ name: string; model?: string }> = [];
  if (arbiter.modelEndpoints && (w.filters ?? []).some((f) => f.plugin?.needsEndpoint === true)) {
    try {
      models = clearedModels(await arbiter.modelEndpoints(), isCloudBackedModel);
    } catch { /* the list is a convenience: the switch still shows its model */ }
  }
  return { ok: true, body: {
    filters: (Array.isArray(w.filters) ? w.filters : []).map((f) => ({
      id: str(f.id), kind: str(f.kind), on: f.on === true, setBy: str(f.setBy, "default"),
      locked: f.locked === true, ...(typeof f.file === "string" ? { file: f.file } : {}),
      onError: str(f.onError), onErrorSet: f.onErrorSet === true, available: f.available !== false,
      ...(typeof f.problem === "string" ? { problem: f.problem } : {}),
      categories: (Array.isArray(f.categories) ? f.categories : []).map((c) => ({ category: str(c.category), action: str(c.action) })),
      origins: (Array.isArray(f.origins) ? f.origins : []).map((o) => ({ origin: o.origin, floor: str(o.floor) })),
      ...(typeof f.endpoint === "string" ? { endpoint: f.endpoint } : {}),
      ...(pluginView(f.plugin) ? { plugin: pluginView(f.plugin) } : {}),
    })),
    // Phase 3 (§5, §8.1): the models a classifier may name, for its choice.
    clearedModels: models,
    actions: (Array.isArray(w.actions) ? w.actions : []).map((a) => ({
      category: str(a.category), action: str(a.action), setBy: str(a.setBy, "default"), locked: a.locked === true,
      ...(typeof a.file === "string" ? { file: a.file } : {}),
    })),
    fallback: str(w.fallback, "redact"),
    exceptions: (Array.isArray(w.exceptions) ? w.exceptions : []).map((e) => ({
      category: str(e.category), match: str(e.match), setBy: str(e.setBy, "you"), inForce: e.inForce !== false,
      ...(typeof e.file === "string" ? { file: e.file } : {}),
    })),
    signedOnly: w.signedOnly === true,
    packs: (Array.isArray(w.packs) ? w.packs : []).map((p) => ({
      id: str(p.id), source: str(p.source), file: str(p.file), version: str(p.version),
      ...(typeof p.description === "string" ? { description: p.description } : {}),
      signedBy: typeof p.signedBy === "string" ? p.signedBy : null,
      ...(typeof p.ignored === "string" ? { ignored: p.ignored } : {}),
      patterns: Number(p.patterns) || 0, keywordGroups: Number(p.keywordGroups) || 0, keywords: Number(p.keywords) || 0, hashedKeywords: Number(p.hashedKeywords) || 0,
      categories: (Array.isArray(p.categories) ? p.categories : []).map((c) => str(c)),
      ...((p as { plugin?: unknown }).plugin === true ? { plugin: true } : {}),
    })),
    packProblems: (Array.isArray(w.packProblems) ? w.packProblems : []).map((p) => ({
      file: str(p.file), source: str(p.source), ...(typeof p.pack === "string" ? { pack: p.pack } : {}),
      problems: (Array.isArray(p.problems) ? p.problems : []).map((x) => str(x)),
    })),
    conflicts: (Array.isArray(w.conflicts) ? w.conflicts : []).map((c) => str(c)),
    userPackDir: typeof w.userPackDir === "string" ? w.userPackDir : null,
    enforcing: w.enforcing === true,
    digest: { policy: str(w.digest?.policy), packs: str(w.digest?.packs), values: str(w.digest?.values) },
    registeredValues: typeof w.registeredValues === "number" ? w.registeredValues : 0,
    editable,
    packsEditable: editable && typeof arbiter.promptPackEdit === "function" && typeof arbiter.promptFilterPacks === "function",
    note: editable ? EDIT_NOTE : READ_ONLY_NOTE,
  } };
}

export async function getPromptFilters(arbiter: (PromptFiltersArbiter & Partial<PolicyAssistantArbiter>) | undefined, res: ServerResponse): Promise<void> {
  const p = await promptFiltersProjection(arbiter);
  if (!p.ok) return json(res, p.status, { error: p.error });
  json(res, 200, p.body);
}

/** GET /api/policy/prompt-filters: Settings › Prompt filters on the product
 *  page (plan 15 §13.7), the panel's projection in the product's words. The
 *  server gates it like the Suggested view's listing (CSRF header AND the
 *  admin session): an exception may hold words the person typed. */
export async function getPromptSettings(arbiter: (PromptFiltersArbiter & Partial<PolicyAssistantArbiter>) | undefined, res: ServerResponse): Promise<void> {
  const p = await promptFiltersProjection(arbiter);
  if (!p.ok) {
    // The product's words: no op name.
    const error = p.status === 404 ? "The protection service is not connected." : p.status === 501 ? READ_ONLY_SETTINGS : "The protection service did not answer.";
    return json(res, p.status, { error });
  }
  json(res, 200, { settings: promptSettingsVM(p.body as PromptFiltersProjection) });
}

/**
 * The administrator's locks the arbiter reports now (its `promptFilters`
 * rows, prompt-settings.ts `lockOf`) as a lookup by category, or null when
 * it cannot say (no arbiter, no op, an arbiter predating the rows, an
 * error): the routes then offer what the events allow, and the arbiter
 * still refuses what it must. A data-plane read; no value in it.
 */
export async function promptLocks(arbiter: Pick<PromptFiltersArbiter, "promptFilters"> | undefined): Promise<PromptLocks | null> {
  if (!arbiter?.promptFilters) return null;
  let w: PromptFiltersWire;
  try {
    w = await arbiter.promptFilters();
  } catch {
    return null;
  }
  if (!Array.isArray(w?.actions)) return null;
  const rows = w.actions.map((a) => ({ category: str(a.category), action: str(a.action), setBy: str(a.setBy, "default"), locked: a.locked === true }));
  return (category) => lockOf(rows, category);
}

/**
 * GET /api/prompt-filters/findings?session=. `source` is the one that owns
 * the session, as for /api/events (server.ts sessionSource): the tenant's
 * store, or the RECORDED replay sessions (dashboard.md §4.28) for a
 * `<runId>/<key>` id, which no arbiter holds (the store rejects such an id).
 * A recorded session's rows come back `recorded: true` with no row
 * `canLet`: its symbols resolve in no arbiter and its findings belong to no
 * live session, so the panel offers neither a reveal nor a let-through.
 * `arbiter`: where the locks in force are read (`promptLocks`), for a live
 * session only.
 */
export async function getPromptFindings(source: EventSource, url: string, res: ServerResponse, opts: { recorded?: boolean; arbiter?: Pick<PromptFiltersArbiter, "promptFilters"> } = {}): Promise<void> {
  const session = new URLSearchParams(url.split("?")[1] ?? "").get("session");
  if (!session) {
    json(res, 400, { error: "missing ?session=" });
    return;
  }
  let events: ManduEvent[];
  try {
    events = await source.readEvents(session);
  } catch (err) {
    json(res, 502, { error: `could not read the session's events: ${(err as Error).message}` });
    return;
  }
  if (!opts.recorded) {
    const locks = events.some((e) => e.kind === "prompt_filter") ? await promptLocks(opts.arbiter) : null;
    return json(res, 200, { session, findings: toFindingRows(events, FINDINGS_LIMIT, locks) });
  }
  const rows = toFindingRows(events);
  json(res, 200, {
    session,
    recorded: true,
    findings: rows.map((r) => ({ ...r, findings: r.findings.map((f) => ({ ...f, canLet: false })) })),
  });
}

/** The symbol a product-page "Show what was hidden" may resolve (plan 15
 *  §13.7): the finding `index` of the session's own (never claimed) event
 *  `eventId`, on the human's own text, masked by the filter's OWN mint (not
 *  a registered value's symbol, not a span merged with one) and outside the
 *  secret kinds; the product page never shows a secret Mandu knows. Pure. */
export function noteRevealSymbol(events: readonly ManduEvent[], eventId: string, index: number): { ok: true; symbol: string } | { ok: false; status: number; error: string } {
  const e = events.find((x) => x.id === eventId);
  const d = e && e.claimed !== true ? detailOf(e) : null;
  const f = d && Array.isArray(d.findings) ? d.findings[index] : undefined;
  if (!d || !f) return { ok: false, status: 404, error: "no prompt filter finding of this session has that id" };
  const category = str(f.category);
  if (d.origin !== "human" || typeof f.symbol !== "string" || !f.symbol.startsWith("$MDU:")) return { ok: false, status: 409, error: "nothing of this finding was kept to show" };
  if (category.startsWith("secret.") || f.how === "value" || f.how === "merged") return { ok: false, status: 409, error: "this finding is a secret Mandu knows; its value is never shown on this page" };
  return { ok: true, symbol: f.symbol };
}

export async function postPromptReveal(source: EventSource, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = (await readJson(req).catch(() => null)) as { session?: unknown; symbol?: unknown; eventId?: unknown; index?: unknown } | null;
  const session = typeof body?.session === "string" ? body.session : "";
  // The product page names the finding by its event and index (its data
  // carries no symbol, plan 15 §13.7); the panel names the symbol.
  if (session && typeof body?.eventId === "string" && body.symbol === undefined) {
    const index = typeof body.index === "number" && Number.isInteger(body.index) && body.index >= 0 ? body.index : -1;
    if (index < 0) return json(res, 400, { error: "index is required" });
    return revealNoted(source, session, body.eventId, index, res);
  }
  const symbol = typeof body?.symbol === "string" ? body.symbol : "";
  if (!session || !symbol.startsWith("$MDU:")) {
    json(res, 400, { error: "session and a $MDU: symbol are required" });
    return;
  }
  if (!source.desymbolize) {
    json(res, 501, { error: "this event source cannot resolve symbols (no arbiter)" });
    return;
  }
  let events: ManduEvent[];
  try {
    events = await source.readEvents(session);
  } catch (err) {
    json(res, 502, { error: `could not read the session's events: ${(err as Error).message}` });
    return;
  }
  // Only a symbol one of the session's own findings names: this route is the
  // panel's reveal, not a general desymbolize.
  if (!findingSymbols(events).has(symbol)) {
    json(res, 404, { error: "no prompt filter finding of this session names that symbol" });
    return;
  }
  try {
    json(res, 200, { symbol, original: await source.desymbolize(symbol) });
  } catch (err) {
    json(res, 502, { error: `desymbolize failed: ${(err as Error).message}` });
  }
}

/** The product page's form of the reveal: the SAME human-plane read, for the
 *  finding `noteRevealSymbol` allows; the answer carries the original only. */
async function revealNoted(source: EventSource, session: string, eventId: string, index: number, res: ServerResponse): Promise<void> {
  if (!source.desymbolize) return json(res, 501, { error: "this event source cannot show it (no protection service)" });
  let events: ManduEvent[];
  try {
    events = await source.readEvents(session);
  } catch (err) {
    return json(res, 502, { error: `could not read the session's events: ${(err as Error).message}` });
  }
  const plan = noteRevealSymbol(events, eventId, index);
  if (!plan.ok) return json(res, plan.status, { error: plan.error });
  try {
    json(res, 200, { original: await source.desymbolize(plan.symbol) });
  } catch {
    json(res, 502, { error: "the protection service could not show it" });
  }
}

export async function postPromptBench(arbiter: PromptFiltersArbiter | undefined, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter) return noArbiter(res);
  if (!arbiter.filterPromptDryRun) {
    json(res, 501, { error: "this arbiter predates the prompt filter (plan 15): no dry run" });
    return;
  }
  const body = (await readJson(req).catch(() => null)) as { text?: unknown; origin?: unknown } | null;
  const text = body?.text;
  const origin = body?.origin;
  if (typeof text !== "string" || text.trim() === "") {
    json(res, 400, { error: "text is required" });
    return;
  }
  if (text.length > BENCH_MAX_CHARS) {
    json(res, 413, { error: `text is longer than ${BENCH_MAX_CHARS} characters` });
    return;
  }
  // The bench offers the two origins a person can reason about (§8.1).
  if (origin !== "human" && origin !== "harness") {
    json(res, 400, { error: "origin must be human or harness" });
    return;
  }
  let w: FilterPromptWire;
  try {
    w = await arbiter.filterPromptDryRun({ agent: "dashboard", segments: [{ id: "bench", origin, text }] });
  } catch (err) {
    // Never echo the text into a log or an error: only the arbiter's reason.
    json(res, 502, { error: `filterPrompt (dry run) failed: ${(err as Error).message}` });
    return;
  }
  const seg = (Array.isArray(w.segments) ? w.segments : []).find((s) => s.id === "bench");
  if (!seg) {
    json(res, 502, { error: "the arbiter did not answer the bench segment" });
    return;
  }
  json(res, 200, {
    dryRun: w.dryRun === true,
    enforcing: w.enforcing === true,
    origin,
    action: seg.action,
    // What the model would receive for this text.
    modelText: seg.action === "rewrite" && typeof seg.text === "string" ? seg.text : text,
    skipped: typeof seg.skipped === "number" ? seg.skipped : 0,
    findings: (Array.isArray(seg.findings) ? seg.findings : []).map((f) => ({
      start: f.start, end: f.end, category: str(f.category), filterId: str(f.filterId), action: str(f.action),
      symbol: typeof f.symbol === "string" ? f.symbol : null, how: typeof f.how === "string" ? f.how : null,
    })),
    digest: { policy: str(w.digest?.policy), packs: str(w.digest?.packs), values: str(w.digest?.values) },
  });
}

/** One prompt edit from a request body, with only its op's keys, or why not. */
export function planPromptEdit(raw: unknown): { ok: true; edit: Record<string, unknown> } | { ok: false; error: string } {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { ok: false, error: "edit must be an object with an op" };
  const e = raw as Record<string, unknown>;
  const keys = typeof e.op === "string" ? PROMPT_EDIT_KEYS[e.op] : undefined;
  if (!keys) return { ok: false, error: `op must be one of ${Object.keys(PROMPT_EDIT_KEYS).join(", ")}` };
  const extra = Object.keys(e).filter((k) => !keys.includes(k));
  if (extra.length > 0) return { ok: false, error: `unknown key${extra.length > 1 ? "s" : ""} ${extra.join(", ")}` };
  for (const k of keys) {
    if (k === "op" || k === "on_error" || e[k] === undefined) continue;
    // A classifier's model, or null to remove it (the arbiter's validator
    // judges the name against the declared models).
    if (k === "endpoint" && e[k] === null) continue;
    const v = e[k];
    if (k === "on" ? typeof v !== "boolean" : typeof v !== "string" || v.length > 256) return { ok: false, error: `${k}: wrong type` };
  }
  return { ok: true, edit: Object.fromEntries(keys.filter((k) => e[k] !== undefined).map((k) => [k, e[k]])) };
}

/** The flattened text of view-model parts (the panel shows them as text). */
const partsText = (parts: Array<{ text: string }>): string => parts.map((p) => p.text).join("");

/** One typed prompt edit through the policy write path (`applyAsHuman`):
 *  previewed, a relaxation answered `confirm` until it is resent with
 *  `expected`, then proposed on the ADMIN channel and approved at once.
 *  `ops` narrows the ops the caller's route accepts; `parts` answers the
 *  question's rows as view-model parts (the product page) or flat text (the
 *  panel). Shared by the panel's change route and Settings › Prompt filters. */
async function applyPromptEdit(
  arbiter: PromptFiltersArbiter & PolicyAssistantArbiter,
  body: Record<string, unknown> | null,
  opts: { ops: readonly string[]; reason: (op: string) => string; requestedBy: string; parts: boolean },
): Promise<{ status: number; body: Record<string, unknown> }> {
  const expected = body?.["expected"];
  if (expected !== undefined && (!Array.isArray(expected) || !expected.every((k) => typeof k === "string"))) {
    return { status: 400, body: { error: "expected must be the list this route answered with" } };
  }
  const plan = planPromptEdit(body?.["edit"]);
  if (!plan.ok) return { status: 400, body: { error: plan.error } };
  if (!opts.ops.includes(String(plan.edit["op"]))) return { status: 400, body: { error: `op must be one of ${opts.ops.join(", ")}` } };
  const edits = [plan.edit];
  if (expected === undefined) {
    let preview;
    try {
      preview = await arbiter.policyPreview!(edits);
    } catch (err) {
      return { status: isAdminBoundaryError(err) ? 503 : 502, body: { error: String((err as Error)?.message ?? err) } };
    }
    if (!preview.ok) {
      if (preview.problems.some((p) => /unknown op/.test(p))) return { status: 501, body: { error: READ_ONLY_NOTE } };
      return { status: 422, body: { error: "This prompt filter change is not valid.", problems: preview.problems } };
    }
    if (preview.relaxations.length > 0) {
      const shape = (p: Array<{ text: string }>): unknown => (opts.parts ? p : partsText(p));
      return { status: 200, body: {
        applied: false,
        confirm: true,
        expected: preview.relaxations.map(relaxKey),
        rows: edits.map((e) => shape(editRow(e))),
        wouldLet: preview.relaxations.map((r) => shape(relaxLine(r))),
        details: preview.relaxations.map((r) => (r as { detail?: string }).detail ?? ""),
        ...(opts.parts ? { warnings: [] } : {}),
      } };
    }
  }
  return applyAsHuman(arbiter, edits, (expected as string[] | undefined) ?? [], {
    reason: opts.reason(String(plan.edit["op"])),
    requestedBy: opts.requestedBy,
    approver: SETTINGS_APPROVER,
    moved: MOVED,
  });
}

/** POST /api/prompt-filters/change: one typed edit through the policy write path. */
export async function postPromptFilterChange(arbiter: (PromptFiltersArbiter & PolicyAssistantArbiter) | undefined, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter) return noArbiter(res);
  if (!canEdit(arbiter)) return json(res, 501, { error: READ_ONLY_NOTE });
  const body = (await readJson(req).catch(() => null)) as Record<string, unknown> | null;
  const r = await applyPromptEdit(arbiter, body, {
    ops: Object.keys(PROMPT_EDIT_KEYS),
    reason: (op) => `Changed in the developer dashboard's Prompt filters panel (${op})`,
    requestedBy: PANEL_REQUESTER,
    parts: false,
  });
  json(res, r.status, r.body);
}

/** Who the arbiter records for a change made in Settings › Prompt filters. */
export const SETTINGS_REQUESTER = "settings";

/** The validator's lines without the file position or the edit's index. */
function settingsProblems(problems: readonly string[]): string[] {
  return problems.map((p) => p.replace(/^edits\[\d+\] \([a-z-]+\): /, "").replace(/^prompt_filters\.[A-Za-z0-9_.[\]-]*: /, ""));
}

/** POST /api/policy/prompt-filters/change {edit, expected?}: Settings ›
 *  Prompt filters (plan 15 §13.7). The SAME typed edit and write path as the
 *  panel's change route, narrowed to the four ops the product page offers
 *  (an action per kind, going back to the default, an exception added or
 *  removed): a switch, a pack or a plugin is the developer view's. Behind
 *  the global mutating gate (CSRF header + admin session). */
export async function postPromptSettingsChange(arbiter: (PromptFiltersArbiter & PolicyAssistantArbiter) | undefined, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter) return json(res, 404, { error: "The protection service is not connected." });
  if (!canEdit(arbiter)) return json(res, 501, { error: READ_ONLY_SETTINGS });
  const body = (await readJson(req).catch(() => null)) as Record<string, unknown> | null;
  const r = await applyPromptEdit(arbiter, body, {
    ops: SETTINGS_PROMPT_OPS,
    reason: (op) => `Changed in Settings › Prompt filters (${op})`,
    requestedBy: SETTINGS_REQUESTER,
    parts: true,
  });
  if (r.status === 422 && Array.isArray(r.body["problems"])) r.body["problems"] = settingsProblems(r.body["problems"] as string[]);
  if (r.status === 501) r.body["error"] = READ_ONLY_SETTINGS;
  json(res, r.status, r.body);
}

/** GET /api/prompt-filters/packs: every pack in full (human plane). */
export async function getPromptPacks(arbiter: PromptFiltersArbiter | undefined, res: ServerResponse): Promise<void> {
  if (!arbiter) return noArbiter(res);
  if (!arbiter.promptFilterPacks) return json(res, 501, { error: "this arbiter has no pack listing (plan 15 phase 2)" });
  try {
    json(res, 200, await arbiter.promptFilterPacks());
  } catch (err) {
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `promptFilterPacks failed: ${(err as Error).message}` });
  }
}

/** POST /api/prompt-filters/pack-edit: typed edits to the person's own pack (admin channel). */
export async function postPromptPackEdit(arbiter: PromptFiltersArbiter | undefined, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter) return noArbiter(res);
  if (!arbiter.promptPackEdit) return json(res, 501, { error: "this arbiter has no pack editor (plan 15 phase 2)" });
  const body = (await readJson(req).catch(() => null)) as { edits?: unknown; dryRun?: unknown; sample?: unknown } | null;
  const edits = body?.edits;
  if (!Array.isArray(edits) || edits.length === 0 || edits.length > 50) return json(res, 400, { error: "edits must be a list of 1 to 50 pack edits" });
  if (!edits.every((e) => e && typeof e === "object" && PACK_EDIT_OPS.includes(String((e as { op?: unknown }).op)))) {
    return json(res, 400, { error: `each edit's op must be one of ${PACK_EDIT_OPS.join(", ")}` });
  }
  const sample = typeof body?.sample === "string" ? body.sample : "";
  if (sample.length > BENCH_MAX_CHARS) return json(res, 413, { error: `sample is longer than ${BENCH_MAX_CHARS} characters` });
  try {
    const r = await arbiter.promptPackEdit({ edits, dryRun: body?.dryRun === true, ...(sample ? { sample } : {}), requestedBy: PANEL_REQUESTER });
    json(res, r.ok ? 200 : 422, r);
  } catch (err) {
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `promptPackEdit failed: ${(err as Error).message}` });
  }
}


// ── Phase 3: ask and "let it through" (plan 15 §7, §13.6) ─────────────────────

const ANSWERS: readonly PromptHoldAnswer[] = ["send", "mask", "cancel"];

/** The arbiter's refusal of a session answer under a locked administrator's
 *  `ask` row (its words: holds.ts ONCE_ONLY_PHRASE). */
export function isOnceOnlyRefusal(msg: string): boolean {
  return /answer it for this message only/.test(msg);
}
const APPROVAL_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** GET /api/prompt-filters/holds: the held prompts with their found text
 *  (human plane; the server gates it like the packs GET). */
export async function getPromptHolds(arbiter: PromptFiltersArbiter | undefined, res: ServerResponse): Promise<void> {
  if (!arbiter) return noArbiter(res);
  if (!arbiter.promptHolds) return json(res, 501, { error: "this arbiter cannot hold a prompt (plan 15 phase 3)" });
  try {
    const w = await arbiter.promptHolds();
    json(res, 200, {
      timeoutMs: typeof w.timeoutMs === "number" ? w.timeoutMs : 0,
      holds: (Array.isArray(w.holds) ? w.holds : []).map((h) => ({
        approvalId: str(h.approvalId), session: str(h.session), category: str(h.category),
        filterId: typeof h.filterId === "string" ? h.filterId : null,
        span: typeof h.span === "string" ? h.span : null,
        fallback: h.fallback === "mask" || h.fallback === "redact" ? h.fallback : null,
        firstSeen: Number(h.firstSeen) || 0, lastSeen: Number(h.lastSeen) || 0,
        timeoutMs: Number(h.timeoutMs) || 0,
        onceOnly: h.onceOnly === true,
      })),
    });
  } catch (err) {
    json(res, isAdminBoundaryError(err) ? 503 : 502, { error: `promptHolds failed: ${(err as Error).message}` });
  }
}

/** POST /api/prompt-filters/holds/answer {approvalId, answer, scope}: the
 *  human's answer to a held prompt (ADMIN channel). */
export async function postPromptHoldAnswer(arbiter: PromptFiltersArbiter | undefined, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter) return noArbiter(res);
  if (!arbiter.resolvePromptHold) return json(res, 501, { error: "this arbiter cannot hold a prompt (plan 15 phase 3)" });
  const body = (await readJson(req).catch(() => null)) as { approvalId?: unknown; answer?: unknown; scope?: unknown } | null;
  const approvalId = typeof body?.approvalId === "string" ? body.approvalId : "";
  const answer = body?.answer;
  const scope = body?.scope === undefined ? "once" : body.scope;
  if (!APPROVAL_ID_RE.test(approvalId)) return json(res, 400, { error: "approvalId is required" });
  if (typeof answer !== "string" || !(ANSWERS as readonly string[]).includes(answer)) return json(res, 400, { error: `answer must be one of ${ANSWERS.join(", ")}` });
  if (scope !== "once" && scope !== "session") return json(res, 400, { error: "scope must be once or session" });
  try {
    const r = await arbiter.resolvePromptHold({ approvalId, answer: answer as PromptHoldAnswer, scope });
    json(res, 200, { approval: r.approval, answer, scope });
  } catch (err) {
    // A session answer under a locked administrator's `ask` row: the
    // arbiter refuses it (409, its reason); anything else it rejects is an
    // unknown hold (404).
    const msg = String((err as Error)?.message ?? err);
    json(res, isAdminBoundaryError(err) ? 503 : isOnceOnlyRefusal(msg) ? 409 : 404, { error: msg, approvalId });
  }
}

/** The let-through a session's own finding allows, or why not. Pure: the
 *  route reads the events, this decides (only a proxy-recorded finding with
 *  an opaque reference and an enforced action, on the human's own text). */
export function letThroughPlan(
  events: readonly ManduEvent[],
  eventId: string,
  index: number,
  scope: PromptVerdictScope,
): { ok: true; category: string; ref: string; turn?: string } | { ok: false; status: number; error: string } {
  const e = events.find((x) => x.id === eventId);
  if (!e || e.claimed === true) return { ok: false, status: 404, error: "no prompt filter finding of this session has that id" };
  const d = detailOf(e);
  const f = d && Array.isArray(d.findings) ? d.findings[index] : undefined;
  if (!d || !f) return { ok: false, status: 404, error: "no prompt filter finding of this session has that id" };
  if (d.origin !== "human") return { ok: false, status: 409, error: "only a finding in the human's own text can be let through" };
  if (typeof f.ref !== "string" || !REF_RE.test(f.ref) || !LETTABLE.has(str(f.action)) || str(f.category).startsWith("secret.registered")) {
    return { ok: false, status: 409, error: "this finding cannot be let through (a registered secret, or nothing was hidden)" };
  }
  if (scope === "once" && !(typeof d.turn === "string" && REF_RE.test(d.turn))) return { ok: false, status: 409, error: "this finding's message cannot be named; let it through for the session instead" };
  return { ok: true, category: str(f.category), ref: f.ref, ...(scope === "once" ? { turn: d.turn as string } : {}) };
}

/** POST /api/prompt-filters/let-through {session, eventId, index, scope}. */
export async function postPromptLetThrough(arbiter: PromptFiltersArbiter | undefined, source: EventSource, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!arbiter) return noArbiter(res);
  if (!arbiter.letPromptFindingThrough) return json(res, 501, { error: "this arbiter cannot let a finding through (plan 15 phase 3)" });
  const body = (await readJson(req).catch(() => null)) as { session?: unknown; eventId?: unknown; index?: unknown; scope?: unknown } | null;
  const session = typeof body?.session === "string" ? body.session : "";
  const eventId = typeof body?.eventId === "string" ? body.eventId : "";
  const index = typeof body?.index === "number" && Number.isInteger(body.index) && body.index >= 0 ? body.index : -1;
  const scope = body?.scope;
  if (!session || !eventId || index < 0) return json(res, 400, { error: "session, eventId and index are required" });
  if (scope !== "once" && scope !== "session") return json(res, 400, { error: "scope must be once or session" });
  let events: ManduEvent[];
  try {
    events = await source.readEvents(session);
  } catch (err) {
    return json(res, 502, { error: `could not read the session's events: ${(err as Error).message}` });
  }
  const plan = letThroughPlan(events, eventId, index, scope);
  if (!plan.ok) return json(res, plan.status, { error: plan.error });
  try {
    const r = await arbiter.letPromptFindingThrough({ session, category: plan.category, ref: plan.ref, ...(plan.turn ? { turn: plan.turn } : {}), scope });
    json(res, 200, { approval: r.approval, scope });
  } catch (err) {
    // A session let-through under a locked administrator's `ask` row is a
    // 409 with the arbiter's reason, as on the hold's routes (plan 15 §12,
    // 2026-10-04); the arbiter decides, not the event's `onceOnly`.
    const msg = String((err as Error)?.message ?? err);
    json(res, isAdminBoundaryError(err) ? 503 : isOnceOnlyRefusal(msg) ? 409 : 422, { error: msg });
  }
}
