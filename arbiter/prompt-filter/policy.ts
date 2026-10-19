/**
 * policy — the prompt filter's switches in policy.yaml (`prompt_filters:`,
 * confidentiality-plan-15-prompt-filter.md §6, phase 2). Mandu-new (no
 * reference origin).
 *
 *   prompt_filters:
 *     filters:                       # filter id → on | off | { on, on_error }
 *       registered-value: on         # the default; off is a relaxation
 *       key-shapes: on
 *       acme-dlp: { on: true, on_error: pass }   # a pack, by its `pack:` id
 *       acme-classifier: { on: true, endpoint: ollama-local }   # a plugin pack
 *                                    # whose classifier needs a model (§5)
 *     actions:                       # category (prefix, longest wins) → action
 *       secret.registered: mask      # the default
 *       secret.shape: redact
 *       pii.payment-card: block
 *     exceptions:
 *       - { category: pii.email, match: "*@example.com" }
 *     signed_only: false
 *
 * A filter only detects; this maps what it found to an action. The defaults
 * (decisions 1-3 of §2): `registered-value` on and `secret.registered: mask`;
 * every other filter off; a category no row names is `redact`. `mask` for a
 * non-registered category is the person's opt-in: it stores the found value.
 *
 * THE ADMINISTRATOR'S LAYER. A file in /etc/mandu/policy.d/ may set
 * `prompt_filters:` too, with `locked: true` on a filter or an action row.
 * Its rows are defaults the person may change; a LOCKED row holds: the
 * effective value is the stricter of the two (`effectivePromptConfig`), a
 * person's row under a locked prefix cannot weaken it, an exception on a
 * locked category does not apply, and a write that adds such a conflict is
 * refused (`promptLockProblems`, run by the validator's `layerProblems`).
 *
 * THE MONOTONIC SPLIT (`comparePromptFilters`, the `prompt-filters` facet of
 * policy-delta.ts). Turning a filter on, a stronger action (`pass` < `log` <
 * `redact` < `mask` < `ask` < `block`), `on_error: block`, a removed
 * exception and `signed_only: false` are tightenings; their opposites are
 * relaxations, only the human's. Phase 2 refused `ask`; phase 3 enacts it
 * (the Inbox hold, holds.ts). `endpoint` is the classifier plugins'.
 *
 * `ask` ranks between `mask` and `block`: its default (no answer within the
 * hold's deadline, or a request that cannot wait) is `mask`, and only the
 * human, answering in the Inbox, can let the span through as written. So an
 * action raised to `ask` is a tightening the agent may make, and the human's
 * answer is the relaxation, on the human plane.
 *
 * THE CLASSIFIER'S ENDPOINT (phase 3, §5, §12 2026-10-03). `endpoint:` names
 * the `models:` entry a plugin that needs a model sends the prompt to. It
 * must be a `local: true` entry (on this machine or inside the perimeter)
 * whose model is not cloud-backed: checked at validation
 * (`checkPromptEndpoints`, against the effective models) and again at every
 * spawn (`resolveLocalEndpoint`, plugin-filter.ts). Setting, changing or
 * removing it is a RELAXATION (only the human's): it chooses where the raw
 * prompt goes. A locked administrator's endpoint holds.
 */
import { createHash } from "node:crypto";

import { ACTION_RANK, type PromptAction } from "./filter.js";

/** The built-in filters (§4.1). */
export const REGISTERED_VALUE_ID = "registered-value";
export const KEY_SHAPES_ID = "key-shapes";
export const BUILTIN_FILTER_IDS: readonly string[] = [REGISTERED_VALUE_ID, KEY_SHAPES_ID];

/** The default action of a category no row names (decision 3). */
export const FALLBACK_ACTION: PromptAction = "redact";
/** The built-in rows (decision 2). */
export const DEFAULT_ACTION_ROWS: ReadonlyArray<{ category: string; action: PromptAction }> = [
  { category: "secret.registered", action: "mask" },
];
/** Built-in filters on by default. */
const DEFAULT_ON: ReadonlySet<string> = new Set([REGISTERED_VALUE_ID]);

/** The actions a policy may name (`ask` since phase 3). */
export const POLICY_ACTIONS: readonly PromptAction[] = ["pass", "log", "redact", "mask", "ask", "block"];

/** A filter or pack id. */
export const FILTER_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
/** A dotted category: `secret.shape.github-token`, `pii.email`. */
export const CATEGORY_RE = /^[a-z0-9][a-z0-9_-]{0,63}(?:\.[a-z0-9][a-z0-9_-]{0,63}){0,7}$/;
/** A classifier's `endpoint:`: a `models:` entry's name. */
export const ENDPOINT_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** An exception's glob (`*`, `?`), matched against the found span. */
export const MAX_EXCEPTION_MATCH = 256;

/** What a DATA-socket policy read shows in place of an exception's pattern
 *  (policy/prompt-pattern-redact.ts; plan 15 §13.7 item 4). Refused as a
 *  pattern, so a document or an edit built from such a read can never
 *  overwrite a stored pattern with it. */
export const PROMPT_PATTERN_PLACEHOLDER = "<pattern hidden: read it on the human plane>";

export type OnError = "block" | "pass";

/** One `filters:` entry as written. */
export type FilterSwitchConfig = "on" | "off" | boolean | { on?: boolean; on_error?: OnError; endpoint?: string; locked?: boolean };
/** One `actions:` entry as written. */
export type ActionRowConfig = PromptAction | { action: PromptAction; locked?: boolean };

export interface PromptFiltersConfig {
  filters?: Record<string, FilterSwitchConfig>;
  actions?: Record<string, ActionRowConfig>;
  exceptions?: Array<{ category: string; match: string }>;
  signed_only?: boolean;
}

/** Who set an effective value (§8.1). */
export type SetBy = "default" | "you" | "administrator";

export interface EffectiveFilter {
  id: string;
  on: boolean;
  /** Absent: the §4.4 default (block when any of its categories enforces). */
  onError?: OnError;
  /** The `models:` entry a classifier plugin sends the prompt to (§5). */
  endpoint?: string;
  setBy: SetBy;
  locked: boolean;
  /** The administrator's file that set or locked it. */
  file?: string;
}

export interface EffectiveActionRow {
  category: string;
  action: PromptAction;
  setBy: SetBy;
  locked: boolean;
  file?: string;
}

export interface EffectiveException {
  category: string;
  match: string;
  setBy: SetBy;
  file?: string;
  /** False when a locked administrator's row covers its category. */
  inForce: boolean;
}

export interface EffectivePromptConfig {
  filters: Map<string, EffectiveFilter>;
  rows: EffectiveActionRow[];
  exceptions: EffectiveException[];
  signedOnly: boolean;
}

/** One administrator's file's `prompt_filters:` (admin-layer.ts). */
export interface AdminPromptFilters {
  readonly file: string;
  readonly config: PromptFiltersConfig;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

const rank = (a: PromptAction): number => ACTION_RANK[a];
const stricterAction = (a: PromptAction, b: PromptAction): PromptAction => (rank(b) > rank(a) ? b : a);

/** Does `prefix` cover `category` (equal, or a dotted parent)? */
export function coversCategory(prefix: string, category: string): boolean {
  return category === prefix || category.startsWith(`${prefix}.`);
}

// ── validation ───────────────────────────────────────────────────────────────

/**
 * Check one `prompt_filters:` value; problems in the validator's style.
 * `admin`: the administrator's layer, where `locked` is allowed and
 * `signed_only` is not (it chooses which of the PERSON's packs count).
 */
export function checkPromptFilters(v: unknown, at: string, out: string[], opts: { admin?: boolean } = {}): void {
  if (!isPlainObject(v)) {
    out.push(`${at}: must be a mapping (filters, actions, exceptions, signed_only)`);
    return;
  }
  const keys = opts.admin ? ["filters", "actions", "exceptions"] : ["filters", "actions", "exceptions", "signed_only"];
  for (const k of Object.keys(v)) {
    if (!keys.includes(k)) out.push(`${at}.${k}: unknown key (allowed: ${keys.join(", ")})`);
  }
  if ("filters" in v) {
    if (!isPlainObject(v.filters)) out.push(`${at}.filters: must be a mapping of filter id → on | off | { on, on_error }`);
    else for (const [id, s] of Object.entries(v.filters)) checkFilterSwitch(id, s, `${at}.filters.${id}`, out, opts);
  }
  if ("actions" in v) {
    if (!isPlainObject(v.actions)) out.push(`${at}.actions: must be a mapping of category → action`);
    else for (const [cat, a] of Object.entries(v.actions)) checkActionRow(cat, a, `${at}.actions.${cat}`, out, opts);
  }
  if ("exceptions" in v) {
    if (!Array.isArray(v.exceptions)) out.push(`${at}.exceptions: must be a list of { category, match }`);
    else {
      const seen = new Set<string>();
      (v.exceptions as unknown[]).forEach((e, i) => {
        const here = `${at}.exceptions[${i}]`;
        if (!isPlainObject(e)) { out.push(`${here}: must be a mapping { category, match }`); return; }
        const extra = Object.keys(e).filter((k) => k !== "category" && k !== "match");
        if (extra.length > 0) out.push(`${here}: unknown key${extra.length > 1 ? "s" : ""} ${extra.map((k) => `'${k}'`).join(", ")} (allowed: category, match)`);
        if (typeof e.category !== "string" || !CATEGORY_RE.test(e.category)) out.push(`${here}.category: must be a dotted category such as pii.email`);
        if (typeof e.match !== "string" || e.match.trim() === "" || e.match.length > MAX_EXCEPTION_MATCH || /[\r\n]/.test(e.match)) {
          out.push(`${here}.match: must be a one-line pattern (* and ? are wildcards), at most ${MAX_EXCEPTION_MATCH} characters`);
        } else if (/^\*+$/.test(e.match.trim())) {
          out.push(`${here}.match: '${e.match}' would let every finding of ${String(e.category)} through; turn the action to pass instead`);
        } else if (e.match === PROMPT_PATTERN_PLACEHOLDER) {
          out.push(`${here}.match: this is the placeholder a data-socket read shows in place of a pattern, not a pattern; read the policy on the human plane (or the admin channel) to change an exception`);
        }
        const k = `${String(e.category)}\0${String(e.match)}`;
        if (seen.has(k)) out.push(`${here}: the same exception is listed twice`);
        seen.add(k);
      });
    }
  }
  if ("signed_only" in v && typeof v.signed_only !== "boolean") out.push(`${at}.signed_only: must be true or false`);
}

function checkFilterSwitch(id: string, s: unknown, at: string, out: string[], opts: { admin?: boolean }): void {
  if (!FILTER_ID_RE.test(id)) out.push(`${at}: a filter id is lowercase letters, digits, . _ - (a built-in or a pack's id)`);
  if (s === "on" || s === "off" || typeof s === "boolean") return;
  if (!isPlainObject(s)) {
    out.push(`${at}: must be on, off, or { on, on_error }`);
    return;
  }
  const allowed = opts.admin ? ["on", "on_error", "endpoint", "locked"] : ["on", "on_error", "endpoint"];
  for (const k of Object.keys(s)) {
    if (k === "locked" && !opts.admin) out.push(`${at}.locked: only your administrator's files can lock a filter`);
    else if (!allowed.includes(k)) out.push(`${at}.${k}: unknown key (allowed: ${allowed.join(", ")})`);
  }
  if ("on" in s && typeof s.on !== "boolean") out.push(`${at}.on: must be true or false`);
  if ("on_error" in s && s.on_error !== "block" && s.on_error !== "pass") out.push(`${at}.on_error: must be block or pass`);
  if ("locked" in s && typeof s.locked !== "boolean") out.push(`${at}.locked: must be true or false`);
  if ("endpoint" in s && (typeof s.endpoint !== "string" || !ENDPOINT_NAME_RE.test(s.endpoint))) {
    out.push(`${at}.endpoint: must name a models: entry (declared local: true)`);
  }
}

/** One `models:` entry as the endpoint check reads it. */
export interface EndpointModelEntry {
  name?: unknown;
  local?: unknown;
  model?: unknown;
}

/**
 * Each `endpoint:` of `prompt_filters.filters` must name a declared
 * `local: true` model entry whose model is not cloud-backed (§5: a
 * classifier reads the raw prompt). `models`: the EFFECTIVE entries (the
 * administrator's and the person's). Pure.
 */
export function checkPromptEndpoints(v: unknown, models: readonly EndpointModelEntry[], at: string, out: string[], isCloudBacked: (model: string) => boolean): void {
  if (!isPlainObject(v) || !isPlainObject(v.filters)) return;
  for (const [id, s] of Object.entries(v.filters)) {
    if (!isPlainObject(s) || typeof s.endpoint !== "string" || !ENDPOINT_NAME_RE.test(s.endpoint)) continue;
    const here = `${at}.filters.${id}.endpoint`;
    const e = models.find((m) => m.name === s.endpoint);
    if (!e) out.push(`${here}: no model named '${s.endpoint}' is declared in models:`);
    else if (e.local !== true) out.push(`${here}: '${s.endpoint}' is not declared local: true; a classifier reads your raw prompt, so it may only use your own model or one inside your organization's perimeter`);
    else if (typeof e.model === "string" && isCloudBacked(e.model)) out.push(`${here}: '${s.endpoint}' names a cloud-backed model (${e.model}); its server sends prompts off this computer`);
  }
}

function checkAction(a: unknown, at: string, out: string[]): void {
  if (typeof a !== "string" || !(POLICY_ACTIONS as readonly string[]).includes(a)) out.push(`${at}: must be one of ${POLICY_ACTIONS.join(", ")}`);
}

function checkActionRow(cat: string, a: unknown, at: string, out: string[], opts: { admin?: boolean }): void {
  if (!CATEGORY_RE.test(cat)) out.push(`${at}: a category is dotted lowercase words such as pii.email`);
  if (isPlainObject(a)) {
    const allowed = opts.admin ? ["action", "locked"] : ["action"];
    for (const k of Object.keys(a)) {
      if (k === "locked" && !opts.admin) out.push(`${at}.locked: only your administrator's files can lock an action`);
      else if (!allowed.includes(k)) out.push(`${at}.${k}: unknown key (allowed: ${allowed.join(", ")})`);
    }
    checkAction(a.action, `${at}.action`, out);
    if ("locked" in a && typeof a.locked !== "boolean") out.push(`${at}.locked: must be true or false`);
    return;
  }
  checkAction(a, at, out);
}

// ── reading one config ───────────────────────────────────────────────────────

function readSwitch(s: unknown): { on: boolean; onError?: OnError; endpoint?: string; locked: boolean } | null {
  if (s === "on" || s === true) return { on: true, locked: false };
  if (s === "off" || s === false) return { on: false, locked: false };
  if (!isPlainObject(s)) return null;
  return {
    on: s.on !== false,
    ...(s.on_error === "block" || s.on_error === "pass" ? { onError: s.on_error } : {}),
    ...(typeof s.endpoint === "string" && ENDPOINT_NAME_RE.test(s.endpoint) ? { endpoint: s.endpoint } : {}),
    locked: s.locked === true,
  };
}

function readRow(a: unknown): { action: PromptAction; locked: boolean } | null {
  const v = isPlainObject(a) ? a.action : a;
  if (typeof v !== "string" || !(POLICY_ACTIONS as readonly string[]).includes(v)) return null;
  return { action: v as PromptAction, locked: isPlainObject(a) && a.locked === true };
}

/** Is `next` a weakening of `prev` (a filter switch)? A different
 *  classifier endpoint is one (it moves the raw prompt elsewhere). */
function weakerSwitch(next: { on: boolean; onError?: OnError; endpoint?: string }, prev: { on: boolean; onError?: OnError; endpoint?: string }): boolean {
  if (prev.on && !next.on) return true;
  if (prev.endpoint !== undefined && next.endpoint !== undefined && next.endpoint !== prev.endpoint) return true;
  return prev.onError === "block" && next.onError === "pass";
}

/**
 * The prompt filter configuration in force: the built-in defaults, then the
 * administrator's rows, then the person's, with every LOCKED administrator's
 * value holding against a weaker one of the person's. Pure.
 */
export function effectivePromptConfig(user: unknown, admin: readonly AdminPromptFilters[] = []): EffectivePromptConfig {
  const filters = new Map<string, EffectiveFilter>();
  for (const id of BUILTIN_FILTER_IDS) filters.set(id, { id, on: DEFAULT_ON.has(id), setBy: "default", locked: false });
  const rows = new Map<string, EffectiveActionRow>();
  for (const r of DEFAULT_ACTION_ROWS) rows.set(r.category, { ...r, setBy: "default", locked: false });
  const exceptions: EffectiveException[] = [];

  for (const a of admin) {
    const c = a.config;
    for (const [id, s] of Object.entries(isPlainObject(c.filters) ? c.filters : {})) {
      const r = readSwitch(s);
      if (!r || !FILTER_ID_RE.test(id)) continue;
      filters.set(id, { id, on: r.on, ...(r.onError ? { onError: r.onError } : {}), ...(r.endpoint ? { endpoint: r.endpoint } : {}), setBy: "administrator", locked: r.locked, file: a.file });
    }
    for (const [cat, v] of Object.entries(isPlainObject(c.actions) ? c.actions : {})) {
      const r = readRow(v);
      if (!r || !CATEGORY_RE.test(cat)) continue;
      rows.set(cat, { category: cat, action: r.action, setBy: "administrator", locked: r.locked, file: a.file });
    }
    for (const e of Array.isArray(c.exceptions) ? c.exceptions : []) {
      if (isPlainObject(e) && typeof e.category === "string" && typeof e.match === "string") {
        exceptions.push({ category: e.category, match: e.match, setBy: "administrator", file: a.file, inForce: true });
      }
    }
  }

  const u = isPlainObject(user) ? user as PromptFiltersConfig : {};
  for (const [id, s] of Object.entries(isPlainObject(u.filters) ? u.filters : {})) {
    const r = readSwitch(s);
    if (!r || !FILTER_ID_RE.test(id)) continue;
    const prev = filters.get(id);
    if (prev && prev.locked) {
      // A locked administrator's switch holds against a weaker one; a
      // stronger one of the person's (on_error: block) is kept. A locked
      // endpoint holds; the person's names one only where it set none.
      const onError = prev.onError === "block" || r.onError === "block" ? "block" : (prev.onError ?? r.onError);
      const endpoint = prev.endpoint ?? r.endpoint;
      filters.set(id, { ...prev, on: prev.on || r.on, ...(onError ? { onError } : {}), ...(endpoint ? { endpoint } : {}) });
      continue;
    }
    // An unlocked administrator's endpoint is a default the person's switch
    // keeps unless it names its own.
    const endpoint = r.endpoint ?? prev?.endpoint;
    filters.set(id, { id, on: r.on, ...(r.onError ? { onError: r.onError } : {}), ...(endpoint ? { endpoint } : {}), setBy: "you", locked: false });
  }
  for (const [cat, v] of Object.entries(isPlainObject(u.actions) ? u.actions : {})) {
    const r = readRow(v);
    if (!r || !CATEGORY_RE.test(cat)) continue;
    const prev = rows.get(cat);
    if (prev && prev.locked && rank(r.action) < rank(prev.action)) continue;
    rows.set(cat, { category: cat, action: prev && prev.locked ? stricterAction(prev.action, r.action) : r.action, setBy: "you", locked: prev?.locked === true, ...(prev?.locked && prev.file ? { file: prev.file } : {}) });
  }
  const lockedRows = [...rows.values()].filter((r) => r.locked && r.setBy !== "default");
  for (const e of Array.isArray(u.exceptions) ? u.exceptions : []) {
    if (!isPlainObject(e) || typeof e.category !== "string" || typeof e.match !== "string") continue;
    const locked = lockedRows.some((r) => coversCategory(r.category, e.category) || coversCategory(e.category, r.category));
    exceptions.push({ category: e.category, match: e.match, setBy: "you", inForce: !locked });
  }
  return {
    filters,
    rows: [...rows.values()].sort((a, b) => a.category.localeCompare(b.category)),
    exceptions,
    signedOnly: u.signed_only === true,
  };
}

/** The action a category gets: the longest prefix row, else the fallback;
 *  never below a LOCKED administrator's row that covers it. Pure. */
export function resolveAction(cfg: Pick<EffectivePromptConfig, "rows">, category: string): PromptAction {
  let best: EffectiveActionRow | null = null;
  let floor: PromptAction = "pass";
  for (const r of cfg.rows) {
    if (!coversCategory(r.category, category)) continue;
    if (best === null || r.category.length > best.category.length) best = r;
    if (r.locked && r.setBy !== "default") floor = stricterAction(floor, r.action);
  }
  return stricterAction(best?.action ?? FALLBACK_ACTION, floor);
}

/** The strictest action a LOCKED administrator's row that covers `category`
 *  sets, or null when none does (§7: "a locked administrator rule cannot be
 *  overridden"; the Inbox's per-finding "let it through" is refused under
 *  one, except under a locked `ask`, whose whole point is the human's
 *  answer). Pure. */
export function lockedAction(cfg: Pick<EffectivePromptConfig, "rows">, category: string): { action: PromptAction; file?: string } | null {
  let out: { action: PromptAction; file?: string } | null = null;
  for (const r of cfg.rows) {
    if (!r.locked || r.setBy === "default" || !coversCategory(r.category, category)) continue;
    if (out === null || rank(r.action) > rank(out.action)) out = { action: r.action, ...(r.file ? { file: r.file } : {}) };
  }
  return out;
}

/** The locked administrator's `ask` row covering `category`, if ANY of the
 *  rows that cover it is one (plan 15 §12, 2026-10-04): the human answers its
 *  hold for THIS MESSAGE only, never for the session, so the administrator's
 *  rule asks again on the next message. Any such row counts, even when a
 *  stricter row also covers the category (which then decides the action).
 *  Pure. */
export function lockedAsk(cfg: Pick<EffectivePromptConfig, "rows">, category: string): { file?: string } | null {
  for (const r of cfg.rows) {
    if (r.locked && r.setBy !== "default" && r.action === "ask" && coversCategory(r.category, category)) return r.file ? { file: r.file } : {};
  }
  return null;
}

/** A glob (`*`, `?`, everything else literal) as an anchored, case-insensitive RegExp. */
export function globRegExp(glob: string): RegExp {
  const body = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${body}$`, "is");
}

/** The digest of the configuration in force (part of the cache key, §3.3). */
export function promptConfigDigest(cfg: EffectivePromptConfig, extra: unknown = null): string {
  const canon = {
    filters: [...cfg.filters.values()].sort((a, b) => a.id.localeCompare(b.id)).map((f) => [f.id, f.on, f.onError ?? null, ...(f.endpoint ? [f.endpoint] : [])]),
    rows: cfg.rows.map((r) => [r.category, r.action, r.locked]),
    exceptions: cfg.exceptions.filter((e) => e.inForce).map((e) => [e.category, e.match]).sort(),
    signedOnly: cfg.signedOnly,
    extra,
  };
  return createHash("sha256").update(JSON.stringify(canon)).digest("hex").slice(0, 16);
}

// ── the administrator's lock ─────────────────────────────────────────────────

/**
 * The person's entries a LOCKED administrator's row keeps out of force, in
 * the validator's style ("set by your administrator (<file>)"). Pure.
 */
export function promptLockProblems(user: unknown, admin: readonly AdminPromptFilters[]): string[] {
  if (!isPlainObject(user) || admin.length === 0) return [];
  const out: string[] = [];
  const base = effectivePromptConfig(null, admin);
  const u = user as PromptFiltersConfig;
  const where = (file: string | undefined): string => `set by your administrator (${file ?? "/etc/mandu/policy.d"})`;
  for (const [id, s] of Object.entries(isPlainObject(u.filters) ? u.filters : {})) {
    const r = readSwitch(s);
    const a = base.filters.get(id);
    if (r && a && a.locked && weakerSwitch(r, a)) {
      out.push(`prompt_filters.filters.${id}: ${where(a.file)} as ${a.on ? "on" : "off"}${a.onError ? ` with on_error: ${a.onError}` : ""}${a.endpoint ? ` and endpoint: ${a.endpoint}` : ""}; it cannot be relaxed here`);
    }
  }
  for (const [cat, v] of Object.entries(isPlainObject(u.actions) ? u.actions : {})) {
    const r = readRow(v);
    if (!r) continue;
    for (const a of base.rows) {
      if (!a.locked || a.setBy !== "administrator" || !coversCategory(a.category, cat)) continue;
      if (rank(r.action) < rank(a.action)) {
        out.push(`prompt_filters.actions.${cat}: ${a.category} is ${where(a.file)} as ${a.action}; ${r.action} would relax it`);
      }
    }
  }
  (Array.isArray(u.exceptions) ? u.exceptions : []).forEach((e, i) => {
    if (!isPlainObject(e) || typeof e.category !== "string") return;
    const a = base.rows.find((r) => r.locked && r.setBy === "administrator" && (coversCategory(r.category, e.category) || coversCategory(e.category, r.category)));
    if (a) out.push(`prompt_filters.exceptions[${i}]: ${a.category} is ${where(a.file)}; an exception cannot let its findings through`);
  });
  return out;
}

// ── the monotonic split (policy-delta.ts facet `prompt-filters`) ────────────

export interface PromptDeltaChange {
  direction: "relax" | "tighten";
  subject: string;
  detail: string;
}

/**
 * Compare two `prompt_filters:` values (the person's, before and after; the
 * same administrator's layer on both sides). Fail closed: a change this
 * function cannot classify is a relaxation. Pure.
 */
export function comparePromptFilters(before: unknown, after: unknown, admin: readonly AdminPromptFilters[] = []): PromptDeltaChange[] {
  const out: PromptDeltaChange[] = [];
  if (JSON.stringify(before ?? null) === JSON.stringify(after ?? null)) return out;
  for (const [side, v] of [["before", before], ["after", after]] as const) {
    if (v !== undefined && v !== null && !isPlainObject(v)) {
      out.push({ direction: "relax", subject: "prompt_filters", detail: `prompt_filters is not a mapping ${side} the change; it cannot be compared` });
      return out;
    }
  }
  const b = effectivePromptConfig(before, admin);
  const a = effectivePromptConfig(after, admin);
  // Filters.
  for (const id of new Set([...b.filters.keys(), ...a.filters.keys()])) {
    const fb = b.filters.get(id) ?? { id, on: false, setBy: "default" as const, locked: false };
    const fa = a.filters.get(id) ?? { id, on: false, setBy: "default" as const, locked: false };
    if (fb.on !== fa.on) {
      out.push({ direction: fa.on ? "tighten" : "relax", subject: `prompt filter ${id}`, detail: fa.on ? `the prompt filter ${id} is turned on` : `the prompt filter ${id} is turned off` });
    }
    const eb = fb.onError ?? "default";
    const ea = fa.onError ?? "default";
    if (eb !== ea) {
      // `default` is block whenever the filter enforces anything, so only
      // an explicit `block` is proven stronger than it.
      const tighten = ea === "block";
      out.push({ direction: tighten ? "tighten" : "relax", subject: `prompt filter ${id}`, detail: `on_error of the prompt filter ${id}: ${eb} → ${ea}` });
    }
    // §12 (2026-10-03): the classifier's endpoint chooses where the raw
    // prompt goes; any change to it (set, changed, removed) is a relaxation.
    if ((fb.endpoint ?? null) !== (fa.endpoint ?? null)) {
      out.push({
        direction: "relax", subject: `prompt filter model ${id}`,
        detail: fa.endpoint
          ? `the prompt filter ${id} sends your prompts to the model ${fa.endpoint}${fb.endpoint ? ` (was ${fb.endpoint})` : ""}`
          : `the prompt filter ${id} no longer names a model (was ${fb.endpoint})`,
      });
    }
  }
  // Actions, compared as resolved on every category either side names.
  for (const cat of new Set([...b.rows.map((r) => r.category), ...a.rows.map((r) => r.category)])) {
    const xb = resolveAction(b, cat);
    const xa = resolveAction(a, cat);
    if (xb === xa) continue;
    out.push({ direction: rank(xa) > rank(xb) ? "tighten" : "relax", subject: `prompt category ${cat}`, detail: `findings of ${cat}: ${xb} → ${xa}` });
  }
  // Exceptions: one added lets findings through.
  const key = (e: EffectiveException): string => `${e.category}\0${e.match}`;
  const eb = new Set(b.exceptions.filter((e) => e.inForce && e.setBy === "you").map(key));
  const ea = new Set(a.exceptions.filter((e) => e.inForce && e.setBy === "you").map(key));
  for (const k of ea) if (!eb.has(k)) { const [c, m] = k.split("\0"); out.push({ direction: "relax", subject: `prompt exception ${c}`, detail: `findings of ${c} matching ${m} are let through` }); }
  for (const k of eb) if (!ea.has(k)) { const [c, m] = k.split("\0"); out.push({ direction: "tighten", subject: `prompt exception ${c}`, detail: `findings of ${c} matching ${m} are no longer let through` }); }
  if (b.signedOnly !== a.signedOnly) {
    out.push({ direction: a.signedOnly ? "relax" : "tighten", subject: "prompt_filters.signed_only", detail: a.signedOnly ? "unsigned packs of yours are ignored" : "unsigned packs of yours count again" });
  }
  // Keys this module does not model (the validator refuses them): fail closed.
  for (const [side, v] of [["before", before], ["after", after]] as const) {
    if (!isPlainObject(v)) continue;
    for (const k of Object.keys(v)) {
      if (!["filters", "actions", "exceptions", "signed_only"].includes(k)) {
        out.push({ direction: "relax", subject: `prompt_filters.${k}`, detail: `prompt_filters.${k} (${side}) has no tightening proof` });
      }
    }
  }
  return out;
}
