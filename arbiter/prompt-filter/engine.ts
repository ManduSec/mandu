/**
 * engine — the arbiter's `filterPrompt` op (confidentiality-plan-15-prompt-filter.md
 * §3.2, §3.3, §4, §6, §7). Mandu-new (no reference origin).
 *
 * The proxies cut each request's user-role text into segments tagged by
 * origin (`human`, `harness`, `side-call`) and send them here; this runs the
 * filters, applies the policy and answers per segment: `pass`, `rewrite`
 * with the text the model may read, or `block` with a reason. The proxies
 * hold no filter logic and no policy.
 *
 * WHICH FILTERS RUN WHERE (§3.1, as built in §13.3).
 *   - `human` segments: every filter the policy turns on (policy.ts:
 *     `registered-value` on by default, `key-shapes` and each pack off by
 *     default), each finding mapped to its category's action, the person's
 *     exceptions applied.
 *   - `harness` and `side-call` segments: the registered-value FLOOR, always
 *     `mask`, in `secrets` mode, whatever `prompt_filters:` says (ingress of
 *     data the human did not write), AND every other filter the policy
 *     turns on, because the human's own text reaches the model inside them
 *     (a title side call quotes the prompt; a token count carries the
 *     conversation without tools). There a `block` acts as `redact`: the
 *     finding never goes, and the harness's request is not refused for text
 *     the human did not send.
 * With the confidentiality axis OFF (modes `off` and the frozen `injection`)
 * every finding is `log`: reported, never enacted (§6 Modes).
 *
 * ACTIONS (§7). `log` reports; `redact` replaces the span with
 * `[redacted: <category>]` and stores nothing; `mask` replaces it with a
 * symbol (a registered value's own; otherwise one minted at the finding's
 * level, default `no-model`, which stores the value); `block` answers the
 * segment `block` with a reason and ALSO the text with every span applied
 * (a blocked span as `[blocked: <category>]`): the proxy refuses the request
 * the first time and may forward that safe text after the human was told
 * (the proxies' block handling). `ask` (phase 3) answers with the span's
 * DEFAULT applied (`mask` when a finding in it carries a level, else
 * `redact`: §7's "no answer within the deadline") and reports the finding as
 * `ask`; the Inbox hold, the human's answer and the per-finding "let it
 * through" are the server's layer over this answer (holds.ts), so the cache
 * keeps the scan and every request consults the verdicts afresh. On harness
 * and side-call text `ask` acts as `redact`, as `block` does: they are never
 * held.
 *
 * MERGING (§4). Overlapping findings are one span; the strictest action
 * wins (`block` > `ask` > `mask` > `redact` > `log` > `pass`). A span that is
 * exactly one registered value becomes that value's symbol (the strictest
 * row when two rows share the value); anything else masked is minted once
 * at the strictest level of what it covers. The rewritten text is scanned
 * again for registered values: one that survives (it would have to
 * straddle a replacement) takes the whole segment, fail-closed.
 *
 * FAILURE (§4.4). A filter that throws, or that the policy turns on but is
 * not available (a pack missing, refused, or unsigned under `signed_only`),
 * fails per its `on_error`: `block` (the default when any of its categories
 * maps to an enforcing action) answers the segment `block` with NO text, so
 * nothing of it can be forwarded; `pass` skips it. A failed mint throws: the
 * op answers an error and the proxy refuses the request.
 *
 * THE CACHE (§3.3). A segment's answer is cached per (hash of its text,
 * origin, axis, policy digest, packs digest, the registered-value set's
 * version), so each turn is scanned once while nothing it depends on
 * changes, and a minted symbol is the same on every resend.
 *
 * A HIGH SESSION'S OWN WRITE (§13.10, 2026-10-09). A registered file whose
 * bytes are exactly the content of a whole-content write this session's
 * model made (the model proxy's believed record), at a level the session's
 * watermark already holds, is not masked in this session's `human`
 * segments: every byte of it is in this session's transcript already (the
 * model's own `Write` input, re-sent as written), and the watermark
 * subsumes in-session derivation (confidentiality.md §8). The finding is
 * reported as `log`. Harness and
 * side-call text, and every other session, keep the mask. The exempt set is
 * the server's (`ownWrites`), read once per request; its signature joins the
 * cache key of the session's human segments, so no other session can ever
 * read an exempt answer from the cache.
 *
 * DRY RUN (§8.1). `dryRun` mints nothing (a span that would be minted shows
 * as `$MDU:<would-mint>`, a registered value as its existing symbol), reads
 * and writes no cache entry, and stores nothing. It is a HUMAN-PLANE request:
 * the server refuses it on the data socket (server.ts isHumanPlaneRequest).
 */

import { createHash } from "node:crypto";

import { confidentialityRank, type ConfidentialityLevel } from "../symbol-table/confidentiality.js";
import { ACTION_RANK, SEGMENT_ORIGINS, type Finding, type PromptAction, type PromptFilter, type ScanResult, type SegmentOrigin } from "./filter.js";
import {
  coversCategory,
  effectivePromptConfig,
  FALLBACK_ACTION,
  globRegExp,
  promptConfigDigest,
  resolveAction,
  type EffectivePromptConfig,
  type OnError,
  type SetBy,
} from "./policy.js";
import {
  PROMPT_FLOOR_MIN_ENTROPY,
  PROMPT_FLOOR_MIN_LEN,
  REGISTERED_VALUE_CATEGORY,
  REGISTERED_VALUE_FILTER_ID,
} from "./registered-value-filter.js";

/** What a plugin reads in place of each code unit of a registered value. */
export const SHIELD_CHAR = "\u2588";

/** What a dry run shows in place of a symbol it would mint. */
export const WOULD_MINT = "$MDU:<would-mint>";

/** Bounds on one request (a malformed request is refused whole). */
export const MAX_SEGMENTS = 4096;
export const MAX_SEGMENT_ID_LEN = 128;
const CACHE_CAP = 4096;

/** The marker a redacted span becomes (§7). */
export const redactedMarker = (category: string): string => `[redacted: ${category}]`;
/** The marker a blocked span becomes in a block answer's safe text. */
export const blockedMarker = (category: string): string => `[blocked: ${category}]`;

export interface PromptSegmentIn {
  id: string;
  origin: SegmentOrigin;
  text: string;
}

export interface PromptFindingOut {
  start: number;
  end: number;
  category: string;
  filterId: string;
  action: PromptAction;
  /** For `mask`: the symbol that replaced the span. */
  symbol?: string;
  /** `value`: one registered value; `line`: a line of one; `merged`:
   *  overlapping findings minted as one. */
  how?: "value" | "line" | "merged";
  /** The rule that found it (a pack's pattern id, `keyword`, a key shape). */
  rule?: string;
  /** Set by the hold layer (holds.ts), never by the engine: the span's
   *  opaque reference (a keyed hash; the Inbox's verdicts and "let it
   *  through" name it, never the span). */
  ref?: string;
  /** Set by the hold layer: a human verdict let this span through as
   *  written (`once`: this message; `session`: this session). */
  let?: "once" | "session";
  /** Set by the hold layer on an `ask` finding: where its hold stands. */
  hold?: PromptHoldState;
  /** Set by the hold layer next to `ref`: a locked administrator's `ask`
   *  row covers the category (`lockedAsk`, plan 15 §12, 2026-10-04), so a
   *  verdict for this span covers its message only; a session answer or a
   *  session "let it through" is refused. The proxies copy it into their
   *  `prompt_filter` events, and the dashboard offers no session answer. */
  onceOnly?: true;
}

/** Where an `ask` finding's hold stands (holds.ts). */
export interface PromptHoldState {
  /** `pending`: waiting for the human; `sent`: the human sent it as
   *  written; `masked`: the human chose the default; `cancelled`: the human
   *  cancelled the message; `timed-out`: no answer within the deadline, the
   *  default went; `default`: the default went with no hold (a request that
   *  cannot wait, the data socket, no session, a registered value inside, a
   *  segment that blocks anyway). */
  state: "pending" | "sent" | "masked" | "cancelled" | "timed-out" | "default";
  /** The Inbox row (absent for `default`). */
  approvalId?: string;
  /** Why `default` (no hold). */
  why?: string;
}

export interface PromptSegmentOut {
  id: string;
  origin: SegmentOrigin;
  action: "pass" | "rewrite" | "hold" | "block";
  /** For `rewrite`: the text with the spans replaced. For `block`: the same
   *  safe text with each blocked span as `[blocked: <category>]`, or absent
   *  when a filter could not run (nothing of the segment may go). */
  text?: string;
  reason?: string;
  /** `hold` (set by the hold layer): the Inbox row to wait on and the time
   *  left before the default applies. */
  hold?: { approvalId: string; timeoutMs: number };
  /** Set by the hold layer on a `human` segment with a finding it can
   *  reference: the message's opaque reference (a "let it through, once"
   *  names it); and on a noted message's later answer with none (holds.ts,
   *  noted messages). */
  turn?: string;
  findings: PromptFindingOut[];
  /** Registered values the prompt floor let through (`human` only). */
  skipped: number;
  /** True when this answer came from the cache (§3.3). */
  cached: boolean;
}

export interface FilterPromptOutcome {
  segments: PromptSegmentOut[];
  /** The confidentiality axis: false = every finding is `log`. */
  enforcing: boolean;
  dryRun: boolean;
  digest: { policy: string; packs: string; values: string };
}

/** One filter as the panel shows it (§8.1). */
export interface PromptFilterView {
  id: string;
  kind: "built-in" | "pack" | "plugin";
  /** A classifier plugin's `endpoint:` (§5). */
  endpoint?: string;
  on: boolean;
  /** Who set the switch: the default, you, or the administrator. */
  setBy: SetBy;
  locked: boolean;
  /** The administrator's file that set or locked it. */
  file?: string;
  /** The `on_error` in force, and whether a policy wrote it. */
  onError: OnError;
  onErrorSet: boolean;
  /** False when it is switched on but cannot run (see `problem`). */
  available: boolean;
  problem?: string;
  categories: Array<{ category: string; action: PromptAction }>;
  /** Origins it runs on, and the floor that applies there. */
  origins: Array<{ origin: SegmentOrigin; floor: string }>;
}

/** What the policy provider hands the engine on every request. */
export interface PromptPolicyInput {
  /** The configuration in force (policy.ts `effectivePromptConfig`). */
  config: EffectivePromptConfig;
  /** The pack filters that may run, by id. */
  packs: ReadonlyMap<string, PromptFilter>;
  /** Packs that exist but may not run, by id → why (refused, unsigned). */
  unavailable?: ReadonlyMap<string, string>;
  /** Digest over the usable packs (cache key). */
  packsDigest: string;
}

/** A session's own HIGH writes (§13.10): which registered rows its human
 *  text may carry unmasked, and a signature of that set (cache key). */
export interface SessionOwnWrites {
  signature: string;
  covers: (symbol: string) => boolean;
}

export interface PromptFilterEngineDeps {
  /** The built-in filters (the registered-value filter is required: it is
   *  also the harness and side-call floor). */
  filters: readonly PromptFilter[];
  /** The policy in force (absent: the built-in defaults, no packs). */
  policy?: () => PromptPolicyInput;
  /** The confidentiality axis (mode `secrets` or `full`). */
  enforcing: () => boolean;
  /** Mint a symbol for `value` at `level` (throws on failure: fail-closed). */
  mint: (value: string, level: ConfidentialityLevel, origin: SegmentOrigin, session: string | undefined) => string;
  /** The registered-value set's version and digest (the index's). */
  values: () => { version: number; digest: string };
  /** §13.10: the registered rows a session's own HIGH writes made, which its
   *  `human` segments may carry unmasked; null (or absent) = none. */
  ownWrites?: (session: string) => SessionOwnWrites | null;
}

const sha = (s: string): string => createHash("sha256").update(s).digest("hex");

/** No packs. */
const NO_PACKS_DIGEST = sha("").slice(0, 16);
const DEFAULT_POLICY: PromptPolicyInput = { config: effectivePromptConfig(null), packs: new Map(), packsDigest: NO_PACKS_DIGEST };

/** The floors the digest also covers (a change to them rescans). */
const FLOORS = { promptFloor: { minLen: PROMPT_FLOOR_MIN_LEN, minEntropy: PROMPT_FLOOR_MIN_ENTROPY }, harness: "registered-value:mask" };

/** Validate one request's segments; a string is the refusal. */
export function parseSegments(raw: unknown): PromptSegmentIn[] | string {
  if (!Array.isArray(raw)) return "segments must be an array";
  if (raw.length > MAX_SEGMENTS) return `at most ${MAX_SEGMENTS} segments`;
  const out: PromptSegmentIn[] = [];
  const ids = new Set<string>();
  for (const s of raw) {
    if (!s || typeof s !== "object") return "a segment is not an object";
    const { id, origin, text } = s as Record<string, unknown>;
    if (typeof id !== "string" || id === "" || id.length > MAX_SEGMENT_ID_LEN) return "a segment id must be a non-empty string";
    if (ids.has(id)) return `segment id ${id} repeats`;
    ids.add(id);
    if (typeof origin !== "string" || !(SEGMENT_ORIGINS as readonly string[]).includes(origin)) {
      return `segment ${id}: origin must be one of ${SEGMENT_ORIGINS.join(", ")}`;
    }
    if (typeof text !== "string") return `segment ${id}: text must be a string`;
    out.push({ id, origin: origin as SegmentOrigin, text });
  }
  return out;
}

type Tagged = Finding & { filterId: string; action: PromptAction };

/** A request's plugin answers, by filter id, then by `origin\0text`. */
type PreScans = Map<string, Map<string, ScanResult | Error>>;
const preKey = (origin: SegmentOrigin, text: string): string => `${origin}\0${text}`;

interface Cluster {
  start: number;
  end: number;
  members: Tagged[];
}

/** Overlapping findings → clusters (touching spans stay apart). */
function clusters(findings: Tagged[]): Cluster[] {
  const sorted = [...findings].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Cluster[] = [];
  for (const f of sorted) {
    const last = out[out.length - 1];
    if (last && f.start < last.end) {
      last.end = Math.max(last.end, f.end);
      last.members.push(f);
    } else {
      out.push({ start: f.start, end: f.end, members: [f] });
    }
  }
  return out;
}

const stricter = (a: ConfidentialityLevel, b: ConfidentialityLevel): ConfidentialityLevel =>
  confidentialityRank(b) > confidentialityRank(a) ? b : a;
const stricterAction = (a: PromptAction, b: PromptAction): PromptAction => (ACTION_RANK[b] > ACTION_RANK[a] ? b : a);
const ENFORCING: ReadonlySet<PromptAction> = new Set(["redact", "mask", "ask", "block"]);

/** One request's view of the policy, computed once per `run`. */
interface RunPolicy {
  input: PromptPolicyInput;
  digest: string;
  /** Filters on for `human` segments: [id, the filter or null when unavailable]. */
  human: Array<{ id: string; filter: PromptFilter | null; onError: OnError; endpoint?: string; problem?: string }>;
  exceptions: Array<{ category: string; re: RegExp }>;
}

export class PromptFilterEngine {
  private readonly cache = new Map<string, Omit<PromptSegmentOut, "id" | "cached">>();
  private readonly builtins: Map<string, PromptFilter>;
  private readonly registered: PromptFilter;

  constructor(private readonly deps: PromptFilterEngineDeps) {
    this.builtins = new Map(deps.filters.map((f) => [f.id, f]));
    const r = this.builtins.get(REGISTERED_VALUE_FILTER_ID);
    if (!r) throw new Error("PromptFilterEngine: the registered-value filter is required (it is the harness and side-call floor)");
    this.registered = r;
  }

  private policyInput(): PromptPolicyInput {
    return this.deps.policy ? this.deps.policy() : DEFAULT_POLICY;
  }

  /** The default `on_error` of a filter (§4.4): `block` when any category
   *  it may report maps to an enforcing action, else `pass`; a filter whose
   *  categories are unknown (unavailable) defaults to `block`. */
  private defaultOnError(cfg: EffectivePromptConfig, categories: readonly string[] | undefined): OnError {
    if (!categories || categories.length === 0) return "block";
    for (const cat of categories) {
      if (ENFORCING.has(resolveAction(cfg, cat))) return "block";
      for (const r of cfg.rows) if (coversCategory(cat, r.category) && ENFORCING.has(resolveAction(cfg, r.category))) return "block";
    }
    return "pass";
  }

  private runPolicy(): RunPolicy {
    const input = this.policyInput();
    const cfg = input.config;
    const human: RunPolicy["human"] = [];
    for (const f of [...cfg.filters.values()].sort((a, b) => a.id.localeCompare(b.id))) {
      if (!f.on) continue;
      const filter = this.builtins.get(f.id) ?? input.packs.get(f.id) ?? null;
      const problem = filter ? undefined : (input.unavailable?.get(f.id) ?? `no built-in filter or pack is named ${f.id}`);
      human.push({ id: f.id, filter, onError: f.onError ?? this.defaultOnError(cfg, filter?.categories), ...(f.endpoint ? { endpoint: f.endpoint } : {}), ...(problem ? { problem } : {}) });
    }
    const exceptions = cfg.exceptions.filter((e) => e.inForce).map((e) => ({ category: e.category, re: globRegExp(e.match) }));
    return { input, digest: promptConfigDigest(cfg, FLOORS), human, exceptions };
  }

  /** The filters as the panel shows them (§8.1). */
  filterViews(): PromptFilterView[] {
    const input = this.policyInput();
    const cfg = input.config;
    const ids = new Set<string>([...this.builtins.keys(), ...input.packs.keys(), ...(input.unavailable?.keys() ?? []), ...cfg.filters.keys()]);
    const out: PromptFilterView[] = [];
    for (const id of ids) {
      const sw = cfg.filters.get(id) ?? { id, on: false, setBy: "default" as const, locked: false };
      const filter = this.builtins.get(id) ?? input.packs.get(id) ?? null;
      const builtin = this.builtins.has(id);
      const categories = id === REGISTERED_VALUE_FILTER_ID ? [REGISTERED_VALUE_CATEGORY] : [...(filter?.categories ?? [])];
      const problem = filter ? undefined : (input.unavailable?.get(id) ?? (sw.on ? `no built-in filter or pack is named ${id}` : undefined));
      const kind = builtin ? "built-in" as const : typeof filter?.scanMany === "function" ? "plugin" as const : "pack" as const;
      out.push({
        id, kind, ...(sw.endpoint ? { endpoint: sw.endpoint } : {}), on: sw.on, setBy: sw.setBy, locked: sw.locked, ...(sw.file ? { file: sw.file } : {}),
        onError: sw.onError ?? this.defaultOnError(cfg, filter?.categories ?? (id === REGISTERED_VALUE_FILTER_ID ? categories : undefined)),
        onErrorSet: sw.onError !== undefined,
        available: filter !== null,
        ...(problem ? { problem } : {}),
        categories: categories.map((category) => ({ category, action: resolveAction(cfg, category) })),
        origins: id === REGISTERED_VALUE_FILTER_ID
          ? [
              { origin: "human", floor: sw.on ? `values of ${PROMPT_FLOOR_MIN_LEN}+ characters and ${PROMPT_FLOOR_MIN_ENTROPY}+ bits of entropy per character` : "off (your policy)" },
              { origin: "harness", floor: "every registered value (always on)" },
              { origin: "side-call", floor: "every registered value (always on)" },
            ]
          : sw.on
            ? [
                { origin: "human", floor: "every finding" },
                // §13.3 item 1, §5 as amended: the policy's filters run on
                // every segment; a block there acts as redact.
                { origin: "harness", floor: "every finding (block acts as redact)" },
                { origin: "side-call", floor: "every finding (block acts as redact)" },
              ]
            : [{ origin: "human", floor: "off" }],
      });
    }
    const order = (v: PromptFilterView): number => (v.id === REGISTERED_VALUE_FILTER_ID ? 0 : v.kind === "built-in" ? 1 : v.kind === "pack" ? 2 : 3);
    return out.sort((a, b) => order(a) - order(b) || a.id.localeCompare(b.id));
  }

  /** The category → action rows in force, and the fallback (§8.1 Actions). */
  actionViews(): { rows: EffectivePromptConfig["rows"]; fallback: PromptAction; exceptions: EffectivePromptConfig["exceptions"]; signedOnly: boolean } {
    const cfg = this.policyInput().config;
    return { rows: cfg.rows, fallback: FALLBACK_ACTION, exceptions: cfg.exceptions, signedOnly: cfg.signedOnly };
  }

  digest(): FilterPromptOutcome["digest"] {
    const p = this.runPolicy();
    return { policy: p.digest, packs: p.input.packsDigest, values: this.deps.values().digest };
  }

  /** Run the filters over `segments` (already validated). Rejects when a
   *  mint fails: the caller answers an error and the proxy refuses the
   *  request (fail-closed). Asynchronous since phase 3: a plugin filter
   *  (§4.3) answers from a child process. Segments are scanned one after
   *  the other, so mints happen in request order. */
  async run(segments: readonly PromptSegmentIn[], opts: { session?: string; dryRun?: boolean } = {}): Promise<FilterPromptOutcome> {
    const enforcing = this.deps.enforcing();
    const dryRun = opts.dryRun === true;
    const values = this.deps.values();
    const policy = this.runPolicy();
    const out: PromptSegmentOut[] = [];
    const own = enforcing && opts.session !== undefined && this.deps.ownWrites ? this.deps.ownWrites(opts.session) : null;
    // §13.10: an answer that may have used the session's exempt set is keyed
    // by the session and the set, so it is never served to another session
    // or after the set changed.
    const ownKey = own !== null ? `own:${sha(`${opts.session}\0${own.signature}`)}` : "";
    const keyOf = (seg: PromptSegmentIn): string | null => dryRun ? null
      : [sha(seg.text), seg.origin, enforcing ? "1" : "0", policy.digest, policy.input.packsDigest, String(values.version), seg.origin === "human" ? ownKey : ""].join("|");
    // Phase 3 (§4.3): a plugin scans every segment the cache cannot answer
    // in ONE run, before the per-segment pass reads its answers.
    const pre = await this.batchScans(segments.filter((s) => { const k = keyOf(s); return k === null || !this.cache.has(k); }), policy);
    for (const seg of segments) {
      const key = keyOf(seg);
      const hit = key !== null ? this.cache.get(key) : undefined;
      if (hit) {
        // Refresh its place in the LRU order.
        this.cache.delete(key!);
        this.cache.set(key!, hit);
        out.push({ id: seg.id, ...hit, cached: true });
        continue;
      }
      const answer = await this.segment(seg, policy, enforcing, dryRun, opts.session, pre, own);
      // A filter that could not run (§4.4: `block` with no text) is not
      // cached: a plugin that timed out once (a local model still loading)
      // is asked again on the next request, which stays blocked until then.
      if (key !== null && !(answer.action === "block" && answer.text === undefined)) {
        this.cache.set(key, answer);
        while (this.cache.size > CACHE_CAP) {
          const oldest = this.cache.keys().next().value as string | undefined;
          if (oldest === undefined) break;
          this.cache.delete(oldest);
        }
      }
      out.push({ id: seg.id, ...answer, cached: false });
    }
    return { segments: out, enforcing, dryRun, digest: { policy: policy.digest, packs: policy.input.packsDigest, values: values.digest } };
  }

  /** Run every batch-capable filter the policy turns on (the plugins) once
   *  over `segments`; each answer (or the batch's error) by filter id and
   *  `origin\0text`. Plugins run side by side. */
  private async batchScans(segments: readonly PromptSegmentIn[], policy: RunPolicy): Promise<PreScans> {
    const pre: PreScans = new Map();
    if (segments.length === 0) return pre;
    const unique = new Map<string, { id: string; origin: SegmentOrigin; text: string }>();
    for (const s of segments) {
      const k = preKey(s.origin, s.text);
      if (!unique.has(k)) unique.set(k, { id: `b${unique.size}`, origin: s.origin, text: s.text });
    }
    // A plugin never reads a registered value (the shield below).
    const batch = await Promise.all([...unique.values()].map(async (b) => ({ ...b, text: await this.shield(b.text) })));
    await Promise.all(policy.human.map(async (r) => {
      if (r.filter === null || typeof r.filter.scanMany !== "function") return;
      const answers = new Map<string, ScanResult | Error>();
      pre.set(r.id, answers);
      try {
        const res = await r.filter.scanMany(batch, r.endpoint !== undefined ? { endpoint: r.endpoint } : {});
        for (const [k, b] of unique) {
          const a = res.get(b.id);
          answers.set(k, a ?? new Error("it gave no answer for a segment"));
        }
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        for (const k of unique.keys()) answers.set(k, e);
      }
    }));
    return pre;
  }

  /**
   * The text a PLUGIN reads (§4.3, §13.5 item 3): every registered value in
   * it, at any level and below the prompt floor too (scanned as harness
   * text), replaced by as many `█` as it has UTF-16 code units, so offsets
   * still match the original. A plugin's classifier is a model (`local:
   * true` at most): a `no-model` value must not reach it (the invariant), and
   * the registered-value floor masks every such span anyway. Throws when the
   * floor itself fails (the arbiter's failure, fail-closed).
   */
  private async shield(text: string): Promise<string> {
    const found = (await this.registered.scan(text, { origin: "harness" })).findings;
    if (found.length === 0) return text;
    const chars = text.split("");
    for (const f of found) for (let i = Math.max(0, f.start); i < Math.min(chars.length, f.end); i++) chars[i] = SHIELD_CHAR;
    return chars.join("");
  }

  /** How many answers the cache holds (tests, the panel). */
  get cacheSize(): number {
    return this.cache.size;
  }

  /** The action of one finding: the policy's on a human segment (with the
   *  exceptions), the floor's (`mask` for a registered value) elsewhere;
   *  `log` with the axis off. */
  private actionOf(f: Finding, text: string, origin: SegmentOrigin, policy: RunPolicy, enforcing: boolean, own: SessionOwnWrites | null = null): PromptAction {
    if (!enforcing) return "log";
    // §13.10: the human's own text carrying a value this HIGH session wrote
    // itself: reported, not enacted.
    if (origin === "human" && own !== null && f.category === REGISTERED_VALUE_CATEGORY && f.symbol !== undefined && own.covers(f.symbol)) return "log";
    // The registered-value FLOOR on text the human did not type: always
    // `mask`, no exception, no switch (§3.1).
    if (origin !== "human" && f.category === REGISTERED_VALUE_CATEGORY) return "mask";
    const span = text.slice(f.start, f.end);
    if (policy.exceptions.some((e) => coversCategory(e.category, f.category) && e.re.test(span))) return "pass";
    const action = resolveAction(policy.input.config, f.category);
    // Text the human did not type as this prompt (a side call carrying the
    // prompt to a title request, a reminder, a slash command's arguments):
    // the finding never goes, but the request is not refused for it.
    if (origin !== "human" && (action === "block" || action === "ask")) return "redact";
    return action;
  }

  /** Every finding over `text`, tagged with its filter and action; filters
   *  that failed (and must block) are named in `failed`. */
  private async scanAll(text: string, origin: SegmentOrigin, policy: RunPolicy, enforcing: boolean, pre: PreScans = new Map(), own: SessionOwnWrites | null = null): Promise<{ findings: Tagged[]; skipped: number; failed: string[] }> {
    const findings: Tagged[] = [];
    let skipped = 0;
    const failed: string[] = [];
    // §13.3 (phase 2): the policy's filters run on EVERY segment, because the
    // human's text reaches the model inside harness and side-call text too
    // (Claude Code's title request quotes the prompt; count_tokens carries
    // the whole conversation without tools). On those the registered-value
    // filter is the floor whatever its switch says.
    const runs: Array<{ id: string; filter: PromptFilter | null; onError: OnError; endpoint?: string; problem?: string }> = origin === "human"
      ? policy.human
      : [{ id: REGISTERED_VALUE_FILTER_ID, filter: this.registered, onError: "block" }, ...policy.human.filter((h) => h.id !== REGISTERED_VALUE_FILTER_ID)];
    for (const r of runs) {
      if (r.filter === null) {
        if (r.onError === "block" && enforcing) failed.push(`${r.id} (${r.problem ?? "unavailable"})`);
        continue;
      }
      let res;
      try {
        const batched = pre.get(r.id)?.get(preKey(origin, text));
        if (batched instanceof Error) throw batched;
        res = batched ?? await r.filter.scan(typeof r.filter.scanMany === "function" ? await this.shield(text) : text, { origin, ...(r.endpoint !== undefined ? { endpoint: r.endpoint } : {}) });
      } catch (err) {
        // The floor never fails alone; a failure there is the arbiter's.
        if (r.filter === this.registered && origin !== "human") throw err;
        if (r.onError === "block" && enforcing) failed.push(`${r.id} (${String((err as Error)?.message ?? err).split("\n")[0]})`);
        continue;
      }
      skipped += res.skipped;
      for (const x of res.findings) {
        if (!(x.start >= 0 && x.end <= text.length && x.end > x.start)) continue;
        findings.push({ ...x, filterId: r.id, action: this.actionOf(x, text, origin, policy, enforcing, own) });
      }
    }
    return { findings, skipped, failed };
  }

  private async segment(seg: PromptSegmentIn, policy: RunPolicy, enforcing: boolean, dryRun: boolean, session: string | undefined, pre: PreScans = new Map(), own: SessionOwnWrites | null = null): Promise<Omit<PromptSegmentOut, "id" | "cached">> {
    const { findings, skipped, failed } = await this.scanAll(seg.text, seg.origin, policy, enforcing, pre, own);
    if (failed.length > 0) {
      // §4.4: a filter that must block could not run; nothing of this
      // segment may go, not even a partly filtered text.
      return {
        origin: seg.origin, action: "block", skipped, findings: [],
        reason: `Mandu could not check this prompt: the prompt filter ${failed.join(", ")} did not run, and your policy blocks the prompt when it cannot. Nothing was sent to the model.`,
      };
    }
    const acting = findings.filter((f) => f.action !== "pass");
    if (acting.length === 0) return { origin: seg.origin, action: "pass", findings: [], skipped };
    const mint = (value: string, level: ConfidentialityLevel): string =>
      dryRun ? WOULD_MINT : this.deps.mint(value, level, seg.origin, session);
    const reported: PromptFindingOut[] = [];
    const replacements: Array<{ start: number; end: number; text: string }> = [];
    const blocked: string[] = [];
    for (const c of clusters(acting)) {
      const action = c.members.map((m) => m.action).reduce(stricterAction, "pass" as PromptAction);
      // The lead names the cluster. On a tie, a finding of another filter
      // leads over the registered-value filter's: after a mask the span is a
      // row of its own (the filter's mint), and the cluster is still the
      // pack's or the key shape's finding (phase 3: its verdicts are keyed by
      // that category).
      const lead = c.members.find((m) => m.action === action && m.filterId !== REGISTERED_VALUE_FILTER_ID) ?? c.members.find((m) => m.action === action)!;
      const base = { start: c.start, end: c.end, category: lead.category, filterId: lead.filterId, action, ...(lead.rule ? { rule: lead.rule } : {}) };
      if (action === "log") { reported.push(base); continue; }
      if (action === "redact") {
        replacements.push({ start: c.start, end: c.end, text: redactedMarker(lead.category) });
        reported.push(base);
        continue;
      }
      if (action === "block") {
        replacements.push({ start: c.start, end: c.end, text: blockedMarker(lead.category) });
        blocked.push(`${lead.category} (${lead.filterId})`);
        reported.push(base);
        continue;
      }
      if (action === "ask" && !c.members.some((m) => m.level !== undefined)) {
        // §7: the default of an `ask` whose findings carry no level is
        // `redact`; the hold layer (holds.ts) decides whether it goes as
        // written.
        replacements.push({ start: c.start, end: c.end, text: redactedMarker(lead.category) });
        reported.push(base);
        continue;
      }
      // mask, or the default of an `ask` (every member counts toward the
      // level, as a mask of the whole cluster would).
      const maskers = action === "ask" ? c.members : c.members.filter((m) => m.action === "mask");
      const level = maskers.map((m) => m.level ?? "no-model").reduce(stricter);
      // The span is exactly one registered value: its own symbol (the
      // strictest row when two rows hold the same value).
      const exact = maskers
        .filter((m) => m.how === "value" && m.symbol !== undefined && m.start === c.start && m.end === c.end)
        .reduce<Tagged | null>((best, m) =>
          best === null || confidentialityRank(m.level ?? "no-model") > confidentialityRank(best.level ?? "no-model") ? m : best, null);
      let symbol: string;
      let how: PromptFindingOut["how"];
      if (exact !== null && confidentialityRank(exact.level ?? "no-model") >= confidentialityRank(level)) {
        symbol = exact.symbol!;
        how = "value";
      } else {
        symbol = mint(seg.text.slice(c.start, c.end), level);
        how = c.members.length === 1 ? c.members[0]!.how : "merged";
      }
      replacements.push({ start: c.start, end: c.end, text: symbol });
      reported.push({ ...base, symbol, ...(how ? { how } : {}) });
    }
    if (replacements.length === 0) {
      return { origin: seg.origin, action: "pass", findings: reported, skipped };
    }
    let text = seg.text;
    for (const r of [...replacements].sort((a, b) => b.start - a.start)) {
      text = `${text.slice(0, r.start)}${r.text}${text.slice(r.end)}`;
    }
    // Scan the result again for registered values: whatever still matches
    // (and is enforced here) takes the whole segment.
    const residual = await this.residual(text, seg.origin, policy, enforcing, own);
    if (residual !== null) {
      const action = residual.map((f) => f.action).reduce(stricterAction, "pass" as PromptAction);
      const all = [...findings, ...residual];
      if (action === "block") {
        return {
          origin: seg.origin, action: "block", skipped, text: blockedMarker(REGISTERED_VALUE_CATEGORY),
          reason: blockReason([`${REGISTERED_VALUE_CATEGORY} (${REGISTERED_VALUE_FILTER_ID})`]),
          findings: [{ start: 0, end: seg.text.length, category: REGISTERED_VALUE_CATEGORY, filterId: REGISTERED_VALUE_FILTER_ID, action: "block", how: "merged" }],
        };
      }
      if (action === "redact") {
        return {
          origin: seg.origin, action: "rewrite", skipped, text: redactedMarker(REGISTERED_VALUE_CATEGORY),
          findings: [{ start: 0, end: seg.text.length, category: REGISTERED_VALUE_CATEGORY, filterId: REGISTERED_VALUE_FILTER_ID, action: "redact", how: "merged" }],
        };
      }
      const level = all.map((m) => m.level ?? "no-model").reduce(stricter);
      const whole = mint(seg.text, level);
      return {
        origin: seg.origin, action: blocked.length > 0 ? "block" : "rewrite", text: whole, skipped,
        ...(blocked.length > 0 ? { reason: blockReason(blocked) } : {}),
        findings: [{ start: 0, end: seg.text.length, category: REGISTERED_VALUE_CATEGORY, filterId: REGISTERED_VALUE_FILTER_ID, action: "mask", symbol: whole, how: "merged" }],
      };
    }
    if (blocked.length > 0) {
      return { origin: seg.origin, action: "block", text, reason: blockReason(blocked), findings: reported, skipped };
    }
    return { origin: seg.origin, action: "rewrite", text, findings: reported, skipped };
  }

  /** Does `text` hold a registered value (any of 8+ characters, no prompt
   *  floor)? The hold layer's check before a span goes as written: a value
   *  Mandu protects as a secret never leaves through the prompt filter's
   *  `ask` or a "let it through" (it has its own release paths). `exclude`
   *  names rows that do not count: the prompt filter's OWN masks (a span it
   *  masked by default is a row too, and would otherwise keep every asked
   *  span of 8+ characters from ever being held or sent as written). */
  async holdsRegisteredValue(text: string, exclude?: (symbol: string) => boolean): Promise<boolean> {
    if (!this.deps.enforcing()) return false;
    return (await this.registered.scan(text, { origin: "harness" })).findings.some((f) => !(f.symbol !== undefined && exclude?.(f.symbol)));
  }

  /** Does `text` hold a registered value the policy enforces on `origin`
   *  text (the residual check, with the floors)? The hold layer's last check
   *  on a segment rebuilt with a span let through; `exclude` as above. */
  async enforcedRegisteredIn(text: string, origin: SegmentOrigin, exclude?: (symbol: string) => boolean): Promise<boolean> {
    const enforcing = this.deps.enforcing();
    if (!enforcing) return false;
    const policy = this.runPolicy();
    if (origin === "human" && !policy.human.some((h) => h.filter === this.registered)) return false;
    return (await this.registered.scan(text, { origin })).findings.some((f) =>
      !(f.symbol !== undefined && exclude?.(f.symbol)) && ENFORCING.has(this.actionOf(f, text, origin, policy, enforcing)));
  }

  /** The configuration in force (the hold layer's lock check). */
  config(): EffectivePromptConfig {
    return this.policyInput().config;
  }

  /** Registered values left in a rewritten text whose action enforces, or null. */
  private async residual(text: string, origin: SegmentOrigin, policy: RunPolicy, enforcing: boolean, own: SessionOwnWrites | null = null): Promise<Tagged[] | null> {
    if (!enforcing) return null;
    if (origin === "human" && !policy.human.some((h) => h.filter === this.registered)) return null;
    const hits: Tagged[] = [];
    for (const f of (await this.registered.scan(text, { origin })).findings) {
      const action = this.actionOf(f, text, origin, policy, enforcing, own);
      if (ENFORCING.has(action)) hits.push({ ...f, filterId: REGISTERED_VALUE_FILTER_ID, action });
    }
    return hits.length > 0 ? hits : null;
  }
}

/** The reason a blocked segment carries: what was found, never the value. */
export function blockReason(found: readonly string[]): string {
  const list = [...new Set(found)];
  return `Mandu blocked this prompt: it contains ${list.join(", ")}, which your prompt filter policy does not let reach the model. Nothing was sent. Send your next message without it; this one then stays in the conversation with that part replaced by [blocked: <category>].`;
}
