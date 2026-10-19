/**
 * holds — the prompt filter's Inbox hold and its per-finding "let it
 * through" (confidentiality-plan-15-prompt-filter.md §7, phase 3; as built in
 * §13.6). Mandu-new (no reference origin).
 *
 * The engine (engine.ts) scans and caches; it answers an `ask` finding with
 * the span's DEFAULT applied (`mask`, or `redact` when no finding in the
 * span carries a level) and reports it as `ask`. This layer runs on every
 * live request AFTER the engine, so a human verdict takes effect on the next
 * request without touching the cache:
 *
 *   - THE HOLD. An `ask` finding on a `human` segment with no verdict files
 *     a PENDING row in the arbiter's approval queue (the same
 *     `egress_approvals` rows the Inbox already answers for secret reads and
 *     protected writes) and answers the segment `hold`. The proxy holds the
 *     model request and asks again until the row is answered or the
 *     deadline (default 30 s) passes. The human answers in the Inbox:
 *     send as written, send masked (the default), or cancel, for this
 *     message or for the session.
 *   - THE DEFAULT ON TIMEOUT (§7: "no answer within the deadline means
 *     `mask` (`redact` for a category without a level)"). The deadline runs
 *     from the row's first sighting, which the store persists, so a resend
 *     after the deadline goes with the default at once and a restarted proxy
 *     or arbiter never holds a message twice for the whole deadline. The row
 *     stays pending: an answer given later applies to the next request that
 *     carries the message (the guard's pattern for a held open, plan 10
 *     §12.2).
 *   - LET IT THROUGH. A human verdict also covers findings the policy
 *     `mask`s, `redact`s or `block`s: the dashboard lets one through, once
 *     (this message) or for the session (§7 "Overriding a finding"), never in
 *     band. A finding it covers goes as written.
 *
 * KEYS. A verdict is a row keyed `prompt:<category>#<ref>` × `model:<session>`
 * (the session) or `model:<session>#turn:<turn>` (one message: the agents
 * resend the whole conversation with every request, so "once" means this
 * message wherever it is resent, never one HTTP request). `ref` and `turn`
 * are HMAC-SHA256 of the span and of the message's text under a random key
 * kept in mandu.db (`prompt_hold_state`), cut to 32 hex: the queue is
 * listed on the data plane and the events reach the SIEM, and a plain
 * SHA-256 of a code name or a card number is a dictionary away from it.
 *
 * NOTED MESSAGES (plan 15 §13.7 item 10, 2026-10-17). The dashboard's note
 * under a message reads the newest `prompt_filter` event filed under the
 * message's `turn`; a proxy files one with no findings when the message's
 * finding is gone (an exception, a kind set to `pass`), but it knows the
 * message had one, and its `turn`, only from its own memory, which a
 * restarted proxy does not have. So this layer remembers, per session, each
 * message it answered an attested caller with a referenced finding
 * (`noted`, keyed `HMAC(session, turn)` under the same key; in
 * `prompt_hold_state` as `noted:<key>` rows, bounded, oldest out), and
 * names the `turn` on such a message's later answers that have no finding
 * to reference: a proxy that never saw the message files its new outcome
 * under the note all the same. It changes no text: the segment's action and
 * text are the engine's. Out of band, so nothing a model or a tool result
 * writes can make or match a mark; only the attested caller's live request
 * makes one, and only it is answered with one. A mark lost (evicted, an
 * unwritable mandu.db) leaves the old note standing, never text dropped.
 *
 * WHAT NEVER GOES AS WRITTEN, whatever the verdict:
 *   - a registered value (category `secret.registered`, or any span that
 *     holds a registered value of 8+ characters): a secret Mandu holds has its
 *     own release paths (bindings, `declassify`), not this one;
 *   - a finding under a LOCKED administrator's row other than `ask` (§7: "a
 *     locked administrator rule cannot be overridden"); under a locked `ask`
 *     the human's answer is the administrator's chosen action;
 *   - anything on `harness` or `side-call` text: never held (the engine
 *     answers `ask` there as `redact`), and no verdict is consulted, so a
 *     title request or a token count cannot wedge the agent or carry the raw
 *     span out beside the held request.
 *
 * WHO MAY ASK, WHO MAY ANSWER (plan 13 D9). Only an ATTESTED caller (the
 * proxies on the human socket, the admin channel) files a row, consults a
 * verdict or holds; from the data socket an `ask` goes with its default, no
 * row, no verdict. Answers are admin-only ops (`resolvePromptHold`,
 * `resolveEgressApproval`, `letPromptFindingThrough`): from the data socket
 * an answer is refused, so the agent cannot approve its own human's prompt.
 * The span itself is kept in memory for the Inbox card (`promptHolds`, a
 * human-plane op), never in the row: the row's reason is listed on the data
 * plane.
 *
 * A LOCKED `ask` ASKS EVERY MESSAGE (§12, 2026-10-04). Under a locked
 * administrator's `ask` row (any of the rows that cover the category) the
 * human answers for THIS MESSAGE only: `resolvePromptHold` and
 * `letPromptFindingThrough` with the session scope, and an Always on the
 * generic route (`resolveEgressApproval`, which would file a session verdict
 * through `afterResolve`), are REFUSED with the reason (`sessionRefusal`),
 * never downgraded to once; a session verdict already stored (filed before
 * the lock) is not consulted under it; and the Inbox listing and every
 * referenced finding of a live answer say so (`onceOnly`), so a front end
 * offers no session answer (the hold's card, the "let it through" notes).
 *
 * FAIL-CLOSED. A request that cannot wait (`holds` absent, a token count)
 * gets the default. A hold the proxy gives up on (its deadline, the arbiter
 * unreachable) refuses the request; the raw span goes only on an `approved`
 * verdict read from the store on this request.
 */

import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import Database from "../db/sqlite.js";
import type { EgressApproval, EgressApprovalStore } from "../policy/egress-approvals.js";
import {
  blockedMarker,
  redactedMarker,
  type FilterPromptOutcome,
  type PromptFindingOut,
  type PromptSegmentIn,
  type PromptSegmentOut,
} from "./engine.js";
import { CATEGORY_RE, coversCategory, lockedAction, lockedAsk, type EffectivePromptConfig } from "./policy.js";
import { REGISTERED_VALUE_CATEGORY, REGISTERED_VALUE_FILTER_ID } from "./registered-value-filter.js";

/** The Inbox row's subject prefix. */
export const PROMPT_SUBJECT_PREFIX = "prompt:";
/** §7: the hold's deadline, inside every supported agent's client timeout. */
export const DEFAULT_PROMPT_HOLD_MS = 30_000;
/** How long a cancel waits to be delivered after the deadline. */
const CANCEL_GRACE_MS = 10_000;
/** The longest span the Inbox card shows. */
const SPAN_SHOWN_MAX = 2000;
/** Spans kept for the Inbox card (pending rows only). */
const SPANS_CAP = 512;
/** A session key as a verdict names it. */
const SESSION_MAX = 256;
/** A reference: 32 lowercase hex. */
export const PROMPT_REF_RE = /^[0-9a-f]{32}$/;
/** The noted messages kept (§13.7 item 10): per arbiter, oldest out. */
const NOTED_CAP = 20_000;
/** A noted message's row name in `prompt_hold_state`. */
const NOTED_PREFIX = "noted:";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS prompt_hold_state (
  name  TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

export type HoldAnswer = "send" | "mask" | "cancel";
export type VerdictScope = "once" | "session";

export const promptSubject = (category: string, ref: string): string => `${PROMPT_SUBJECT_PREFIX}${category}#${ref}`;
export const sessionTarget = (session: string): string => `model:${session}`;
export const turnTarget = (session: string, turn: string): string => `model:${session}#turn:${turn}`;

/** A prompt verdict row's parts, or null for any other row. */
export function parsePromptRow(row: { symbol: string; destination: string }): { category: string; ref: string; session: string; turn?: string } | null {
  if (!row.symbol.startsWith(PROMPT_SUBJECT_PREFIX)) return null;
  const s = /^prompt:([^#]+)#([0-9a-f]{32})$/.exec(row.symbol);
  const d = /^model:(.+?)(?:#turn:([0-9a-f]{32}))?$/.exec(row.destination);
  if (!s || !d) return null;
  return { category: s[1]!, ref: s[2]!, session: d[1]!, ...(d[2] ? { turn: d[2] } : {}) };
}

/** What the Inbox card shows for one pending hold (human plane). */
export interface PromptHoldView {
  approvalId: string;
  session: string;
  category: string;
  /** The filter that found it (absent after an arbiter restart until the
   *  message is seen again). */
  filterId?: string;
  /** The human's own text that was found, cut to 2000 characters. Absent
   *  when this arbiter has not seen the message since it started. */
  span?: string;
  /** What the default does: `mask` (a symbol) or `redact`. */
  fallback?: "mask" | "redact";
  firstSeen: number;
  lastSeen: number;
  /** Time left before the default applies (0: it already did; the row waits
   *  for an answer that applies to the message's next resend). */
  timeoutMs: number;
  /** A locked administrator's `ask` row covers the category: the hold takes
   *  an answer for this message only (no session answer). */
  onceOnly?: true;
}

/** What one request's segments need from the server. */
export interface HoldContext {
  session?: string;
  /** A live run (no dry run) with the confidentiality axis on. */
  live: boolean;
  /** The caller is believed (plan 13 D9): the human socket or the admin channel. */
  attested: boolean;
  /** The caller enacts holds (a proxy that waits); absent: the default. */
  holds: boolean;
  /** The caller's last ask of a hold, its deadline passed: no further hold. */
  heldMs?: number;
  config: EffectivePromptConfig;
  /** Does `span` hold a registered value (no prompt floor)? */
  holdsRegisteredValue: (span: string) => Promise<boolean>;
  /** Does `text` (a rebuilt segment) hold a registered value the policy
   *  enforces on `human` text? The last check before it goes. */
  enforcedRegisteredIn: (text: string) => Promise<boolean>;
}

interface HeldSpan {
  session: string;
  category: string;
  filterId: string;
  span: string;
  fallback: "mask" | "redact";
}

export interface PromptHoldsDeps {
  approvals: EgressApprovalStore;
  /** mandu.db (the reference key). Absent: a key for this process only. */
  dbPath?: string;
  now?: () => number;
  timeoutMs?: number;
  log?: (msg: string) => void;
  /** How many noted messages are kept (default 20 000; tests lower it). */
  notedCap?: number;
}

/** Overridable actions: the ones that change what the model reads. */
const ENFORCED: ReadonlySet<string> = new Set(["redact", "mask", "ask", "block"]);

const isRegisteredFinding = (f: PromptFindingOut): boolean =>
  f.filterId === REGISTERED_VALUE_FILTER_ID || coversCategory(REGISTERED_VALUE_CATEGORY, f.category);

/** The words every session-scope refusal under a locked `ask` row ends with
 *  (the dashboard's routes answer 409 on them). */
export const ONCE_ONLY_PHRASE = "answer it for this message only";

/** Why a session-wide answer is refused for `category`, or null when one is
 *  allowed (§12, 2026-10-04: a locked administrator's `ask` row asks every
 *  message). */
export function sessionRefusal(config: EffectivePromptConfig, category: string): string | null {
  const l = lockedAsk(config, category);
  if (l === null) return null;
  return `your administrator set ${category} to ask every time (${l.file ?? "/etc/mandu/policy.d"}), so it takes no answer for the session; ${ONCE_ONLY_PHRASE}`;
}

export const CANCEL_REASON =
  "You cancelled this message in Mandu's Inbox, so nothing was sent to the model. Send your next message; this one then stays in the conversation with the found part hidden.";

export class PromptHolds {
  private readonly key: Buffer;
  private readonly spans = new Map<string, HeldSpan>();
  private readonly cancels = new Map<string, number>();
  private readonly now: () => number;
  readonly timeoutMs: number;

  /** The noted messages (notedKey → when first noted), oldest first. */
  private readonly noted = new Map<string, number>();
  private readonly notedCap: number;

  constructor(private readonly deps: PromptHoldsDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.timeoutMs = deps.timeoutMs !== undefined && Number.isFinite(deps.timeoutMs) && deps.timeoutMs >= 0 ? deps.timeoutMs : DEFAULT_PROMPT_HOLD_MS;
    this.notedCap = deps.notedCap !== undefined && Number.isInteger(deps.notedCap) && deps.notedCap > 0 ? deps.notedCap : NOTED_CAP;
    if (deps.dbPath !== undefined) {
      const st = loadState(deps.dbPath);
      this.key = st.key;
      for (const [k, at] of st.noted) this.noted.set(k, at);
    } else {
      this.key = randomBytes(32);
    }
  }

  /** A span's reference (keyed, never reversible without the key). */
  ref(span: string): string {
    return createHmac("sha256", this.key).update(`span\0${span}`).digest("hex").slice(0, 32);
  }

  /** A message's reference. */
  turn(text: string): string {
    return createHmac("sha256", this.key).update(`turn\0${text}`).digest("hex").slice(0, 32);
  }

  /** The key a noted message is kept under (keyed, so mandu.db names
   *  neither the session nor the message). */
  private notedKey(session: string, turn: string): string {
    return createHmac("sha256", this.key).update(`noted\0${session}\0${turn}`).digest("hex").slice(0, 32);
  }

  /** Whether this arbiter answered `turn` with a referenced finding in
   *  `session` (an attested caller's live request). */
  wasNoted(session: string, turn: string): boolean {
    return this.noted.has(this.notedKey(session, turn));
  }

  /** Remember that `turn` was answered with a referenced finding in
   *  `session`: in memory, and in mandu.db when the arbiter has one (a
   *  write that fails keeps the mark for this process only; a mark lost
   *  leaves a note standing, never text dropped). Bounded, oldest out. */
  private note(session: string, turn: string): void {
    const key = this.notedKey(session, turn);
    if (this.noted.has(key)) return;
    const at = this.now();
    this.noted.set(key, at);
    const evicted: string[] = [];
    while (this.noted.size > this.notedCap) {
      const oldest = this.noted.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.noted.delete(oldest);
      evicted.push(oldest);
    }
    if (this.deps.dbPath === undefined) return;
    try {
      saveNoted(this.deps.dbPath, key, at, evicted);
    } catch (err) {
      this.deps.log?.(`filterPrompt: could not keep a noted message in mandu.db (${(err as Error).message}); kept for this process only`);
    }
  }

  /** Apply the verdicts and the holds to one request's answer. */
  async apply(outcome: FilterPromptOutcome, inputs: readonly PromptSegmentIn[], ctx: HoldContext): Promise<FilterPromptOutcome> {
    if (!ctx.live) return outcome;
    const textOf = new Map(inputs.map((s) => [s.id, s.text]));
    const segments: PromptSegmentOut[] = [];
    for (const seg of outcome.segments) segments.push(await this.segment(seg, textOf.get(seg.id), ctx));
    return { ...outcome, segments };
  }

  private async segment(seg: PromptSegmentOut, text: string | undefined, ctx: HoldContext): Promise<PromptSegmentOut> {
    if (text === undefined || seg.origin !== "human") return seg;
    // A filter that could not run: nothing of the segment may go.
    if (seg.action === "block" && typeof seg.text !== "string") return seg;
    const candidate = (f: PromptFindingOut): boolean =>
      ENFORCED.has(f.action) && !isRegisteredFinding(f) && f.start >= 0 && f.end <= text.length && f.end > f.start;
    const session = typeof ctx.session === "string" && ctx.session !== "" && ctx.session.length <= SESSION_MAX ? ctx.session : null;
    if (!seg.findings.some(candidate)) {
      // No finding to reference now. A message this arbiter answered with
      // one before in the session (an attested caller's request) is named
      // all the same, so the proxy records its new outcome under the
      // message's note, whatever that proxy remembers (§13.7 item 10).
      if (session === null || !ctx.attested) return seg;
      const turn = this.turn(text);
      return this.wasNoted(session, turn) ? { ...seg, turn } : seg;
    }
    const findings = seg.findings.map((f) => ({ ...f }));
    if (session === null) {
      // Nothing to key a verdict by: every ask goes with its default.
      for (const f of findings) if (f.action === "ask") f.hold = { state: "default", why: "no session" };
      return { ...seg, findings };
    }
    const turn = this.turn(text);
    if (ctx.attested) this.note(session, turn);
    let overridden = false;
    let cancelled = false;
    const asks: Array<{ f: PromptFindingOut; span: string; subject: string; turnRow?: EgressApproval }> = [];
    for (const f of findings) {
      if (!candidate(f)) continue;
      const span = text.slice(f.start, f.end);
      f.ref = this.ref(span);
      // The lock rides the finding: the proxies copy it into their events,
      // so the dashboard's "let it through" offers no session answer.
      const onceOnly = lockedAsk(ctx.config, f.category) !== null;
      if (onceOnly) f.onceOnly = true;
      const subject = promptSubject(f.category, f.ref);
      const locked = lockedAction(ctx.config, f.category);
      const fixed = locked !== null && locked.action !== "ask"
        ? `set by your administrator (${locked.file ?? "/etc/mandu/policy.d"})`
        : (await ctx.holdsRegisteredValue(span)) ? "it holds a value Mandu protects as a secret" : null;
      const turnRow = this.deps.approvals.lookupEntry(subject, turnTarget(session, turn));
      // Under a locked `ask` row a session verdict (one stored before the
      // lock) is not consulted: the rule asks every message (§12, 2026-10-04).
      const sessionRow = !onceOnly ? this.deps.approvals.lookupEntry(subject, sessionTarget(session)) : undefined;
      // Plan 13 D9: only an attested caller consults a human verdict.
      const decided = ctx.attested ? [turnRow, sessionRow].find((r) => r !== undefined && r.status !== "pending") : undefined;
      if (decided !== undefined && fixed === null) {
        if (decided.status === "approved") {
          f.let = decided === turnRow ? "once" : "session";
          overridden = true;
          if (f.action === "ask") f.hold = { state: "sent", approvalId: decided.id };
        } else if (f.action === "ask") {
          if (decided === turnRow && this.takeCancel(decided.id)) {
            cancelled = true;
            f.hold = { state: "cancelled", approvalId: decided.id };
          } else {
            f.hold = { state: "masked", approvalId: decided.id };
          }
        }
        continue;
      }
      if (f.action !== "ask") continue;
      if (fixed !== null) {
        f.hold = { state: "default", why: fixed };
        continue;
      }
      asks.push({ f, span, subject, ...(turnRow ? { turnRow } : {}) });
    }
    const stillBlocks = findings.some((f) => f.action === "block" && f.let === undefined);
    let hold: { approvalId: string; timeoutMs: number } | null = null;
    for (const a of asks) {
      const why = !ctx.attested ? "an unauthenticated caller (the data socket)"
        : !ctx.holds ? "a request that cannot wait"
          : stillBlocks ? "the message is blocked anyway"
            : null;
      if (why !== null) {
        a.f.hold = { state: "default", why };
        continue;
      }
      const fallback: "mask" | "redact" = a.f.symbol !== undefined ? "mask" : "redact";
      let row = a.turnRow;
      let left: number;
      if (row !== undefined) {
        left = this.timeoutMs - (this.now() - row.firstSeen);
      } else {
        if (ctx.heldMs !== undefined) {
          a.f.hold = { state: "timed-out" };
          continue;
        }
        row = this.deps.approvals.recordPending(a.subject, turnTarget(session, turn), rowReason(a.f, fallback), session);
        left = this.timeoutMs;
        this.deps.log?.(`filterPrompt: ${a.f.category} (${a.f.filterId}) held for the human (${row.id})`);
      }
      // Kept (again, after a restart) for the Inbox card while the row waits.
      this.remember(row.id, { session, category: a.f.category, filterId: a.f.filterId, span: a.span, fallback });
      if (ctx.heldMs !== undefined || left <= 0) {
        a.f.hold = { state: "timed-out", approvalId: row.id };
        continue;
      }
      a.f.hold = { state: "pending", approvalId: row.id };
      if (hold === null || left < hold.timeoutMs) hold = { approvalId: row.id, timeoutMs: left };
    }
    const refs = { turn };
    if (hold !== null) {
      // Nothing of the segment goes while it is held: no text.
      const { text: _t, reason: _r, ...rest } = seg;
      return { ...rest, ...refs, action: "hold", hold, findings };
    }
    let out: PromptSegmentOut = { ...seg, ...refs, findings };
    if (overridden) {
      const rebuilt = rebuild(text, findings);
      if (await ctx.enforcedRegisteredIn(rebuilt)) {
        // Defensive: a registered value would go raw; keep the engine's answer.
        this.deps.log?.("filterPrompt: a let-through would carry a registered value; the engine's answer stands");
        for (const f of findings) delete f.let;
        out = { ...seg, ...refs, findings };
      } else {
        const blocks = findings.some((f) => f.action === "block" && f.let === undefined);
        const { reason: _r, ...rest } = seg;
        out = blocks
          ? { ...seg, ...refs, findings, text: rebuilt }
          : { ...rest, ...refs, findings, action: rebuilt === text ? "pass" : "rewrite", text: rebuilt };
        if (out.action === "pass") delete out.text;
      }
    }
    if (cancelled) {
      const reason = out.action === "block" && out.reason ? `${CANCEL_REASON} ${out.reason}` : CANCEL_REASON;
      out = { ...out, action: "block", text: typeof out.text === "string" ? out.text : text, reason };
      if (out.text === text) {
        // Defensive: a cancelled segment's text is the engine's (defaults applied).
        out.text = seg.text ?? rebuild(text, findings.map((f) => ({ ...f, let: undefined })));
      }
    }
    return out;
  }

  private takeCancel(id: string): boolean {
    const until = this.cancels.get(id);
    if (until === undefined) return false;
    this.cancels.delete(id);
    return until >= this.now();
  }

  private remember(id: string, s: HeldSpan): void {
    this.spans.delete(id);
    this.spans.set(id, { ...s, span: s.span.length > SPAN_SHOWN_MAX ? `${s.span.slice(0, SPAN_SHOWN_MAX)}…` : s.span });
    while (this.spans.size > SPANS_CAP) {
      const oldest = this.spans.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.spans.delete(oldest);
    }
  }

  /** The human's answer to a hold (admin-only op). Throws on an unknown id,
   *  a row that is not a prompt hold, or a session answer under a locked
   *  administrator's `ask` row (refused, never downgraded to once). */
  answer(approvalId: string, answer: HoldAnswer, scope: VerdictScope, config: EffectivePromptConfig): EgressApproval {
    const row = this.deps.approvals.list().find((a) => a.id === approvalId);
    if (!row) throw new Error(`unknown prompt hold: ${approvalId}`);
    const p = parsePromptRow(row);
    if (p === null || p.turn === undefined) throw new Error(`${approvalId} is not a prompt hold`);
    if (scope === "session") {
      const why = sessionRefusal(config, p.category);
      if (why !== null) throw new Error(`resolvePromptHold: ${why}`);
    }
    const resolved = this.deps.approvals.resolve(approvalId, answer === "send", answer === "cancel" || scope === "once" ? "once" : "always");
    if (!resolved) throw new Error(`unknown prompt hold: ${approvalId}`);
    if (answer === "cancel") {
      // Delivered once, to the request still waiting on this hold: it is
      // refused. Later requests that carry the message get the default.
      const until = row.firstSeen + this.timeoutMs + CANCEL_GRACE_MS;
      if (until >= this.now()) this.cancels.set(approvalId, until);
    }
    this.afterResolve(resolved, config);
    return { ...resolved, sessions: [...resolved.sessions] };
  }

  /** Why the generic route (`resolveEgressApproval`) may not resolve `row`
   *  with `scope`, or null: an Always on a prompt hold under a locked `ask`
   *  row would be a session answer. Checked BEFORE the resolve. */
  genericRefusal(row: EgressApproval | undefined, scope: "once" | "always", config: EffectivePromptConfig): string | null {
    if (row === undefined || scope !== "always") return null;
    const p = parsePromptRow(row);
    if (p === null || p.turn === undefined) return null;
    return sessionRefusal(config, p.category);
  }

  /** After any resolve of a prompt row (this op or `resolveEgressApproval`):
   *  an answer for the session covers the span in every later message of
   *  the session too, except under a locked `ask` row (defensive: the ops
   *  refuse that answer before it is resolved). */
  afterResolve(row: EgressApproval, config: EffectivePromptConfig): void {
    const p = parsePromptRow(row);
    if (p === null) return;
    this.spans.delete(row.id);
    if (p.turn === undefined || row.status === "pending" || row.scope !== "always") return;
    if (sessionRefusal(config, p.category) !== null) {
      this.deps.log?.(`filterPrompt: ${row.id} answered for the session under a locked ask row; no session verdict filed`);
      return;
    }
    const s = this.deps.approvals.recordPending(promptSubject(p.category, p.ref), sessionTarget(p.session), sessionReason(p.category), p.session);
    this.deps.approvals.resolve(s.id, row.status === "approved", "always");
  }

  /** Let one past finding through (admin-only op): `once` for its message,
   *  `session` for the session. Throws with the reason it may not. */
  letThrough(args: { session: unknown; category: unknown; ref: unknown; turn?: unknown; scope: unknown }, config: EffectivePromptConfig): EgressApproval {
    const { session, category, ref, turn, scope } = args;
    if (typeof session !== "string" || session === "" || session.length > SESSION_MAX) throw new Error("letPromptFindingThrough: a session is required");
    if (typeof category !== "string" || !CATEGORY_RE.test(category)) throw new Error("letPromptFindingThrough: category must be a dotted category");
    if (typeof ref !== "string" || !PROMPT_REF_RE.test(ref)) throw new Error("letPromptFindingThrough: ref must be a finding's reference (32 hex)");
    if (scope !== "once" && scope !== "session") throw new Error("letPromptFindingThrough: scope must be once or session");
    if (scope === "once" && (typeof turn !== "string" || !PROMPT_REF_RE.test(turn))) throw new Error("letPromptFindingThrough: once needs the message's reference (turn)");
    if (coversCategory(REGISTERED_VALUE_CATEGORY, category)) {
      throw new Error("letPromptFindingThrough: a registered secret is not let through by the prompt filter; its own rules (bindings, declassify) release it");
    }
    const locked = lockedAction(config, category);
    if (locked !== null && locked.action !== "ask") {
      throw new Error(`letPromptFindingThrough: ${category} is set by your administrator (${locked.file ?? "/etc/mandu/policy.d"}) as ${locked.action}; it cannot be let through`);
    }
    if (scope === "session") {
      const why = sessionRefusal(config, category);
      if (why !== null) throw new Error(`letPromptFindingThrough: ${why}`);
    }
    const target = scope === "once" ? turnTarget(session, turn as string) : sessionTarget(session);
    const row = this.deps.approvals.recordPending(promptSubject(category, ref), target, scope === "once" ? letReason(category, "this message") : sessionReason(category), session);
    const resolved = this.deps.approvals.resolve(row.id, true, scope === "once" ? "once" : "always");
    if (!resolved) throw new Error("letPromptFindingThrough: the verdict could not be recorded");
    this.spans.delete(row.id);
    return { ...resolved, sessions: [...resolved.sessions] };
  }

  /** The pending holds, with the spans this arbiter has seen (human plane);
   *  `onceOnly` under a locked administrator's `ask` row. */
  pending(config: EffectivePromptConfig): PromptHoldView[] {
    const out: PromptHoldView[] = [];
    for (const row of this.deps.approvals.list({ status: "pending" })) {
      const p = parsePromptRow(row);
      if (p === null || p.turn === undefined) continue;
      const s = this.spans.get(row.id);
      out.push({
        approvalId: row.id, session: p.session, category: p.category,
        ...(s ? { filterId: s.filterId, span: s.span, fallback: s.fallback } : {}),
        firstSeen: row.firstSeen, lastSeen: row.lastSeen,
        timeoutMs: Math.max(0, this.timeoutMs - (this.now() - row.firstSeen)),
        ...(lockedAsk(config, p.category) !== null ? { onceOnly: true as const } : {}),
      });
    }
    return out;
  }
}

/** The segment's text with each finding's span as the answer stands: a span
 *  let through as written, every other one replaced as the engine did. */
function rebuild(text: string, findings: readonly PromptFindingOut[]): string {
  let out = "";
  let at = 0;
  for (const f of [...findings].sort((a, b) => a.start - b.start)) {
    if (f.start < at) continue; // findings are disjoint clusters; defensive
    out += text.slice(at, f.start);
    const span = text.slice(f.start, f.end);
    out += f.let !== undefined ? span : replacementOf(f, span);
    at = f.end;
  }
  return out + text.slice(at);
}

function replacementOf(f: PromptFindingOut, span: string): string {
  switch (f.action) {
    case "pass":
    case "log":
      return span;
    case "mask":
      return f.symbol ?? redactedMarker(f.category);
    case "ask":
      return f.symbol ?? redactedMarker(f.category);
    case "block":
      return blockedMarker(f.category);
    case "redact":
    default:
      return redactedMarker(f.category);
  }
}

/** The row's reason: listed on the data plane, so it names the category and
 *  the filter, never the span. */
function rowReason(f: PromptFindingOut, fallback: "mask" | "redact"): string {
  return `Your message to the model holds ${f.category} (found by ${f.filterId}). Mandu holds it until you answer: send it as written, send it ${fallback === "mask" ? "masked" : "with that part removed"}, or cancel it.`;
}

function sessionReason(category: string): string {
  return `Your answer for ${category} in a message to the model, for the rest of this session.`;
}

function letReason(category: string, scope: string): string {
  return `You let ${category} in a message to the model through as written, for ${scope}.`;
}

/** The reference key, created once per mandu.db, and the noted messages
 *  kept there (`noted:<key>` rows of `prompt_hold_state`, oldest first; a
 *  malformed row is skipped). */
function loadState(dbPath: string): { key: Buffer; noted: Array<[string, number]> } {
  const dir = dirname(dbPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  const db = new Database(dbPath);
  try {
    db.pragma("journal_mode = WAL");
    db.exec(SCHEMA_SQL);
    const noted: Array<[string, number]> = [];
    const rows = db.prepare(`SELECT name, value FROM prompt_hold_state WHERE name LIKE '${NOTED_PREFIX}%'`).all() as Array<{ name: string; value: string }>;
    for (const r of rows) {
      const k = r.name.slice(NOTED_PREFIX.length);
      const at = Number(r.value);
      if (PROMPT_REF_RE.test(k) && Number.isFinite(at)) noted.push([k, at]);
    }
    noted.sort((a, b) => a[1] - b[1]);
    const r = db.prepare("SELECT value FROM prompt_hold_state WHERE name = 'ref-key'").get() as { value: string } | undefined;
    if (r && /^[0-9a-f]{64}$/.test(r.value)) return { key: Buffer.from(r.value, "hex"), noted };
    // A new key: marks keyed with another one could never match again.
    const key = randomBytes(32);
    db.prepare("INSERT INTO prompt_hold_state (name, value) VALUES ('ref-key', ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value").run(key.toString("hex"));
    db.prepare(`DELETE FROM prompt_hold_state WHERE name LIKE '${NOTED_PREFIX}%'`).run();
    return { key, noted: [] };
  } finally {
    db.close();
  }
}

/** Keep one noted message in mandu.db and drop the evicted ones. */
function saveNoted(dbPath: string, key: string, at: number, evicted: readonly string[]): void {
  const db = new Database(dbPath);
  try {
    db.pragma("journal_mode = WAL");
    db.exec(SCHEMA_SQL);
    const put = db.prepare("INSERT INTO prompt_hold_state (name, value) VALUES (?, ?) ON CONFLICT(name) DO NOTHING");
    const drop = db.prepare("DELETE FROM prompt_hold_state WHERE name = ?");
    db.transaction(() => {
      put.run(`${NOTED_PREFIX}${key}`, String(at));
      for (const k of evicted) drop.run(`${NOTED_PREFIX}${k}`);
    })();
  } finally {
    db.close();
  }
}
