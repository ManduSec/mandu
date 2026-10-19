/**
 * reply-media — files OpenClaw attaches because the MODEL'S OWN REPLY TEXT
 * names them on a `MEDIA:` line (supported-agents.md §2.1, "Files named in
 * the reply"; guarantees.md §3).
 *
 * Mandu-new (no reference origin). Read statically from the openclaw
 * 2026.7.1 and 2026.9.9 dist and pinned in
 * arbiter/test/fixtures/openclaw-media-lines-2026-10-17.json. When OpenClaw
 * delivers a reply to a chat channel (the gateway's auto-reply, `openclaw
 * agent --deliver`, a heartbeat or a cron run), it runs the reply text
 * through `parseReplyDirectives` → `splitMediaFromOutput`: a line whose
 * first non-blank characters are `MEDIA:` (any case) names attachments, and
 * OpenClaw reads each named local file in its own process and uploads it to
 * the channel (any host path its read policy admits: with the default tool
 * profile the parent directory of the named file is added to the allowed
 * roots). Its own system prompt teaches the model the directive ("Media
 * attachment: own line `MEDIA:<path-or-url>` per item"). No tool call
 * carries it, so no gate of the tool tables reads it: the model could write
 * `MEDIA: /home/u/.env` and the key went to the channel as a file.
 *
 * WHERE: the model-API proxy, on the response. OpenClaw reads the reply
 * from the API response this proxy relays (the reply filter sits on the
 * terminal, after OpenClaw, and never feeds it), so what this module lets
 * through is exactly what OpenClaw parses. Text only: a `thinking` block is
 * never delivered (shouldSuppressReasoningPayload), and its signature must
 * stay intact.
 *
 * WHAT IT DOES, over the whole text of one response (each text block, the
 * blocks joined by "\n" as OpenClaw joins them):
 *   1. A CANONICAL directive line (planReplyMedia): its first non-blank
 *      characters are `MEDIA:` in the raw text, it holds no `<`, `[` or `]`
 *      and no second directive. Its references are read with BOTH builds'
 *      grammars, ported below (openclawMediaRefs; every reading a remote-URL
 *      check could choose), and each is judged (judgeMediaLine): a local
 *      file goes to the arbiter's `fileUploadDecision` with NO host (a chat
 *      channel is no host a binding can name, as for `message`), an http(s)
 *      URL to the net legs (its host, its symbols), OpenClaw's `media://`
 *      store and a relative path with no known base are held. One held
 *      reference replaces the WHOLE line with a notice (replyMediaNotice):
 *      OpenClaw then finds no directive, the person in the chat reads why,
 *      and the model reads it in its own turn on the next request.
 *   2. ANY OTHER place OpenClaw could read a directive is neutralized: its
 *      colon becomes U+A789 (MEDIA_COLON_NEUTRAL), which no OpenClaw
 *      sanitizer deletes or folds. OpenClaw strips markup from the reply
 *      BEFORE it looks for directives (sanitizeAssistantVisibleText,
 *      sanitizeUserFacingText: model special tokens, reasoning and final
 *      tags, tool-call XML, `[Tool Call: …]` blocks, plain-text tool-call
 *      lines at a line start), so `ME<think>…</think>DIA: /x`,
 *      `<b>MEDIA: /x` or `analysis to=f {}MEDIA: /x` become directives
 *      after the raw text was scanned. Every span those strippers remove
 *      inside a line starts with `<`, `[` or `]` (or at a line start), so a
 *      colon is a possible directive when "MEDIA" precedes it with gaps that
 *      each start with one of those (ColonScan). Over-matching costs one
 *      lookalike colon in prose such as "social media: …".
 *   3. THE WINDOW. OpenClaw reads the files at delivery, after the run
 *      ends. A response that also carries a tool call is not the last one:
 *      that call (and every later turn) runs before the read, and may change
 *      the file judged now. So every local reference of such a response is
 *      held (`proxy:reply-media-with-call`), before anything is asked; the
 *      model is told to name files in its final reply.
 *
 * FAIL-CLOSED: an arbiter without the op, one that throws or does not
 * answer in time, a line the grammar cannot read in the bound
 * (ORACLE_RUNS_MAX), or more references than UPLOAD_GATE_MAX_PATHS hold the
 * line. Fences are NOT skipped (OpenClaw skips a directive inside a code
 * fence; a fence this module misread would be a bypass, so a fenced line
 * is judged too).
 *
 * Streaming (reply-media-stream.ts) holds a line from its start while it
 * may still become a directive, and once one appears holds the rest of the
 * response until it ends, then rewrites what it held with gateReplyTexts.
 */

import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { Arbiter, FileUploadDecision, RuleRef } from "./arbiter-client.js";
import { DEFAULT_NET_GATE_TIMEOUT_MS, gateNetToolUse, hostOf } from "./net-gate.js";
import { uploadHeldWords } from "./unmapped-upload-core.js";
import { DEFAULT_UPLOAD_GATE_TIMEOUT_MS, UPLOAD_GATE_MAX_PATHS } from "./upload-gate.js";

/** The tool name the arbiter's upload gate and its Approvals rows see
 *  (`fs:MEDIA:upload`). */
export const REPLY_MEDIA_TOOL = "MEDIA";

/** What a neutralized directive colon becomes: MODIFIER LETTER COLON. It
 *  reads as a colon, has no compatibility decomposition, and OpenClaw's
 *  grammar wants an ASCII `:`. */
export const MEDIA_COLON_NEUTRAL = "\uA789";

/** The marker every notice line starts with. Never a directive. */
export const REPLY_MEDIA_MARKER = "[mandu]";

// ── OpenClaw's grammar (src/media/parse.ts 2026.7.1, parse-output.ts 2026.9.9) ──

const MEDIA_TOKEN_RE = /\bMEDIA:\s*`?([^\n]+)`?/gi;
const WINDOWS_DRIVE_RE = /^[a-zA-Z]:[\\/]/;
const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;
const HAS_FILE_EXT = /\.\w{1,10}$/;
const TRAVERSAL_SEGMENT_RE = /(?:^|[/\\])\.\.(?:[/\\]|$)/;
const MEDIA_SOURCE_ROOT_RE = /^(?:[a-z]:[\\/]|[/~]|\.{1,2}[\\/]|\\\\)/i;
const FILE_URL_PREFIX_RE = /^file:(?:\/\/)?/i;
const TRAILING_SERIALIZED_JSON_AFTER_EXT_RE = /^(.*\.\w{1,10})\\?"(?=[\]},:]|$).*/s;
const HTTP_URL_PREFIX_RE = /^https?:\/\//i;
const INBOUND_MEDIA_RE = /^media:\/\//i;

function cleanCandidate(raw: string): string {
  const stripped = raw.replace(/^[`"'[{(]+/, "").replace(/[`"'\\})\],]+$/, "");
  return TRAILING_SERIALIZED_JSON_AFTER_EXT_RE.exec(stripped)?.[1] ?? stripped;
}
function isSupportedHomeRelativePath(c: string): boolean {
  return c.startsWith("~/") || c.startsWith("~\\");
}
function hasTraversalOrUnsupportedHomeDirPrefix(c: string): boolean {
  return c.startsWith("../") || c === ".." || (c.startsWith("~") && !isSupportedHomeRelativePath(c)) || TRAVERSAL_SEGMENT_RE.test(c);
}
function looksLikeLocalFilePath(c: string): boolean {
  return c.startsWith("/") || c.startsWith("./") || c.startsWith("../") || c.startsWith("~") || WINDOWS_DRIVE_RE.test(c) ||
    c.startsWith("\\\\") || (!SCHEME_RE.test(c) && (c.includes("/") || c.includes("\\")));
}
function isLikelyLocalPath(c: string): boolean {
  if (hasTraversalOrUnsupportedHomeDirPrefix(c)) return false;
  return c.startsWith("/") || c.startsWith("./") || isSupportedHomeRelativePath(c) || WINDOWS_DRIVE_RE.test(c) ||
    c.startsWith("\\\\") || (!SCHEME_RE.test(c) && (c.includes("/") || c.includes("\\")));
}
function unwrapQuoted(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed.length < 2) return undefined;
  const first = trimmed[0];
  if (first !== trimmed[trimmed.length - 1]) return undefined;
  if (first !== `"` && first !== "'" && first !== "`") return undefined;
  return trimmed.slice(1, -1).trim();
}

/** Is this remote (http(s)) or `media://` source valid in OpenClaw's eyes?
 *  OpenClaw decides by host and inbound-store checks this module does not
 *  copy; every answer is explored instead (everyReading). */
type Oracle = (source: string) => boolean;
interface ValidOpts { allowSpaces?: boolean; allowBareFilename?: boolean }

// 2026.9.9
const norm99 = (s: string): string => s.replace(FILE_URL_PREFIX_RE, "");
function isValid99(source: string, opts: ValidOpts | undefined, oracle: Oracle): boolean {
  const c = norm99(source);
  if (!c || c.length > 4096) return false;
  if (!opts?.allowSpaces && /\s/.test(c)) return false;
  if (HTTP_URL_PREFIX_RE.test(c)) return oracle(c);
  if (INBOUND_MEDIA_RE.test(c)) return oracle(c);
  if (isLikelyLocalPath(c)) return true;
  if (hasTraversalOrUnsupportedHomeDirPrefix(c)) return false;
  return Boolean(opts?.allowBareFilename && !SCHEME_RE.test(c) && HAS_FILE_EXT.test(c));
}
function begins99(raw: string): boolean {
  const c = norm99(cleanCandidate(raw));
  return MEDIA_SOURCE_ROOT_RE.test(c) || SCHEME_RE.test(c);
}
function splitUnquoted99(payload: string, oracle: Oracle): string[] {
  const parts: string[] = [];
  let previousEnd = 0;
  for (const match of payload.matchAll(/\S+/g)) {
    const index = match.index ?? 0;
    const candidate = norm99(cleanCandidate(match[0]));
    const previous = parts.at(-1);
    const previousCandidate = previous ? norm99(cleanCandidate(previous)) : "";
    if (MEDIA_SOURCE_ROOT_RE.test(previousCandidate) && !begins99(candidate) &&
      (!HAS_FILE_EXT.test(previousCandidate) || !isValid99(candidate, undefined, oracle))) {
      parts[parts.length - 1] = `${previous}${payload.slice(previousEnd, index)}${match[0]}`;
    } else {
      parts.push(match[0]);
    }
    previousEnd = index + match[0].length;
  }
  return parts;
}
function lineRefs99(line: string, oracle: Oracle): string[] {
  const media: string[] = [];
  for (const match of line.matchAll(MEDIA_TOKEN_RE)) {
    const payload = match[1] ?? "";
    const unwrapped = unwrapQuoted(payload);
    const payloadValue = unwrapped ?? payload;
    const parts = unwrapped ? [unwrapped] : splitUnquoted99(payload, oracle);
    const start = media.length;
    let validCount = 0;
    let hasValid = false;
    const invalid: string[] = [];
    for (const part of parts) {
      const candidate = unwrapped === undefined ? cleanCandidate(part) : part;
      if (isValid99(candidate, { allowSpaces: Boolean(unwrapped) || /\s/.test(candidate) }, oracle)) {
        media.push(candidate);
        hasValid = true;
        validCount += 1;
      } else if (!/\s/.test(part) || !hasTraversalOrUnsupportedHomeDirPrefix(candidate)) {
        invalid.push(part);
      }
    }
    const trimmedPayload = payloadValue.trim();
    const looksLocal = looksLikeLocalFilePath(trimmedPayload) || FILE_URL_PREFIX_RE.test(trimmedPayload);
    if (!unwrapped && validCount === 1 && invalid.length > 0 && !parts.slice(1).some(begins99) && /\s/.test(payloadValue) && looksLocal) {
      const fallback = cleanCandidate(payloadValue);
      if (isValid99(fallback, { allowSpaces: true }, oracle)) {
        media.splice(start, media.length - start, fallback);
        hasValid = true;
      }
    }
    if (!hasValid) {
      const fallback = unwrapped ?? cleanCandidate(payloadValue);
      if (isValid99(fallback, { allowSpaces: true, allowBareFilename: true }, oracle)) media.push(fallback);
    }
  }
  return media;
}

// 2026.7.1
const norm71 = (s: string): string => (s.startsWith("file://") ? s.replace("file://", "") : s);
function isValid71(c: string, opts: ValidOpts | undefined, oracle: Oracle): boolean {
  if (!c || c.length > 4096) return false;
  if (!opts?.allowSpaces && /\s/.test(c)) return false;
  if (HTTP_URL_PREFIX_RE.test(c)) return oracle(c);
  if (isLikelyLocalPath(c)) return true;
  if (hasTraversalOrUnsupportedHomeDirPrefix(c)) return false;
  return Boolean(opts?.allowBareFilename && !SCHEME_RE.test(c) && HAS_FILE_EXT.test(c));
}
function lineRefs71(line: string, oracle: Oracle): string[] {
  const media: string[] = [];
  for (const match of line.matchAll(MEDIA_TOKEN_RE)) {
    const payload = match[1] ?? "";
    const unwrapped = unwrapQuoted(payload);
    const payloadValue = unwrapped ?? payload;
    const parts = unwrapped ? [unwrapped] : payload.split(/\s+/).filter(Boolean);
    const start = media.length;
    let validCount = 0;
    let hasValid = false;
    const invalid: string[] = [];
    for (const part of parts) {
      const candidate = norm71(cleanCandidate(part));
      if (isValid71(candidate, unwrapped ? { allowSpaces: true } : undefined, oracle)) {
        media.push(candidate);
        hasValid = true;
        validCount += 1;
      } else {
        invalid.push(part);
      }
    }
    const trimmedPayload = payloadValue.trim();
    const looksLocal = looksLikeLocalFilePath(trimmedPayload) || trimmedPayload.startsWith("file://");
    if (!unwrapped && validCount === 1 && invalid.length > 0 && /\s/.test(payloadValue) && looksLocal) {
      const fallback = norm71(cleanCandidate(payloadValue));
      if (isValid71(fallback, { allowSpaces: true }, oracle)) {
        media.splice(start, media.length - start, fallback);
        hasValid = true;
      }
    }
    if (!hasValid && !unwrapped && /\s/.test(payloadValue)) {
      const spaced = norm71(cleanCandidate(payloadValue));
      if (isValid71(spaced, { allowSpaces: true, allowBareFilename: true }, oracle)) {
        media.splice(start, media.length - start, spaced);
        hasValid = true;
      }
    }
    if (!hasValid) {
      const fallback = norm71(cleanCandidate(payloadValue));
      if (isValid71(fallback, { allowSpaces: true, allowBareFilename: true }, oracle)) media.push(fallback);
    }
  }
  return media;
}

/** Bound on the grammar runs one line may take (each remote or store
 *  source doubles them); a line needing more is held whole. */
export const ORACLE_RUNS_MAX = 64;

/** Every result `run` gives under every answer its oracle could get: a
 *  depth-first walk over the sources it asks about. null past the bound. */
function everyReading(run: (oracle: Oracle) => string[]): string[] | null {
  const out = new Set<string>();
  const todo: Array<Map<string, boolean>> = [new Map()];
  let runs = 0;
  while (todo.length > 0) {
    if (++runs > ORACLE_RUNS_MAX) return null;
    const asked = new Map(todo.pop()!);
    const oracle: Oracle = (s) => {
      const known = asked.get(s);
      if (known !== undefined) return known;
      const alt = new Map(asked);
      alt.set(s, true);
      todo.push(alt);
      asked.set(s, false);
      return false;
    };
    for (const r of run(oracle)) out.add(r);
  }
  return [...out];
}

/**
 * The media references OpenClaw would take from one directive line: the
 * union of the 2026.7.1 and 2026.9.9 readings, each under every answer of
 * its remote / store checks. null when the bound is passed. Pure.
 */
export function openclawMediaRefs(line: string): string[] | null {
  const a = everyReading((o) => lineRefs99(line, o));
  const b = everyReading((o) => lineRefs71(line, o));
  if (a === null || b === null) return null;
  return [...new Set([...a, ...b])];
}

/**
 * Is `line` (from its start) a directive line in OpenClaw's raw reading:
 * "yes" when its first non-blank characters are `MEDIA:` (2026.9.9 upper-
 * cases the first six, 2026.7.1 the whole rest); "maybe" while the text so
 * far could still become one; "no" otherwise. A COMPLETE line that is
 * "maybe" is not one. Pure.
 */
export function mediaLineState(line: string): "yes" | "maybe" | "no" {
  const t = line.replace(/^\s+/, "");
  if (t === "") return "maybe";
  const head = t.slice(0, 6).toUpperCase();
  if (head.startsWith("MEDIA:") || t.toUpperCase().startsWith("MEDIA:")) return "yes";
  if (t.length < 6 && "MEDIA:".startsWith(head)) return "maybe";
  return "no";
}

// ── possible directives after OpenClaw's sanitizers (module header, 2) ──────

const WORD = "MEDIA";
/** Where a span OpenClaw's sanitizers remove inside a line can start. */
const GAP_START = new Set(["<", "[", "]"]);

/** The scan state: `at[k]` the last characters read spell WORD[0..k)
 *  (gaps skipped); `gap[k]` a removable span is open after k letters (it
 *  may run on to any later character). */
export interface ColonScan { at: boolean[]; gap: boolean[] }

export function colonScanStart(): ColonScan {
  return { at: [true, false, false, false, false, false], gap: [false, false, false, false, false, false] };
}

/** Read one character: the next state, and whether it is a colon "MEDIA"
 *  may precede after OpenClaw's deletions. Pure. */
export function colonScanStep(s: ColonScan, ch: string): { next: ColonScan; directive: boolean } {
  const u = ch.toUpperCase();
  const at = [true, false, false, false, false, false];
  const gap = [...s.gap];
  let directive = false;
  for (let k = 0; k <= 5; k++) {
    if (!(s.at[k] || s.gap[k])) continue;
    if (k < 5 && u === WORD[k]) at[k + 1] = true;
    if (k === 5 && ch === ":") directive = true;
    if (k >= 1 && GAP_START.has(ch)) gap[k] = true;
  }
  return { next: { at, gap }, directive };
}

/** One canonical directive line of a text: where it is and what it says. */
export interface CanonicalLine { start: number; end: number; line: string }

/** What a text holds (module header): its canonical directive lines, and
 *  the positions of every other possible directive colon. */
export interface ReplyMediaPlan { canonical: CanonicalLine[]; neutral: number[] }

/** Plan one text (the blocks of a response joined by "\n"). Pure. */
export function planReplyMedia(text: string): ReplyMediaPlan {
  const colons: number[] = [];
  let s = colonScanStart();
  for (let i = 0; i < text.length; i++) {
    const r = colonScanStep(s, text[i]!);
    s = r.next;
    if (r.directive) colons.push(i);
  }
  const canonical: CanonicalLine[] = [];
  const neutral: number[] = [];
  let ci = 0;
  let start = 0;
  while (start <= text.length) {
    const nl = text.indexOf("\n", start);
    const end = nl < 0 ? text.length : nl;
    const mine: number[] = [];
    while (ci < colons.length && colons[ci]! < end) mine.push(colons[ci++]!);
    if (mine.length > 0) {
      const line = text.slice(start, end);
      const lead = line.length - line.replace(/^\s+/, "").length;
      const isCanonical = mediaLineState(line) === "yes" && !/[<[\]]/.test(line) && mine.length === 1 && mine[0] === start + lead + 5;
      if (isCanonical) canonical.push({ start, end, line });
      else neutral.push(...mine);
    }
    if (nl < 0) break;
    start = nl + 1;
  }
  return { canonical, neutral };
}

/** Does the text hold anything to judge or neutralize? Pure. */
export function hasReplyMedia(text: string): boolean {
  const p = planReplyMedia(text);
  return p.canonical.length > 0 || p.neutral.length > 0;
}

// ── placing and judging a reference ─────────────────────────────────────────

/** What one reference names, read as OpenClaw's reply media loader reads it
 *  (reply-media-paths.ts normalizeMediaSource, web-media.ts): `file:` URLs
 *  decoded (one that cannot be is refused there), `~/` as the home, a
 *  relative path in the agent's workspace. No `@` strip (that is the media
 *  tools' spelling, not a directive's). */
export type ReplyRef =
  | { kind: "local"; path: string }
  | { kind: "remote"; url: string; host: string | null }
  | { kind: "store" }
  | { kind: "relative" }
  | { kind: "none" };

export function placeReplyRef(raw: string, home: string, base?: string): ReplyRef {
  let s = raw.trim();
  if (s === "") return { kind: "none" };
  if (INBOUND_MEDIA_RE.test(s)) return { kind: "store" };
  if (HTTP_URL_PREFIX_RE.test(s)) return { kind: "remote", url: s, host: hostOf(s) };
  if (/^data:/i.test(s)) return { kind: "none" };
  if (/^file:/i.test(s)) {
    try { s = fileURLToPath(s); } catch { return { kind: "none" }; }
  }
  if (s.startsWith("/")) return { kind: "local", path: path.posix.resolve(s) };
  if (s === "~" || s.startsWith("~/") || s.startsWith("~\\")) return { kind: "local", path: path.posix.resolve(home, s.slice(2)) };
  if (base !== undefined && base.startsWith("/")) return { kind: "local", path: path.posix.resolve(base, s) };
  return { kind: "relative" };
}

/** One reference a line names that was held. */
export interface WithheldRef {
  /** The reference as the model wrote it. */
  ref: string;
  /** The absolute file judged, for a local one. */
  path?: string;
  reason: string;
  ruleRef: RuleRef;
  requiresApproval: boolean;
  approvalId?: string;
  /** Why, in the person's words (the notice). */
  plain: string;
  /** The person can allow it on the Approvals page. */
  asks: boolean;
}

export interface ReplyMediaOptions {
  arbiter: Pick<Arbiter, "fileUploadDecision" | "sessionEgressDecision" | "desymbolizationDecision">;
  /** The watermark session and the approval row's session. */
  sessionKey?: string;
  /** Where OpenClaw resolves a relative reference (its workspace, pinned to
   *  the launch directory; proxy.ts relativeBaseFor). Absent: a relative
   *  reference is held. */
  launchDir?: string;
  home?: string;
  timeoutMs?: number;
  tlsInspected?: boolean;
  log?: (m: string) => void;
}

function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(message)), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e as Error); });
  });
}

/** The notice line that replaces a held directive line. Names the
 *  reference the model wrote and the rule; never what a file holds. Not a
 *  directive itself (it starts with REPLY_MEDIA_MARKER). Pure. */
export function replyMediaNotice(held: readonly WithheldRef[]): string {
  const first = held[0]!;
  const more = held.length > 1 ? ` (and ${held.length - 1} more)` : "";
  const ask = held.some((h) => h.asks)
    ? " The user can allow it on the Mandu dashboard's Approvals page (mandu dashboard), then ask for it again."
    : "";
  return `${REPLY_MEDIA_MARKER} attachment not sent, nothing was uploaded: ${first.plain}${more}.${ask} (rule: ${first.ruleRef.id})`;
}

/** Why a reference was held, for the cases the arbiter does not answer. */
function heldBy(ref: string, id: string, plain: string, extra: Partial<WithheldRef> = {}): WithheldRef {
  return { ref, reason: plain, ruleRef: { source: "fail-closed", id }, requiresApproval: false, plain, asks: false, ...extra };
}

/**
 * Judge one canonical directive line (module header, 1 and 3). Returns the
 * line that replaces it (null: keep it) and every reference held. NEVER
 * THROWS: a failure holds the reference.
 */
export async function judgeMediaLine(
  line: string,
  withCall: string | undefined,
  opts: ReplyMediaOptions,
): Promise<{ replacement: string | null; withheld: WithheldRef[] }> {
  const refs = openclawMediaRefs(line);
  if (refs === null || refs.length > UPLOAD_GATE_MAX_PATHS) {
    const w = heldBy(line.trim(), "proxy:reply-media-unreadable", "Mandu could not read this attachment line well enough to check what it names");
    return { replacement: replyMediaNotice([w]), withheld: [w] };
  }
  const home = opts.home ?? homedir();
  const timeoutMs = opts.timeoutMs ?? DEFAULT_UPLOAD_GATE_TIMEOUT_MS;
  const withheld: WithheldRef[] = [];
  const asked = new Set<string>();
  for (const ref of refs) {
    const placed = placeReplyRef(ref, home, opts.launchDir);
    if (placed.kind === "none") continue;
    if (placed.kind === "store") {
      withheld.push(heldBy(ref, "proxy:reply-media-store", `${ref} names OpenClaw's own media store, where Mandu cannot tell which file it is`));
      continue;
    }
    if (placed.kind === "relative") {
      withheld.push(heldBy(ref, "proxy:reply-media-relative", `${ref} is a relative path, and Mandu does not know the folder OpenClaw reads it in; name the file by its absolute path`));
      continue;
    }
    if (placed.kind === "remote") {
      if (placed.host === null) {
        withheld.push(heldBy(ref, "proxy:reply-media-unreadable", `Mandu could not read the address ${ref}`));
        continue;
      }
      const ng = await gateNetToolUse(REPLY_MEDIA_TOOL, { url: placed.url }, {
        arbiter: opts.arbiter as Arbiter,
        ...(opts.sessionKey ? { sessionKey: opts.sessionKey } : {}),
        ...(opts.log ? { log: opts.log } : {}),
        // the net leg keeps the net gate's ceiling; only the file check
        // waits for a streamed scan (DEFAULT_UPLOAD_GATE_TIMEOUT_MS)
        timeoutMs: opts.timeoutMs ?? DEFAULT_NET_GATE_TIMEOUT_MS,
        ...(opts.tlsInspected ? { tlsInspected: true } : {}),
        netTools: { [REPLY_MEDIA_TOOL]: { destination: "url", symbols: "url" } },
      });
      if (ng.outcome?.decision === "block") {
        const o = ng.outcome;
        withheld.push(heldBy(ref, o.ruleRef?.id ?? "proxy:net-blocked", `Mandu did not let OpenClaw fetch ${ref} (${o.reason})`, {
          ...(o.ruleRef ? { ruleRef: o.ruleRef } : {}),
          ...(o.approvalId ? { approvalId: o.approvalId, asks: true } : {}),
        }));
      }
      continue;
    }
    // a local file
    if (withCall !== undefined) {
      withheld.push(heldBy(ref, "proxy:reply-media-with-call",
        `this reply also calls ${withCall}, which runs before OpenClaw reads ${ref}, and Mandu checks a file before that, not when OpenClaw reads it; name the file in your final reply, once the tools have run`,
        { path: placed.path }));
      continue;
    }
    if (asked.has(placed.path)) continue;
    asked.add(placed.path);
    let d: FileUploadDecision;
    try {
      if (!opts.arbiter.fileUploadDecision) throw new Error("this arbiter cannot judge an upload");
      d = await withTimeout(
        opts.arbiter.fileUploadDecision({
          tool: REPLY_MEDIA_TOOL, path: placed.path, destination: "",
          ...(opts.sessionKey ? { sessionKey: opts.sessionKey } : {}),
        }),
        timeoutMs,
        `arbiter fileUploadDecision timed out after ${timeoutMs}ms`,
      );
    } catch (err) {
      const msg = (err as Error).message;
      const words = uploadHeldWords(ref, null, msg);
      withheld.push(heldBy(ref, words.id, words.plain, { path: placed.path, reason: `arbiter unreachable — fail closed: ${msg}` }));
      continue;
    }
    if (d.allow) continue;
    const words = uploadHeldWords(ref, d);
    withheld.push({
      ref, path: placed.path, reason: d.reason,
      ruleRef: d.ruleRef ?? { source: "fail-closed", id: words.id },
      requiresApproval: d.requiresApproval,
      ...(d.approvalId ? { approvalId: d.approvalId } : {}),
      plain: words.plain, asks: words.asks,
    });
  }
  if (withheld.length === 0) return { replacement: null, withheld };
  opts.log?.(`reply-media: ${withheld.length} reference(s) of a MEDIA line HELD (${withheld[0]!.ruleRef.id})`);
  return { replacement: replyMediaNotice(withheld), withheld };
}

/** The result of gating the texts of one response. */
export interface ReplyMediaResult {
  texts: string[];
  changed: boolean;
  withheld: WithheldRef[];
  /** How many possible directive colons were neutralized. */
  neutralized: number;
}

/**
 * Gate the texts of one response (each text block, in order; OpenClaw joins
 * them with "\n"): judge every canonical directive line, neutralize every
 * other possible directive. `withCall`: the first tool call the response
 * carries (the window). NEVER THROWS.
 */
export async function gateReplyTexts(
  texts: readonly string[],
  withCall: string | undefined,
  opts: ReplyMediaOptions,
): Promise<ReplyMediaResult> {
  const plan = planReplyMedia(texts.join("\n"));
  if (plan.canonical.length === 0 && plan.neutral.length === 0) return { texts: [...texts], changed: false, withheld: [], neutralized: 0 };
  const verdicts = new Map<string, string | null>();
  const withheld: WithheldRef[] = [];
  for (const c of plan.canonical) {
    if (verdicts.has(c.line)) continue;
    if (verdicts.size >= MEDIA_LINES_MAX) {
      const w = heldBy(c.line.trim(), "proxy:reply-media-unreadable", `this reply names more attachments than Mandu checks in one reply (${MEDIA_LINES_MAX})`);
      verdicts.set(c.line, replyMediaNotice([w]));
      withheld.push(w);
      continue;
    }
    const v = await judgeMediaLine(c.line, withCall, opts);
    verdicts.set(c.line, v.replacement);
    withheld.push(...v.withheld);
  }
  const first = applyEdits(texts, [
    ...plan.neutral.map((p) => ({ start: p, end: p + 1, text: MEDIA_COLON_NEUTRAL })),
    ...plan.canonical.flatMap((c) => {
      const r = verdicts.get(c.line);
      return r === null || r === undefined ? [] : [{ start: c.start, end: c.end, text: r }];
    }),
  ]);
  // A notice quotes the reference the model wrote, which may itself spell a
  // directive: one more pass neutralizes whatever the rewrite left (a kept
  // canonical line is canonical again and stays as it is).
  const again = planReplyMedia(first.join("\n"));
  const out = applyEdits(first, again.neutral.map((p) => ({ start: p, end: p + 1, text: MEDIA_COLON_NEUTRAL })));
  return { texts: out, changed: out.some((s, i) => s !== texts[i]), withheld, neutralized: plan.neutral.length + again.neutral.length };
}

/** Bound on the distinct directive lines one response may have judged; the
 *  rest are held. */
export const MEDIA_LINES_MAX = 256;

/** Apply edits made over `texts.join("\n")` back to each text (back to
 *  front; none spans a "\n"). Pure. */
function applyEdits(texts: readonly string[], edits: ReadonlyArray<{ start: number; end: number; text: string }>): string[] {
  const sorted = [...edits].sort((a, b) => b.start - a.start);
  const out: string[] = [];
  let offset = 0;
  for (const t of texts) {
    let s = t;
    for (const e of sorted) {
      if (e.start >= offset && e.end <= offset + t.length) s = s.slice(0, e.start - offset) + e.text + s.slice(e.end - offset);
    }
    out.push(s);
    offset += t.length + 1;
  }
  return out;
}
