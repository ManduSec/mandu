/**
 * transcript — parse the readable `▸ role` conversation summary the proxies put
 * in a `tllm_call` / `ullm_call` event's input DualRepr, and derive a
 * human-readable session label from it.
 *
 * Mandu-new (NO reference origin). The anthropic-proxy used to dump the raw
 * `JSON.stringify(request)` into `input.symbolized`; the dashboard rendered it
 * as an unreadable JSON blob. The proxy now emits a `▸ role\n…content` transcript
 * (interceptors/anthropic-proxy/src/proxy.ts `summarizeRequest`); this module is
 * the consumer side — pure, so it's unit-tested under `node --test` and mirrored
 * verbatim into the browser at public/js/transcript.js (same no-build mirror
 * pattern as render-helpers).
 *
 * Everything here is tolerant: it accepts the new `▸` transcript, a legacy inline
 * `"system: … user: …"` summary, a raw Anthropic request JSON, or arbitrary text,
 * and never throws.
 */

/** One message in a parsed transcript: a role plus its (possibly multi-line) body. */
export interface TranscriptMessage {
  /** "system" | "user" | "assistant" | "tool_result" | … (verbatim from the marker). */
  role: string;
  /** The message text, symbols ($MDU:*) intact. May contain `→ tool(args)` lines. */
  body: string;
}

const ROLE_MARK = "▸";
/** A line that begins a new message block: `▸ <role>`. */
const MARKER_RE = /^▸[  ]+(.+?)\s*$/;

/**
 * Parse a `▸ role` transcript into messages. Returns null if the text carries no
 * marker (i.e. it is not a transcript — the caller should fall back to plain
 * rendering). Lines before the first marker are ignored.
 */
export function parseTranscript(text: unknown): TranscriptMessage[] | null {
  if (typeof text !== "string" || !text.includes(ROLE_MARK)) return null;
  const msgs: TranscriptMessage[] = [];
  let cur: TranscriptMessage | null = null;
  for (const line of text.split("\n")) {
    const m = MARKER_RE.exec(line);
    if (m) {
      cur = { role: m[1]!.trim(), body: "" };
      msgs.push(cur);
    } else if (cur) {
      cur.body += cur.body ? "\n" + line : line;
    }
  }
  if (!msgs.length) return null;
  for (const x of msgs) x.body = x.body.replace(/\s+$/, "");
  return msgs;
}

/** A parsed message annotated with how the detail pane should present it. */
export interface TranscriptRow extends TranscriptMessage {
  /** Collapse this block by default — the agent's large `▸ system` prompt, which
   *  otherwise drowns the conversation. The renderer puts it in a closed
   *  `<details>` the human can expand on demand. */
  collapsed: boolean;
  /** The human's actual prompt: the FIRST `▸ user` message. The renderer
   *  highlights it so it's findable at a glance (dashboard.md §4.3). */
  primary: boolean;
  /** True when this is a tool RESULT (the Messages API delivers them as user-role
   *  messages, body `[tool_result <id>]`) — so the renderer labels it "tool result"
   *  rather than "user". */
  toolResult: boolean;
  /** This message relative to the PREVIOUS model call's transcript:
   *    "carried" — part of the common prefix the stateless Messages API re-sends,
   *    "fresh"   — new this turn (the tail beyond the prior call),
   *    null      — no prior call to diff against (the first model turn).
   *  The renderer dims "carried" and accents "fresh" so the new input pops. */
  delta: "carried" | "fresh" | null;
}

/** Normalize a body for cross-turn diffing: the proxy re-symbolizes untrusted
 *  spans on EVERY request, so the SAME carried message reappears with a different
 *  `$MDU:<tool>[<hash>]` token. Collapse the hash so re-symbolization does
 *  not read as a change; everything else compares verbatim. */
function normalizeForDiff(body: string): string {
  return body.replace(/(\$MDU:[A-Za-z]+)\[[0-9a-fA-F]+\]/g, "$1[#]");
}

/** Length of the longest common prefix of two transcripts (role + symbol-normalized
 *  body equal), i.e. how many leading messages `cur` carried over from `prev`. */
function carriedPrefixLength(cur: TranscriptMessage[], prev: TranscriptMessage[]): number {
  let i = 0;
  const n = Math.min(cur.length, prev.length);
  while (
    i < n &&
    cur[i]!.role === prev[i]!.role &&
    normalizeForDiff(cur[i]!.body) === normalizeForDiff(prev[i]!.body)
  )
    i++;
  return i;
}

/**
 * Annotate parsed transcript messages for the detail pane: collapse the agent's
 * `▸ system` block (it's huge and not what the human is looking for) and flag the
 * first `▸ user` message as the primary prompt. Pure — mirrored verbatim into
 * public/js/transcript.js for the browser.
 */
export function annotateTranscript(
  msgs: TranscriptMessage[],
  prev?: TranscriptMessage[] | null,
): TranscriptRow[] {
  // Fresh/carried diff: the stateless Messages API re-sends the whole transcript
  // each turn, so `msgs` is `prev` (a prefix) plus a fresh tail. Dim the carried
  // prefix; accent the tail. With no prior call, every row's delta is null.
  const hasPrev = !!(prev && prev.length);
  const carried = hasPrev ? carriedPrefixLength(msgs, prev!) : 0;
  let primarySeen = false;
  return msgs.map((m, i) => {
    const isUser = /^user$/i.test(m.role);
    // The Messages API sends tool RESULTS as `user`-role messages (body starts
    // `[tool_result <id>]`); flag them so they don't read as the human's prompt.
    const toolResult = /^tool_result$/i.test(m.role) || (isUser && /^\s*\[tool_result\b/.test(m.body));
    const primary = isUser && !toolResult && !primarySeen;
    if (primary) primarySeen = true;
    const delta: TranscriptRow["delta"] = !hasPrev ? null : i < carried ? "carried" : "fresh";
    return { ...m, collapsed: /^system$/i.test(m.role), primary, toolResult, delta };
  });
}

/** Tag spans the Claude Code harness injects INTO a user-role message around
 *  the human's typed text: `<system-reminder>` context blocks, and the
 *  local-command record a slash command leaves behind (`<local-command-caveat>`,
 *  `<command-name>/model</command-name>`, `<command-message>`, `<command-args>`,
 *  `<command-contents>`, `<local-command-stdout>`/`stderr`). None of it is the
 *  prompt — a session whose first turn ran `/model` otherwise labels/cards as
 *  "<local-command-caveat>Caveat: …" instead of what the human typed. */
const HARNESS_TAG_SPAN_RE =
  /<(system-reminder|local-command-caveat|local-command-stdout|local-command-stderr|command-name|command-message|command-args|command-contents)>[\s\S]*?<\/\1>/gi;

/** Drop every harness-injected tag span from a user message body. */
export function stripHarnessTags(s: string): string {
  return s.replace(HARNESS_TAG_SPAN_RE, "\n");
}

/**
 * Reduce a candidate user message to a clean label: drop the harness-injected
 * tag spans (the actual prompt is buried under them in Claude Code turns),
 * then return the first line that carries real text — skipping
 * blanks and bracketed placeholders like `[system-reminder]` / `[tool_result]`.
 * Returns null if nothing human-meaningful remains.
 */
function cleanPrompt(s: string): string | null {
  const lines = fromLastOpenclawEnvelope(stripOpenclawInternalContext(stripHarnessTags(s))).split("\n");
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i]!.trim().replace(OPENCLAW_ENVELOPE, "");
    if (!t) continue;
    if (t.endsWith(OPENCLAW_CONTEXT_MARKER)) {
      // an OpenClaw context header: its JSON fence goes with it
      if (lines[i + 1]?.trim().startsWith("```")) {
        i++;
        while (i + 1 < lines.length && lines[i + 1]!.trim() !== "```") i++;
        i++;
      }
      continue;
    }
    if (/^\[[^\]]*\]$/.test(t)) continue; // placeholder: [system-reminder], [tool_result], …
    if (/^<\/?[a-z][\w-]*>?$/i.test(t)) continue; // a lone (possibly truncated) tag line
    return t;
  }
  return null;
}

/** OpenClaw prefixes every user turn with its wall-clock envelope
 *  (`[Sun 2026-09-27 07:45 GMT+9] Read the notes`); the label is the prompt
 *  after it, so every OpenClaw row does not start with the same timestamp. */
const OPENCLAW_ENVELOPE =
  /^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?(?: [A-Za-z]{1,5}(?:[+-]\d{1,2}(?::?\d{2})?)?)?\]\s+/;
/** The same envelope anywhere at a line start. */
const OPENCLAW_ENVELOPE_LINE =
  /^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?(?: [A-Za-z]{1,5}(?:[+-]\d{1,2}(?::?\d{2})?)?)?\][ \t]+/gm;

/** OpenClaw's provenance marker at the end of each context header it puts
 *  before the human's text (2026.9.x inbound-context-marker.ts:
 *  `Conversation info: ⟦openclaw:ctx⟧`, then a ```json fence). */
const OPENCLAW_CONTEXT_MARKER = "⟦openclaw:ctx⟧";

/** OpenClaw 2026.9.x's internal-context block (active exec sessions,
 *  subagents), sent as a user text of its own; never the prompt. */
const OPENCLAW_INTERNAL_CONTEXT_RE = /^<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>$[\s\S]*?^<<<END_OPENCLAW_INTERNAL_CONTEXT>>>$/gm;

function stripOpenclawInternalContext(s: string): string {
  return s.replace(OPENCLAW_INTERNAL_CONTEXT_RE, "\n");
}

/** The human's text follows OpenClaw's LAST envelope; everything before it
 *  (the sender or conversation header, earlier context) is OpenClaw's. The
 *  prompt filter places it the same way (anthropic-proxy prompt-filter.ts
 *  openclawPieces). A text with no envelope is returned whole. */
function fromLastOpenclawEnvelope(s: string): string {
  let last = -1;
  OPENCLAW_ENVELOPE_LINE.lastIndex = 0;
  for (let m = OPENCLAW_ENVELOPE_LINE.exec(s); m !== null; m = OPENCLAW_ENVELOPE_LINE.exec(s)) last = m.index;
  return last < 0 ? s : s.slice(last);
}

/** Best-effort JSON parse; returns null on any failure (incl. truncated JSON). */
function tryJson(text: string): Record<string, unknown> | null {
  const t = text.trimStart();
  if (!t.startsWith("{") && !t.startsWith("[")) return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Flatten Anthropic message content (string | block[]) to text, for label use. */
function contentToText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .map((b) => {
      const block = (b ?? {}) as Record<string, unknown>;
      return block.type === "text" ? String(block.text ?? "") : "";
    })
    .filter(Boolean)
    .join("\n");
}

/**
 * Extract the first user-authored prompt from a `tllm_call` input summary,
 * tolerant of every shape the field has carried:
 *   1. the `▸ user` transcript (current proxy output),
 *   2. a raw Anthropic request JSON `{messages:[{role:"user",…}]}` (legacy),
 *   3. an inline `"… user: <prompt> …"` summary (legacy fixtures),
 *   4. otherwise the first non-empty line.
 * Returns null only for empty input.
 */
export function firstUserPrompt(text: unknown): string | null {
  if (typeof text !== "string" || !text.trim()) return null;

  const transcript = parseTranscript(text);
  if (transcript) {
    // The first user message can be harness-only (an @-mention pre-read
    // reminder): take the first one that carries a prompt.
    for (const user of transcript.filter((m) => /^user$/i.test(m.role))) {
      const p = cleanPrompt(user.body);
      if (p) return p;
    }
  }

  const json = tryJson(text);
  if (json && Array.isArray(json.messages)) {
    for (const m of json.messages as Array<Record<string, unknown>>) {
      if (m && /^user$/i.test(String(m.role))) {
        const p = cleanPrompt(contentToText(m.content));
        if (p) return p;
      }
    }
  }

  // A raw Anthropic request JSON that is TRUNCATED (legacy events: the proxy
  // capped input.symbolized at 4096 chars, so the strict parse above fails) —
  // salvage the first user message's text with a tolerant regex.
  const loose = looseUserFromRequestJson(text);
  if (loose) return loose;

  const inline = /(?:^|[\s.])user:\s*([^\n]+)/i.exec(text);
  if (inline) {
    const p = cleanPrompt(inline[1]!.replace(/\s+(?:assistant|system|tool):\s.*$/i, ""));
    if (p) return p;
  }

  // Last resort: a non-empty line — but never dump a raw JSON request (an old,
  // truncated event whose real prompt fell off the length cap is unrecoverable;
  // return null so the sidebar shows the scope id instead of a JSON blob).
  if (/^\s*[{[]/.test(text)) return null;
  // Nor a transcript's own role marker ("▸ system" over a header the parse
  // could not split): that names no prompt.
  if (transcript) return null;
  return cleanPrompt(text);
}

/** Unescape a JSON string body (the contents BETWEEN the quotes). */
function jsonUnescape(s: string): string {
  try {
    return JSON.parse(`"${s}"`) as string;
  } catch {
    return s;
  }
}

/**
 * Pull the first user message's text out of a (possibly truncated) Anthropic
 * request JSON with a tolerant regex — handles the block form
 * (`"role":"user" … "text":"…"`) and the string-content shorthand
 * (`"role":"user","content":"…"`). Used to salvage legacy events whose
 * input.symbolized is the raw, length-capped request JSON.
 */
function looseUserFromRequestJson(text: string): string | null {
  if (!text.includes('"role"') || !text.includes('"user"')) return null;
  const block = /"role"\s*:\s*"user"[\s\S]{0,400}?"text"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(text);
  if (block) {
    const s = cleanPrompt(jsonUnescape(block[1]!));
    if (s) return s;
  }
  const str = /"role"\s*:\s*"user"\s*,\s*"content"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(text);
  if (str) {
    const s = cleanPrompt(jsonUnescape(str[1]!));
    if (s) return s;
  }
  return null;
}

/** Cap a derived label, marking elision with an ellipsis (no byte-count noise). */
export function truncateLabel(s: string, max = 72): string {
  return s.length <= max ? s : s.slice(0, max - 1).trimEnd() + "…";
}

/**
 * A short relative-time string ("just now", "3m ago", "2h ago", "5d ago", or an
 * ISO date for older). `nowMs` is passed in so the function stays pure/testable;
 * the browser passes `Date.now()`.
 */
export function relativeTime(iso: string | null | undefined, nowMs: number): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.round((nowMs - t) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 7) return `${d}d ago`;
  return localDayKey(t);
}

/**
 * The LOCAL wall-clock an event happened ("14:32", 24h, zero-padded) — the
 * sidebar session row's start time (the date lives on its batch header, so the
 * row shows only the time of day). Unparseable/absent → "".
 */
export function clockLabel(iso: string | null | undefined): string {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const d = new Date(t);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/**
 * A compact elapsed-duration label ("42s", "3m 12s", "2h 5m") for the sidebar's
 * per-session/per-batch runtime. Negative/non-finite → "" (the caller shows
 * nothing rather than a lie).
 */
export function elapsedLabel(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] as const;

/** Intl formatters are expensive to construct and localDayKey runs once per
 *  session; memoize per zone. A zone Intl rejects caches as null (asked once). */
const DAY_FORMATTERS = new Map<string, Intl.DateTimeFormat | null>();

function dayFormatter(tz: string): Intl.DateTimeFormat | null {
  if (!DAY_FORMATTERS.has(tz)) {
    let f: Intl.DateTimeFormat | null = null;
    try {
      f = new Intl.DateTimeFormat("en-US", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" });
    } catch {
      f = null; // not a valid IANA zone — caller falls back to the ambient one
    }
    DAY_FORMATTERS.set(tz, f);
  }
  return DAY_FORMATTERS.get(tz) ?? null;
}

/**
 * The calendar day (`YYYY-MM-DD`) an instant (epoch ms or ISO string) falls on
 * **in the zone `tz`** — or, with `tz` omitted, in the ambient zone of whatever
 * process is running (the browser's zone on the client). Unparseable/absent ts →
 * "undated"; an unknown `tz` degrades to the ambient zone rather than throwing.
 *
 * The single date basis for every day the sidebar shows, and it must NOT be
 * `toISOString().slice(0, 10)` (UTC), because the clock printed next to it is
 * the viewer's wall-clock (clockLabel). Mixing the two makes the day header and
 * the clock disagree across a UTC midnight: for a KST (UTC+9) viewer a session
 * at 06:00 on the 12th is 21:00Z on the 11th, so a UTC key files it under the
 * 11th while its row reads "06:00" — everything before 09:00 local lands in the
 * previous day's group.
 *
 * `tz` is explicit because the SERVER also buckets days, and the server's own
 * zone is not the viewer's: the docker rig runs the dashboard in a UTC container
 * that a KST browser watches on :4500. So the client sends its resolved zone
 * (api-routes `?tz=`) and the server keys days in THAT zone; it never guesses.
 * Twin of public/js/transcript.js.
 */
export function localDayKey(ts: number | string | null | undefined, tz?: string): string {
  const t = typeof ts === "number" ? ts : ts ? Date.parse(ts) : NaN;
  if (!Number.isFinite(t)) return "undated";
  const d = new Date(t);
  if (tz) {
    const f = dayFormatter(tz);
    if (f) {
      const p: Record<string, string> = {};
      for (const part of f.formatToParts(d)) p[part.type] = part.value;
      if (p.year && p.month && p.day) return `${p.year}-${p.month}-${p.day}`;
    }
  }
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${mo}-${day}`;
}

/**
 * Prettify a per-day batch title (a LOCAL `YYYY-MM-DD` from session-batches
 * `day:` groups — see localDayKey): "Today", "Yesterday", "Jun 21", or
 * "Jun 21, 2025" when the year differs from now's. `nowMs` is passed in so the
 * function stays pure/testable; the browser passes `Date.now()`. Anything that
 * isn't an ISO day (e.g. "undated") passes through unchanged.
 *
 * Both days come from the ONE `nowMs` (never a second clock read), and
 * yesterday is the calendar day before today, not `nowMs - 24 h`: in the first
 * hour after a 23-hour (DST spring-forward) day, 24 hours back is the day
 * BEFORE yesterday, which used to drop the "Yesterday" name.
 */
export function dayLabel(day: string, nowMs: number): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day || "");
  if (!m) return day || "";
  const today = localDayKey(nowMs);
  if (day === today) return "Today";
  const n = new Date(nowMs);
  const yesterday = localDayKey(new Date(n.getFullYear(), n.getMonth(), n.getDate() - 1, 12).getTime());
  if (day === yesterday) return "Yesterday";
  const [, y, mo, d] = m;
  const month = MONTHS[Number(mo) - 1] ?? mo;
  const dayNum = String(Number(d));
  return y === today.slice(0, 4) ? `${month} ${dayNum}` : `${month} ${dayNum}, ${y}`;
}
