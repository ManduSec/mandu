/**
 * inbound — what Chrome sends the agent, masked before the agent reads it
 * (docs/design/agents/devtools-relay.md §3.1). Mandu-new (no reference
 * origin).
 *
 * Every DevTools message is JSON. The relay walks it and:
 *   1. withholds a credential header's value (cookies, authorization) and a
 *      cookie object's value, wherever they sit (policy.ts
 *      CREDENTIAL_HEADERS): the agent never needs them;
 *   2. withholds the whole message when it carries bytes the relay cannot
 *      read (`base64Encoded: true`, a binary WebSocket frame);
 *   3. sends every string (values AND object keys) of at least
 *      MIN_SCAN_LEN characters to the arbiter's prompt filter as `harness`
 *      text, one call per message, and puts back what it answers: a
 *      registered secret comes back as its `$MDU:*` symbol.
 * An arbiter that cannot answer, a held segment, or a blocked one with no
 * safe text → the message is withheld (fail-closed): the caller answers a
 * command with an error and drops an event.
 */
import type { Arbiter, FilteredSegment } from "./arbiter-client.js";
import { CREDENTIAL_HEADERS, WITHHELD_HEADER } from "./policy.js";

/** Shorter strings are not scanned: the arbiter's own floor for a value it
 *  fingerprints (arbiter/policy/egress-fingerprint.ts MIN_FINGERPRINT_LEN). */
export const MIN_SCAN_LEN = 8;

export type InboundVerdict =
  | { kind: "forward"; message: unknown }
  | { kind: "withhold"; reason: string };

export interface MaskDeps {
  arbiter: Arbiter;
  session?: string;
}

/** Step 1 and 2: credential values out, unreadable bytes refused. Pure. */
export function stripCredentials(value: unknown): { value: unknown; unreadable: boolean } {
  let unreadable = false;
  const visit = (v: unknown, key: string | null): unknown => {
    if (Array.isArray(v)) {
      return v.map((x) => {
        // Fetch / HAR form: [{name, value}]
        if (isRecord(x) && typeof x["name"] === "string" && CREDENTIAL_HEADERS.has(x["name"].toLowerCase()) && typeof x["value"] === "string") {
          return { ...visitRecord(x), value: WITHHELD_HEADER };
        }
        return visit(x, key);
      });
    }
    if (isRecord(v)) return visitRecord(v);
    if (typeof v === "string" && key !== null && /headerstext$/i.test(key)) return stripHeaderLines(v);
    return v;
  };
  const visitRecord = (r: Record<string, unknown>): Record<string, unknown> => {
    if (r["base64Encoded"] === true) unreadable = true;
    // A binary WebSocket frame (opcode 2) carries base64 bytes.
    if (r["opcode"] === 2 && typeof r["payloadData"] === "string") unreadable = true;
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(r)) {
      if (CREDENTIAL_HEADERS.has(k.toLowerCase())) {
        if (typeof x === "string") { out[k] = WITHHELD_HEADER; continue; }
        if (isRecord(x) && typeof x["value"] === "string") { out[k] = { ...visitRecord(x), value: WITHHELD_HEADER }; continue; }
      }
      out[k] = visit(x, k);
    }
    return out;
  };
  return { value: visit(value, null), unreadable };
}

/** A raw header block with its credential lines' values withheld. */
export function stripHeaderLines(text: string): string {
  return text
    .split(/(\r?\n)/)
    .map((line) => {
      const m = /^([A-Za-z0-9-]+):/.exec(line);
      return m && CREDENTIAL_HEADERS.has(m[1]!.toLowerCase()) ? `${m[1]}: ${WITHHELD_HEADER}` : line;
    })
    .join("");
}

/** Every string worth scanning (values and keys), de-duplicated. Pure. */
export function collectStrings(value: unknown, min = MIN_SCAN_LEN): string[] {
  const seen = new Set<string>();
  const visit = (v: unknown): void => {
    if (typeof v === "string") { if (v.length >= min) seen.add(v); return; }
    if (Array.isArray(v)) { for (const x of v) visit(x); return; }
    if (isRecord(v)) {
      for (const [k, x] of Object.entries(v)) {
        if (k.length >= min) seen.add(k);
        visit(x);
      }
    }
  };
  visit(value);
  return [...seen];
}

/** `value` with each string (value or key) found in `map` replaced. Pure. */
export function replaceStrings(value: unknown, map: ReadonlyMap<string, string>): unknown {
  if (map.size === 0) return value;
  const visit = (v: unknown): unknown => {
    if (typeof v === "string") return map.get(v) ?? v;
    if (Array.isArray(v)) return v.map(visit);
    if (isRecord(v)) {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) out[map.get(k) ?? k] = visit(x);
      return out;
    }
    return v;
  };
  return visit(value);
}

/** The arbiter's answers as a replacement map, or why the message must be
 *  withheld. Pure. */
export function replacementsFrom(texts: readonly string[], answers: readonly FilteredSegment[]): Map<string, string> | string {
  const byId = new Map(answers.map((a) => [a.id, a]));
  const map = new Map<string, string>();
  for (let i = 0; i < texts.length; i++) {
    const a = byId.get(segmentId(i));
    if (a === undefined) return "the filter did not answer every segment";
    if (a.action === "pass") continue;
    if (a.action === "hold") return "a filter finding waits for your answer";
    if (typeof a.text !== "string") return `a segment was ${a.action === "block" ? "blocked" : "rewritten"} with no safe text`;
    if (a.text !== texts[i]) map.set(texts[i]!, a.text);
  }
  return map;
}

export function segmentId(i: number): string {
  return `s${i}`;
}

/** Steps 1 to 3 over one message. Never throws. */
export async function maskMessage(message: unknown, deps: MaskDeps): Promise<InboundVerdict> {
  const stripped = stripCredentials(message);
  if (stripped.unreadable) return { kind: "withhold", reason: "it carries bytes the relay cannot read (base64)" };
  const texts = collectStrings(stripped.value);
  if (texts.length === 0) return { kind: "forward", message: stripped.value };
  let answers: FilteredSegment[];
  try {
    answers = await deps.arbiter.filterText(texts.map((text, i) => ({ id: segmentId(i), text })), deps.session);
  } catch (err) {
    return { kind: "withhold", reason: `the arbiter could not filter it (${(err as Error).message})` };
  }
  const map = replacementsFrom(texts, answers);
  if (typeof map === "string") return { kind: "withhold", reason: map };
  return { kind: "forward", message: replaceStrings(stripped.value, map) };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
