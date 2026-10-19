/**
 * openclaw-redaction — undo OpenClaw's own redaction of a tool result the
 * proxy already forwarded in clear (confidentiality.md §6, "OpenClaw's
 * history redacts placeholders", 2026-10-11).
 *
 * OpenClaw redacts every tool payload it keeps in its session history
 * (openclaw `src/logging/redact.ts`; on 2026.9 the transcript store's
 * `redactTranscriptMessage`, which keeps `toolCall.id` and
 * `toolResult.toolCallId` verbatim and redacts the result's text): a value
 * that looks like a secret (`STRIPE_KEY='…'`, `Bearer …`, a URL's password,
 * a JSON `"api_key"`, `ghp_…`) becomes `maskToken(value)`, its first 6
 * characters, `…`, its last 4, or `***` (under 18 characters, and on some
 * patterns whatever the length: `{"api_key": "***"}`). Mandu's placeholders
 * look like secrets to it, so the structured twin of `.env` the model got in
 * clear on the turn of the read (`STRIPE_KEY='$MDU:nomodel_Read[e7f3].STRIPE_KEY'`)
 * comes back on every later turn as `STRIPE_KEY='$MDU:n…_KEY'`. That is no
 * twin, so the arbiter masked the whole result "after the fact", and the
 * model, left with one handle for the whole file, could no longer use the
 * key on its own (seen walking the first-session tour live).
 *
 * THE RESTORE. When a later request carries, under a tool-call id, a text
 * that is exactly OpenClaw's redaction (`isOpenclawRedactionOf`) of the text
 * this proxy forwarded in clear under that id, the forwarded text is put
 * back BEFORE the result is classified, and the whole pipeline then decides
 * it as it decided it the first time (a file labelled since is masked, with
 * the after-the-fact note). Two sources for "the text forwarded under that
 * id":
 *
 *   1. this launch's memory (`ForwardedResultMemory`, by id, bounded);
 *   2. across a relaunch that resumes the conversation, the arbiter's
 *      placeholder record (mandu.db `forwarded_placeholders`): for each
 *      result forwarded in clear that carried a placeholder, the
 *      placeholders with their offsets and a SHA-256 digest of the call id
 *      and the text (`placeholderMapOf`). The next launch rebuilds the text
 *      from the redacted history (`rebuildFromPlaceholders`): the text
 *      between placeholders is copied from the history as it stands, each
 *      placeholder's redacted form is replaced by the recorded token, and
 *      the result is accepted only when its digest is the recorded one. The
 *      record holds no other byte of the text (the arbiter refuses a
 *      "placeholder" that is not exactly one symbol token), so it is no new
 *      store of anything the symbol table does not already hold.
 *
 * WHY A FORGED REDACTION CANNOT UN-MASK ANYTHING. The text that comes back
 * is the one this proxy forwarded under that id, byte for byte: from memory
 * by construction, from the arbiter record because its SHA-256 matches the
 * digest a Mandu proxy recorded, on the human plane the agent's processes
 * cannot reach, for that id. A history (a model, a file, an edited
 * transcript) can at most choose, by its call id, WHICH of Mandu's own
 * forwarded texts comes back, a text the model already received under that
 * id; a rebuild only ever supplies placeholder characters (every other byte
 * is the history's own). The restored text is then
 * judged again like any result: what is secret now is masked. Nothing new
 * reaches the model: the text went to it under that id already.
 *
 * Mandu-new (no reference origin).
 */

import { createHash } from "node:crypto";
import type { PlaceholderMapWire } from "./arbiter-client.js";

/** OpenClaw's `maskToken` floor: a value shorter than this becomes `***`. */
const MASK_MIN_LENGTH = 18;
/** Characters `maskToken` keeps before the ellipsis, and after it. */
const KEEP_START = 6;
const KEEP_END = 4;
/** The largest text the matcher looks at (a twin is a small file). */
export const REDACTION_MATCH_MAX = 256 * 1024;

type Piece = { lit: string } | { min: number; max: number };

/**
 * Is `redacted` exactly what OpenClaw's redaction makes of `original`: the
 * same text with one or more spans replaced by `…` (keeping, around it, the
 * span's first 6 and last 4 characters, so at least 8 characters hidden) or
 * by `***` (a span of any length: under 18 characters by `maskToken`, any
 * length by `maskSecretValue`, both read off OpenClaw 2026.7.1 and 2026.9.9)?
 * At least one mask, and the two differ. Pure, linear in the text (every gap
 * is unbounded above, so placing each literal piece at its earliest position
 * is exact).
 */
export function isOpenclawRedactionOf(redacted: string, original: string): boolean {
  if (typeof redacted !== "string" || typeof original !== "string") return false;
  if (redacted === original || redacted.length > REDACTION_MATCH_MAX || original.length > REDACTION_MATCH_MAX) return false;
  const pieces: Piece[] = [];
  let lit = "";
  let masks = 0;
  for (let i = 0; i < redacted.length; ) {
    if (redacted[i] === "…") {
      // the kept 6 and 4 characters stay literal around the hidden span
      if (lit.length < KEEP_START) return false;
      pieces.push({ lit }, { min: MASK_MIN_LENGTH - KEEP_START - KEEP_END, max: Infinity });
      lit = "";
      masks++;
      i++;
      continue;
    }
    if (redacted.startsWith("***", i)) {
      pieces.push({ lit }, { min: 1, max: Infinity });
      lit = "";
      masks++;
      i += 3;
      continue;
    }
    lit += redacted[i];
    i++;
  }
  pieces.push({ lit });
  if (masks === 0) return false;
  // every `…` is followed by its 4 kept characters
  for (let k = 1; k < pieces.length; k++) {
    const gap = pieces[k - 1];
    const next = pieces[k];
    if (gap && "min" in gap && gap.min === MASK_MIN_LENGTH - KEEP_START - KEEP_END && next && "lit" in next && next.lit.length < KEEP_END) return false;
  }
  let pos = 0;
  let gap: { min: number; max: number } | null = null;
  for (let k = 0; k < pieces.length; k++) {
    const p = pieces[k]!;
    if ("min" in p) {
      // two masks in a row (`******`): one gap at least as long as both
      gap = gap ? { min: gap.min + p.min, max: Infinity } : p;
      continue;
    }
    const last = k === pieces.length - 1;
    if (gap === null) {
      if (!original.startsWith(p.lit, pos)) return false;
      pos += p.lit.length;
      continue;
    }
    const from = pos + gap.min;
    let at: number;
    if (last) {
      at = original.length - p.lit.length;
      if (at < from || !original.endsWith(p.lit)) return false;
    } else {
      at = p.lit === "" ? from : original.indexOf(p.lit, from);
      if (at < 0) return false;
    }
    if (at - pos > gap.max) return false;
    pos = at + p.lit.length;
    gap = null;
  }
  return gap === null ? pos === original.length : original.length - pos >= gap.min && original.length - pos <= gap.max;
}

/** An OpenClaw session's gate surface (the arbiter's spec id, either
 *  spelling rewrite-request.ts `symbolValueFor` accepts). Pure. */
export function isOpenclawSurface(surface: { spec: string } | undefined): boolean {
  return surface?.spec === "openclaw-agent" || surface?.spec === "openclaw";
}

// ── the placeholder record (across a relaunch) ───────────────────────────────

/** Mandu's symbol token (the arbiter's grammar; net-gate.ts SYMBOL_RE). */
const PLACEHOLDER_RE = /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*/g;
/** The arbiter's bounds on one record (symbol-table/forwarded-placeholders.ts). */
const MAX_PLACEHOLDERS = 256;
const MAX_TOKEN_LENGTH = 512;
/** Domain of the digest, so it can be no other digest of the same text. */
const DIGEST_DOMAIN = "mandu.openclaw-forwarded.v1";

/** The digest a record carries: SHA-256 over the call id and the text. Pure. */
export function forwardedDigest(callId: string, text: string): string {
  return createHash("sha256").update(`${DIGEST_DOMAIN}\0${callId}\0${text}`, "utf8").digest("hex");
}

/**
 * The record of a text forwarded in clear under `callId`: its placeholders
 * with their offsets (UTF-16 code units) and its digest; null when it
 * carries no placeholder (OpenClaw's redaction of it then changes no
 * verdict: nothing to rebuild) or exceeds the record's bounds. Pure.
 */
export function placeholderMapOf(callId: string, text: string): PlaceholderMapWire | null {
  if (typeof text !== "string" || text.length > REDACTION_MATCH_MAX || !text.includes("$MDU:")) return null;
  const placeholders: Array<[number, string]> = [];
  for (const m of text.matchAll(PLACEHOLDER_RE)) {
    if (m[0].length > MAX_TOKEN_LENGTH || placeholders.length >= MAX_PLACEHOLDERS) return null;
    placeholders.push([m.index!, m[0]]);
  }
  return placeholders.length ? { callId, digest: forwardedDigest(callId, text), placeholders } : null;
}

/** Bounds of a rebuild's search (a placeholder whose redacted form could be
 *  read at more than one length). Exceeding them only loses the restore. */
const REBUILD_MAX_STEPS = 20_000;
const REBUILD_MAX_CANDIDATES = 64;

/**
 * The text `map` records, rebuilt from `redacted` (OpenClaw's history copy
 * of it), or undefined. Walks the record in order: the text before each
 * placeholder is copied from the history at its recorded length, and the
 * history's form of the placeholder (verbatim, or OpenClaw's redaction of
 * it) is replaced by the recorded token; the text after the last one is
 * copied as it stands. Accepted ONLY when the digest is the recorded one
 * (so it is byte for byte the text Mandu forwarded under that id) and the
 * history is exactly OpenClaw's redaction of it. Pure.
 */
export function rebuildFromPlaceholders(redacted: string, map: PlaceholderMapWire): string | undefined {
  if (typeof redacted !== "string" || redacted.length > REDACTION_MATCH_MAX) return undefined;
  if (!redacted.includes("…") && !redacted.includes("***")) return undefined;
  const ph = map.placeholders;
  if (!Array.isArray(ph) || ph.length === 0) return undefined;
  let steps = REBUILD_MAX_STEPS;
  let candidates = REBUILD_MAX_CANDIDATES;
  const parts: string[] = [];
  const go = (k: number, r: number, o: number): string | undefined => {
    if (--steps < 0 || candidates <= 0) return undefined;
    if (k === ph.length) {
      candidates--;
      const text = parts.join("") + redacted.slice(r);
      return text !== redacted && forwardedDigest(map.callId, text) === map.digest && isOpenclawRedactionOf(redacted, text) ? text : undefined;
    }
    const [off, tok] = ph[k]!;
    if (typeof off !== "number" || typeof tok !== "string" || off < o) return undefined;
    const at = r + (off - o);
    if (at > redacted.length) return undefined;
    const lens: number[] = [];
    if (redacted.startsWith(tok, at)) lens.push(tok.length);
    // `***` for a span of one or two characters makes the form longer
    const maxLen = Math.min(redacted.length - at, tok.length + 2);
    for (let len = 1; len <= maxLen; len++) {
      const form = redacted.slice(at, at + len);
      if (form !== tok && isOpenclawRedactionOf(form, tok)) lens.push(len);
    }
    for (const len of lens) {
      parts.push(redacted.slice(r, at), tok);
      const got = go(k + 1, at + len, off + tok.length);
      parts.length -= 2;
      if (got !== undefined) return got;
    }
    return undefined;
  };
  return go(0, 0, 0);
}

/** Where the records outlive this proxy: the arbiter (proxy.ts builds it
 *  over the `Arbiter`'s `forwardedPlaceholders` / `recordForwardedPlaceholders`). */
export interface PlaceholderStore {
  known(ids: string[]): Promise<PlaceholderMapWire[]>;
  record(maps: PlaceholderMapWire[]): Promise<void>;
}

/** The store over a proxy's arbiter, or undefined when it lacks either op:
 *  the restore then lasts this launch. */
export function arbiterPlaceholderStore(arbiter: {
  forwardedPlaceholders?(ids: string[]): Promise<PlaceholderMapWire[]>;
  recordForwardedPlaceholders?(maps: PlaceholderMapWire[]): Promise<unknown>;
}): PlaceholderStore | undefined {
  const known = arbiter.forwardedPlaceholders?.bind(arbiter);
  const record = arbiter.recordForwardedPlaceholders?.bind(arbiter);
  return known && record ? { known, record: async (maps) => { await record(maps); } } : undefined;
}

// ── the memory ───────────────────────────────────────────────────────────────

/** Bounds of the memory: results kept, and their total characters. */
export const FORWARDED_MEMORY_MAX_ENTRIES = 2000;
export const FORWARDED_MEMORY_MAX_CHARS = 8 * 1024 * 1024;
/** Records kept (the arbiter's answers and this proxy's own), ids asked. */
const MAX_MAPS = 20_000;
/** Ids per arbiter ask, maps per record (the arbiter's own limits are higher). */
const ASK_CHUNK = 1_000;
const RECORD_CHUNK = 200;

/** Is this result text possibly OpenClaw's redaction of something? */
const mayBeRedacted = (v: string): boolean => v.includes("…") || v.includes("***");

/** Put into a bounded insertion-ordered map, dropping the oldest. */
function setBounded<V>(m: Map<string, V>, k: string, v: V, max: number): void {
  m.delete(k);
  m.set(k, v);
  if (m.size > max) {
    const oldest = m.keys().next();
    if (!oldest.done) m.delete(oldest.value);
  }
}

/**
 * What this proxy forwarded in clear, by tool-call id (in memory, per
 * launch; oldest dropped first past the bounds, which only loses a restore),
 * and, with a store, the placeholder records that let a later launch
 * rebuild it.
 */
export class ForwardedResultMemory {
  private readonly texts = new Map<string, string>();
  private chars = 0;
  /** Records by id: the store's answers and this proxy's own. */
  private readonly maps = new Map<string, PlaceholderMapWire>();
  /** Ids the store was asked about and did not know. */
  private readonly asked = new Map<string, true>();
  /** Records not yet in the store. */
  private readonly unsaved = new Map<string, PlaceholderMapWire>();
  private readonly store: PlaceholderStore | undefined;
  private readonly log: (msg: string) => void;

  constructor(
    private readonly maxEntries = FORWARDED_MEMORY_MAX_ENTRIES,
    private readonly maxChars = FORWARDED_MEMORY_MAX_CHARS,
    opts: { store?: PlaceholderStore; log?: (msg: string) => void } = {},
  ) {
    this.store = opts.store;
    this.log = opts.log ?? (() => {});
  }

  get(id: string): string | undefined {
    return this.texts.get(id);
  }

  /** Remember a text this proxy forwarded in clear (call AFTER the rewrite
   *  succeeded); with a store, its placeholder record is queued for
   *  {@link flush}. */
  remember(id: string, text: string): void {
    if (typeof id !== "string" || typeof text !== "string" || text.length > REDACTION_MATCH_MAX) return;
    const had = this.texts.get(id);
    if (had !== text && this.store) {
      const map = placeholderMapOf(id, text);
      if (map && this.maps.get(id)?.digest !== map.digest) {
        setBounded(this.maps, id, map, MAX_MAPS);
        setBounded(this.unsaved, id, map, MAX_MAPS);
      }
    }
    this.keep(id, text);
  }

  private keep(id: string, text: string): void {
    const had = this.texts.get(id);
    if (had !== undefined) {
      this.chars -= had.length;
      this.texts.delete(id);
    }
    this.texts.set(id, text);
    this.chars += text.length;
    while (this.texts.size > this.maxEntries || this.chars > this.maxChars) {
      const oldest = this.texts.keys().next();
      if (oldest.done) break;
      this.chars -= this.texts.get(oldest.value)!.length;
      this.texts.delete(oldest.value);
    }
  }

  /** Send the queued records to the store. Never rejects: a failed record
   *  is retried with the next flush (and only a relaunch's restore is at
   *  stake). */
  async flush(): Promise<void> {
    if (!this.store || this.unsaved.size === 0) return;
    const pending = [...this.unsaved.values()];
    for (let i = 0; i < pending.length; i += RECORD_CHUNK) {
      const chunk = pending.slice(i, i + RECORD_CHUNK);
      try {
        await this.store.record(chunk);
      } catch (err) {
        this.log(`openclaw-redaction: could not record ${pending.length - i} forwarded result(s) with the arbiter (${(err as Error).message}); retried with the next request`);
        return;
      }
      for (const m of chunk) if (this.unsaved.get(m.callId) === m) this.unsaved.delete(m.callId);
    }
  }

  /** Before a request's rewrite: ask the store for the records of the
   *  results that may be OpenClaw's redaction of something and that this
   *  launch never forwarded (a resumed history's). Never throws: a failed
   *  ask only means no restore for those this time (masked whole). */
  async prime(results: Iterable<readonly [string, string]>): Promise<void> {
    if (!this.store) return;
    const wanted = new Set<string>();
    for (const [id, value] of results) {
      if (typeof id !== "string" || typeof value !== "string" || !mayBeRedacted(value)) continue;
      if (this.texts.has(id) || this.maps.has(id) || this.asked.has(id)) continue;
      wanted.add(id);
    }
    const ask = [...wanted];
    for (let i = 0; i < ask.length; i += ASK_CHUNK) {
      const chunk = ask.slice(i, i + ASK_CHUNK);
      let got: PlaceholderMapWire[];
      try {
        got = await this.store.known(chunk);
      } catch (err) {
        this.log(`openclaw-redaction: the arbiter could not say what earlier launches forwarded (${(err as Error).message}); a redacted result is judged as it is this time`);
        return;
      }
      const hit = new Set<string>();
      const inChunk = new Set(chunk);
      for (const m of Array.isArray(got) ? got : []) {
        if (m && typeof m.callId === "string" && inChunk.has(m.callId)) {
          setBounded(this.maps, m.callId, m, MAX_MAPS);
          hit.add(m.callId);
        }
      }
      for (const id of chunk) if (!hit.has(id)) setBounded(this.asked, id, true as const, MAX_MAPS);
    }
  }

  /** The text this proxy (or, through the store, an earlier launch's)
   *  forwarded under `id` when `value` is OpenClaw's redaction of it; else
   *  undefined. */
  restore(id: string, value: string): string | undefined {
    const before = this.texts.get(id);
    if (before !== undefined && isOpenclawRedactionOf(value, before)) return before;
    const map = this.maps.get(id);
    if (!map) return undefined;
    const rebuilt = rebuildFromPlaceholders(value, map);
    if (rebuilt !== undefined) this.keep(id, rebuilt);
    return rebuilt;
  }
}
