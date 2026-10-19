/**
 * forwarded-placeholders — where Mandu's placeholders sat in a tool result a
 * model proxy forwarded to the model in clear, and a digest of that text, by
 * tool-call id (confidentiality.md §6, "OpenClaw's history redacts
 * placeholders", *Across a relaunch*; 2026-10-11).
 *
 * OpenClaw keeps every tool result in its history through its own redaction
 * (a secret-looking value becomes its first 6 characters, `…`, its last 4,
 * or `***`), and Mandu's placeholders look like secrets to it: the per-key
 * twin of `.env` the model got in clear comes back, on every later turn, as
 * `STRIPE_KEY='$MDU:n…_KEY'`, which is no twin, so it would be masked whole.
 * The anthropic-proxy puts the forwarded text back (openclaw-redaction.ts).
 * Within a launch it remembers the text; a relaunch that resumes the
 * conversation re-sends the history to a proxy that never saw it, so the
 * proxy also records, here, what it needs to rebuild the text from the
 * redacted history:
 *
 *   - the placeholders of the text, each with its offset (Mandu's own
 *     symbol tokens: the symbol table holds every one of them, with the
 *     value it stands for);
 *   - a SHA-256 digest of the call id and the text (the proxy computes and
 *     checks it; the arbiter only keeps it).
 *
 * NO OTHER BYTE OF THE TEXT. Every placeholder must be exactly one symbol
 * token of the active format, or the record is refused, so nothing but
 * tokens, offsets and a digest can land in this table: it is no copy of the
 * results the model read, and no new store of anything the symbol table
 * does not already hold (it holds the tokens AND their values). The digest
 * is a one-way function of a text the model already received; reading this
 * table tells less than reading the symbol table beside it.
 *
 * The key is the tool-call id alone, as for `forwarded_clear` (the provider
 * mints it, OpenClaw keeps it verbatim in its transcript, and a resume
 * re-sends it), and the digest binds the record to that id: a record found
 * under another conversation's id rebuilds nothing that conversation's
 * history does not match byte for byte. A whole table of its own, so a file
 * of the previous schema is adopted (symbol-table.ts `ADDITIVE_FROM`).
 * Bounded: past {@link MAX_ROWS} the oldest rows go first, which only loses
 * a restore (the result is then masked whole: over-masking, never a leak).
 *
 * Mandu-new (no reference origin).
 */
import Database from "../db/sqlite.js";
import { getSymbolDbPath } from "./symbol-table.js";
import { getActiveFormat } from "./symbol-format.js";
import { isCallId } from "./forwarded-clear.js";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS forwarded_placeholders (
  call_id      TEXT PRIMARY KEY,
  digest       TEXT NOT NULL,
  placeholders TEXT NOT NULL,
  recorded_at  INTEGER NOT NULL
);
`;

/** Rows kept (an OpenClaw result that carried a placeholder, many sessions). */
export const MAX_ROWS = 100_000;
/** Maps per record request, and ids per read. */
export const MAX_MAPS_PER_REQUEST = 1_000;
export const MAX_IDS_PER_REQUEST = 10_000;
/** Placeholders per result, the longest token, the furthest offset. */
export const MAX_PLACEHOLDERS = 256;
export const MAX_TOKEN_LENGTH = 512;
export const MAX_OFFSET = 1 << 20;

/** One forwarded result's record: offsets in UTF-16 code units of the text. */
export interface PlaceholderMap {
  callId: string;
  /** Lowercase hex SHA-256 the proxy computed over the call id and the text. */
  digest: string;
  placeholders: Array<[number, string]>;
}

/**
 * The record a proxy sent, validated, or a reason it is skipped: the call id
 * is a call id, the digest 64 lowercase hex digits, and the placeholders
 * 1..{@link MAX_PLACEHOLDERS} `[offset, token]` pairs in increasing,
 * non-overlapping order where each token is EXACTLY one symbol token of the
 * active format (so no other text can be stored). Pure.
 */
export function parsePlaceholderMap(x: unknown): PlaceholderMap | string {
  if (x === null || typeof x !== "object" || Array.isArray(x)) return "not an object";
  const r = x as Record<string, unknown>;
  if (!isCallId(r["callId"])) return "callId is not a tool-call id";
  if (typeof r["digest"] !== "string" || !/^[0-9a-f]{64}$/.test(r["digest"])) return "digest is not 64 lowercase hex digits";
  const ph = r["placeholders"];
  if (!Array.isArray(ph) || ph.length === 0 || ph.length > MAX_PLACEHOLDERS) return `placeholders must be 1 to ${MAX_PLACEHOLDERS} pairs`;
  const whole = new RegExp(`^(?:${getActiveFormat().pattern.source})$`);
  const out: Array<[number, string]> = [];
  let end = 0;
  for (const p of ph) {
    if (!Array.isArray(p) || p.length !== 2) return "a placeholder is not an [offset, token] pair";
    const [offset, token] = p as [unknown, unknown];
    if (typeof offset !== "number" || !Number.isSafeInteger(offset) || offset < end || offset > MAX_OFFSET) return "placeholder offsets must increase and not overlap";
    if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH || !whole.test(token)) return "a placeholder is not exactly one symbol token";
    out.push([offset, token]);
    end = offset + token.length;
  }
  return { callId: r["callId"] as string, digest: r["digest"] as string, placeholders: out };
}

export class ForwardedPlaceholderStore {
  private readonly db: InstanceType<typeof Database>;
  private readonly maxRows: number;

  constructor(opts: { dbPath?: string; maxRows?: number } = {}) {
    this.db = new Database(opts.dbPath ?? getSymbolDbPath());
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA_SQL);
    this.maxRows = opts.maxRows ?? MAX_ROWS;
  }

  /** Record validated maps (a later record of an id replaces it). Returns
   *  how many were written. */
  record(maps: readonly PlaceholderMap[], now: number = Date.now()): number {
    const put = this.db.prepare("INSERT OR REPLACE INTO forwarded_placeholders (call_id, digest, placeholders, recorded_at) VALUES (?, ?, ?, ?)");
    const tx = this.db.transaction((list: readonly PlaceholderMap[]) => {
      for (const m of list) put.run(m.callId, m.digest, JSON.stringify(m.placeholders), now);
    });
    tx(maps);
    const rows = Number((this.db.prepare("SELECT COUNT(*) AS n FROM forwarded_placeholders").get() as { n: number | bigint }).n);
    if (rows > this.maxRows) {
      this.db.prepare("DELETE FROM forwarded_placeholders WHERE rowid IN (SELECT rowid FROM forwarded_placeholders ORDER BY rowid LIMIT ?)").run(rows - this.maxRows);
    }
    return maps.length;
  }

  /** The recorded maps of `ids`, in the order asked (unknown ids left out). */
  known(ids: readonly string[]): PlaceholderMap[] {
    const get = this.db.prepare("SELECT digest, placeholders FROM forwarded_placeholders WHERE call_id = ?");
    const out: PlaceholderMap[] = [];
    for (const id of ids) {
      const row = get.get(id) as { digest: string; placeholders: string } | undefined;
      if (!row) continue;
      try {
        const parsed = parsePlaceholderMap({ callId: id, digest: row.digest, placeholders: JSON.parse(row.placeholders) });
        if (typeof parsed !== "string") out.push(parsed);
      } catch {
        /* a row that does not parse rebuilds nothing */
      }
    }
    return out;
  }

  close(): void {
    try { this.db.close(); } catch { /* double-close must not throw */ }
  }
}
