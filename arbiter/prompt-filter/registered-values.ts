/**
 * registered-values — the active secret rows of the symbol table as one
 * {@link ValueMatcher} (confidentiality-plan-15-prompt-filter.md §4.1).
 * Mandu-new (no reference origin).
 *
 * The rows are every ACTIVE row whose level is a secret, in the symbol map's
 * own order. Each row contributes its whole value (at or above
 * MIN_FINGERPRINT_LEN) and its pieces (`valueFingerprints`: a multi-line
 * value's long lines, MIN_LINE_FINGERPRINT_LEN; the value without its final
 * line terminator; its credential-shaped spans; for a row registered from a
 * labelled file, its bare credential tokens: plan 10 §11.15), exactly the
 * patterns `secretValueMatch` tests one `includes` at a time, less the lines of an
 * agent runtime's own result head at the start of a row the caller names
 * (`sync`'s `headOf`, plan 10 §11.14), and less the lines a registered
 * file's own structured twin carries verbatim (`sync`'s `twinOf`, plan 10
 * §11.8), and less, for a row the value backstop alone made secret, the long
 * lines no secret was found in (`sync`'s `keepLinesOf`, plan 15 §13.11).
 * Callers re-check each
 * hit's row LIVE (active, level, evidence) because a row can change in place;
 * the index only needs to hold every row that could be a secret.
 *
 * A large or binary row's pieces are computed window by window under a
 * bound (`valuePieces`, plan 10 §11.18); a row cut at the bound is listed by
 * `incompleteRows`, and a row of many pieces keeps an automaton of its own
 * (`OWN_AUTOMATON_PIECES`), so a new row does not rebuild it.
 *
 * Rebuilt when the symbol table changes: the symbol table bumps a generation
 * on every mutation it makes (`symbolMapGeneration`), and the index also
 * compares the map's size and identity, so a row added past those functions
 * still invalidates it. A rebuild whose row set is unchanged (a public row
 * was added) keeps the automaton and its content version.
 */

import { createHash } from "node:crypto";

import { valuePieces, DEFAULT_PIECE_LIMITS, MIN_FINGERPRINT_LEN, MIN_LINE_FINGERPRINT_LEN, fingerprintableValue, type FingerprintHit, type PieceLimits, type SecretFingerprint, type ValueTwin } from "../policy/egress-fingerprint.js";
import { destinationIsBound } from "../policy/session-egress.js";
import { locateSecretShapes } from "../policy/secret-detectors.js";
import { isSecret } from "../symbol-table/confidentiality.js";
import { symbolMapGeneration, type SymbolEntry, type SymbolMap } from "../symbol-table/symbol-table.js";
import { envRowVariable, isRegisteredFileRow } from "../secret-registry/registry.js";
import { fieldLastName, passwordKind, shortTokenValue, tokenBounded } from "../policy/credential-names.js";
import { ValueMatcher } from "./value-matcher.js";

/** How a row matched: its whole value, or one of its long lines. */
export type ValueHow = "value" | "line";

/** One pattern of the index: a row's whole value or one of its lines.
 *  `token`: a short password's value, matched as a whole token only
 *  ({@link shortTokenRow}). */
interface Pattern {
  row: number;
  how: ValueHow;
  token?: true;
}

/**
 * THE SHORT-TOKEN RULE (2026-10-19, secret-discovery.md §2.9, "The
 * tripwire"): a row whose value is under the general floor
 * (MIN_FINGERPRINT_LEN, 8) is still a pattern, matched as a WHOLE TOKEN
 * (credential-names.ts `tokenBounded`), when it is a PASSWORD: a field of a
 * registered file under a password's name (`db.password`, `smtp.pass`,
 * `app.db_pw`, a `.pgpass` or `.netrc` password), or a password variable's
 * row (`PGPASSWORD`, `SMTP_PASS`), whose value of 6 or 7 characters
 * `shortTokenValue` takes (a letter with a digit or a mark, no default, no
 * stand-in). So `password = Tr0ub4` in a labelled `config.ini` is masked
 * where it turns up verbatim in an output and trips the tripwire on the
 * wire, while `pin = 4821` (digits only: a number any body may hold) and
 * every other short value stay under the floor. Pure.
 */
export function shortTokenRow(e: Pick<SymbolEntry, "value" | "tool" | "call_id" | "origin" | "integrity" | "field">): boolean {
  if (fingerprintableValue(e.value)) return false;
  let name: string | null = null;
  if (isRegisteredFileRow(e)) name = e.field === null ? null : fieldLastName(e.field);
  else name = envRowVariable(e);
  return name !== null && passwordKind(name) === "password" && shortTokenValue(e.value, MIN_FINGERPRINT_LEN);
}

/** One verbatim occurrence of a row's value or line, at [start, end). */
export interface ValueOccurrence {
  symbol: string;
  how: ValueHow;
  /** The matched text (the value, or the line). */
  text: string;
  start: number;
  end: number;
}

/** True when a row may be indexed: active and labelled a secret. */
export function indexableRow(e: SymbolEntry): boolean {
  return e.obsoleted_at === null && isSecret(e.confidentiality);
}

/**
 * The lines of `value` (0-based, split at `\n`) that overlap any of `spans`
 * ([start, end) offsets of registered secrets found in it): the lines that
 * made a row the value backstop raised secret (plan 15 §13.11, "What a raised
 * row registers"). A span across a line break keeps every line it touches.
 * Pure.
 */
export function raisedRowKeptLines(value: string, spans: ReadonlyArray<{ start: number; end: number }>): Set<number> {
  const kept = new Set<number>();
  if (spans.length === 0) return kept;
  // Line i covers [starts[i], ends[i]) (its terminator excluded).
  const starts: number[] = [0];
  for (let i = value.indexOf("\n"); i !== -1; i = value.indexOf("\n", i + 1)) starts.push(i + 1);
  const lineAt = (offset: number): number => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= offset) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
  for (const s of spans) {
    if (s.end <= s.start) continue;
    const a = lineAt(s.start);
    const b = lineAt(s.end - 1);
    for (let i = a; i <= b; i++) kept.add(i);
  }
  return kept;
}

/**
 * The pieces of a row the value backstop raised (plan 15 §13.11, "What a raised
 * row registers"): `pieces` (`valuePieces` of `value`) less every long line
 * that is NOT one of `keep` (the lines a registered secret was found in,
 * `raisedRowKeptLines`). A dropped line is ordinary text of the tool's output
 * (a heading, `}`, a log line), not what made the row secret: as a piece it
 * masked every later result that shared it. Kept whatever `keep` says: a line
 * with a credential-shaped span in it (`locateSecretShapes`), and the value
 * without its final line break. The whole value and every credential-shaped
 * span stay pieces (they are not lines). Pure.
 */
export function raisedRowPieces(value: string, pieces: readonly string[], keep: ReadonlySet<number>): string[] {
  const kept = new Set<string>();
  const drop = new Set<string>();
  value.split("\n").forEach((raw, i) => {
    const line = raw.trim();
    if (line.length < MIN_LINE_FINGERPRINT_LEN) return;
    (keep.has(i) ? kept : drop).add(line);
  });
  for (const l of kept) drop.delete(l);
  for (const l of [...drop]) if (locateSecretShapes(l).length > 0) drop.delete(l);
  drop.delete(value.replace(/(?:\r?\n)+$/, ""));
  return drop.size === 0 ? [...pieces] : pieces.filter((p) => !drop.has(p));
}

/** {@link RegisteredValueIndex.stream}: one text fed in pieces. */
export interface ValueHitStream {
  /** How many code units of the text before each piece it matches again. */
  readonly overlap: number;
  /** The next piece of the text. */
  push(piece: string): void;
  /** The rows found so far, exactly as `hits` over the text pushed. */
  hits(): Array<{ symbol: string; how: ValueHow }>;
}

/** A row with at least this many pieces gets an automaton of its own, kept
 *  while the row is unchanged (plan 10 §11.18): a new secret row then
 *  rebuilds only the automaton of the small rows, not a large file's. */
export const OWN_AUTOMATON_PIECES = 4096;

/** One automaton over some of the index's patterns: `ids[i]` is the index's
 *  pattern id of the automaton's pattern `i`. */
interface Group {
  matcher: ValueMatcher;
  ids: number[];
}

export class RegisteredValueIndex {
  private map: SymbolMap | null = null;
  private generation = -1;
  private size = -1;
  private headsVersion = 0;
  private readonly limits: PieceLimits;
  /** Each indexed row's pieces (`valuePieces`), by name, value length, head and twin. */
  private readonly pieceCache = new Map<string, { pieces: string[]; complete: boolean }>();
  /** The automaton of each row with its own (OWN_AUTOMATON_PIECES), by its piece key. */
  private readonly ownMatchers = new Map<string, ValueMatcher>();
  private rowKey = "";
  private rows: string[] = [];
  private patterns: Pattern[] = [];
  private patternText: string[] = [];
  private groups: Group[] = [];
  /** The short passwords' patterns ({@link shortTokenRow}), in an automaton
   *  of their own: each occurrence is checked for its token bounds. */
  private tokenGroup: Group | null = null;
  private tokenRowNames = new Set<string>();
  /** The rows whose pieces were cut at the bound (plan 10 §11.18). */
  private incomplete = new Set<string>();
  /** Bumped only when the indexed row set changes (the cache key, §3.3). */
  private version = 0;
  /** How many automata this index has built (a test reads it: §11.18). */
  private builds = 0;
  /** A digest of the indexed row set (names and patterns), for the panel. */
  private digestValue = "";

  /** `pieceLimits`: the bound on one row's piece extraction (plan 10
   *  §11.18; `DEFAULT_PIECE_LIMITS`). */
  constructor(opts: { pieceLimits?: PieceLimits } = {}) {
    this.limits = opts.pieceLimits ?? DEFAULT_PIECE_LIMITS;
  }

  /** Bring the index up to date with `map`; cheap when nothing changed.
   *  `headOf` names, per row, the length of the agent runtime's own result
   *  head at the start of its value (plan 10 §11.14), whose lines are not
   *  fingerprinted; absent or 0 = every line is. A head that covers the
   *  whole value leaves the row no pattern at all, the whole value included
   *  (plan 15 §13.10). A row's head can be learned
   *  after the row was added, so the caller bumps `headsVersion` when it
   *  learns one. `twinOf` gives, for a registered file's base row, its
   *  structured twin (registry.ts `registeredFileTwin`), whose lines are no
   *  piece of that row (`valueFingerprints`, plan 10 §11.8); null or absent
   *  = every line is. It is asked when the row set changes: a twin changes
   *  only with its field rows, which are indexed rows themselves. */
  sync(
    map: SymbolMap,
    headOf?: (name: string, e: SymbolEntry) => number,
    headsVersion = 0,
    twinOf?: (name: string, e: SymbolEntry) => ValueTwin | null,
    keepLinesOf?: (name: string, e: SymbolEntry) => ReadonlySet<number> | null,
    // 2026-10-19 (secret-discovery.md §2.7, "A person's name"): a row this
    // says is no fingerprint (a person's name in a personal document's
    // twin, registry.ts `documentNameRows`) is not indexed at all. Asked
    // when the row set changes, as `twinOf` is.
    notFingerprinted?: (name: string, e: SymbolEntry) => boolean,
  ): void {
    const gen = symbolMapGeneration(map);
    if (map === this.map && gen === this.generation && map.symbols.size === this.size && headsVersion === this.headsVersion) return;
    this.map = map;
    this.generation = gen;
    this.size = map.symbols.size;
    this.headsVersion = headsVersion;
    const rows: string[] = [];
    const heads: number[] = [];
    const keeps: Array<ReadonlySet<number> | null> = [];
    const keepKeys: string[] = [];
    const key: string[] = [];
    for (const [name, e] of map.symbols) {
      if (!indexableRow(e) || notFingerprinted?.(name, e) === true) continue;
      rows.push(name);
      const head = headOf?.(name, e) ?? 0;
      heads.push(head);
      const keep = keepLinesOf?.(name, e) ?? null;
      keeps.push(keep);
      const keepKey = keep === null ? "-" : [...keep].sort((a, b) => a - b).join(",");
      keepKeys.push(keepKey);
      // The name and the value's length and hash prefix: a row whose value
      // changed under the same name (a collision sentinel replaced) rebuilds;
      // so does a row whose head, or whose kept lines, became known.
      key.push(`${name}\u0000${e.value.length}\u0000${head}\u0000${keepKey}\u0000${head === 0 && shortTokenRow(e) ? 1 : 0}`);
    }
    const rowKey = key.join("\u0001");
    if (rowKey === this.rowKey && this.version > 0) return;
    this.rowKey = rowKey;
    this.rows = rows;
    const patterns: Pattern[] = [];
    const texts: string[] = [];
    const live = new Set<string>();
    const small: number[] = [];
    const groups: Group[] = [];
    const incomplete = new Set<string>();
    const tokenIds: number[] = [];
    const tokenRowNames = new Set<string>();
    rows.forEach((name, row) => {
      const e = map.symbols.get(name)!;
      const v = e.value;
      // A row's pieces depend only on its value, head and twin: cached, so a new
      // row does not re-run the detectors over every other row's value.
      const fileRow = isRegisteredFileRow(e);
      const twin = twinOf?.(name, e) ?? null;
      const twinKey = twin === null ? "-" : createHash("sha256").update(twin.text).update("\u0000").update(twin.secrets.join("\u0000"))
        .update("\u0001").update((twin.nameLines ?? []).join("\u0000")).update("\u0001").update((twin.names ?? []).join("\u0000")).digest("hex").slice(0, 16);
      const pieceKey = `${name}\u0000${v.length}\u0000${heads[row]}\u0000${fileRow ? 1 : 0}\u0000${twinKey}\u0000${keepKeys[row]}`;
      live.add(pieceKey);
      let got = this.pieceCache.get(pieceKey);
      if (got === undefined) {
        got = valuePieces(v, heads[row], { bareTokens: fileRow, limits: this.limits, ...(twin !== null ? { twin } : {}) });
        // Plan 15 §4.1, a row the value backstop raised: only the lines that
        // made it secret stay pieces (`raisedRowPieces`).
        const keep = keeps[row];
        if (keep != null) got = { ...got, pieces: raisedRowPieces(v, got.pieces, keep) };
        this.pieceCache.set(pieceKey, got);
      }
      if (!got.complete) incomplete.add(name);
      const first = patterns.length;
      // The whole value, unless it is symbol tokens only (egress-fingerprint.ts
      // symbolTokensOnly): a token is no secret byte. Nor a value that is
      // all head (`headOf` covers it whole, plan 15 §13.10: a write tool's
      // own success notice): it holds no byte but the runtime's.
      if (fingerprintableValue(v) && heads[row]! < v.length) { patterns.push({ row, how: "value" }); texts.push(v); }
      for (const l of got.pieces) { patterns.push({ row, how: "line" }); texts.push(l); }
      const ids = Array.from({ length: patterns.length - first }, (_, i) => first + i);
      if (got.pieces.length >= OWN_AUTOMATON_PIECES) {
        // Plan 10 §11.18: a large row's automaton is built once per change
        // of that row, not on every new secret row.
        let m = this.ownMatchers.get(pieceKey);
        if (m === undefined) { m = this.build(ids.map((i) => texts[i]!)); this.ownMatchers.set(pieceKey, m); }
        groups.push({ matcher: m, ids });
      } else {
        for (const i of ids) small.push(i);
      }
      // A short password (§2.9): its whole value, as a token.
      if (heads[row] === 0 && shortTokenRow(e)) {
        tokenIds.push(patterns.length);
        patterns.push({ row, how: "value", token: true });
        texts.push(v);
        tokenRowNames.add(name);
      }
    });
    for (const k of this.pieceCache.keys()) if (!live.has(k)) this.pieceCache.delete(k);
    for (const k of this.ownMatchers.keys()) if (!live.has(k)) this.ownMatchers.delete(k);
    groups.unshift({ matcher: this.build(small.map((i) => texts[i]!)), ids: small });
    this.tokenGroup = tokenIds.length === 0 ? null : { matcher: this.build(tokenIds.map((i) => texts[i]!)), ids: tokenIds };
    this.tokenRowNames = tokenRowNames;
    this.patterns = patterns;
    this.patternText = texts;
    this.groups = groups;
    this.incomplete = incomplete;
    this.version++;
    this.digestValue = createHash("sha256").update(rowKey).digest("hex").slice(0, 16);
  }

  private build(texts: readonly string[]): ValueMatcher {
    this.builds++;
    return new ValueMatcher(texts);
  }

  /** How many automata this index has built since it was made. */
  get automatonBuilds(): number {
    return this.builds;
  }

  /** The indexed rows whose pieces were cut at the bound (plan 10 §11.18):
   *  a piece of such a row past the bound is not matched. The arbiter fails
   *  closed on the file of such a row (`callTaint`, `decideSecretOpen`). */
  incompleteRows(): ReadonlySet<string> {
    return this.incomplete;
  }

  /** The content version (bumped when the indexed rows change). */
  get contentVersion(): number {
    return this.version;
  }

  /** A short digest of the indexed rows (never a value). */
  get digest(): string {
    return this.digestValue;
  }

  /** The indexed rows' symbols, in the symbol map's order. */
  rowNames(): readonly string[] {
    return this.rows;
  }

  /** How many rows are indexed. */
  get rowCount(): number {
    return this.rows.length;
  }

  /**
   * Every indexed row that occurs in `text`, in the map's order, with how:
   * `value` when the whole value occurs (at or above the floor), else `line`
   * when one of its long lines does. Exactly `secretValueMatch` per row.
   */
  hits(text: string): Array<{ symbol: string; how: ValueHow }> {
    if (text === "" || this.patterns.length === 0) return [];
    const how = new Map<number, ValueHow>();
    for (const g of this.groups) {
      for (const local of g.matcher.matched(text)) {
        const p = this.patterns[g.ids[local]!]!;
        if (p.how === "value" || !how.has(p.row)) how.set(p.row, p.how);
      }
    }
    for (const o of this.tokenOccurrences(text)) how.set(this.patterns[o.id]!.row, "value");
    if (how.size === 0) return [];
    return [...how.keys()].sort((a, b) => a - b).map((row) => ({ symbol: this.rows[row]!, how: how.get(row)! }));
  }

  /** The short passwords' occurrences in `text` that stand as whole tokens
   *  (pattern ids, §2.9). */
  private tokenOccurrences(text: string): Array<{ id: number; start: number; end: number }> {
    const g = this.tokenGroup;
    if (g === null) return [];
    const out: Array<{ id: number; start: number; end: number }> = [];
    for (const o of g.matcher.occurrences(text)) {
      const id = g.ids[o.pattern]!;
      if (tokenBounded(text, o.start, o.end, this.patternText[id]!)) out.push({ id, start: o.start, end: o.end });
    }
    return out;
  }

  /** Is `name` indexed by the short-token rule ({@link shortTokenRow})? */
  isTokenRow(name: string): boolean {
    return this.tokenRowNames.has(name);
  }

  /** The longest indexed pattern, in code units (0 = none). */
  get longestPattern(): number {
    let n = 0;
    for (const t of this.patternText) if (t.length > n) n = t.length;
    return n;
  }

  /**
   * A streaming form of {@link hits} for a text too large to hold whole (the
   * upload gate's scan of a file, confidentiality.md §7): push its pieces in
   * order, then `hits()` answers exactly what `hits(pieces.join(""))`
   * would. Each piece is matched together with the last `longestPattern - 1`
   * code units before it, so a value that straddles two pieces is found (an
   * occurrence of a pattern of length L lies whole in some such window). The
   * stream keeps the automata and rows of the index as they were when it was
   * made: a row added while it runs is not looked for (the caller re-reads
   * each hit's row live, as for `hits`).
   */
  stream(): ValueHitStream {
    const groups = this.groups;
    const tokens = this.tokenGroup;
    const patterns = this.patterns;
    const texts = this.patternText;
    const rows = this.rows;
    // A short password's token bounds need the character before it and the
    // one after it (§2.9): the carry keeps at least MIN_FINGERPRINT_LEN
    // characters (a token pattern is shorter), so an occurrence judged in a
    // window always has the character before it there, and one that ends
    // at a window's end waits for the next piece (`pending`; the text's own
    // end is a token end, so `hits()` counts it).
    const keep = Math.max(0, this.longestPattern - 1, tokens === null ? 0 : MIN_FINGERPRINT_LEN);
    const how = new Map<number, ValueHow>();
    let pending = new Set<number>();
    let carry = "";
    return {
      overlap: keep,
      push(piece: string): void {
        if (piece === "" || patterns.length === 0) return;
        const window = carry + piece;
        for (const g of groups) {
          for (const local of g.matcher.matched(window)) {
            const p = patterns[g.ids[local]!]!;
            if (p.how === "value" || !how.has(p.row)) how.set(p.row, p.how);
          }
        }
        if (tokens !== null) {
          const next = new Set<number>();
          for (const o of tokens.matcher.occurrences(window)) {
            // Ended inside the last window's text: judged there, with both
            // of its neighbours in view.
            if (o.end < carry.length) continue;
            const id = tokens.ids[o.pattern]!;
            const row = patterns[id]!.row;
            // At the window's end the character after it is unknown (read
            // as a token end here): its start is judged now, its end with
            // the next piece.
            if (!tokenBounded(window, o.start, o.end, texts[id]!)) continue;
            if (o.end === window.length) next.add(row);
            else how.set(row, "value");
          }
          pending = next;
        }
        carry = keep === 0 ? "" : window.length > keep ? window.slice(window.length - keep) : window;
      },
      hits(): Array<{ symbol: string; how: ValueHow }> {
        const all = new Map(how);
        for (const row of pending) all.set(row, "value");
        return [...all.keys()].sort((a, b) => a - b).map((row) => ({ symbol: rows[row]!, how: all.get(row)! }));
      },
    };
  }

  /** Every occurrence of every indexed value or line in `text`. */
  occurrences(text: string): ValueOccurrence[] {
    if (text === "" || this.patterns.length === 0) return [];
    const all: Array<{ id: number; start: number; end: number }> = [];
    for (const g of this.groups) for (const o of g.matcher.occurrences(text)) all.push({ id: g.ids[o.pattern]!, start: o.start, end: o.end });
    // A short password's (§2.9): only where it stands as a whole token.
    const tokens = this.tokenOccurrences(text);
    for (const o of tokens) all.push(o);
    // One automaton lists by end position; several are merged the same way
    // (a stable sort keeps one automaton's order among equal ends).
    if (this.groups.length > 1 || tokens.length > 0) all.sort((a, b) => a.end - b.end);
    return all.map((o) => {
      const p = this.patterns[o.id]!;
      return { symbol: this.rows[p.row]!, how: p.how, text: this.patternText[o.id]!, start: o.start, end: o.end };
    });
  }
}

/**
 * The egress tripwire over the index: the same answer as
 * `scanEgressFingerprint(surfaces, secrets, destination)` with `secrets` the
 * active secret rows in map order, in one pass per surface instead of one
 * `includes` per secret per surface. `row(symbol)` reads a row LIVE and
 * returns its fingerprint (null = not a secret now).
 */
export function scanEgressFingerprintIndexed(
  surfaces: ReadonlyArray<{ where: string; text: string }>,
  index: RegisteredValueIndex,
  row: (symbol: string) => SecretFingerprint | null,
  destination: string,
): FingerprintHit[] {
  const matched = surfaces.map((s) => (s.text ? new Set(index.hits(s.text).map((h) => h.symbol)) : new Set<string>()));
  const names = new Set<string>();
  for (const m of matched) for (const n of m) names.add(n);
  if (names.size === 0) return [];
  const hits: FingerprintHit[] = [];
  for (const name of index.rowNames()) {
    if (!names.has(name)) continue;
    const s = row(name);
    if (s === null || s.level === "public") continue;
    // Under the floor only a short password the index holds as a token
    // (§2.9; `token` on the reference's fingerprint).
    if (!s.value || (s.value.length < MIN_FINGERPRINT_LEN && !index.isTokenRow(name))) continue;
    if (destination && destinationIsBound(destination, s.bindings)) continue;
    const at = matched.findIndex((m) => m.has(name));
    if (at >= 0) hits.push({ symbol: s.symbol, level: s.level, where: surfaces[at]!.where });
  }
  return hits;
}
