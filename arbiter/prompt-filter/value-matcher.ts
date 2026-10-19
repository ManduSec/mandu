/**
 * value-matcher — one pass over a text for every registered secret value
 * (confidentiality-plan-15-prompt-filter.md §4.1). Mandu-new (no reference
 * origin).
 *
 * The value backstop (`scanSecretValues`, the classify-time scan), the egress
 * tripwire (`egressFingerprintScan`) and the prompt filter all ask the same
 * question: which registered values, or long lines of one, appear verbatim in
 * this text? Before plan 15 each asked it with one `String.includes` per row,
 * so the cost grew with the rows times the text. This is an Aho-Corasick
 * automaton over the patterns' KEYS (the first {@link KEY_LEN} code units of
 * each pattern), and every key hit is verified with `startsWith` at its
 * position. The key bound keeps the trie small when a pattern is a whole
 * document (a labeled file's content is one row); the verification keeps the
 * answer exact: `text.includes(p)` holds iff some position of `text` starts
 * with `p`, every such position ends a key match, and the automaton reports
 * every key match (overlapping ones included).
 *
 * Pure: no I/O, no clock. The strings are JavaScript strings, so offsets are
 * UTF-16 code units, the unit `String.prototype.slice` takes.
 */

/** How many leading code units of a pattern the automaton indexes. Shorter
 *  patterns are indexed whole. 16 keeps the trie at most 16 nodes per pattern;
 *  a collision past the key costs one `startsWith`. */
export const KEY_LEN = 16;

/** One occurrence: pattern `pattern` at [start, end) of the text. */
export interface Occurrence {
  pattern: number;
  start: number;
  end: number;
}

/**
 * The automaton. Built once from a pattern list (index = pattern id); every
 * query is one left-to-right pass over the text.
 */
export class ValueMatcher {
  private readonly patterns: readonly string[];
  /** Trie edges: `node * 65536 + codeUnit` → child node. */
  private readonly edges = new Map<number, number>();
  private readonly fail: number[] = [0];
  /** The nearest node on the fail chain (excluding the node itself) that ends
   *  a key; -1 = none. */
  private readonly outLink: number[] = [-1];
  /** Key length of a node that ends a key (0 = ends none). */
  private readonly keyLen: number[] = [0];
  /** The patterns whose key ends at a node. */
  private readonly keyPatterns = new Map<number, number[]>();
  /** The root's edges by code unit (0 = none: stay at the root). The same
   *  edges as in `edges`, read without a hash lookup (the walk spends most
   *  of its time at the root: the upload scan of a large binary file). */
  private readonly root = new Int32Array(65536);

  constructor(patterns: readonly string[]) {
    this.patterns = patterns;
    const kids: number[][] = [[]];
    patterns.forEach((p, id) => {
      if (p.length === 0) return;
      const n = Math.min(p.length, KEY_LEN);
      let node = 0;
      for (let i = 0; i < n; i++) {
        const k = node * 65536 + p.charCodeAt(i);
        let next = this.edges.get(k);
        if (next === undefined) {
          next = this.fail.length;
          this.edges.set(k, next);
          this.fail.push(0);
          this.outLink.push(-1);
          this.keyLen.push(0);
          kids.push([]);
          kids[node]!.push(next);
        }
        node = next;
      }
      this.keyLen[node] = n;
      const list = this.keyPatterns.get(node);
      if (list) list.push(id); else this.keyPatterns.set(node, [id]);
    });
    // Fail links, breadth first from the root's children. A node's character
    // is recovered once from its parent's edge key.
    for (const [k, child] of this.edges) if (k < 65536) this.root[k] = child;
    const charOf = new Map<number, number>();
    for (const [k, child] of this.edges) charOf.set(child, k % 65536);
    const queue: number[] = [...kids[0]!];
    for (let head = 0; head < queue.length; head++) {
      const u = queue[head]!;
      for (const v of kids[u]!) {
        const c = charOf.get(v)!;
        let f = this.fail[u]!;
        while (f !== 0 && !this.edges.has(f * 65536 + c)) f = this.fail[f]!;
        this.fail[v] = this.edges.get(f * 65536 + c) ?? 0;
        queue.push(v);
      }
      const fu = this.fail[u]!;
      this.outLink[u] = u === 0 ? -1 : this.keyLen[fu]! > 0 ? fu : this.outLink[fu]!;
    }
  }

  /** How many patterns the automaton holds. */
  get size(): number {
    return this.patterns.length;
  }

  /**
   * Walk the text once; call `visit(pattern, start)` for every verified
   * occurrence. `want(pattern)` lets a caller skip the verification of a
   * pattern it no longer needs (the backstop needs one hit per pattern).
   */
  private walk(text: string, visit: (pattern: number, start: number) => void, want?: (pattern: number) => boolean): void {
    if (this.patterns.length === 0 || text.length === 0) return;
    let state = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (state === 0) {
        // The root's edges are a table: most code units of a text start no
        // key (the root keeps no output), so they cost one array read.
        state = this.root[c]!;
        if (state === 0) continue;
      } else {
        let next = this.edges.get(state * 65536 + c);
        while (next === undefined) {
          state = this.fail[state]!;
          if (state === 0) { next = this.root[c]!; break; }
          next = this.edges.get(state * 65536 + c);
        }
        state = next;
        if (state === 0) continue;
      }
      let node = this.keyLen[state]! > 0 ? state : this.outLink[state]!;
      while (node !== -1) {
        const len = this.keyLen[node]!;
        const start = i - len + 1;
        for (const id of this.keyPatterns.get(node)!) {
          if (want && !want(id)) continue;
          const p = this.patterns[id]!;
          if (p.length === len || text.startsWith(p, start)) visit(id, start);
        }
        node = this.outLink[node]!;
      }
    }
  }

  /** Every pattern that occurs in `text` at least once. */
  matched(text: string): Set<number> {
    const out = new Set<number>();
    this.walk(text, (id) => { out.add(id); }, (id) => !out.has(id));
    return out;
  }

  /** Every occurrence of every pattern, in order of their END position, then
   *  by pattern id (overlapping occurrences included). */
  occurrences(text: string): Occurrence[] {
    const out: Occurrence[] = [];
    this.walk(text, (id, start) => { out.push({ pattern: id, start, end: start + this.patterns[id]!.length }); });
    return out;
  }
}
