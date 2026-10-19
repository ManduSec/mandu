/**
 * shown — the placeholders the relay has shown the agent
 * (docs/design/agents/devtools-relay.md §3.2, *A placeholder that names
 * nothing*). Mandu-new (no reference origin).
 *
 * Every placeholder the prompt filter put into a message the relay then
 * delivered to the agent (pair.ts, events.ts `addedSymbols`): the arbiter
 * minted each, and the agent has read each, so naming them back to the
 * agent tells it nothing it was not told. Names only, never a value. When
 * the agent types a placeholder the arbiter does not know (a hash it made up,
 * a character dropped), the refusal lists the nearest of these, so its model
 * can copy the right one. One per relay (every connection of the agent's),
 * at most MAX_SHOWN, the oldest forgotten first.
 */

/** How many placeholders the relay remembers. */
export const MAX_SHOWN = 64;
/** How many the refusal names. */
export const MAX_HINTS = 5;

export class ShownPlaceholders {
  /** Insertion order is recency: the last shown is last. */
  private readonly seen = new Set<string>();

  /** Placeholders a delivered message carried. */
  add(symbols: readonly string[]): void {
    for (const s of symbols) {
      this.seen.delete(s);
      this.seen.add(s);
    }
    while (this.seen.size > MAX_SHOWN) this.seen.delete(this.seen.values().next().value!);
  }

  get size(): number {
    return this.seen.size;
  }

  /** The `n` shown placeholders nearest to `token` (fewest character edits;
   *  the more recent first on a tie), never `token` itself. Pure over the
   *  set. */
  nearest(token: string, n: number = MAX_HINTS): string[] {
    const all = [...this.seen].reverse().filter((s) => s !== token);
    const scored = all.map((s, recency) => ({ s, d: editDistance(token, s), recency }));
    scored.sort((a, b) => a.d - b.d || a.recency - b.recency);
    return scored.slice(0, Math.max(0, n)).map((x) => x.s);
  }
}

/** Levenshtein distance (two rows; placeholders are short). Pure. */
export function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length]!;
}
