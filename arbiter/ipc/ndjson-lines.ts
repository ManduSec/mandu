/**
 * ndjson-lines — linear-time line framing for NDJSON socket readers.
 *
 * Mandu-new (no reference origin). Every NDJSON reader in the repo used the
 * same idiom: `buf += chunk; while ((nl = buf.indexOf("\n")) >= 0) …`. That is
 * linear for a stream of SHORT lines (the buffer empties after each one) but
 * QUADRATIC for one LONG line: every arriving chunk re-scans the whole
 * accumulated string from offset 0, and a 16 MB single-line reply (the
 * arbiter's `events` op for one long interactive session) arrives in ~260
 * chunks — ~2 GB of scanning, 6–7 s on the 2026-09-17 stack, against a 5 s
 * per-op deadline (dashboard.md §3.3). The same reply read linearly takes
 * 0.8 s end to end.
 *
 * This splitter scans ONLY the newly arrived chunk for newlines and joins the
 * pending fragments once per completed line, so cost is proportional to the
 * bytes received, never to the bytes buffered.
 *
 * A twin copy lives in `dashboard/src/event-source/ndjson-lines.ts` (the
 * dashboard deliberately does not import from the arbiter package); keep the
 * two identical.
 */
export class NdjsonLineSplitter {
  /** Fragments of the line in progress (no newline seen yet), in order. */
  private pending: string[] = [];

  /** Feed one chunk; returns every COMPLETE line it closed (without the
   *  newline), in order. A trailing fragment stays pending for the next push. */
  push(chunk: string): string[] {
    const lines: string[] = [];
    let start = 0;
    for (;;) {
      const nl = chunk.indexOf("\n", start);
      if (nl < 0) break;
      const head = chunk.slice(start, nl);
      if (this.pending.length > 0) {
        this.pending.push(head);
        lines.push(this.pending.join(""));
        this.pending = [];
      } else {
        lines.push(head);
      }
      start = nl + 1;
    }
    if (start < chunk.length) this.pending.push(chunk.slice(start));
    return lines;
  }

  /** Bytes (UTF-16 code units) buffered for the line in progress. */
  get pendingLength(): number {
    let n = 0;
    for (const p of this.pending) n += p.length;
    return n;
  }
}
