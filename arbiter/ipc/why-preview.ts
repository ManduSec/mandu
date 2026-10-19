/**
 * why-preview — what `whyPath` (`mandu why <path>`, comparisons.md §3.2)
 * says of the twin a registration makes of a file as it is now: its form,
 * shape and number of masked values (`twinFormOf`), and the commands an
 * `~/.ssh/config` twin withholds (`withheldCommands`), read from the real
 * file on the arbiter's one event loop.
 *
 * `whyPath` is not a human-plane op: the agent's programs reach it on the
 * data socket, with a path and a file they can write. So it is bounded
 * (2026-10-10):
 *   - the file is checked BEFORE it is opened (`whyFileStat`): only a
 *     regular file, and a FIFO or a device is never opened (a `.env` made a
 *     FIFO blocked the arbiter for good; one linked to `/dev/zero` was read
 *     without end);
 *   - at most `WHY_MAX_BYTES` of it (the extraction costs up to about 1 µs
 *     a byte on an adversarial file: a 7 MB YAML of `-u a:b` flow items took
 *     3.5 s, every interceptor waiting meanwhile);
 *   - an answer is remembered by the path, the label's rule and the hash
 *     of the text read, so asking again about an unchanged file costs a
 *     read of at most `WHY_MAX_BYTES` and a hash, not an extraction (not by
 *     `mtime` and `ctime`: two writes of one size within the kernel's
 *     timestamp tick keep both, and the earlier answer came back);
 *   - a text not remembered spends a budget of `WHY_BUDGET_BYTES` per
 *     `WHY_BUDGET_WINDOW_MS`: an agent that rewrites a file between calls
 *     gets the hedged answer once the window's budget is spent. The server
 *     keeps one `WhyPreview` for the data socket and one, with no budget,
 *     for the human plane (the dashboard), which the agent cannot reach.
 * A file it does not read gets no `twin` (and no `withheld`): `mandu why`
 * then says what the twin depends on, as it does for an older arbiter.
 *
 * Mandu-new (no reference origin).
 */
import { createHash } from "node:crypto";
import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readSync, statSync, type BigIntStats } from "node:fs";

import { MAX_STRUCTURED_BYTES, withheldCommands } from "../policy/secret-extract.js";
import { twinFormOf, type TwinForm } from "../secret-registry/registry.js";

/** The most of a file `whyPath` reads: about a quarter of a second of
 *  extraction on the worst file measured (2026-10-10). A labelled config
 *  is a few kilobytes; a larger file gets the hedged answer. */
export const WHY_MAX_BYTES = 256 * 1024;
/** The bytes of texts not remembered that `whyPath` extracts per window. */
export const WHY_BUDGET_BYTES = 1024 * 1024;
export const WHY_BUDGET_WINDOW_MS = 10_000;
/** How many answers are remembered (least recently used goes first). */
const WHY_CACHE_ENTRIES = 64;

/**
 * The regular file at `path` as `whyFileText` would read it, checked
 * without opening it: `lstat` first (the path itself, not followed), and
 * for a symbolic link `stat` of what it names (a link is followed, as
 * `registerSecret` follows it). Null for anything but a regular file of at
 * most `maxBytes`, or a path that cannot be checked. `link` says whether
 * the path was a link (the open then may not refuse one). Never throws.
 */
export function whyFileStat(path: string, maxBytes = MAX_STRUCTURED_BYTES): { st: BigIntStats; link: boolean } | null {
  try {
    const own = lstatSync(path, { bigint: true });
    const link = own.isSymbolicLink();
    const st = link ? statSync(path, { bigint: true }) : own;
    if (!st.isFile() || st.size > BigInt(maxBytes)) return null;
    return { st, link };
  } catch {
    return null;
  }
}

/**
 * The text of a file for `whyPath`, or null: only what `whyFileStat` passes
 * is opened (`O_NONBLOCK | O_NOCTTY`, and `O_NOFOLLOW` when the path was no
 * link), and the descriptor must be that same regular file (`dev`, `ino`:
 * a file swapped in between is refused). At most `maxBytes` and one byte
 * past the size `fstat` gave, so a file that grew is caught. Never throws.
 */
export function whyFileText(path: string, maxBytes = MAX_STRUCTURED_BYTES, checked = whyFileStat(path, maxBytes)): string | null {
  if (checked === null) return null;
  let fd: number;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NONBLOCK | fsConstants.O_NOCTTY | (checked.link ? 0 : fsConstants.O_NOFOLLOW));
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd, { bigint: true });
    if (!st.isFile() || st.dev !== checked.st.dev || st.ino !== checked.st.ino || st.size > BigInt(maxBytes)) return null;
    const size = Number(st.size);
    const buf = Buffer.alloc(size + 1);
    let n = 0;
    while (n < buf.length) {
      const got = readSync(fd, buf, n, buf.length - n, null);
      if (got === 0) break;
      n += got;
    }
    if (n > size) return null;
    return buf.subarray(0, n).toString("utf8");
  } catch {
    return null;
  } finally {
    try { closeSync(fd); } catch { /* already closed */ }
  }
}

/** What `whyPath` adds of a file's twin: none when it was not read. */
export interface WhyFacts {
  twin?: TwinForm;
  withheld?: Array<{ line: number; keyword: string }>;
}

export interface WhyPreviewOptions {
  maxBytes?: number;
  budgetBytes?: number;
  windowMs?: number;
  now?: () => number;
}

/** One arbiter's `whyPath` reads: the remembered answers and the budget. */
export class WhyPreview {
  private readonly maxBytes: number;
  private readonly budgetBytes: number;
  private readonly windowMs: number;
  private readonly now: () => number;
  private readonly cache = new Map<string, { hash: string; facts: WhyFacts }>();
  private windowStart = -Infinity;
  private spent = 0;
  /** Texts extracted (not remembered): for tests. */
  reads = 0;

  constructor(opts: WhyPreviewOptions = {}) {
    this.maxBytes = opts.maxBytes ?? WHY_MAX_BYTES;
    this.budgetBytes = opts.budgetBytes ?? WHY_BUDGET_BYTES;
    this.windowMs = opts.windowMs ?? WHY_BUDGET_WINDOW_MS;
    this.now = opts.now ?? Date.now;
  }

  /**
   * The twin facts of `path` under `match` (the rule and `extract:` of its
   * label): `twinFormOf` of the file as it is now (none when it is empty),
   * and with `withheld`, `withheldCommands`. `{}` when the file is not one
   * `whyFileStat` passes at `maxBytes`, cannot be read, or the window's
   * budget is spent. Never throws.
   */
  facts(path: string, match: { rule: string | null; extract?: string }, opts: { withheld?: boolean } = {}): WhyFacts {
    const text = whyFileText(path, this.maxBytes);
    if (text === null) return {};
    const key = `${path}\u0000${match.rule ?? ""}\u0000${match.extract ?? ""}\u0000${opts.withheld ? 1 : 0}`;
    const hash = createHash("sha256").update(text).digest("hex");
    const hit = this.cache.get(key);
    if (hit !== undefined && hit.hash === hash) {
      this.cache.delete(key);
      this.cache.set(key, hit);
      return hit.facts;
    }
    const t = this.now();
    if (t - this.windowStart >= this.windowMs) { this.windowStart = t; this.spent = 0; }
    if (this.spent + text.length > this.budgetBytes) return {};
    this.spent += text.length;
    this.reads++;
    const facts: WhyFacts = {};
    try {
      if (text !== "") facts.twin = twinFormOf(path, text, match);
      if (opts.withheld) facts.withheld = withheldCommands(path, text);
    } catch {
      return {};
    }
    this.cache.set(key, { hash, facts });
    if (this.cache.size > WHY_CACHE_ENTRIES) this.cache.delete(this.cache.keys().next().value as string);
    return facts;
  }
}
