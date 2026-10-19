/**
 * screen.ts — the differential harness's screen model: raw PTY bytes →
 * rendered viewport grid → normalized lines → diff.
 *
 * Mandu-new (differential-interactive.md §4). The emulator is
 * `@xterm/headless` (pure JS, zero transitive deps) at a fixed 80×24 — both
 * differential sides run `script(1)` under a PIPE, whose pty winsize defaults
 * the same way for both, so 80-col rendering is apples-to-apples (spike §6).
 *
 * Snapshots read the VIEWPORT ONLY (the last `rows` buffer lines): a
 * whole-buffer dump duplicates repaint regions (spike finding — the composer
 * echo showed up twice). Everything here except ScreenTap is pure and
 * unit-tested in differential-screen.test.ts.
 */

// @xterm/headless ships a UMD/CJS bundle — under ESM its named exports are
// not statically detectable (loads under `default`), while a CJS transpile
// (tsx from a CJS caller) exposes them on the namespace itself. Handle both.
import * as xtermHeadlessNs from "@xterm/headless";
type Terminal = import("@xterm/headless").Terminal;
const { Terminal } = ((xtermHeadlessNs as { default?: unknown }).default ??
  xtermHeadlessNs) as typeof import("@xterm/headless");

export const SCREEN_COLS = 80;
export const SCREEN_ROWS = 24;

/** Feed PTY bytes in, take viewport snapshots out. Wraps the emulator's async
 *  write pipeline behind an awaitable chain so a snapshot never races a feed. */
export class ScreenTap {
  private term: Terminal;
  private pending: Promise<void> = Promise.resolve();
  /** Timestamped ring of viewport snapshots (the F2 held-symbol oracle input). */
  readonly ring: Array<{ at: number; lines: string[] }> = [];

  constructor(cols = SCREEN_COLS, rows = SCREEN_ROWS) {
    this.term = new Terminal({ cols, rows, allowProposedApi: true, scrollback: 5000 });
  }

  /** Resize the screen model — the driver calls this in lock-step with the
   *  pty's TIOCSWINSZ (differential-driver.ts resizeOuterPty), after the
   *  pending writes have landed, so the model reflows exactly what the TUI
   *  was shown. */
  async resize(cols: number, rows: number): Promise<void> {
    await this.pending;
    this.term.resize(cols, rows);
  }

  /** Bytes go to the emulator AS BYTES: its UTF-8 decoder keeps a
   *  character split across two PTY reads whole. Decoding each chunk on its
   *  own turned a split `─` into two U+FFFD cells, one cell too many, and the
   *  wrapped row scrolled the whole screen by a line (CI 2026-09-29, the
   *  wrapped side's extra pipes split more often under load). */
  feed(bytes: Buffer | string): void {
    const data = typeof bytes === "string" ? bytes : new Uint8Array(bytes);
    this.pending = this.pending.then(() => new Promise<void>((r) => this.term.write(data, r)));
  }

  /** Right-trimmed viewport lines (trailing empty lines dropped). */
  async snapshot(): Promise<string[]> {
    await this.pending;
    const buf = this.term.buffer.active;
    const start = Math.max(0, buf.length - this.term.rows);
    const lines: string[] = [];
    for (let i = start; i < buf.length; i++) {
      lines.push((buf.getLine(i)?.translateToString(true) ?? "").trimEnd());
    }
    while (lines.length && lines[lines.length - 1] === "") lines.pop();
    return lines;
  }

  /** Take a snapshot into the ring (driver calls this on a timer). */
  async captureRing(now = Date.now()): Promise<void> {
    this.ring.push({ at: now, lines: await this.snapshot() });
  }

  /** EVERY line the human could scroll through — scrollback + viewport,
   *  right-trimmed, trailing empties dropped. The post-hoc oracle surface:
   *  claude's TUI repaints the MAIN buffer (no alternate screen), so the
   *  rendered transcript — including any mis-erased row, exactly as painted —
   *  survives here after the session ends. */
  async fullLines(): Promise<string[]> {
    await this.pending;
    const buf = this.term.buffer.active;
    const lines: string[] = [];
    for (let i = 0; i < buf.length; i++) {
      lines.push((buf.getLine(i)?.translateToString(true) ?? "").trimEnd());
    }
    while (lines.length && lines[lines.length - 1] === "") lines.pop();
    return lines;
  }

  dispose(): void {
    this.term.dispose();
  }
}

/** Render a whole captured PTY byte stream after the fact and return the full
 *  scroll history (ScreenTap.fullLines). Pure local CPU — no session, no
 *  model. What a raw-bytes substring check cannot see, this can: a value whose
 *  tail the TUI's own cursor math erased is missing HERE while fully present
 *  in the byte stream (the 2026-07-17 clip class, differential doc §10/§11). */
export async function renderCapturedLines(bytes: string | Buffer, cols = SCREEN_COLS, rows = SCREEN_ROWS): Promise<string[]> {
  const tap = new ScreenTap(cols, rows);
  try {
    tap.feed(bytes);
    return await tap.fullLines();
  } finally {
    tap.dispose();
  }
}

// ── normalization ──────────────────────────────────────────────────────────

export interface NormMask {
  pattern: RegExp; // must be global if it can occur more than once per line
  replace: string;
  /** Diagnostic name, shown when a diff hunk survives so the reader can tell
   *  which masks already ran. */
  name: string;
}

/** Path pairs mapped BEFORE masking (wrapped AgentView → human workspace —
 *  the one intended cosmetic diff, differential-interactive.md §2). */
export interface PathMap {
  from: string;
  to: string;
}

/** A profile's whole-viewport chrome normalization (welcome-box collapse,
 *  banner/hint-bar drops). Runs BEFORE path mapping + masks. */
export type ChromeCollapse = (lines: string[]) => string[];

/**
 * Cut claude's fullscreen CHANGE PANEL off every viewport row. At wide widths
 * the alt-screen renderer (≥ 2.1.27x) shows a git-aware side panel right of
 * the transcript — "N file(s) changed ✕" on the header row, `─` separators,
 * "<file> (untracked)", "New file not yet staged.", "No changes this
 * session" — whose CONTENT is structurally different between the sides: the
 * wrapped agent runs in the AgentView worktree where fs-sync COMMITS its
 * writes (the panel sees a clean tree) while vanilla's write stays untracked
 * (differential-interactive.md §19, write-file @160×40). The panel's left
 * edge is the column where a separator row's `─` run starts; a separator
 * that starts in the left 40% of the widest row is the inline renderer's
 * full-width input-box rule, not a panel, and nothing is cut. Rows are
 * truncated at that column and right-trimmed.
 */
export function collapseChangePanel(lines: string[]): string[] {
  // A full-width `─` rule (the input box's) is normalized on EVERY viewport:
  // a panel shortens it on one side only, and the other side may not show
  // the panel yet (its git poll fires later), so the rule's length is never
  // parity-relevant. Identical on both sides otherwise.
  const rule = (l: string) => l.replace(/^(\s*)─{8,}\s*$/, "$1────");
  if (!lines.some((l) => l.includes("✕"))) return lines.map(rule);
  const widest = Math.max(0, ...lines.map((l) => l.length));
  const sep = lines.find((l) => /^\s+─{8,}\s*$/.test(l));
  let out = lines;
  if (sep) {
    const col = sep.search(/─/);
    if (col >= Math.floor(widest * 0.4)) out = lines.map((l) => l.slice(0, col).trimEnd());
  }
  // The EMPTY panel has no separator rows — just the header's `✕`, a "No
  // changes this session" row, and an input-box rule shortened by the panel's
  // width — so the panel's remnants are masked row-wise (its poll timing
  // differs per side: one side may still show no panel at all).
  return out.map((l) =>
    l
      .replace(/\s+(?:\d+ files? changed )?✕\s*$/, "")
      .replace(/\s{2,}No changes this session\s*$/, ""),
  ).map(rule);
}

/** Collapse an agent's WELCOME/boot BOX (╭…╰) to one placeholder line when its
 *  content carries `marker`. The box's internal column geometry adapts to the
 *  cwd string length — a structural, intended difference between the two sides
 *  (the wrapped cwd is the deep AgentView path), so the whole box is an
 *  allowlisted region. A box TAIL cut by the viewport top — a `╰` closing line
 *  with no `╭` before it — is collapsed too; other ╭-boxes (permission
 *  dialogs — the Phase 2 substrate) are left intact. The marker itself is
 *  agent-shaped and lives in the agent's driver profile (differential-
 *  profiles.ts) — e.g. "Claude Code" for the claude profile. */
export function collapseMarkedBox(lines: string[], marker: string): string[] {
  const open = lines.findIndex((l) => l.trimStart().startsWith("╭"));
  const close = lines.findIndex((l) => l.trimStart().startsWith("╰"));
  if (close === -1) return lines;
  if (open !== -1 && open < close) {
    const block = lines.slice(open, close + 1).join("\n");
    if (!block.includes(marker)) return lines;
    return [...lines.slice(0, open), "<welcome-box>", ...lines.slice(close + 1)];
  }
  // Tail-only: the viewport cut the box top off — rows 0..close are box rows.
  return ["<welcome-box>", ...lines.slice(close + 1)];
}

/** Where a TUI blinks the pending tool call's bullet while its permission
 *  dialog is up (claude: `●`, on and blank in turn). */
export interface PendingToolBlink {
  /** The blinking glyph, drawn at column 0 and followed by one space. */
  bullet: string;
  /** Leads the row under the tool header that shows its progress
   *  (claude: `  ⎿  Waiting…` inline, `  ⎿  $ <command>` fullscreen). */
  connector: RegExp;
  /** The permission dialog is on the viewport (the profile's detect). */
  dialog: (screenText: string) => boolean;
  /** The row the dialog's question sits on; the pending tool is above it. */
  question: RegExp;
}

/**
 * Fold the blink phase of the PENDING tool call's bullet (§23): while a
 * permission dialog is up, claude blinks the bullet of the call it asks about
 * ("● Showing notes…" and "  Showing notes…" in turn, forever), so each side's
 * dialog checkpoint keeps whichever phase it was captured in. Only that one
 * glyph is folded, to its on phase, and only on:
 *   - a viewport that shows the permission dialog (`dialog`);
 *   - the pending tool's header row: the top row of the non-empty block
 *     that ends in the last `connector` row above the dialog's `question`
 *     (a header wrapped over two rows still has one top row);
 *   - a header whose first two cells are the bullet and a space, or two
 *     spaces, followed by text.
 * Every other row, including every completed tool's bullet, compares raw.
 */
export function foldPendingToolBlink(lines: string[], spec: PendingToolBlink): string[] {
  if (!spec.dialog(lines.join("\n"))) return lines;
  const q = lines.findIndex((l) => spec.question.test(l));
  if (q <= 0) return lines;
  let conn = -1;
  for (let i = q - 1; i > 0; i--) {
    if (spec.connector.test(lines[i]!)) { conn = i; break; }
  }
  if (conn <= 0) return lines;
  let top = conn - 1;
  while (top > 0 && lines[top - 1]!.trim() !== "") top--;
  const header = lines[top]!;
  const on = `${spec.bullet} `;
  if (header.startsWith(on) || !/^ {2}\S/.test(header)) return lines;
  const out = lines.slice();
  out[top] = on + header.slice(2);
  return out;
}

/** Apply a path map to one string. */
function mapLine(line: string, pathMap: PathMap[]): string {
  let out = line;
  for (const { from, to } of pathMap) out = out.split(from).join(to);
  return out;
}

/** Does some path of the map occur in `joined` across one of the row seams
 *  at `seams` (offsets into `joined` where a row ends and the next begins)? */
function pathCrossesSeam(joined: string, seams: number[], pathMap: PathMap[]): boolean {
  for (const { from } of pathMap) {
    if (from === "") continue;
    for (let at = joined.indexOf(from); at !== -1; at = joined.indexOf(from, at + 1)) {
      if (seams.some((s) => at < s && s < at + from.length)) return true;
    }
  }
  return false;
}

/**
 * The path map over a viewport, soft-wrapped rows included. A row exactly
 * `cols` characters wide is taken to continue on the next (the terminal
 * wrapped it); when a mapped path crosses such a seam (Goose's banner
 * `\____)    <session> · <cwd>` wrapped its cwd at 80 columns under a
 * longer TMPDIR, 2026-10-09) the rows are joined, mapped as one line, cut
 * back into `cols`-wide rows,
 * and padded with empty rows to the run's row count, so every later row
 * keeps its place. A run no path crosses is mapped row by row, as before.
 * Without `cols` every row maps on its own. The width is the string's
 * length: a row holding a double-width character reads short and is not
 * joined (it maps per row, never wrongly). Pure.
 */
export function mapScreenPaths(lines: string[], pathMap: PathMap[], cols?: number): string[] {
  if (pathMap.length === 0) return lines.slice();
  const out: string[] = [];
  for (let i = 0; i < lines.length;) {
    let j = i;
    if (cols !== undefined && cols > 0) {
      while (j + 1 < lines.length && lines[j]!.length === cols) j++;
    }
    if (j > i) {
      const run = lines.slice(i, j + 1);
      const joined = run.join("");
      const seams = run.slice(0, -1).map((_, k) => (k + 1) * cols!);
      if (pathCrossesSeam(joined, seams, pathMap)) {
        const mapped = mapLine(joined, pathMap);
        const rows: string[] = [];
        for (let at = 0; at < mapped.length; at += cols!) rows.push(mapped.slice(at, at + cols!));
        while (rows.length < run.length) rows.push("");
        out.push(...rows);
        i = j + 1;
        continue;
      }
    }
    for (let k = i; k <= j; k++) out.push(mapLine(lines[k]!, pathMap));
    i = j + 1;
  }
  return out;
}

/** Normalize a viewport for the parity diff: chrome collapse (profile-shaped),
 *  then path mapping (across soft-wrapped rows when `cols`, the terminal's
 *  width at this screen, is given: mapScreenPaths), then the mask table, in
 *  that order. The mask table is agent-shaped and REQUIRED — each agent's
 *  masks live in its driver profile (differential-profiles.ts CLAUDE_MASKS /
 *  OPENCLAW_MASKS / …). */
export function normalizeScreen(
  lines: string[],
  pathMap: PathMap[] = [],
  masks: NormMask[] = [],
  collapse: ChromeCollapse = (l) => l,
  cols?: number,
): string[] {
  return mapScreenPaths(collapse(lines), pathMap, cols).map((line) => {
    let out = line;
    for (const m of masks) out = out.replace(m.pattern, m.replace);
    return out.trimEnd();
  });
}

// ── diff ───────────────────────────────────────────────────────────────────

export interface ScreenMismatch {
  row: number; // 0-based viewport row
  a: string;
  b: string;
}

/** Row-by-row mismatches between two (normalized) viewports. Rows are aligned
 *  positionally — both sides render the same TUI at the same size, so
 *  structural drift IS a finding, not an alignment problem to paper over. */
export function diffScreens(a: string[], b: string[]): ScreenMismatch[] {
  const rows = Math.max(a.length, b.length);
  const out: ScreenMismatch[] = [];
  for (let i = 0; i < rows; i++) {
    const la = a[i] ?? "";
    const lb = b[i] ?? "";
    if (la !== lb) out.push({ row: i, a: la, b: lb });
  }
  return out;
}

/**
 * The vertical offset between two (normalized) viewports whose content is the
 * same shifted by `k` rows (1 ≤ |k| ≤ maxShift): `b[i + k] === a[i]` on every
 * row both hold, over at least `minOverlap` non-empty rows. Positive k: b's
 * content sits k rows LOWER (a scrolled k rows further). null otherwise.
 * DIAGNOSTIC ONLY: the parity oracle still fails such a pair (§23 — one side
 * scrolled an extra row because a transient frame was taller on that side);
 * this names the shape so a red reads as what it is.
 */
export function verticalShift(a: string[], b: string[], maxShift = 2, minOverlap = 4): number | null {
  const rows = Math.max(a.length, b.length);
  const at = (x: string[], i: number): string => x[i] ?? "";
  for (let s = 1; s <= maxShift; s++) {
    for (const k of [s, -s]) {
      let same = 0;
      let ok = true;
      for (let i = Math.max(0, -k); i + k < rows && i < rows; i++) {
        if (at(a, i) !== at(b, i + k)) { ok = false; break; }
        if (at(a, i) !== "") same++;
      }
      if (ok && same >= minOverlap) return k;
    }
  }
  return null;
}

export function formatScreenDiff(name: string, mismatches: ScreenMismatch[], shift: number | null = null): string {
  const lines = [`screen diff (${name}): ${mismatches.length} row(s) differ`];
  if (shift !== null) {
    const lower = shift > 0 ? "wrapped" : "vanilla";
    lines.push(
      `  (the same content, ${lower} ${Math.abs(shift)} row(s) lower: the other side scrolled ${Math.abs(shift)} more row(s), ` +
        "a transient frame taller on that side — differential-interactive.md §23)",
    );
  }
  for (const m of mismatches) {
    lines.push(`  row ${m.row}:`);
    lines.push(`    vanilla | ${m.a}`);
    lines.push(`    wrapped | ${m.b}`);
  }
  return lines.join("\n");
}

// ── fidelity scans (F1/F2) ─────────────────────────────────────────────────

/** Anything that looks like a (possibly truncated) symbol token. Matches the
 *  full `$MDU:<tool>[hash].field` shape AND bare prefixes — a held partial
 *  ("$MDU:Bash[ab" at a chunk seam) is exactly the A3/A4 leak shape. */
export const SYMBOL_TOKEN_RE = /\$MDU[:\w[\].]*/;

export function screenHasSymbol(lines: string[]): string | null {
  for (const line of lines) {
    const m = SYMBOL_TOKEN_RE.exec(line);
    if (m) return m[0];
  }
  return null;
}

/** Probe present even when hard-wrapped across rows (the A5 shape): the TUI
 *  breaks long lines at the column edge and may indent continuations, so scan
 *  the whitespace-collapsed concatenation. Probes must be unique alphanumeric
 *  runs for this to be collision-safe (differential-scenarios.ts keeps them so). */
export function screenHasProbeWrapped(lines: string[], probe: string): boolean {
  return lines.join("").replace(/\s+/g, "").includes(probe.replace(/\s+/g, ""));
}

/** F1's "the human can see the planted value": verbatim (wrap-aware) match,
 *  or — for long probes the TUI may legitimately elide mid-run when a line
 *  wraps repeatedly — its distinctive prefix AND suffix both present. */
export function probeRendered(lines: string[], probe: string): boolean {
  if (screenHasProbeWrapped(lines, probe)) return true;
  const collapsed = lines.join("").replace(/\s+/g, "");
  const p = probe.replace(/\s+/g, "");
  return p.length > 32 && collapsed.includes(p.slice(0, 24)) && collapsed.includes(p.slice(-8));
}

// ── scrollback residue (F4, reply-row-reservation.md §3.7) ─────────────────

/** A reserve-block marker, whole or in part: a continuation row's `$MDU/`,
 *  its `/<hash>/<i>` tail (a cell-diff fragment such as `/464e/2`), or a
 *  head's `/1:N` suffix. None of these belongs on a human screen. */
export const RESERVE_MARKER_RE = /\$MDU\/|\/[0-9a-f]{4,8}\/\d+|\/1:\d+/;

export interface ScrollbackResidue {
  row: number; // 0-based row of the full scroll history
  text: string;
  why: "marker" | "corrupt";
}

/**
 * F4: rows of the full scroll history (ScreenTap.fullLines) that show what
 * the screen reconciler can no longer heal: a row that scrolled into
 * scrollback before a cell-diff fragment on it was repainted (§3.7,
 * "Residual, stated honestly"). A row is residue when it holds a reserve
 * marker, or when it matches `anchor` (a value row) but equals no `expected`
 * line. Rows compare trimmed, with runs of spaces collapsed, so the content
 * indent and a TAB's expansion do not count. `anchor` should match text a
 * fragment cannot reach: a fragment rewrites only the cells where two
 * markers differ, the index digits at columns 12–13 for a 4-hex hash.
 */
export function reserveResidue(lines: string[], expected: string[], anchor: RegExp): ScrollbackResidue[] {
  const norm = (s: string): string => s.trim().replace(/ {2,}/g, " ");
  const want = new Set(expected.map(norm));
  const out: ScrollbackResidue[] = [];
  lines.forEach((text, row) => {
    if (RESERVE_MARKER_RE.test(text)) out.push({ row, text, why: "marker" });
    else if (anchor.test(text) && !want.has(norm(text))) out.push({ row, text, why: "corrupt" });
  });
  return out;
}

export interface HeldSymbol {
  token: string;
  fromIndex: number; // ring index where the run started
  count: number; // consecutive ring snapshots it persisted
}

/** F2 ring oracle: a symbol token visible across >= minConsecutive CONSECUTIVE
 *  ring snapshots. A single-frame flash is repaint noise; persistence is a
 *  held/opaque symbol the human can read (A2/A3). */
export function findHeldSymbol(
  ring: Array<{ at: number; lines: string[] }>,
  minConsecutive = 3,
): HeldSymbol | null {
  let run = 0;
  let token: string | null = null;
  for (let i = 0; i < ring.length; i++) {
    const hit = screenHasSymbol(ring[i]!.lines);
    if (hit) {
      run++;
      token = hit;
      if (run >= minConsecutive) return { token: token!, fromIndex: i - run + 1, count: run };
    } else {
      run = 0;
      token = null;
    }
  }
  return null;
}
