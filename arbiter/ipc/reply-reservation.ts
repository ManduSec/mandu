/**
 * reply-reservation — the arbiter half of reply row reservation
 * (docs/design/ui/reply-row-reservation.md §3.3, §3.6, §11.5). Mandu-new, no
 * reference origin: the reference implementation rendered replies inside
 * OpenClaw and had no terminal relay to reserve rows on.
 *
 * Three pieces, all privilege-free and unit-tested without a socket:
 *
 *   - {@link shapeLines}: the line count `symbolShape` returns for a resolved
 *     value. ONLY the count leaves this module's caller — never the value, its
 *     length, its widths or its label (§5.2: N is the one new flow).
 *   - {@link parseShapeLayout} / {@link shapeRows} (v2, §11.5): with a
 *     `width` (and optional `first`), `symbolShape` also returns the number of
 *     screen rows the value occupies under `layoutRows` (reserve-layout.ts,
 *     a verbatim copy of the reply filter's module). Again only a count.
 *     `width` and `first` are refused outside the ranges the grammar allows
 *     (§11.3), so a caller cannot probe at arbitrary widths.
 *   - {@link SessionRelayStore}: the in-memory, session-keyed relay state the
 *     reply filter reports (`setSessionRelay`) and the proxy reads
 *     (`sessionRelay`). Modelled on `setSessionSpec`'s in-memory binding, but
 *     NOT bind-once: the filter re-reports on every resize. A missing entry
 *     only costs a reply its reservation (null ⇒ no expansion, §3.6). Since
 *     v2 the state is NOT harmless: `cols` sets the wrap width `W` the proxy
 *     asks `symbolShape` for, and an agent that chose `W` could replay one
 *     secret at widths of its choosing and learn its line lengths from the
 *     row counts. So both relay ops are human-plane ops (server.ts
 *     `HUMAN_PLANE_OPS`, §11.5, arbiter-human-plane.md §3).
 *   - {@link ReserveBlockStore} (§3.8): the blocks the proxy expanded, per
 *     session, by hash (`noteReserveBlock`), so the reply filter can paint a
 *     continuation row whose head never reached the screen (`reserveBlock`).
 *     Tokens and counts only; human-plane ops too.
 */
import type { ReplyTabOrigin, ReserveBlockWire, SessionRelayMode, SessionRelayWire } from "./protocol.js";
import { LAYOUT_RULES, layoutRows, layoutWidth, type LayoutRule } from "./reserve-layout.js";

/** The TAB origins a reply filter can report (§19.7). */
export const TAB_ORIGINS: readonly ReplyTabOrigin[] = ["screen", "content"];

/** The relay modes a reply filter can report (reply-filter `relay_mode`). */
export const SESSION_RELAY_MODES: readonly SessionRelayMode[] = ["pty", "pipe", "passthrough"];

/** Upper bound on `cols` / `rows` (a terminal is never this large; anything
 *  above is a malformed report, refused rather than clamped). */
export const SESSION_RELAY_MAX_DIM = 10_000;

/** Upper bound on a relay session key's length (a scope id is ~40 chars). */
export const SESSION_RELAY_MAX_KEY = 512;

/** Upper bound on the number of sessions held. The map must not grow without
 *  bound whoever reports (kept as defence in depth now that the relay ops are
 *  human-plane only); past the cap the least-recently-reported session is
 *  evicted (it then reads null, i.e. no expansion — the fail-safe direction). */
export const SESSION_RELAY_MAX_SESSIONS = 4096;

/**
 * The number of rows a resolved value occupies on the human's screen when
 * each of its lines gets one row (§3.3): drop exactly ONE trailing line break
 * (`\r\n`, `\n` or `\r`), then count the lines split on any line break. An
 * empty value is one (empty) line.
 */
export function shapeLines(value: string): number {
  let v = value;
  if (v.endsWith("\r\n")) v = v.slice(0, -2);
  else if (v.endsWith("\n") || v.endsWith("\r")) v = v.slice(0, -1);
  return v.split(/\r\n|\r|\n/).length;
}

/** The narrowest content width `symbolShape` lays out at (§11.3 `W`). */
export const SHAPE_MIN_WIDTH = 20;
/** The widest content width `symbolShape` lays out at (§11.3 `W`). */
export const SHAPE_MAX_WIDTH = 1000;

/** A validated `symbolShape` layout request: `first` defaults to `width`;
 *  `rule` absent is `ink`. */
export interface ShapeLayout {
  width: number;
  first: number;
  rule?: LayoutRule;
  /** The content area's terminal column (§11.2, the TAB stops); absent: 0. */
  indent?: number;
}

/** Whether `v` names a wrap rule (§17). */
export function isLayoutRule(v: unknown): v is LayoutRule {
  return typeof v === "string" && (LAYOUT_RULES as readonly string[]).includes(v);
}

/**
 * Validate `symbolShape`'s optional `width` / `first` / `rule` / `indent`
 * (§11.3, §11.5, §17, §11.2).
 *
 *   - none present → null (v1: a line count only);
 *   - `width`: an integer from {@link SHAPE_MIN_WIDTH} to {@link SHAPE_MAX_WIDTH};
 *   - `first`: 0, or an integer from ⌈width/2⌉ to width; absent ⇒ `width`;
 *   - `rule`: `ink` or `terminal`; absent ⇒ `ink`;
 *   - `indent`: the terminal column the content area starts at (the
 *     relay's columns minus `width`), an integer from 0 to
 *     {@link SESSION_RELAY_MAX_DIM}; absent ⇒ 0. It moves only the TAB stops;
 *   - `first`, `rule` or `indent` without `width` is refused.
 *
 * Returns the layout, null, or an error string. Anything but `undefined`
 * counts as present (a JSON `null` is refused, not read as absent).
 */
export function parseShapeLayout(
  req: { width?: unknown; first?: unknown; rule?: unknown; indent?: unknown }, op = "symbolShape",
): ShapeLayout | null | string {
  const { width, first, rule, indent } = req;
  if (width === undefined) {
    if (first !== undefined) return `${op}: first requires width`;
    if (indent !== undefined) return `${op}: indent requires width`;
    return rule === undefined ? null : `${op}: rule requires width`;
  }
  if (typeof width !== "number" || !Number.isInteger(width) || width < SHAPE_MIN_WIDTH || width > SHAPE_MAX_WIDTH) {
    return `${op}: width must be an integer from ${SHAPE_MIN_WIDTH} to ${SHAPE_MAX_WIDTH}`;
  }
  if (rule !== undefined && !isLayoutRule(rule)) return `${op}: rule must be one of ${LAYOUT_RULES.join(", ")}`;
  if (indent !== undefined &&
    (typeof indent !== "number" || !Number.isInteger(indent) || indent < 0 || indent > SESSION_RELAY_MAX_DIM)) {
    return `${op}: indent must be an integer from 0 to ${SESSION_RELAY_MAX_DIM}`;
  }
  const r = { ...(rule !== undefined ? { rule } : {}), ...(indent !== undefined ? { indent } : {}) };
  if (first === undefined) return { width, first: width, ...r };
  const lo = Math.ceil(width / 2);
  if (typeof first !== "number" || !Number.isInteger(first) || (first !== 0 && (first < lo || first > width))) {
    return `${op}: first must be 0 or an integer from ${lo} to ${width}`;
  }
  return { width, first, ...r };
}

/**
 * The number of screen rows a resolved value occupies at content width
 * `width`, its first row `first` wide, under the wrap `rule`, its TAB
 * stops counted from the content area's column `indent` (§11.2
 * `layoutRows`, §17). Only the count leaves: the rows' text never does.
 */
export function shapeRows(value: string, layout: ShapeLayout): number {
  return layoutRows(value, layout.width, layout.first, layout.rule, layout.indent).length;
}

/**
 * The rows and the display width of the LAST row at that layout (§14): the
 * proxy breaks the model's text after a mid-line block where the joined line
 * would wrap, so the text after the value never clips. A width, never text.
 */
export function shapeRowsLast(value: string, layout: ShapeLayout): { rows: number; last: number } {
  const rows = layoutRows(value, layout.width, layout.first, layout.rule, layout.indent);
  return { rows: rows.length, last: rows.length === 0 ? 0 : layoutWidth(rows[rows.length - 1]!.text) };
}

/** A validated `setSessionRelay` request body. */
export interface SessionRelayInput {
  sessionKey: string;
  mode: SessionRelayMode;
  reserve: boolean;
  cols?: number;
  rows?: number;
  /** The filter paints v2 (`T/1:N:W:F`) heads (§11.5). Absent: a v1 filter. */
  wrap?: boolean;
  /** The agent's TUI wraps its reply by this rule (§17). Absent: `ink`. */
  rule?: LayoutRule;
  /** Where the agent's TUI counts a reply TAB's stops from (§19.7). Absent:
   *  `screen`. */
  tabs?: ReplyTabOrigin;
}

function validDim(v: unknown): boolean {
  return typeof v === "number" && Number.isInteger(v) && v > 0 && v <= SESSION_RELAY_MAX_DIM;
}

/** Validate a relay session key. Returns an error string, or null when valid. */
export function relaySessionKeyProblem(op: string, sessionKey: unknown): string | null {
  if (typeof sessionKey !== "string" || sessionKey === "") return `${op}: sessionKey required`;
  if (sessionKey.length > SESSION_RELAY_MAX_KEY) {
    return `${op}: sessionKey longer than ${SESSION_RELAY_MAX_KEY} characters`;
  }
  return null;
}

/**
 * Strictly validate a `setSessionRelay` body. Returns the input to store, or
 * an error string — never a half-valid entry.
 */
export function parseSessionRelay(req: Record<string, unknown>): SessionRelayInput | string {
  const keyProblem = relaySessionKeyProblem("setSessionRelay", req.sessionKey);
  if (keyProblem) return keyProblem;
  if (typeof req.mode !== "string" || !(SESSION_RELAY_MODES as readonly string[]).includes(req.mode)) {
    return `setSessionRelay: mode must be one of ${SESSION_RELAY_MODES.join(", ")}`;
  }
  if (typeof req.reserve !== "boolean") return "setSessionRelay: reserve must be a boolean";
  if (req.wrap !== undefined && typeof req.wrap !== "boolean") return "setSessionRelay: wrap must be a boolean";
  if (req.rule !== undefined && !isLayoutRule(req.rule)) {
    return `setSessionRelay: rule must be one of ${LAYOUT_RULES.join(", ")}`;
  }
  if (req.tabs !== undefined && !(typeof req.tabs === "string" && (TAB_ORIGINS as readonly string[]).includes(req.tabs))) {
    return `setSessionRelay: tabs must be one of ${TAB_ORIGINS.join(", ")}`;
  }
  for (const dim of ["cols", "rows"] as const) {
    if (req[dim] !== undefined && !validDim(req[dim])) {
      return `setSessionRelay: ${dim} must be a positive integer ≤ ${SESSION_RELAY_MAX_DIM}`;
    }
  }
  return {
    sessionKey: req.sessionKey as string,
    mode: req.mode as SessionRelayMode,
    reserve: req.reserve,
    ...(req.cols !== undefined ? { cols: req.cols as number } : {}),
    ...(req.rows !== undefined ? { rows: req.rows as number } : {}),
    ...(req.wrap !== undefined ? { wrap: req.wrap as boolean } : {}),
    ...(req.rule !== undefined ? { rule: req.rule as LayoutRule } : {}),
    ...(req.tabs !== undefined ? { tabs: req.tabs as ReplyTabOrigin } : {}),
  };
}

/** In-memory relay state per session (lost on restart: null ⇒ no expansion). */
export class SessionRelayStore {
  private readonly bySession = new Map<string, SessionRelayWire>();

  constructor(private readonly maxSessions: number = SESSION_RELAY_MAX_SESSIONS) {}

  /** Record (or overwrite) a session's relay state, stamped `now`. */
  set(input: SessionRelayInput, now: number = Date.now()): SessionRelayWire {
    const { sessionKey, ...rest } = input;
    const entry: SessionRelayWire = { ...rest, updatedAt: now };
    // Re-insert so Map order is report recency (the eviction order).
    this.bySession.delete(sessionKey);
    this.bySession.set(sessionKey, entry);
    while (this.bySession.size > this.maxSessions) {
      const oldest = this.bySession.keys().next().value;
      if (oldest === undefined) break;
      this.bySession.delete(oldest);
    }
    return entry;
  }

  /** The session's relay state, or null when never reported (or evicted). */
  get(sessionKey: string): SessionRelayWire | null {
    const e = this.bySession.get(sessionKey);
    return e ? { ...e } : null;
  }

  /** Drop a session's relay state (the deleteSession / retention path). */
  delete(sessionKey: string): boolean {
    return this.bySession.delete(sessionKey);
  }

  get size(): number {
    return this.bySession.size;
  }
}

// ── the reserve-block registry (reply-row-reservation.md §3.8) ─────────────

/** Largest N a registered block can carry (the grammar's RESERVE_ROWS_LIMIT). */
export const RESERVE_BLOCK_MAX_ROWS = 200;

/** Upper bound on the blocks held per session; past it the least recently
 *  noted is forgotten (its continuation rows then paint blank, as before). */
export const RESERVE_BLOCKS_PER_SESSION = 1024;

/** A validated `noteReserveBlock` request body. `token` is canonical
 *  (unescaped) and exactly one symbol token; `hash` is its bracket hash. */
export interface ReserveBlockInput {
  sessionKey: string;
  hash: string;
  token: string;
  n: number;
  /** v2 heads only (`T/1:N:W:F`): the layout the block was sized at. */
  width?: number;
  first?: number;
}

/** The bracket hash of a canonical symbol token (`$MDU:tag[464e].f` →
 *  `464e`), or null. The continuation rows `$MDU/<hash>/<i>` carry it. */
export function reserveBlockHash(token: string): string | null {
  const m = /\[([0-9a-f]{4,8})\]/.exec(token);
  return m ? m[1]! : null;
}

/**
 * Strictly validate a `noteReserveBlock` body whose `token` the caller has
 * already unescaped and checked to be exactly one symbol token. `n` is an
 * integer 2..{@link RESERVE_BLOCK_MAX_ROWS}; `width`/`first` follow
 * {@link parseShapeLayout}'s ranges and come together or not at all.
 * Returns the input to store, or an error string.
 */
export function parseReserveBlock(req: Record<string, unknown>, token: string): ReserveBlockInput | string {
  const keyProblem = relaySessionKeyProblem("noteReserveBlock", req.sessionKey);
  if (keyProblem) return keyProblem;
  const hash = reserveBlockHash(token);
  if (hash === null) return "noteReserveBlock: token has no hash";
  const n = req.n;
  if (typeof n !== "number" || !Number.isInteger(n) || n < 2 || n > RESERVE_BLOCK_MAX_ROWS) {
    return `noteReserveBlock: n must be an integer from 2 to ${RESERVE_BLOCK_MAX_ROWS}`;
  }
  if ((req.width === undefined) !== (req.first === undefined)) {
    return "noteReserveBlock: width and first come together";
  }
  const layout = parseShapeLayout(req, "noteReserveBlock");
  if (typeof layout === "string") return layout;
  return {
    sessionKey: req.sessionKey as string,
    hash,
    token,
    n,
    ...(layout ? { width: layout.width, first: layout.first } : {}),
  };
}

/**
 * The blocks the proxy expanded, per session: hash → the head it sent. The
 * reply filter reads one back when a continuation row reaches the screen but
 * its head never did (a block taller than a fullscreen renderer's viewport
 * shows only its tail). It holds tokens and counts, never an original.
 * In memory; lost on restart (the rows then paint blank, the old fail-safe).
 */
export class ReserveBlockStore {
  private readonly bySession = new Map<string, Map<string, ReserveBlockWire>>();

  constructor(
    private readonly maxSessions: number = SESSION_RELAY_MAX_SESSIONS,
    private readonly perSession: number = RESERVE_BLOCKS_PER_SESSION,
  ) {}

  note(input: ReserveBlockInput): void {
    const { sessionKey, hash, ...block } = input;
    const blocks = this.bySession.get(sessionKey) ?? new Map<string, ReserveBlockWire>();
    this.bySession.delete(sessionKey); // re-insert: Map order is recency
    this.bySession.set(sessionKey, blocks);
    blocks.delete(hash);
    blocks.set(hash, block);
    while (blocks.size > this.perSession) {
      const oldest = blocks.keys().next().value;
      if (oldest === undefined) break;
      blocks.delete(oldest);
    }
    while (this.bySession.size > this.maxSessions) {
      const oldest = this.bySession.keys().next().value;
      if (oldest === undefined) break;
      this.bySession.delete(oldest);
    }
  }

  /** The block last noted for `hash` in the session, or null. */
  get(sessionKey: string, hash: string): ReserveBlockWire | null {
    const b = this.bySession.get(sessionKey)?.get(hash);
    return b ? { ...b } : null;
  }

  /** Drop a session's blocks (the deleteSession / retention path). */
  delete(sessionKey: string): boolean {
    return this.bySession.delete(sessionKey);
  }
}
