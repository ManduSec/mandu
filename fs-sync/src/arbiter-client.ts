/**
 * arbiter-client — the arbiter dependency the fs-sync view-sync speaks to.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. Pattern mirrored from
 *     interceptors/anthropic-proxy/src/arbiter-client.ts
 *   (narrow interface + adapter over the real arbiter IPC client + a mock for
 *   tests). No reference-source origin — adfi-openclaw's fs-sync modules called
 *   the symbol table in-process (loadSymbolMap / resolveAllSymbols /
 *   allocateDerivedSymbol / obsoleteSymbol). Mandu promotes the symbol table
 *   to a arbiter daemon, so fs-sync MUST go through this IPC surface instead and
 *   NEVER open the symbol DB directly (the arbiter is the single owner).
 *
 * The op shapes mirror arbiter/ipc/protocol.ts and arbiter/ipc/client.ts exactly:
 *   - symbolize({tool, value, field?, origin?, sessionKey?, callId?}) -> symbol
 *   - desymbolize(text)                                               -> text
 *   - resolve(symbol)                                                 -> value | null
 *
 * SECURITY-INVARIANT NOTE: this is the ONLY channel by which fs-sync turns
 * untrusted file content into a symbol (ingress) or a symbol back into raw
 * content (egress). If a arbiter op fails the caller FAILS CLOSED: on the read /
 * symbolize path it must refuse to expose content to the AgentView rather than
 * fall back to raw bytes. Callers in this package treat a rejected symbolize as
 * a hard error for exactly that reason.
 *
 * THE HUMAN PLANE (docs/design/architecture/arbiter-human-plane.md): `desymbolize`, shallow
 * `resolve`, `events` and `subscribe` return originals, so the arbiter serves
 * them ONLY on its human-plane socket ($MANDU_ARBITER_HUMAN_SOCK), never on
 * the data socket the agent world can reach. fs-sync is a human-plane
 * consumer end to end (it writes originals into the HumanView), so the CLI
 * builds its one client over the HUMAN socket (the human channel accepts the
 * data-plane ops too). No human socket → the CLI refuses to run (fail closed,
 * like an unreachable arbiter); it never asks the data socket instead — the
 * data socket would refuse every one of those ops, and a sync that could not
 * desymbolize writes nothing.
 */

/** The env var naming the human-plane socket (arbiter/ipc/instance.ts
 *  HUMAN_SOCK_ENV, mirrored so this package typechecks standalone). */
export const HUMAN_SOCK_ENV = "MANDU_ARBITER_HUMAN_SOCK";

/** The human-plane socket fs-sync talks to, or null. ONLY
 *  $MANDU_ARBITER_HUMAN_SOCK: a set data socket is never a fallback. */
export function humanSockFromEnv(env: NodeJS.ProcessEnv = process.env): string | null {
  const v = env[HUMAN_SOCK_ENV];
  return typeof v === "string" && v !== "" ? v : null;
}

/** Symbol regex shape, kept in sync with arbiter/symbol-table/symbol-format.ts
 * `MDU_SYM_FORMAT.pattern`. fs-sync needs a LOCAL detector (line-map building,
 * "does this AgentView file still carry symbols?") that does not require a
 * arbiter round-trip per line. This is a pure read-only predicate over text the
 * arbiter already produced; it allocates/owns nothing. */
export const SYMBOL_PATTERN =
  /\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*|\$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\]/g;

/** Substring every symbol contains (fast pre-check). Mirrors the format prefix. */
export const SYMBOL_PREFIX = "$MDU:";

/** True if `text` contains any symbol reference. Format-prefix fast path first. */
export function hasSymbols(text: string): boolean {
  if (!text.includes(SYMBOL_PREFIX)) return false;
  SYMBOL_PATTERN.lastIndex = 0;
  return SYMBOL_PATTERN.test(text);
}

/**
 * The confidentiality level a symbol NAME advertises through its marker
 * (`$MDU:nomodel_…`, `$MDU:localmodel_…`, `$MDU:anymodel_…`, else public). A twin of the
 * arbiter's `levelFromSymbolName` (symbol-format.ts) — the packages install
 * independently; KEEP IN SYNC. The table row is authoritative for every
 * decision (confidentiality.md §2); fs-sync reads the marker only to decide
 * whether to RE-MINT a seeded twin, which then sets the row from scratch.
 */
export function levelOfSymbolName(name: string): "no-model" | "local-model" | "any-model" | "public" {
  if (name.startsWith("$MDU:anymodel_")) return "any-model";
  if (name.startsWith("$MDU:localmodel_")) return "local-model";
  if (name.startsWith("$MDU:nomodel_")) return "no-model";
  return "public";
}

/** Return every distinct symbol name appearing in `text`, in first-seen order. */
export function extractSymbols(text: string): string[] {
  if (!text.includes(SYMBOL_PREFIX)) return [];
  SYMBOL_PATTERN.lastIndex = 0;
  const seen = new Set<string>();
  for (const m of text.matchAll(SYMBOL_PATTERN)) seen.add(m[0]);
  return [...seen];
}

/** Mirrors arbiter/ipc/protocol.ts `SymbolizeRequest` (minus id/op). */
export interface SymbolizeArgs {
  tool: string;
  value: string;
  field?: string;
  origin?: string;
  sessionKey?: string;
  callId?: string;
  /** Parent symbol for a derived mint — the human-edit split path
   *  (symbol-lineage.md G2). Stored in symbols.derived_from. */
  derivedFrom?: string;
  /** End-exclusive `start:end` line span within the parent value. */
  lineRange?: string;
}

/**
 * The narrow arbiter surface fs-sync depends on. Anything that satisfies this —
 * the real adapter or a mock — can drive the view-sync. Deliberately a SUBSET
 * of the full arbiter client (no classify/handlingPrompt/recordToolCall; those
 * belong to Track A / the policy path, not the FS view-sync).
 */
export interface SymbolArbiter {
  /** Allocate (or reuse) a symbol for an untrusted value. Ingress. */
  symbolize(args: SymbolizeArgs): Promise<string>;
  /** Replace every known symbol reference in `text` with its raw value. Egress. */
  desymbolize(text: string): Promise<string>;
  /** Resolve one symbol name to its raw value, or null if unknown/obsoleted. */
  resolve(symbol: string): Promise<string | null>;
  /** Original field metadata, not the encoded wire suffix. Absent on older clients. */
  symbolProvenance?(symbol: string): Promise<{ field?: string | null } | null>;
  /**
   * OPTIONAL: the confidentiality level the arbiter would mint for a read of
   * `path` today (`{ level, axis }`; `axis: false` = the confidentiality axis
   * is OFF). The re-launch fast path compares it with the marker a seeded
   * twin's token carries and re-seeds on a mismatch (fs-sync.md §3
   * §2). Absent on older arbiters → the comparison is skipped.
   */
  pathLevel?(path: string): Promise<{ level: string; axis: boolean }>;
  /**
   * Provenance lookup (Plan 1 `fileTrust`): is this file untrusted-by-origin?
   * Dual-keyed — supply contentHash and/or path; the arbiter returns untrusted
   * if EITHER matches (fail-closed). Used to close the read fast-path and to
   * re-symbolize tainted-raw files at sync (design §4).
   */
  fileTrust(args: { contentHash?: string; path?: string }): Promise<{ untrusted: boolean; origin?: string }>;
  /**
   * OPTIONAL, OBSERVABILITY ONLY (symbol-lineage.md G1): append a symbol-birth
   * event to the arbiter's per-session event stream. BEST-EFFORT and off the
   * security path — callers (src/events.ts `emitBirth`) swallow every failure,
   * and a mock without this method disables emission entirely. Nothing may
   * gate on it.
   */
  emit?(event: object): Promise<number>;
}

/** A stored observability event as delivered by the arbiter's `events` /
 * `subscribe` ops (arbiter/events/event-store.ts `StoredEvent`). Opaque to
 * fs-sync except for the arbiter-assigned `seq` — the "subscribe from now"
 * cursor. The eager-sync driver reads the rest tolerantly (unknown shape). */
export interface StoredEventLike {
  seq: number;
  [key: string]: unknown;
}

/** Handle to an open event subscription; close() ends the dedicated stream
 * connection (the arbiter drops the subscriber when the socket closes). */
export interface EventStreamHandle {
  close(): void;
}

/**
 * Structural shape of the real arbiter IPC client (arbiter/ipc/client.ts). We
 * declare it here rather than importing so this package typechecks standalone
 * (the arbiter is a sibling package owned by another sub-agent). The symbol ops
 * fs-sync uses landed in M0 and are stable; the event-stream ops (ping/events/
 * subscribe) are the dashboard-proven observability surface the eager-sync
 * watcher rides (fs-sync.md §2.4 option B).
 */
export interface RealArbiterClient {
  connect(): Promise<void>;
  symbolize(args: SymbolizeArgs): Promise<string>;
  desymbolize(text: string): Promise<string>;
  resolve(symbol: string): Promise<string | null>;
  symbolProvenance?(symbol: string): Promise<{ field?: string | null }>;
  pathLevel?(path: string): Promise<{ level: string; bindings: string[]; axis: boolean }>;
  fileTrust(args: { contentHash?: string; path?: string }): Promise<{ untrusted: boolean; origin?: string }>;
  emit(event: object): Promise<number>;
  ping(): Promise<unknown>;
  events(sessionId: string, sinceSeq?: number): Promise<StoredEventLike[]>;
  subscribe(
    sessionId: string,
    sinceSeq: number,
    onEvent: (event: StoredEventLike) => void,
  ): Promise<EventStreamHandle>;
  close(): void;
}

/**
 * Adapter: present the real arbiter IPC client as a `SymbolArbiter`. The
 * client must be one over the HUMAN-PLANE socket (see the header): on the
 * data socket `desymbolize` / `resolve` are refused. Used at
 * deployment (the Rust fs-supervisor will host an equivalent over the same wire
 * protocol; this TS adapter serves TS callers and the test/integration path).
 */
export class ArbiterClientAdapter implements SymbolArbiter {
  constructor(private readonly client: RealArbiterClient) {}

  async symbolize(args: SymbolizeArgs): Promise<string> {
    return this.client.symbolize(args);
  }

  async desymbolize(text: string): Promise<string> {
    return this.client.desymbolize(text);
  }

  async resolve(symbol: string): Promise<string | null> {
    return this.client.resolve(symbol);
  }

  async symbolProvenance(symbol: string): Promise<{ field?: string | null } | null> {
    return this.client.symbolProvenance ? this.client.symbolProvenance(symbol) : null;
  }
  async pathLevel(path: string): Promise<{ level: string; axis: boolean }> {
    // An older arbiter has no derivation to ask: answer "axis off" so the
    // relabel guard is a no-op there (the fast path keeps its other checks).
    if (!this.client.pathLevel) return { level: "public", axis: false };
    const r = await this.client.pathLevel(path);
    return { level: r.level, axis: r.axis };
  }

  async fileTrust(args: { contentHash?: string; path?: string }): Promise<{ untrusted: boolean; origin?: string }> {
    return this.client.fileTrust(args);
  }

  async emit(event: object): Promise<number> {
    return this.client.emit(event);
  }
}

/**
 * The narrow event-stream surface the eager-sync watcher depends on
 * (fs-sync.md §2.4 option B). Anything satisfying it — the real adapter
 * below or a test mock — can feed the `watch` command's EagerSync driver.
 *
 * OBSERVABILITY ONLY, deliberately separate from `SymbolArbiter`: the event
 * stream is the documented ONE-WAY, BEST-EFFORT channel. Nothing security-
 * relevant may gate on it — a dropped event or dead stream means a staler
 * HumanView until the launcher's unconditional post-exit sweep, never anything
 * worse (design §5). The view-sync library needs only symbols; only the watch
 * CLI needs events.
 */
export interface EventStreamArbiter {
  /**
   * Subscribe to a session's live event feed from "now" — the current end of
   * the persisted log — so history is NEVER replayed into sync triggers.
   * Resolves once the stream is live; the handle's close() ends it.
   */
  subscribeFromNow(
    sessionId: string,
    onEvent: (event: StoredEventLike) => void,
  ): Promise<EventStreamHandle>;
  /** Liveness probe — the watch health loop's outage-warn/resubscribe signal. */
  ping(): Promise<void>;
}

/**
 * Adapter: present the real arbiter IPC client as an `EventStreamArbiter`.
 * "Now" is computed by reading the session's persisted events once and
 * subscribing with the max seq as the cursor: the arbiter replays only events
 * with seq > cursor, so anything emitted between the read and the subscribe is
 * still delivered (a near-now trigger we want), while genuine history is not.
 */
export class ArbiterEventStreamAdapter implements EventStreamArbiter {
  constructor(private readonly client: RealArbiterClient) {}

  async subscribeFromNow(
    sessionId: string,
    onEvent: (event: StoredEventLike) => void,
  ): Promise<EventStreamHandle> {
    const persisted = await this.client.events(sessionId, 0);
    let last = 0;
    for (const e of persisted) {
      if (typeof e.seq === "number" && e.seq > last) last = e.seq;
    }
    return this.client.subscribe(sessionId, last, onEvent);
  }

  async ping(): Promise<void> {
    await this.client.ping();
  }
}
