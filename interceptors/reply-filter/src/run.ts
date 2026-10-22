#!/usr/bin/env tsx
/**
 * run — the Mandu user-reply egress CLI (cooperative wrapper layer).
 *
 * The launcher (`mandu-run.sh --reply-filter`) prepends this wrapper to the
 * agent command:  reply-filter -- claude -p "…". We spawn the agent with its
 * output routed through the desymbolizing stream filter (src/filter.ts), so
 * the human sees ORIGINAL data where the agent's context holds $MDU:*
 * tokens — the paper's "resolve symbols in user-facing replies" (OpenClaw
 * hook: message_sending), realized on the process output channel.
 *
 * Flow (all failures DEGRADE to passthrough — this is a utility surface, the
 * inverse of the enforcement chokepoints; a symbol shown raw leaks nothing):
 *   0. Mode decision (src/print-mode.ts; see TTY SAFETY below): pipe / pty /
 *      passthrough.
 *   1. MANDU_ARBITER_HUMAN_SOCK set + the human plane reachable → filter the
 *      child's output through the arbiter's deep desymbolize (served only on
 *      the human-plane socket: docs/design/architecture/arbiter-human-plane.md). Else →
 *      NOTE to stderr + spawn the agent with stdio fully inherited (zero
 *      interposition). NEVER the data socket instead.
 *   2. stdin/stderr inherit; SIGINT/SIGTERM/SIGHUP(/SIGWINCH in pty mode)
 *      forward.
 *   3. Exit with the child's exit code (or 128+n convention via re-kill on a
 *      signal death), after flushing the filter tail.
 *
 * TTY SAFETY (src/print-mode.ts decides per run):
 *   - "pipe": the child's stdout is a pipe through the filter. Used when
 *     stdout is already a pipe (captured runs) and for known PRINT-mode
 *     invocations on a TTY (`claude -p/--print …`, `codex exec …`).
 *   - "pty": PTY RELAY for interactive TUIs on a TTY — the child runs under
 *     util-linux `script(1)`, which gives it a REAL pseudo-terminal (raw-mode
 *     stdin forwarding, SIGWINCH resize, exit-code propagation via -e) and
 *     relays the session to script's stdout, which WE pipe through the filter
 *     to the real terminal. The child's stderr merges into the pty (script
 *     semantics), so symbols there resolve too. The filter runs in EAGER mode
 *     (filter.ts): every chunk is emitted immediately with tokens resolved
 *     inline — cursor-control sequences and unterminated prompt lines are
 *     never delayed (a delayed hide-cursor reads as a blinking cursor) — and
 *     only a suffix that could still be an in-flight token is held, drained
 *     after IDLE_DRAIN_MS of stream silence. Backend is util-linux `script(1)`
 *     on Linux, BSD `script(1)` on macOS (pty-relay.ts); degrades to
 *     passthrough where neither is available (win32, no `script` on PATH).
 *     BSD script relays neither a resize nor a signal to the child, so on
 *     macOS a companion (bsd-relay.ts) re-sizes the child's pty on a terminal
 *     resize, sends INT/TERM/HUP to the child instead of script, and reports
 *     a death by a signal it delivered as 128+n (docs/design/agents/pty-relay.md).
 *     Tokens the TUI hard-wraps across screen rows are AGGRESSIVELY
 *     reassembled (filter.ts: wrap insertions — \r/\n, indent, ANSI escapes —
 *     are looked through when matching, and an incomplete prefix at an emit
 *     boundary is held for its continuation); the distinctive token grammar
 *     makes false candidates vanishingly rare, and a false candidate merely
 *     fails the arbiter lookup and passes through byte-identical.
 *   - "passthrough": stdio fully inherited, zero interposition (symbols stay
 *     opaque — nothing leaks).
 *
 * EARLY START (src/handoff.ts, packaging.md §5.3): started as
 * `reply-filter --mandu-handoff-fd=3`, the wrapper loads its modules and
 * waits for the launcher to hand it the command, environment, directory and
 * the launch scope's prefix over fd 3; from there it runs exactly as the
 * serial form `reply-filter -- <command>` does, with the scope prefix in front
 * of whatever it spawns. An end of file first (the launch stopped) ends it
 * silently.
 *
 * Env:
 *   MANDU_ARBITER_HUMAN_SOCK  the arbiter's HUMAN-PLANE socket (optional —
 *                         absent/unreachable → passthrough). Deleted from the
 *                         child's env (the agent is never told its name).
 *   MANDU_ARBITER_SOCK  the arbiter's data socket — the best-effort
 *                         passthrough health record, and the `hello` that
 *                         re-learns a restarted arbiter's NEW human socket
 *                         (arbiter-human-plane.md §5.1). Never asked to
 *                         desymbolize.
 *   MANDU_SCOPE_ID      session id for the best-effort `desymbolize` events
 *                         (absent → events are skipped; filtering still works).
 *   MANDU_REPLY_FILTER_FORCE=1  force pipe filtering regardless of TTY-ness.
 *   MANDU_REPLY_FILTER_PTY      "1" force the PTY relay (even on a pipe —
 *                         tests/nested setups); "0" disable it (interactive
 *                         TUIs fall back to passthrough, the pre-relay
 *                         behavior); unset → auto (relay interactive TTY runs).
 *   MANDU_REPLY_RESERVE=0 the row-reservation kill switch: the relay reports
 *                         `reserve: false`, so the proxy never expands a
 *                         multi-line token into a reserve block (blocks that
 *                         arrive anyway are still painted).
 *   MANDU_REPLY_WRAP_RULE=terminal  the agent's TUI prints its reply raw at
 *                         column 0 and leaves the wrap to the terminal (the
 *                         launcher sets it for Goose, §17): the relay reports
 *                         `rule: "terminal"` and reserved rows are painted by
 *                         character wrap at the full width. Deleted from the
 *                         child's env.
 *   MANDU_REPLY_TAB_ORIGIN=content  the agent's TUI expands a reply TAB
 *                         itself, from its text's left column (the launcher
 *                         sets it for Claude Code, reply-row-reservation.md
 *                         §19.7): the relay reports `tabs: "content"` and TAB
 *                         stops count from there. Deleted from the child's env.
 *
 * RELAY REPORT (docs/design/ui/reply-row-reservation.md §3.6): once the mode is
 * decided the wrapper tells the arbiter (`setSessionRelay`, keyed by
 * MANDU_SCOPE_ID; skipped when unset) which mode this session got and whether
 * it paints reserve blocks (`reserve` is true only for the PTY relay, and
 * `wrap: true` rides with it: this filter paints v2 heads, §11.3; with them
 * `rule: "terminal"` under MANDU_REPLY_WRAP_RULE, §17), and
 * reports again on every terminal resize (cols/rows: v2's content width).
 * The report goes ONLY over the HUMAN-plane client ($MANDU_ARBITER_HUMAN_SOCK,
 * the same client the filter resolves over): the op is human-plane (§11.5),
 * because `cols` sets W and an agent that could set W could learn a value's
 * line lengths. Without a human socket the relay stays unreported. Best-effort
 * and never on the output path: an error or an arbiter without the op is
 * swallowed, and the only cost is that the proxy does not expand (today's
 * rendering).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants as osConstants } from "node:os";
import { closeSync, constants as fsConstants, fstatSync, openSync, writeSync } from "node:fs";

import { ReplyStreamFilter, placeholderNames } from "./filter.js";
import { StructuredReplyFilter } from "./structured-filter.js";
import { replyOutputFormat, parseReplyInvocation } from "./output-format.js";
import { decideMode, type ReplyFilterMode } from "./print-mode.js";
import { buildPtyArgv, ptyFlavor, ptyRelayAvailable, ptyRelayEnv, ptyStdinProblem, stdinFacts } from "./pty-relay.js";
import { BsdRelayCompanion, realBsdRelayDeps } from "./bsd-relay.js";
import { ScreenReconciler } from "./screen-reconcile.js";
import { WatchedResolver } from "./resolve-health.js";
import { HANDOFF_FLAG, applyHandoff, handoffArgv, handoffChannel, receiveHandoff } from "./handoff.js";
import { RESERVE_CACHE_MAX, ReserveValueCache, sessionRelay, tabOrigin, wrapRule } from "./reserve-block.js";
import {
  ArbiterClientAdapter, childEnv, humanSockFromEnv, HUMAN_SOCK_ENV,
  type RealArbiterClient, type ReplyArbiter, type SessionRelay,
} from "./arbiter-client.js";

/** PTY relay: stream-quiet interval after which a HELD CANDIDATE (a suffix
 *  that could still be an in-flight token — the only thing eager mode ever
 *  holds) drains via filter.flush() — bounds display latency at a prompt that
 *  ends token-shaped. Ordinary frames hold nothing and are never delayed. */
const IDLE_DRAIN_MS = 200;

/** A degrade or a failure: on stderr in every display, and in the launch's
 *  log (launch-log.ts) when the launch names one. */
function note(message: string): void {
  const line = `mandu-reply-filter: ${message}`;
  toLaunchLog(line);
  process.stderr.write(`${line}\n`);
}

/** An all-is-well notice. The launcher's display policy (launcher/src/
 *  launch-banner.ts, packaging.md §5) prints one banner line by default
 *  (healthy rung lines only under --verbose) and tells this wrapper so via
 *  MANDU_LAUNCH_DISPLAY=compact: then the notice goes to the launch's log
 *  only; degrades and failures still use `note`. */
function info(message: string): void {
  const line = `mandu-reply-filter: ${message}`;
  if (process.env["MANDU_LAUNCH_DISPLAY"] === "compact") { toLaunchLog(line); return; }
  note(message);
}

/** Append one line to the launch's log, `MANDU_LAUNCH_LOG` (absolute; the
 *  launcher made it 0600). Never through a link at the name, never creates
 *  it, never a FIFO's open that blocks. Best-effort. */
function toLaunchLog(line: string): void {
  const p = process.env["MANDU_LAUNCH_LOG"];
  if (p === undefined || !p.startsWith("/")) return;
  try {
    const fd = openSync(p, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
    try {
      if (fstatSync(fd).isFile()) writeSync(fd, `${line.replace(/[\r\n]+/g, " ")}\n`);
    } finally {
      closeSync(fd);
    }
  } catch { /* best-effort */ }
}

/** The arbiter client module's specifier, assembled at runtime so the arbiter
 *  package is not statically resolved into this program (mirrors
 *  interceptors/exec-wrap/src/wrap.ts buildArbiter). A BUNDLED build
 *  (packaging.md §5) sets MANDU_ARBITER_CLIENT_MODULE to the co-located
 *  dist/arbiter-client.mjs — import.meta.url has moved to launcher/dist/, so
 *  the relative fallback would resolve wrong. Unset in dev/tsx and tests →
 *  the from-source relative path. */
function arbiterClientSpecifier(): string {
  return process.env["MANDU_ARBITER_CLIENT_MODULE"] ?? ["..", "..", "..", "arbiter", "ipc", "client.js"].join("/");
}

/** Build the REAL arbiter client over the Unix socket. With `human`, a
 *  human-plane client that follows the arbiter across a restart: it re-learns
 *  the human socket from $MANDU_ARBITER_SOCK's `hello` and never sends a
 *  human-plane op to the data socket (arbiter-human-plane.md §5.1). */
async function buildArbiter(sock: string, human = false): Promise<{
  arbiter: ReplyArbiter;
  close: () => void;
  /** How many times the client moved to a re-learned human socket. */
  epoch: () => number;
}> {
  const arbiterMod = (await import(arbiterClientSpecifier())) as {
    // Optional: an older client module has no `humanPlane`.
    ArbiterClient: (new (sock: string) => RealArbiterClient) & {
      humanPlane?: (humanSock: string, dataSock?: string | null) => RealArbiterClient;
    };
  };
  const client: RealArbiterClient = human
    ? (arbiterMod.ArbiterClient.humanPlane?.(sock, process.env["MANDU_ARBITER_SOCK"]) ?? new arbiterMod.ArbiterClient(sock))
    : new arbiterMod.ArbiterClient(sock);
  await client.connect();
  return {
    arbiter: new ArbiterClientAdapter(client),
    close: () => client.close(),
    epoch: () => client.rediscoveries ?? 0,
  };
}

/** The best-effort `desymbolize` observability event (canonical schema:
 *  dashboard/src/event-model.ts; the arbiter persists it opaquely and assigns
 *  the real seq — mirrors how inspect-mcp builds its ullm_call events). */
function desymbolizeEvent(sessionId: string, before: string, after: string): unknown {
  const names = placeholderNames(before).join(" ");
  return {
    id: randomUUID(),
    sessionId,
    turn: 0,
    ts: new Date().toISOString(),
    seq: 0,
    callId: null,
    parentId: null,
    kind: "desymbolize",
    view: "HumanView",
    boundary: "model_context",
    emitter: "reply-filter",
    // DualRepr: symbolized = the placeholders the output named, as the agent
    // wrote them (names only); original = what the human actually saw after
    // resolution. Never the output itself: a terminal write or a json-mode
    // record can hold text the model never saw (a tool's output as the
    // agent process got it, the human's prompt before the prompt filter),
    // and the dashboard's signed-out projection keeps every `symbolized`
    // (dashboard.md §6).
    input: { symbolized: names, original: null, differs: false, symbols: [] },
    output: { symbolized: names, original: after, differs: true, symbols: [] },
    invariant: { violatedInvariant: false },
    // Tenant stamp (policy-surface.md §2.7) from the launcher's env.
    ...(process.env["MANDU_TENANT"] === "live" || process.env["MANDU_TENANT"] === "test"
      ? { tenant: process.env["MANDU_TENANT"] }
      : {}),
  };
}

/** The session-health `relay_mode` event (dashboard.md §4.21): which mode the
 *  wrapper actually chose for THIS terminal. A PASSTHROUGH mode is the one
 *  degradation the human cannot see from the TUI (symbols simply stay opaque),
 *  so it must be on the record. */
function relayModeEvent(sessionId: string, mode: ReplyFilterMode, reason: string, resolveFailure?: string): unknown {
  // A relay that runs but whose lookups fail (resolve-health.ts): the mode is
  // unchanged, and `resolveFailure` says why the placeholders stay opaque.
  const said = resolveFailure === undefined
    ? `reply-filter mode: ${mode.toUpperCase()} — ${reason}`
    : `reply-filter mode: ${mode.toUpperCase()} — DEGRADED: the arbiter did not resolve a placeholder (${resolveFailure}); ` +
      "$MDU: placeholders stay opaque on this terminal (nothing leaks)";
  return {
    id: randomUUID(),
    sessionId,
    turn: 0,
    ts: new Date().toISOString(),
    seq: 0,
    callId: null,
    parentId: null,
    kind: "relay_mode",
    view: "HumanView",
    boundary: "model_context",
    emitter: "reply-filter",
    mode,
    ...(resolveFailure !== undefined ? { resolveFailure } : {}),
    input: { symbolized: said, original: null, differs: false, symbols: [] },
    output: null,
    invariant: { violatedInvariant: false },
    ...(process.env["MANDU_TENANT"] === "live" || process.env["MANDU_TENANT"] === "test"
      ? { tenant: process.env["MANDU_TENANT"] }
      : {}),
  };
}

/** Best-effort relay report — never throws, never awaited on the output path. */
function reportRelay(arbiter: ReplyArbiter, relay: SessionRelay): Promise<void> {
  return arbiter.setSessionRelay(relay).catch(() => {});
}

/** Best-effort: report a PASSTHROUGH decision to the arbiter when one is
 *  reachable (the filtered path emits through its own client). Never delays
 *  the spawn by more than the connect timeout. The relay report
 *  (`setSessionRelay`) goes ONLY over the HUMAN-plane socket: the op is
 *  human-plane (reply-row-reservation.md §11.5) and the data socket refuses
 *  it. Without a human socket the health event still goes to the data
 *  socket (`emit` is a data-plane op) and the relay stays unreported, which
 *  means no expansion, the same as `passthrough`. */
async function reportPassthrough(reason: string): Promise<void> {
  const human = humanSockFromEnv();
  const sock = human ?? process.env["MANDU_ARBITER_SOCK"];
  const sessionId = process.env["MANDU_SCOPE_ID"] ?? "";
  if (!sock || sessionId === "") return;
  try {
    const { arbiter, close } = await buildArbiter(sock);
    await arbiter.emit(relayModeEvent(sessionId, "passthrough", reason)).catch(() => {});
    if (human) await reportRelay(arbiter, sessionRelay(sessionId, "passthrough"));
    close();
  } catch {
    /* no arbiter → nothing to record; the note on stderr stands */
  }
}

/** Forward terminal signals to the child for as long as it runs. A handler
 *  also keeps a ^C that reaches the wrapper (a TTY ^C once the agent's
 *  terminal is cooked again, or the launcher's forwarded SIGINT) from killing
 *  the wrapper and orphaning the agent part-way through its exit
 *  (differential-interactive.md §21). */
function forwardSignals(child: ChildProcess, signals: readonly NodeJS.Signals[]): void {
  for (const sig of signals) process.on(sig, () => { child.kill(sig); });
}

/** End the wrapper the way the child ended: re-raise its signal (128+n)
 *  after dropping our forwarding handler, which would otherwise catch the
 *  re-raise and leave the wrapper to exit 0. Should the signal not be fatal
 *  here (node ignores SIGPIPE), the drained process still exits 128+n. */
function reraise(signal: NodeJS.Signals): void {
  process.removeAllListeners(signal);
  const n = osConstants.signals[signal as keyof typeof osConstants.signals];
  if (typeof n === "number") process.exitCode = 128 + n;
  process.kill(process.pid, signal);
}

/** The launch scope's prefix from an early-start hand-off (src/handoff.ts),
 *  run in front of every spawn; empty in the serial form. */
let outer: string[] = [];

/** Passthrough: zero interposition — stdio fully inherited, so the child gets
 *  the REAL stdout (a TTY when the wrapper has one); exit/signal propagate. */
function spawnPassthrough(cmd: string[]): void {
  const argv = [...outer, ...cmd];
  const child = spawn(argv[0]!, argv.slice(1), { stdio: "inherit", env: childEnv() });
  child.on("error", (err) => {
    note(`failed to spawn '${argv[0]}': ${err.message}`);
    process.exit(127);
  });
  forwardSignals(child, ["SIGINT", "SIGTERM", "SIGHUP"]);
  child.on("close", (code, signal) => {
    if (signal) {
      reraise(signal); // preserve 128+n semantics
      return;
    }
    process.exit(code ?? 0);
  });
}

/** How spawnFiltered interposes: `pty` = the child runs under script(1) (the
 *  idle-flush timers, SIGWINCH forwarding, the screen model); `bsd` = that
 *  script is BSD script (macOS), so the companion (bsd-relay.ts) resizes the
 *  pty and takes the signals script does not relay. */
interface FilteredSpawnOpts {
  pty: boolean;
  screen?: ScreenReconciler | null;
  bsd?: boolean;
  /** The env the child's is derived from (childEnv drops the human-plane
   *  socket); default process.env. */
  env?: NodeJS.ProcessEnv;
  /** A line for stderr once the child's output is drained (the agent has
   *  left the terminal), or null: resolve-health.ts `exitNote`. */
  exitNote?: () => string | null;
}

/** Filtered spawn — shared by pipe mode (spawn the command directly) and pty
 *  mode (spawn it under `script`, plus the idle-flush timers). */
function spawnFiltered(
  spawnArgv: string[],
  filter: Pick<ReplyStreamFilter, "write" | "flush" | "pending" | "held">,
  closeArbiter: () => void,
  opts: FilteredSpawnOpts,
): void {
  const { pty } = opts;
  const screen = opts.screen ?? null;
  const argv = [...outer, ...spawnArgv];
  const child = spawn(argv[0]!, argv.slice(1), { stdio: ["inherit", "pipe", "inherit"], env: childEnv(opts.env ?? process.env) });
  child.on("error", (err) => {
    note(`failed to spawn '${argv[0]}': ${err.message}`);
    closeArbiter();
    process.exit(127);
  });

  // macOS: BSD script neither re-sizes its pty nor relays a signal to the
  // child (bsd-relay.ts). The companion locates the child at once and does
  // both from outside; it stops the moment script exits.
  const companion = pty && opts.bsd && child.pid !== undefined
    ? new BsdRelayCompanion(child.pid, realBsdRelayDeps())
    : null;
  companion?.start();
  child.once("exit", () => companion?.dispose());

  // Forward terminal signals to the child (belt-and-suspenders; a TTY Ctrl-C
  // already reaches the whole foreground process group). In pty mode SIGWINCH
  // is forwarded too — util-linux script re-reads the winsize and resizes the
  // pty slave (BSD script ignores it; the stdout 'resize' hook below covers
  // macOS). Under BSD script INT/TERM/HUP go to the relayed child itself:
  // sent to script they kill script, the child gets only the SIGHUP of the
  // closed master, and what it prints while shutting down is lost.
  const signals: NodeJS.Signals[] = pty
    ? ["SIGINT", "SIGTERM", "SIGHUP", "SIGWINCH"]
    : ["SIGINT", "SIGTERM", "SIGHUP"];
  const forwarders: Array<[NodeJS.Signals, () => void]> = [];
  for (const sig of signals) {
    const forward = (): void => {
      if (sig !== "SIGWINCH" && companion?.signal(sig)) return;
      child.kill(sig);
    };
    forwarders.push([sig, forward]);
    process.on(sig, forward);
  }
  // Re-raise the child's fatal signal on ourselves (128+n for the parent).
  // Our forwarders must go first: while one is installed the signal is
  // handled, not fatal, and the wrapper would drain out with exit 0.
  const dieBy = (signal: NodeJS.Signals): void => {
    for (const [sig, forward] of forwarders) process.off(sig, forward);
    reraise(signal);
  };

  // Bound pending work by pausing the child during each chunk. Await stdout
  // writes too, so slow consumers cannot grow an unbounded promise/write queue.
  const writeOutput = async (filtered: string): Promise<void> => {
    // No `$MDU` byte the stream let through as a marker or token a cell
    // diff split around a cursor move goes out (on the alternate screen no
    // `$MDU` byte at all): it is blanked here and the reconcile below paints
    // the row's truth (screen-reconcile.ts maskFragments; the TUI model
    // already holds this write, see the callers' feedTui).
    const out = screen ? await screen.maskFragments(filtered) : filtered;
    if (out !== "") await new Promise<void>((resolve, reject) => {
      process.stdout.write(out, (error) => error ? reject(error) : resolve());
    });
    // The human model sees exactly what the terminal saw, in order.
    screen?.feedHuman(out);
  };
  // SCREEN RECONCILE (screen-reconcile.ts): after the stream filter's
  // output for a chunk (or an idle drain) is on the wire, re-read the alt
  // screen's token rows (and reserve-block rows on either screen,
  // reply-row-reservation.md §3.7) and repaint what the stream could not
  // resolve. Never throws.
  const reconcile = async (): Promise<void> => {
    if (!screen) return;
    const repaint = await screen.reconcile();
    if (repaint !== "" && !closed) await new Promise<void>((resolve, reject) => {
      process.stdout.write(repaint, (error) => error ? reject(error) : resolve());
    });
  };
  // Terminal resize. The screen model resizes in stream order (before the
  // TUI's repaint at the new size arrives); under BSD script the companion
  // also re-sizes the child's pty — the kernel then raises SIGWINCH for the
  // TUI. On Linux, util-linux script does that part on the forwarded SIGWINCH.
  if ((screen || companion) && process.stdout.isTTY) {
    process.stdout.on("resize", () => {
      const cols = process.stdout.columns ?? 80;
      const rows = process.stdout.rows ?? 24;
      if (screen) queue = queue.then(() => screen.resize(cols, rows)).catch(() => {});
      companion?.resize(cols, rows);
    });
  }
  // BSD script sized its pty from ITS stdin; match the terminal the human
  // sees (stdout) once the child is located. Same size → no-op, no SIGWINCH.
  if (companion && process.stdout.isTTY) {
    companion.resize(process.stdout.columns ?? 80, process.stdout.rows ?? 24);
  }
  let queue: Promise<void> = Promise.resolve();
  let closed = false;
  let outputFailed = false;

  // PTY quiet-period drain: eager mode only ever holds a possible in-flight
  // token suffix; if the stream goes quiet while one is held (a prompt ending
  // token-shaped), drain it after IDLE_DRAIN_MS. New data re-arms. The drain
  // is NON-final (filter.flush(false)): a tail that is still a candidate — a
  // complete token whose `.field` delta may be in flight on a loaded SSE
  // stream — is re-held (bounded inside the filter, IDLE_HOLD_MAX), so the
  // timer re-arms while the filter still holds bytes; without the re-arm a
  // re-held token would strand until the next data event.
  let idleTimer: NodeJS.Timeout | null = null;
  // A rejected write (e.g. a consumer closes its pipe) must not strand the
  // paused child or an arbiter connection in an unhandled promise chain.
  const failOutput = (): void => {
    if (outputFailed) return;
    outputFailed = true;
    closed = true;
    if (idleTimer) clearTimeout(idleTimer);
    note("output delivery failed; stopping wrapped child");
    closeArbiter();
    child.stdout!.destroy();
    if (child.exitCode !== null || child.signalCode !== null) process.exit(1);
    if (!companion?.signal("SIGTERM")) child.kill("SIGTERM");
    const killTimer = setTimeout(() => child.kill("SIGKILL"), 1000);
    child.once("close", () => { clearTimeout(killTimer); process.exit(1); });
  };
  process.stdout.on("error", failOutput);
  const armDrain = (): void => {
    if (!pty) return;
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      queue = queue.then(async () => {
        if (closed) return;
        const out = await filter.flush(false);
        screen?.feedTui("", filter.held); // what the drain let through
        await writeOutput(out);
        await reconcile();
        // Re-arm while the filter holds bytes, or while masked cells wait for
        // their restore pass (screen-reconcile.ts maskFragments: a quiet TUI
        // sends no next write to trigger it; the pass ends the wait).
        if (filter.pending > 0 || screen?.restorePending === true) armDrain();
      }).catch(failOutput);
    }, IDLE_DRAIN_MS);
  };

  child.stdout!.setEncoding("utf8");
  child.stdout!.on("data", (chunk: string) => {
    child.stdout!.pause();
    queue = queue.then(async () => {
      if (outputFailed) return;
      const out = await filter.write(chunk);
      // The TUI model takes the chunk minus what the filter still holds, so
      // it never runs ahead of the human's terminal (screen-reconcile.ts).
      screen?.feedTui(chunk, filter.held);
      await writeOutput(out);
      await reconcile();
      child.stdout!.resume();
    }).catch(failOutput);
    armDrain();
  });

  child.on("close", (code, signal) => {
    if (outputFailed) return;
    closed = true;
    if (idleTimer) clearTimeout(idleTimer);
    // Drain the filter tail AFTER the last data event, then propagate.
    queue = queue.then(async () => {
      const rest = await filter.flush();
      screen?.feedTui("", filter.held);
      await writeOutput(rest);
      await reconcile();
      screen?.dispose();
      closeArbiter();
      const said = opts.exitNote?.() ?? null;
      if (said !== null) note(said);
      if (signal) {
        dieBy(signal);
        return;
      }
      // BSD script reports a child's signal death as the bare number; the
      // companion restores 128+n for a signal it delivered itself.
      process.exit((companion ? companion.exitCode(code) : code) ?? 0);
    }).catch(failOutput);
  });
}

/** The early-start form (src/handoff.ts): load, warm the arbiter client's
 *  import (no connection), and wait for the launcher's hand-off. Returns the
 *  serial form's argv, or null when the launch stopped first. */
async function awaitHandoff(): Promise<string[] | null> {
  void import(arbiterClientSpecifier()).catch(() => {});
  const wait = await receiveHandoff(handoffChannel(), (h) => applyHandoff(h));
  if (wait.kind === "aborted") return null;
  if (wait.kind === "invalid") {
    note(`refused the launcher's hand-off: ${wait.why}`);
    process.exit(2);
  }
  outer = wait.handoff.outer;
  return handoffArgv(wait.handoff);
}

async function main(): Promise<void> {
  process.title = "mandu-reply-filter"; // canonical ps title (runtime-instances.md §7)
  let argv = process.argv.slice(2);
  if (argv.length === 1 && argv[0] === HANDOFF_FLAG) {
    const handed = await awaitHandoff();
    if (handed === null) process.exit(0); // the launch stopped before its agent started
    argv = handed;
  }
  const { cmd, outputFormat: launchOutputFormat } = parseReplyInvocation(argv);
  if (cmd.length === 0) {
    note("no command given. Usage: reply-filter [--] <command> [args...]");
    process.exit(2);
  }

  // ── TTY safety: decide HOW to interpose (src/print-mode.ts) ─────────────────
  const outputFormat = launchOutputFormat ?? replyOutputFormat(cmd);
  let decision = decideMode(cmd, process.stdout.isTTY === true, {
    force: process.env["MANDU_REPLY_FILTER_FORCE"] === "1",
    ptyOverride: process.env["MANDU_REPLY_FILTER_PTY"],
  });
  if ((outputFormat === "json" || outputFormat === "stream-json") && process.env["MANDU_REPLY_FILTER_PTY"] !== "1") {
    decision = { mode: "pipe", reason: "Claude structured stdout requires a pipe (validated output format)" };
  }
  if (outputFormat === "passthrough" || (outputFormat !== "text" && decision.mode === "pty")) {
    const reason = "structured stdout format is unsupported, ambiguous, or forced through a PTY";
    note(`${reason} — PASSTHROUGH mode.`);
    spawnPassthrough(cmd);
    void reportPassthrough(reason);
    return;
  }
  if (decision.mode === "passthrough") {
    note(
      `${decision.reason} — PASSTHROUGH mode (stdio fully inherited, the child ` +
        "keeps the real TTY; symbols in the reply stay opaque, nothing leaks).",
    );
    spawnPassthrough(cmd);
    void reportPassthrough(decision.reason);
    return;
  }

  // ── pty mode needs its backend; unavailable → passthrough (utility posture) ─
  // A backend that cannot start on this stdin (BSD script on a socket or a
  // named FIFO exits 1 before the child runs) is unavailable for this run.
  if (decision.mode === "pty") {
    const cap = ptyRelayAvailable();
    const why = cap.ok ? ptyStdinProblem(ptyFlavor(), stdinFacts()) : cap.why;
    if (why !== null) {
      note(
        `${decision.reason}, but the PTY relay is unavailable: ${why} — ` +
          "PASSTHROUGH mode (the child keeps the real TTY; symbols stay opaque, nothing leaks).",
      );
      spawnPassthrough(cmd);
      void reportPassthrough(`PTY relay unavailable: ${why}`);
      return;
    }
  }

  // ── arbiter's HUMAN PLANE (optional): missing/unreachable → full passthrough.
  // desymbolize is served only on the human-plane socket; the data socket
  // ($MANDU_ARBITER_SOCK) is NEVER a fallback (arbiter-human-plane.md).
  const sock = humanSockFromEnv();
  let arbiter: ReplyArbiter | null = null;
  let closeArbiter: () => void = () => {};
  let arbiterEpoch: () => number = () => 0;
  if (sock) {
    try {
      ({ arbiter, close: closeArbiter, epoch: arbiterEpoch } = await buildArbiter(sock, true));
    } catch (err) {
      note(
        `arbiter human plane unreachable at ${sock} (${(err as Error).message}) — ` +
          "PASSTHROUGH mode (symbols in the reply stay opaque; nothing leaks).",
      );
    }
  } else {
    note(`${HUMAN_SOCK_ENV} not set — PASSTHROUGH mode (symbols in the reply stay opaque).`);
  }

  // ── passthrough: zero interposition when we cannot resolve ─────────────────
  if (!arbiter) {
    spawnPassthrough(cmd);
    return;
  }

  // ── filtered: the child's output routed through the desymbolizer ───────────
  const sessionId = process.env["MANDU_SCOPE_ID"] ?? "";
  const resolver = arbiter;
  const onResolve = async (before: string, after: string): Promise<void> => {
    if (sessionId === "") return;
    await resolver.emit(desymbolizeEvent(sessionId, before, after)).catch(() => {});
  };
  // Every lookup the stream filter and the screen model make goes through the
  // watch (resolve-health.ts): a failure still passes the text through, and
  // is now on the record (a `relay_mode` with `resolveFailure`) and in the
  // exit note, instead of a silent raw placeholder (the S8 miss).
  const watched = new WatchedResolver(resolver, {
    // A lookup answered on a re-learned human socket (a restarted arbiter)
    // counts as a recovery even when no lookup failed in between.
    epoch: arbiterEpoch,
    onDegraded: (why) => {
      if (sessionId === "") return;
      void resolver.emit(relayModeEvent(sessionId, decision.mode, decision.reason, why)).catch(() => {});
    },
    onRecovered: () => {
      if (sessionId === "") return;
      void resolver.emit(relayModeEvent(sessionId, decision.mode, decision.reason)).catch(() => {});
      // A recovery is often a restarted arbiter (the client re-learned its
      // human socket, arbiter-human-plane.md §5.1), which holds no relay
      // report for this session: report again so reservation resumes.
      const size = decision.mode === "pty" ? { cols: process.stdout.columns, rows: process.stdout.rows } : {};
      void reportRelay(resolver, sessionRelay(sessionId, decision.mode, size));
    },
  });
  const exitNote = (): string | null => watched.exitNote();
  // The session's reserve-block memory, shared by the stream splice and the
  // screen reconciler (reply-row-reservation.md §3.7), with the wrap rule the
  // agent's TUI lays its reply out by (§17: the launcher sets it for Goose).
  const reserveCache = new ReserveValueCache(RESERVE_CACHE_MAX, wrapRule(), tabOrigin());
  const filter = outputFormat === "json" || outputFormat === "stream-json"
    ? new StructuredReplyFilter(watched, outputFormat, {
      onResolve,
      onDiagnostic: (reason) => note(`structured stdout: ${reason}; original record retained`),
    })
    : new ReplyStreamFilter(watched, {
      // Preserve the existing eager terminal rendering and idle-drain behavior.
      eager: decision.mode === "pty",
      // Bounds the column model for column-aware TAB expansion (filter.ts);
      // no TTY width → undefined → the one-space tab fallback.
      cols: () => process.stdout.columns,
      onResolve,
      reserveCache,
    });

  // The health record: which mode this terminal actually got (best-effort,
  // and NEVER before the spawn — a slow arbiter must not delay the TUI's
  // boot, the driver/human types into a pty that has to exist by then).
  if (sessionId !== "") {
    void resolver.emit(relayModeEvent(sessionId, decision.mode, decision.reason)).catch(() => {});
    const size = decision.mode === "pty" ? { cols: process.stdout.columns, rows: process.stdout.rows } : {};
    void reportRelay(resolver, sessionRelay(sessionId, decision.mode, size));
    // Re-report on resize (cols/rows for v2's wrapped-line reservation).
    if (decision.mode === "pty" && process.stdout.isTTY) {
      process.stdout.on("resize", () => {
        void reportRelay(resolver, sessionRelay(sessionId, "pty", { cols: process.stdout.columns, rows: process.stdout.rows }));
      });
    }
  }

  if (decision.mode === "pty") {
    // The fullscreen-aware half (screen-reconcile.ts): ON by default for the
    // PTY relay; MANDU_REPLY_FILTER_SCREEN=0 opts out (stream filter only —
    // the pre-2026-09-19 behavior, raw tokens under the alt-screen renderer).
    const screen = process.env["MANDU_REPLY_FILTER_SCREEN"] === "0"
      ? null
      : new ScreenReconciler(watched, {
        cols: process.stdout.columns ?? 80,
        rows: process.stdout.rows ?? 24,
        onResolve,
        reserveCache,
        // A block whose head never reached the screen (§3.8): the proxy
        // recorded it under this session's key.
        ...(sessionId !== "" ? { blockLookup: (hash: string) => resolver.reserveBlock(sessionId, hash) } : {}),
      });
    info(
      `${decision.reason} — PTY RELAY (${process.platform === "darwin" ? "BSD" : "util-linux"} script): the child keeps a real ` +
        "terminal; the relayed session is desymbolized on its way to yours" +
        (screen
          ? " (stream + cell model: the alternate screen, and reserved rows and split tokens on the main screen)."
          : " (stream only — MANDU_REPLY_FILTER_SCREEN=0)."),
    );
    // util-linux script runs its -c string through $SHELL: /bin/sh, not the
    // user's shell (pty-relay.ts PTY_RELAY_SHELL); BSD script execs directly.
    const bsd = ptyFlavor() === "bsd";
    spawnFiltered(buildPtyArgv(cmd), filter, closeArbiter, { pty: true, screen, bsd, env: bsd ? process.env : ptyRelayEnv(), exitNote });
  } else {
    spawnFiltered(cmd, filter, closeArbiter, { pty: false, exitNote });
  }
}

main().catch((err) => {
  note(`fatal: ${(err as Error).message}`);
  process.exit(1);
});
