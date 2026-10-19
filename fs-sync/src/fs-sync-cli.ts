#!/usr/bin/env tsx
/**
 * fs-sync-cli — entry point so the bash launcher can drive the `ViewSync`
 * orchestrator (the rest of fs-sync is a library; this is its only CLI).
 *
 * Mandu Track B (userspace half). The launcher runs `init` before exec so the
 * symbolized AgentView worktree exists at the path fs-preload redirects reads to,
 * `sync` to propagate AgentView writes back to the HumanView, and `leaks` as the
 * security-invariant oracle.
 *
 * This file is the ONLY place in fs-sync that imports the sibling arbiter package
 * (its IPC client). The specifier is built at runtime so TypeScript does NOT
 * statically resolve arbiter/**.ts into this package's program (which would drag
 * it under our rootDir and break the standalone typecheck) — mirrors
 * interceptors/anthropic-proxy/src/server-main.ts. The test suite uses a mock arbiter
 * for the library; THIS CLI is exercised end-to-end against a real arbiter daemon
 * (test/integrity/fs-sync-cli.test.ts boots one).
 *
 * Usage:
 *   tsx src/fs-sync-cli.ts <cmd> <workspacePath> [--state-base <S>] [--tool <name>]
 *                                                 [--session <id>]
 *
 * Env:
 *   MANDU_ARBITER_HUMAN_SOCK  the arbiter's HUMAN-PLANE socket (REQUIRED for
 *                            init/sync/leaks/watch): fs-sync resolves symbols
 *                            into the HumanView, and the ops that return
 *                            originals are served only there
 *                            (docs/design/architecture/arbiter-human-plane.md). Never
 *                            replaced by MANDU_ARBITER_SOCK (the data socket).
 *   MANDU_ARBITER_SOCK       optional: where a restarted arbiter's NEW human
 *                            socket is re-learned (`hello` only; the human-plane
 *                            ops still go to the human socket alone,
 *                            arbiter-human-plane.md §5.1)
 *   MANDU_SCOPE_ID          default --session for `watch` when the flag is absent
 *   MANDU_FS_IGNORED         "0" leaves `.gitignore`d files out of the AgentView
 *                            (default: they enter it as symbolized twins, ignored.ts)
 *   MANDU_FS_IGNORED_DENY    extra directory names never walked for ignored files
 *                            (comma-separated; added to the default deny list)
 *
 * Subcommands (one line of JSON to stdout on success, exit 0; on any error a
 * message to stderr + non-zero exit — FAIL CLOSED, never exit 0 on failure):
 *   init  <ws> [--state-base S]     -> {"ok":true,"agentView":S,"stateBase":S,"workspaceId":id}
 *   sync  <ws> [--state-base S] [--tool N] -> {"ok":true,"synced":[...]}
 *   leaks <ws> [--state-base S]     -> {"ok":true,"leaks":[...]}
 *   watch <ws> [--state-base S] [--session ID]
 *         LONG-RUNNING (fs-sync.md §2.3–§4, Phase 1): subscribes to the
 *         session's arbiter event stream FROM NOW and runs a coalesced
 *         syncToHuman per tool_result until SIGTERM/SIGINT. Prints one
 *         {"ok":true,"watching":ID,"agentView":...} ready line once the stream
 *         is live. Startup failures (arbiter unreachable, bad args) fail
 *         closed like the other subcommands; once running, mid-stream errors
 *         are FAIL-SAFE (warn + keep going / resubscribe — the launcher's
 *         post-exit sweep remains the catch-all, design §5).
 */

import { existsSync, watch as fsWatch, type FSWatcher } from "node:fs";

import { ViewSync, type Logger, type WriteProvenance } from "./view-sync.js";
import {
  ArbiterClientAdapter,
  ArbiterEventStreamAdapter,
  HUMAN_SOCK_ENV,
  humanSockFromEnv,
  type RealArbiterClient,
} from "./arbiter-client.js";
import { EagerSync } from "./eager-sync.js";
import { ViewLayout, defaultStateBase } from "./layout.js";
import { listWriteCycles, planRevert, revertToWriteCycle } from "./revert.js";
import { armLifeline } from "./lifeline.js";
import { humanEditClockIgnores, ignoredInclusionEnabled, ignoredLimitsFromEnv, skipCounts } from "./ignored.js";

interface ParsedArgs {
  cmd: string;
  workspacePath: string;
  stateBase?: string;
  /** revert: the write cycle to return to (1-based). */
  to?: number;
  dryRun?: boolean;
  tool?: string;
  session?: string;
}

const USAGE =
  "usage: fs-sync-cli <init|sync|leaks|watch|history|revert> <workspacePath> [--state-base <S>] [--tool <name>] [--session <id>] [--to <N>] [--dry-run]";

/** watch health-loop cadence: ping the arbiter, warn once per outage, and
 * resubscribe when it comes back (fail-safe, never exits on a mid-stream error). */
const WATCH_HEALTH_INTERVAL_MS = 15_000;

/** Bound on waiting for an in-flight sync at shutdown so a wedged git op can't
 * hang the launcher's teardown (the sweep serializes on the layout lock anyway). */
const WATCH_DRAIN_TIMEOUT_MS = 20_000;

function die(message: string, code: number): never {
  console.error(`[fs-sync-cli] ${message}`);
  process.exit(code);
}

function parseArgs(argv: string[]): ParsedArgs {
  const cmd = argv[0];
  if (!cmd || !["init", "sync", "leaks", "watch", "history", "revert"].includes(cmd)) {
    die(`unknown subcommand: ${cmd ?? "(none)"}\n${USAGE}`, 2);
  }

  let workspacePath: string | undefined;
  let stateBase: string | undefined;
  let tool: string | undefined;
  let session: string | undefined;
  let to: number | undefined;
  let dryRun = false;

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--state-base") {
      stateBase = argv[++i];
      if (stateBase === undefined) die(`--state-base requires a value\n${USAGE}`, 2);
    } else if (arg === "--tool") {
      tool = argv[++i];
      if (tool === undefined) die(`--tool requires a value\n${USAGE}`, 2);
    } else if (arg === "--session") {
      session = argv[++i];
      if (session === undefined) die(`--session requires a value\n${USAGE}`, 2);
    } else if (arg === "--to") {
      to = Number(argv[++i]);
      if (!Number.isInteger(to) || to < 1) die(`--to requires a write number (1 or more)\n${USAGE}`, 2);
    } else if (arg === "--dry-run") {
      dryRun = true;
    } else if (arg.startsWith("--")) {
      die(`unknown flag: ${arg}\n${USAGE}`, 2);
    } else if (workspacePath === undefined) {
      workspacePath = arg;
    } else {
      die(`unexpected argument: ${arg}\n${USAGE}`, 2);
    }
  }

  if (workspacePath === undefined) {
    die(`missing <workspacePath>\n${USAGE}`, 2);
  }

  if (cmd === "revert" && to === undefined) die(`revert requires --to <N>\n${USAGE}`, 2);
  return { cmd, workspacePath, stateBase, tool, session, ...(to !== undefined ? { to } : {}), dryRun };
}

/**
 * Resolve the view state base: explicit --state-base wins (the launcher's
 * revert passes it), else the path table's default (`defaultStateBase`: the
 * Mandu home's `state/`, `~/.mandu/state` unless MANDU_HOME moves the home).
 */
function resolveStateBase(flag: string | undefined): string {
  return flag ?? defaultStateBase();
}

/**
 * Build the REAL arbiter client (RealArbiterClient -> ArbiterClientAdapter) over
 * the HUMAN-PLANE socket in MANDU_ARBITER_HUMAN_SOCK. The specifier is
 * assembled at runtime so the arbiter package is not statically resolved into
 * this program.
 */
async function buildArbiter(sock: string): Promise<{
  arbiter: ArbiterClientAdapter;
  /** The raw IPC client — `watch` additionally needs its event-stream ops. */
  client: RealArbiterClient;
  close: () => void;
}> {
  // A BUNDLED build (packaging.md §5) sets MANDU_ARBITER_CLIENT_MODULE to the
  // co-located dist/arbiter-client.mjs; unset in dev/tsx → the relative source.
  const arbiterClientSpecifier =
    process.env["MANDU_ARBITER_CLIENT_MODULE"] ?? ["..", "..", "arbiter", "ipc", "client.js"].join("/");
  const arbiterMod = (await import(arbiterClientSpecifier)) as {
    // `humanPlane` (arbiter-human-plane.md §5.1): a human-plane client that
    // re-learns the human socket from the data socket after an arbiter
    // restart. Optional: an older client module has none.
    ArbiterClient: (new (sock: string) => RealArbiterClient) & {
      humanPlane?: (humanSock: string, dataSock?: string | null) => RealArbiterClient;
    };
  };
  // The human-plane socket, followed across an arbiter restart.
  const client: RealArbiterClient = (arbiterMod.ArbiterClient.humanPlane?.(sock, process.env["MANDU_ARBITER_SOCK"]) ?? new arbiterMod.ArbiterClient(sock));
  await client.connect();
  const arbiter = new ArbiterClientAdapter(client);
  return { arbiter, client, close: () => client.close() };
}

/** Trailing debounce for the human-edit clock: editors save as a burst
 *  (write → rename → chmod), and one reconcile per burst is enough. */
const HUMAN_EDIT_DEBOUNCE_MS = 400;

/**
 * Watch the HumanView tree and call `fire` (debounced) when something under it
 * changes. Pure clock: it never reads a file and decides nothing. Returns a
 * closer; never throws (a filesystem that cannot be watched logs once and
 * yields a no-op clock).
 */
function startHumanEditClock(
  humanPath: string,
  fire: () => void,
  log: Logger,
  debounceMs: number = HUMAN_EDIT_DEBOUNCE_MS,
): { close(): void } {
  let timer: NodeJS.Timeout | undefined;
  let watcher: FSWatcher | undefined;
  const schedule = (): void => {
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = undefined;
      try { fire(); } catch { /* fail-safe: the driver never throws, but a clock must not either */ }
    }, debounceMs);
    timer.unref?.();
  };
  try {
    watcher = fsWatch(humanPath, { recursive: true, persistent: false }, (_ev, name) => {
      if (name !== null && humanEditClockIgnores(String(name))) return;
      // Events our OWN sync causes are not filtered out: dropping events while
      // a run is in flight would also drop a human edit made in that window.
      // They cost one extra run that finds nothing (the sync commits what it
      // writes), after which the tree is quiet and the clock stops.
      schedule();
    });
    watcher.on("error", (err) => {
      log.warn(`[fs-sync-cli] watch: human-edit clock stopped (${(err as Error).message}) — human edits reconcile at the tool_result cadence only`);
    });
  } catch (err) {
    log.warn(`[fs-sync-cli] watch: human-edit clock unavailable (${(err as Error).message}) — human edits reconcile at the tool_result cadence only`);
  }
  return {
    close(): void {
      if (timer !== undefined) clearTimeout(timer);
      try { watcher?.close(); } catch { /* already closed */ }
    },
  };
}

/**
 * The long-running `watch` loop (fs-sync.md §2.3–§4, Phase 1): subscribe
 * to the session's event stream FROM NOW, coalesce a syncToHuman per
 * tool_result, and keep going until SIGTERM/SIGINT. Resolves on signal after
 * draining the in-flight sync (bounded), so the caller can close cleanly.
 *
 * Everything past the initial subscribe is FAIL-SAFE (design §5): a dead
 * stream / unreachable arbiter warns and pauses eager sync (the health loop
 * resubscribes when the arbiter answers again); nothing here may throw once
 * the ready line is printed — the launcher's post-exit sweep is the catch-all.
 */
async function runWatch(
  dv: ViewSync,
  client: RealArbiterClient,
  sessionId: string,
  log: Logger,
): Promise<void> {
  const stream = new ArbiterEventStreamAdapter(client);
  const driver = new EagerSync({
    // The seam is exactly the two-stage commit — the driver decides WHEN it
    // runs, never what it does (R2 guard, step-0 re-symbolization, symlink
    // refusals all stay inside ViewSync.syncToHuman).
    target: {
      syncToHuman: (prov: WriteProvenance) => dv.syncToHuman(prov),
      // HumanView → AgentView (fs-sync.md §2.5a): the reference ran this
      // from a `before_tool_call` hook Mandu does not have. Live (watch U27):
      // nothing called it, so a file the human edited mid-session kept its
      // pre-edit twin and the model quoted the old line.
      reconcileHumanEdits: () => dv.reconcileHumanEdits(),
    },
    log,
  });
  const onEvent = (ev: unknown): void => driver.handleEvent(ev);

  // The human-edit CLOCK. Like the tool_result, the file event is only a clock:
  // the reconcile diffs the HumanView against the shadow HEAD and returns at
  // once when nothing diverged, so over-triggering is cheap and the events our
  // own sync causes are harmless (one extra run that finds nothing).
  // FAIL-SAFE: no watcher (an fs that cannot do it) degrades to
  // reconciling at the tool_result cadence, which every run already does.
  const clock = startHumanEditClock(dv.humanPath, () => driver.triggerReconcile(), log);
  // The `session_start` analog: an edit made between `init` and now.
  driver.triggerReconcile();

  // Startup is FAIL-CLOSED like every other subcommand: a subscribe failure
  // here propagates to main()'s catch → stderr + non-zero exit.
  let handle = await stream.subscribeFromNow(sessionId, onEvent);

  // Ready line AFTER the stream is live so the launcher can gate on it.
  process.stdout.write(
    JSON.stringify({ ok: true, watching: sessionId, agentView: dv.agentViewPath }) + "\n",
  );

  // Health loop: ping the arbiter; warn ONCE per outage; resubscribe from now
  // when it answers again. The interval also keeps the event loop alive while
  // a resubscribe is pending. Every path is caught — an unhandled rejection
  // here would kill the watcher, which fail-safe forbids.
  let outage = false;
  const health = setInterval(() => {
    void (async () => {
      try {
        await stream.ping();
        if (outage) {
          try {
            handle.close();
          } catch {
            /* already dead */
          }
          handle = await stream.subscribeFromNow(sessionId, onEvent);
          outage = false;
          log.warn(`[fs-sync-cli] watch: arbiter is back — resubscribed to ${sessionId}`);
        }
      } catch {
        if (!outage) {
          log.warn(
            `[fs-sync-cli] watch: arbiter unreachable — eager sync paused, HumanView goes stale ` +
              `(the post-exit sweep remains the catch-all)`,
          );
        }
        outage = true;
      }
    })();
  }, WATCH_HEALTH_INTERVAL_MS);

  // Run until the launcher (or a human) tears us down. The lifeline
  // (lifeline.ts) is the kernel-guaranteed variant of the same teardown: the
  // launcher spawns this watcher with MANDU_LIFELINE=stdin, so stdin EOF
  // means the launcher died (even by SIGKILL) — resolve into the SAME graceful
  // drain below instead of orphaning a watcher that syncs into a dead session.
  await new Promise<void>((resolve) => {
    process.once("SIGTERM", resolve);
    process.once("SIGINT", resolve);
    armLifeline(resolve);
  });

  clearInterval(health);
  clock.close();
  try {
    handle.close();
  } catch {
    /* already dead */
  }
  // Let an in-flight commit pair finish (bounded) so teardown never tears one;
  // anything still pending after the bound is the sweep's job.
  let drainTimer: NodeJS.Timeout | undefined;
  await Promise.race([
    driver.idle(),
    new Promise<void>((resolve) => {
      drainTimer = setTimeout(resolve, WATCH_DRAIN_TIMEOUT_MS);
    }),
  ]);
  if (drainTimer !== undefined) clearTimeout(drainTimer);
  log.info(
    `[fs-sync-cli] watch: exiting (syncs=${driver.syncsRun} failed=${driver.syncsFailed})`,
  );
}

async function main(): Promise<void> {
  const { cmd, workspacePath, stateBase: stateBaseFlag, tool, session, to, dryRun } = parseArgs(
    process.argv.slice(2),
  );

  // history / revert (comparisons.md §3.8, `mandu revert`): pure git
  // over the shadow repo, no arbiter (revert.ts: the symbol table is
  // append-only and unaffected by a rollback).
  if (cmd === "history" || cmd === "revert") {
    process.title = "mandu-fs-cli";
    const layout = new ViewLayout(workspacePath, resolveStateBase(stateBaseFlag));
    try {
      if (!existsSync(layout.gitDir)) die(`no Mandu history for ${workspacePath} (it was never opened in a mode that tracks writes: injection or full)`, 1);
      if (cmd === "history") {
        const cycles = listWriteCycles(layout).map((c) => ({ number: c.number, timestamp: c.timestamp, files: c.files, tool: c.meta.toolName, human: c.meta.human === true }));
        process.stdout.write(JSON.stringify({ ok: true, cycles }) + "\n");
      } else {
        const plan = dryRun ? planRevert(layout, to!) : revertToWriteCycle(layout, to!);
        process.stdout.write(JSON.stringify({
          ok: true, reverted: !dryRun, to: plan.target.number, timestamp: plan.target.timestamp,
          abandoned: plan.abandonedCount, kept: plan.filesKept.length, removed: plan.filesRemoved,
        }) + "\n");
      }
    } catch (err) {
      die((err as Error).message, 1);
    }
    return;
  }

  // Canonical ps titles (runtime-instances.md §7): the resident eager watcher is
  // mandu-fs-watch; the one-shot init/sync/leaks commands are mandu-fs-cli.
  process.title = cmd === "watch" ? "mandu-fs-watch" : "mandu-fs-cli";

  // The human plane (arbiter-human-plane.md): fs-sync writes originals into
  // the HumanView, so it talks to the arbiter's human-plane socket. Absent →
  // fail closed, exactly like an unreachable arbiter. NEVER the data socket.
  const sock = humanSockFromEnv(process.env);
  if (!sock) {
    die(
      `${HUMAN_SOCK_ENV} is required (the arbiter's human-plane socket — the ops that ` +
        "return originals are served only there; the data socket is never a fallback)",
      1,
    );
  }

  // watch needs a session to subscribe to (the arbiter's subscribe op is
  // per-session): --session flag, else the launcher's MANDU_SCOPE_ID.
  const sessionId = session ?? process.env["MANDU_SCOPE_ID"];
  if (cmd === "watch" && !sessionId) {
    die(`watch requires --session <id> (or MANDU_SCOPE_ID)\n${USAGE}`, 2);
  }

  const stateBase = resolveStateBase(stateBaseFlag);

  // Fail-closed: a arbiter that is unreachable (no daemon / bad socket) must NOT
  // produce a worktree and must NOT exit 0. client.connect() rejects here.
  let arbiter: ArbiterClientAdapter;
  let client: RealArbiterClient;
  let closeArbiter: () => void;
  try {
    ({ arbiter, client, close: closeArbiter } = await buildArbiter(sock));
  } catch (err) {
    die(`arbiter unreachable at ${sock}: ${(err as Error).message}`, 1);
  }

  // The long-running watch logs to stderr (the launcher redirects it to the
  // scope run dir); the one-shot commands keep the quiet no-op logger.
  const log: Logger = {
    info: (m) => console.error(m),
    warn: (m) => console.error(m),
    error: (m) => console.error(m),
  };

  try {
    // sessionKey files every mint's birth event under the launcher's scope
    // (symbol-lineage.md G1) — for `init` too, so seed-time mints are visible.
    const dv = new ViewSync({
      workspacePath, arbiter, stateBase,
      ...(sessionId ? { sessionKey: sessionId } : {}),
      ...(cmd === "watch" ? { log } : {}),
      // The `.gitignore`d files (ignored.ts, fs-sync.md §3.4.1):
      // MANDU_FS_IGNORED=0 turns them off, MANDU_FS_IGNORED_DENY adds
      // directory names to the deny list.
      ignored: ignoredInclusionEnabled(process.env) ? ignoredLimitsFromEnv(process.env) : false,
    });

    switch (cmd) {
      case "init": {
        await dv.initialize();
        const layout = new ViewLayout(workspacePath, stateBase);
        const ig = dv.ignoredStatus();
        process.stdout.write(
          JSON.stringify({
            ok: true,
            agentView: dv.agentViewPath,
            stateBase,
            workspaceId: layout.workspaceId,
            // What of the ignored files is in the AgentView, and what is not
            // (the launcher prints the "not in the AI's copy" line from it).
            ...(ig
              ? {
                  ignored: {
                    enabled: ig.enabled,
                    included: ig.included,
                    minted: ig.minted,
                    skippedCounts: skipCounts(ig.skipped),
                    skipped: ig.skipped.slice(0, 20),
                    manifest: layout.ignoredManifestPath,
                  },
                }
              : {}),
          }) + "\n",
        );
        break;
      }
      case "sync": {
        const synced = await dv.syncToHuman({ toolName: tool ?? "fs-preload" });
        process.stdout.write(JSON.stringify({ ok: true, synced }) + "\n");
        break;
      }
      case "leaks": {
        const leaks = dv.agentViewLeaks();
        process.stdout.write(JSON.stringify({ ok: true, leaks }) + "\n");
        break;
      }
      case "watch": {
        await runWatch(dv, client, sessionId!, log);
        break;
      }
    }
  } catch (err) {
    // Any failure (arbiter op rejected mid-flight, git error, etc.) fails closed.
    closeArbiter();
    die(`${cmd} failed: ${(err as Error).message}`, 1);
  }

  // Close the connection cleanly so the process exits (no hanging socket).
  closeArbiter();
}

main().catch((err) => {
  die(`fatal: ${(err as Error).message}`, 1);
});
