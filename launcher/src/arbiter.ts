/**
 * arbiter — attach to a running arbiter or start one; REFUSE to launch if neither.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh: socket-existence attach (L620-621),
 *   wait_for_socket poll (L609-617), NO_ARBITER_AUTOSTART (L622-624), autostart
 *   via `npm run serve` in arbiter/ (L625-636). Fail-closed (spec §5): every
 *   gate decides through the arbiter, so launching without it = launching
 *   ungated → we refuse. Socket-existence is the parity health check today; a
 *   real IPC ping is a Part-2 refinement.
 */
import { existsSync, fstatSync, lstatSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { userInfo } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import type { DaemonSpec, Layout } from "./services/layout.js";
import { manduPath } from "./generated/mandu-paths.js";
import { hardenedGitArgs, hardenedGitEnv } from "./hardened-git.js";
import { openAppendLog, serviceReadyDeadlineMs } from "./services/primitives.js";
import { resolveNativeBin } from "./services/native-bins.js";
import { movedBaseHint } from "./arbiter-sock.js";
import {
  accountRendezvous as defaultBaseRendezvous, ensurePrivateIfFallback, ensureRuntimeBaseDir, fallbackBaseContaining,
  instanceBaseProblem, instanceSockSuffix, maxPidDigitsFor, resolveRuntimeBase, runtimeBaseContaining,
  sharedParentBaseContaining, sunPathMaxFor, type PrivateDirDeps, type RuntimeBaseOptions,
} from "./runtime-base.js";

/** The `sockaddr_un.sun_path` capacity: 108 bytes on Linux, 104 on the BSDs /
 *  macOS (both include the trailing NUL). A path at or past this is SILENTLY
 *  TRUNCATED by bind(2)/connect(2) — the arbiter binds a shorter name than the
 *  launcher polls, so the socket "never comes up" with no hint why. We refuse up
 *  front instead. `- 1` reserves the NUL. */
const SUN_PATH_MAX = sunPathMaxFor(process.platform);

/**
 * Reject a MANDU_ARBITER_SOCK whose path does not fit in `sun_path` (it would
 * truncate at bind and surface as the misleading "arbiter did not come up").
 * Byte length, not char length — the kernel limit is bytes. Throws a clear,
 * actionable error naming the limit + the fix.
 */
export function assertSockPathFits(sock: string): void {
  const bytes = Buffer.byteLength(sock, "utf8");
  if (bytes >= SUN_PATH_MAX) {
    throw new Error(
      `mandu: the arbiter socket path is ${bytes} bytes, over the ${SUN_PATH_MAX - 1}-byte ` +
      `OS limit for a Unix socket (sun_path) — bind(2) would silently TRUNCATE it and the ` +
      `arbiter would appear to never come up. Point MANDU_ARBITER_SOCK (or MANDU_RUNTIME_DIR) ` +
      `at a shorter path, e.g. MANDU_ARBITER_SOCK=/tmp/mdu-$USER/arbiter.sock. Path was: ${sock}`,
    );
  }
}

export interface EnsureArbiterOpts {
  sock: string;
  noAutostart: boolean;
  /** Start the arbiter daemon (backgrounded). Injected for tests. Returns the
   *  daemon whose socket the wait is for, when the start knows it, so the
   *  wait ends at once if that daemon exits. */
  start: () => Promise<DaemonHandle | void>;
  /** Poll until the socket answers, or time out; `giveUp` (the started daemon
   *  exited) ends the poll early. Injected for tests. */
  waitForSocket: (sock: string, giveUp?: () => boolean) => Promise<boolean>;
  /** How to start an arbiter by hand (for the noAutostart refusal message).
   *  Instance-mode resolutions must NOT suggest pinning the `current`
   *  spelling — binding through the symlink is impossible. */
  startHint?: string;
  /** The daemon log the start writes to. When the arbiter does not come up,
   *  its last `[arbiter] fatal:` line is quoted in the refusal, so a boot
   *  refusal the user must act on (a mandu.db schema mismatch, a symbol DB
   *  owned by a live writer) reaches the terminal instead of only the log. */
  logPath?: string;
  /** Test seam for reading the log. */
  readLog?: (path: string) => string | null;
  /** Further dirs this launch will create under a runtime base (the scope
   *  run dir): each one inside the shared-/tmp fallback gets that base
   *  created 0700 / verified private FIRST (runtime-instances.md §3b), so no
   *  later `mkdir -p` makes it with the umask's group/other bits. `sock` and
   *  `logPath` are always covered. Default: the runtime base of `env`
   *  (runtime-base.ts resolveRuntimeBase), the root parse.ts gives every
   *  scope dir — which is the fallback even when a pinned MANDU_ARBITER_SOCK
   *  lives elsewhere. */
  runtimeDirs?: readonly string[];
  /** The env the fallback's test-only root hook is read from (defaults to
   *  process.env). */
  env?: Record<string, string | undefined>;
  /** Test seams for the fallback rule and the private-dir check. */
  runtimeBaseOpts?: RuntimeBaseOptions;
  privateDirDeps?: PrivateDirDeps;
}

/** The last `[arbiter] fatal: …` line of a daemon log, or null. */
export function lastArbiterFatal(text: string | null): string | null {
  if (!text) return null;
  const lines = text.split("\n").filter((l) => l.includes("[arbiter] fatal:"));
  const last = lines[lines.length - 1];
  return last ? last.slice(last.indexOf("[arbiter] fatal:") + "[arbiter] fatal:".length).trim() : null;
}

/**
 * Why a daemon did not start, in one line the user can act on, from the part
 * of its log written by THIS start (release checklist d6): the last line that
 * reads as an error, with EADDRINUSE turned into the port it names. null when
 * the log shows nothing that looks like a failure.
 */
export function lastStartFailure(text: string | null): string | null {
  if (!text) return null;
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  const addrInUse = [...lines].reverse().find((l) => /EADDRINUSE/.test(l));
  if (addrInUse) {
    const port = addrInUse.match(/:(\d{1,5})\b(?!.*:\d)/)?.[1];
    return port
      ? `port ${port} is already in use (unset DASHBOARD_PORT to get a free port, or pick another)`
      : "its port is already in use (unset DASHBOARD_PORT to get a free port, or pick another)";
  }
  const failure = /\b(Error|ERR_[A-Z_]+|EACCES|ENOENT|fatal|refusing|Cannot find|must be)\b/;
  const last = [...lines].reverse().find((l) => failure.test(l) && !/^\s*at\s/.test(l));
  return last ? last.replace(/^\[dashboard\]\s*/, "").slice(0, 300) : null;
}

/** The bytes a log gained since `offset` (a start's own output), or null. */
function readLogSince(path: string, offset: number): string | null {
  try {
    const buf = readFileSync(path);
    return buf.subarray(Math.min(offset, buf.length)).toString("utf8");
  } catch {
    return null;
  }
}

export async function ensureArbiter(opts: EnsureArbiterOpts): Promise<{ attached: boolean }> {
  // Preflight: a path that cannot fit in sun_path truncates silently — refuse
  // with a clear message rather than the downstream "did not come up".
  assertSockPathFits(opts.sock);
  // The shared-/tmp fallback base (/tmp/mandu-<uid>) is trusted only as a
  // private 0700 dir of this uid: made so when absent, refused otherwise —
  // BEFORE a socket found under it is attached to (runtime-instances.md §3b).
  const env = opts.env ?? process.env;
  const runtimeDirs = opts.runtimeDirs ?? [resolveRuntimeBase(env, opts.runtimeBaseOpts).base];
  for (const p of [opts.sock, opts.logPath, ...runtimeDirs]) {
    if (p) guardRuntimePath(p, env, opts.runtimeBaseOpts, opts.privateDirDeps, { createOther: false });
  }
  if (existsSync(opts.sock)) return { attached: true };
  if (opts.noAutostart) {
    const hint = opts.startHint ?? `(cd arbiter && MANDU_ARBITER_SOCK=${opts.sock} npm run serve)`;
    throw new Error(
      `mandu: arbiter socket ${opts.sock} is absent and MANDU_NO_ARBITER_AUTOSTART=1 — refusing to launch ungated. ` +
      `Start it: ${hint}`,
    );
  }
  const started = await opts.start();
  const up = await opts.waitForSocket(opts.sock, started ? () => !started.running() : undefined);
  if (!up) {
    const readLog = opts.readLog ?? ((p: string) => { try { return readFileSync(p, "utf8"); } catch { return null; } });
    const fatal = opts.logPath ? lastArbiterFatal(readLog(opts.logPath)) : null;
    throw new Error(
      `mandu: arbiter did not come up on ${opts.sock} — refusing to launch ungated` +
        (fatal ? `.\n  The arbiter refused to start: ${fatal}` : "") +
        (opts.logPath ? `\n  (log: ${opts.logPath})` : ""),
    );
  }
  return { attached: false };
}

/** Is there an entry at `p` (a dangling link counts: the rule refuses it)? */
function entryExists(p: string): boolean {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

/** ensurePrivateIfFallback with the launcher's `mandu:` voice: when `path` is
 *  (under) the shared-/tmp fallback base, that base is created 0700 or
 *  verified private, else the launch is refused (runtime-instances.md §3b).
 *  `createOther: false` (ensureArbiter's preflight) leaves an ABSENT base of
 *  the third rule (`$XDG_RUNTIME_DIR/mandu`, an explicit base outside a shared
 *  sticky dir) uncreated, so a launch the arbiter step refuses (a base too
 *  long for its socket) still creates nothing; a present one is still
 *  tightened or refused. The creators that follow create it 0700. */
export function guardRuntimePath(
  path: string,
  env: Record<string, string | undefined> = process.env,
  opts: RuntimeBaseOptions = {},
  deps: PrivateDirDeps = {},
  { createOther = true }: { createOther?: boolean } = {},
): void {
  try {
    if (createOther || fallbackBaseContaining(path, env, opts) !== null || sharedParentBaseContaining(path, env, opts, deps) !== null) {
      ensurePrivateIfFallback(path, env, opts, deps);
      return;
    }
    const base = runtimeBaseContaining(path, env, opts);
    if (base !== null && entryExists(base)) ensureRuntimeBaseDir(base, deps);
  } catch (err) {
    throw new Error(`mandu: refusing to launch: ${(err as Error).message}`);
  }
}

/** Default socket poll: 50 × 100ms (~5s), mirroring mandu-run.sh wait_for_socket.
 *  `giveUp` (checked after each miss) ends it early, unready. */
export async function pollSocket(sock: string, tries = 50, delayMs = 100, giveUp?: () => boolean): Promise<boolean> {
  for (let i = 0; i < tries; i++) {
    if (existsSync(sock)) return true;
    if (giveUp?.()) break;
    await new Promise((r) => setTimeout(r, delayMs));
  }
  return existsSync(sock);
}

/**
 * The launcher's wait for the arbiter socket after a start: the load-aware
 * service readiness deadline (services/primitives.ts serviceReadyDeadlineMs,
 * runtime-instances.md §14.6), 100 ms probes, ending early once the started daemon has
 * exited. Was a fixed 50 probes (about 5 s), which a saturated host missed
 * (runtime-instances.md §10, "Autostart deadlines under load").
 */
export function pollArbiterSocket(sock: string, giveUp?: () => boolean, deadlineMs = serviceReadyDeadlineMs()): Promise<boolean> {
  return pollSocket(sock, Math.max(1, Math.ceil(deadlineMs / 100)), 100, giveUp);
}

/** A spawner's return value as a DaemonHandle, when it is one. */
function asHandle(h: unknown): DaemonHandle | undefined {
  return h && typeof (h as DaemonHandle).running === "function" ? h as DaemonHandle : undefined;
}

/**
 * Default start: background the arbiter with the socket in its env and the
 * event dir as the `--event-dir` flag (on-disk-layout.md §5: store paths reach
 * the arbiter as flags, set only by Mandu's own spawners). A bundled layout
 * runs `node dist/arbiter.mjs --event-dir …`, a source checkout `node --import
 * <tsx> arbiter/ipc/server-main.ts --event-dir …` (the layout resolver picks). The
 * arbiter never imports its own IPC client, so
 * it needs no MANDU_ARBITER_CLIENT_MODULE (needsClient=false).
 *
 * DELIBERATELY NO LIFELINE (runtime-instances.md §8): unlike the per-session
 * services in services/primitives.ts, the arbiter is the shared attach-or-start
 * daemon — later launches and the dashboard attach to the SAME socket, so it
 * must outlive the launcher that happened to start it. Its teardown is
 * `mandu stop` / the instance sweep, not launcher death. stdio therefore
 * stays ["ignore", …] and MANDU_LIFELINE is not set (test harnesses that
 * want a session-bound arbiter pass their own lifeline pipe + env).
 *
 * Returns the spawned daemon (when the spawner reports one), for the socket
 * wait to stop early if it exits.
 */
export function startArbiter(
  layout: Layout,
  sock: string,
  eventDir: string,
  logPath: string,
  /** Extra env for the arbiter process (e.g. MANDU_CONFIDENTIALITY from the
   *  launcher flag). Optional + trailing so existing callers are unaffected. */
  extraEnv: Record<string, string> = {},
  deps: {
    /** The daemon spawner (defaults to the real child_process spawn). */
    spawnDaemon?: (spec: DaemonSpec, env: NodeJS.ProcessEnv, out: number, args: string[]) => unknown;
    /** The env the launch resolved its paths from: `main()`'s, which the
     *  runtime-dir checks judge (the fallback's private-dir rule, the shared
     *  parent's owner rule), as `startArbiterInstance`'s `runtimeEnv`
     *  (runtime-instances.md §3b). Defaults to process.env, the env the
     *  arbiter is spawned with either way. */
    runtimeEnv?: Record<string, string | undefined>;
  } = {},
): () => Promise<DaemonHandle | undefined> {
  return async () => {
    const runtimeEnv = deps.runtimeEnv ?? process.env;
    // Create the scope run dir, event dir, and socket dir before opening the
    // log / starting the arbiter — parity with mandu-run.sh:553. Without this,
    // openSync throws ENOENT on the first run on any fresh host.
    // A fallback base any of these live under is made private first (§3b).
    for (const p of [logPath, eventDir, sock]) guardRuntimePath(p, runtimeEnv);
    // The log's own directories are made by its open, one at a time and never
    // through a link (safe-log.ts), so a planted `logs/` link gets nothing.
    const out = openAppendLog(logPath, runtimeBaseContaining(logPath, runtimeEnv) ?? undefined);
    mkdirSync(eventDir, { recursive: true });
    mkdirSync(dirname(sock), { recursive: true });
    const baseEnv = {
      ...process.env,
      MANDU_ARBITER_SOCK: sock,
      ...extraEnv,
    };
    // A spawn failure (npm missing, bad cwd) is swallowed in spawnDaemonSpec:
    // the socket poll in ensureArbiter is the real liveness signal and refuses
    // the launch cleanly if nothing comes up.
    const spawnDaemon = deps.spawnDaemon ?? spawnDaemonSpec;
    return asHandle(spawnDaemon(layout.daemon("arbiter", "arbiter", false), baseEnv, out, ["--event-dir", eventDir, ...classifierArgsOf(layout)]));
  };
}

/**
 * The arbiter's policy-classifier flags (confidentiality-plan-14 §14.3):
 * `--classifier <json argv>` from the layout and `--landlock-apply <path>`
 * when the applier is built. Never from the environment on the arbiter's
 * side: only Mandu's own spawners pass them (the dashboard supervisor does
 * the same from its layout). Empty when the classifier's runtime is missing.
 */
export function arbiterClassifierArgs(
  layout: Pick<Layout, "policyClassifier">,
  resolveApplier: () => string | null = () => resolveNativeBin("mandu-landlock-apply"),
): string[] {
  const argv = layout.policyClassifier();
  if (argv === null) return [];
  const applier = resolveApplier();
  return ["--classifier", JSON.stringify(argv), ...(applier ? ["--landlock-apply", applier] : [])];
}

/**
 * Instance-mode start (runtime-instances.md §5): no pinned socket — the
 * arbiter binds instances/<id>/arbiter.sock under `base` and PROMOTES itself
 * to ${base}/current, which is exactly the `current`-spelling path the launch
 * resolved (arbiter-sock.ts mode "autostart"). The event dir is deliberately
 * NOT set here: a resident arbiter must use its own durable default, not one
 * launch's scope-local events dir, so it is started with no store flags.
 * Same no-lifeline rationale as
 * startArbiter above — this daemon outlives the launcher that started it.
 */
/** A daemon the launcher started: its pid (= its process group, it is
 *  spawned detached) and whether it is still running. */
export interface DaemonHandle {
  readonly pid: number | undefined;
  running(): boolean;
}

export interface InstanceStartDeps {
  /** The daemon spawner (defaults to the real child_process spawn). A spawner
   *  that returns no handle is treated as "cannot tell if it still runs": the
   *  fallback follows the first wait, as before the handle existed. */
  spawnDaemon?: (spec: DaemonSpec, env: NodeJS.ProcessEnv, out: number, args?: string[]) => DaemonHandle | void;
  /** Poll for the promoted socket (defaults to pollSocket). */
  waitForSocket?: (sock: string, tries: number, delayMs: number) => Promise<boolean>;
  /** How long past the first 6 s wait a supervisor that is STILL RUNNING gets
   *  to promote before it is stopped and the bare arbiter replaces it
   *  (default: defaultSupervisorGraceMs of the load-aware service readiness
   *  deadline; 54 s on an idle host, so 60 s in all). */
  supervisorGraceMs?: number;
  /** Stop a supervisor that never promoted: its whole process group (it is
   *  spawned detached), SIGTERM then SIGKILL. Defaults to stopDaemonGroup. */
  stopDaemon?: (daemon: DaemonHandle) => Promise<void>;
  /** Where the fallback (the dashboard did not come up) is explained. */
  log?: (msg: string) => void;
  /** Where the all-is-well "starting the stack" note goes (defaults to
   *  `log`). The launcher shows it only under --verbose (launch-banner.ts). */
  info?: (msg: string) => void;
  /** MANDU_AUTOSTART_SUPERVISOR=0 opts back into the bare-arbiter start.
   *  The env the stack is spawned with (defaults to process.env). */
  env?: NodeJS.ProcessEnv;
  /** The env `base` was resolved from: the launch's own (`main()`'s), which
   *  the runtime-dir checks judge — the instance socket's fit and its
   *  XDG_RUNTIME_DIR advice, the fallback's private-dir rule, the moved-base
   *  hint. Defaults to `env`. */
  runtimeEnv?: Record<string, string | undefined>;
  /** The account this launch runs as: its passwd home and its host
   *  rendezvous base (`/run/user/<uid>/mandu`). Defaults to the real ones;
   *  null = unknown, the foreign-HOME rewrite is skipped. */
  account?: Account | null;
  /** What this start appended to the log (defaults to reading the file from
   *  the size it had before the spawn). */
  readLogSince?: (path: string, offset: number) => string | null;
  /** The platform whose sun_path size and pid width the instance-socket
   *  preflight uses (defaults to process.platform). */
  platform?: string;
  /** The code rev the arbiter about to start will put in its instance id
   *  (defaults to arbiterRevOf(arbiterRevDir(layout))). Read only when a
   *  worst-case socket would not fit under the base. */
  arbiterRev?: () => string;
  /** Test seams for the fallback rule and the private-dir check. */
  runtimeBaseOpts?: RuntimeBaseOptions;
  privateDirDeps?: PrivateDirDeps;
}

/** The supervisor's grace past its first 6 s wait, for a service readiness
 *  deadline `readyMs` (runtime-instances.md §14.6): two of them less those 6 s, since
 *  the supervisor must first come up itself and then bring its arbiter up
 *  within `readyMs` of its own; never under the 14 s it was fixed at (54 s on
 *  an idle host, so 60 s in all). Only a supervisor that is still running and
 *  has not promoted waits this long: one whose arbiter failed exits
 *  (DASHBOARD_AUTOSTART=arbiter), and the fallback starts at once. */
export function defaultSupervisorGraceMs(readyMs: number): number {
  return Math.max(14_000, 2 * readyMs - 6_000);
}

/** The promoted `current` socket an instance-mode start is expected to produce. */
export function promotedSockPath(base: string): string {
  return `${base}/current/arbiter.sock`;
}

/**
 * Stage 0b (policy-surface.md §2.6): the instance-mode autostart
 * starts the SUPERVISOR — the dashboard server (`DASHBOARD_AUTOSTART=arbiter`)
 * — which owns the arbiter over the inherited admin fd. A bare-arbiter start
 * would leave a later dashboard ADOPTING it, its human-decision controls
 * read-only until a restart; starting the supervisor first means the human
 * channel exists from the first launch. FAIL-SOFT: if the dashboard does not
 * bring the promoted socket up in time (port busy, package missing), the
 * bare arbiter is started as before and the log says why — the launch is
 * never left ungated for want of a dashboard. A supervisor that is still
 * RUNNING at 6 s is slow, not failed: it gets `supervisorGraceMs` more, and
 * one that never promotes is stopped (its whole process group) before the
 * fallback starts, so a launch never leaves two resident arbiters
 * (runtime-instances.md §10). `MANDU_AUTOSTART_SUPERVISOR=0` skips the
 * supervisor path.
 *
 * Two refusals come first (runtime-instances.md §3b): a base the arbiter's
 * instance socket cannot fit under fails at once naming MANDU_RUNTIME_DIR (not
 * after an 11 s wait for an arbiter that cannot bind), and the shared-/tmp
 * fallback base must be a private 0700 dir of this uid (a base directly in a
 * shared sticky dir: ours, and writable by nobody else). The socket is sized
 * with the REAL suffix — the rev this arbiter will run and the platform's
 * widest pid — so a base only the worst case overflows still starts (it did
 * on Linux before the preflight existed); the arbiter's own socket-path check
 * stays authoritative. Then, when the base is the fallback while a stack still
 * answers at the pre-2026-09-29 `$TMPDIR/mandu`, one line says so
 * (movedBaseHint).
 */
export function startArbiterInstance(
  layout: Layout,
  base: string,
  logPath: string,
  extraEnv: Record<string, string> = {},
  deps: InstanceStartDeps = {},
): () => Promise<DaemonHandle | undefined> {
  return async () => {
    const env = deps.env ?? process.env;
    const runtimeEnv = deps.runtimeEnv ?? env;
    const platform = deps.platform ?? process.platform;
    let tooLong = instanceBaseProblem(base, platform);
    if (tooLong !== null) {
      // The worst case (a 16-char rev, a 7-digit pid) does not fit: size the
      // socket THIS arbiter will bind. Only here, so a short base runs no git.
      const rev = (deps.arbiterRev ?? (() => arbiterRevOf(arbiterRevDir(layout))))();
      tooLong = instanceBaseProblem(base, platform, instanceSockSuffix(rev, maxPidDigitsFor(platform)));
    }
    if (tooLong !== null) {
      throw new Error(
        `mandu: refusing to launch: ${tooLong}.` +
          (!runtimeEnv["MANDU_RUNTIME_DIR"] && runtimeEnv["XDG_RUNTIME_DIR"]
            ? " The dir comes from XDG_RUNTIME_DIR; MANDU_RUNTIME_DIR overrides it."
            : ""),
      );
    }
    for (const p of [base, logPath]) guardRuntimePath(p, runtimeEnv, deps.runtimeBaseOpts, deps.privateDirDeps);
    mkdirSync(base, { recursive: true });
    // `<base>/logs/` is made by the open, never through a link (safe-log.ts).
    const out = openAppendLog(logPath, resolvePath(logPath).startsWith(`${resolvePath(base)}/`) ? base : undefined);
    let logOffset = 0;
    try { logOffset = fstatSync(out).size; } catch { /* read the whole log */ }
    const log = deps.log ?? ((m: string) => process.stderr.write(m + "\n"));
    const info = deps.info ?? log;
    const moved = movedBaseHint(runtimeEnv, deps.runtimeBaseOpts);
    if (moved !== null) log(moved);
    const spawnDaemon = deps.spawnDaemon ?? spawnDaemonSpec;
    const waitForSocket = deps.waitForSocket ?? pollSocket;
    const baseEnv: NodeJS.ProcessEnv = {
      ...env,
      MANDU_RUNTIME_DIR: base,
      MANDU_PROMOTE: "1",
      // The resident stack has NO owner: it outlives this launcher on purpose
      // (§8), so `mandu reap` must not stop it once the launcher exits
      // (release checklist d4: status called the launch's own dashboard
      // "DEAD → reapable"). It stops by `mandu stop` or from the dashboard.
      MANDU_OWNER_PID: "none",
      ...extraEnv,
    };
    // A pinned sock in the inherited env would flip server-main back to
    // pinned mode; the resolver already decided there is nothing pinned.
    delete baseEnv["MANDU_ARBITER_SOCK"];
    delete baseEnv["MANDU_ARBITER_SOCKET"];
    // The shared stack belongs to the ACCOUNT (runtime-instances.md §13): a
    // launch under a scratch HOME still starts it under the real home, or its
    // arbiter would keep the account's symbol DB, policy and events in the
    // scratch dir and every later launch and the dashboard would join that
    // (found live 2026-09-28). This launch's own agent keeps its HOME.
    const asAccount = sharedStackHomeEnv(env, base, deps.account === undefined ? accountOf() : deps.account);
    if (asAccount) {
      Object.assign(baseEnv, asAccount.set);
      for (const k of asAccount.unset) delete baseEnv[k];
      info(
        `mandu: HOME is ${env["HOME"]}, not your account's home; the shared Mandu stack starts under ` +
          `${asAccount.set["HOME"]} (this launch keeps its HOME). Set MANDU_RUNTIME_DIR for a private stack instead.`,
      );
    }

    if (env["MANDU_AUTOSTART_SUPERVISOR"] !== "0") {
      // The supervisor: only the arbiter (the proxies are this launch's own
      // per-session services), instance mode + promote via the same env; the
      // lifeline stays unset — the stack outlives the launcher (§8).
      // needsClient=true: the dashboard DOES import the arbiter client (its
      // approvals adapter); spawned without MANDU_ARBITER_CLIENT_MODULE the
      // bundled dashboard logged "egress approvals disabled: Cannot find
      // module …/arbiter/ipc/client.js" on every fresh install (2026-09-24).
      // One load-aware readiness deadline for the supervisor's own arbiter
      // start (dashboard supervisor-defs.ts startTimeoutFromEnv; its fixed
      // 10 s SIGKILLed an arbiter a saturated host was still starting) and
      // for this wait (runtime-instances.md §10 "Autostart deadlines under load").
      const readyMs = serviceReadyDeadlineMs(env);
      const supervisorEnv: NodeJS.ProcessEnv = {
        ...baseEnv,
        DASHBOARD_AUTOSTART: "arbiter",
        MANDU_SERVICE_READY_TIMEOUT_MS: String(readyMs),
        // A free port unless the user pinned one (release checklist a1,
        // runtime-instances.md §8): the fixed 4500 belongs to whichever
        // dashboard started first on the host (another user's, a resident
        // deployment's), and a busy port used to cost this launch its
        // supervisor. The dashboard registers its BOUND port in
        // <runtime>/dashboards/, which is how `mandu dashboard` finds it.
        DASHBOARD_PORT: (env["DASHBOARD_PORT"] ?? "") !== "" ? env["DASHBOARD_PORT"] : "0",
      };
      const supervisor = spawnDaemon(layout.daemon("dashboard", "dashboard", true), supervisorEnv, out);
      info("mandu: no arbiter running — starting the Mandu stack (dashboard + arbiter) so your decisions have a place to land (`mandu dashboard` opens it)");
      const sock = promotedSockPath(base);
      if (await waitForSocket(sock, 60, 100)) return undefined;
      // ONE resident arbiter (2026-09-29): a supervisor that is merely SLOW
      // (a loaded host, a cold tsx cache) is still bringing its own arbiter
      // up. Starting the bare fallback beside it planted a SECOND resident
      // arbiter: it stole `current` from the supervised one, nobody owned it
      // (MANDU_OWNER_PID=none, no lifeline), and whoever stopped the
      // dashboard left it serving (found as a 3-hour orphan of
      // instance-autostart.test.ts). So while the supervisor still runs, keep
      // waiting; if it never promotes, stop its whole group BEFORE the
      // fallback starts. A supervisor that EXITED (port busy, package
      // missing) falls back at once, as before.
      const graceMs = deps.supervisorGraceMs ?? defaultSupervisorGraceMs(readyMs);
      let stalled = false;
      if (supervisor && supervisor.running()) {
        const deadline = Date.now() + graceMs;
        while (supervisor.running() && Date.now() < deadline) {
          if (await waitForSocket(sock, 5, 100)) return undefined;
        }
        if (await waitForSocket(sock, 1, 0)) return undefined;
        if (supervisor.running()) {
          stalled = true;
          await (deps.stopDaemon ?? stopDaemonGroup)(supervisor);
          // It may have promoted while it was being stopped; that arbiter is
          // going down with it, so the fallback still starts.
        }
      }
      const why = stalled
        ? `it was still starting after ${Math.round((6_000 + graceMs) / 1000)} s, so it was stopped`
        : lastStartFailure((deps.readLogSince ?? readLogSince)(logPath, logOffset));
      log(
        `mandu: the dashboard did not start (${why ?? "it did not answer within 6 s, and its log shows no error"}); ` +
        `protection runs without it (log: ${logPath}). Approvals need a dashboard: \`mandu dashboard\` starts one, ` +
        "but its approve and deny buttons stay read-only until you restart the services from it.",
      );
    }
    const classifier = classifierArgsOf(layout);
    const spec = layout.daemon("arbiter", "arbiter", false);
    return asHandle(classifier.length > 0 ? spawnDaemon(spec, baseEnv, out, classifier) : spawnDaemon(spec, baseEnv, out));
  };
}

/** `arbiterClassifierArgs` for a layout that may predate the classifier (a
 *  test's stand-in layout): no flags then. Followed by the prompt filter
 *  plugins' confinement flags (`arbiterPluginArgs`). */
function classifierArgsOf(layout: Layout): string[] {
  let classifier: string[] = [];
  try {
    classifier = typeof (layout as Partial<Layout>).policyClassifier === "function" ? arbiterClassifierArgs(layout) : [];
  } catch {
    classifier = [];
  }
  return [...classifier, ...arbiterPluginArgs(classifier)];
}

/**
 * The prompt filter plugins' confinement flags (confidentiality-plan-15
 * §4.3, §12 2026-10-03): `--net-guard <path>` (the address guard, required
 * for any plugin to run) and `--landlock-apply <path>` when the classifier's
 * flags did not already pass it. Empty when the native bins are not built
 * (`scripts/build-native.sh`): the arbiter then runs no plugin.
 */
export function arbiterPluginArgs(
  already: readonly string[],
  resolve: (name: "mandu-net-guard" | "mandu-landlock-apply") => string | null = (n) => resolveNativeBin(n),
): string[] {
  const out: string[] = [];
  const guard = resolve("mandu-net-guard");
  if (guard) out.push("--net-guard", guard);
  if (!already.includes("--landlock-apply")) {
    const applier = resolve("mandu-landlock-apply");
    if (applier) out.push("--landlock-apply", applier);
  }
  return out;
}

/** An account's passwd home and its host rendezvous base. */
export interface Account {
  home: string;
  rendezvous: string;
}

/**
 * The dir the arbiter this launch starts reads its code rev from:
 * arbiter/ipc/server-main.ts takes REPO_DIR = <its own dir>/../.. — in a
 * checkout `<repoRoot>/arbiter/ipc` → the checkout root (the dashboard
 * supervisor spawns the same file); installed, the bundle
 * `<pkgRoot>/dist/arbiter.mjs` → the dir that holds the package, which is
 * inside a git work tree more often than one might think (a Homebrew prefix).
 */
export function arbiterRevDir(layout: Layout): string {
  return layout.mode === "installed" ? resolvePath(layout.pkgRoot, "..") : layout.repoRoot;
}

/** The rev the arbiter will put in its instance id, the way
 *  arbiter/ipc/instance.ts gitRevOf() reads it: the same HARDENED `git
 *  rev-parse --short HEAD` in `dir` (hardened-git.ts, git-hardening.md §2:
 *  `dir` can be an agent's workspace or a Homebrew prefix, so no program its
 *  config names may start and no inherited `GIT_*` may redirect the read),
 *  "nogit" when that fails. gitRevOf's dirty flag never changes the rev. */
export function arbiterRevOf(dir: string): string {
  try {
    return execFileSync("git", hardenedGitArgs(["rev-parse", "--short", "HEAD"]), {
      cwd: dir, encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"],
      env: hardenedGitEnv(process.env, { GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C" }),
    }).trim() || "nogit";
  } catch {
    return "nogit";
  }
}

/** Do revs `a` and `b` of the checkout at `dir` hold one `arbiter/` tree
 *  (the release check's build comparison, arbiter-version.ts compareBuilds;
 *  the same scope as the dashboard's STALE flag, runtime-instances.md §4)?
 *  One hardened `git rev-parse` of both tree ids. Null when git cannot say
 *  (a rev not in this repository, no git): the caller takes that as
 *  "different". Only hex revs reach the argv (`a` is the arbiter's claim). */
export function arbiterTreesMatch(dir: string, a: string, b: string): boolean | null {
  const hex = /^[0-9a-f]{4,40}$/;
  if (!hex.test(a) || !hex.test(b)) return null;
  const treeOf = (rev: string): string => execFileSync("git", hardenedGitArgs(["rev-parse", "--verify", "--quiet", `${rev}^{commit}:arbiter`]), {
    cwd: dir, encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"],
    env: hardenedGitEnv(process.env, { GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C" }),
  }).trim();
  try {
    const ta = treeOf(a);
    const tb = treeOf(b);
    return ta !== "" && tb !== "" ? ta === tb : null;
  } catch {
    return null;
  }
}

/** Injectable facts for accountOf (tests pin darwin on any host). */
export interface AccountDeps {
  platform?: string;
  getuid?: (() => number) | null;
  homedir?: () => string;
  darwinTempDir?: () => string;
}

/** The account this process runs as, or null when the platform cannot say.
 *  Mirror of arbiter/ipc/instance.ts accountIdentity: the rendezvous is
 *  accountRendezvous (`/run/user/<uid>/mandu`) on Linux and, on macOS, the
 *  default runtime base of DARWIN_USER_TEMP_DIR (runtime-base.ts
 *  accountRendezvous — in practice `/tmp/mandu-<uid>`). */
export function accountOf(deps: AccountDeps = {}): Account | null {
  try {
    const getuid = deps.getuid !== undefined
      ? deps.getuid
      : (typeof process.getuid === "function" ? () => process.getuid!() : null);
    if (typeof getuid !== "function") return null;
    const uid = getuid();
    const home = (deps.homedir ?? (() => userInfo().homedir))();
    const platform = deps.platform ?? process.platform;
    return {
      home,
      rendezvous: platform === "darwin"
        ? defaultBaseRendezvous(uid, { platform, ...(deps.darwinTempDir ? { darwinTempDir: deps.darwinTempDir } : {}) })
        : accountRendezvous(uid, home),
    };
  } catch {
    return null;
  }
}

/** An account's host rendezvous base: the path table's `runtime-dir` under
 *  its logind runtime dir, `/run/user/<uid>/mandu` (on-disk-layout.md §5). */
export function accountRendezvous(uid: number, home: string): string {
  return manduPath("runtime-dir", { XDG_RUNTIME_DIR: `/run/user/${uid}` }, home);
}

/**
 * The env rewrite that starts the SHARED stack as the account when this launch
 * runs under a foreign HOME, or null when none is needed (runtime-instances.md
 * §13). Applies only at the account's own rendezvous (accountOf: Linux
 * `/run/user/<uid>/mandu`, macOS `/tmp/mandu-<uid>`):
 * a run with its own MANDU_RUNTIME_DIR / XDG_RUNTIME_DIR is isolated on purpose
 * and keeps its HOME. A MANDU_HOME or an XDG base dir that points INTO the
 * foreign HOME goes with it (it would move the state right back); one pointing
 * elsewhere was set on purpose and stays. The arbiter refuses the same promotion on its own
 * (arbiter/ipc/instance.ts foreignHomePromotion) — this rewrite is what keeps
 * the launch working instead of waiting for a `current` that never comes.
 */
export function sharedStackHomeEnv(
  env: NodeJS.ProcessEnv,
  base: string,
  account: Account | null,
): { set: Record<string, string>; unset: string[] } | null {
  const home = env["HOME"];
  if (!account || !home) return null;
  if (resolvePath(base) !== resolvePath(account.rendezvous)) return null;
  const foreign = resolvePath(home);
  if (foreign === resolvePath(account.home)) return null;
  const inside = (p: string | undefined): boolean =>
    p !== undefined && p !== "" && (resolvePath(p) === foreign || resolvePath(p).startsWith(foreign + "/"));
  const unset = ["MANDU_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME"].filter((k) => inside(env[k]));
  return { set: { HOME: account.home }, unset };
}

/** The argv that runs a daemon spec with `args` appended: `<cmd> <spec.args>
 *  <args>` (a bundle or a tsx-loaded entry, one node process either way). */
export function daemonArgv(spec: DaemonSpec, args: readonly string[] = []): { cmd: string; argv: string[] } {
  return { cmd: spec.cmd, argv: [...spec.args, ...args] };
}

/** Spawn one daemon spec detached (the shared tail for every start mode).
 *  Detached = its own process group (pgid = pid), which is what lets
 *  stopDaemonGroup take the daemon and anything it started down together.
 *  A spawn failure emits 'error'; without the listener below Node would crash
 *  the launcher. */
function spawnDaemonSpec(spec: DaemonSpec, baseEnv: NodeJS.ProcessEnv, out: number, args: readonly string[] = []): DaemonHandle {
  const { cmd, argv } = daemonArgv(spec, args);
  const child = spawn(cmd, argv, {
    cwd: spec.cwd, env: { ...baseEnv, ...spec.env }, detached: true, stdio: ["ignore", out, out],
  });
  let exited = false;
  child.on("error", () => { exited = true; /* failed to start; the socket poll refuses the launch */ });
  child.on("exit", () => { exited = true; });
  child.unref();
  return { pid: child.pid, running: () => !exited && child.pid !== undefined };
}

/** Stop a detached daemon's whole process group: SIGTERM (the dashboard's
 *  handler stops its supervised arbiter), then SIGKILL after `graceMs`. */
export async function stopDaemonGroup(daemon: DaemonHandle, graceMs = 5_000): Promise<void> {
  const pid = daemon.pid;
  if (pid === undefined) return;
  const signal = (sig: NodeJS.Signals | 0): boolean => {
    try { process.kill(-pid, sig); return true; } catch { return false; }
  };
  if (!signal("SIGTERM")) return;
  const deadline = Date.now() + graceMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
    if (!signal(0)) return; // the group is empty
  }
  signal("SIGKILL");
}

