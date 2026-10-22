/**
 * supervisor — a tiny dependency-free process supervisor for the Mandu
 * control plane (arbiter + the Track-A model/openai/egress proxies), driven from
 * the dashboard.
 *
 * Mandu-new (NO reference origin). The design mirrors two existing pieces:
 *   - the node:child_process spawn/env-merge style of fs-sync/src/git.ts
 *     (Promise-wrapped spawn, `{ ...process.env, ...env }`), and
 *   - launcher/mandu-run.sh `wait_for_socket()` (poll until the arbiter's Unix
 *     socket exists) + its background arbiter autostart pattern — ported here to
 *     an active `net.connect()` readiness probe (fast-rejects a stale/missing
 *     socket; retries until startTimeoutMs).
 *
 * Why a process-group kill: each service is `npm run --silent serve`, which
 * forks `tsx`, which forks the real node entrypoint. Killing the npm pid alone
 * orphans the grandchildren. We spawn with `detached: true` (new process group)
 * and signal the whole group via `process.kill(-pid, sig)`, escalating
 * SIGTERM → SIGKILL after stopGraceMs. This is the part the stop() test proves:
 * after stop(), `process.kill(pid, 0)` throws ESRCH (no orphan left behind).
 *
 * Module map (agent-legibility split; this file keeps the stateful Supervisor
 * class and re-exports the public types):
 *   - ./supervisor-defs   public types, DEFAULTS, the production
 *                         ServiceDefinitions, arbiterStaleness
 *   - ./socket-owner      /proc discovery of a unix socket's listener pid
 *   - ./process-signals   process-group / foreign-pid signalling helpers
 *   - ./service-runtime   the internal per-service runtime record (shape,
 *                         fresh-record factory, admin-channel teardown)
 *   - ./service-logs      log capture: the in-memory ring + subscribers, the
 *                         durable per-module log file, the crash stderr tail
 */

import { spawn, type ChildProcess } from "node:child_process";
import { type Socket } from "node:net";
import { join, dirname, resolve as resolvePath } from "node:path";
import { mkdirSync, rmSync } from "node:fs";

// Public types + defaults + the production ServiceDefinitions live in
// ./supervisor-defs (agent-legibility split); re-exported so the public API is
// unchanged, imported back for the process machinery below.
export type {
  ArbiterIdentity,
  LogLine,
  ServiceDefinition,
  ServiceId,
  ServiceState,
  ServiceStatus,
  SupervisorOptions,
} from "./supervisor-defs.js";
import {
  arbiterReleaseStaleness,
  arbiterStaleness,
  buildDefinitions,
  checkoutBundleFresh,
  DEFAULTS,
  SERVICE_IDS,
  type ArbiterIdentity,
  type LogLine,
  type ResolvedSupervisorOptions,
  type ServiceDefinition,
  type ServiceId,
  type ServiceStatus,
  type StalenessVerdict,
  type SupervisorOptions,
} from "./supervisor-defs.js";
import { gitChangedFiles, gitShortRev } from "../self-status.js";
import { ownArbiterBuildOf } from "./own-arbiter-build.js";
import { arbiterAxisSpawnEnv } from "../config-axes.js";
import { checkReady, helloProbe, readPortFile, READY_PROBE_INTERVAL_MS } from "../net-probes.js";
import { defaultEventDir } from "../event-dir.js";
import { discoverUnixSocketOwner, procCmdlineOf } from "./socket-owner.js";
import { liveSessionsOn } from "./stack-sessions.js";
import { signalGroup, signalPidChecked, waitPidGone } from "./process-signals.js";
import { createServiceRuntime, dropAdminChannel, type ServiceRuntime } from "./service-runtime.js";
import { endLogFile, logFileWritten, openLogFile, tailStderr, wireLogs } from "./service-logs.js";

/** Re-probe cadence for an adopted daemon that has no hello identity yet: the
 *  status poll retries the handshake (and, failing that, the /proc socket-owner
 *  walk) at most this often. The adopt-time probe is one-shot and can lose a
 *  boot race — without the retry, one 1.5s hiccup froze the row in the
 *  "no verified identity" dead end forever. */
const ADOPTED_IDENT_REFRESH_MS = 10_000;

// ─────────────────────────────────────────────────────────────────────────────
// Supervisor
// ─────────────────────────────────────────────────────────────────────────────

export class Supervisor {
  private readonly opts: ResolvedSupervisorOptions;
  private readonly logRingMax: number;
  /** Directory for durable per-module log files (one `<id>.log` per service). */
  private readonly logDir: string;
  /** Services whose log file has been TRUNCATED (overwritten "w") once this
   *  process; subsequent in-process restarts APPEND ("a") so a restart doesn't
   *  wipe earlier output. The file is still fresh per dashboard PROCESS. */
  private readonly truncatedLogs = new Set<ServiceId>();
  private readonly services: Record<ServiceId, ServiceRuntime>;

  constructor(opts: SupervisorOptions) {
    const log = opts.log ?? ((m: string) => console.error(`[supervisor] ${m}`));
    this.opts = {
      repoRoot: opts.repoRoot,
      // The installed layout (packaging.md §5): dropped here once, so the
      // bundled dashboard spawned the CHECKOUT definitions (`<pkg>/arbiter`
      // as cwd → `spawn node ENOENT`) although server-main had detected the
      // bundle (fresh-install 24.04, 2026-09-24). Carried explicitly.
      layout: opts.layout,
      checkoutDist: opts.checkoutDist,
      bundleFresh: opts.bundleFresh ?? checkoutBundleFresh,
      arbiterSock: opts.arbiterSock,
      arbiterInstanceBase: opts.arbiterInstanceBase,
      eventDir: opts.eventDir,
      symbolDb: opts.symbolDb,
      modelProxyPort: opts.modelProxyPort ?? DEFAULTS.modelProxyPort,
      openaiProxyPort: opts.openaiProxyPort ?? DEFAULTS.openaiProxyPort,
      egressProxyPort: opts.egressProxyPort ?? DEFAULTS.egressProxyPort,
      proxyHost: opts.proxyHost ?? DEFAULTS.proxyHost,
      upstreamAnthropic: opts.upstreamAnthropic ?? DEFAULTS.upstreamAnthropic,
      upstreamOpenai: opts.upstreamOpenai ?? DEFAULTS.upstreamOpenai,
      logRingMax: opts.logRingMax ?? DEFAULTS.logRingMax,
      startTimeoutMs: opts.startTimeoutMs ?? DEFAULTS.startTimeoutMs,
      stopGraceMs: opts.stopGraceMs ?? DEFAULTS.stopGraceMs,
      autoStartArbiter: opts.autoStartArbiter ?? true,
      definitions: opts.definitions,
      mockSitesPath: opts.mockSitesPath,
      axisEnv: opts.axisEnv ?? ((processEnv) => arbiterAxisSpawnEnv(processEnv)),
      gitRev: opts.gitRev ?? gitShortRev,
      gitChangedInRange: opts.gitChangedInRange ?? gitChangedFiles,
      ownArbiterBuild: opts.ownArbiterBuild ?? (() => ownArbiterBuildOf({ repoRoot: opts.repoRoot, ...(opts.layout ? { layout: opts.layout } : {}), ...(opts.checkoutDist ? { checkoutDist: opts.checkoutDist } : {}) })),
      procCmdline: opts.procCmdline ?? procCmdlineOf,
      killPid: opts.killPid ?? ((pid, sig) => process.kill(pid, sig)),
      discoverSocketOwner: opts.discoverSocketOwner ?? discoverUnixSocketOwner,
      replaceStaleOnAdopt: opts.replaceStaleOnAdopt ?? true,
      liveSessions: opts.liveSessions ?? ((base) => liveSessionsOn(base)),
      onCrash: opts.onCrash ?? (() => {}),
      log,
    };
    this.logRingMax = this.opts.logRingMax;
    // Instance mode: NEVER derive paths from dirname(current/arbiter.sock) — a
    // `mkdir -p` there would materialize `current` as a real directory and break
    // the promotion symlink. Logs live directly under the runtime base instead.
    this.logDir =
      opts.logDir ??
      (opts.arbiterInstanceBase ? join(opts.arbiterInstanceBase, "logs") : join(dirname(opts.arbiterSock), "logs"));

    const defs = buildDefinitions(this.opts);
    this.services = {} as Record<ServiceId, ServiceRuntime>;
    for (const id of SERVICE_IDS) {
      this.services[id] = createServiceRuntime(defs[id]);
    }
  }

  /**
   * The admin channel to a service THIS supervisor spawned (the parent end of
   * the stdio socketpair the child sees as `MANDU_ADMIN_FD`), or null when
   * the service is adopted / stopped / crashed / defined without one. The
   * caller wraps it in an arbiter client; a fresh spawn yields a fresh socket,
   * so callers must re-read this rather than cache the first answer.
   */
  adminChannel(id: ServiceId): Socket | null {
    const svc = this.services[id];
    if (!svc.child || svc.state !== "running") return null;
    const sock = svc.adminSocket;
    return sock && !sock.destroyed ? sock : null;
  }

  // ── public API ─────────────────────────────────────────────────────────────

  /**
   * Start a service. Resolves once it is READY; rejects on readiness timeout or
   * an early child exit. Idempotent: if already running (or currently starting),
   * the in-flight/established run is reused and the same pid is kept.
   */
  async start(id: ServiceId): Promise<void> {
    const svc = this.services[id];

    if (svc.state === "running") return; // idempotent — same pid kept
    if (svc.startPromise) return svc.startPromise; // an in-flight start — coalesce

    // Publish the in-flight promise SYNCHRONOUSLY (before any await inside
    // bringUp), so a concurrent start() coalesces onto it instead of racing into
    // a second adopt-probe / spawn.
    const p = this.bringUp(id);
    svc.startPromise = p;
    try {
      await p;
    } finally {
      svc.startPromise = undefined;
    }
  }

  /** Adopt an already-running instance, else spawn one (after its deps). The
   *  caller (start) publishes the returned promise as svc.startPromise so
   *  concurrent starts coalesce. */
  private async bringUp(id: ServiceId): Promise<void> {
    const svc = this.services[id];

    // ADOPT an already-running instance: if the readiness endpoint is ALREADY
    // live (a arbiter started outside this dashboard, a concurrent run, or another
    // dashboard process), use it instead of spawning a duplicate. An adopted
    // service has no child pid, so stop()/shutdownAll() leave it running — we only
    // reap what we started. This decouples a dashboard restart from a shared
    // arbiter's lifecycle (a dashboard restart no longer bounces the arbiter).
    // A `port-file` service is never adopted: its port is kernel-assigned per
    // spawn, so a leftover file names a dead (or someone else's) port.
    if (svc.def.ready.kind !== "port-file" && (await checkReady(svc.def.ready))) {
      svc.state = "running";
      svc.adopted = true;
      svc.child = null;
      dropAdminChannel(svc); // an adopted instance has no admin channel — by design
      svc.pid = null;
      svc.since = Date.now();
      svc.lastError = null;
      // Adopt KNOWINGLY (runtime-instances.md): fetch the listener's identity so
      // a weeks-stale daemon can't masquerade as current. Best-effort — an old
      // arbiter without the hello op still adopts, identity stays null.
      if (id === "arbiter") {
        svc.identity = await helloProbe(this.opts.arbiterSock);
        // A null identity here is NOT final: the adopt-time probe can lose a
        // boot race, so the status poll keeps retrying (refreshAdoptedIdentity)
        // — identRefreshAt=0 lets the first poll retry immediately.
        svc.owner = null;
        svc.identRefreshAt = 0;
        const who = svc.identity
          ? `pid ${svc.identity.pid}, rev ${svc.identity.gitRev}${svc.identity.gitDirty ? "+dirty" : ""}, ` +
            (svc.identity.version ? `Mandu ${svc.identity.version}, ` : "") +
            (svc.identity.build?.bundle ? `bundle ${svc.identity.build.bundle}, ` : "") +
            `since ${svc.identity.startedAt}${svc.identity.instanceId ? `, instance ${svc.identity.instanceId}` : ""}`
          : "identity unknown (no hello answer yet — the status poll keeps retrying)";
        // A FOREIGN arbiter (dashboard.md §3.3a, 2026-09-28): one that keeps
        // its events somewhere else — started under another HOME (a test
        // launch with a scratch HOME autostarted the host stack and held
        // `current` for 20 h; this dashboard adopted it and showed that
        // scratch dir's sessions, no drills, no tests). In instance mode we do
        // NOT adopt it: our own instance starts and takes over `current` by
        // promotion. The foreign one is left running for whoever already
        // joined it. A pinned socket cannot be displaced: adopt and say so.
        const foreign = this.foreignArbiterReason(svc.identity);
        if (foreign !== null && this.opts.arbiterInstanceBase && svc.identity) {
          this.opts.log(
            `${id}: NOT adopting the instance at ${svc.def.endpoint} (${who}): ${foreign}. ` +
              "Starting this dashboard's own instance, which takes over 'current'; the other one keeps running for whoever joined it.",
          );
          svc.displacePid = svc.identity.pid;
          svc.state = "stopped";
          svc.adopted = false;
          svc.identity = null;
          svc.since = null;
          // fall through to the spawn below
        } else {
          const verdict = this.staleness(svc.identity);
          // A STALE arbiter of OUR stack (runtime-instances.md §4.1b,
          // 2026-10-21): another release, build or rev than this dashboard
          // would start, and so than the launches of this checkout or
          // install, which refuse it. Adopting it kept it the stack's
          // arbiter across every restart of this dashboard (four days, two
          // releases). When no `mandu` session uses the stack it is
          // replaced, as a launch of this build replaces an unused older
          // stack (§4.1); with one, it is adopted and flagged as before.
          const replacing = verdict.stale && foreign === null && svc.identity !== null
            && this.opts.arbiterInstanceBase !== undefined && this.opts.replaceStaleOnAdopt;
          const sessions = replacing ? this.opts.liveSessions(this.opts.arbiterInstanceBase!) : [];
          if (replacing && sessions !== null && sessions.length === 0) {
            this.opts.log(
              `${id}: NOT adopting the instance at ${svc.def.endpoint} (${who}): STALE — ${verdict.staleReason}. ` +
                "No mandu session uses this stack, so this dashboard replaces it with its own.",
            );
            try {
              await this.stopAdoptedDaemon(id, svc.identity!.pid);
              svc.adopted = false;
              svc.identity = null;
              svc.owner = null;
              svc.state = "stopped";
              svc.since = null;
            } catch (err) {
              this.opts.log(`${id}: could not replace the stale arbiter: ${(err as Error).message}`);
              // Refused before any signal (it stays, adopted and flagged), or
              // it went down and the endpoint is clear: then start our own.
              if (!(await checkReady(svc.def.ready))) {
                svc.adopted = false;
                svc.identity = null;
                svc.state = "stopped";
                svc.since = null;
              }
            }
          }
          if (svc.adopted) {
            this.opts.log(`${id}: adopted an already-running instance at ${svc.def.endpoint} (${who})`);
            if (foreign !== null) this.opts.log(`${id}: FOREIGN — ${foreign}; this dashboard shows that arbiter's sessions, not yours`);
            if (verdict.stale) {
              const why = !replacing ? ""
                : sessions === null ? " (not replaced: this dashboard cannot tell which mandu sessions use it)"
                  : sessions.length > 0 ? ` (not replaced: mandu session${sessions.length === 1 ? "" : "s"} pid ${sessions.join(", ")} use${sessions.length === 1 ? "s" : ""} it)`
                    : "";
              this.opts.log(`${id}: STALE — ${verdict.staleReason}; restart the arbiter to load current code${why}`);
            }
            return;
          }
          // fall through to the spawn below
        }
      } else {
        this.opts.log(`${id}: adopted an already-running instance at ${svc.def.endpoint}`);
        return;
      }
    }

    // Ordered constraint: a proxy needs the arbiter up first.
    const requires = svc.def.requires ?? [];
    for (const dep of requires) {
      if (this.services[dep].state !== "running") {
        if (this.opts.autoStartArbiter && dep === "arbiter") {
          this.opts.log(`${id}: arbiter not running — autostarting it first`);
          await this.start("arbiter");
        } else {
          throw new Error(
            `cannot start ${id}: required service ${dep} is not running ` +
              `(state=${this.services[dep].state}; enable autoStartArbiter or start it first)`,
          );
        }
      }
    }

    // The human plane (arbiter-human-plane.md): a service that requires the
    // arbiter gets the human socket of the instance answering NOW (it is per
    // instance, so it is read at spawn, never cached across arbiter restarts).
    const extraEnv = requires.includes("arbiter") ? await this.humanPlaneEnv(id) : {};
    const form = await this.spawnForm(id);
    try {
      await this.launch(id, extraEnv, form);
    } finally {
      svc.displacePid = null;
    }
    if (id === "arbiter") {
      // Record who we actually started (pid/rev/instance) for the status panel.
      svc.identity = await helloProbe(this.opts.arbiterSock);
    }
  }

  /** MANDU_ARBITER_HUMAN_SOCK for a service that requires the arbiter: the
   *  human socket the live instance names in `hello`. Blank when it names
   *  none — the service then runs without the human plane and keeps its own
   *  fail-closed rule (the net-proxy keeps egress symbolic); it is never
   *  pointed at the data socket instead. */
  private async humanPlaneEnv(id: ServiceId): Promise<NodeJS.ProcessEnv> {
    const identity = await helloProbe(this.opts.arbiterSock);
    const human = typeof identity?.humanSock === "string" && identity.humanSock !== "" ? identity.humanSock : null;
    if (human === null) {
      this.opts.log(`${id}: the arbiter names no human-plane socket — started without MANDU_ARBITER_HUMAN_SOCK (originals stay unavailable to it)`);
      // Blank, not absent: a stale value in this process's env must not be
      // inherited (every consumer reads "" as unset).
      return { MANDU_ARBITER_HUMAN_SOCK: "" };
    }
    return { MANDU_ARBITER_HUMAN_SOCK: human };
  }

  /** Why the arbiter answering at our socket is not OURS to adopt, or null:
   *  its event dir differs from the one this dashboard's own arbiter would use
   *  (the explicit eventDir option, else the path table's `events` under
   *  MANDU_HOME). An identity without an event dir (an old arbiter) is never
   *  called foreign — nothing to compare. */
  private foreignArbiterReason(identity: ArbiterIdentity | null): string | null {
    if (!identity || typeof identity.eventDir !== "string" || identity.eventDir === "") return null;
    const want = resolvePath(this.opts.eventDir ?? defaultEventDir(process.env));
    const got = resolvePath(identity.eventDir);
    if (want === got) return null;
    return `its event dir is ${got}, not ${want} (started under another MANDU_HOME, or another HOME, or with --event-dir)`;
  }

  /** Stop a service: SIGTERM → SIGKILL after stopGraceMs. Reaps the whole group.
   *
   *  REFUSES on an ADOPTED service (one that was already listening when we went
   *  to start it): it has no child pid here, so there is nothing for us to reap.
   *  Quietly marking it "stopped" — what this did before — was a LIE: the daemon
   *  kept serving while the panel showed it grey and "Stop all" reported success.
   *  That silent divergence IS the stale-daemon trap, so say so loudly instead
   *  and name the process the operator has to kill. shutdownAll() allSettles, so
   *  the dashboard's own exit/self-restart path is unaffected (adopted instances
   *  surviving it is by design). */
  async stop(id: ServiceId): Promise<void> {
    const svc = this.services[id];
    const child = svc.child;
    if (!child || svc.pid === null) {
      if (svc.adopted) throw new Error(this.adoptedRefusal(id));
      svc.state = "stopped";
      return;
    }
    svc.stopping = true;
    const pid = svc.pid;

    await new Promise<void>((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        clearTimeout(killTimer);
        resolve();
      };
      child.once("exit", done);
      // If the child already exited between the guard and here.
      if (child.exitCode !== null || child.signalCode !== null) {
        done();
        return;
      }
      signalGroup(pid, "SIGTERM");
      const killTimer = setTimeout(() => {
        signalGroup(pid, "SIGKILL");
        // Give the OS a tick to deliver; the exit handler resolves us. As a
        // backstop, resolve shortly after the hard kill regardless.
        setTimeout(done, 200);
      }, this.opts.stopGraceMs);
    });

    svc.child = null;
    dropAdminChannel(svc);
    svc.pid = null;
    svc.since = null;
    svc.state = "stopped";
    svc.stopping = false;
    svc.identity = null;
    svc.owner = null;
  }

  /** Stop then start a service (resolves when READY again). Rejects on an ADOPTED
   *  service, via stop(): a "restart" there would only re-adopt the very same
   *  daemon — the silent no-op that lets a stale arbiter outlive its own STALE
   *  banner. The refusal names the pid to kill. */
  async restart(id: ServiceId): Promise<void> {
    await this.stop(id);
    await this.start(id);
  }

  /**
   * REPLACE an ADOPTED daemon: the sanctioned takeover that stop()/restart()
   * refuse. Where the refusal used to dead-end in "kill <pid> yourself", this
   * does that kill — but only under the exact safety rules the by-hand
   * instruction assumed, and never silently:
   *
   *  1. Only with a VERIFIED target: the daemon's hello pid, and only after
   *     `/proc/<pid>/cmdline` confirms an arbiter-shaped process (the
   *     recycled-pid guard, mirroring launcher/src/reap.ts). A pre-hello
   *     daemon, an adopted proxy (no identity), or an unreadable /proc (a
   *     container's pid namespace, another user) all refuse loudly — the
   *     dashboard never signals a process it cannot positively identify.
   *  2. SEQUENTIAL same-DB handover (runtime-instances.md §9): SIGTERM (the
   *     daemon's graceful shutdown tidies its instance dir and releases the
   *     `<db>.owner` lock), SIGKILL after stopGraceMs, and the successor is
   *     not spawned until the old pid is GONE and the endpoint has cleared.
   *  3. Failure is surfaced, not smoothed over: if the old daemon survives or
   *     something else still holds the endpoint, this throws and the row keeps
   *     telling the truth (adopted, running).
   *
   * Replacing a healthy shared arbiter is a legitimate but wide call — it ties
   * the hub's lifetime to THIS dashboard — so the UI arms the button (two-click
   * confirm) rather than this method second-guessing the operator.
   */
  async replace(id: ServiceId): Promise<void> {
    const svc = this.services[id];
    try {
      await this.doReplace(id);
    } catch (err) {
      // Persist the refusal/failure on the row (status().lastError): the 3s
      // poll repaints the panel, and a message that only lived in one HTTP
      // response would vanish on the next tick.
      svc.lastError = (err as Error).message;
      throw err;
    }
  }

  private async doReplace(id: ServiceId): Promise<void> {
    const svc = this.services[id];
    if (!svc.adopted || svc.state !== "running") {
      throw new Error(`${id} is not an adopted running instance — use Start/Stop/Restart instead`);
    }
    // The target, by provenance strength: the daemon's own hello pid, else a
    // FRESH /proc socket-owner walk (never the cached one — a pid cached for
    // display could have been recycled since; re-verifying at kill time is the
    // same rule as the fresh cmdline read below).
    let pid = svc.identity?.pid;
    if (!pid && svc.def.ready.kind === "socket") {
      pid = this.opts.discoverSocketOwner(svc.def.ready.path)?.pid ?? undefined;
      if (pid) this.opts.log(`${id}: REPLACE — no hello identity; the OS names socket owner pid ${pid}`);
    }
    if (!pid) {
      throw new Error(
        `${id} was adopted without a verifiable identity (no hello answer, and the OS could not name ` +
          `the socket's owner — another user's process, or a container this dashboard cannot see). ` +
          `Stop whatever listens on ${svc.def.endpoint} yourself, then press Start.`,
      );
    }
    await this.stopAdoptedDaemon(id, pid);
    svc.adopted = false;
    svc.identity = null;
    svc.owner = null;
    svc.state = "stopped";
    svc.since = null;
    svc.lastError = null;
    this.opts.log(`${id}: REPLACE — old daemon gone; starting our own`);
    await this.start(id);
  }

  /**
   * Stop the daemon `pid` that answers at an adopted service's endpoint and
   * wait until its endpoint is clear (replace(), and the adopt-time
   * replacement of a stale arbiter). Signals only a pid whose command line
   * names an arbiter; SIGTERM, SIGKILL after stopGraceMs. Throws, naming why,
   * when it refuses or the daemon or its endpoint outlives that.
   */
  private async stopAdoptedDaemon(id: ServiceId, pid: number): Promise<void> {
    const svc = this.services[id];
    const cmd = this.opts.procCmdline(pid) ?? "";
    if (!/arbiter|server-main/.test(cmd)) {
      throw new Error(
        `refusing to replace ${id}: pid ${pid} is not verifiably an arbiter ` +
          (cmd
            ? `(cmdline: ${cmd.slice(0, 120)})`
            : `(its command line is unreadable — recycled pid, another user, or a container this dashboard cannot reach)`) +
          `. Stop it yourself, then press Start.`,
      );
    }
    this.opts.log(`${id}: REPLACE — SIGTERM adopted daemon pid ${pid} (SIGKILL after ${this.opts.stopGraceMs}ms)`);
    signalPidChecked(this.opts.killPid, pid, "SIGTERM");
    if (!(await waitPidGone(this.opts.killPid, pid, this.opts.stopGraceMs))) {
      this.opts.log(`${id}: REPLACE — pid ${pid} survived SIGTERM grace; SIGKILL`);
      signalPidChecked(this.opts.killPid, pid, "SIGKILL");
      if (!(await waitPidGone(this.opts.killPid, pid, 2_000))) {
        throw new Error(`replace ${id}: pid ${pid} survived SIGKILL — cannot take over from here.`);
      }
    }
    // The old owner is gone; require its endpoint to actually clear before we
    // spawn (a third process still listening would just be re-adopted).
    const deadline = Date.now() + 2_000;
    while (await checkReady(svc.def.ready)) {
      if (Date.now() > deadline) {
        throw new Error(
          `replace ${id}: pid ${pid} is gone but something still listens on ${svc.def.endpoint} — ` +
            `not spawning over it. Investigate, then press Start.`,
        );
      }
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  /**
   * Keep retrying the identity of an adopted, identity-less daemon — kicked
   * (fire-and-forget, throttled to ADOPTED_IDENT_REFRESH_MS) by every status()
   * poll. Two rungs, strongest provenance first:
   *   1. the hello handshake (arbiter only) — the adopt-time probe is one-shot
   *      and can lose a boot race; a daemon that answers late gets its
   *      identity (and thus its staleness verdict and Replace) back;
   *   2. the /proc socket-owner walk (unix-socket endpoints) — the OS's answer
   *      where the daemon gives none, enough for a verified Replace.
   * Purely poll-driven (no standing timer — nothing to leak in tests); every
   * assignment re-checks that the row is STILL adopted/running/identity-less,
   * so a stop/replace that raced the probe wins.
   */
  private maybeRefreshAdoptedIdentity(id: ServiceId): void {
    const svc = this.services[id];
    if (!svc.adopted || svc.state !== "running" || svc.identity) return;
    if (svc.identRefreshing || Date.now() - svc.identRefreshAt < ADOPTED_IDENT_REFRESH_MS) return;
    svc.identRefreshing = true;
    svc.identRefreshAt = Date.now();
    // Fire-and-forget, so it must never reject unhandled: Node 22 exits the
    // whole dashboard on an unhandled rejection (a probe that threw on darwin,
    // where there is no /proc, took the dashboard down on its next poll).
    void this.refreshAdoptedIdentity(id)
      .catch((err: unknown) => {
        this.opts.log(`${id}: adopted-identity re-probe failed: ${err instanceof Error ? err.message : String(err)}`);
      })
      .finally(() => {
        svc.identRefreshing = false;
      });
  }

  private async refreshAdoptedIdentity(id: ServiceId): Promise<void> {
    const svc = this.services[id];
    const live = (): boolean => svc.adopted && svc.state === "running" && !svc.identity;
    if (id === "arbiter") {
      const identity = await helloProbe(this.opts.arbiterSock);
      if (identity && live()) {
        svc.identity = identity;
        svc.owner = null; // the daemon's own claim supersedes the /proc answer
        this.opts.log(
          `${id}: adopted daemon answered hello on re-probe — pid ${identity.pid}, rev ${identity.gitRev}`,
        );
        return;
      }
    }
    if (!svc.owner && svc.def.ready.kind === "socket" && live()) {
      const owner = this.opts.discoverSocketOwner(svc.def.ready.path);
      if (owner && live()) {
        svc.owner = owner;
        this.opts.log(`${id}: no hello answer; the OS names socket owner pid ${owner.pid} (${owner.cmdline ?? "cmdline unreadable"})`);
      }
    }
  }

  /** The refusal text for a stop()/restart() of an ADOPTED service: what happened,
   *  why we won't, and which process the operator must kill to take ownership. */
  private adoptedRefusal(id: ServiceId): string {
    const svc = this.services[id];
    const who = svc.identity
      ? `daemon pid ${svc.identity.pid}`
      : `the process listening on ${svc.def.endpoint}`;
    return (
      `${id} was ADOPTED — it was already running when this dashboard started, so the dashboard ` +
      `does not own the process and will not kill it. Stop it yourself (${who}), then press Start ` +
      `to have the dashboard launch its own.`
    );
  }

  /** The resolved (production or overridden) definition of a service — read-only
   *  introspection for tests and the control panel. */
  definition(id: ServiceId): ServiceDefinition {
    return this.services[id].def;
  }

  /** Synchronous snapshot of all services. Doubles as the retry heartbeat for
   *  adopted identity-less daemons: each snapshot kicks a throttled background
   *  re-probe (hello, then /proc socket-owner), so the panel's 3s poll is what
   *  eventually upgrades "no verified identity" into a Replace-able row. */
  status(): ServiceStatus[] {
    return SERVICE_IDS.map((id) => {
      const svc = this.services[id];
      this.maybeRefreshAdoptedIdentity(id);
      const base: ServiceStatus = {
        id,
        label: svc.def.label,
        state: svc.state,
        pid: svc.pid,
        since: svc.since,
        lastError: svc.lastError,
        endpoint:
          svc.state === "running" && svc.boundPort !== null && svc.def.ready.kind === "port-file"
            ? `${svc.def.ready.host}:${svc.boundPort}`
            : svc.def.endpoint,
        adopted: svc.adopted,
      };
      if (id === "arbiter") {
        base.identity = svc.identity;
        const verdict = this.staleness(svc.identity);
        base.stale = verdict.stale;
        base.staleReason = verdict.staleReason;
      }
      // The /proc-discovered owner, only while the daemon itself stays silent
      // (identity known → the daemon's own claim is the single source shown).
      if (!svc.identity && svc.owner) {
        base.ownerPid = svc.owner.pid;
        base.ownerCmdline = svc.owner.cmdline;
      }
      return base;
    });
  }

  /** Ring snapshot for a service. */
  logs(id: ServiceId): LogLine[] {
    return this.services[id].ring.slice();
  }

  /** Path of the durable per-module log file for a service (`<logDir>/<id>.log`).
   *  The file persists on disk for the lifetime of the dashboard process; the
   *  COMPLETE module log is read from here (the ring is just the live tail). */
  logFilePath(id: ServiceId): string {
    return join(this.logDir, `${id}.log`);
  }

  /** Resolves once every line the ring holds now is in the durable log file
   *  (the file is written asynchronously, after the ring), or after
   *  `timeoutMs` on a disk that does not answer; never rejects. The "full
   *  log" reads the file after it, so it holds every line the live view
   *  already showed (dashboard.md §4.8). */
  logFileWritten(id: ServiceId, timeoutMs = 2000): Promise<void> {
    return logFileWritten(this.services[id], timeoutMs);
  }

  /** Subscribe to live log lines for a service. Returns an unsubscribe fn. */
  subscribeLogs(id: ServiceId, cb: (l: LogLine) => void): () => void {
    const subs = this.services[id].subscribers;
    subs.add(cb);
    return () => {
      subs.delete(cb);
    };
  }

  /**
   * Bring up the whole stack in dependency order: the arbiter FIRST (awaited
   * ready), then the proxies. start() is idempotent and auto-starts the arbiter
   * for a requiring service, so starting the arbiter explicitly first is safe and
   * keeps the ordering deterministic (the proxies then reuse the running arbiter).
   * Returns the post-start status snapshot. A proxy that fails to start leaves
   * its own status `crashed` (with lastError) but does not abort the others, so
   * the caller can surface per-service results from the returned snapshot.
   */
  async startAll(): Promise<ServiceStatus[]> {
    await this.start("arbiter");
    const proxies: ServiceId[] = SERVICE_IDS.filter((id) => id !== "arbiter");
    await Promise.allSettled(proxies.map((id) => this.start(id)));
    return this.status();
  }

  /** Stop the whole stack (best-effort, never throws). Returns the snapshot. */
  async stopAll(): Promise<ServiceStatus[]> {
    await this.shutdownAll();
    return this.status();
  }

  /** Stop everything (dashboard exit). Best-effort; never throws. */
  async shutdownAll(): Promise<void> {
    await Promise.allSettled(SERVICE_IDS.map((id) => this.stop(id)));
  }

  // ── launch / readiness ──────────────────────────────────────────────────────

  /**
   * What this spawn runs (packaging.md §5.1). A checkout's definition is the
   * SOURCE form and carries the bundled form (`checkoutBundle`); the bundle
   * runs only when its build record, read NOW, says it matches the source.
   * The dashboard is resident, so a bundle fresh at its start may be stale at
   * a later restart: a stale bundle is never started, the source runs and the
   * log says why. An installed or a test definition has no bundled form.
   */
  private async spawnForm(id: ServiceId): Promise<ServiceDefinition> {
    const def = this.services[id].def;
    const b = def.checkoutBundle;
    if (!b) return def;
    const verdict = await this.opts.bundleFresh(b.distDir, b.repoRoot);
    if (verdict.fresh) {
      this.opts.log(`${id}: starting from the checkout's bundle (${b.distDir})`);
      return { ...def, command: b.command, args: b.args, cwd: b.cwd, env: { ...def.env, ...b.env } };
    }
    this.opts.log(`${id}: starting from source (the bundle in ${b.distDir} is not used: ${verdict.reason})`);
    return def;
  }

  private launch(id: ServiceId, extraEnv: NodeJS.ProcessEnv = {}, def: ServiceDefinition = this.services[id].def): Promise<void> {
    const svc = this.services[id];

    svc.state = "starting";
    svc.lastError = null;
    svc.stopping = false;
    svc.adopted = false; // we are spawning our own child, not adopting
    svc.owner = null;
    svc.carry = { stdout: "", stderr: "" };

    // Axis plumbing (dashboard.md §4.19, the "posture nobody runs" guard): the
    // ARBITER spawn resolves config.toml's `mode` + integrity/confidentiality
    // keys (and an exported MANDU_MODE, protection-modes.md) into
    // MANDU_INTEGRITY/MANDU_CONFIDENTIALITY, launcher-precedence (explicit
    // process env wins — the fill only ever contains keys process.env lacks).
    // Computed HERE, at spawn time, not at construction: a Protection-drawer
    // config edit must land on the very next restart. Best-effort like the
    // config file itself — a reader failure fills nothing (arbiter defaults).
    let axisFill: Record<string, string> = {};
    if (id === "arbiter") {
      try {
        axisFill = this.opts.axisEnv(process.env);
      } catch (err) {
        this.opts.log(`arbiter: axis config read failed (arbiter defaults rule): ${(err as Error).message}`);
      }
    }

    // Admin channel (ServiceDefinition.adminChannel): a 4th stdio entry makes
    // libuv create a socketpair; the child sees its end as fd 3 and is told so
    // via MANDU_ADMIN_FD. We keep the parent end on the runtime record.
    const adminEnv: NodeJS.ProcessEnv = def.adminChannel ? { MANDU_ADMIN_FD: "3" } : {};
    // Port-file readiness (ServiceDefinition.ready): the child binds port 0 and
    // writes the port it got to MANDU_PORT_FILE. A file left by an earlier
    // instance must not read as this one being ready, so it goes first.
    svc.boundPort = null;
    const portEnv: NodeJS.ProcessEnv = {};
    if (def.ready.kind === "port-file") {
      try { rmSync(def.ready.path, { force: true }); } catch { /* unreadable dir: the probe times out */ }
      try { mkdirSync(dirname(def.ready.path), { recursive: true }); } catch { /* exists */ }
      portEnv["MANDU_PORT_FILE"] = def.ready.path;
    }
    const child = spawn(def.command, def.args, {
      cwd: def.cwd,
      // New process group so we can SIGTERM/SIGKILL everything the service
      // started via process.kill(-pid) (every production form is one node
      // process, but a test's definition may be a wrapper, and a service may
      // start helpers).
      detached: true,
      stdio: def.adminChannel ? ["ignore", "pipe", "pipe", "pipe"] : ["ignore", "pipe", "pipe"],
      env: { ...process.env, ...axisFill, ...def.env, ...extraEnv, ...adminEnv, ...portEnv },
    });

    svc.child = child;
    svc.pid = child.pid ?? null;
    svc.since = Date.now();
    dropAdminChannel(svc);
    if (def.adminChannel) {
      const adminSock = (child.stdio[3] ?? null) as Socket | null;
      if (adminSock) {
        // A dead child closes its end; the error is expected noise, never fatal.
        adminSock.on("error", () => { /* teardown runs on exit */ });
        svc.adminSocket = adminSock;
      } else {
        this.opts.log(`${id}: admin channel requested but the spawn yielded no fd 3 — human-decision ops stay unavailable`);
      }
    }

    openLogFile(svc, id, this.logDir, this.logFilePath(id), this.truncatedLogs);
    // Close the durable stream when the child exits (stop or crash). The file
    // persists on disk for reading; only the writable handle is released.
    child.once("exit", () => endLogFile(svc));

    wireLogs(svc, child, this.logRingMax);

    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const finish = (err?: Error) => {
        if (settled) return;
        settled = true;
        clearInterval(probeTimer);
        clearTimeout(deadline);
        child.off("exit", onEarlyExit);
        child.off("error", onError);
        if (err) reject(err);
        else resolve();
      };

      // Spawn error (e.g. ENOENT on the command).
      const onError = (err: Error) => {
        svc.state = "crashed";
        svc.lastError = `spawn failed: ${err.message}`;
        svc.child = null;
        dropAdminChannel(svc);
        svc.pid = null;
        finish(new Error(`${id}: ${svc.lastError}`));
      };

      // Child exited before becoming READY → crashed.
      const onEarlyExit = (code: number | null, signal: NodeJS.Signals | null) => {
        const tail = tailStderr(svc);
        svc.state = "crashed";
        svc.lastError =
          `exited before ready (${code !== null ? `code ${code}` : `signal ${signal}`})` +
          (tail ? `\n${tail}` : "");
        svc.child = null;
        dropAdminChannel(svc);
        svc.pid = null;
        svc.since = null;
        finish(new Error(`${id}: ${svc.lastError}`));
      };

      child.once("error", onError);
      child.once("exit", onEarlyExit);

      const markReady = () => {
        if (settled) return;
        // Swap the early-exit guard for the steady-state crash watcher.
        child.off("exit", onEarlyExit);
        svc.state = "running";
        svc.lastError = null;
        if (def.ready.kind === "port-file") svc.boundPort = readPortFile(def.ready.path);
        this.watchForCrash(id, child);
        finish();
      };

      const probe = () => {
        if (settled) return;
        checkReady(def.ready)
          .then(async (ok) => {
            // Displacing a foreign arbiter: `current` answers from the start,
            // so ready means it answers as SOMEONE ELSE now (our promotion).
            if (ok && svc.displacePid !== null) {
              const who = await helloProbe(this.opts.arbiterSock);
              ok = who !== null && who.pid !== svc.displacePid;
            }
            if (ok) markReady();
          })
          .catch(() => {
            /* probe error → keep retrying until the deadline */
          });
      };

      const probeTimer = setInterval(probe, READY_PROBE_INTERVAL_MS);
      const deadline = setTimeout(() => {
        if (settled) return;
        svc.state = "crashed";
        svc.lastError = `readiness timeout after ${this.opts.startTimeoutMs}ms (endpoint ${def.endpoint})`;
        // Reap the child we could not bring up so it isn't left running.
        const pid = svc.pid;
        child.off("exit", onEarlyExit);
        if (pid !== null) {
          svc.stopping = true;
          signalGroup(pid, "SIGKILL");
        }
        svc.child = null;
        svc.pid = null;
        svc.since = null;
        finish(new Error(`${id}: ${svc.lastError}`));
      }, this.opts.startTimeoutMs);

      // Probe immediately too (don't wait a full interval).
      probe();
    });
  }

  /** Watch a running child for an *unexpected* exit (→ crashed). */
  private watchForCrash(id: ServiceId, child: ChildProcess): void {
    child.once("exit", (code, signal) => {
      const svc = this.services[id];
      // Only react if this is still the live child for this service.
      if (svc.child !== child) return;
      if (svc.stopping) {
        // Expected stop — stop() handles state transition.
        return;
      }
      const tail = tailStderr(svc);
      svc.state = "crashed";
      svc.lastError =
        `crashed while running (${code !== null ? `code ${code}` : `signal ${signal}`})` +
        (tail ? `\n${tail}` : "");
      svc.child = null;
      dropAdminChannel(svc);
      svc.pid = null;
      svc.since = null;
      try { this.opts.onCrash(id, svc.lastError); } catch { /* a listener's failure is not the supervisor's */ }
    });
  }

  /** Scope-honest staleness of the listening arbiter (supervisor-defs
   *  arbiterStaleness) with this supervisor's repo root + git seams applied.
   *  HEAD is re-read per call, not boot-captured: an arbiter commit landing
   *  while the dashboard runs must flag without a dashboard restart — the same
   *  live recomputation as DashboardSelf.status(). The release and build it
   *  reports come first (runtime-instances.md §4.1): another release, or
   *  another bundle of this one, is stale wherever there is a checkout or not. */
  private staleness(identity: ArbiterIdentity | null): StalenessVerdict {
    const release = identity ? arbiterReleaseStaleness(identity, this.opts.ownArbiterBuild()) : null;
    if (release !== null) return release;
    return arbiterStaleness(identity, this.opts.repoRoot, this.opts.gitRev, this.opts.gitChangedInRange);
  }
}
