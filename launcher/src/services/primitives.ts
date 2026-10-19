/**
 * services/primitives — injectable low-level service ops (probe / wait / spawn).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh: wait_for_port (L712-722), the
 *   setsid-detached autostart with a pidfile (L731-762), and the MITM CA-cert
 *   wait (L814-844). Bundled as the injectable `ServiceDeps` so the service
 *   modules unit-test without binding real ports or spawning real npm — the
 *   Part-1 ensureArbiter({start,waitForSocket}) pattern, generalized.
 */
import { connect } from "node:net";
import { request as httpRequest } from "node:http";
import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { openSafeLog } from "../safe-log.js";
import { spawn, spawnSync } from "node:child_process";
import { availableParallelism, loadavg } from "node:os";

export interface WaitOpts {
  tries: number;
  delayMs: number;
  /** Checked after each failed probe: true ends the wait at once, unready
   *  (the started child already exited, so no amount of waiting helps). */
  giveUp?: () => boolean;
}

/** The readiness deadline of a resident proxy the launcher starts, on an idle
 *  host (services/context-proxy.ts, services/net-proxy.ts). Was a fixed
 *  100 probes 100 ms apart (about 10 s), which a saturated host missed
 *  (docs/design/architecture/runtime-instances.md §14.6). */
export const SERVICE_READY_BASE_MS = 30_000;
/** The load-scaled deadline never exceeds this. */
export const SERVICE_READY_MAX_MS = 120_000;
/** Env override of the readiness deadline, in milliseconds. */
export const SERVICE_READY_ENV = "MANDU_SERVICE_READY_TIMEOUT_MS";

/**
 * How long to wait for a started proxy to become ready before failing the
 * launch closed. Load-aware: the base deadline is stretched by the 1-minute
 * load average per usable CPU when that exceeds 1 (a host at twice its CPU
 * count gets twice the time), capped at SERVICE_READY_MAX_MS. A positive
 * integer in MANDU_SERVICE_READY_TIMEOUT_MS replaces the computation (no cap:
 * the operator asked). A garbled override is ignored. Expiry stays fail-closed
 * in every case: the deadline decides how long, never whether.
 * Pure over its inputs.
 */
export function serviceReadyDeadlineMs(
  env: Record<string, string | undefined> = process.env,
  host: { load1: number; ncpu: number } = { load1: loadavg()[0] ?? 0, ncpu: availableParallelism() },
): number {
  const raw = env[SERVICE_READY_ENV]?.trim();
  if (raw && /^\d+$/.test(raw) && Number(raw) > 0) return Number(raw);
  const ratio = host.ncpu > 0 && Number.isFinite(host.load1) ? host.load1 / host.ncpu : 1;
  const scaled = SERVICE_READY_BASE_MS * Math.max(1, ratio);
  return Math.round(Math.min(SERVICE_READY_MAX_MS, scaled));
}

/** A started service's process: `exited()` is its exit status once it has
 *  exited (code or signal), null while it runs. */
export interface DetachedHandle {
  /** The service's pid, which is also its process group id (it leads a
   *  group of its own: spawned detached). */
  pid: number | undefined;
  /** SIGTERM the whole process group, and sever the lifeline. */
  stop: () => void;
  /** SIGTERM the service process ONLY (its group is left alone), and sever
   *  the lifeline: a service that drains on SIGTERM lets the children it is
   *  running finish. The fs-sync watcher's teardown uses it, because a git it
   *  runs that is SIGTERMed can leave the worktree's index.lock behind
   *  (fs-sync.md §2.4a). Optional: test doubles may omit it. */
  stopLeader?: () => void;
  exited?: () => { code: number | null; signal: NodeJS.Signals | null } | null;
}

/** One readiness deadline shared by a service's successive waits (its port
 *  file, then its listen). */
export interface ReadinessBudget {
  /** The time left, as waitFor probes `delayMs` apart (at least one), ending
   *  early once the started process has exited. */
  opts(delayMs: number): WaitOpts;
  /** Why the wait ended unready, for the fail-closed error. */
  note(): string;
}

export function readinessBudget(
  handle: Pick<DetachedHandle, "exited">,
  deadlineMs: number = serviceReadyDeadlineMs(),
  now: () => number = Date.now,
): ReadinessBudget {
  const startedAt = now();
  return {
    opts: (delayMs) => ({
      tries: Math.max(1, Math.ceil(Math.max(0, deadlineMs - (now() - startedAt)) / delayMs)),
      delayMs,
      giveUp: () => Boolean(handle.exited?.()),
    }),
    note: () => {
      const e = handle.exited?.();
      if (e) return e.signal ? `it was killed by ${e.signal} before becoming ready` : `it exited with code ${e.code} before becoming ready`;
      const within = deadlineMs < 10_000 ? `${deadlineMs} ms` : `${Math.round(deadlineMs / 1000)} s`;
      return `not ready within ${within}; ${SERVICE_READY_ENV} (milliseconds) sets a longer deadline`;
    },
  };
}

/** The identity a context proxy publishes at GET /_mandu/identity (mirrors
 *  interceptors/{anthropic,openai}-proxy `ProxyIdentity`, plus the `mandu`
 *  discriminator). `null` = nothing usable answered. */
export interface ProxyIdentity {
  mandu: boolean;
  service?: string;
  sessionKey?: string;
  arbiterSock?: string;
  viewMap?: Array<{ human: string; agent: string }>;
  /** The agent start directory relative paths resolve against (anthropic-proxy
   *  MANDU_AGENT_CWD); absent = none. */
  agentCwd?: string;
  /** The net-proxy's upload-host deny list (MANDU_NET_PROXY_DENY_HOSTS);
   *  absent = none. */
  denyHosts?: string[];
  /** The model hosts the net-proxy judges by path (the model-host deny,
   *  MANDU_NET_PROXY_MODEL_HOST_DENY); absent = the deny is off. */
  modelHostDeny?: string[];
  /** The logins the net-proxy's session leaves raw
   *  (MANDU_NET_PROXY_SESSION_LOGINS); absent = none (an older proxy). */
  sessionLogins?: unknown;
}

/** A short human description of an occupying process for the fail-closed
 *  conflict errors (the context-proxy + net-proxy start-or-reuse checks). */
export function describeOccupant(id: ProxyIdentity | null): string {
  if (!id) return "a non-Mandu server (no /_mandu/identity)";
  if (id.mandu !== true) return "a non-Mandu server";
  const sock = id.arbiterSock ? ` arbiter=${id.arbiterSock}` : "";
  return `another Mandu ${id.service ?? "proxy"} (${id.sessionKey ? `session=${id.sessionKey},` : ""}${sock})`;
}

/**
 * GET http://host:port/_mandu/identity and parse the JSON identity document,
 * or null on ANY failure (not listening, not a Mandu proxy, non-JSON, slow).
 * Used by the context-proxy and net-proxy start-or-reuse safety checks to
 * verify a listening proxy is THIS session's before adopting it.
 */
export function probeIdentity(host: string, port: number, timeoutMs = 1500): Promise<ProxyIdentity | null> {
  return new Promise((resolve) => {
    const req = httpRequest(
      { host, port, method: "GET", path: "/_mandu/identity", timeout: timeoutMs },
      (res) => {
        let buf = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (buf += c));
        res.on("end", () => {
          try {
            const obj = JSON.parse(buf) as ProxyIdentity;
            resolve(obj && typeof obj === "object" ? obj : null);
          } catch {
            resolve(null);
          }
        });
      },
    );
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.on("error", () => resolve(null));
    req.end();
  });
}

/** Is something accepting TCP connections at host:port right now? */
export function probePort(host: string, port: number, timeoutMs = 500): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host, port });
    const done = (ok: boolean) => { sock.destroy(); resolve(ok); };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

/** Poll `check` up to `tries` times; resolve true on first pass, false on exhaustion. */
export async function waitFor(check: () => boolean | Promise<boolean>, o: WaitOpts): Promise<boolean> {
  for (let i = 0; i < o.tries; i++) {
    if (await check()) return true;
    if (o.giveUp?.()) return false;
    await new Promise((r) => setTimeout(r, o.delayMs));
  }
  return false;
}

/** Wait until `path` exists and is non-empty (the async-minted MITM CA cert). */
export function waitForFile(path: string, o: WaitOpts): Promise<boolean> {
  return waitFor(() => existsSync(path) && statSync(path).size > 0, o);
}

/**
 * Open a daemon's log for append, never through something planted at its
 * name or on its way (runtime-instances.md §2, "planted paths"). The logs
 * live in the runtime dir (`<base>/dashboard.log`, `<base>/logs/`, a scope
 * dir), which the agent may write, and the process that opens them runs
 * outside any confinement: a plain `openSync(p, "a")` follows a link there
 * and appends (daemon output the agent can steer) to whatever file it
 * names, a shell startup file included. `safe-log.ts` `openSafeLog` checks
 * every component (2026-10-17; before, the last one only, so a `logs/`
 * that was a link to a folder got the log made there), makes a missing
 * directory one at a time (0700), and opens the file O_NOFOLLOW|O_NONBLOCK
 * in its directory's descriptor: a link, a FIFO, a hard link to someone's
 * file at the name, or a link of this user's on the way, is refused.
 * `root`: the runtime base, when the caller knows it (its directories must
 * be this user's). Returns the fd (O_WRONLY|O_APPEND|O_CREAT, mode 0666
 * before the umask, as `"a"` was); throws a plain message otherwise.
 */
export function openAppendLog(logPath: string, root?: string): number {
  return openSafeLog(resolve(logPath), root === undefined ? {} : { root: resolve(root) });
}

/**
 * Spawn a long-running service command, detached, logging to a file: every
 * managed service (a daemon from the layout resolver, the fs-sync eager
 * watcher) is one node process, a bundle or a `node --import tsx` entry.
 * stop() SIGTERMs the process group so anything it spawned dies too.
 *
 * LIFELINE (runtime-instances.md §8): stdin is a pipe whose ONLY write end this
 * process holds and never writes. The kernel closes it when this process dies —
 * however it dies (SIGKILL, OOM, a wedged-then-killed test runner) — and the
 * service exits on the EOF (armLifeline in each service entry, keyed on the
 * MANDU_LIFELINE=stdin env set here). stop() stays the graceful path; the
 * lifeline is the kernel-guaranteed backstop that retires the orphaned-daemon
 * class where a detached group's only teardown was an in-memory closure in a
 * parent that died ungracefully.
 */
export function startDetachedCmd(
  cmd: string,
  args: string[],
  opts: { cwd: string; env: Record<string, string | undefined> },
  logPath: string,
): DetachedHandle {
  // The log's dir is made by the open if missing (one component at a time,
  // never through a link): the scope run dir may not exist when the arbiter
  // was attached rather than autostarted (it is otherwise created as a side
  // effect of startArbiter), and a `--net-proxy` launch against a running
  // arbiter crashed on the ENOENT.
  const out = openAppendLog(logPath);
  const child = spawn(cmd, args, {
    cwd: opts.cwd,
    env: { ...opts.env, MANDU_LIFELINE: "stdin" },
    detached: true,
    stdio: ["pipe", out, out],
  });
  // The exit status, for a readiness wait that should stop waiting on a
  // process that is already gone (a spawn error counts as an exit).
  let exitState: { code: number | null; signal: NodeJS.Signals | null } | null = null;
  child.on("exit", (code, signal) => { exitState = { code, signal }; });
  child.on("error", () => { exitState ??= { code: null, signal: null }; /* the caller's readiness wait refuses/warns */ });
  // Hold the lifeline's write end for our lifetime, but let neither it nor the
  // child handle keep the launcher's event loop alive (the pipe is a net.Socket
  // under the Writable type, hence the cast for unref).
  (child.stdin as unknown as { unref?: () => void } | null)?.unref?.();
  child.unref();
  const pgid = child.pid;
  return {
    pid: pgid,
    exited: () => exitState,
    stop: () => {
      if (pgid !== undefined) { try { process.kill(-pgid, "SIGTERM"); } catch { try { child.kill("SIGTERM"); } catch { /* gone */ } } }
      // Sever the lifeline too: a service that ignores/mishandles SIGTERM (the
      // tsx wrapper's 143 quirk) still sees stdin EOF and exits.
      try { child.stdin?.destroy(); } catch { /* already closed */ }
    },
    stopLeader: () => {
      if (pgid !== undefined) { try { process.kill(pgid, "SIGTERM"); } catch { /* gone */ } }
      try { child.stdin?.destroy(); } catch { /* already closed */ }
    },
  };
}

/**
 * Run a one-shot command to completion, capturing output (git probe,
 * fs-sync-cli init/sync).
 *
 * `ownSession` runs it in a session (and process group) of its own, away from
 * the terminal's foreground group, so a ^C or ^\ typed at the terminal never
 * reaches it: the post-exit fs-view sweep uses it (teardown-signals.ts).
 * Dispositions cannot do this: libuv resets every signal to its default in the
 * child before exec, so an ignored SIGINT in the launcher is not inherited.
 */
export function runOnce(
  cmd: string,
  args: string[],
  opts: { cwd: string; env: Record<string, string | undefined>; timeoutMs?: number; ownSession?: boolean },
): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd, env: opts.env, encoding: "utf8", timeout: opts.timeoutMs,
    ...(opts.ownSession ? { detached: true } : {}),
  });
  // A spawn-layer failure (missing binary, signal, timeout, ENOBUFS) yields
  // status:null with EMPTY streams — surface the reason so callers' fail-closed
  // errors carry an actionable message instead of a blank one.
  const spawnErr = r.error ? String(r.error.message ?? r.error) : r.signal ? `killed by ${r.signal}` : "";
  const stderr = r.stderr ?? "";
  return { status: r.status, stdout: r.stdout ?? "", stderr: stderr || spawnErr };
}

/** The default, real dependency bundle. Tests pass a partial override. */
export interface ServiceDeps {
  probePort: typeof probePort;
  probeIdentity: typeof probeIdentity;
  waitFor: typeof waitFor;
  waitForFile: typeof waitForFile;
  startDetachedCmd: typeof startDetachedCmd;
  runOnce: typeof runOnce;
  /** Test seams for the context proxy's MANDU_SECRET_POSTURE prediction
   *  (proxy-secret-posture.ts); absent = process.platform and a PATH lookup. */
  platform?: NodeJS.Platform;
  commandExists?: (cmd: string) => boolean;
  /** Test seam for the net-proxy's session logins (agent-login.ts
   *  `sessionLogins`): the launch's HOME; absent = os.homedir(). */
  home?: string;
}

export const realDeps: ServiceDeps = { probePort, probeIdentity, waitFor, waitForFile, startDetachedCmd, runOnce };
