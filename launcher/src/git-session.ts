/**
 * git-session — one git sandbox for many git calls (confidentiality.md §7.2a
 * "Cost on a relaunch"; write-protection.md §8.5.3).
 *
 * The launcher runs every git call of its launch prep (the history-masking
 * step, git-object-twins.ts; its prefetch, twin-prefetch.ts; the placeholder
 * watch beside it) in the git sandbox (hardened-git.ts `gitCommand`): no
 * network, a read-only filesystem, no capability, its own user, pid, ipc and
 * uts namespaces, a new session. One bubblewrap per call cost about 17 ms of
 * namespace set-up, and the kernel serializes it: eight calls at once took
 * 70 ms a batch sandboxed against 12 ms plain, so a launch's ~30-70 calls
 * spent most of the step making namespaces.
 *
 * A SESSION makes the sandbox ONCE: the same bubblewrap, with the same flags
 * the probe chose, runs a small request runner (GIT_SESSION_RUNNER_SOURCE,
 * node, started with an empty environment) that starts each git call INSIDE
 * that sandbox, as many at once as the callers ask. What a call runs is what
 * the per-call runner ran: `git` from the call's PATH, the same hardened
 * arguments (hardenedGitArgs, literal pathspecs, unquoted paths) and the same
 * scrubbed environment (hardenedGitEnv, passed per call, exactly), the same
 * cwd and stdin; the runner starts nothing but `git` (the name is fixed in
 * its source, never taken from a request), argv is passed as an array (no
 * shell), and its output comes back as raw bytes (the caller decodes it as
 * the per-call runner did, so the answers are byte-identical).
 *
 * Every rule of `runChild` (child-run.ts, write-protection.md §8.5.1) holds
 * per call: the call's git is a process group of its own (inside the
 * sandbox) and its deadline SIGKILLs the whole group; a killed call, one
 * whose output passed the cap (GIT_RUNNER_MAX_STDOUT characters, never a
 * truncated answer), and one that could not start are failures (code 1);
 * an exit by a signal is 128 + the signal, as bubblewrap reports it; when a
 * git call exits, whatever it left in its group is killed (bubblewrap tore
 * the call's whole sandbox down). FAIL CLOSED beyond that:
 *
 *   - the runner ends (a crash, a kill, a protocol error, the sandbox gone):
 *     every call in flight fails (code 1, "the git sandbox ended: …"), so
 *     the step refuses the launch as for any failed git call, and the
 *     session's later calls run one sandbox each (the per-call runner);
 *   - a call that does not settle within its kill grace after its kill (the
 *     runner did not answer, or a process outside the call's group holds its
 *     output), or whose output a process it started keeps open past the
 *     close grace, fails, and the WHOLE sandbox is torn down with it: no
 *     straggler outlives its call, as none outlived a per-call sandbox;
 *   - a runner that ends before it said it is ready ran no call: those calls,
 *     and every later one, run per call (a host where node cannot start in
 *     the sandbox loses the speed, never a call);
 *   - `close()` (the owner, at the end of the step, on every path) kills the
 *     sandbox's process group (bubblewrap, its `--die-with-parent` child and
 *     with it the whole pid namespace) and fails whatever is still in
 *     flight; later calls fail. While idle the session holds no reference on
 *     the event loop, so a forgotten session never keeps the launcher alive,
 *     and a process `exit` kills it.
 *
 * Not in a session (per call, as before): a call that writes (`writable`,
 * the pack build: its bind is per call), no sandbox at all (none can be made
 * here, MANDU_GIT_SANDBOX=0: plain hardened git), and macOS, whose Seatbelt
 * profile lets git start nothing (no fork), so no runner can start git.
 *
 * KEEPING THE CALLS APART. The calls of one session share a pid namespace,
 * which one sandbox per call did not: a program started in one call despite
 * the hardening (write-protection.md §8.3, no vector known) must not reach
 * another call, on another repository, and make it mask less. So:
 *
 *   - the session sandbox has an EMPTY read-only /proc (SESSION_PROC_FLAGS,
 *     in place of `--proc /proc`): no `/proc/<pid>/fd`, `environ`, `mem`, no
 *     pid to find. A git call gets only its own stdin, stdout and stderr
 *     (node opens every other descriptor close-on-exec);
 *   - a session is used only where the host's Yama ptrace scope is >= 1
 *     (sessionAllowed): ptrace, `pidfd_getfd` and `process_vm_writev` of a
 *     non-descendant (a sibling call, the runner) are refused. Scope 0,
 *     absent or unreadable: one sandbox per call, as before.
 *
 * What is left is kill(): a program may still signal a sibling call by a
 * guessed pid. That call fails, and the step refuses the launch (fail
 * closed). The sandbox's guarantees to the host (no write, no network, no
 * capability, no host process) are unchanged.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { constants as osConstants } from "node:os";
import { resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";
import { CHILD_CLOSE_GRACE_MS, CHILD_KILL_GRACE_MS, runChild, type RunningChild } from "./child-run.js";
import type { GitRun, GitRunner } from "./git-object-twins.js";
import { gitCommand, hardenedGitArgs, hardenedGitEnv, isSeatbeltGitSandbox, type BwrapGitSandbox, type GitSandbox } from "./hardened-git.js";
import { launchGitSandbox } from "./probe-cache.js";

/** Collected stdout over this many characters fails a call of the
 *  production runner (never a silently truncated answer). */
export const GIT_RUNNER_MAX_STDOUT = 512 * 1024 * 1024;
/** stderr kept per call (the callers quote its last line). */
export const GIT_RUNNER_MAX_STDERR = 64 * 1024;
/** A call's deadline when the caller names none. */
export const GIT_RUNNER_DEFAULT_TIMEOUT_MS = 120_000;

type RunOpts = Parameters<GitRunner>[1];

/** The arguments a production call runs git with. Pure. */
export function productionGitArgs(args: readonly string[]): string[] {
  return hardenedGitArgs(["-c", "core.quotepath=off", ...args], { literalPathspecs: true });
}

/** The environment a production call runs git with. */
export function productionGitEnv(extra: Readonly<Record<string, string>> | undefined): Record<string, string> {
  return hardenedGitEnv(process.env, { GIT_OPTIONAL_LOCKS: "0", LC_ALL: "C", ...(extra ?? {}) });
}

/** The production runners (per call or a session's): the same git in the
 *  same sandbox, so they share the sandbox probe's `git --version`. */
const PRODUCTION = new WeakSet<GitRunner>();
export function isProductionGitRunner(r: GitRunner): boolean {
  return PRODUCTION.has(r);
}

/**
 * The per-call runner: `git` HARDENED (hardened-git.ts, write-protection.md
 * §8), in a sandbox of its own (`gitCommand`: bubblewrap on Linux, Seatbelt
 * on macOS, none where neither can be made), run by `runChild` (each call a
 * process group of its own, its deadline killing the whole group).
 * `children` tracks the calls while they run (an owner's `close` kills them).
 */
export function perCallGitRunner(children?: Set<RunningChild>, sandbox: () => GitSandbox | null = launchGitSandbox): GitRunner {
  const run: GitRunner = async (args, opts) => {
    const cmd = gitCommand(productionGitArgs(args), sandbox(), opts.writable ?? []);
    const r = await runChild(cmd.file, cmd.args, {
      cwd: opts.cwd,
      env: productionGitEnv(opts.env),
      ...(opts.input !== undefined ? { input: opts.input } : {}),
      timeoutMs: opts.timeoutMs ?? GIT_RUNNER_DEFAULT_TIMEOUT_MS,
      maxStdout: GIT_RUNNER_MAX_STDOUT,
      maxStderr: GIT_RUNNER_MAX_STDERR,
    }, children);
    return { code: r.code, stdout: r.stdout, stderr: r.stderr };
  };
  PRODUCTION.add(run);
  return run;
}

// ── The runner inside the sandbox ───────────────────────────────────────────

/** Frame types the runner writes: `[type u8][id u32 BE][len u32 BE][payload]`. */
export const FRAME = { stdout: 1, stderr: 2, exit: 3, close: 4, error: 5, ready: 6 } as const;
const HEADER = 9;
/** A frame larger than this is a protocol error (the runner sends chunks of
 *  a pipe read, at most 64 KiB, and small JSON). */
const MAX_FRAME = 16 * 1024 * 1024;

/**
 * The request runner, run as `node -e <this>` inside the sandbox with an
 * empty environment. Requests on stdin, one JSON object a line:
 * `{"op":"run","id","args","cwd","env","input","errBytes"}` starts `git
 * <args>` (a process group of its own) with exactly that cwd and environment,
 * writes `input` to its stdin and closes it; `{"op":"kill","id"}` SIGKILLs
 * that call's group. Answers on stdout, framed (FRAME): its stdout and stderr
 * bytes as they come (stderr up to `errBytes`), its exit (`{code,signal}`),
 * its close, or an error starting it; `ready` first of all. The runner
 * starts only `git`. Its stdin's end (the session closed) or a line it
 * cannot read ends it, every call's group killed first. Backpressure: while
 * its stdout is full it stops reading every call's output.
 */
export const GIT_SESSION_RUNNER_SOURCE = String.raw`"use strict";
const { spawn } = require("node:child_process");
const kids = new Map();
let full = false;
const send = (type, id, payload) => {
  const head = Buffer.alloc(9);
  head.writeUInt8(type, 0);
  head.writeUInt32BE(id >>> 0, 1);
  head.writeUInt32BE(payload.length, 5);
  if (!process.stdout.write(Buffer.concat([head, payload])) && !full) {
    full = true;
    for (const k of kids.values()) { k.stdout.pause(); k.stderr.pause(); }
  }
};
const json = (v) => Buffer.from(JSON.stringify(v));
process.stdout.on("drain", () => {
  full = false;
  for (const k of kids.values()) { k.stdout.resume(); k.stderr.resume(); }
});
const killGroup = (c) => {
  if (c.pid !== undefined) { try { process.kill(-c.pid, "SIGKILL"); } catch (e) { /* gone */ } }
  try { c.kill("SIGKILL"); } catch (e) { /* gone */ }
};
const end = () => {
  for (const c of kids.values()) killGroup(c);
  process.exit(0);
};
process.stdout.on("error", end);
const run = (q) => {
  const id = q.id;
  let c;
  try {
    c = spawn("git", q.args, { cwd: q.cwd, env: q.env, stdio: ["pipe", "pipe", "pipe"], detached: true });
  } catch (e) {
    send(5, id, json({ message: String((e && e.message) || e) }));
    return;
  }
  let errLeft = q.errBytes;
  let failed = false;
  kids.set(id, c);
  if (full) { c.stdout.pause(); c.stderr.pause(); }
  c.stdout.on("data", (b) => send(1, id, b));
  c.stderr.on("data", (b) => {
    if (errLeft <= 0) return;
    const s = b.length > errLeft ? b.subarray(0, errLeft) : b;
    errLeft -= s.length;
    send(2, id, s);
  });
  c.on("error", (e) => {
    if (failed) return;
    failed = true;
    killGroup(c);
    kids.delete(id);
    send(5, id, json({ message: String((e && e.message) || e) }));
  });
  c.on("exit", (code, signal) => {
    if (failed) return;
    if (c.pid !== undefined) { try { process.kill(-c.pid, "SIGKILL"); } catch (e) { /* none left */ } }
    send(3, id, json({ code, signal }));
  });
  c.on("close", (code, signal) => {
    kids.delete(id);
    if (failed) return;
    send(4, id, json({ code, signal }));
  });
  c.stdin.on("error", () => {});
  c.stdin.end(typeof q.input === "string" ? q.input : "");
};
let buf = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
  buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
  let nl;
  while ((nl = buf.indexOf(10)) >= 0) {
    const line = buf.subarray(0, nl).toString("utf8");
    buf = buf.subarray(nl + 1);
    let q;
    try { q = JSON.parse(line); } catch (e) { end(); return; }
    if (q === null || typeof q !== "object" || typeof q.id !== "number") { end(); return; }
    if (q.op === "run") {
      if (!Array.isArray(q.args) || !q.args.every((a) => typeof a === "string") || typeof q.cwd !== "string"
        || q.env === null || typeof q.env !== "object" || typeof q.errBytes !== "number") { end(); return; }
      run(q);
    } else if (q.op === "kill") {
      const c = kids.get(q.id);
      if (c !== undefined) killGroup(c);
    } else { end(); return; }
  }
});
process.stdin.on("end", end);
process.stdin.on("error", end);
send(6, 0, Buffer.from("ready"));
`;

/** The session sandbox's /proc: an EMPTY tmpfs, remounted read-only, in
 *  place of the probe's `--proc /proc`. No call can open another call's
 *  `/proc/<pid>/fd`, `environ` or `mem` (or find its pid). Never no /proc
 *  mount at all: under `--ro-bind / /` the HOST's /proc would show through
 *  (a recursive bind). */
export const SESSION_PROC_FLAGS: readonly string[] = ["--tmpfs", "/proc", "--remount-ro", "/proc"];

/** The session sandbox's flags: the probe's, with every `--proc <dir>` pair
 *  dropped and SESSION_PROC_FLAGS last (after the `--ro-bind / /` it must
 *  cover). Pure. */
export function sessionSandboxFlags(flags: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < flags.length; i++) {
    if (flags[i] === "--proc") { i++; continue; }
    out.push(flags[i]!);
  }
  return [...out, ...SESSION_PROC_FLAGS];
}

/** The command that starts the runner in `sandbox`: the probe's bubblewrap
 *  and flags (`gitCommand`'s, nothing bound read-write) but an empty
 *  read-only /proc (sessionSandboxFlags), then this process's own node
 *  running GIT_SESSION_RUNNER_SOURCE. Pure. */
export function sessionRunnerCommand(sandbox: BwrapGitSandbox, node: string = process.execPath): { file: string; args: string[] } {
  return { file: sandbox.bwrap, args: [...sessionSandboxFlags(sandbox.flags), "--", node, "-e", GIT_SESSION_RUNNER_SOURCE] };
}

/** The host's Yama ptrace scope (`/proc/sys/kernel/yama/ptrace_scope`), or
 *  null when absent or unreadable. */
export function hostPtraceScope(read: (p: string) => string = (p) => readFileSync(p, "utf8")): number | null {
  try {
    const v = read("/proc/sys/kernel/yama/ptrace_scope").trim();
    return /^\d+$/.test(v) ? Number(v) : null;
  } catch {
    return null;
  }
}

/** May calls share one sandbox here? Only when Yama keeps a process from
 *  attaching to anything but its descendants (scope >= 1): ptrace,
 *  `pidfd_getfd` and `process_vm_writev` of a sibling call (all
 *  PTRACE_MODE_ATTACH) are refused. 0, absent or unreadable: no (one sandbox
 *  per call: fail toward isolation). Pure. */
export function sessionAllowed(scope: number | null): boolean {
  return scope !== null && scope >= 1;
}

/** The exit code bubblewrap reports for its command: the code, or 128 + the
 *  signal that ended it. Pure. */
export function sandboxExitCode(code: number | null, signal: string | null): number {
  if (signal !== null) {
    const n = (osConstants.signals as Record<string, number | undefined>)[signal];
    return 128 + (n ?? 0);
  }
  return code ?? 1;
}

// ── The session ─────────────────────────────────────────────────────────────

export interface GitSessionOpts {
  /** The sandbox (default: launchGitSandbox, the launch's probe answer). */
  sandbox?: () => GitSandbox | null;
  /** How the runner is started for a bubblewrap sandbox (default
   *  sessionRunnerCommand). A test knob. */
  runnerCommand?: (sandbox: BwrapGitSandbox) => { file: string; args: string[] };
  /** The runner for calls not in the session (default perCallGitRunner). */
  perCall?: (children?: Set<RunningChild>) => GitRunner;
  /** The host's Yama ptrace scope (default hostPtraceScope). A test knob. */
  ptraceScope?: () => number | null;
  killGraceMs?: number;
  closeGraceMs?: number;
}

export interface GitSessionStats {
  /** Runners started (sandboxes made for the session). */
  sandboxes: number;
  /** Calls run in the session's sandbox. */
  inSession: number;
  /** Calls run one sandbox each (writes, no sandbox, fallback). */
  perCall: number;
  /** Why the session stopped taking calls, when it did. */
  ended?: string;
  /** Why the session never shared a sandbox (Yama), when it did not. */
  perCallWhy?: string;
}

interface Pending {
  id: number;
  /** Frames arrive for it. */
  onFrame(type: number, payload: Buffer): void;
  /** The runner ended under it. */
  fail(why: string): void;
  /** The runner ended before it ran (re-dispatch per call). */
  redo(): void;
}

type Mode = "unresolved" | "session" | "per-call" | "closed";

/** One sandbox for many git calls (the module comment). */
export class GitSession {
  readonly stats: GitSessionStats = { sandboxes: 0, inSession: 0, perCall: 0 };
  private mode: Mode = "unresolved";
  private sandbox: BwrapGitSandbox | null = null;
  private child: ChildProcess | null = null;
  private ready = false;
  private readonly calls = new Map<number, Pending>();
  private nextId = 1;
  private rx: Buffer[] = [];
  private rxLen = 0;
  private runnerErr = "";
  private readonly perCallRunners = new Map<Set<RunningChild> | undefined, GitRunner>();
  private readonly onExit = (): void => this.killRunner();

  constructor(private readonly opts: GitSessionOpts = {}) {}

  /** A GitRunner over this session; `children` tracks its calls while they
   *  run (an owner's `close` kills them, as trackedGitRunner's). */
  runner(children?: Set<RunningChild>): GitRunner {
    const run: GitRunner = (args, opts) => this.run(args, opts, children);
    PRODUCTION.add(run);
    return run;
  }

  /** The running runner's process (bubblewrap's), if any: a test aid. */
  get runnerPid(): number | undefined {
    return this.child?.pid;
  }

  /** Start the sandbox now (its start-up overlaps whatever the caller does
   *  next); a no-op where the session runs nothing in one. */
  warm(): void {
    this.resolve();
    if (this.mode === "session" && this.child === null) this.start();
  }

  /** End the session: the sandbox's process group killed, every call in
   *  flight failed, later calls failed. Idempotent. */
  close(): void {
    if (this.mode === "closed") return;
    this.mode = "closed";
    this.stats.ended ??= "closed";
    this.endRunner("the git session was closed");
  }

  private resolve(): void {
    if (this.mode !== "unresolved") return;
    const sb = (this.opts.sandbox ?? launchGitSandbox)();
    if (sb === null || isSeatbeltGitSandbox(sb)) {
      this.mode = "per-call";
      return;
    }
    this.sandbox = sb;
    // Calls share a sandbox only where Yama keeps one from attaching to
    // another (write-protection.md §8.5.3); else one sandbox per call.
    const scope = (this.opts.ptraceScope ?? hostPtraceScope)();
    if (sessionAllowed(scope)) {
      this.mode = "session";
    } else {
      this.mode = "per-call";
      this.stats.perCallWhy = `kernel.yama.ptrace_scope is ${scope ?? "absent or unreadable"}: one git sandbox per call`;
    }
  }

  private perCallRunner(children: Set<RunningChild> | undefined): GitRunner {
    let r = this.perCallRunners.get(children);
    if (r === undefined) {
      r = (this.opts.perCall ?? ((c?: Set<RunningChild>) => perCallGitRunner(c, () => this.sandboxForPerCall())))(children);
      this.perCallRunners.set(children, r);
    }
    return r;
  }

  /** The per-call path runs in the sandbox the session resolved (the same
   *  answer), else the launch's. */
  private sandboxForPerCall(): GitSandbox | null {
    return this.sandbox ?? launchGitSandbox();
  }

  private run(args: string[], opts: RunOpts, children: Set<RunningChild> | undefined): Promise<GitRun> {
    if (this.mode === "closed") return Promise.resolve({ code: 1, stdout: "", stderr: "the git session was closed" });
    this.resolve();
    if (this.mode !== "session" || (opts.writable !== undefined && opts.writable.length > 0)) {
      this.stats.perCall++;
      return this.perCallRunner(children)(args, opts);
    }
    if (this.child === null) this.start();
    if (this.mode !== "session") {
      // The runner could not even be spawned: one sandbox per call.
      this.stats.perCall++;
      return this.perCallRunner(children)(args, opts);
    }
    return new Promise<GitRun>((resolveRun) => this.enqueue(args, opts, children, resolveRun));
  }

  private start(): void {
    const sb = this.sandbox!;
    const cmd = (this.opts.runnerCommand ?? sessionRunnerCommand)(sb);
    this.stats.sandboxes++;
    this.ready = false;
    this.rx = [];
    this.rxLen = 0;
    this.runnerErr = "";
    let child: ChildProcess;
    try {
      child = spawn(cmd.file, cmd.args, { cwd: "/", env: {}, stdio: ["pipe", "pipe", "pipe"], detached: true });
    } catch (e) {
      this.child = null;
      this.toPerCall(`the git sandbox could not start (${(e as Error).message})`);
      return;
    }
    this.child = child;
    process.once("exit", this.onExit);
    child.stdout!.on("data", (b: Buffer) => { if (this.child === child) this.receive(b); });
    child.stderr!.setEncoding("utf8");
    child.stderr!.on("data", (s: string) => { if (this.runnerErr.length < 4096) this.runnerErr += s.slice(0, 4096 - this.runnerErr.length); });
    child.stdin!.on("error", () => { /* the runner died: close reports it */ });
    child.on("error", (e) => { if (this.child === child) this.runnerEnded(`the git sandbox could not start (${e.message})`); });
    child.on("close", (code, signal) => {
      if (this.child !== child) return;
      const said = this.runnerErr.trim().split("\n").slice(-1)[0] ?? "";
      this.runnerEnded(`the git sandbox ended (${signal ?? `exit ${code}`})${said !== "" ? `: ${said}` : ""}`);
    });
    this.idle();
  }

  private enqueue(args: string[], opts: RunOpts, children: Set<RunningChild> | undefined, resolveRun: (r: GitRun) => void): void {
    const id = this.nextId++;
    const timeoutMs = opts.timeoutMs ?? GIT_RUNNER_DEFAULT_TIMEOUT_MS;
    const killGraceMs = this.opts.killGraceMs ?? CHILD_KILL_GRACE_MS;
    const closeGraceMs = this.opts.closeGraceMs ?? CHILD_CLOSE_GRACE_MS;
    // The cwd resolved here, as a spawn from this process resolves it (the
    // runner itself runs in `/`).
    const line = JSON.stringify({
      op: "run", id, args: productionGitArgs(args), cwd: resolve(opts.cwd), env: productionGitEnv(opts.env),
      ...(opts.input !== undefined ? { input: opts.input } : {}),
      // Enough bytes for GIT_RUNNER_MAX_STDERR characters whatever they are.
      errBytes: GIT_RUNNER_MAX_STDERR * 4,
    }) + "\n";
    const outDec = new StringDecoder("utf8");
    const errDec = new StringDecoder("utf8");
    let out = "";
    let err = "";
    let killed = false;
    let why = "";
    let exited = false;
    let settled = false;
    let grace: NodeJS.Timeout | null = null;
    let deadline: NodeJS.Timeout | undefined;
    const handle: RunningChild = { kill: (reason?: string) => kill(reason ?? "stopped") };
    const self = this;

    const settle = (r: GitRun): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (grace !== null) clearTimeout(grace);
      children?.delete(handle);
      self.calls.delete(id);
      self.idle();
      resolveRun(r);
    };
    const addErr = (s: string): void => { if (err.length < GIT_RUNNER_MAX_STDERR) err += s.slice(0, GIT_RUNNER_MAX_STDERR - err.length); };
    const failed = (reason: string): GitRun => ({ code: 1, stdout: out, stderr: [err.trim(), reason].filter((x) => x !== "").join("\n") });
    const kill = (reason: string): void => {
      if (settled) return;
      if (!killed) { killed = true; why = reason; }
      self.send(JSON.stringify({ op: "kill", id }) + "\n");
      if (grace !== null) clearTimeout(grace);
      // A kill that does not take within the grace: the call fails, and the
      // sandbox goes with it (what holds its output dies with the sandbox).
      grace = setTimeout(() => {
        settle(failed(`${why}; its output did not close after the kill`));
        self.runnerEnded(`a killed git call did not end within ${killGraceMs} ms`);
      }, killGraceMs);
    };
    const addOut = (s: string): void => {
      if (s === "") return;
      out += s;
      if (out.length > GIT_RUNNER_MAX_STDOUT && !killed) kill(`its output passed ${GIT_RUNNER_MAX_STDOUT} characters`);
    };

    const p: Pending = {
      id,
      onFrame(type, payload) {
        if (settled) return;
        switch (type) {
          case FRAME.stdout: addOut(outDec.write(payload)); return;
          case FRAME.stderr: addErr(errDec.write(payload)); return;
          case FRAME.error: {
            const m = parseJson(payload) as { message?: unknown } | null;
            const message = typeof m?.message === "string" ? m.message : "the git call could not start";
            settle(failed(message));
            return;
          }
          case FRAME.exit: {
            if (killed || exited) return;
            exited = true;
            const e = parseJson(payload) as { code?: number | null; signal?: string | null } | null;
            // Its output closes when the last holder exits; one that does
            // not within the grace is a process it started outside its
            // group: the call fails, and the sandbox with it.
            grace = setTimeout(() => {
              settle(failed(`exited (${e?.signal ?? e?.code ?? "?"}) but a process it started kept its output open`));
              self.runnerEnded("a process a git call started kept its output open");
            }, closeGraceMs);
            return;
          }
          case FRAME.close: {
            addOut(outDec.end());
            addErr(errDec.end());
            if (killed) { settle(failed(why)); return; }
            const c = parseJson(payload) as { code?: number | null; signal?: string | null } | null;
            if (c === null) { settle(failed("the git sandbox sent an unreadable answer")); return; }
            settle({ code: sandboxExitCode(c.code ?? null, c.signal ?? null), stdout: out, stderr: err });
            return;
          }
          default:
            return;
        }
      },
      fail(reason) { settle(failed(reason)); },
      redo() {
        if (settled) return;
        settled = true;
        clearTimeout(deadline);
        children?.delete(handle);
        self.calls.delete(id);
        self.stats.perCall++;
        void self.perCallRunner(children)(args, opts).then(resolveRun);
      },
    };
    this.calls.set(id, p);
    this.stats.inSession++;
    children?.add(handle);
    deadline = setTimeout(() => kill(`killed at its ${timeoutMs} ms deadline`), Math.max(1, timeoutMs));
    this.busy();
    this.send(line);
  }

  private send(line: string): void {
    const c = this.child;
    if (c === null || c.stdin === null || c.stdin.destroyed) return;
    try { c.stdin.write(line); } catch { /* the runner died: close reports it */ }
  }

  private receive(b: Buffer): void {
    this.rx.push(b);
    this.rxLen += b.length;
    for (;;) {
      if (this.rxLen < HEADER) return;
      let buf = this.rx.length === 1 ? this.rx[0]! : Buffer.concat(this.rx, this.rxLen);
      const type = buf.readUInt8(0);
      const id = buf.readUInt32BE(1);
      const len = buf.readUInt32BE(5);
      if (len > MAX_FRAME || type < FRAME.stdout || type > FRAME.ready) {
        this.runnerEnded("the git sandbox sent an unreadable frame");
        return;
      }
      if (buf.length < HEADER + len) { this.rx = [buf]; return; }
      const payload = buf.subarray(HEADER, HEADER + len);
      buf = buf.subarray(HEADER + len);
      this.rx = buf.length > 0 ? [buf] : [];
      this.rxLen = buf.length;
      if (type === FRAME.ready) { this.ready = true; continue; }
      if (!this.ready) { this.runnerEnded("the git sandbox answered before it was ready"); return; }
      this.calls.get(id)?.onFrame(type, payload);
      if (this.child === null) return;
    }
  }

  /** The runner is gone (or must go): calls in flight fail (or, when it
   *  never said it was ready, run per call), and the session runs every
   *  later call per call. */
  private runnerEnded(why: string): void {
    if (this.child === null) return;
    const wasReady = this.ready;
    if (this.mode === "session") this.mode = "per-call";
    this.stats.ended ??= why;
    if (wasReady) this.endRunner(why);
    else this.toPerCall(why);
  }

  /** Never ready: nothing ran in it; every pending call runs per call. */
  private toPerCall(why: string): void {
    if (this.mode === "session") this.mode = "per-call";
    this.stats.ended ??= why;
    const pending = [...this.calls.values()];
    this.killRunner();
    for (const p of pending) p.redo();
  }

  private endRunner(why: string): void {
    const pending = [...this.calls.values()];
    this.killRunner();
    for (const p of pending) p.fail(why);
  }

  private killRunner(): void {
    const c = this.child;
    if (c === null) return;
    this.child = null;
    process.removeListener("exit", this.onExit);
    if (c.pid !== undefined) { try { process.kill(-c.pid, "SIGKILL"); } catch { /* gone */ } }
    try { c.kill("SIGKILL"); } catch { /* gone */ }
    for (const s of [c.stdin, c.stdout, c.stderr]) { try { s?.destroy(); } catch { /* closed */ } }
  }

  /** Calls in flight hold the event loop; an idle session does not. */
  private busy(): void {
    const c = this.child;
    if (c === null) return;
    c.ref();
    for (const s of [c.stdin, c.stdout, c.stderr]) (s as unknown as { ref?: () => void } | null)?.ref?.();
  }

  private idle(): void {
    const c = this.child;
    if (c === null || this.calls.size > 0) return;
    c.unref();
    for (const s of [c.stdin, c.stdout, c.stderr]) (s as unknown as { unref?: () => void } | null)?.unref?.();
  }
}

function parseJson(b: Buffer): unknown {
  try { return JSON.parse(b.toString("utf8")); } catch { return null; }
}

/** A new session (the module comment). The owner closes it. */
export function openGitSession(opts: GitSessionOpts = {}): GitSession {
  return new GitSession(opts);
}
