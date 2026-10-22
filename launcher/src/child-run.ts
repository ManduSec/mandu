/**
 * child-run — run one short-lived child (git, usually inside the git
 * sandbox, hardened-git.ts `gitCommand`) to its end or to its deadline, and
 * ALWAYS settle (docs/design/architecture/write-protection.md §8.5.1).
 *
 * Why a runner of its own (found 2026-09-30, the R3 hangs of CI pipelines
 * 7777 and 7778): node reports a child's end on `close`, which waits for
 * every holder of its stdout and stderr, not for the child. bubblewrap's
 * sandbox child, cloned into its new namespaces, first blocks reading an
 * eventfd until its parent has set it up, and binds its life to that
 * parent (`--die-with-parent`) only later. A SIGKILL of the parent in that
 * window (a runner's deadline, a `stop()` while a background cycle is
 * starting a call; `nice -n 19` and a loaded host widen it) leaves the child
 * reparented to init, blocked on that read FOREVER, holding the pipes: no
 * `close`, the call's promise never settles, the cycle never ends, and the
 * arbiter's `close()` awaits it forever. Measured on this host: 5% of
 * SIGKILLs within 10 ms of the spawn left such an orphan. So:
 *
 *   - the child runs in a process group of its own (`detached`), and a kill
 *     is SIGKILL to the WHOLE group: nice, bubblewrap and its sandbox child
 *     until that child calls setsid (`--new-session`), which it does only
 *     after the eventfd read, so the orphan above is always in the group;
 *   - and to every descendant read just before the kill (found 2026-10-21,
 *     CI jobs 18255 to 18296): after its setsid the sandbox child (the
 *     sandbox's pid 1) leads a session of its own, out of the group's
 *     reach, and binds its life to bubblewrap's (`--die-with-parent`) only
 *     in its init, after it forked the command, with no check that
 *     bubblewrap is still there. A kill in that window left the sandbox
 *     running the command to its end, unbound, holding the pipes (2 of 8192
 *     kills within 3 ms of the spawn on an idle host; at nice 19 in a busy
 *     cgroup, `git --version` past a 5 s grace). So a kill reads the
 *     child's descendants (`descendants`), kills the group, then each
 *     descendant and its group. Each is read while its parent lives, so it
 *     has not been reaped (its pid not reused) at the read; microseconds
 *     pass between the read and the kill;
 *   - a kill settles the call within `killGraceMs` whatever still holds the
 *     pipes (they are destroyed: nothing more is read);
 *   - an exit whose output does not close within `closeGraceMs` (a process
 *     the child started holds it) settles too, as a FAILURE (its output may
 *     be incomplete: fail closed), after SIGKILL to the group.
 *
 * A call therefore settles by `timeoutMs + killGraceMs` at the latest. A
 * killed call, one that failed to start, and one whose output did not close
 * are failures (`code` 1, `complete` false).
 *
 * The arbiter and the launcher (its `defaultGitRunner`) ship standalone, so
 * this file is copied verbatim into each package's src/; the parity test
 * (tests/stack/hardened-git-parity.test.ts) holds the copies
 * byte-identical: edit one, copy it out again.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";

export interface ChildRunOptions {
  cwd: string;
  env: NodeJS.ProcessEnv;
  /** Written to stdin, which is then closed (closed empty when unset). */
  input?: string;
  /** SIGKILL to the group at this deadline. */
  timeoutMs: number;
  /** stdout decoded as UTF-8 and handed over a chunk at a time instead of
   *  collected. */
  onStdout?: (chunk: string) => void;
  /** stdout raw, a chunk at a time, instead of collected. */
  onStdoutBytes?: (chunk: Buffer) => void;
  /** How collected stdout is decoded: UTF-8 (the default), or `latin1`, one
   *  character per byte, for a binary answer. */
  stdoutEncoding?: "utf8" | "latin1";
  /** Collected stdout over this many characters kills the call (a
   *  failure, never a silently truncated answer). Default: unbounded. */
  maxStdout?: number;
  /** stderr kept (the rest dropped). Default 4096 characters. */
  maxStderr?: number;
  /** After the child's exit, how long its output may take to close. */
  closeGraceMs?: number;
  /** After a kill, how long the pipes are read before they are dropped. */
  killGraceMs?: number;
}

export interface ChildRunResult {
  /** The exit code; 1 when killed, not started, or its output never closed. */
  code: number;
  stdout: string;
  stderr: string;
  /** Exited on its own, code 0, its output closed. */
  complete: boolean;
  killed: boolean;
  /** Set when the child could not be started or failed as a process (the
   *  `error` event), as opposed to a command that ran and failed. */
  error?: string;
}

/** A call in flight, as its owner tracks it: `kill` ends it (SIGKILL to its
 *  group) and the call settles within its kill grace. */
export interface RunningChild {
  kill(reason?: string): void;
}

export const CHILD_CLOSE_GRACE_MS = 10_000;
export const CHILD_KILL_GRACE_MS = 1_000;

/** At most this many descendants are read for a kill (a git call has a
 *  handful: bubblewrap's pid 1 and the command). */
export const CHILD_MAX_DESCENDANTS = 256;

/** The live descendants of `pid`, parents first, from
 *  /proc/<pid>/task/<tid>/children (Linux, CONFIG_PROC_CHILDREN: on in the
 *  distributions' kernels). None where there is no /proc (macOS, where the
 *  Seatbelt sandbox execs git in place and leaves no sandbox child) or the
 *  file cannot be read: the group kill alone, as before. */
export function descendants(pid: number): number[] {
  const out: number[] = [];
  const seen = new Set<number>([pid]);
  const queue = [pid];
  while (queue.length > 0 && out.length < CHILD_MAX_DESCENDANTS) {
    const p = queue.shift()!;
    let tasks: string[];
    try { tasks = readdirSync(`/proc/${p}/task`); } catch { continue; }
    for (const t of tasks) {
      let kids: string;
      try { kids = readFileSync(`/proc/${p}/task/${t}/children`, "utf8"); } catch { continue; }
      for (const k of kids.split(" ")) {
        const n = Number(k);
        if (k === "" || !Number.isInteger(n) || n <= 0 || seen.has(n) || out.length >= CHILD_MAX_DESCENDANTS) continue;
        seen.add(n);
        out.push(n);
        queue.push(n);
      }
    }
  }
  return out;
}

/** Run `file args` (see the module comment); `children` tracks it while it
 *  runs so an owner's `stop` can kill it. */
export function runChild(
  file: string,
  args: readonly string[],
  opts: ChildRunOptions,
  children?: Set<RunningChild>,
): Promise<ChildRunResult> {
  return new Promise((resolveRun) => {
    let child: ChildProcess;
    try {
      child = spawn(file, [...args], { cwd: opts.cwd, env: opts.env, stdio: ["pipe", "pipe", "pipe"], detached: true });
    } catch (e) {
      resolveRun({ code: 1, stdout: "", stderr: (e as Error).message, complete: false, killed: false, error: (e as Error).message });
      return;
    }
    const maxStderr = opts.maxStderr ?? 4096;
    let out = "";
    let err = "";
    let killed = false;
    let why = "";
    let settled = false;
    let grace: NodeJS.Timeout | null = null;
    let deadline: NodeJS.Timeout | undefined;
    const handle: RunningChild = { kill: (reason?: string) => kill(reason ?? "stopped") };

    const settle = (r: ChildRunResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (grace !== null) clearTimeout(grace);
      children?.delete(handle);
      resolveRun(r);
    };
    // The group: nice, bubblewrap, and bubblewrap's sandbox child before
    // its setsid (a group of its own since `detached`); then each
    // descendant read before the kill, which reaches that sandbox child
    // after its setsid (see the module comment). Only while node has not
    // reaped the child (its exit reported on this same thread): a reaped
    // child's pid may be another process's by now.
    const killGroup = (): void => {
      const unreaped = child.pid !== undefined && child.exitCode === null && child.signalCode === null;
      const left = unreaped ? descendants(child.pid!) : [];
      if (child.pid !== undefined) { try { process.kill(-child.pid, "SIGKILL"); } catch { /* gone */ } }
      try { child.kill("SIGKILL"); } catch { /* gone */ }
      for (const pid of left) {
        try { process.kill(-pid, "SIGKILL"); } catch { /* leads no group */ }
        try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
      }
    };
    // Stop reading: output a straggler holds open is never waited for.
    const abandon = (reason: string, error?: string): void => {
      for (const s of [child.stdin, child.stdout, child.stderr]) { try { s?.destroy(); } catch { /* closed */ } }
      settle({ code: 1, stdout: out, stderr: [err.trim(), reason].filter((x) => x !== "").join("\n"), complete: false, killed, ...(error !== undefined ? { error } : {}) });
    };
    const kill = (reason: string): void => {
      if (settled) return;
      if (!killed) { killed = true; why = reason; }
      killGroup();
      if (grace !== null) clearTimeout(grace);
      grace = setTimeout(() => abandon(`${why}; its output did not close after the kill`), opts.killGraceMs ?? CHILD_KILL_GRACE_MS);
    };

    deadline = setTimeout(() => kill(`killed at its ${opts.timeoutMs} ms deadline`), Math.max(1, opts.timeoutMs));
    children?.add(handle);
    if (opts.onStdoutBytes) {
      child.stdout!.on("data", (c: Buffer) => { if (!settled) opts.onStdoutBytes!(c); });
    } else {
      child.stdout!.setEncoding(opts.stdoutEncoding ?? "utf8");
      child.stdout!.on("data", (c: string) => {
        if (settled) return;
        if (opts.onStdout) { opts.onStdout(c); return; }
        out += c;
        if (opts.maxStdout !== undefined && out.length > opts.maxStdout) kill(`its output passed ${opts.maxStdout} characters`);
      });
    }
    child.stderr!.setEncoding("utf8");
    child.stderr!.on("data", (c: string) => { if (err.length < maxStderr) err += c.slice(0, maxStderr - err.length); });
    child.on("error", (e) => { killGroup(); abandon(e.message, e.message); });
    child.on("exit", (code, signal) => {
      if (settled || killed) return;
      // Its output closes when the last holder exits. One that does not
      // within the grace is a process it started, outside the sandbox's
      // lifetime: the call failed (its output may be incomplete).
      grace = setTimeout(() => {
        killGroup();
        abandon(`exited (${signal ?? code}) but a process it started kept its output open`);
      }, opts.closeGraceMs ?? CHILD_CLOSE_GRACE_MS);
    });
    child.on("close", (code, signal) => {
      if (killed) {
        settle({ code: 1, stdout: out, stderr: [err.trim(), why].filter((x) => x !== "").join("\n"), complete: false, killed });
        return;
      }
      const c = signal !== null ? 1 : (code ?? 1);
      settle({ code: c, stdout: out, stderr: err || (signal !== null ? `killed by ${signal}` : ""), complete: signal === null && code === 0, killed });
    });
    child.stdin!.on("error", () => { /* the child died: close reports it */ });
    child.stdin!.end(opts.input ?? "");
  });
}
