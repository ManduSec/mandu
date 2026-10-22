/**
 * abandoned-stacks — resident Mandu daemons of ANOTHER stack whose code is
 * gone, for `mandu reap` (runtime-instances.md §10.5).
 *
 * `mandu reap` walks the registry of one runtime base, the caller's. A stack
 * started under another runtime folder is invisible to it, and ownerless by
 * design when it is a resident stack (§10 "The resident stack has no owner").
 * Found 2026-10-21: a dashboard and its arbiter of `/run/user/1007/mrel-npmtest`,
 * started by hand from a scratch npm install that was then deleted, serving
 * with nobody able to reach, upgrade or stop them but `mandu stop`; and the
 * test stacks of agent worktrees removed since (their working folder
 * `… (deleted)`).
 *
 * A daemon is abandoned when ALL hold:
 *   - it is this user's, titled as a resident daemon (`mandu-arbiter`,
 *     `mandu-dashboard`, a `mandu-*-proxy`), not in a container;
 *   - its environment selects a stack other than the one reap walks (that
 *     one's daemons are its registry's to judge, and an upgrade that replaced
 *     the account's install leaves them in a deleted folder for a while, still
 *     in use);
 *   - the folder its code runs in is gone (`/proc/<pid>/cwd` reads
 *     `… (deleted)`): no install is left that could restart, upgrade or
 *     reach it;
 *   - nobody owns it: `MANDU_OWNER_PID` is `none`/`0`, or names a dead pid,
 *     or is unset and its parent is gone (reparented) or another daemon of
 *     the same stack;
 *   - no `mandu` session runs on that stack (a launcher, title `mandu`,
 *     whose environment selects it).
 * Then reap SIGTERMs it, after checking its title and its deleted folder
 * again; `--dry-run` lists it. Linux only (/proc); nothing elsewhere.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { readdirSync, readFileSync, readlinkSync } from "node:fs";
import { resolve } from "node:path";
import { runtimeBase } from "./arbiter-sock.js";

const RESIDENT = /^mandu-(arbiter|dashboard|anthropic-proxy|openai-proxy|net-proxy)$/;

/** One process as the rule reads it. */
export interface ProcFacts {
  pid: number;
  /** argv[0] (the process title). */
  title: string;
  /** The stack its environment selects, or null. */
  stack: string | null;
  /** `MANDU_OWNER_PID` as set (undefined = unset). */
  owner: string | undefined;
  ppid: number | null;
  /** Its working folder, as /proc says it (`… (deleted)` when gone), or null. */
  cwd: string | null;
  container: boolean;
}

export interface AbandonedDeps {
  /** This user's processes (Linux: /proc), without this one. */
  procs: () => ProcFacts[];
  pidAlive: (pid: number) => boolean;
}

export interface AbandonedDaemon {
  pid: number;
  title: string;
  stack: string;
  cwd: string;
}

function norm(p: string): string {
  return resolve(p).replace(/\/+$/, "") || "/";
}

/** `/proc/<pid>/cwd` of a removed folder. */
export function folderGone(cwd: string | null): boolean {
  return cwd !== null && / \(deleted\)$/.test(cwd);
}

/** The abandoned resident daemons of stacks other than `base`. Pure over `deps`. */
export function findAbandonedDaemons(base: string, deps: AbandonedDeps): AbandonedDaemon[] {
  const procs = deps.procs();
  const walked = norm(base);
  const sessions = new Set(procs.filter((p) => p.title === "mandu" && !p.container && p.stack !== null).map((p) => norm(p.stack!)));
  const out: AbandonedDaemon[] = [];
  for (const p of procs) {
    if (!RESIDENT.test(p.title) || p.container || p.stack === null) continue;
    const stack = norm(p.stack);
    if (stack === walked || sessions.has(stack) || !folderGone(p.cwd)) continue;
    const owner = (p.owner ?? "").trim();
    let ownerless: boolean;
    if (owner === "none" || owner === "0") ownerless = true;
    else if (/^\d+$/.test(owner)) ownerless = !deps.pidAlive(Number(owner));
    else {
      // Unset (or unreadable): the owner is the parent (instance.ts resolveOwnerPid).
      const parent = p.ppid === null ? null : procs.find((q) => q.pid === p.ppid);
      ownerless = p.ppid === null || p.ppid <= 1 || !deps.pidAlive(p.ppid)
        || (parent !== undefined && parent !== null && RESIDENT.test(parent.title) && parent.stack !== null && norm(parent.stack) === stack);
    }
    if (ownerless) out.push({ pid: p.pid, title: p.title, stack, cwd: p.cwd!.replace(/ \(deleted\)$/, "") });
  }
  return out.sort((a, b) => a.pid - b.pid);
}

function readEnv(pid: number): Record<string, string> | null {
  let raw: string;
  try { raw = readFileSync(`/proc/${pid}/environ`, "utf8"); } catch { return null; }
  const env: Record<string, string> = {};
  for (const kv of raw.split("\0")) {
    const i = kv.indexOf("=");
    if (i > 0) env[kv.slice(0, i)] = kv.slice(i + 1);
  }
  return env;
}

/** One process's facts from /proc, or null (gone, another user's). */
export function procFactsOf(pid: number): ProcFacts | null {
  const env = readEnv(pid);
  if (env === null) return null;
  let title = "";
  let ppid: number | null = null;
  let cwd: string | null = null;
  let container = false;
  try { title = (readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0")[0] ?? "").trim(); } catch { return null; }
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const n = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
    ppid = Number.isInteger(n) && n > 0 ? n : null;
  } catch { /* gone */ }
  try { cwd = readlinkSync(`/proc/${pid}/cwd`); } catch { /* not ours */ }
  try { container = /(^|\/)(docker[-/]|libpod-|containerd[-/]|kubepods|lxc[./])/m.test(readFileSync(`/proc/${pid}/cgroup`, "utf8")); } catch { /* gone */ }
  let stack: string | null = null;
  if (env["MANDU_RUNTIME_DIR"] || env["XDG_RUNTIME_DIR"] || env["HOME"]) {
    try { stack = runtimeBase(env); } catch { stack = null; }
  }
  return { pid, title, stack, owner: env["MANDU_OWNER_PID"], ppid, cwd, container };
}

export const realAbandonedDeps: AbandonedDeps = {
  procs: () => {
    if (process.platform !== "linux") return [];
    let names: string[];
    try { names = readdirSync("/proc"); } catch { return []; }
    const out: ProcFacts[] = [];
    for (const n of names) {
      if (!/^\d+$/.test(n) || Number(n) === process.pid) continue;
      const f = procFactsOf(Number(n));
      if (f !== null && (f.title === "mandu" || f.title.startsWith("mandu-"))) out.push(f);
    }
    return out;
  },
  pidAlive: (pid) => {
    try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
  },
};

/** Is `pid` still the abandoned daemon reap planned to stop (its title, its
 *  removed folder)? Checked again right before the signal. */
export function stillAbandoned(d: Pick<AbandonedDaemon, "pid" | "title">, factsOf: (pid: number) => ProcFacts | null = procFactsOf): boolean {
  const f = factsOf(d.pid);
  return f !== null && f.title === d.title && folderGone(f.cwd);
}
