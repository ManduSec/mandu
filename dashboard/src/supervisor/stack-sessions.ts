/**
 * stack-sessions — the `mandu` sessions that use the stack at a runtime base,
 * for the supervisor's adopt-time replacement of a stale arbiter
 * (supervisor.ts bringUp; runtime-instances.md §4.1b).
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code, mirroring
 * launcher/src/subcommands.ts `liveLaunchersOn` (the release check's peer
 * scan before it restarts a stack) per the standalone-package rule: a
 * session is a process of this user titled exactly `mandu` (the launcher's
 * process title, runtime-instances.md §7) whose stack is this one, read from
 * its environment the way the launcher's `realStackOf` reads it (the same
 * runtime-base rule, runtime-base.ts), else from the stack's registry, where
 * every launch has its `<epochSec>-<pid>` scope dir (§10.4). A container's
 * process belongs to another stack. A short-lived verb (`mandu status`)
 * carries the title too and counts: here that only keeps a stale arbiter
 * adopted, the safe side.
 *
 * Another user's process is never counted: its environment cannot be read,
 * and its scope dir cannot be in this user's 0700 base.
 *
 * Linux reads /proc. Where it cannot be read (macOS, a masked /proc), the
 * answer is null: "cannot tell", which the caller treats as in use.
 */
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { resolveRuntimeBase } from "../runtime-base.js";

/** The process facts the scan needs (test-injectable). */
export interface SessionScanDeps {
  /** This user's pids, or null when the process table cannot be read. */
  listPids(): number[] | null;
  /** argv[0] of `pid` (its process title), or null. */
  titleOf(pid: number): string | null;
  /** The environment `pid` was started with, or null when unreadable. */
  environOf(pid: number): Record<string, string> | null;
  /** `/proc/<pid>/cgroup`, or null. */
  cgroupOf(pid: number): string | null;
  /** The entries of `dir` (the scope dirs live directly under the base). */
  entriesOf(dir: string): string[];
}

function readText(path: string): string | null {
  try { return readFileSync(path, "utf8"); } catch { return null; }
}

export const realSessionScanDeps: SessionScanDeps = {
  listPids: () => {
    if (process.platform !== "linux") return null;
    let names: string[];
    try { names = readdirSync("/proc"); } catch { return null; }
    return names.filter((n) => /^\d+$/.test(n)).map(Number);
  },
  titleOf: (pid) => readText(`/proc/${pid}/cmdline`)?.split("\0")[0] ?? null,
  environOf: (pid) => {
    const raw = readText(`/proc/${pid}/environ`);
    if (raw === null) return null;
    const env: Record<string, string> = {};
    for (const kv of raw.split("\0")) {
      const i = kv.indexOf("=");
      if (i > 0) env[kv.slice(0, i)] = kv.slice(i + 1);
    }
    return env;
  },
  cgroupOf: (pid) => readText(`/proc/${pid}/cgroup`),
  entriesOf: (dir) => { try { return readdirSync(dir); } catch { return []; } },
};

/** A container's cgroup (docker, podman, containerd, k8s, lxc): another stack's. */
export function isContainerCgroup(cgroup: string): boolean {
  return /(^|\/)(docker[-/]|libpod-|containerd[-/]|kubepods|lxc[./])/m.test(cgroup);
}

function normStack(base: string): string {
  return resolve(base).replace(/\/+$/, "") || "/";
}

/**
 * The pids of the `mandu` sessions on the stack at `base`, or null when the
 * process table cannot be read. Never this process.
 */
export function liveSessionsOn(base: string, deps: SessionScanDeps = realSessionScanDeps): number[] | null {
  const pids = deps.listPids();
  if (pids === null) return null;
  const stack = normStack(base);
  const scopePids = new Set(
    deps.entriesOf(stack)
      .map((n) => /^\d+-(\d+)$/.exec(n)?.[1])
      .filter((p): p is string => p !== undefined)
      .map(Number),
  );
  const out: number[] = [];
  for (const pid of pids) {
    if (pid === process.pid || deps.titleOf(pid) !== "mandu") continue;
    const cg = deps.cgroupOf(pid);
    if (cg !== null && isContainerCgroup(cg)) continue;
    const env = deps.environOf(pid);
    let onStack: boolean;
    if (env !== null && (env["MANDU_RUNTIME_DIR"] || env["XDG_RUNTIME_DIR"] || env["HOME"])) {
      try { onStack = normStack(resolveRuntimeBase(env).base) === stack; } catch { onStack = scopePids.has(pid); }
    } else {
      onStack = scopePids.has(pid);
    }
    if (onStack) out.push(pid);
  }
  return out.sort((a, b) => a - b);
}
