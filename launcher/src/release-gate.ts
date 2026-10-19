/**
 * release-gate — two launches on one stack of another release (or build) do
 * not both refuse (runtime-instances.md §4.1, "Racing launches").
 *
 * Before this, the release check of two `mandu` launches started together
 * against one older, unused resident stack could refuse in both: each saw
 * the other, a process titled `mandu` on that stack, as a session using it.
 * Two pieces under `<base>/release-check/` (the stack's private runtime dir)
 * fix that:
 *
 *   - a PENDING marker per launch (`pending-<pid>`), written as the launch's
 *     check starts and removed when it ends, before any session op. A launch
 *     with a fresh marker has used nothing but `hello`, so the peer scan
 *     leaves it out (`pendingReleaseChecks`). A marker whose pid is dead, or
 *     older than PENDING_MAX_AGE_MS, counts for nothing: the launch is a peer
 *     again, the safe side.
 *   - a RESTART LOCK (`lock/`, an atomic mkdir holding the owner's pid): the
 *     launch that would restart the stack takes it, reads `hello` again (the
 *     last holder may have replaced the stack already, and then it simply
 *     attaches) and only then stops and starts. A lock whose owner is dead is
 *     taken over.
 *
 * So of two racing launches one replaces the stack and the other waits and
 * adopts the new one. Every effect is injectable; the decisions are pure.
 *
 * The agent must not forge either (runtime-instances.md §4.1, "The gate and
 * the agent"): a marker naming a real session's launcher pid would take that
 * session out of the next launch's scan, and the launch would replace the
 * stack under it. `release-check/` is a runtime registry entry
 * (runtime-registry.ts), so the whole-agent guard and the macOS profile deny
 * the agent every file write in it. The guard does not judge a bare mkdir,
 * so only a REGULAR file (lstat, not a link) whose content is its pid counts
 * as a marker, `release-check/` itself must be a real directory, and a lock
 * dir without an owner file (all an agent can make there) is taken over
 * after a few seconds.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy): NEW Mandu code (no reference origin).
 */
import { lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** The gate's directory under a stack's runtime dir. */
export const GATE_DIR = "release-check";
/** A pending marker older than this is not believed (a launch's check takes
 *  seconds; one waiting on the lock refreshes nothing, so this is generous). */
export const PENDING_MAX_AGE_MS = 10 * 60_000;
/** How long a launch waits for another's restart before it refuses. */
export const LOCK_WAIT_MS = 90_000;
/** A lock dir with no owner file yet (its maker died between mkdir and the
 *  write) is taken over after this long. */
const OWNERLESS_GRACE_MS = 5_000;

/** The file-system and process effects, injectable for tests. */
export interface GateDeps {
  mkdir: (p: string, recursive: boolean) => void;
  writeFile: (p: string, data: string) => void;
  readFile: (p: string) => string;
  readdir: (p: string) => string[];
  /** lstat: what the entry is (a link is "other") and its mtime; null when absent. */
  entry: (p: string) => { kind: "file" | "dir" | "other"; mtimeMs: number } | null;
  rm: (p: string) => void;
  pidAlive: (pid: number) => boolean;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}

export const realGateDeps: GateDeps = {
  mkdir: (p, recursive) => { mkdirSync(p, { recursive, mode: 0o700 }); },
  writeFile: (p, data) => writeFileSync(p, data, { mode: 0o600 }),
  readFile: (p) => readFileSync(p, "utf8"),
  readdir: (p) => readdirSync(p),
  entry: (p) => {
    try {
      const st = lstatSync(p);
      return { kind: st.isFile() ? "file" : st.isDirectory() ? "dir" : "other", mtimeMs: st.mtimeMs };
    } catch {
      return null;
    }
  },
  rm: (p) => rmSync(p, { recursive: true, force: true }),
  pidAlive: (pid) => {
    try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
  },
  now: () => Date.now(),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};

const PENDING_RE = /^pending-(\d+)$/;

/** Make (or find) `<base>/release-check`. Never creates the runtime dir
 *  itself: a base that is not there has no stack to race on, and only the
 *  launch's own checks (the private-dir rule, runtime-instances.md §3b) may
 *  create one. */
function gateDir(base: string, deps: GateDeps): boolean {
  try {
    deps.mkdir(join(base, GATE_DIR), false);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") return false;
  }
  // A link planted at the name would put the gate somewhere else.
  return deps.entry(join(base, GATE_DIR))?.kind === "dir";
}

/** Write this launch's pending marker; returns the remover (idempotent).
 *  Best-effort: a marker that cannot be written leaves the launch a peer. */
export function markReleaseCheckPending(base: string, pid: number = process.pid, deps: GateDeps = realGateDeps): () => void {
  const path = join(base, GATE_DIR, `pending-${pid}`);
  try {
    if (!gateDir(base, deps)) return () => {};
    deps.writeFile(path, String(pid));
  } catch {
    return () => {};
  }
  let done = false;
  return () => {
    if (done) return;
    done = true;
    try { deps.rm(path); } catch { /* gone */ }
  };
}

/** The pids of launches whose release check is still running on the stack at
 *  `base`: a marker that is fresh and whose pid is alive. */
export function pendingReleaseChecks(base: string, deps: GateDeps = realGateDeps): Set<number> {
  const out = new Set<number>();
  let names: string[];
  if (deps.entry(join(base, GATE_DIR))?.kind !== "dir") return out;
  try { names = deps.readdir(join(base, GATE_DIR)); } catch { return out; }
  const now = deps.now();
  for (const n of names) {
    const m = PENDING_RE.exec(n);
    if (!m) continue;
    const pid = Number(m[1]);
    const path = join(base, GATE_DIR, n);
    // Only what a launch writes: a regular file holding its pid (a bare
    // directory, which the guard lets the agent make, is no marker).
    const e = deps.entry(path);
    if (e === null || e.kind !== "file" || now - e.mtimeMs > PENDING_MAX_AGE_MS || !deps.pidAlive(pid)) continue;
    let content = "";
    try { content = deps.readFile(path).trim(); } catch { continue; }
    if (content !== String(pid)) continue;
    out.add(pid);
  }
  return out;
}

/**
 * Take the stack's restart lock, waiting up to `waitMs` for another launch's
 * restart to finish. Resolves to the release function, or null when the wait
 * ran out (the caller refuses). A lock whose owner is dead is taken over.
 */
export async function acquireRestartLock(
  base: string,
  opts: { pid?: number; waitMs?: number; pollMs?: number } = {},
  deps: GateDeps = realGateDeps,
): Promise<(() => void) | null> {
  const pid = opts.pid ?? process.pid;
  const dir = join(base, GATE_DIR);
  const lock = join(dir, "lock");
  const owner = join(lock, "owner");
  const deadline = deps.now() + (opts.waitMs ?? LOCK_WAIT_MS);
  if (!gateDir(base, deps)) return null;
  for (;;) {
    let made = false;
    try { deps.mkdir(lock, false); made = true; } catch { made = false; }
    if (made) {
      try { deps.writeFile(owner, String(pid)); } catch { /* the pid is informational; the dir is the lock */ }
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try { deps.rm(lock); } catch { /* gone */ }
      };
    }
    // Held: by a live launch (wait), or by a dead one (take it over).
    let holder: number | null = null;
    try {
      const n = Number(deps.readFile(owner).trim());
      holder = Number.isSafeInteger(n) && n > 0 ? n : null;
    } catch {
      holder = null;
    }
    const at = deps.entry(lock)?.mtimeMs ?? null;
    const stale = holder !== null
      ? holder !== pid && !deps.pidAlive(holder)
      : at === null || deps.now() - at > OWNERLESS_GRACE_MS;
    if (stale) {
      try { deps.rm(lock); } catch { /* another waiter took it over first */ }
      continue;
    }
    if (deps.now() >= deadline) return null;
    await deps.sleep(opts.pollMs ?? 100);
  }
}
