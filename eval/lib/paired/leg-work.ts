/**
 * leg-work — the agent-facing work dir of an evaluation leg, kept OUT of the
 * run's output dir and out of every Mandu home.
 *
 * Only results go under the output dir (`<out>/<leg>/`: reports, captures,
 * the runner-owned arbiter's DB and events). Everything the agent under test
 * touches lives in a per-leg `mkdtemp` dir, `<base>/mdu-e-XXXXXX/`:
 *   `workspace/`   the agent's cwd, staged with the task's inputs;
 *   `home/`        HOME, with CLAUDE_CONFIG_DIR and the XDG config and cache;
 *   `mandu-home/`  the wrapped leg's own MANDU_HOME;
 *   `runtime/`     XDG_RUNTIME_DIR and the launcher's MANDU_RUNTIME_DIR
 *                  registry, whose scope dirs hold `clean.sock` and the like;
 *   `tmp/`         TMPDIR, where tsx puts its IPC pipe;
 *   `a.sock`       the leg's arbiter socket.
 * Two reasons (on-disk-layout.md §9 decision 3):
 *   - A default output dir lies in `~/.mandu/runs/eval/`. The Mandu home is
 *     denied to the agent (on-disk-layout.md §4), and a launch whose cwd is
 *     inside it is refused. The agent must never work inside it.
 *   - Linux caps a socket path at 107 bytes and truncates a longer bind
 *     silently (arbiter/ipc/socket-path.ts); a default output dir plus a leg's
 *     nesting overflows that.
 * `<base>` is TMPDIR, else /tmp; /tmp too when TMPDIR is inside a Mandu home
 * or too deep for the sockets. (Not XDG_RUNTIME_DIR: a small tmpfs, and the
 * workspace and HOME live here too.)
 *
 * When the leg ends, `close()` copies the work dir back into the leg's results
 * dir minus sockets and FIFOs (the workspace, transcripts and launcher logs
 * stay with the run's evidence, as before) and removes it, unless
 * MANDU_EVAL_KEEP_WORK=1 keeps it for debugging.
 *
 * Mandu-new (no reference origin).
 */
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readlinkSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { manduPath } from "../generated/mandu-paths.js";
import type { RunPaths } from "./paired-config.js";

/** sun_path capacity on Linux minus the NUL. */
export const MAX_SOCKET_PATH = 107;

/** `mkdtemp` prefix; the dir it makes is `<base>/mdu-e-XXXXXX`. */
const PREFIX = "mdu-e-";

/** What `close()` copies back into the results dir. */
const RETAINED = ["workspace", "home", "mandu-home", "runtime", "tmp"] as const;

/** The socket paths a wrapped leg can create under its work dir, at their
 *  longest: the arbiter, the launcher's scope dir (`<unix secs>-<pid>`, a
 *  7-digit pid) with its clean-host socket, and tsx's IPC pipe. */
export function legSocketPaths(work: string, uid: number = process.getuid?.() ?? 1000): string[] {
  return [
    join(work, "a.sock"),
    join(work, "runtime", "registry", "9999999999-4194304", "clean.sock"),
    join(work, "tmp", `tsx-${uid}`, "4194304.pipe"),
  ];
}

/** Why a leg's sockets cannot live under `work`, or null when every one fits. */
export function legSocketProblem(work: string, uid?: number): string | null {
  for (const p of legSocketPaths(work, uid)) {
    const bytes = Buffer.byteLength(p, "utf8");
    if (bytes > MAX_SOCKET_PATH) return `a leg socket would be ${bytes} bytes, over the ${MAX_SOCKET_PATH}-byte Unix socket limit: ${p}`;
  }
  return null;
}

/** The Mandu homes no agent-facing path may lie in: the effective one
 *  (MANDU_HOME, else ~/.mandu) and the default ~/.mandu (as the launcher's
 *  own `manduHomes`). */
export function manduHomes(env: NodeJS.ProcessEnv = process.env, home: string = homedir()): string[] {
  return [...new Set([manduPath("mandu-home", env, home), manduPath("mandu-home", {}, home)])];
}

const realOr = (p: string): string => {
  try { return realpathSync(p); } catch { return resolve(p); }
};

/** Whether `path` is one of `roots` or under one; symlinks resolved where they exist. */
export function insideAny(path: string, roots: readonly string[]): boolean {
  const forms = [...new Set([resolve(path), realOr(path)])];
  return roots.flatMap((r) => [...new Set([resolve(r), realOr(r)])])
    .some((r) => forms.some((p) => p === r || p.startsWith(r.endsWith("/") ? r : r + "/")));
}

/** Why `base` cannot hold leg work dirs, or null. */
export function legWorkBaseProblem(base: string, env: NodeJS.ProcessEnv = process.env, home: string = homedir(), uid?: number): string | null {
  if (insideAny(base, manduHomes(env, home))) return `${base} is inside a Mandu home (${manduHomes(env, home).join(", ")}), which the agent may not reach`;
  return legSocketProblem(join(base, `${PREFIX}XXXXXX`), uid);
}

/** TMPDIR when it can hold leg work dirs, else /tmp. Throws (before any leg
 *  starts) when neither can. */
export function legWorkBase(env: NodeJS.ProcessEnv = process.env, home: string = homedir(), uid?: number): string {
  const tried: string[] = [];
  for (const base of [...new Set([env.TMPDIR || "/tmp", "/tmp"])]) {
    const problem = legWorkBaseProblem(base, env, home, uid);
    if (problem === null) return base;
    tried.push(problem);
  }
  throw new Error(`No usable directory for an evaluation leg's work dir (set TMPDIR to a short dir outside the Mandu home):\n  ${tried.join("\n  ")}`);
}

export interface LegWork {
  paths: RunPaths;
  /** Copy the work dir back into the results dir minus sockets, then remove
   *  it (kept under MANDU_EVAL_KEEP_WORK=1). Returns what could not be
   *  copied or removed; never throws. Idempotent. */
  close(): string[];
}

/** Make a leg's results dir `root` (0700) and its agent-facing work dir
 *  (`mkdtemp`, 0700), and return the leg's RunPaths. */
export function openLegWork(root: string, env: NodeJS.ProcessEnv = process.env, home: string = homedir()): LegWork {
  const base = legWorkBase(env, home);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  let work: string;
  // An unusable TMPDIR (absent, not writable) falls back to /tmp.
  try { work = mkdtempSync(join(base, PREFIX)); } catch (e) {
    if (base === "/tmp") throw e;
    work = mkdtempSync(join("/tmp", PREFIX));
  }
  // Re-checked on the real dir (a symlinked base resolves here).
  const problem = legSocketProblem(work) ?? (insideAny(work, manduHomes(env, home)) ? `${work} is inside a Mandu home` : null);
  if (problem !== null) {
    rmSync(work, { recursive: true, force: true });
    throw new Error(`leg work dir ${work} is unusable: ${problem}`);
  }
  const paths: RunPaths = {
    root: resolve(root), work,
    workspace: join(work, "workspace"), home: join(work, "home"), manduHome: join(work, "mandu-home"),
    runtime: join(work, "runtime"), tmp: join(work, "tmp"), sock: join(work, "a.sock"),
  };
  // The wrapped leg's launcher makes its MANDU_HOME itself, owner-only.
  for (const p of [paths.workspace, paths.home, paths.runtime, paths.tmp]) mkdirSync(p, { mode: 0o700 });
  let closed = false;
  return {
    paths,
    close(): string[] {
      if (closed) return [];
      closed = true;
      const skipped: string[] = [];
      for (const name of RETAINED) copyTree(join(work, name), join(paths.root, name), skipped);
      if (env.MANDU_EVAL_KEEP_WORK !== "1") {
        try { rmSync(work, { recursive: true, force: true }); } catch (e) { skipped.push(`remove ${work}: ${String(e)}`); }
      }
      return skipped;
    },
  };
}

/** Copy `src` to `dst`: directories (0700), regular files, symlinks as links.
 *  Sockets, FIFOs and devices are left out; an unreadable entry is noted in
 *  `skipped`, never thrown. */
function copyTree(src: string, dst: string, skipped: string[]): void {
  let st;
  try { st = lstatSync(src); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") skipped.push(`${src}: ${String(e)}`); return; }
  try {
    if (st.isDirectory()) {
      mkdirSync(dst, { recursive: true, mode: 0o700 });
      for (const name of readdirSync(src)) copyTree(join(src, name), join(dst, name), skipped);
    } else if (st.isFile()) copyFileSync(src, dst);
    else if (st.isSymbolicLink()) symlinkSync(readlinkSync(src), dst);
  } catch (e) { skipped.push(`${src}: ${String(e)}`); }
}
