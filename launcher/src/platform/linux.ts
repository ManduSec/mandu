/**
 * platform/linux — systemd-scope-or-pgid scoping, /proc tree, XDG runtime dir.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   Adapted from launcher/mandu-run.sh: scope manager selection (L1294-1299),
 *   no-scope/pgid fallback (L1236-1239), runtime dir (L484), reap shape (L646-656).
 */
import { readFile, readdir } from "node:fs/promises";
import { runtimeBase } from "../arbiter-sock.js";
import type { Platform, ScopePlan } from "./types.js";
import { inertTree } from "./proc-tree.js";

export const linuxPlatform: Platform = {
  id: "linux",

  // The one default-base rule (runtime-base.ts, runtime-instances.md §3b):
  // XDG_RUNTIME_DIR/mandu, else TMPDIR/mandu when an instance socket fits,
  // else the private /tmp/mandu-<uid>. The same root parse.ts gives scope dirs.
  runtimeDir(env) {
    // The path table's `runtime-dir` (arbiter-sock.ts runtimeBase).
    return runtimeBase(env);
  },

  planScope({ scopeId, env, noScope, commandExists, systemdUserOk }): ScopePlan {
    if (noScope || !commandExists("systemd-run") || !systemdUserOk()) {
      return { prefix: [], detached: true };
    }
    // --quiet drops systemd-run's own "Running as unit: …" stderr line — the
    // launch display policy (launch-banner.ts) owns what the terminal shows.
    const prefix = ["systemd-run", "--user", "--scope", "--quiet", `--unit=mandu-${scopeId}`];
    for (const [k, v] of Object.entries(env)) prefix.push(`--setenv=${k}=${v}`);
    prefix.push("--");
    return { prefix, detached: false };
  },

  async agentTree(pid) {
    // BFS over /proc/<pid>/task/*/children (present on modern kernels).
    const seen = new Set<number>([pid]);
    const queue = [pid];
    while (queue.length) {
      const p = queue.shift()!;
      let tasks: string[] = [];
      try { tasks = await readdir(`/proc/${p}/task`); } catch { continue; }
      for (const t of tasks) {
        let kids = "";
        try { kids = await readFile(`/proc/${p}/task/${t}/children`, "utf8"); } catch { continue; }
        for (const c of kids.split(/\s+/).filter(Boolean)) {
          const n = Number(c);
          if (!seen.has(n)) { seen.add(n); queue.push(n); }
        }
      }
    }
    seen.delete(pid);
    return [...seen];
  },

  // Linux keeps its kernel-held scope (portable-wrapper-cross-platform.md
  // §3.5): the twin wrap's PID namespace ends the agent's tree with its first
  // process. The launcher itself ends nothing here, so where the twin wrap is
  // not in the chain (mode off, a posture without it) background processes
  // outlive the session: inside the systemd scope (attributed; `systemctl
  // --user stop mandu-<id>.scope` ends them) or, on the detached no-systemd
  // fallback, loose. That is the Linux gap §3.5 records, not closed here.
  trackTree(rootPid) {
    return inertTree(rootPid);
  },

  async killTree() {
    return { terminated: [], killed: [], survivors: [], skipped: LINUX_TREE_SKIP };
  },
};

export const LINUX_TREE_SKIP =
  "linux: the launcher does not end the agent tree (the twin wrap's PID namespace or the systemd scope holds it)";
