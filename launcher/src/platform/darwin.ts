/**
 * platform/darwin — pgid scoping (no systemd), pgrep tree, short runtime dir.
 *
 * PROVENANCE (CONTRIBUTING.md reuse policy):
 *   NEW Mandu code. macOS has no systemd/cgroup and no /proc; scoping is the
 *   POSIX process-group floor (spec §2.2) and tree enumeration uses `pgrep -P`.
 *   The runtime dir is the one default-base rule (runtime-base.ts,
 *   runtime-instances.md §3b): the per-user TMPDIR (/var/folders/…/T/) leaves
 *   no room for an arbiter instance socket in darwin's 104-byte sun_path, so
 *   in practice it is the private 0700 /tmp/mandu-<uid>.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runtimeBase } from "../arbiter-sock.js";
import type { Platform, ScopePlan } from "./types.js";
import { ProcTreeTracker, endTree, realTreeDeps } from "./proc-tree.js";

const pexec = promisify(execFile);

export const darwinPlatform: Platform = {
  id: "darwin",

  runtimeDir(env) {
    // The path table's `runtime-dir` (arbiter-sock.ts runtimeBase), as on
    // Linux: macOS sets no XDG_RUNTIME_DIR, and its per-user TMPDIR leaves no
    // room for an instance socket, so in practice it is the private
    // /tmp/mandu-<uid> (runtime-base.ts, runtime-instances.md §3b).
    return runtimeBase(env);
  },

  planScope({ noScope: _noScope }): ScopePlan {
    // No systemd on macOS — always the detached-process-group floor.
    return { prefix: [], detached: true };
  },

  async agentTree(pid) {
    const seen = new Set<number>([pid]);
    const queue = [pid];
    while (queue.length) {
      const p = queue.shift()!;
      let out = "";
      try { ({ stdout: out } = await pexec("pgrep", ["-P", String(p)])); } catch { continue; }
      for (const c of out.split(/\s+/).filter(Boolean)) {
        const n = Number(c);
        if (!seen.has(n)) { seen.add(n); queue.push(n); }
      }
    }
    seen.delete(pid);
    return [...seen];
  },

  // Session-end teardown (portable-wrapper-cross-platform.md §3.5): a process
  // group is the only scope here, and what the agent leaves running is
  // reparented to launchd the moment the chain exits, so the tree is sampled
  // (pid + start time, and the process groups it used) while the chain runs
  // and ended from that record afterwards (proc-tree.ts).
  trackTree(rootPid, opts) {
    return new ProcTreeTracker(rootPid, realTreeDeps, opts?.intervalMs ?? DARWIN_TREE_SAMPLE_MS, opts?.sinceMs);
  },

  async killTree(tree, opts) {
    if (!(tree instanceof ProcTreeTracker)) {
      return { terminated: [], killed: [], survivors: [], skipped: "darwin: this tree was not tracked by trackTree" };
    }
    await tree.stop();
    return endTree(tree.record, realTreeDeps, opts);
  },
};

/** How often the darwin tracker samples the agent tree (one `ps -x`, a few ms). */
export const DARWIN_TREE_SAMPLE_MS = 1000;
