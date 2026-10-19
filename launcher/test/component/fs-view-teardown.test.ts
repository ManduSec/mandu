/**
 * fs-view-teardown.test — the fs-sync watcher quiesces before the post-exit
 * sweep, with REAL processes (fs-sync.md §2.4a).
 *
 * REGRESSION ORIGIN (2026-10-04): the golden-path canary's sweep failed once
 * on CI with `…/worktrees/agentview/index.lock: File exists`. The teardown
 * SIGTERMed the watcher's whole process group, so a git it was running died
 * too, and a SIGTERMed git can leave its index.lock behind (a few in a
 * thousand, measured with git 2.53); the sweep's commit then failed on it.
 *
 * The stand-in watcher here holds a lock file through a child shell (the
 * "git") that removes it when it ends; a SIGTERM to the group kills the shell
 * with the lock still there, exactly as the old teardown did. Two shapes:
 *   - drain:   the watcher handles SIGTERM by waiting for its child (the
 *              watcher's real drain: its git calls are synchronous);
 *   - startup: no handler yet, so the SIGTERM ends the watcher at once and
 *              its child outlives it in the group.
 * Either way the sweep must find the lock gone: the child was not signalled
 * and the wait covered the whole group.
 *
 * Real: startDetachedCmd, waitFor, the process group. Mocked: runOnce (the
 * git probe, `fs-sync-cli init`, and the sweep, which records the lock).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { groupAlive, startFsView } from "../../src/services/fs-view.js";
import { Layout } from "../../src/services/layout.js";
import { startDetachedCmd, waitFor, waitForFile, probePort, probeIdentity, type ServiceDeps } from "../../src/services/primitives.js";
import type { LaunchPlan } from "../../src/types.js";

const FAKE_WATCHER = `
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const [lock, mode] = process.argv.slice(2);
fs.writeFileSync(lock, "");
const git = spawn("sh", ["-c", 'sleep 1.5; rm -f "$1"', "sh", lock], { stdio: "ignore" });
if (mode === "drain") {
  process.on("SIGTERM", () => {
    if (git.exitCode !== null || git.signalCode !== null) process.exit(0);
    git.on("exit", () => process.exit(0));
  });
}
process.stdout.write('{"ok":true}\\n');
setInterval(() => {}, 1000);
`;

function plan(root: string): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid-teardown", tenant: "live", arbiterSock: "/run/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: join(root, "run", "events"), cwd: root, humanCwd: root, basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noContextProxy: true, fsSync: undefined, fsSyncEager: true,
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true,
  };
}

for (const mode of ["drain", "startup"] as const) {
  test(`teardown (${mode}): the watcher's child is not SIGTERMed and has ended before the sweep runs`, { timeout: 30_000 }, async () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "mandu-fsview-teardown-")));
    try {
      mkdirSync(join(root, "run"), { recursive: true });
      const script = join(root, "fake-watcher.cjs");
      writeFileSync(script, FAKE_WATCHER);
      const lock = join(root, "index.lock");
      let pgid: number | undefined;
      let lockAtSweep: boolean | undefined;
      const deps: ServiceDeps = {
        probePort, probeIdentity, waitFor, waitForFile,
        startDetachedCmd: (_cmd, _args, opts, logPath) => {
          // The layout's cwd (the dev fs-sync package under /repo) is not real here.
          const h = startDetachedCmd(process.execPath, [script, lock, mode], { ...opts, cwd: root }, logPath);
          pgid = h.pid;
          return h;
        },
        runOnce: (cmd, args) => {
          if (cmd === "git") return { status: 0, stdout: `${root}\n`, stderr: "" };
          if (args.includes("sync")) lockAtSweep = existsSync(lock);
          return { status: 0, stdout: `{"ok":true,"agentView":"${join(root, "agentview")}","synced":[]}\n`, stderr: "" };
        },
      };
      const warned: string[] = [];
      const r = await startFsView(plan(root), Layout.dev("/repo"), deps, (m) => warned.push(m));
      assert.ok(r?.eager, "the stand-in watcher was spawned");
      await r!.ready;
      assert.ok(existsSync(lock), "the watcher's child holds the lock when the teardown starts");
      await r!.stop();
      assert.equal(lockAtSweep, false, "the sweep ran after the child ended and removed its lock (never killed holding it)");
      assert.ok(pgid !== undefined && !groupAlive(pgid), "nothing of the watcher's group is left");
      assert.deepEqual(warned, [], `no teardown warning: ${warned.join(" | ")}`);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}
