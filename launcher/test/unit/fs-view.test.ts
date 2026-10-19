/**
 * fs-view.test — AgentView seeding + CWD rewrite with an injected runOnce
 * (no real git, no real fs-sync-cli). The service contract:
 *   - auto mode (fsSync undefined): non-git workspace → null (skip, raw CWD)
 *   - explicit --fs-sync: non-git workspace → throw (fail-closed)
 *   - git workspace: fs-sync-cli init → agentCwd = agentView (+ rel subdir)
 *   - stop(): fs-sync-cli sync; a sync failure WARNS (never throws)
 */
import { test } from "node:test";
import { Layout } from "../../src/services/layout.js";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ignoredSkipNote, startFsView } from "../../src/services/fs-view.js";
import type { ServiceDeps } from "../../src/services/primitives.js";
import type { LaunchPlan } from "../../src/types.js";

// A REAL temp dir (realpath'd) so the service's realpathSync on humanCwd works.
function tempWorkspace(): { root: string; sub: string; cleanup: () => void } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "mandu-fsview-")));
  const sub = join(root, "pkg", "web");
  mkdirSync(sub, { recursive: true });
  return { root, sub, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

function plan(over: Partial<LaunchPlan> = {}): LaunchPlan {
  return {
    target: "claude", argv: ["claude"], scopeId: "sid-7", tenant: "live", arbiterSock: "/run/b.sock", arbiterSockMode: "pinned" as const, arbiterRuntimeBase: "/tmp/mandu",
    eventDir: "/run/sid/events", cwd: "/w", humanCwd: "/w", basePath: "/usr/bin",
    proxy: { host: "127.0.0.1", port: 8788 }, openaiProxy: { host: "127.0.0.1", port: 8789 },
    openaiProviderName: "mandu", noProxyExtra: [],
    requested: { netProxy: false, netProxyMitm: false, execWrap: false },
    execWrapCmds: [], ullm: { mode: "cli", baseUrl: "https://api.anthropic.com", binary: "claude" },
    noContextProxy: true, fsSync: undefined,
    noScope: false, writeMcp: true, bestEffort: false, replyFilter: true, ...over,
  };
}

function deps(over: Partial<ServiceDeps> = {}): ServiceDeps {
  return {
    probePort: async () => false, probeIdentity: async () => null, waitFor: async () => true, waitForFile: async () => true,
    startDetachedCmd: () => ({ pid: 12, stop: () => {} }),
    runOnce: () => ({ status: 0, stdout: "", stderr: "" }),
    ...over,
  };
}

test("auto mode: non-git workspace → null (skip) with an informative warn", async () => {
  const warned: string[] = [];
  const r = await startFsView(plan({ humanCwd: "/definitely/not/a/repo" }), Layout.dev("/repo"),
    deps({ runOnce: (cmd) => cmd === "git"
      ? { status: 128, stdout: "", stderr: "fatal: not a git repository" }
      : { status: 0, stdout: "{}", stderr: "" } }), (m) => warned.push(m));
  assert.equal(r, null);
  assert.equal(warned.length, 1);
  assert.match(warned[0]!, /RAW CWD/);
});

test("explicit --fs-sync: non-git workspace → throws (fail-closed)", async () => {
  await assert.rejects(
    startFsView(plan({ fsSync: true, humanCwd: "/definitely/not/a/repo" }), Layout.dev("/repo"),
      deps({ runOnce: () => ({ status: 128, stdout: "", stderr: "fatal: not a git repository" }) })),
    /--fs-sync.*not inside a git repository/i,
  );
});

test("git workspace: init runs via the fs-sync package tsx and cwd becomes the AgentView", async () => {
  const ws = tempWorkspace();
  const calls: Array<{ cmd: string; args: string[]; opts: { cwd: string; env: Record<string, string | undefined>; timeoutMs?: number } }> = [];
  try {
    const r = await startFsView(plan({ humanCwd: ws.root }), Layout.dev("/repo"),
      deps({ runOnce: (cmd, args, opts) => {
        calls.push({ cmd, args, opts });
        if (cmd === "git") return { status: 0, stdout: `${ws.root}\n`, stderr: "" };
        return { status: 0, stdout: `{"ok":true,"agentView":"/dv/workspaces/x/agentview"}\n`, stderr: "" };
      } }));
    assert.ok(r);
    assert.equal(r!.agentCwd, "/dv/workspaces/x/agentview");
    // The view-map pair for the context proxy (P2): git root ↔ AgentView ROOT.
    assert.equal(r!.agentView, "/dv/workspaces/x/agentview");
    assert.equal(r!.gitRoot, ws.root);
    const init = calls[1]!;
    // node --import <the package-local tsx ESM entry>, never the tsx binary
    // (layout.ts devTsx: a --require preload dies on a symbol-twin package.json)
    assert.equal(init.cmd, "node");
    assert.deepEqual(init.args.slice(0, 3), ["--import", "file:///repo/fs-sync/node_modules/tsx/dist/esm/index.mjs", "/repo/fs-sync/src/fs-sync-cli.ts"]);
    // --session on init: seed-time mints file their births under the scope
    // (symbol-lineage.md G1).
    assert.deepEqual(init.args.slice(3), ["init", ws.root, "--session", "sid-7"], "no --state-base: fs-sync takes the home's state/ from the env");
    // Pin the init call opts: arbiter socket rides the env, cwd is the fs-sync
    // package, and the long symbolization timeout bounds the subprocess.
    assert.equal(init.opts.env["MANDU_ARBITER_SOCK"], "/run/b.sock");
    // No human plane reported (the plan's default): explicitly unset, so an
    // ambient value never points fs-sync at another arbiter's human plane.
    assert.ok("MANDU_ARBITER_HUMAN_SOCK" in init.opts.env && init.opts.env["MANDU_ARBITER_HUMAN_SOCK"] === undefined);
    assert.equal(init.opts.cwd, "/repo/fs-sync");
    assert.equal(init.opts.timeoutMs, 600_000);
  } finally { ws.cleanup(); }
});

test("the post-exit sweep runs in a session of its own (a terminal ^C cannot stop it part-way); init does not", async () => {
  const ws = tempWorkspace();
  const calls: Array<{ sub: string | undefined; ownSession: boolean | undefined }> = [];
  try {
    const r = await startFsView(plan({ humanCwd: ws.root }), Layout.dev("/repo"),
      deps({ runOnce: (cmd, args, opts) => {
        if (cmd === "git") return { status: 0, stdout: `${ws.root}\n`, stderr: "" };
        calls.push({ sub: args[3], ownSession: opts.ownSession });
        return { status: 0, stdout: `{"ok":true,"agentView":"/dv/ws/agentview"}\n`, stderr: "" };
      } }));
    await r!.stop();
    // init stays in the launcher's group: a ^C during the LAUNCH should stop it.
    assert.deepEqual(calls, [{ sub: "init", ownSession: undefined }, { sub: "sync", ownSession: true }]);
  } finally { ws.cleanup(); }
});

test("ignored files left out of the AgentView are named at launch (fs-sync.md §3.4.1)", async () => {
  const ws = tempWorkspace();
  try {
    const warns: string[] = [];
    const init = {
      ok: true, agentView: "/dv/ws/agentview",
      ignored: { enabled: true, included: 3, minted: 3, skippedCounts: { "deny-dir": 2, "too-large": 1 }, skipped: [], manifest: "/dv/ws/ignored.json" },
    };
    await startFsView(plan({ humanCwd: ws.root }), Layout.dev("/repo"),
      deps({ runOnce: (cmd) => cmd === "git"
        ? { status: 0, stdout: `${ws.root}\n`, stderr: "" }
        : { status: 0, stdout: `${JSON.stringify(init)}\n`, stderr: "" } }),
      (m) => warns.push(m));
    const line = warns.find((w) => w.includes("git-ignored"));
    assert.ok(line, "a launch line names the ignored paths left out");
    assert.match(line!, /3 git-ignored path\(s\) are NOT in the AI's working copy \(2 deny-dir, 1 too-large\)/);
    assert.match(line!, /\/dv\/ws\/ignored\.json/);
  } finally { ws.cleanup(); }
});

test("ignoredSkipNote: nothing left out, an older fs-sync, or junk gives no line", () => {
  assert.equal(ignoredSkipNote(undefined), null);
  assert.equal(ignoredSkipNote({ skippedCounts: {} }), null);
  assert.equal(ignoredSkipNote({ skippedCounts: { "deny-dir": 0, x: "2", y: -1 } }), null);
  assert.match(ignoredSkipNote({ skippedCounts: { binary: 1 } })!, /^fs-view: 1 git-ignored path\(s\)/);
});

test("launch CWD below the git root is preserved relative to the AgentView", async () => {
  const ws = tempWorkspace();
  try {
    const r = await startFsView(plan({ humanCwd: ws.sub }), Layout.dev("/repo"),
      deps({ runOnce: (cmd) => cmd === "git"
        ? { status: 0, stdout: `${ws.root}\n`, stderr: "" }
        : { status: 0, stdout: `{"ok":true,"agentView":"/dv/ws/agentview"}\n`, stderr: "" } }));
    assert.equal(r!.agentCwd, join("/dv/ws/agentview", "pkg", "web"));
  } finally { ws.cleanup(); }
});

test("init failure → throws (fail-closed)", async () => {
  const ws = tempWorkspace();
  try {
    await assert.rejects(
      startFsView(plan({ humanCwd: ws.root }), Layout.dev("/repo"),
        deps({ runOnce: (cmd) => cmd === "git"
          ? { status: 0, stdout: `${ws.root}\n`, stderr: "" }
          : { status: 1, stdout: "", stderr: "[fs-sync-cli] arbiter unreachable" } })),
      /fs-view init failed/i,
    );
  } finally { ws.cleanup(); }
});

test("init exit-0 but no agentView in the JSON → throws (fail-closed, no silent raw CWD)", async () => {
  const ws = tempWorkspace();
  try {
    await assert.rejects(
      startFsView(plan({ humanCwd: ws.root }), Layout.dev("/repo"),
        deps({ runOnce: (cmd) => cmd === "git"
          ? { status: 0, stdout: `${ws.root}\n`, stderr: "" }
          : { status: 0, stdout: `{"ok":true}\n`, stderr: "" } })),
      /no agentView path/i,
    );
  } finally { ws.cleanup(); }
});

test("init exit-0 but unparseable stdout → throws (fail-closed)", async () => {
  const ws = tempWorkspace();
  try {
    await assert.rejects(
      startFsView(plan({ humanCwd: ws.root }), Layout.dev("/repo"),
        deps({ runOnce: (cmd) => cmd === "git"
          ? { status: 0, stdout: `${ws.root}\n`, stderr: "" }
          : { status: 0, stdout: "not-json\n", stderr: "" } })),
      /unparseable JSON/i,
    );
  } finally { ws.cleanup(); }
});

test("stop() runs fs-sync-cli sync; a sync failure warns but does not throw", async () => {
  const ws = tempWorkspace();
  const warned: string[] = [];
  try {
    let phase = 0;
    const r = await startFsView(plan({ humanCwd: ws.root }), Layout.dev("/repo"),
      deps({ runOnce: (cmd, args) => {
        if (cmd === "git") return { status: 0, stdout: `${ws.root}\n`, stderr: "" };
        phase++;
        if (phase === 1) return { status: 0, stdout: `{"ok":true,"agentView":"/dv/ws/agentview"}\n`, stderr: "" };
        assert.equal(args[3], "sync");            // the post-exit call is sync
        assert.deepEqual(args.slice(-2), ["--tool", "launcher"]);
        return { status: 1, stdout: "", stderr: "sync exploded" };
      } }), (m) => warned.push(m));
    await r!.stop();                              // must NOT throw
    assert.equal(warned.length, 1);
    assert.match(warned[0]!, /sync-back FAILED/);
  } finally { ws.cleanup(); }
});

// ── --fs-sync-eager: the resident watcher (fs-sync.md §2 Phase 1) ────────

/** deps.runOnce that satisfies the git probe + init happy path. */
function happyRunOnce(gitRoot: string): ServiceDeps["runOnce"] {
  return (cmd) => cmd === "git"
    ? { status: 0, stdout: `${gitRoot}\n`, stderr: "" }
    : { status: 0, stdout: `{"ok":true,"agentView":"/dv/ws/agentview"}\n`, stderr: "" };
}

test("eager OFF (default): no watcher is spawned", async () => {
  const ws = tempWorkspace();
  const spawned: string[] = [];
  try {
    const r = await startFsView(plan({ humanCwd: ws.root }), Layout.dev("/repo"),
      deps({
        runOnce: happyRunOnce(ws.root),
        startDetachedCmd: (cmd) => { spawned.push(cmd); return { pid: 12, stop: () => {} }; },
      }));
    assert.ok(r);
    assert.equal(r!.eager, false);
    assert.equal(spawned.length, 0, "no watcher without --fs-sync-eager");
  } finally { ws.cleanup(); }
});

test("eager ON: watcher spawned as node --import tsx `watch` with session, arbiter sock in env", async () => {
  const ws = tempWorkspace();
  const calls: Array<{ cmd: string; args: string[]; opts: { cwd: string; env: Record<string, string | undefined> }; logPath: string }> = [];
  try {
    const r = await startFsView(
      plan({ humanCwd: ws.root, fsSyncEager: true, eventDir: "/run/sid-7/events" }), Layout.dev("/repo"),
      deps({
        runOnce: happyRunOnce(ws.root),
        startDetachedCmd: (cmd, args, opts, logPath) => { calls.push({ cmd, args, opts, logPath }); return { pid: 12, stop: () => {} }; },
      }));
    assert.ok(r);
    assert.equal(r!.eager, true, "the result reports the eager watcher (truth-in-labeling)");
    assert.equal(calls.length, 1);
    const w = calls[0]!;
    // Single-process node --import <tsx esm> (NOT the tsx wrapper — SIGTERM semantics).
    assert.equal(w.cmd, "node");
    assert.deepEqual(w.args, [
      "--import", "file:///repo/fs-sync/node_modules/tsx/dist/esm/index.mjs", "/repo/fs-sync/src/fs-sync-cli.ts",
      "watch", ws.root, "--session", "sid-7",
    ]);
    assert.equal(w.opts.cwd, "/repo/fs-sync");
    assert.equal(w.opts.env["MANDU_ARBITER_SOCK"], "/run/b.sock");
    assert.equal(w.logPath, "/run/sid-7/fs-sync-watch.log");
  } finally { ws.cleanup(); }
});

test("eager ON but the watcher spawn throws → warn + DEGRADE (launch continues, sweep-only)", async () => {
  const ws = tempWorkspace();
  const warned: string[] = [];
  try {
    const r = await startFsView(plan({ humanCwd: ws.root, fsSyncEager: true }), Layout.dev("/repo"),
      deps({
        runOnce: happyRunOnce(ws.root),
        startDetachedCmd: () => { throw new Error("spawn exploded"); },
      }), (m) => warned.push(m));
    assert.ok(r, "the fs rung itself stays up");
    assert.equal(r!.eager, false);
    assert.equal(r!.agentCwd, "/dv/ws/agentview");
    assert.ok(warned.some((m) => /eager watcher failed to start/.test(m) && /post-exit sweep/.test(m)));
  } finally { ws.cleanup(); }
});

test("eager ON but the watcher never confirms ready → warn, keep it running, launch continues", async () => {
  const ws = tempWorkspace();
  const warned: string[] = [];
  const stops: number[] = [];
  try {
    const r = await startFsView(plan({ humanCwd: ws.root, fsSyncEager: true }), Layout.dev("/repo"),
      deps({
        runOnce: happyRunOnce(ws.root),
        waitFor: async () => false, // ready line never shows
        startDetachedCmd: () => ({ pid: 12, stop: () => { stops.push(12); } }),
      }), (m) => warned.push(m));
    assert.ok(r);
    assert.ok(warned.some((m) => /not confirmed ready/.test(m)));
    assert.equal(stops.length, 0, "a slow watcher is left running (it may still come up)");
  } finally { ws.cleanup(); }
});

test("stop() tears the watcher down BEFORE the post-exit sweep (which stays unconditional)", async () => {
  const ws = tempWorkspace();
  const order: string[] = [];
  try {
    const r = await startFsView(plan({ humanCwd: ws.root, fsSyncEager: true }), Layout.dev("/repo"),
      deps({
        runOnce: (cmd, args) => {
          if (cmd === "git") return { status: 0, stdout: `${ws.root}\n`, stderr: "" };
          if (args[3] === "sync") order.push("sweep");
          return { status: 0, stdout: `{"ok":true,"agentView":"/dv/ws/agentview","synced":[]}\n`, stderr: "" };
        },
        startDetachedCmd: () => ({ pid: 12, stop: () => order.push("group-stop"), stopLeader: () => order.push("leader-stop") }),
      }));
    await r!.stop();
    // The watcher alone is SIGTERMed, never its group: a git it runs that is
    // SIGTERMed can leave the AgentView's index.lock behind (fs-sync.md §2.4a).
    assert.deepEqual(order, ["leader-stop", "sweep"], "watcher teardown precedes the sweep");
  } finally { ws.cleanup(); }
});

test("stop(): a watcher that will not exit warns, and the sweep still runs (catch-all)", async () => {
  const ws = tempWorkspace();
  const warned: string[] = [];
  const order: string[] = [];
  try {
    let waits = 0;
    const r = await startFsView(plan({ humanCwd: ws.root, fsSyncEager: true }), Layout.dev("/repo"),
      deps({
        runOnce: (cmd, args) => {
          if (cmd === "git") return { status: 0, stdout: `${ws.root}\n`, stderr: "" };
          if (args[3] === "sync") order.push("sweep");
          return { status: 0, stdout: `{"ok":true,"agentView":"/dv/ws/agentview","synced":[]}\n`, stderr: "" };
        },
        // First waitFor = readiness (true); the exit-waits after it false (wedged).
        waitFor: async () => ++waits === 1,
        startDetachedCmd: () => ({ pid: 12, stop: () => order.push("group-stop"), stopLeader: () => order.push("leader-stop") }),
      }), (m) => warned.push(m));
    await r!.stop();
    assert.ok(warned.some((m) => /did not exit after SIGTERM/.test(m)));
    assert.deepEqual(order, ["leader-stop", "group-stop", "sweep"], "a wedged watcher's group is SIGTERMed whole, and the sweep ran anyway");
  } finally { ws.cleanup(); }
});

test("human plane: fs-sync's init and watch get the arbiter's human socket (it resolves and desymbolizes there), the data socket unchanged", async () => {
  const ws = tempWorkspace();
  const calls: Array<{ cmd: string; opts: { env: Record<string, string | undefined> } }> = [];
  try {
    await startFsView(plan({ humanCwd: ws.root, arbiterHumanSock: "/run/mandu/human/i.sock" }), Layout.dev("/repo"),
      deps({
        runOnce: (cmd, _args, opts) => {
          calls.push({ cmd, opts });
          if (cmd === "git") return { status: 0, stdout: `${ws.root}\n`, stderr: "" };
          return { status: 0, stdout: `{"ok":true,"agentView":"/dv/workspaces/x/agentview"}\n`, stderr: "" };
        },
        startDetachedCmd: (cmd, _args, opts) => { calls.push({ cmd, opts }); return { pid: 12, stop: () => {} }; },
      }));
    const fsSyncCalls = calls.filter((c) => c.cmd !== "git");
    assert.ok(fsSyncCalls.length >= 1);
    for (const c of fsSyncCalls) {
      assert.equal(c.opts.env["MANDU_ARBITER_HUMAN_SOCK"], "/run/mandu/human/i.sock");
      assert.equal(c.opts.env["MANDU_ARBITER_SOCK"], "/run/b.sock");
    }
  } finally { ws.cleanup(); }
});

test("the work-tree probe runs HARDENED git (docs/design/architecture/write-protection.md): the forced config, no inherited GIT_*", async () => {
  const seen: Array<{ args: string[]; env: Record<string, string | undefined> }> = [];
  const saved = process.env["GIT_DIR"];
  process.env["GIT_DIR"] = "/elsewhere/.git";
  try {
    await startFsView(plan({ humanCwd: "/definitely/not/a/repo" }), Layout.dev("/repo"),
      deps({ runOnce: (cmd, args, opts) => {
        if (cmd === "git") seen.push({ args, env: opts.env });
        return { status: 128, stdout: "", stderr: "fatal: not a git repository" };
      } }), () => {});
  } finally {
    if (saved === undefined) delete process.env["GIT_DIR"]; else process.env["GIT_DIR"] = saved;
  }
  assert.equal(seen.length, 1);
  const { args, env } = seen[0]!;
  assert.deepEqual(args.slice(-4), ["-C", "/definitely/not/a/repo", "rev-parse", "--show-toplevel"]);
  for (const kv of ["core.fsmonitor=false", "log.showSignature=false", "protocol.allow=never"]) assert.ok(args.includes(kv), `${kv} forced`);
  assert.ok(args.includes("--no-pager"));
  assert.equal(env["GIT_DIR"], undefined, "an inherited GIT_DIR does not reach git");
  assert.equal(env["GIT_NO_LAZY_FETCH"], "1");
});
