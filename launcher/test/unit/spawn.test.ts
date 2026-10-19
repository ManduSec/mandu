/**
 * spawn.test — buildFinalArgv composes scope/launch/agent argv correctly;
 * runAgent propagates the child's exit code and runs postExit.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildFinalArgv, runAgent, treeTeardownNote } from "../../src/spawn.js";
import { tmpDir } from "../lib/tmp-dir.js";

test("buildFinalArgv: scope.prefix, then launchPrefix, then argv[0] + splice + rest", () => {
  const argv = buildFinalArgv(
    ["claude", "--flag"],
    ["-c", "model_provider=mandu"],
    { prefix: ["systemd-run", "--user", "--scope", "--"], detached: false },
    ["unshare", "--user"],
  );
  assert.deepEqual(argv, [
    "systemd-run", "--user", "--scope", "--",
    "unshare", "--user",
    "claude", "-c", "model_provider=mandu", "--flag",
  ]);
});

test("buildFinalArgv: goose's --with-extension flags go after `session` / `run` (the subcommand's flags; Goose's top level takes none)", () => {
  const ext = ["--with-extension", "mandu-inspect:/n /s.mjs"];
  assert.deepEqual(buildFinalArgv(["/usr/bin/goose", "session", "-r"], ext, { prefix: [], detached: true }, ["guard", "--"]),
    ["guard", "--", "/usr/bin/goose", "session", ...ext, "-r"]);
  assert.deepEqual(buildFinalArgv(["goose", "--version"], ext, { prefix: [], detached: true }, []), ["goose", "--version"]);
});

test("buildFinalArgv: empty prefixes → just agent argv with splice (codex: after argv[0] AND after the subcommand)", () => {
  assert.deepEqual(
    buildFinalArgv(["codex", "exec"], ["-c", "x"], { prefix: [], detached: true }, []),
    ["codex", "-c", "x", "exec", "-c", "x"],
  );
});

test("buildFinalArgv: a user's exec-level -c no longer drops the routing overrides", () => {
  // codex 0.154: the innermost -c list replaces the outer ones (codex-argv.ts).
  assert.deepEqual(
    buildFinalArgv(["codex", "exec", "-c", "model_reasoning_effort=low", "hi"], ["-c", "model_provider=mandu"], { prefix: [], detached: true }, []),
    ["codex", "-c", "model_provider=mandu", "exec", "-c", "model_provider=mandu", "-c", "model_reasoning_effort=low", "hi"],
  );
});

test("runAgent propagates the child exit code and runs postExit", async () => {
  let posted = false;
  const code = await runAgent({
    argv: ["bash", "-c", "exit 7"],
    env: { ...process.env },
    cwd: process.cwd(),
    detached: false,
    postExit: async () => { posted = true; },
  });
  assert.equal(code, 7);
  assert.equal(posted, true);
});

test("runAgent stdioRelay: the chain gets piped stdin / stdout handed to the relay (goose acp)", async () => {
  let out = "";
  const code = await runAgent({
    argv: ["bash", "-c", "read line; echo \"got:$line\""],
    env: { ...process.env }, cwd: process.cwd(), detached: false,
    stdioRelay: ({ stdin, stdout }) => {
      stdout.setEncoding("utf8");
      stdout.on("data", (c: string) => (out += c));
      stdin.end("hello\n");
    },
  });
  assert.equal(code, 0);
  assert.equal(out, "got:hello\n");
});

test("runAgent runs postExit even when the child is killed by a signal", async () => {
  let posted = false;
  const code = await runAgent({
    argv: ["bash", "-c", "kill -TERM $$"],
    env: { ...process.env }, cwd: process.cwd(), detached: false,
    postExit: async () => { posted = true; },
  });
  assert.ok(code >= 128, `signal death maps to 128+signo, got ${code}`);
  assert.equal(posted, true);
});

test("runAgent forwards SIGWINCH to the DETACHED child's whole process group (a grandchild behind a non-relaying wrapper sees it)", async () => {
  // The child is a wrapper that does NOT relay SIGWINCH (like tsx); its
  // grandchild traps WINCH and reports. Only a GROUP signal reaches it.
  // wrapper: a no-op WINCH handler (NOT SIG_IGN — an ignored disposition is
  // inherited across exec and a child could not trap it) that does not relay;
  // it re-waits when its own trap interrupts `wait`. grandchild: traps WINCH
  // while blocked in an interruptible `wait` and exits 0, else times out 3.
  const chunks: string[] = [];
  // Observe the grandchild's report through a file instead of the inherited tty.
  const { readFileSync, existsSync } = await import("node:fs");
  const { join } = await import("node:path");
  const dir = tmpDir("mandu-winch-");
  const out = join(dir, "out.txt");
  // The grandchild touches READY only once its WINCH trap is installed. The
  // signal is sent after that, never on a fixed delay: under a loaded full
  // suite a 700 ms timer fired before the trap existed, the default WINCH
  // disposition (ignore) swallowed it, and the grandchild timed out.
  const ready = join(dir, "ready");
  // The grandchild records its OWN exit status in a file; the wrapper exits
  // with it. Not from `wait`: when the wrapper's trap interrupts `wait` just
  // as the grandchild exits, bash can lose the child's status (the next
  // `wait $p` returns -1, exit 255), and the old loop exited with the
  // interrupted wait's 156 instead. Both were this test's load flake (seen
  // under 16 parallel copies: 36/48 and 40/48 passes), never the forwarding.
  const status = join(dir, "status");
  // mkdtemp paths are bare (no space or quote), so they sit unquoted inside
  // the nested quoting of the grandchild's trap.
  assert.match(dir, /^[A-Za-z0-9._/-]+$/, "a bare temp path");
  const script =
    "trap ':' WINCH; " +
    // The trap also stops the grandchild's own `sleep`, which would otherwise
    // outlive the test in the agent's detached group (the suite runner's
    // stray check, test-organization.md §8.5); READY comes once it runs.
    `sh -c 'trap "kill \\$s 2>/dev/null; echo GRANDCHILD_WINCH; echo 0 > ${status}; exit 0" WINCH; sleep 10 & s=$!; : > ${ready}; wait $s; echo GRANDCHILD_TIMEOUT; echo 3 > ${status}; exit 3' & p=$!; ` +
    // Wait until the grandchild is gone (the trap may interrupt any `wait`),
    // then exit with the status it wrote (4 = it wrote none).
    `while kill -0 $p 2>/dev/null; do wait $p; done; exit $(cat ${status} 2>/dev/null || echo 4)`;
  let sent = false;
  const poll = setInterval(() => {
    if (!sent && existsSync(ready)) {
      sent = true;
      process.kill(process.pid, "SIGWINCH");
    }
  }, 20);
  const code = await runAgent({
    argv: ["bash", "-c", `{ ${script}; } > ${JSON.stringify(out)} 2>&1`],
    env: { ...process.env }, cwd: process.cwd(), detached: true,
  });
  clearInterval(poll);
  assert.equal(sent, true, "the grandchild reported its trap ready");
  const report = readFileSync(out, "utf8");
  chunks.push(report);
  assert.equal(code, 0, `grandchild should exit 0 on WINCH, got ${code}: ${report}`);
  assert.match(report, /GRANDCHILD_WINCH/);
});

test("runAgent arms the teardown guard once the chain exits, BEFORE postExit, so a ^C in the teardown is swallowed", async () => {
  const { createTeardownGuard } = await import("../../src/teardown-signals.js");
  const order: string[] = [];
  const notes: string[] = [];
  const guard = createTeardownGuard({ note: (l) => notes.push(l) });
  const teardown = { arm: () => { order.push("arm"); guard.arm(); } };
  let sigintListenersInTeardown = -1;
  try {
    const code = await runAgent({
      argv: ["bash", "-c", "exit 5"],
      env: { ...process.env }, cwd: process.cwd(), detached: false,
      teardown,
      onChainExit: () => { order.push("chain-exit"); },
      postExit: async () => {
        order.push("postExit");
        // Only the guard is left listening: the agent-run forwarders are off.
        sigintListenersInTeardown = process.listeners("SIGINT").length;
        process.emit("SIGINT", "SIGINT"); // what a ^C would dispatch
      },
    });
    assert.equal(code, 5, "the agent's code, untouched by the ^C");
  } finally {
    guard.disarm();
  }
  assert.deepEqual(order, ["chain-exit", "arm", "postExit"]);
  assert.equal(sigintListenersInTeardown, 1);
  assert.equal(guard.presses, 1);
  assert.equal(notes.length, 1);
});

// ── the agent-tree teardown hook (portable-wrapper-cross-platform.md §3.5) ────

test("runAgent: the tree is tracked from the spawn and ended after the chain exits, BEFORE onChainExit and postExit", async () => {
  const order: string[] = [];
  let tracked: number | undefined;
  let stops = 0;
  const code = await runAgent({
    argv: ["bash", "-c", "exit 3"],
    env: { ...process.env }, cwd: process.cwd(), detached: true,
    tree: {
      track: (pid) => {
        tracked = pid;
        order.push("track");
        return { rootPid: pid, sample: async () => {}, stop: async () => { stops++; } };
      },
      end: async (t) => {
        order.push(`end:${t.rootPid === tracked}`);
        return { terminated: [], killed: [], survivors: [] };
      },
    },
    onChainExit: (pid) => { order.push(`chainExit:${pid === tracked}`); },
    postExit: async () => { order.push("postExit"); },
  });
  assert.equal(code, 3, "the exit code is the chain's");
  assert.ok(typeof tracked === "number" && tracked > 0, "track got the chain's first pid");
  assert.deepEqual(order, ["track", "end:true", "chainExit:true", "postExit"]);
  assert.ok(stops >= 1, "the tracker is stopped before postExit");
});

test("runAgent: a teardown that throws (or a tracker that cannot start) never costs the exit code or postExit", async () => {
  let posted = 0;
  const failingEnd = await runAgent({
    argv: ["bash", "-c", "exit 5"], env: { ...process.env }, cwd: process.cwd(), detached: true,
    tree: {
      track: (pid) => ({ rootPid: pid, sample: async () => {}, stop: async () => { throw new Error("stop failed"); } }),
      end: async () => { throw new Error("ps failed"); },
    },
    postExit: async () => { posted++; },
  });
  assert.equal(failingEnd, 5);
  let ended = false;
  const failingTrack = await runAgent({
    argv: ["bash", "-c", "exit 6"], env: { ...process.env }, cwd: process.cwd(), detached: true,
    tree: {
      track: () => { throw new Error("cannot track"); },
      end: async () => { ended = true; return { terminated: [], killed: [], survivors: [] }; },
    },
    postExit: async () => { posted++; },
  });
  assert.equal(failingTrack, 6);
  assert.equal(ended, false, "no tree, nothing to end");
  assert.equal(posted, 2);
});

test("runAgent prints ONE line when the teardown stopped something, and nothing when it did not", async () => {
  const lines: string[] = [];
  const orig = console.error;
  console.error = (...a: unknown[]) => { lines.push(a.map(String).join(" ")); };
  try {
    for (const terminated of [[], [101, 102]]) {
      await runAgent({
        argv: ["bash", "-c", "exit 0"], env: { ...process.env }, cwd: process.cwd(), detached: true,
        tree: {
          track: (pid) => ({ rootPid: pid, sample: async () => {}, stop: async () => {} }),
          end: async () => ({ terminated, killed: [], survivors: [] }),
        },
      });
    }
  } finally {
    console.error = orig;
  }
  assert.deepEqual(lines, ["mandu: the session ended, so 2 processes the agent left running were stopped (pid 101, 102)"]);
});

test("treeTeardownNote: singular/plural, at most five pids, and the unkillable named", () => {
  assert.equal(treeTeardownNote({ terminated: [], killed: [], survivors: [] }), null);
  assert.equal(
    treeTeardownNote({ terminated: [7], killed: [], survivors: [] }),
    "mandu: the session ended, so 1 process the agent left running was stopped (pid 7)",
  );
  assert.equal(
    treeTeardownNote({ terminated: [1, 2, 3, 4, 5, 6], killed: [6], survivors: [6] }),
    "mandu: the session ended, so 6 processes the agent left running were stopped (pid 1, 2, 3, 4, 5, …); 1 could not be stopped (pid 6)",
  );
});


test("runAgent: an already-exited adopted chain still ends its tracked tree and runs post-exit hooks", async () => {
  const { spawn } = await import("node:child_process");
  const { childExit } = await import("../../src/spawn.js");
  const child = spawn(process.execPath, ["-e", "process.exit(7)"], { stdio: "ignore" });
  const exit = childExit(child);
  assert.equal(await exit, 7, "the early reply-filter chain already exited before adoption");
  const order: string[] = [];
  const spawnedAtMs = Date.now() - 8_000;
  const code = await runAgent({
    argv: ["does-not-exist"], adopted: { child, exit, spawnedAtMs },
    env: process.env, cwd: process.cwd(), detached: false,
    tree: {
      track: (pid, sinceMs) => {
        assert.equal(pid, child.pid);
        // The age floor is the adopted chain's own spawn, not the adoption
        // (else on macOS the whole tree reads as older than the launch).
        assert.equal(sinceMs, spawnedAtMs);
        order.push("track");
        return { rootPid: pid, sample: async () => {}, stop: async () => { order.push("stop"); } };
      },
      end: async () => { order.push("end"); return { terminated: [], killed: [], survivors: [] }; },
    },
    onChainExit: (pid) => { assert.equal(pid, child.pid); order.push("chainExit"); },
    postExit: async () => { order.push("postExit"); },
  });
  assert.equal(code, 7, "adoption preserves the early chain's real status");
  assert.deepEqual(order, ["track", "end", "chainExit", "stop", "postExit"]);
});
