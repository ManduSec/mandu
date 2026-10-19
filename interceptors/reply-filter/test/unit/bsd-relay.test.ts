/**
 * bsd-relay.test — unit tests for the macOS PTY relay companion
 * (src/bsd-relay.ts): locating BSD script's child and its pty slave in a `ps`
 * snapshot, the stty argv that re-sizes it, the exit-status mapping, and the
 * companion's schedule (poll until located, coalesced resizes, signals to the
 * child, nothing after dispose) over injected process steps. The real steps
 * (a real outer terminal, BSD script, stty) are proven end to end on darwin by
 * test/component/bsd-relay.test.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  BsdRelayCompanion,
  parseRelayedChild,
  realBsdRelayDeps,
  relayExitCode,
  sttyResizeArgv,
  type BsdRelayDeps,
} from "../../src/bsd-relay.js";

/** A `ps -A -o pid=,ppid=,tty=` snapshot, in ps's column layout. */
function ps(rows: Array<[number, number, string]>): string {
  return rows.map(([pid, ppid, tty]) => `${String(pid).padStart(5)} ${String(ppid).padStart(5)} ${tty.padEnd(8)}`).join("\n") + "\n";
}

const SCRIPT = 4100;
const CHILD = 4101;
const NOT_FORKED = ps([[1, 0, "??"], [4000, 1, "??"], [SCRIPT, 4000, "??"]]);
const PRE_LOGIN = ps([[1, 0, "??"], [SCRIPT, 4000, "??"], [CHILD, SCRIPT, "??"]]);
const LOCATED = ps([[1, 0, "??"], [SCRIPT, 4000, "??"], [CHILD, SCRIPT, "ttys007"], [4200, CHILD, "ttys007"]]);

test("parseRelayedChild names script's child and its pty slave once login_tty has run", () => {
  assert.deepEqual(parseRelayedChild(LOCATED, SCRIPT), { pid: CHILD, tty: "/dev/ttys007" });
  // The grandchild on the same tty is not script's child.
  assert.equal(parseRelayedChild(LOCATED, CHILD)?.pid, 4200);
});

test("parseRelayedChild: no child yet → null; forked but not on its pty yet → pid only", () => {
  assert.equal(parseRelayedChild(NOT_FORKED, SCRIPT), null);
  assert.deepEqual(parseRelayedChild(PRE_LOGIN, SCRIPT), { pid: CHILD, tty: null });
  assert.equal(parseRelayedChild("", SCRIPT), null);
});

test("parseRelayedChild never names the human's terminal: a child still on script's tty is not located", () => {
  // Before login_tty the forked child carries script's controlling terminal —
  // the human's, when the reply-filter has one. Resizing THAT would be wrong.
  const onHumansTty = ps([[SCRIPT, 4000, "ttys001"], [CHILD, SCRIPT, "ttys001"]]);
  assert.deepEqual(parseRelayedChild(onHumansTty, SCRIPT), { pid: CHILD, tty: null });
  const onItsOwn = ps([[SCRIPT, 4000, "ttys001"], [CHILD, SCRIPT, "ttys009"]]);
  assert.deepEqual(parseRelayedChild(onItsOwn, SCRIPT), { pid: CHILD, tty: "/dev/ttys009" });
});

test("parseRelayedChild only turns pty slave names into device paths", () => {
  for (const tty of ["console", "../ttys1", "ttys", "ttys1x", "-", "/dev/ttys003"]) {
    assert.deepEqual(parseRelayedChild(ps([[SCRIPT, 1, "??"], [CHILD, SCRIPT, tty]]), SCRIPT), { pid: CHILD, tty: null }, tty);
  }
  assert.equal(parseRelayedChild(ps([[SCRIPT, 1, "??"], [CHILD, SCRIPT, "pts/3"]]), SCRIPT)?.tty, "/dev/pts/3");
});

test("parseRelayedChild skips malformed lines and takes the first child", () => {
  const out = [
    "garbage",
    "  x  4100 ttys002",
    `${CHILD} ${SCRIPT}`,
    ` ${CHILD}  ${SCRIPT} ttys002 `,
    ` 4102  ${SCRIPT} ttys003`,
  ].join("\n");
  assert.deepEqual(parseRelayedChild(out, SCRIPT), { pid: CHILD, tty: "/dev/ttys002" });
});

test("sttyResizeArgv is BSD stty -f <dev> rows R cols C, and refuses what a winsize cannot carry", () => {
  assert.deepEqual(sttyResizeArgv("/dev/ttys007", 40, 120), ["-f", "/dev/ttys007", "rows", "40", "cols", "120"]);
  for (const [r, c] of [[0, 80], [24, 0], [-1, 80], [24, 70000], [Number.NaN, 80], [24.5, 80]] as const) {
    assert.equal(sttyResizeArgv("/dev/ttys007", r, c), null, `${r}x${c}`);
  }
});

test("relayExitCode: 128+n only for the number of a signal the relay delivered", () => {
  const term = new Set([15]);
  assert.equal(relayExitCode(15, term), 143, "the child died by the SIGTERM we sent: script said 15");
  assert.equal(relayExitCode(9, term), 9, "a normal `exit 9` (or a SIGKILL from elsewhere) stays 9");
  assert.equal(relayExitCode(0, term), 0, "the child caught SIGTERM and exited cleanly");
  assert.equal(relayExitCode(null, term), null);
  assert.equal(relayExitCode(15, new Set()), 15, "no signal delivered → never remapped");
});

// ── the companion over fake process steps ─────────────────────────────────────

interface Fake extends BsdRelayDeps {
  snapshots: string[];
  winsizes: Array<[string, number, number]>;
  kills: Array<[number, NodeJS.Signals]>;
  psCalls: number;
  /** Resolve the in-flight setWinsize (when `holdWinsize` is on). */
  release(): void;
}

function fakeDeps(snapshots: string[], opts: { holdWinsize?: boolean; killThrows?: boolean } = {}): Fake {
  const pending: Array<() => void> = [];
  const f: Fake = {
    snapshots,
    winsizes: [],
    kills: [],
    psCalls: 0,
    release: () => pending.shift()?.(),
    psSnapshot: async () => {
      f.psCalls++;
      // The last snapshot repeats (the process table does not change).
      return f.snapshots.length > 1 ? f.snapshots.shift()! : (f.snapshots[0] ?? "");
    },
    setWinsize: async (dev, rows, cols) => {
      f.winsizes.push([dev, rows, cols]);
      if (opts.holdWinsize) await new Promise<void>((r) => pending.push(r));
      return true;
    },
    kill: (pid, sig) => {
      if (opts.killThrows) throw Object.assign(new Error("kill ESRCH"), { code: "ESRCH" });
      f.kills.push([pid, sig]);
    },
    sleep: async () => {},
  };
  return f;
}

/** Let the companion's promise chains settle. */
async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
}

test("the companion polls until the child is on its pty, then re-sizes THAT pty (rows, cols)", async () => {
  const deps = fakeDeps([NOT_FORKED, PRE_LOGIN, LOCATED]);
  const c = new BsdRelayCompanion(SCRIPT, deps, [0, 1, 1, 1]);
  c.start();
  c.resize(120, 40);
  await settle();
  assert.equal(deps.psCalls, 3, "three snapshots: not forked, pre-login_tty, located");
  assert.deepEqual(deps.winsizes, [["/dev/ttys007", 40, 120]]);
  assert.equal(c.childPid, CHILD);
  // Once located, a resize needs no new snapshot.
  c.resize(100, 30);
  await settle();
  assert.equal(deps.psCalls, 3);
  assert.deepEqual(deps.winsizes.at(-1), ["/dev/ttys007", 30, 100]);
});

test("resizes coalesce: one stty in flight, and only the latest size follows it", async () => {
  const deps = fakeDeps([LOCATED], { holdWinsize: true });
  const c = new BsdRelayCompanion(SCRIPT, deps, [0]);
  c.resize(90, 30);
  await settle();
  assert.equal(deps.winsizes.length, 1, "the first request is applying");
  c.resize(100, 31);
  c.resize(110, 32);
  c.resize(120, 40);
  await settle();
  assert.equal(deps.winsizes.length, 1, "nothing starts while one is in flight");
  deps.release();
  await settle();
  assert.deepEqual(deps.winsizes, [["/dev/ttys007", 30, 90], ["/dev/ttys007", 40, 120]], "the latest size wins");
  deps.release();
  await settle();
  assert.equal(deps.winsizes.length, 2);
});

test("a child that never reaches its pty is never resized; a later request polls again", async () => {
  const deps = fakeDeps([PRE_LOGIN]);
  const c = new BsdRelayCompanion(SCRIPT, deps, [0, 1, 1]);
  c.resize(120, 40);
  await settle();
  assert.equal(deps.psCalls, 3, "the whole schedule, then give up");
  assert.deepEqual(deps.winsizes, []);
  deps.snapshots = [LOCATED];
  c.resize(120, 40);
  await settle();
  assert.deepEqual(deps.winsizes, [["/dev/ttys007", 40, 120]], "the second request located it");
});

test("a failing ps snapshot is retried on the schedule, not fatal", async () => {
  const deps = fakeDeps([LOCATED]);
  let failures = 2;
  const real = deps.psSnapshot;
  deps.psSnapshot = async () => {
    if (failures-- > 0) throw new Error("ps: timed out");
    return real();
  };
  const c = new BsdRelayCompanion(SCRIPT, deps, [0, 1, 1, 1]);
  c.resize(120, 40);
  await settle();
  assert.deepEqual(deps.winsizes, [["/dev/ttys007", 40, 120]]);
});

test("signals go to the relayed child once its pid is known; before that the caller falls back to script", async () => {
  const deps = fakeDeps([NOT_FORKED, PRE_LOGIN]);
  const c = new BsdRelayCompanion(SCRIPT, deps, [0, 1]);
  assert.equal(c.signal("SIGTERM"), false, "not located yet → the caller signals script");
  assert.equal(c.exitCode(15), 15, "nothing delivered → nothing remapped");
  c.start();
  await settle();
  // The pre-login_tty snapshot already names the pid: enough for a signal.
  assert.equal(c.signal("SIGTERM"), true);
  assert.deepEqual(deps.kills, [[CHILD, "SIGTERM"]]);
  assert.equal(c.exitCode(15), 143, "script's bare 15 after our SIGTERM is a SIGTERM death");
  assert.equal(c.exitCode(1), 1, "an unrelated exit code is left alone");
  assert.equal(c.signal("SIGHUP"), true);
  assert.equal(c.exitCode(1), 129);
});

test("a signal the kernel refuses (child already gone) is not recorded and reports false", async () => {
  const deps = fakeDeps([LOCATED], { killThrows: true });
  const c = new BsdRelayCompanion(SCRIPT, deps, [0]);
  c.start();
  await settle();
  assert.equal(c.signal("SIGINT"), false);
  assert.equal(c.exitCode(2), 2);
});

test("after dispose nothing reaches the pty or the pid (their names may be reused)", async () => {
  const deps = fakeDeps([LOCATED]);
  const c = new BsdRelayCompanion(SCRIPT, deps, [0]);
  c.start();
  await settle();
  c.dispose();
  c.resize(120, 40);
  await settle();
  assert.deepEqual(deps.winsizes, []);
  assert.equal(c.signal("SIGTERM"), false);
  assert.deepEqual(deps.kills, []);
});

test("dispose during the locate schedule stops the polling", async () => {
  const deps = fakeDeps([NOT_FORKED]);
  let slept = 0;
  deps.sleep = async () => {
    slept++;
    if (slept === 2) c.dispose();
  };
  const c = new BsdRelayCompanion(SCRIPT, deps, [0, 1, 1, 1, 1, 1]);
  c.resize(120, 40);
  await settle();
  assert.equal(deps.psCalls, 2, "no snapshot after the dispose");
  assert.deepEqual(deps.winsizes, []);
});

test("the real ps snapshot parses on this host (darwin: the companion's platform)", { skip: process.platform !== "darwin" && "macOS only" }, async () => {
  // Our own line: pid, ppid = the test runner, tty = whatever it is. The
  // parser keyed on our PARENT must name us as its child.
  const snap = await realBsdRelayDeps().psSnapshot();
  const me = parseRelayedChild(snap, process.ppid);
  assert.ok(me !== null, "the snapshot lists this process as its parent's child");
  const mine = snap.split("\n").some((l) => l.trim().split(/\s+/)[0] === String(process.pid));
  assert.ok(mine, "this process is in the snapshot");
});
