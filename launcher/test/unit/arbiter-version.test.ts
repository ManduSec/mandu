/**
 * arbiter-version.test — the launcher never uses an arbiter of another Mandu
 * release (runtime-instances.md §4.1; reply-row-reservation.md §18.6).
 *
 * Pure decisions (versionVerdict, skewAction, afterRestartRefusal), the
 * driver over injected effects (checkArbiterRelease), and the process side
 * (liveLaunchersOn, stopStackAndWait) over a mock process table. Nothing is
 * spawned or signalled.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  afterRestartRefusal, checkArbiterRelease, skewAction, versionVerdict,
  type SkewInput, type VersionVerdict,
} from "../../src/arbiter-version.js";
import { liveLaunchersOn, stopStackAndWait, type Proc, type ProcOps } from "../../src/subcommands.js";

const OURS = "0.2.0-beta.6";
const REAL = { pid: 4242, protocolVersion: 1, gitRev: "abc1234" };

test("versionVerdict: same release matches; another is older, newer or not comparable", () => {
  assert.deepEqual(versionVerdict(OURS, { ...REAL, version: OURS }), { kind: "match", theirs: OURS });
  assert.deepEqual(versionVerdict(OURS, { ...REAL, version: "0.2.0-beta.5" }), { kind: "older", theirs: "0.2.0-beta.5" });
  assert.deepEqual(versionVerdict(OURS, { ...REAL, version: "0.2.0" }), { kind: "newer", theirs: "0.2.0" });
  assert.deepEqual(versionVerdict(OURS, { ...REAL, version: "unknown" }), { kind: "other", theirs: "unknown" });
  assert.deepEqual(versionVerdict(OURS, { ...REAL, version: "0.2.0-beta.6+build.1" }), { kind: "other", theirs: "0.2.0-beta.6+build.1" },
    "equal precedence but another string is not this release");
});

test("versionVerdict: a real arbiter that reports no version is a release from before the check", () => {
  assert.deepEqual(versionVerdict(OURS, REAL), { kind: "older", theirs: null });
  assert.deepEqual(versionVerdict(OURS, { ...REAL, version: "" }), { kind: "older", theirs: null });
});

test("versionVerdict: no answer, or no Mandu identity, is unknown (nothing to compare)", () => {
  for (const h of [undefined, null, "x", 3, {}, { pid: 1, integrity: false, confidentiality: true }]) {
    assert.deepEqual(versionVerdict(OURS, h), { kind: "unknown" }, JSON.stringify(h));
  }
});

test("versionVerdict: a launcher that cannot read its own version has nothing to compare", () => {
  assert.equal(versionVerdict("unknown", { ...REAL, version: "unknown" }).kind, "unknown");
  assert.equal(versionVerdict("unknown", { ...REAL, version: OURS }).kind, "unknown");
  assert.equal(versionVerdict(OURS, { ...REAL, version: "unknown" }).kind, "other", "an arbiter that cannot read its own is another release");
});

function input(verdict: VersionVerdict, over: Partial<SkewInput> = {}): SkewInput {
  return {
    verdict, ours: OURS, sock: "/run/user/1/mandu/current/arbiter.sock", mode: "current", started: false,
    base: "/run/user/1/mandu", arbiterPid: 4242, peers: [], ...over,
  };
}

test("skewAction: same release or unknown proceeds, in every mode", () => {
  for (const mode of ["pinned", "current", "legacy", "autostart"] as const) {
    for (const started of [false, true]) {
      assert.equal(skewAction(input({ kind: "match", theirs: OURS }, { mode, started })).kind, "proceed");
      assert.equal(skewAction(input({ kind: "unknown" }, { mode, started })).kind, "proceed");
    }
  }
});

test("skewAction: an older resident stack no session uses is restarted", () => {
  const a = skewAction(input({ kind: "older", theirs: "0.2.0-beta.5" }));
  assert.equal(a.kind, "restart");
  assert.match((a as { note: string }).note, /were Mandu 0\.2\.0-beta\.5; restarting them as Mandu 0\.2\.0-beta\.6/);
  assert.equal(skewAction(input({ kind: "older", theirs: null }, { mode: "legacy" })).kind, "restart", "a pre-check release, legacy path");
  assert.equal(skewAction(input({ kind: "other", theirs: "unknown" })).kind, "restart");
});

test("skewAction: a session on the stack makes it a refusal naming mandu stop --stack", () => {
  const a = skewAction(input({ kind: "older", theirs: null }, { peers: [111, 222] }));
  assert.equal(a.kind, "refuse");
  const m = (a as { message: string }).message;
  assert.match(m, /an older Mandu release \(one that does not report its version\)/);
  assert.match(m, /2 other mandu sessions use them \(pid 111, 222\)/);
  assert.match(m, /mandu stop --stack \/run\/user\/1\/mandu$/);
  assert.match(m, /refusing to launch against another release/);
  assert.match((skewAction(input({ kind: "older", theirs: "0.2.0-beta.5" }, { peers: [7] })) as { message: string }).message,
    /another mandu session uses them \(pid 7\)\. Run mandu again once it ends/);
});

test("skewAction: a newer resident stack is never downgraded, sessions or not", () => {
  for (const peers of [[], [9]]) {
    const a = skewAction(input({ kind: "newer", theirs: "0.3.0" }, { peers }));
    assert.equal(a.kind, "refuse");
    assert.match((a as { message: string }).message, /are Mandu 0\.3\.0, newer than this mandu \(0\.2\.0-beta\.6\).*mandu stop --stack/);
  }
});

test("skewAction: a pinned arbiter of another release is refused, never restarted", () => {
  for (const verdict of [{ kind: "older", theirs: "0.1.0" }, { kind: "newer", theirs: "9.0.0" }, { kind: "older", theirs: null }] as const) {
    const a = skewAction(input(verdict, { mode: "pinned", sock: "/tmp/a.sock" }));
    assert.equal(a.kind, "refuse");
    assert.match((a as { message: string }).message, /the arbiter at \/tmp\/a\.sock \(MANDU_ARBITER_SOCK, pid 4242\).*unset MANDU_ARBITER_SOCK/);
  }
});

test("skewAction: the arbiter this launch started must be this release", () => {
  const a = skewAction(input({ kind: "older", theirs: "0.1.0" }, { started: true, mode: "autostart" }));
  assert.equal(a.kind, "refuse");
  assert.match((a as { message: string }).message, /the arbiter this launch started .* reports Mandu 0\.1\.0/);
});

test("checkArbiterRelease: scans for sessions only when a restart is possible; a failed hello is unknown", async () => {
  let scans = 0;
  const deps = (hello: unknown) => ({
    hello: async () => { if (hello instanceof Error) throw hello; return hello; },
    peers: () => { scans++; return [5]; },
  });
  const base = { ours: OURS, sock: "/s", mode: "current" as const, started: false, base: "/b" };
  assert.equal((await checkArbiterRelease(base, deps({ ...REAL, version: OURS }))).action.kind, "proceed");
  assert.equal((await checkArbiterRelease(base, deps(new Error("ECONNREFUSED")))).action.kind, "proceed");
  assert.equal((await checkArbiterRelease({ ...base, mode: "pinned" }, deps(REAL))).action.kind, "refuse");
  assert.equal((await checkArbiterRelease(base, deps({ ...REAL, version: "9.9.9" }))).action.kind, "refuse");
  assert.equal(scans, 0, "no scan for a match, an unknown, a pinned or a newer arbiter");
  const r = await checkArbiterRelease(base, deps({ ...REAL, version: "0.0.1" }));
  assert.equal(scans, 1);
  assert.equal(r.action.kind, "refuse");
  assert.match((r.action as { message: string }).message, /the arbiter at \/s, pid 4242/);
});

test("afterRestartRefusal: only this release, answering, passes", () => {
  assert.equal(afterRestartRefusal({ kind: "match", theirs: OURS }, OURS, "/s"), null);
  assert.match(afterRestartRefusal({ kind: "unknown" }, OURS, "/s")!, /did not report this release/);
  assert.match(afterRestartRefusal({ kind: "older", theirs: "0.1.0" }, OURS, "/s")!, /reports Mandu 0\.1\.0/);
});

function mockOps(procs: Array<Proc & { stack: string | null }>, alive: Set<number>, killed: number[]): ProcOps {
  return {
    list: () => procs.map(({ pid, title, container }) => ({ pid, title, ...(container ? { container } : {}) })),
    kill: (pid) => { killed.push(pid); alive.delete(pid); },
    stackOf: (pid) => procs.find((p) => p.pid === pid)?.stack ?? null,
  };
}

test("liveLaunchersOn: the launchers of this stack only", () => {
  const ops = mockOps([
    { pid: 1, title: "mandu", stack: "/b" },
    { pid: 2, title: "mandu", stack: "/other" },
    { pid: 3, title: "mandu", stack: null },
    { pid: 4, title: "mandu", stack: "/b", container: true },
    { pid: 5, title: "mandu-arbiter", stack: "/b" },
    { pid: 6, title: "mandu", stack: "/b" },
  ], new Set(), []);
  assert.deepEqual(liveLaunchersOn("/b/", ops), [1, 6]);
});

test("stopStackAndWait: SIGTERMs this stack's resident daemons and waits for them", async () => {
  const alive = new Set([10, 11, 12, 13]);
  const killed: number[] = [];
  const ops = mockOps([
    { pid: 10, title: "mandu-arbiter", stack: "/b" },
    { pid: 11, title: "mandu-dashboard", stack: "/b" },
    { pid: 12, title: "mandu-arbiter", stack: "/other" },
    { pid: 13, title: "mandu", stack: "/b" },
  ], alive, killed);
  const r = await stopStackAndWait("/b", 1_000, ops, (p) => alive.has(p));
  assert.deepEqual(killed.sort(), [10, 11], "only this stack's resident daemons, never a launcher or another stack");
  assert.deepEqual(r, { stopped: [10, 11], survivors: [] });
});

test("stopStackAndWait: a daemon that does not exit is reported", async () => {
  const ops = mockOps([{ pid: 20, title: "mandu-arbiter", stack: "/b" }], new Set(), []);
  const r = await stopStackAndWait("/b", 200, { ...ops, kill: () => {} }, () => true);
  assert.deepEqual(r, { stopped: [20], survivors: [20] });
});
