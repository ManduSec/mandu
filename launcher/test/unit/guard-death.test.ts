/**
 * guard-death.test — reading the guard's status file, the note, and ending
 * what a dead guard left of the session (rootless-confinement §12.2).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  afterGuardedLaunch,
  endSession,
  guardDeathNote,
  parseGuardStatus,
  sessionOfStat,
  type EndSessionDeps,
} from "../../src/guard-death.js";

test("parseGuardStatus: the guard's two records, anything else is no record", () => {
  assert.deepEqual(parseGuardStatus("supervising 10 11\n"), { state: "supervising", guard: 10, child: 11 });
  assert.deepEqual(parseGuardStatus("exited 0\n"), { state: "exited", code: 0 });
  assert.deepEqual(parseGuardStatus("exited 126"), { state: "exited", code: 126 });
  for (const t of [null, "", "garbage", "supervising 10", "exited"]) assert.equal(parseGuardStatus(t), null, String(t));
});

test("guardDeathNote: only a guard that was still supervising died first", () => {
  const note = guardDeathNote({ state: "supervising", guard: 10, child: 11 });
  assert.ok(note && /WARNING/.test(note) && /pid 10/.test(note) && /ENOSYS/.test(note) && /session is ended/.test(note), String(note));
  assert.equal(guardDeathNote({ state: "exited", code: 1 }), null, "the agent failed; the guard did its job");
  assert.equal(guardDeathNote(null), null, "no record: the guard never supervised (degraded or off)");
});

function recorder(): EndSessionDeps & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    systemctl: (a) => { calls.push("systemctl " + a.join(" ")); return true; },
    sessionPids: (sid) => (sid === 50 ? [50, 51, 52, process.pid] : []),
    kill: (pid, sig) => { calls.push(`kill ${pid} ${sig}`); },
  };
}

test("endSession: the systemd scope is killed as a unit; on the no-scope path every process of the session, never the launcher", () => {
  const a = recorder();
  endSession({ scopeUnit: "mandu-x.scope" }, a);
  assert.deepEqual(a.calls, ["systemctl kill --signal=SIGKILL mandu-x.scope"]);
  const b = recorder();
  endSession({ sessionLeader: 50 }, b);
  assert.deepEqual(b.calls, ["kill 50 SIGKILL", "kill 51 SIGKILL", "kill 52 SIGKILL"]);
});

test("afterGuardedLaunch: ends the session only when the guard died first", () => {
  const died = recorder();
  const note = afterGuardedLaunch("/s", { sessionLeader: 50 }, died, () => "supervising 7 8\n");
  assert.ok(note);
  assert.equal(died.calls.length, 3);
  for (const text of ["exited 0\n", null]) {
    const ok = recorder();
    assert.equal(afterGuardedLaunch("/s", { sessionLeader: 50 }, ok, () => text), null);
    assert.deepEqual(ok.calls, [], "a normal end (or no guard record) leaves the session alone");
  }
});

test("sessionOfStat: field 6, past a name holding spaces and parentheses", () => {
  assert.equal(sessionOfStat("123 (a (b) c) S 1 123 99 0 -1 0"), 99);
  assert.equal(sessionOfStat("garbage"), null);
});
