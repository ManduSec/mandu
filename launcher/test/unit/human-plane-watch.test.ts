/**
 * human-plane-watch — the walled launch's user is told why its file guard
 * is not believed while an unwalled launch runs (arbiter-human-plane.md
 * §10.1.1, P0 (E) decision 3). Pure lines + the watch's state machine over
 * a scripted arbiter. The decision itself (the claim) is the arbiter's and
 * is not touched here. Axes: secrets (the watch runs only in a protecting
 * mode; nothing here reads an axis).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EXPOSURE_FIX, exposureLostLines, exposureRecapLines, exposureRestoredLine, exposureStep, humanPlaneWatch,
  launchWords, parseHumanPlaneStatus, watchesHumanPlane, type HumanPlaneStatusWire,
} from "../../src/human-plane-watch.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const OFF = { pid: 4242, mode: "off", posture: "off", session: "claude-20261003-x1" };

test("the WARNING names each launch (pid, session, mode), says what is lost here, and gives the fix", () => {
  const lines = exposureLostLines([OFF]);
  assert.match(lines[0]!, /^WARNING: mandu: this session's file guard is not believed: another Mandu launch can reach Mandu's own controls: pid 4242 \(session claude-20261003-x1, mode off\)\.$/);
  assert.match(lines[2]!, /placeholder/);
  assert.match(lines[2]!, /protected file is refused/);
  assert.match(lines[2]!, /shell output is masked/);
  assert.equal(lines.at(-1), EXPOSURE_FIX);
  assert.match(EXPOSURE_FIX, /stop that launch, or start it again with its file guard on/);
  assert.match(EXPOSURE_FIX, /--mode off/);
  // several, and one Mandu could not name (the arbiter failed closed)
  const many = exposureLostLines([OFF, { pid: 7, mode: "secrets", posture: "gated" }, { pid: 0, mode: "unknown", posture: "unknown" }, { pid: 9, mode: "off", posture: "off" }]);
  assert.match(many[0]!, /4 other Mandu launches/);
  assert.match(many[0]!, /pid 7 \(mode secrets\)/);
  assert.match(many[0]!, /a launch Mandu could not name/);
  assert.match(many[0]!, /and 1 more\.$/);
  assert.equal(launchWords({ pid: 5, mode: "secrets", posture: "gated" }), "pid 5 (mode secrets)");
  assert.match(exposureRestoredLine([OFF]), /^mandu: this session's file guard is believed again: the launch .*pid 4242 \(session claude-20261003-x1, mode off\).* ended\.$/);
});

test("parseHumanPlaneStatus: the arbiter's answer, defensively", () => {
  assert.equal(parseHumanPlaneStatus(null), null);
  assert.equal(parseHumanPlaneStatus({ exposed: "yes", launches: [] }), null);
  assert.deepEqual(parseHumanPlaneStatus({ exposed: false, since: null, launches: [] }), { exposed: false, since: null, launches: [] });
  assert.deepEqual(
    parseHumanPlaneStatus({ exposed: true, since: 5, launches: [{ pid: 1, mode: "off", posture: "off", session: "s", begunAt: 4 }, { bogus: 1 }, { pid: 2, session: "" }] }),
    { exposed: true, since: 5, launches: [{ pid: 1, mode: "off", posture: "off", session: "s", begunAt: 4 }, { pid: 2, mode: "unknown", posture: "unknown" }] },
  );
  // launches named but `exposed` false: still exposed (fail closed in the telling too)
  assert.equal(parseHumanPlaneStatus({ exposed: false, launches: [{ pid: 3 }] })!.exposed, true);
});

test("exposureStep: told once when lost, one line when the set changes, one when restored, nothing otherwise", () => {
  const walled: HumanPlaneStatusWire = { exposed: false, since: null, launches: [] };
  const one: HumanPlaneStatusWire = { exposed: true, since: 1, launches: [OFF] };
  const two: HumanPlaneStatusWire = { exposed: true, since: 1, launches: [OFF, { pid: 8, mode: "secrets", posture: "gated" }] };
  assert.deepEqual(exposureStep([], walled), { lines: [], told: [], change: null });
  const lost = exposureStep([], one);
  assert.equal(lost.change, "lost");
  assert.deepEqual(lost.lines, exposureLostLines([OFF]));
  assert.deepEqual(exposureStep(lost.told, one).lines, [], "the same set again: silent");
  const changed = exposureStep(lost.told, two);
  assert.equal(changed.change, "changed");
  assert.equal(changed.lines.length, 1);
  assert.match(changed.lines[0]!, /still not believed.*pid 4242.*pid 8/);
  const back = exposureStep(changed.told, walled);
  assert.equal(back.change, "restored");
  assert.match(back.lines[0]!, /believed again/);
  // exposed with nobody named: told as an unnamed launch, never silent
  assert.equal(exposureStep([], { exposed: true, since: null, launches: [] }).change, "lost");
});

test("watchesHumanPlane: a walled launch in a protecting mode with a human socket", () => {
  assert.equal(watchesHumanPlane({ mode: "secrets", humanPlaneWalled: true }, "/h.sock"), true);
  assert.equal(watchesHumanPlane({ mode: "secrets", humanPlaneWalled: false }, "/h.sock"), false, "an unwalled launch is the exposure");
  assert.equal(watchesHumanPlane({ mode: "secrets" }, "/h.sock"), false);
  assert.equal(watchesHumanPlane({ mode: "off", humanPlaneWalled: true }, "/h.sock"), false, "off protects nothing");
  assert.equal(watchesHumanPlane({ mode: "secrets", humanPlaneWalled: true }, null), false);
});

test("the watch over a scripted arbiter: prints on each change, recaps after; a failed ask prints nothing; an older arbiter retires it", async () => {
  const answers: Array<unknown> = [
    { exposed: false, since: null, launches: [] },
    { exposed: true, since: 1000, launches: [OFF] },
    new Error("connect ENOENT /h.sock"),
    { exposed: true, since: 1000, launches: [OFF] },
    { exposed: false, since: null, launches: [] },
  ];
  const printed: string[] = [];
  const calls: string[] = [];
  let t = 1000;
  const w = humanPlaneWatch("/h.sock", {
    call: async (sock, op) => { calls.push(`${sock} ${op}`); const a = answers.shift(); if (a instanceof Error) throw a; return a; },
    print: (l) => printed.push(l),
    now: () => (t += 1000),
  });
  await w.checkNow();
  assert.equal(printed.length, 0, "walled: nothing");
  await w.checkNow();
  assert.deepEqual(printed, exposureLostLines([OFF]));
  await w.checkNow(); // unreachable: this tick says nothing
  await w.checkNow(); // same set: nothing
  assert.equal(printed.length, 4);
  await w.checkNow();
  assert.match(printed.at(-1)!, /believed again/);
  assert.deepEqual(calls, Array(5).fill("/h.sock humanPlaneStatus"));
  const recap = w.recap();
  assert.equal(recap.length, 2, "ended: no fix line");
  assert.match(recap[0]!, /during this session its file guard was not believed \(\d\d:\d\d:\d\d to \d\d:\d\d:\d\d\).*pid 4242/);
  w.stop();

  // an arbiter that predates the op: retired, no line, no further ask
  let n = 0;
  const old = humanPlaneWatch("/h.sock", { call: async () => { n++; throw new Error("unknown op: humanPlaneStatus"); }, print: (l) => printed.push(l) });
  await old.checkNow();
  await old.checkNow();
  assert.equal(n, 1);
  assert.deepEqual(old.recap(), []);
});

test("exposureRecapLines: nothing when nothing happened; the fix when it is still exposed at the end", () => {
  assert.deepEqual(exposureRecapLines([]), []);
  const open = exposureRecapLines([{ from: 0, to: null, launches: [OFF] }]);
  assert.match(open[0]!, /to the end\)/);
  assert.equal(open.at(-1), EXPOSURE_FIX);
});
