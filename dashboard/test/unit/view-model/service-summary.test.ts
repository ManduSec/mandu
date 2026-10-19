/**
 * service-summary.test — the product page's Protection service line
 * (view-model/service-summary.ts, dashboard.md §4.25 *One Protection row*):
 * the main service's state in plain words, its one button, the helpers
 * hidden unless one crashed, and copy inside the product vocabulary. The
 * page writes "<name>. <sentence>" under the on/off, so no sentence repeats
 * its name or says Mandu protects anything (a service runs with protection
 * off too).
 *
 * Pure projection, no server. Axes: none (display only). Mandu-new test.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { ADOPTED_SENTENCE, buildServiceSummary, HELPER_NOTE, RESTART_CONFIRM } from "../../../src/view-model/service-summary.js";
import type { ServiceId, ServiceState, ServiceStatus } from "../../../src/supervisor/supervisor-defs.js";

const svc = (id: ServiceId, state: ServiceState, over: Partial<ServiceStatus> = {}): ServiceStatus => ({
  id, label: id, state, pid: state === "running" ? 4242 : null, since: state === "running" ? 1_000 : null,
  lastError: state === "crashed" ? "exited with code 1" : null, endpoint: "127.0.0.1:1", ...over,
});
const stack = (main: ServiceState, helpers: ServiceState = "stopped"): ServiceStatus[] => [
  svc("arbiter", main),
  svc("anthropic-proxy", helpers), svc("openai-proxy", helpers), svc("net-proxy", helpers), svc("test-arbiter", helpers),
];

// The inspector terms the product copy must not use (home-view-model.test's list).
const FORBIDDEN = /\b(symboliz|desymboliz|egress|invariant|T-LLM|U-LLM|quarantin|AgentView|HumanView|lineage|chokepoint|arbiter|proxy|proxies)\b|\$MDU:/i;

test("running: one Running row with Restart, which asks first; stopped helpers are not mentioned", () => {
  const s = buildServiceSummary(stack("running"));
  assert.equal(s.available, true);
  assert.equal(s.state, "running");
  assert.equal(s.name, "Running");
  assert.equal(s.since, 1_000);
  assert.deepEqual(s.action, { label: "Restart", path: "control/arbiter/restart", confirm: RESTART_CONFIRM });
  assert.match(s.action!.confirm!, /blocked until it is back/, "the question says what a restart costs");
  assert.equal(s.helperNote, null, "stopped helpers are the normal state, not an outage");
  assert.equal(s.sentence, "", "Running says it all: the on/off above it says what is on");
});

test("no sentence says Mandu protects anything, nor repeats its state's name", () => {
  const all = [
    ...(["running", "starting", "stopped", "crashed"] as const).map((st) => buildServiceSummary(stack(st))),
    buildServiceSummary([svc("arbiter", "running", { adopted: true })]),
  ];
  for (const s of all) {
    assert.doesNotMatch(s.sentence, /protect/i, s.state!);
    if (s.sentence) assert.ok(!s.sentence.startsWith(s.name), `${s.state}: the page writes the name first`);
  }
});

test("stopped / crashed: the words, Start without a question, and no since", () => {
  for (const [state, name] of [["stopped", "Stopped"], ["crashed", "Stopped unexpectedly"]] as const) {
    const s = buildServiceSummary(stack(state));
    assert.equal(s.name, name, state);
    assert.equal(s.since, null, state);
    assert.deepEqual(s.action, { label: "Start", path: "control/arbiter/start", confirm: null }, state);
  }
  assert.match(buildServiceSummary(stack("stopped")).sentence, /starts again by itself/);
});

test("starting: the words and no button (a Start would only wait for the start under way; the page's poll redraws the row)", () => {
  for (const adopted of [false, true]) {
    const s = buildServiceSummary([svc("arbiter", "starting", { adopted }), svc("net-proxy", "stopped")]);
    assert.equal(s.name, "Starting");
    assert.equal(s.sentence, "", "the page writes \"Starting.\"");
    assert.equal(s.since, null);
    assert.equal(s.action, null, `adopted=${adopted}: no Start on a start under way`);
  }
});

test("adopted (already running when the dashboard started): no Restart, which the supervisor always refuses, the reason, and no start time", () => {
  const s = buildServiceSummary([svc("arbiter", "running", { adopted: true, pid: null, since: 9_000 }), svc("net-proxy", "stopped")]);
  assert.equal(s.available, true);
  assert.equal(s.name, "Running");
  assert.equal(s.action, null, "no button: stop() refuses an adopted service, so every Restart would fail");
  assert.equal(s.sentence, ADOPTED_SENTENCE);
  assert.match(s.sentence, /^It was already running when this dashboard started, so this page cannot restart it\.$/);
  assert.equal(s.since, null, "its since is when this dashboard found it, not when it started");
  // Once it is no longer running, Start works again (start adopts or spawns).
  for (const state of ["stopped", "crashed"] as const) {
    const down = buildServiceSummary([svc("arbiter", state, { adopted: true })]);
    assert.deepEqual(down.action, { label: "Start", path: "control/arbiter/start", confirm: null }, state);
    assert.notEqual(down.sentence, ADOPTED_SENTENCE, state);
  }
  // Spawned here: Restart as before.
  assert.equal(buildServiceSummary([svc("arbiter", "running", { adopted: false })]).action?.label, "Restart");
});

test("a crashed helper adds the one note; running or stopped helpers do not", () => {
  assert.equal(buildServiceSummary(stack("running", "running")).helperNote, null);
  assert.equal(buildServiceSummary(stack("running", "starting")).helperNote, null);
  const s = buildServiceSummary([svc("arbiter", "running"), svc("net-proxy", "crashed"), svc("openai-proxy", "stopped")]);
  assert.equal(s.helperNote, HELPER_NOTE);
  assert.equal(s.name, "Running", "the main row still reads the main service");
});

test("no main service in the snapshot: not available, no button", () => {
  const s = buildServiceSummary([svc("anthropic-proxy", "running")]);
  assert.equal(s.available, false);
  assert.equal(s.action, null);
  assert.match(s.sentence, /does not run the protection service/);
});

test("every state's copy stays in the product vocabulary (no service ids or inspector terms)", () => {
  for (const main of ["running", "starting", "stopped", "crashed"] as const) {
    for (const helpers of ["stopped", "crashed"] as const) {
      const s = buildServiceSummary(stack(main, helpers));
      const adopted = buildServiceSummary([svc("arbiter", main, { adopted: true }), svc("net-proxy", helpers)]);
      assert.doesNotMatch(adopted.sentence, FORBIDDEN, `${main}/${helpers} adopted: ${adopted.sentence}`);
      for (const words of [s.name, s.sentence, s.helperNote ?? "", s.action?.label ?? "", s.action?.confirm ?? ""]) {
        assert.doesNotMatch(words, FORBIDDEN, `${main}/${helpers}: ${words}`);
      }
    }
  }
  assert.doesNotMatch(buildServiceSummary([]).sentence, FORBIDDEN);
});
