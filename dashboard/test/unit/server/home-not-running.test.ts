/**
 * home-not-running.test — Home when nothing of Mandu's runs (dashboard.md
 * §4.25, *Protection is off when nothing runs*): the probe
 * (src/mandu-running.ts `manduNotRunning`) and `buildHome` (GET /api/home)
 * over a session list that cannot be read.
 *
 * Pins:
 * - the probe says "not running" only when there is no arbiter socket, no
 *   live arbiter instance and no live launch; anything of Mandu's there is
 *   not "not running" (a fault, or a moment), the cautious side;
 * - `everRan` counts agent sessions on record, never the system logs;
 * - buildHome, the list unreadable and Mandu not running: the hero says
 *   protection is off (never "Not connected.", never protected), with the
 *   kept scan's card; the list unreadable and the probe null or absent: the
 *   read's failure stands, as before (the route answers 503 and the page
 *   says "Not connected.").
 *
 * Axes: no arbiter answers, so no posture is read; `secrets` stated for the
 * configured mode the hero's setup card names.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildHome, HomeFacts, type HomeDeps } from "../../../src/server/home-routes.js";
import { manduNotRunning, type RunningProbeDeps } from "../../../src/mandu-running.js";
import type { EventSource } from "../../../src/event-source.js";
import type { LastScanWire } from "../../../src/view-model/last-scan.js";

const AT = { arbiterSock: "/run/u/mandu/current/arbiter.sock", runtimeBase: "/run/u/mandu", eventDir: "/home/u/.mandu/events" };

function probe(over: { exists?: string[]; dirs?: Record<string, string[]>; json?: Record<string, unknown>; alive?: number[] } = {}): RunningProbeDeps {
  return {
    exists: (p) => (over.exists ?? []).includes(p),
    list: (d) => over.dirs?.[d] ?? [],
    readJson: (p) => over.json?.[p] ?? null,
    pidAlive: (pid) => (over.alive ?? []).includes(pid),
  };
}

test("manduNotRunning: nothing there is not running; a socket, a live instance or a live launch is something", () => {
  assert.deepEqual(manduNotRunning(AT, probe()), { everRan: false }, "never ran: nothing anywhere");
  // A socket file that does not answer (a crashed arbiter's): a fault.
  assert.equal(manduNotRunning(AT, probe({ exists: [AT.arbiterSock] })), null);
  // An arbiter instance starting (not promoted yet), its pid alive; a dead one is history.
  const inst = { dirs: { "/run/u/mandu/instances": ["i1"] }, json: { "/run/u/mandu/instances/i1/manifest.json": { pid: 41 } } };
  assert.equal(manduNotRunning(AT, probe({ ...inst, alive: [41] })), null);
  assert.deepEqual(manduNotRunning(AT, probe(inst)), { everRan: false });
  // A `mandu claude` alive (its scope run dir <epochSec>-<pid>) without its arbiter: a fault.
  const launch = { dirs: { "/run/u/mandu": ["1760000000-77", "dashboards", "dashboard-77.port", "human"] } };
  assert.equal(manduNotRunning(AT, probe({ ...launch, alive: [77] })), null);
  assert.deepEqual(manduNotRunning(AT, probe(launch)), { everRan: false }, "a dead launch's dir, a dashboard's own files: not running");
  // Ever ran: an agent session on record; the system logs are not one.
  assert.deepEqual(manduNotRunning(AT, probe({ dirs: { [AT.eventDir]: ["arbiter-admin.ndjson", "net-guard.ndjson"] } })), { everRan: false });
  assert.deepEqual(manduNotRunning(AT, probe({ dirs: { [AT.eventDir]: ["arbiter-admin.ndjson", "a1b2c3.ndjson"] } })), { everRan: true });
});

test("manduNotRunning: the real filesystem, a runtime base and an event store on disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-not-running-"));
  try {
    const at = { arbiterSock: join(dir, "rt", "current", "arbiter.sock"), runtimeBase: join(dir, "rt"), eventDir: join(dir, "events") };
    assert.deepEqual(manduNotRunning(at), { everRan: false }, "absent dirs read as empty");
    mkdirSync(join(dir, "rt", `1760000000-${process.pid}`), { recursive: true });
    assert.equal(manduNotRunning(at), null, "a live launch (this process)");
    rmSync(join(dir, "rt", `1760000000-${process.pid}`), { recursive: true });
    mkdirSync(at.eventDir, { recursive: true });
    writeFileSync(join(at.eventDir, "s1.ndjson"), "");
    assert.deepEqual(manduNotRunning(at), { everRan: true });
    mkdirSync(join(dir, "rt", "current"), { recursive: true });
    writeFileSync(at.arbiterSock, "");
    assert.equal(manduNotRunning(at), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

const SCAN: LastScanWire = {
  version: 1, ranAt: "2026-10-21T09:00:00Z", sessions: { "claude-code": 3 }, duringMandu: 0, sessionsUnderMandu: 0, sessionsByTime: 0,
  findings: [{ kind: "known", preview: "STRIPE_KEY in ~/shop/.env", sessions: 3, how: { "read-file": 3 }, agents: ["claude-code"], projects: ["~/shop"], duringMandu: 0, source: { path: "~/shop/.env", name: "STRIPE_KEY" } }],
  dropped: 0, known: 1, capped: { overTime: 0, overBytes: 0, tooBig: 0, overFiles: 0, readFailed: 0 }, suggestions: null,
};

function deps(notRunning: HomeDeps["notRunning"] | "absent"): HomeDeps {
  // The live tenant's source with no arbiter behind it: every read fails.
  const source = {
    listSessions: async () => { throw new Error("connect ENOENT /run/u/mandu/current/arbiter.sock"); },
    policySnapshot: async () => { throw new Error("connect ENOENT"); },
  } as unknown as EventSource;
  return {
    source,
    facts: new HomeFacts(source, "/home/u"),
    approvals: undefined,
    testRuns: [],
    watchRuns: [],
    env: { MANDU_HOME: "/nonexistent/mandu-home-not-running" },
    home: "/home/u",
    lastScan: () => SCAN,
    ...(notRunning === "absent" ? {} : { notRunning }),
  };
}

test("buildHome, no arbiter and Mandu not running: protection is off, the kept scan's card, no session; something there: the failure stands", async () => {
  const vm = await buildHome(deps(() => ({ everRan: false })));
  assert.equal(vm.verdict, "off");
  assert.equal(vm.headline, "Protection is off: no agent runs with Mandu.");
  assert.match(vm.sentence, /start it with mandu claude \(or mandu codex\)\.$/);
  assert.equal(vm.protection.connected, false);
  assert.equal(vm.protection.notRunning, true);
  assert.deepEqual(vm.agents, []);
  assert.equal(vm.history.total, 0);
  assert.ok(vm.firstRun, "never ran: the setup card");
  // The scan card says the sessions ran without Mandu.
  assert.equal(vm.scan?.headline, "1 of your secrets left this computer in your agents' requests");
  assert.match(vm.scan?.sentence ?? "", /in a session without Mandu/);
  // The probe answers null (something of Mandu's is there), or no probe
  // (the test tenant): the failure stands, the page says Not connected.
  await assert.rejects(buildHome(deps(() => null)), /ENOENT/);
  await assert.rejects(buildHome(deps("absent")), /ENOENT/);
});
