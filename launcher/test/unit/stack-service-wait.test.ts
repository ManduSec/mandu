/**
 * stack-service-wait.test — a launch during a restart of the systemd service
 * that runs the stack waits for that service's arbiter instead of
 * autostarting a second stack beside it (runtime-instances.md §4.1c; the
 * 2026-10-21 incident: a launch in the two-second gap of a
 * mandu-dashboard.service restart started an ownerless dashboard and arbiter,
 * and the service's dashboard adopted that arbiter for four days).
 *
 * stackService over a fake process table (which processes count), then the
 * wait (answers, the service stops, the deadline), then startArbiterInstance
 * end to end with the seams: no dashboard is spawned while the service brings
 * its arbiter up. The real systemd unit is tests/stack/unit-restart-race.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ensureArbiter, promotedSockPath, startArbiterInstance, waitForStackService } from "../../src/arbiter.js";
import { stackService, type StackServiceDeps, type StackSupervisor } from "../../src/stack-supervisor.js";
import { Layout, type DaemonSpec } from "../../src/services/layout.js";

const BASE = "/run/user/1000/mandu";
const UNIT_CG = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/mandu-dashboard.service";

interface P { cg: string; env: Record<string, string> | null; ppid: number }

function table(procs: Record<number, P>, mainPid = 10, restart = "always"): StackServiceDeps {
  return {
    listPids: () => Object.keys(procs).map(Number),
    cgroupOf: (pid) => procs[pid]?.cg ?? null,
    ppidOf: (pid) => procs[pid]?.ppid ?? null,
    environOf: (pid) => procs[pid]?.env ?? null,
    stackOfEnv: (env) => env["MANDU_RUNTIME_DIR"] ?? (env["XDG_RUNTIME_DIR"] ? `${env["XDG_RUNTIME_DIR"]}/mandu` : null),
    show: (unit) => (unit === "mandu-dashboard.service" ? `MainPID=${mainPid}\nRestart=${restart}\nWorkingDirectory=/home/u/mandu/dashboard\nFragmentPath=/home/u/.config/systemd/user/mandu-dashboard.service\n` : null),
  };
}

test("stackService: the unit's main process on this stack, still loading (no title yet), names the service", () => {
  const s = stackService(BASE, table({ 10: { cg: UNIT_CG, env: { XDG_RUNTIME_DIR: "/run/user/1000" }, ppid: 1 } }));
  assert.equal(s?.unit, "mandu-dashboard.service");
  assert.equal(s?.user, true);
  assert.equal(s?.restart, "always");
});

test("stackService: another stack's service, a scope, a process deeper in a service (a CI job) or Restart=no is none", () => {
  assert.equal(stackService(BASE, table({ 10: { cg: UNIT_CG, env: { MANDU_RUNTIME_DIR: "/tmp/other" }, ppid: 1 } })), null);
  assert.equal(stackService(BASE, table({ 10: { cg: "0::/user.slice/user-1000.slice/user@1000.service/tmux-spawn-1.scope", env: { MANDU_RUNTIME_DIR: BASE }, ppid: 1 } })), null);
  assert.equal(stackService(BASE, table({ 30: { cg: UNIT_CG, env: { MANDU_RUNTIME_DIR: BASE }, ppid: 20 } }, 10)), null, "not the main process nor its child");
  assert.equal(stackService(BASE, table({ 10: { cg: UNIT_CG, env: { MANDU_RUNTIME_DIR: BASE }, ppid: 1 } }, 10, "no")), null);
  assert.equal(stackService(BASE, table({ 10: { cg: UNIT_CG, env: null, ppid: 1 } })), null, "an unreadable environment says nothing");
});

const SVC: StackSupervisor = {
  unit: "mandu-dashboard.service", user: true, mainPid: 10, restart: "always",
  workingDirectory: "/home/u/mandu/dashboard", fragmentPath: null,
};

test("waitForStackService: no service, no wait (after three more looks, 100 ms apart: a restart's gap)", async () => {
  let polled = 0;
  let looks = 0;
  const t0 = Date.now();
  const r = await waitForStackService(BASE, {}, async () => { polled++; return false; }, () => {}, { stackService: () => { looks++; return null; } });
  assert.equal(r, false);
  assert.equal(polled, 0, "no socket wait");
  assert.equal(looks, 4);
  assert.ok(Date.now() - t0 >= 250);
});

test("waitForStackService: a service found on a later look (its new process was not exec'd yet) is waited for", async () => {
  let looks = 0;
  const logs: string[] = [];
  const r = await waitForStackService(BASE, {}, async () => true, (m) => logs.push(m),
    { stackService: () => (++looks < 3 ? null : SVC), serviceWaitMs: 5_000, serviceRecheckMs: 10 });
  assert.equal(r, true);
  assert.equal(logs.length, 1);
});

test("waitForStackService: the service's arbiter comes up: true, after one notice naming the service", async () => {
  const logs: string[] = [];
  let calls = 0;
  const r = await waitForStackService(BASE, {}, async (sock) => { assert.equal(sock, promotedSockPath(BASE)); return ++calls >= 3; },
    (m) => logs.push(m), { stackService: () => SVC, serviceWaitMs: 5_000, serviceRecheckMs: 10 });
  assert.equal(r, true);
  assert.equal(logs.length, 1);
  assert.match(logs[0]!, /the Mandu services are starting under the systemd user service mandu-dashboard\.service \(Restart=always, in \/home\/u\/mandu\/dashboard\); waiting for them/);
});

test("waitForStackService: a service that goes away (stopped, not restarted) falls back to the autostart after two checks", async () => {
  const logs: string[] = [];
  let looks = 0;
  const r = await waitForStackService(BASE, {}, async () => false, (m) => logs.push(m),
    { stackService: () => (looks++ === 0 ? SVC : null), serviceWaitMs: 5_000, serviceRecheckMs: 10 });
  assert.equal(r, false);
  assert.match(logs.at(-1)!, /mandu-dashboard\.service stopped without starting the Mandu services; starting them here/);
});

test("waitForStackService: a service that stays but never answers is a refusal naming its log", async () => {
  await assert.rejects(
    () => waitForStackService(BASE, {}, async () => false, () => {}, { stackService: () => SVC, serviceWaitMs: 60, serviceRecheckMs: 10 }),
    /refusing to launch: the systemd user service mandu-dashboard\.service .* runs the Mandu services for \/run\/user\/1000\/mandu, but its arbiter did not answer within 0 s\. Look at its log: journalctl --user -u mandu-dashboard\.service/,
  );
});

test("ensureArbiter: a start that found the service's arbiter reports it attached (the release check judges it as the resident stack's)", async () => {
  const dir = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "ssw-")));
  try {
    const sock = join(dir, "absent.sock");
    const svc = await ensureArbiter({ sock, noAutostart: false, start: async () => ({ pid: undefined, running: () => true, attached: true }), waitForSocket: async () => true });
    assert.equal(svc.attached, true);
    const own = await ensureArbiter({ sock, noAutostart: false, start: async () => ({ pid: 4242, running: () => true }), waitForSocket: async () => true });
    assert.equal(own.attached, false, "an arbiter this launch started is not attached");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("startArbiterInstance during the service's restart: no dashboard or arbiter is spawned, the launch uses the service's", async () => {
  const dir = realpathSync(mkdtempSync(join(existsSync("/tmp") ? "/tmp" : tmpdir(), "ssw-")));
  const base = join(dir, "runtime");
  const spawned: DaemonSpec[] = [];
  const logs: string[] = [];
  let polls = 0;
  try {
    const handle = await startArbiterInstance(Layout.dev(join(dir, "repo")), base, join(dir, "a.log"), {}, {
      spawnDaemon: (spec: DaemonSpec) => { spawned.push(spec); },
      waitForSocket: async () => ++polls >= 4, // the service's arbiter answers a few polls later
      log: (m) => logs.push(m),
      env: { HOME: "/h" },
      stackService: () => SVC,
      serviceWaitMs: 5_000,
      serviceRecheckMs: 10,
    })();
    assert.equal(handle?.attached, true, "the service's arbiter is used, attached (not this launch's own)");
    assert.deepEqual(spawned, [], "no second dashboard, no bare arbiter");
    assert.ok(logs.some((l) => /waiting for them/.test(l)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
