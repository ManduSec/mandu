/**
 * human-plane-status — the human plane's exposure, made visible
 * (arbiter-human-plane.md §10.1.1, P0 (E) decision 3, 2026-10-03).
 *
 * While a launch with no wall is live, the human socket's guard and proxy
 * reports are claims (§10.1), so a confined launch beside it loses its
 * guard's attestation. That stays (fail closed); what this adds is the
 * telling:
 *   - `humanPlaneStatus` (human plane only) answers whether the plane is
 *     exposed, since when, and by which launches (pid, mode, posture and the
 *     session the launcher named);
 *   - each change is told once on the arbiter's audit stream (a
 *     `config_change` event carrying `humanPlane`), the end too, even when
 *     the launcher dies and nobody asks;
 *   - none of it changes a decision: the report stays a claim while exposed.
 *
 * Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ADMIN_SESSION_ID, ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-hp-status-"));
  const secret = join(dir, "x.txt");
  writeFileSync(secret, "token=HP_STATUS_CANARY\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [ssh-add]\n`);
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  const human = new ArbiterClient(join(dir, "human", "h.sock")); await human.connect();
  const data = new ArbiterClient(join(dir, "a.sock")); await data.connect();
  return {
    dir, secret, human, data,
    done: async () => { human.close(); data.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

type HumanPlaneEvent = { kind: string; emitter: string; claimed?: boolean; humanPlane?: { state: string; since: number | null; launches: Array<{ pid: number; session?: string }>; ended?: Array<{ pid: number; session?: string }> } };

async function humanPlaneEvents(c: ArbiterClient): Promise<HumanPlaneEvent[]> {
  return ((await c.events(ADMIN_SESSION_ID)) as unknown as HumanPlaneEvent[]).filter((e) => e.humanPlane !== undefined);
}

test("humanPlaneStatus names the unwalled launch (pid, session) while it runs and clears at its end; each change is one audit event; the report stays a claim (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    assert.deepEqual(await r.human.humanPlaneStatus(), { exposed: false, since: null, launches: [] });
    // a walled launch exposes nothing, and is not told
    const walled = await r.human.beginLaunch({ pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: true, sessionId: "walled-sess" });
    assert.equal((await r.human.humanPlaneStatus()).exposed, false);

    const before = Date.now();
    const rec = await r.human.beginLaunch({ pid: process.pid, mode: "off", posture: "off", writeProtect: false, humanPlaneWalled: false, sessionId: "claude-unwalled-1" });
    const st = await r.human.humanPlaneStatus();
    assert.equal(st.exposed, true);
    assert.ok(st.since !== null && st.since >= before, String(st.since));
    assert.deepEqual(st.launches.map((l) => [l.pid, l.mode, l.posture, l.session]), [[process.pid, "off", "off", "claude-unwalled-1"]]);

    // display only: the confined guard's report on the human socket is still a claim
    const d = await r.human.decideSecretOpen({ path: r.secret, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "hp-1", session: "confined-sess" });
    assert.equal(d.verdict, "twin", JSON.stringify(d));

    // one event per change, not per ask
    await r.human.humanPlaneStatus();
    await r.human.humanPlaneStatus();
    let evs = await humanPlaneEvents(r.human);
    assert.equal(evs.length, 1, JSON.stringify(evs));
    assert.equal(evs[0]!.kind, "config_change");
    assert.equal(evs[0]!.emitter, "arbiter");
    assert.equal(evs[0]!.claimed, undefined, "the arbiter's own event is believed");
    assert.equal(evs[0]!.humanPlane!.state, "exposed");
    assert.deepEqual(evs[0]!.humanPlane!.launches.map((l) => [l.pid, l.session]), [[process.pid, "claude-unwalled-1"]]);

    await r.human.endLaunch(rec.token);
    assert.deepEqual(await r.human.humanPlaneStatus(), { exposed: false, since: null, launches: [] });
    evs = await humanPlaneEvents(r.human);
    assert.equal(evs.length, 2);
    assert.equal(evs[1]!.humanPlane!.state, "walled");
    assert.deepEqual(evs[1]!.humanPlane!.ended, [{ pid: process.pid, session: "claude-unwalled-1" }]);
    const real = await r.human.decideSecretOpen({ path: r.secret, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "hp-2", session: "confined-sess" });
    assert.equal(real.verdict, "raw", `believed again: ${JSON.stringify(real)}`);
    await r.human.endLaunch(walled.token);
  } finally { await r.done(); }
});

test("humanPlaneStatus is a human-plane op: refused on the data socket (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    await assert.rejects(r.data.humanPlaneStatus(), /human-plane: 'humanPlaneStatus' names the live launches/);
  } finally { await r.done(); }
});

test("a launcher that dies is told as the exposure's end without anybody asking (secrets axes, explicit)", async () => {
  const r = await rig();
  const { spawn } = await import("node:child_process");
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  try {
    await r.human.beginLaunch({ pid: child.pid!, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false, sessionId: "dies-1" });
    assert.equal((await humanPlaneEvents(r.human)).at(-1)?.humanPlane?.state, "exposed");
    const exited = new Promise((ok) => child.once("exit", ok));
    child.kill("SIGKILL");
    await exited;
    // no op that reads the exposure in between: the arbiter's own watch tells it
    let last: string | undefined;
    for (let i = 0; i < 40 && last !== "walled"; i++) {
      await new Promise((ok) => setTimeout(ok, 100));
      last = (await humanPlaneEvents(r.human)).at(-1)?.humanPlane?.state;
    }
    assert.equal(last, "walled");
  } finally { child.kill("SIGKILL"); await r.done(); }
});
