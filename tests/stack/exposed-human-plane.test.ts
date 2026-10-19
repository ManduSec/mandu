/**
 * Stack e2e — the human plane's exposure (confidentiality plan 13 D9
 * leftovers, arbiter-human-plane.md §8, §10) over the PRODUCTION wiring: the
 * launcher's own wall reading (`humanPlaneWalled`) and launch record
 * (`beginLaunchRecord` / `endLaunchRecord` over `ndjsonCall`, what run.ts
 * calls), the launcher's notices (`unrecordedExposureRefusal`,
 * `concurrentLaunchNotice`; the watch that tells the lost attestation is
 * human-plane-exposure-notice.test.ts), against a REAL ArbiterServer with its human
 * socket, and a program of the unwalled agent dialing that socket by path
 * with the arbiter's own client (nothing walls it off there).
 *
 *   - a `gated` launch with neither the guard nor the wrap is recorded
 *     unwalled; while it runs, the program's forged raw open of its own copy
 *     of `mytool` over the HUMAN socket is a twin, and policy.yaml gains no pin
 *     (on master `a79ccf98` it was raw, and the pin outlived the launch);
 *   - a confined launch begun beside it is told, and warns (refuses under
 *     --require-confinement);
 *   - once the unwalled launch ends, the guard's report there is believed;
 *   - the bind-only `gated` posture (the wrap's tmpfs over the human dir)
 *     is walled: believed throughout;
 *   - an unwalled launch the arbiter refuses to record (handed the data
 *     socket) is refused unless --best-effort.
 *
 * Axes: secrets (stated below).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { ndjsonCall } from "../../launcher/src/secret-setup.js";
import { humanPlaneWalled } from "../../launcher/src/human-plane.js";
import {
  beginLaunchRecord, concurrentLaunchNotice, endLaunchRecord, unrecordedExposureRefusal,
  type CacheEpochDeps, type LaunchClaim,
} from "../../launcher/src/cache-epoch.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mdu-exposed-stack-"));
  const secret = join(dir, "x.txt");
  writeFileSync(secret, "token=EXPOSED_STACK_CANARY\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [{ app: mytool, prints: nothing }]\n`);
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  mkdirSync(dirname(humanSock), { mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false, packDir: null,
  });
  await server.listen();
  const agentProgram = new ArbiterClient(humanSock);
  const logs: string[] = [];
  const deps: CacheEpochDeps = { call: (s, op, a) => ndjsonCall(s, op, a, 5000), log: (m) => logs.push(m), purge: () => {} };
  return {
    dir, secret, policy, sock, humanSock, agentProgram, deps, logs,
    close: async () => { agentProgram.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}
type Rig = Awaited<ReturnType<typeof rig>>;

const forgeOpen = (r: Rig, n: number) =>
  r.agentProgram.decideSecretOpen({ path: r.secret, exe: join(r.dir, "ws", `mytool${n}`), sha256: "c".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: `forge-${n}`, session: "stack" });

function claim(r: Rig, over: Partial<LaunchClaim> & { launchPrefix?: string[]; guardDeny?: boolean }): LaunchClaim {
  const { launchPrefix = [], guardDeny = false, ...rest } = over;
  return {
    pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false,
    humanPlaneWalled: humanPlaneWalled({ dirs: [dirname(r.humanSock)], guardDeny, launchPrefix, platform: "linux" }),
    ...rest,
  };
}

test("e2e: while an unwalled gated launch runs, its program's forged open over the human socket pins nothing; a confined launch beside it warns; its end restores belief", async () => {
  const r = await rig();
  try {
    const gated = claim(r, {});
    assert.equal(gated.humanPlaneWalled, false, "no guard and no wrap: unwalled");
    const rec = await beginLaunchRecord(r.humanSock, gated, r.deps);
    assert.ok(rec.token !== null && !rec.confined, JSON.stringify(rec));
    assert.equal(unrecordedExposureRefusal(r.humanSock, gated, rec, { bestEffort: false }), null, "recorded: nothing to refuse");

    const forged = await forgeOpen(r, 1);
    // MASTER: raw, and policy.yaml gained `{app: mytool, path: <copy>}`
    assert.equal(forged.verdict, "twin", JSON.stringify(forged));
    assert.ok(!readFileSync(r.policy, "utf8").includes(join(r.dir, "ws")), "no pin of the agent's copy");

    // A confined launch begun beside it is told, the way run.ts reads it.
    const conf = await beginLaunchRecord(r.humanSock, claim(r, { posture: "confined", writeProtect: true, guardDeny: true }), r.deps);
    assert.equal(conf.confined, true);
    assert.deepEqual(conf.others.map((o) => [o.pid, o.posture, o.walled]), [[process.pid, "gated", false]]);
    const notice = concurrentLaunchNotice("confined", conf.others, { requireConfinement: false });
    assert.match(notice.lines.join("\n"), /rewrite this launch's placeholder files/);
    // the lost attestation is the human-plane watch's to say, with the fix
    // (human-plane-exposure-notice.test.ts)
    assert.equal(concurrentLaunchNotice("confined", conf.others, { requireConfinement: true }).refuse, true);
    await endLaunchRecord(r.humanSock, conf, r.deps);

    await endLaunchRecord(r.humanSock, rec, r.deps);
    const real = await r.agentProgram.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", sha256: "d".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "after-1", session: "stack" });
    assert.equal(real.verdict, "raw", `believed again once the launch ended: ${JSON.stringify(real)}`);
  } finally { await r.close(); }
});

test("e2e: the bind-only gated posture (the wrap's tmpfs over the human dir) is walled, and the human socket stays believed", async () => {
  const r = await rig();
  try {
    const bindOnly = claim(r, { launchPrefix: ["bwrap", "--dev-bind", "/", "/", "--tmpfs", dirname(r.humanSock), "--"] });
    assert.equal(bindOnly.humanPlaneWalled, true);
    const rec = await beginLaunchRecord(r.humanSock, bindOnly, r.deps);
    const d = await r.agentProgram.decideSecretOpen({ path: r.secret, exe: "/usr/bin/mytool", sha256: "d".repeat(64), isAgent: false, exeSystem: true, openerEnv: [], procKey: "w-1", session: "stack" });
    assert.equal(d.verdict, "raw", JSON.stringify(d));
    await endLaunchRecord(r.humanSock, rec, r.deps);
  } finally { await r.close(); }
});

test("e2e: an unwalled launch the arbiter does not record (the data socket handed as the human one) is refused unless --best-effort", async () => {
  const r = await rig();
  try {
    const gated = claim(r, {});
    const rec = await beginLaunchRecord(r.sock, gated, r.deps);
    assert.equal(rec.token, null);
    const refusal = unrecordedExposureRefusal(r.sock, gated, rec, { bestEffort: false });
    assert.equal(refusal?.refuse, true, JSON.stringify(refusal));
    assert.equal(unrecordedExposureRefusal(r.sock, gated, rec, { bestEffort: true })?.refuse, false);
  } finally { await r.close(); }
});
