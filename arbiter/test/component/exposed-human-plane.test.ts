/**
 * exposed-human-plane — while a launch whose agent world can reach the
 * human-plane socket is live (no guard and no wrap: the `gated` posture on a
 * host with neither, or `off`), nothing that arrives on the human socket is
 * believed as the guard's or a proxy's record (confidentiality plan 13 D9's
 * leftovers, arbiter-human-plane.md §8, §10).
 *
 * The human socket is believed because the walls keep the agent's world off
 * it (the guard's `unixDeny`, the wrap's tmpfs). A launch without either has
 * no wall: its agent's programs connect to `<runtime>/human/<id>.sock` like
 * any same-uid process. Before this change the arbiter believed them there,
 * so a program of that agent could, over the HUMAN socket:
 *   - report a raw open of its own copy of `ssh-add` as a system binary: the
 *     arbiter pinned the bare-name reader to the copy in policy.yaml, a pin
 *     that outlives the launch and every confined launch after it honors;
 *   - file an Inbox row for a protected write in the guard's words.
 * Now the launcher says whether its agent's world is walled off from the
 * human plane (`beginLaunch`'s `humanPlaneWalled`), and while an unwalled
 * launch is live every attested report on the human socket is a claim, as
 * on the data socket. The admin channel stays believed. A walled launch
 * (the bind-only `gated` posture: the wrap's tmpfs) changes nothing.
 *
 * Each test marked MASTER was red on master `a79ccf98`. Axes: secrets.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the axis under test

async function rig() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-exposed-"));
  const secret = join(dir, "x.txt");
  writeFileSync(secret, "token=EXPOSED_CANARY_0\n");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `version: 1\npaths:\n  - path: ${secret}\n    level: no-model\n    readers: [ssh-add]\n`);
  const sock = join(dir, "a.sock");
  const human = join(dir, "human", "h.sock");
  mkdirSync(join(dir, "human"), { mode: 0o700 });
  const s = new ArbiterServer({
    socketPath: sock, humanSocketPath: human, dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"),
    policyPath: policy, log: () => {}, confidentiality: true, integrity: false,
  });
  await s.listen();
  // `launcher`: the launch's own record; `exposed`: a program of an unwalled
  // launch's agent, on the same human socket (nothing walls it off).
  const launcher = new ArbiterClient(human); await launcher.connect();
  const exposed = new ArbiterClient(human); await exposed.connect();
  return {
    dir, secret, policy, server: s, launcher, exposed,
    done: async () => { launcher.close(); exposed.close(); await s.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

type Rig = Awaited<ReturnType<typeof rig>>;

async function forgePin(r: Rig, n: number) {
  const copy = join(r.dir, "ws", `ssh-add${n}`);
  const d = await r.exposed.decideSecretOpen({ path: r.secret, exe: copy, sha256: String(n).repeat(64).slice(0, 64), isAgent: false, exeSystem: true, openerEnv: [], procKey: `pin-${n}`, session: "exp" });
  return { d, copy, pinned: readFileSync(r.policy, "utf8").includes(copy) };
}

test("while an unwalled launch is live, a forged open over the human socket pins no reader; before it and after it ends the human socket is believed (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const rec = await r.launcher.beginLaunch({ pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false });
    assert.equal(rec.confined, false);
    const during = await forgePin(r, 1);
    // MASTER: raw, and policy.yaml gained a pin of the agent's copy
    assert.equal(during.d.verdict, "twin", JSON.stringify(during.d));
    assert.match(during.d.reason, /can reach the human plane/);
    assert.equal(during.pinned, false, "no pin of the agent's copy");
    // a protected write in the guard's words files no Inbox row
    const pw = await r.exposed.decideProtectedWrite({ path: join(r.dir, ".bashrc"), exe: "/usr/bin/vim", sha256: "e".repeat(64), exeSystem: true, openerEnv: [], procKey: "pw-1", label: "a shell startup file", session: "exp" });
    // MASTER: ask, with a pending row
    assert.equal(pw.verdict, "deny", JSON.stringify(pw));
    assert.equal((await r.launcher.egressApprovals("pending")).length, 0);
    // the admin channel (an in-process dispatch) is still believed
    const adm = r.server.dispatch({ id: "a", op: "decideSecretOpen", path: r.secret, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "adm-1", session: "exp" }) as { ok: boolean; result?: { verdict: string } };
    assert.equal(adm.result?.verdict, "raw", JSON.stringify(adm));

    const end = await r.launcher.endLaunch(rec.token);
    assert.equal(end.ended, true);
    // the launch is over: the guard's report on the human socket is believed again
    const after = await r.exposed.decideSecretOpen({ path: r.secret, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "after-1", session: "exp" });
    assert.equal(after.verdict, "raw", JSON.stringify(after));
  } finally { await r.done(); }
});

test("a walled launch (the bind-only gated posture, or the guard's deny) leaves the human socket believed (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    await r.launcher.beginLaunch({ pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: true });
    const d = await r.exposed.decideSecretOpen({ path: r.secret, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "w-1", session: "w" });
    assert.equal(d.verdict, "raw", JSON.stringify(d));
  } finally { await r.done(); }
});

test("a launcher that does not say (an older one) counts as unwalled: fail closed (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    await r.launcher.beginLaunch({ pid: process.pid, mode: "off", posture: "off", writeProtect: false });
    const { d, pinned } = await forgePin(r, 2);
    assert.equal(d.verdict, "twin", JSON.stringify(d));
    assert.equal(pinned, false);
  } finally { await r.done(); }
});

test("the exposure ends when the unwalled launch's launcher is gone, and a row deleted from mandu.db does not end it while the launcher lives (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    await r.launcher.beginLaunch({ pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false });
    // a program of the unwalled agent can write mandu.db directly (nothing
    // hides the home there); deleting its launch's row does not end the
    // exposure: the arbiter keeps it in memory too
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(join(r.dir, "db.sqlite"));
    db.exec("DELETE FROM unconfined_launches");
    db.close();
    assert.equal((await forgePin(r, 3)).d.verdict, "twin");
  } finally { await r.done(); }
});

test("the exposure ends when the unwalled launch's launcher is gone (secrets axes, explicit)", async () => {
  const r = await rig();
  const { spawn } = await import("node:child_process");
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  try {
    await r.launcher.beginLaunch({ pid: child.pid!, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false });
    assert.equal((await forgePin(r, 4)).d.verdict, "twin", "exposed while the launcher lives");
    const exited = new Promise((ok) => child.once("exit", ok));
    child.kill("SIGKILL");
    await exited;
    // the exposure answer is memoized for 250 ms: a gone launcher ends it at most that much later
    await new Promise((ok) => setTimeout(ok, 300));
    const d = await r.exposed.decideSecretOpen({ path: r.secret, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "gone-1", session: "exp" });
    assert.equal(d.verdict, "raw", JSON.stringify(d));
  } finally { child.kill("SIGKILL"); await r.done(); }
});

test("beginLaunch tells a launch which other unconfined launches are live, and whether each walls the human plane (secrets axes, explicit)", async () => {
  const r = await rig();
  try {
    const a = await r.launcher.beginLaunch({ pid: process.pid, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false });
    assert.deepEqual(a.others ?? [], []);
    const b = await r.launcher.beginLaunch({ pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true, humanPlaneWalled: true });
    assert.equal(b.confined, true);
    // MASTER: no `others` field
    assert.deepEqual((b.others ?? []).map((o) => [o.pid, o.posture, o.walled]), [[process.pid, "gated", false]]);
  } finally { await r.done(); }
});
