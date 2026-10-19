/**
 * cache-seals e2e — the enforcement caches' seals and epochs through the
 * REAL arbiter (confidentiality-plan-14-policy-suggestions.md §11.2):
 * in-process ArbiterServers with their human socket, the production
 * `ArbiterClient`, the REAL daemon entrypoint (server-main) killed and
 * stopped, and a REAL repository holding a committed-then-deleted deploy
 * key.
 *
 *   - the history-scan cache: an entry that marks the key's blob clean (the
 *     finding hidden) is refused, the scan starts fresh, the finding
 *     returns, and an admin event names the entry by kind and key;
 *   - the four ops are human plane: the data socket refuses each;
 *   - a seal from an older epoch is void after an `off` launch ends, after a
 *     `gated` launch ends, after a macOS `read-blocked` launch that does not
 *     claim `homeSealed` ends, and after an unclean restart (the daemon
 *     SIGKILLed); a clean restart (SIGTERM) and a `read-blocked` launch
 *     with the home sealed honour it.
 *
 * The oracle (implementation-plan.md §9): no reply, event or log carries the
 * key or an 8-character run of its body. Axes stated: secrets.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ADMIN_SESSION_ID, ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { CURRENT_LINK } from "../../ipc/instance.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";
import { randomSecretBody } from "../helpers/random-secret.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the caches serve the confidentiality axis

const ARBITER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SERVER_MAIN = join(ARBITER_DIR, "ipc", "server-main.ts");

// A letter and a digit, no placeholder run: a value the detectors take
// (a plain random draw has no digit 0.19% of the time; random-secret.ts).
const alnum = randomSecretBody;
const KEY_BODY = `${alnum(94)}a7`;
const PEM = `-----BEGIN OPENSSH ` + `PRIVATE KEY-----\n${KEY_BODY}\n-----END OPENSSH PRIVATE KEY-----\n`;
const RUNS = Array.from({ length: KEY_BODY.length - 7 }, (_, i) => KEY_BODY.slice(i, i + 8));
function noValue(what: string, s: string): void {
  assert.ok(!s.includes(PEM), `${what} carries the key`);
  assert.equal(RUNS.find((r) => s.includes(r)), undefined, `${what} carries an 8-character run of the key`);
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred: () => boolean, what: string, ms = 90_000): Promise<void> {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (pred()) return;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what}`);
}

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

interface Rig { server: ArbiterServer; data: ArbiterClient; human: ArbiterClient; close: () => Promise<void> }

async function rig(dir: string, db: string, extra: Partial<ConstructorParameters<typeof ArbiterServer>[0]> = {}): Promise<Rig> {
  const n = readdirSync(dir).filter((x) => x.startsWith("a-")).length;
  const sock = join(dir, `a-${n}.sock`);
  const humanSock = join(dir, `human-${n}`, "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: db, eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, packDir: null, ...extra,
  });
  await server.listen();
  const data = new ArbiterClient(sock);
  const human = new ArbiterClient(humanSock);
  return { server, data, human, close: async () => { data.close(); human.close(); await server.close(); } };
}

const seal = (key: string) => ({ kind: "object-twin", key, sha256: "a".repeat(64), size: 1 });

test("e2e: a history-scan entry that marks the key's blob clean is refused; the scan starts fresh and the finding returns", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seals-scan-"));
  dirs.push(dir);
  const home = join(dir, "home");
  const manduHome = join(dir, "mandu-home");
  const repo = join(home, "proj");
  mkdirSync(repo, { recursive: true });
  const gitEnv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t" };
  const git = (...a: string[]): string => execFileSync("git", a, { cwd: repo, env: gitEnv, encoding: "utf8" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(repo, "README.md"), "a project\n");
  git("add", "."); git("commit", "-qm", "init");
  mkdirSync(join(repo, "deploy"));
  writeFileSync(join(repo, "deploy", "id_ed25519"), PEM);
  git("add", "."); git("commit", "-qm", "add deploy key");
  git("rm", "-q", "deploy/id_ed25519"); git("commit", "-qm", "remove it");
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, "version: 1\n");

  // The production default: the cache dir from MANDU_HOME, as the daemon.
  const saved = process.env["MANDU_HOME"];
  process.env["MANDU_HOME"] = manduHome;
  let r: Rig;
  try {
    r = await rig(dir, join(dir, "mandu.db"), { policyPath: policy });
  } finally {
    if (saved === undefined) delete process.env["MANDU_HOME"]; else process.env["MANDU_HOME"] = saved;
  }
  try {
    const first = await r.data.scanSecretHistory([repo], home);
    assert.equal(first.repos[0]!.cache!.plan, "fresh");
    const finding = first.findings.find((f) => f.paths.includes("deploy/id_ed25519"));
    assert.ok(finding, "the deleted key is found");
    const again = await r.data.scanSecretHistory([repo], home);
    assert.equal(again.repos[0]!.cache!.plan, "hit", "the sealed entry is used");

    // An unconfined writer marks the key's blob clean: scanned, no hit.
    const cacheDir = join(manduHome, "state", "object-walks", "history-scan");
    const file = join(cacheDir, readdirSync(cacheDir).find((n) => n.endsWith(".json"))!);
    const entry = JSON.parse(readFileSync(file, "utf8")) as { hits: Record<string, unknown> };
    assert.ok(Object.keys(entry.hits).length >= 1, "precondition: the entry holds the hit");
    writeFileSync(file, JSON.stringify({ ...entry, hits: {} }));

    const later = await r.data.scanSecretHistory([repo], home);
    assert.equal(later.repos[0]!.cache!.plan, "fresh", "the tampered entry is not used");
    assert.ok(later.findings.some((f) => f.paths.includes("deploy/id_ed25519")), "the finding returns");

    const events = await r.human.events(ADMIN_SESSION_ID);
    const rejected = events.filter((e) => (e as unknown as { cacheSeal?: { action: string } }).cacheSeal?.action === "rejected");
    assert.equal(rejected.length, 1, JSON.stringify(events.map((e) => e.kind)));
    const key = file.slice(file.lastIndexOf("/") + 1, -".json".length);
    assert.deepEqual((rejected[0] as unknown as { cacheSeal: { entries: unknown[] } }).cacheSeal.entries, [{ kind: "history-scan", key, reason: "mismatch" }]);
    noValue("the replies and events", JSON.stringify([first, again, later, events]));
  } finally {
    await r.close();
  }
});

test("e2e: the seal ops are human plane; an off launch's end and a gated launch's end void every older seal; a confined launch voids nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seals-ops-"));
  dirs.push(dir);
  const r = await rig(dir, join(dir, "mandu.db"));
  try {
    for (const [op, call] of [
      ["cacheSeals", () => r.data.cacheSeals("object-twin", ["k"])],
      ["sealCacheEntries", () => r.data.sealCacheEntries([seal("k")])],
      ["beginLaunch", () => r.data.beginLaunch({ pid: process.pid, mode: "off", posture: "off", writeProtect: false })],
      ["endLaunch", () => r.data.endLaunch("t")],
    ] as const) {
      await assert.rejects(call as () => Promise<unknown>, new RegExp(`human-plane: '${op}'`), `${op} on the data socket`);
    }

    const e0 = (await r.human.sealCacheEntries([seal("k")])).epoch;
    assert.deepEqual((await r.human.cacheSeals("object-twin", ["k"])).seals, [{ key: "k", sha256: "a".repeat(64), size: 1 }]);

    const confined = await r.human.beginLaunch({ pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true });
    assert.equal(confined.confined, true);
    assert.equal((await r.human.cacheSeals("object-twin", ["k"])).honoured, true);
    assert.deepEqual(await r.human.endLaunch(confined.token), { ended: false, rotated: false, epoch: e0 });
    assert.equal((await r.human.cacheSeals("object-twin", ["k"])).seals.length, 1, "a confined launch voids nothing");

    let epoch = e0;
    for (const [mode, posture] of [["off", "off"], ["secrets", "gated"]] as const) {
      await r.human.sealCacheEntries([seal("k")]);
      const l = await r.human.beginLaunch({ pid: process.pid, mode, posture, writeProtect: mode !== "off" });
      assert.equal(l.confined, false, `${mode}/${posture} is unconfined`);
      const during = await r.human.cacheSeals("object-twin", ["k"]);
      assert.equal(during.honoured, false);
      assert.deepEqual(during.seals, []);
      const end = await r.human.endLaunch(l.token);
      assert.equal(end.rotated, true);
      assert.notEqual(end.epoch, epoch, `${posture}: a new epoch`);
      epoch = end.epoch;
      const now = await r.human.cacheSeals("object-twin", ["k"]);
      assert.equal(now.honoured, true);
      assert.deepEqual(now.seals, [], `${posture}: the older seal is void`);
    }
    const rotated = (await r.human.events(ADMIN_SESSION_ID)).filter((e) => (e as unknown as { cacheSeal?: { action: string } }).cacheSeal?.action === "rotated");
    assert.equal(rotated.length, 2, "each rotation is on the record");
  } finally {
    await r.close();
  }
});

test("e2e, macOS claim: a read-blocked launch with homeSealed voids nothing; without it (or with a non-boolean) it is an unconfined period whose end voids every older seal", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seals-mac-"));
  dirs.push(dir);
  const r = await rig(dir, join(dir, "mandu.db"));
  try {
    const e0 = (await r.human.sealCacheEntries([seal("k")])).epoch;
    const sealed = await r.human.beginLaunch({ pid: process.pid, mode: "secrets", posture: "read-blocked", writeProtect: true, homeSealed: true });
    assert.equal(sealed.confined, true, "the one profile seals the home: confined for the caches");
    assert.equal((await r.human.cacheSeals("object-twin", ["k"])).honoured, true);
    assert.deepEqual(await r.human.endLaunch(sealed.token), { ended: false, rotated: false, epoch: e0 });
    assert.equal((await r.human.cacheSeals("object-twin", ["k"])).seals.length, 1, "its end voids nothing");

    // The wire as a launcher could send it: only a literal `true` counts.
    let epoch = e0;
    for (const claim of [{}, { homeSealed: false }, { homeSealed: "true" }] as const) {
      await r.human.sealCacheEntries([seal("k")]);
      const l = await r.human.beginLaunch({ pid: process.pid, mode: "secrets", posture: "read-blocked", writeProtect: true, ...(claim as { homeSealed?: boolean }) });
      assert.equal(l.confined, false, JSON.stringify(claim));
      assert.equal((await r.human.cacheSeals("object-twin", ["k"])).honoured, false, `${JSON.stringify(claim)}: no seal honoured while it runs`);
      const end = await r.human.endLaunch(l.token);
      assert.equal(end.rotated, true);
      assert.notEqual(end.epoch, epoch);
      epoch = end.epoch;
      assert.deepEqual((await r.human.cacheSeals("object-twin", ["k"])).seals, [], `${JSON.stringify(claim)}: the older seal is void`);
    }
    // homeSealed never lifts another posture.
    const gated = await r.human.beginLaunch({ pid: process.pid, mode: "secrets", posture: "gated", writeProtect: true, homeSealed: true });
    assert.equal(gated.confined, false);
    await r.human.endLaunch(gated.token);
  } finally {
    await r.close();
  }
});

/** The real daemon on `db`: its data socket (`current`) and its human socket. */
async function daemon(root: string, db: string): Promise<{ child: ChildProcess; data: ArbiterClient; human: ArbiterClient; stderr: () => string }> {
  const base = join(root, `rt-${readdirSync(root).length}`);
  const child = spawn(process.execPath, ["--import", "tsx", SERVER_MAIN, "--symbol-db", db, "--event-dir", join(root, "events")], {
    cwd: ARBITER_DIR,
    env: {
      ...process.env, MANDU_RUNTIME_DIR: base, MANDU_HOME: join(root, "home"), MANDU_ARBITER_SOCK: "", MANDU_ARBITER_HUMAN_SOCK: "",
      MANDU_PROMOTE: "1", MANDU_MODE: "secrets", MANDU_POLICY_FILE: join(root, "policy.yaml"),
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (c: string) => { stderr += c; });
  const sock = join(base, CURRENT_LINK, "arbiter.sock");
  await waitFor(() => existsSync(sock) || child.exitCode !== null, `the daemon (stderr: ${stderr})`);
  assert.equal(child.exitCode, null, stderr);
  const data = new ArbiterClient(sock);
  const hs = (await data.hello()).humanSock;
  assert.ok(typeof hs === "string", "the daemon reports its human socket");
  return { child, data, human: new ArbiterClient(hs!), stderr: () => stderr };
}

async function stop(d: { child: ChildProcess; data: ArbiterClient; human: ArbiterClient }, signal: NodeJS.Signals): Promise<void> {
  d.data.close();
  d.human.close();
  await new Promise<void>((resolve) => {
    const kill = setTimeout(() => d.child.kill("SIGKILL"), 60_000);
    kill.unref();
    d.child.once("exit", () => { clearTimeout(kill); resolve(); });
    d.child.kill(signal);
  });
}

test("e2e: the real daemon SIGKILLed (an unclean shutdown) voids its seals at the next start; stopped cleanly (SIGTERM) it keeps them", { timeout: 240_000 }, async () => {
  // A short prefix: the instance socket lands deep under it (rt-1/instances/<id>/
  // arbiter.sock, 103-byte macOS / 107-byte Linux sun_path) and a suite's TMPDIR is longer than /tmp
  // (test-organization.md §8.5).
  const root = mkdtempSync(join(tmpdir(), "mdu-"));
  dirs.push(root);
  writeFileSync(join(root, "policy.yaml"), "version: 1\n");
  const db = join(root, "mandu.db");

  const a = await daemon(root, db);
  let e1: string;
  try {
    e1 = (await a.human.sealCacheEntries([seal("k")])).epoch;
    assert.equal((await a.human.cacheSeals("object-twin", ["k"])).seals.length, 1);
  } finally {
    await stop(a, "SIGTERM");
  }
  const b = await daemon(root, db);
  let e2: string;
  try {
    const got = await b.human.cacheSeals("object-twin", ["k"]);
    assert.equal(got.epoch, e1, `a clean restart keeps the epoch (stderr: ${b.stderr()})`);
    assert.equal(got.seals.length, 1, "and honours its seal");
    e2 = got.epoch;
  } finally {
    await stop(b, "SIGKILL");
  }
  const c = await daemon(root, db);
  try {
    const got = await c.human.cacheSeals("object-twin", ["k"]);
    assert.notEqual(got.epoch, e2, "an unclean restart starts a new epoch");
    assert.deepEqual(got.seals, [], "and every older seal is void");
    assert.equal(got.honoured, true);
  } finally {
    await stop(c, "SIGTERM");
  }
});


test("e2e: macOS confinement, human-plane wall and launch display metadata survive together through the real client", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seals-mac-wall-"));
  dirs.push(dir);
  const r = await rig(dir, join(dir, "mandu.db"));
  try {
    const sealed = await r.human.beginLaunch({
      pid: process.pid, mode: "secrets", posture: "read-blocked", writeProtect: true,
      homeSealed: true, humanPlaneWalled: true, sessionId: "mac-sealed", workspace: "/Users/u/project",
    });
    assert.equal(sealed.confined, true);
    assert.equal((await r.human.cacheSeals("object-twin", ["k"])).honoured, true);
    assert.equal((await r.human.humanPlaneStatus()).exposed, false);

    // A profile can wall the socket without sealing every part of the home:
    // caches stay void, but guard records remain attested.
    const partial = await r.human.beginLaunch({
      pid: process.pid, mode: "secrets", posture: "read-blocked", writeProtect: true,
      homeSealed: false, humanPlaneWalled: true, sessionId: "mac-partial", workspace: "/Users/u/project",
    });
    assert.equal(partial.confined, false);
    const partialStatus = await r.human.cacheSeals("object-twin", ["k"]);
    assert.equal(partialStatus.honoured, false);
    assert.deepEqual(partialStatus.live?.map((l) => [l.session, l.workspace, l.why, l.walled]),
      [["mac-partial", "/Users/u/project", "posture read-blocked", true]]);
    assert.equal((await r.human.humanPlaneStatus()).exposed, false);

    const unwalled = await r.human.beginLaunch({
      pid: process.pid, mode: "secrets", posture: "read-blocked", writeProtect: true,
      homeSealed: false, humanPlaneWalled: false, sessionId: "mac-unwalled", workspace: "/Users/u/other",
    });
    assert.equal(unwalled.confined, false);
    assert.deepEqual(unwalled.others?.map((l) => [l.session, l.workspace]), [["mac-partial", "/Users/u/project"]]);
    const exposure = await r.human.humanPlaneStatus();
    assert.equal(exposure.exposed, true);
    assert.deepEqual(exposure.launches.map((l) => [l.session, l.posture]), [["mac-unwalled", "read-blocked"]]);
    await r.human.endLaunch(unwalled.token);
    assert.equal((await r.human.humanPlaneStatus()).exposed, false);
    assert.equal((await r.human.cacheSeals("object-twin", ["k"])).honoured, false, "the partial seal still voids caches");
    await r.human.endLaunch(partial.token);
    assert.equal((await r.human.cacheSeals("object-twin", ["k"])).honoured, true);
    await r.human.endLaunch(sealed.token);
  } finally { await r.close(); }
});
