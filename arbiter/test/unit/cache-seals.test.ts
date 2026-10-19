/**
 * cache-seals — the enforcement caches' seal table and epochs
 * (confidentiality-plan-14-policy-suggestions.md §11.2; policy/cache-seals.ts)
 * over a real mandu.db file, with the clock, the epoch ids and the pid
 * liveness injected:
 *
 *   - the seal table: add-only, current-epoch answers, the shape checks, the
 *     per-epoch cap;
 *   - the verify logic: ok / unsealed / mismatch / not-honoured;
 *   - classification, fail closed (a macOS `read-blocked` launch counts only
 *     with `homeSealed`);
 *   - the launcher's start token: /proc on Linux, `ps -o lstart=` on darwin
 *     (injected sources; the real ones on this host);
 *   - the rotation triggers: an unconfined launch's end (by token, by its
 *     launcher's pid gone or reused, an invisible pid's expiry), an unclean
 *     restart (never shut down, shut down with an unconfined launch live, a
 *     run with the confidentiality axis off), and a clean restart that keeps
 *     the epoch and its seals;
 *   - the history-scan cache through the gate: a tampered entry is refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../../db/sqlite.js";
import {
  CacheSealStore, claimWorkspace, unconfinedWhy, DARWIN_START_MEMO_MS, INVISIBLE_LAUNCH_MAX_MS, launchConfinedForCaches, parseLstartUtc, pidExists, procStartTime, PS_ENV, realProcStartSource,
  sealGate, sha256Hex, type CacheSealStoreOptions, type ProcStartSource,
} from "../../policy/cache-seals.js";
import { LockResolver, resolutionSealKey } from "../../policy/lock-resolution.js";
import { fileHistoryScanCache, historyCacheFile, type HistoryScanCacheEntry } from "../../policy/secret-history-cache.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the seals serve the confidentiality axis; one case runs a store with it OFF by option

const sha = (s: string): string => sha256Hex(Buffer.from(s));

interface Rig {
  dir: string;
  db: string;
  now: { t: number };
  alive: Set<number>;
  starts: Map<number, string>;
  rotations: Array<{ from: string | null; to: string; reason: string }>;
  open: (o?: Partial<CacheSealStoreOptions>) => CacheSealStore;
  done: () => void;
}

function rig(): Rig {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seals-"));
  let n = 0;
  const r: Rig = {
    dir, db: join(dir, "mandu.db"), now: { t: 1_000_000 }, alive: new Set(), starts: new Map(), rotations: [],
    open: (o = {}) => new CacheSealStore({
      dbPath: r.db, confidentiality: true, now: () => r.now.t, newEpoch: () => `epoch-${++n}`,
      pidExists: (p) => r.alive.has(p), procStartTime: (p) => r.starts.get(p) ?? null,
      onRotate: (e) => r.rotations.push(e), ...o,
    }),
    done: () => rmSync(dir, { recursive: true, force: true }),
  };
  return r;
}

const SEAL = (key: string, body = key) => ({ kind: "object-twin", key, sha256: sha(body), size: Buffer.byteLength(body) });

test("seal table: add-only in the current epoch; answers only the asked keys of the kind; malformed entries refused", () => {
  const r = rig();
  try {
    const s = r.open();
    const e = s.epoch();
    assert.match(e, /^epoch-1$/);
    assert.deepEqual(r.rotations.map((x) => x.reason), ["first start"]);
    assert.deepEqual(s.record([SEAL("a/p.pack"), SEAL("a/p.idx"), { ...SEAL("w1"), kind: "history-walk" }]), { epoch: e, recorded: 3 });
    assert.deepEqual(s.record([SEAL("a/p.pack")]).recorded, 1, "a repeat refreshes, never duplicates");
    const got = s.seals("object-twin", ["a/p.pack", "w1", "missing"]);
    assert.equal(got.honoured, true);
    assert.deepEqual(got.seals, [{ key: "a/p.pack", sha256: sha("a/p.pack"), size: 8 }], "only asked keys of the kind");
    s.record([SEAL("a/p.pack", "other bytes")]);
    assert.equal(s.seals("object-twin", ["a/p.pack"]).seals.length, 2, "add-only: a second seal beside the first");
    for (const bad of [
      { kind: "Bad", key: "k", sha256: sha("x"), size: 1 },
      { kind: "object-twin", key: "../k", sha256: sha("x"), size: 1 },
      { kind: "object-twin", key: "k", sha256: "ABC", size: 1 },
      { kind: "object-twin", key: "k", sha256: sha("x"), size: -1 },
      { kind: "object-twin", key: "k", sha256: sha("x"), size: 1.5 },
    ]) assert.throws(() => s.record([bad]), /sealCacheEntries: every entry is/, JSON.stringify(bad));
    assert.throws(() => s.seals("object-twin", ["ok", "no spaces allowed"]), /cacheSeals: keys must be/);
    assert.throws(() => s.seals("x y", []), /cacheSeals: kind must match/);
    s.markShutdown();
  } finally { r.done(); }
});

test("check: ok only for bytes a current-epoch seal vouches for; unsealed, mismatch, not-honoured otherwise", () => {
  const r = rig();
  try {
    const s = r.open();
    s.sealBytes("history-scan", "abc", Buffer.from("entry-bytes"));
    assert.equal(s.check("history-scan", "abc", Buffer.from("entry-bytes")), "ok");
    assert.equal(s.check("history-scan", "abc", Buffer.from("entry-bytez")), "mismatch");
    assert.equal(s.check("history-scan", "abd", Buffer.from("entry-bytes")), "unsealed");
    assert.equal(s.check("history-walk", "abc", Buffer.from("entry-bytes")), "unsealed", "the kind is part of the seal");
    r.alive.add(7);
    s.beginLaunch({ pid: 7, mode: "off", posture: "off", writeProtect: false });
    assert.equal(s.check("history-scan", "abc", Buffer.from("entry-bytes")), "not-honoured");
    s.markShutdown();
  } finally { r.done(); }
});

test("classification fails closed: confined only for secrets/full, posture confined, home write-protected, the axis on", () => {
  const ok = { pid: 1, mode: "secrets", posture: "confined", writeProtect: true };
  assert.equal(launchConfinedForCaches(ok, true), true);
  assert.equal(launchConfinedForCaches({ ...ok, mode: "full" }, true), true);
  assert.equal(launchConfinedForCaches(ok, false), false, "an arbiter with the axis off confines nothing");
  for (const bad of [{ mode: "off" }, { mode: "injection" }, { mode: "unknown" }, { mode: undefined }, { posture: "gated" }, { posture: "read-blocked" },
    { posture: "off" }, { posture: undefined }, { writeProtect: false }, { writeProtect: undefined }]) {
    assert.equal(launchConfinedForCaches({ ...ok, ...bad } as never, true), false, JSON.stringify(bad));
  }
});

test("classification, macOS: read-blocked counts only with homeSealed (the one Seatbelt profile seals the home), and the rest of the rule still holds", () => {
  const mac = { pid: 1, mode: "secrets", posture: "read-blocked", writeProtect: true, homeSealed: true };
  assert.equal(launchConfinedForCaches(mac, true), true);
  assert.equal(launchConfinedForCaches({ ...mac, mode: "full" }, true), true);
  assert.equal(launchConfinedForCaches(mac, false), false, "an arbiter with the axis off confines nothing");
  for (const bad of [
    { homeSealed: false }, { homeSealed: undefined }, { homeSealed: "true" }, { homeSealed: 1 },
    { writeProtect: false }, { mode: "off" }, { mode: "injection" }, { posture: "gated" }, { posture: "off" }, { posture: "Read-Blocked" },
  ]) {
    assert.equal(launchConfinedForCaches({ ...mac, ...bad } as never, true), false, JSON.stringify(bad));
  }
  // homeSealed is read only beside read-blocked: it neither makes a gated
  // launch confined nor is needed by the Linux posture.
  assert.equal(launchConfinedForCaches({ pid: 1, mode: "secrets", posture: "gated", writeProtect: true, homeSealed: true }, true), false);
  assert.equal(launchConfinedForCaches({ pid: 1, mode: "secrets", posture: "confined", writeProtect: true, homeSealed: false }, true), true);
});

test("rotation, macOS: a read-blocked launch with the home sealed holds nothing void and its end rotates nothing; without the seal it is an unconfined period", () => {
  const r = rig();
  try {
    const s = r.open();
    s.record([SEAL("k")]);
    r.alive.add(41);
    const sealed = s.beginLaunch({ pid: 41, mode: "secrets", posture: "read-blocked", writeProtect: true, homeSealed: true });
    assert.equal(sealed.confined, true);
    assert.deepEqual(s.liveLaunches(), [], "a confined launch is not stored");
    assert.equal(s.status().honoured, true);
    assert.deepEqual(s.endLaunch(sealed.token), { ended: false, rotated: false, epoch: "epoch-1" });
    assert.equal(s.seals("object-twin", ["k"]).seals.length, 1, "its seals survive");

    const open = s.beginLaunch({ pid: 41, mode: "secrets", posture: "read-blocked", writeProtect: true });
    assert.equal(open.confined, false, "no seal claim: unconfined (fail closed)");
    assert.deepEqual(s.liveLaunches().map((l) => l.posture), ["read-blocked"]);
    assert.equal(s.status().honoured, false);
    assert.equal(s.endLaunch(open.token).rotated, true);
    assert.deepEqual(s.seals("object-twin", ["k"]).seals, [], "its end voided the older seal");
    s.markShutdown();
  } finally { r.done(); }
});

// ── procStartTime: /proc on Linux, `ps -o lstart=` on darwin ─────────────────

/** A source whose calls are recorded; each rung answers what it is given. */
function source(platform: NodeJS.Platform, ans: { stat?: string | Error; lstart?: string | Error }): ProcStartSource & { calls: string[] } {
  const calls: string[] = [];
  const give = (v: string | Error | undefined, what: string): string => {
    calls.push(what);
    if (v === undefined) throw new Error(`${what}: not expected`);
    if (v instanceof Error) throw v;
    return v;
  };
  return { platform, calls, readProcStat: (pid) => give(ans.stat, `stat ${pid}`), psLstart: (pid) => give(ans.lstart, `ps ${pid}`) };
}

test("procStartTime, darwin: `ps -o lstart=` in UTC as epoch ms; a failed ps (a gone pid) or an unknown shape is null; /proc is never read", () => {
  const ok = source("darwin", { lstart: "Wed Sep 30 20:01:39 2026\n" });
  assert.equal(procStartTime(4242, ok), String(Date.UTC(2026, 8, 30, 20, 1, 39)));
  assert.deepEqual(ok.calls, ["ps 4242"], "ps only");
  assert.equal(procStartTime(7, source("darwin", { lstart: "Thu Oct  1 03:04:05 2026" })), String(Date.UTC(2026, 9, 1, 3, 4, 5)), "a space-padded day");
  assert.equal(procStartTime(7, source("darwin", { lstart: new Error("Command failed: /bin/ps (exit 1)") })), null);
  assert.equal(procStartTime(7, source("darwin", { lstart: "" })), null);
  assert.equal(procStartTime(7, source("darwin", { lstart: "mer 30 sep 2026 20:01:39 CEST" })), null, "a localized shape is never taken");
  for (const bad of [0, -1, 1.5, Number.NaN]) {
    const s = source("darwin", { lstart: "Wed Sep 30 20:01:39 2026" });
    assert.equal(procStartTime(bad, s), null);
    assert.deepEqual(s.calls, [], `no ps for ${bad}`);
  }
  assert.equal(parseLstartUtc("Wed Sep 30 20:01:39 2026"), Date.UTC(2026, 8, 30, 20, 1, 39));
  assert.equal(parseLstartUtc("Wed Foo 30 20:01:39 2026"), null);
  assert.deepEqual(PS_ENV, { LC_ALL: "C", TZ: "UTC0", PATH: "/usr/bin:/bin" }, "the C locale and UTC: a fixed shape a zone change cannot move");
});

test("procStartTime, Linux (unchanged): field 22 of /proc/<pid>/stat, a comm with spaces and parens included; ps is never run", () => {
  const stat = `1234 (a (b) c) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n`;
  const s = source("linux", { stat });
  assert.equal(procStartTime(1234, s), "987654");
  assert.deepEqual(s.calls, ["stat 1234"], "/proc only");
  assert.equal(procStartTime(1, source("linux", { stat: new Error("ENOENT") })), null);
  assert.equal(procStartTime(1, source("linux", { stat: "1 (x) S 1" })), null, "a short stat");
});

test("the store's start reads, darwin: `ps` at most once per pid per DARWIN_START_MEMO_MS however many answers reap; beginLaunch reads fresh; a reused pid still ends the period", () => {
  const r = rig();
  try {
    let lstart = "Wed Sep 30 20:01:39 2026";
    const src = source("darwin", {});
    src.psLstart = (pid) => { src.calls.push(`ps ${pid}`); return lstart; };
    const s = r.open({ procStartTime: undefined, procStartSource: src });
    const ps = (): number => src.calls.filter((c) => c.startsWith("ps ")).length;
    r.alive.add(51);
    s.beginLaunch({ pid: 51, mode: "secrets", posture: "gated", writeProtect: true });
    assert.equal(ps(), 1, "the recorded token is one fresh read");
    for (let i = 0; i < 50; i++) assert.equal(s.status().honoured, false);
    for (let i = 0; i < 20; i++) assert.equal(s.check("history-scan", "k", Buffer.from("x")), "not-honoured");
    assert.equal(ps(), 1, "70 answers within the memo window: no ps");
    r.now.t += DARWIN_START_MEMO_MS - 1;
    s.status();
    assert.equal(ps(), 1, "still inside the window");
    r.now.t += 1;
    for (let i = 0; i < 10; i++) s.status();
    assert.equal(ps(), 2, "one read per window");
    // A second launch from the same pid (a test's launcher, a reused pid):
    // its token is read fresh although the memo holds one.
    s.beginLaunch({ pid: 51, mode: "off", posture: "off", writeProtect: false });
    assert.equal(ps(), 3, "beginLaunch never takes the memo");
    // The launcher ends and its pid is reused: within the window the memo
    // keeps the old token (the period stays open, seals stay void); the next
    // read sees the new start and ends both periods.
    lstart = "Wed Sep 30 20:05:00 2026";
    assert.equal(s.status().honoured, false, "within the window: still live (fail safe)");
    r.now.t += DARWIN_START_MEMO_MS;
    const st = s.status();
    assert.equal(st.honoured, true, "the reused pid was seen: the periods ended");
    assert.match(r.rotations.at(-1)!.reason, /launcher gone/);
    assert.equal(ps(), 4);
    // A clock that went back reads fresh.
    s.beginLaunch({ pid: 51, mode: "off", posture: "off", writeProtect: false });
    r.now.t -= 10_000;
    s.status();
    assert.equal(ps(), 6);
    s.markShutdown();
  } finally { r.done(); }
});

test("the store's start reads, Linux (unchanged): /proc on every check, no memo", () => {
  const r = rig();
  try {
    const stat = `51 (node) S 1 51 51 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 424242 1000 100 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n`;
    const src = source("linux", { stat });
    const s = r.open({ procStartTime: undefined, procStartSource: src });
    r.alive.add(51);
    s.beginLaunch({ pid: 51, mode: "secrets", posture: "gated", writeProtect: true });
    for (let i = 0; i < 5; i++) s.status();
    assert.deepEqual(src.calls, Array(11).fill("stat 51"), "one fresh read at beginLaunch; each answer checks the durable row and in-memory exposure without a memo");
    assert.equal(s.status().honoured, false);
    s.markShutdown();
  } finally { r.done(); }
});

test("procStartTime on this host: this process has a stable start token (Linux /proc, darwin ps), a gone pid has none", { skip: process.platform !== "linux" && process.platform !== "darwin" ? "Linux and darwin only" : false }, async () => {
  const a = procStartTime(process.pid);
  assert.ok(a !== null && /^\d+$/.test(a), String(a));
  assert.equal(procStartTime(process.pid), a, "stable");
  assert.equal(realProcStartSource.platform, process.platform);
  const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
  try {
    await new Promise((res) => child.once("spawn", res));
    const pid = child.pid!;
    const t = procStartTime(pid);
    assert.ok(t !== null, "a live child has one");
    const gone = new Promise((res) => child.once("exit", res));
    child.kill("SIGKILL");
    await gone;
    // Reaped by node once `exit` fired: the pid is free.
    assert.equal(pidExists(pid) ? "live" : procStartTime(pid), null, "a gone pid answers null");
  } finally {
    try { child.kill("SIGKILL"); } catch { /* gone */ }
  }
});

test("the store with the REAL liveness and start-time sources: an unconfined launch whose launcher exits ends its period (the darwin ps rung included)", { skip: process.platform !== "linux" && process.platform !== "darwin" ? "Linux and darwin only" : false }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seals-real-"));
  const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 30000)"], { stdio: "ignore" });
  try {
    await new Promise((res) => child.once("spawn", res));
    let n = 0;
    const s = new CacheSealStore({ dbPath: join(dir, "mandu.db"), confidentiality: true, newEpoch: () => `real-${++n}` });
    s.record([SEAL("k")]);
    s.beginLaunch({ pid: child.pid!, mode: "secrets", posture: "gated", writeProtect: true });
    assert.equal(s.status().honoured, false, "its launcher is live");
    const db = new Database(join(dir, "mandu.db"));
    const row = db.prepare("SELECT pid_start FROM unconfined_launches").get() as { pid_start: string | null };
    db.close();
    assert.ok(row.pid_start !== null && /^\d+$/.test(row.pid_start), `the reuse guard is recorded: ${String(row.pid_start)}`);
    const gone = new Promise((res) => child.once("exit", res));
    child.kill("SIGKILL");
    await gone;
    const st = s.status();
    assert.equal(st.honoured, true, "the launcher is gone: the period ended");
    assert.notEqual(st.epoch, "real-1");
    s.markShutdown();
  } finally {
    try { child.kill("SIGKILL"); } catch { /* gone */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("rotation: an unconfined launch holds every seal void while live; its end starts a new epoch; a confined launch changes nothing", () => {
  const r = rig();
  try {
    const s = r.open();
    s.record([SEAL("k")]);
    r.alive.add(11).add(12);
    const confined = s.beginLaunch({ pid: 11, mode: "secrets", posture: "confined", writeProtect: true });
    assert.equal(confined.confined, true);
    assert.equal(s.status().honoured, true, "a confined launch holds nothing void");
    assert.deepEqual(s.endLaunch(confined.token), { ended: false, rotated: false, epoch: "epoch-1" });

    for (const [posture, mode] of [["off", "off"], ["gated", "secrets"]] as const) {
      const before = s.epoch();
      s.record([SEAL("k")]);
      const l = s.beginLaunch({ pid: 12, mode, posture, writeProtect: mode !== "off" });
      assert.equal(l.confined, false);
      const st = s.status();
      assert.equal(st.honoured, false);
      assert.match(st.reason!, /1 unconfined launch is live/);
      assert.deepEqual(s.seals("object-twin", ["k"]).seals, [], `${posture}: none answered while it runs`);
      const end = s.endLaunch(l.token);
      assert.equal(end.rotated, true);
      assert.notEqual(end.epoch, before, `${posture}: a new epoch`);
      assert.equal(s.status().honoured, true);
      assert.deepEqual(s.seals("object-twin", ["k"]).seals, [], `${posture}: the older seal is void`);
      assert.equal(r.rotations.at(-1)!.reason, "an unconfined launch ended");
    }
    assert.deepEqual(s.endLaunch("tok-unknown"), { ended: false, rotated: false, epoch: s.epoch() }, "an unknown token changes nothing");
    assert.throws(() => s.beginLaunch({ pid: 0, mode: "off", posture: "off", writeProtect: false }), /pid must be a positive integer/);
    s.markShutdown();
  } finally { r.done(); }
});

test("rotation: a launcher whose pid is gone, or reused by another process, ends its period; an invisible pid is live until its end or a day", () => {
  const r = rig();
  try {
    const s = r.open();
    r.alive.add(21);
    r.starts.set(21, "500");
    s.beginLaunch({ pid: 21, mode: "off", posture: "off", writeProtect: false });
    s.record([SEAL("k")]);
    assert.equal(s.status().honoured, false);
    r.alive.delete(21);
    const e1 = s.epoch();
    assert.equal(s.status().honoured, true, "the launcher is gone: the period ended");
    assert.notEqual(s.epoch(), e1);
    assert.match(r.rotations.at(-1)!.reason, /1 unconfined launch ended \(launcher gone\)/);

    r.alive.add(22);
    r.starts.set(22, "600");
    s.beginLaunch({ pid: 22, mode: "secrets", posture: "gated", writeProtect: true });
    assert.equal(s.status().honoured, false);
    r.starts.set(22, "999"); // the pid now names another process
    assert.equal(s.status().honoured, true, "a reused pid is not the launcher");

    // Pid 23 is not visible to this arbiter (another pid namespace).
    const inv = s.beginLaunch({ pid: 23, mode: "off", posture: "off", writeProtect: false });
    assert.equal(s.status().honoured, false);
    r.now.t += INVISIBLE_LAUNCH_MAX_MS - 1;
    assert.equal(s.status().honoured, false, "live until its end");
    assert.equal(s.endLaunch(inv.token).rotated, true);
    s.beginLaunch({ pid: 23, mode: "off", posture: "off", writeProtect: false });
    r.now.t += INVISIBLE_LAUNCH_MAX_MS;
    assert.equal(s.status().honoured, true, "or a day");
    s.markShutdown();
  } finally { r.done(); }
});

test("human-plane exposure (plan 13 D9 leftovers): only unwalled unconfined launches count; a row deleted by hand is still live in memory; a gone launcher ends it; `others` names the launches before", () => {
  const r = rig();
  try {
    const s = r.open();
    r.alive.add(31).add(32).add(33);
    r.starts.set(31, "1").set(32, "2").set(33, "3");
    assert.deepEqual(s.humanPlaneExposure(), []);
    const walled = s.beginLaunch({ pid: 31, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: true });
    assert.deepEqual(walled.others, []);
    assert.deepEqual(s.humanPlaneExposure(), [], "a walled launch exposes nothing");
    const conf = s.beginLaunch({ pid: 32, mode: "secrets", posture: "confined", writeProtect: true, humanPlaneWalled: true });
    assert.deepEqual(conf.others, [{ pid: 31, mode: "secrets", posture: "gated", walled: true, begunAt: r.now.t, why: "no file guard" }]);
    const bare = s.beginLaunch({ pid: 33, mode: "secrets", posture: "gated", writeProtect: false });
    assert.deepEqual(s.humanPlaneExposure(), [{ pid: 33, mode: "secrets", posture: "gated", walled: false, begunAt: r.now.t }], "no field: unwalled");
    // a program of that launch's agent deletes its row from mandu.db
    const db = new Database(r.db);
    db.exec("DELETE FROM unconfined_launches WHERE pid = 33");
    db.close();
    assert.equal(s.humanPlaneExposure().length, 1, "still live in memory");
    assert.equal(s.status().honoured, false, "and still an unconfined period for the seals");
    r.alive.delete(33);
    assert.deepEqual(s.humanPlaneExposure(), [], "its launcher is gone");
    assert.match(r.rotations.at(-1)!.reason, /launcher gone/);
    assert.equal(s.endLaunch(bare.token).ended, false, "already ended");
    s.markShutdown();
  } finally { r.done(); }
});

test("human-plane exposure: a store from before the `walled` column gains it, and a launch row it holds counts as unwalled", () => {
  const r = rig();
  try {
    const db = new Database(r.db);
    db.exec("CREATE TABLE unconfined_launches (token TEXT PRIMARY KEY, pid INTEGER NOT NULL, pid_start TEXT, mode TEXT NOT NULL, posture TEXT NOT NULL, begun_at INTEGER NOT NULL)");
    db.prepare("INSERT INTO unconfined_launches VALUES (?, ?, ?, ?, ?, ?)").run("old", 41, "7", "off", "off", r.now.t);
    db.close();
    r.alive.add(41);
    r.starts.set(41, "7");
    const s = r.open();
    assert.deepEqual(s.humanPlaneExposure(), [{ pid: 41, mode: "off", posture: "off", walled: false, begunAt: r.now.t }]);
    s.markShutdown();
  } finally { r.done(); }
});

test("human-plane exposure names each launch's session (display only): a scope-id-shaped one is kept, in the row and in memory; anything else is dropped; a store from before the column gains it", () => {
  const r = rig();
  try {
    const db = new Database(r.db);
    db.exec("CREATE TABLE unconfined_launches (token TEXT PRIMARY KEY, pid INTEGER NOT NULL, pid_start TEXT, mode TEXT NOT NULL, posture TEXT NOT NULL, begun_at INTEGER NOT NULL, walled INTEGER)");
    db.close();
    const s = r.open();
    r.alive.add(51).add(52).add(53);
    r.starts.set(51, "1").set(52, "2").set(53, "3");
    s.beginLaunch({ pid: 51, mode: "off", posture: "off", writeProtect: false, sessionId: "claude-20261003-ab12" });
    r.now.t += 1;
    s.beginLaunch({ pid: 52, mode: "secrets", posture: "gated", writeProtect: false, sessionId: "../../etc\nforged line" });
    r.now.t += 1;
    const walled = s.beginLaunch({ pid: 53, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: true, sessionId: "walled-1" });
    const got = s.humanPlaneExposure();
    assert.deepEqual(got.map((l) => [l.pid, l.session]), [[51, "claude-20261003-ab12"], [52, undefined]], "oldest first; the bad name dropped; the walled one is not exposure");
    assert.ok(!("session" in got[1]!), "no field at all when not named");
    // a program of that agent rewrites its row: the in-memory copy wins
    const w = new Database(r.db);
    w.exec("UPDATE unconfined_launches SET session = 'renamed' WHERE pid = 51");
    w.close();
    assert.equal(s.humanPlaneExposure()[0]!.session, "claude-20261003-ab12");
    s.endLaunch(walled.token);
    s.markShutdown();
  } finally { r.done(); }
});

test("why a launch is unconfined, in plain words: the first rule it fails; null when confined", () => {
  const ok = { pid: 1, mode: "secrets", posture: "confined", writeProtect: true };
  assert.equal(unconfinedWhy(ok, true), null);
  assert.equal(unconfinedWhy({ ...ok, mode: "full" }, true), null);
  assert.equal(unconfinedWhy(ok, false), "the protection service runs with secret protection off");
  assert.equal(unconfinedWhy({ ...ok, mode: "off", posture: "off" }, true), "protection off");
  assert.equal(unconfinedWhy({ ...ok, mode: "injection" }, true), "mode injection");
  assert.equal(unconfinedWhy({ ...ok, mode: undefined }, true), "mode unknown");
  assert.equal(unconfinedWhy({ ...ok, posture: "gated" }, true), "no file guard");
  assert.equal(unconfinedWhy({ ...ok, posture: "read-blocked" }, true), "posture read-blocked");
  assert.equal(unconfinedWhy({ ...ok, posture: "read-blocked", homeSealed: true }, true), null);
  assert.equal(unconfinedWhy({ ...ok, posture: "read-blocked", homeSealed: true, writeProtect: false }, true), "Mandu's home not write-protected");
  assert.equal(unconfinedWhy({ ...ok, writeProtect: false }, true), "Mandu's home not write-protected");
  // Agrees with the classification everywhere.
  for (const c of [ok, { ...ok, mode: "off" }, { ...ok, posture: "gated" }, { ...ok, writeProtect: false },
    { ...ok, posture: "read-blocked" }, { ...ok, posture: "read-blocked", homeSealed: true },
    { ...ok, posture: "read-blocked", homeSealed: true, writeProtect: false }]) {
    for (const axis of [true, false]) assert.equal(unconfinedWhy(c, axis) === null, launchConfinedForCaches(c, axis), JSON.stringify([c, axis]));
  }
});

test("a workspace claim is display only: an absolute path without a control character, at most 512 characters; anything else dropped", () => {
  assert.equal(claimWorkspace("/home/u/project"), "/home/u/project");
  assert.equal(claimWorkspace("/home/u/my project (2)"), "/home/u/my project (2)");
  for (const bad of ["relative/dir", "", "/x\nmandu: forged line", "/x\u001b[2Jclear", "/x\u009b", `/${"a".repeat(512)}`, 7, null, undefined]) {
    assert.equal(claimWorkspace(bad), null, JSON.stringify(bad));
  }
});

test("seals void while an unconfined launch runs: the answer names it (pid, workspace, why, session), oldest first, at most five; an unwalled one whose row was deleted is still named; a store from before the columns gains them", () => {
  const r = rig();
  try {
    const db = new Database(r.db);
    db.exec("CREATE TABLE unconfined_launches (token TEXT PRIMARY KEY, pid INTEGER NOT NULL, pid_start TEXT, mode TEXT NOT NULL, posture TEXT NOT NULL, begun_at INTEGER NOT NULL, walled INTEGER, session TEXT)");
    db.close();
    const s = r.open();
    assert.equal(s.status().live, undefined, "honoured: no list");
    for (const p of [61, 62, 63, 64, 65, 66]) { r.alive.add(p); r.starts.set(p, String(p)); }
    s.beginLaunch({ pid: 61, mode: "off", posture: "off", writeProtect: false, sessionId: "claude-off-1", workspace: "/home/u/wt-a" });
    r.now.t += 1;
    s.beginLaunch({ pid: 62, mode: "secrets", posture: "gated", writeProtect: true, humanPlaneWalled: true, workspace: "/x\nforged" });
    const st = s.status();
    assert.equal(st.honoured, false);
    assert.deepEqual(st.live, [
      { pid: 61, mode: "off", posture: "off", walled: false, session: "claude-off-1", begunAt: r.now.t - 1, workspace: "/home/u/wt-a", why: "protection off" },
      { pid: 62, mode: "secrets", posture: "gated", walled: true, begunAt: r.now.t, why: "no file guard" },
    ], "oldest first; the forged workspace dropped");
    assert.deepEqual(s.seals("object-twin", ["k"]).live?.map((l) => l.pid), [61, 62], "the cacheSeals answer carries it");
    // A program of the unwalled launch's agent deletes its row: still named.
    const w = new Database(r.db);
    w.exec("DELETE FROM unconfined_launches WHERE pid = 61");
    w.close();
    assert.deepEqual(s.status().live?.map((l) => [l.pid, l.workspace]), [[61, "/home/u/wt-a"], [62, undefined]]);
    for (const p of [63, 64, 65, 66]) { r.now.t += 1; s.beginLaunch({ pid: p, mode: "off", posture: "off", writeProtect: false }); }
    assert.deepEqual(s.status().live?.map((l) => l.pid), [61, 62, 63, 64, 65], "at most five");
    assert.match(s.status().reason!, /6 unconfined launches are live/, "the count stays whole");
    s.markShutdown();
  } finally { r.done(); }
});

test("restart: a clean shutdown keeps the epoch and its seals; no shutdown, one with an unconfined launch live, or a run with the axis off voids them", () => {
  const r = rig();
  try {
    const a = r.open();
    a.record([SEAL("k")]);
    const e = a.epoch();
    a.markShutdown();

    const b = r.open();
    assert.equal(b.epoch(), e, "a clean restart keeps the epoch");
    assert.equal(b.seals("object-twin", ["k"]).seals.length, 1, "and its seals are honoured");
    // b is never shut down (a crash, a SIGKILL, a power loss).

    const c = r.open();
    assert.notEqual(c.epoch(), e, "an unclean restart starts a new epoch");
    assert.equal(c.seals("object-twin", ["k"]).seals.length, 0);
    assert.match(r.rotations.at(-1)!.reason, /last shutdown was not clean/);
    c.record([SEAL("k")]);
    r.alive.add(31);
    c.beginLaunch({ pid: 31, mode: "off", posture: "off", writeProtect: false });
    c.markShutdown(); // with an unconfined launch live: not clean

    const d = r.open();
    assert.equal(d.seals("object-twin", ["k"]).honoured, false, "the launch survived the restart: still live");
    assert.equal(d.seals("object-twin", ["k"]).seals.length, 0, "and its epoch's seals are void");
    assert.equal(d.liveLaunches().length, 1);
    r.alive.delete(31);
    assert.equal(d.status().honoured, true);
    d.record([SEAL("k")]);
    d.markShutdown();

    const off = r.open({ confidentiality: false });
    assert.equal(off.status().honoured, false, "with the axis off nothing is honoured");
    assert.match(off.status().reason!, /confidentiality axis is off/);
    off.markShutdown();
    const on = r.open();
    assert.equal(on.seals("object-twin", ["k"]).seals.length, 0, "a run with the axis off voids every seal at the next start");
    on.markShutdown();
  } finally { r.done(); }
});

test("plan 14 §11.2.1 the rebuild notice: the answer says why the epoch began (unprotected-ended, unclean-stop, first-start), only while honoured; a by-hand rotation or an older store says nothing", () => {
  const r = rig();
  try {
    const s = r.open();
    assert.equal(s.status().epochCause, "first-start");
    assert.equal(s.seals("object-twin", ["k"]).epochCause, "first-start", "the cacheSeals answer carries it");

    // An `off` launch's end, then a `gated` one's launcher gone.
    r.alive.add(51).add(52);
    const off = s.beginLaunch({ pid: 51, mode: "off", posture: "off", writeProtect: false });
    assert.equal(s.status().epochCause, undefined, "not honoured: no cause (the live launch is the reason)");
    s.endLaunch(off.token);
    assert.equal(s.status().epochCause, "unprotected-ended");
    s.rotate("by hand");
    assert.equal(s.status().epochCause, undefined, "a rotation with no cause says none");
    s.beginLaunch({ pid: 52, mode: "secrets", posture: "gated", writeProtect: true });
    r.alive.delete(52);
    assert.equal(s.status().epochCause, "unprotected-ended", "its launcher gone ends the period the same way");
    // A confined launch's end rotates nothing: the cause stays.
    const conf = s.beginLaunch({ pid: 51, mode: "secrets", posture: "confined", writeProtect: true });
    s.endLaunch(conf.token);
    assert.equal(s.status().epochCause, "unprotected-ended");
    s.markShutdown();

    const kept = r.open();
    assert.equal(kept.status().epochCause, "unprotected-ended", "a clean restart keeps the epoch and its cause");
    // never shut down
    const unclean = r.open();
    assert.equal(unclean.status().epochCause, "unclean-stop");
    unclean.markShutdown();

    // A store an older arbiter rotated: no cause recorded.
    const db = new Database(r.db);
    db.prepare("DELETE FROM cache_seal_state WHERE name = 'rotation_cause'").run();
    db.close();
    const older = r.open();
    assert.equal(older.status().honoured, true);
    assert.equal("epochCause" in older.status(), false);
    older.markShutdown();
  } finally { r.done(); }
});

test("the per-epoch cap drops the oldest tenth (a rebuild, never a wrong answer)", () => {
  const r = rig();
  try {
    const s = r.open({ maxSealsPerEpoch: 10 });
    for (let i = 0; i < 10; i++) { r.now.t++; s.record([SEAL(`k${i}`)]); }
    r.now.t++;
    s.record([SEAL("k10")]);
    const left = s.seals("object-twin", Array.from({ length: 11 }, (_, i) => `k${i}`)).seals.map((x) => x.key).sort();
    assert.equal(left.length, 9);
    assert.ok(!left.includes("k0") && !left.includes("k1") && left.includes("k10"), left.join(","));
    s.markShutdown();
  } finally { r.done(); }
});

test("the history-scan cache through the gate: a save is sealed; a tampered entry (a finding's blob marked clean) is refused and reported; without a gate it would be read", () => {
  const r = rig();
  try {
    const s = r.open();
    const rejected: unknown[] = [];
    const dir = join(r.dir, "scan");
    const cache = fileHistoryScanCache(dir, { seals: sealGate(s, (x) => rejected.push(x)) });
    const blob = "a".repeat(40);
    const entry: HistoryScanCacheEntry = {
      v: 1, repoRoot: "/w/repo", base: "b", tips: ["c".repeat(40)], blobs: [[blob, 10, "deploy/key"]],
      scanned: [blob], binary: [], hits: { [blob]: [{ shape: "private-key", line: 1, preview: "-----BEGIN [masked]" }] }, traces: {},
    };
    assert.equal(cache.save(entry), true);
    assert.deepEqual(cache.load("/w/repo"), entry, "a sealed entry is read");
    const file = historyCacheFile(dir, "/w/repo");
    const tampered = { ...entry, hits: {} };
    writeFileSync(file, JSON.stringify(tampered));
    assert.deepEqual(fileHistoryScanCache(dir).load("/w/repo"), tampered, "precondition: an unsealed reader would take the finding as clean");
    assert.equal(cache.load("/w/repo"), null, "the tampered entry is refused: the scan starts fresh");
    const key = file.slice(file.lastIndexOf("/") + 1, -".json".length);
    assert.deepEqual(rejected, [{ kind: "history-scan", key, reason: "mismatch" }]);
    // A rotation voids the good one too (unsealed, reported).
    writeFileSync(file, JSON.stringify(entry));
    s.rotate("test");
    assert.equal(cache.load("/w/repo"), null);
    assert.deepEqual(rejected.at(-1), { kind: "history-scan", key, reason: "unsealed" });
    s.markShutdown();
  } finally { r.done(); }
});

test("lock resolutions read back from mandu.db (plan 14 §11.1 R2) are used only under a seal of the current epoch: a changed row is refused and reported, a rotation voids them all", async () => {
  const r = rig();
  const env = {
    ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
  };
  const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env });
  const blobOf = (cwd: string, body: string): string => execFileSync("git", ["hash-object", "--stdin"], { cwd, input: body, encoding: "utf8", env }).trim();
  try {
    const root = join(realpathSync(r.dir), "repo");
    mkdirSync(join(root, "deploy"), { recursive: true });
    git(root, "init", "-q", "-b", "main");
    writeFileSync(join(root, "deploy", "key"), "gone-v1\n");
    git(root, "add", "."); git(root, "commit", "-qm", "1");
    git(root, "rm", "-q", "deploy/key"); git(root, "commit", "-qm", "2");
    const gone = blobOf(root, "gone-v1\n");
    const labels = [{ path: join(root, "deploy", "key"), level: "no-model", recursive: true }];
    const s = r.open();
    const rejected: unknown[] = [];
    const resolver = () => new LockResolver({ labels: () => labels, blobLocks: () => [], home: r.dir, dbPath: r.db, seals: sealGate(s, (x) => rejected.push(x)) });

    const first = resolver();
    first.note([root], "launch");
    await first.runCycle(); await first.idle();
    assert.deepEqual(first.snapshot().lockedSet.sha1, [gone]);
    await first.stop();
    const key = resolutionSealKey(root);
    assert.ok(s.seals("lock-resolution", [key]).seals.length >= 1, "the row is sealed");

    const second = resolver();
    assert.deepEqual(second.snapshot().lockedSet.sha1, [gone], "a sealed row is answered from mandu.db");
    await second.stop();

    // An unconfined writer of mandu.db drops the version from the row.
    const raw = new Database(r.db);
    const row = raw.prepare("SELECT entry FROM lock_resolutions WHERE root = ?").get(root) as { entry: string };
    const e = JSON.parse(row.entry) as { history: string[] };
    raw.prepare("UPDATE lock_resolutions SET entry = ? WHERE root = ?").run(JSON.stringify({ ...e, history: e.history.filter((b) => b !== gone) }), root);
    raw.close();
    const third = resolver();
    assert.deepEqual(third.snapshot().lockedSet.sha1, [], "the changed row is not loaded (the repository resolves again)");
    assert.deepEqual(rejected, [{ kind: "lock-resolution", key, reason: "mismatch" }]);
    await third.runCycle(); await third.idle();
    assert.deepEqual(third.snapshot().lockedSet.sha1, [gone], "and the version is back once resolved");
    await third.stop();

    s.rotate("an unconfined launch ended");
    const fourth = resolver();
    assert.deepEqual(fourth.snapshot().lockedSet.sha1, [], "a rotation voids every row");
    assert.equal(rejected.length, 1, "unsealed after a rotation is expected, not reported");
    await fourth.stop();
    s.markShutdown();
  } finally { r.done(); }
});
