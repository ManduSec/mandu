/**
 * Parity and e2e — the enforcement caches' seals (confidentiality-plan-14
 * §11.2) over the PRODUCTION wiring: the launcher's socket adapter
 * (`socketSecretArbiter(sock, { humanSock })`, what applySecretTwins calls,
 * turned into the object twins' seal client by `sealClientOf`), the
 * launcher's launch record (`beginLaunchRecord` / `endLaunchRecord` over
 * `ndjsonCall`, what run.ts calls) and the arbiter's own client, against a
 * REAL ArbiterServer with its human socket, over a REAL repository:
 *
 *   - both adapters answer the same seals; the data socket refuses them;
 *   - the object twins seal what they build through the real arbiter, and a
 *     relaunch is served from the cache;
 *   - a pack replaced under a clean `.idx` (the real pack's bytes) is
 *     refused and rebuilt; the pack served holds no byte of the key; the
 *     arbiter's admin stream names the entry by kind and key;
 *   - an `off` launch recorded by the launcher holds every seal void while
 *     it runs, and its end voids the older ones: the next launch rebuilds,
 *     and says so in ONE line before the work (plan 14 §11.2.1 "The rebuild
 *     notice": the arbiter's `epochCause` through the production wiring);
 *     cold, warm and while it runs, no such line;
 *   - the launcher's own reading of the classification and the arbiter's
 *     answer agree on every claim (mode × posture × write-protect × the
 *     macOS `homeSealed`); a macOS `read-blocked` launch with the home
 *     sealed keeps the cache, one without voids it;
 *   - the launcher that is handed the DATA socket as the human one is
 *     refused and falls back (the caches are deleted at the end);
 *   - the arbiter's copies of the launcher's `ps` start-time pieces (the
 *     darwin pid-reuse guard: cache-seals.ts `PS_ENV`, `parseLstartUtc`)
 *     equal the launcher's (platform/proc-tree.ts `PS_ENV`, reap.ts
 *     `parseLstartUtc`), and both read one start time for one process.
 *
 * The kernel oracle through a real confined launch is
 * tests/sandbox/git-history-locks.test.ts (K8).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateSync } from "node:zlib";

import { ADMIN_SESSION_ID, ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { parseLstartUtc as arbiterParseLstartUtc, procStartTime, PS_ENV as ARBITER_PS_ENV } from "../../arbiter/policy/cache-seals.js";
import { parseLstartUtc as launcherParseLstartUtc, processStartMs } from "../../launcher/src/reap.js";
import { PS_ENV as LAUNCHER_PS_ENV } from "../../launcher/src/platform/proc-tree.js";
import { ndjsonCall, sealClientOf, socketSecretArbiter } from "../../launcher/src/secret-setup.js";
import { beginLaunchRecord, endLaunchRecord, launchConfinedLocally, type CacheEpochDeps, type LaunchClaim } from "../../launcher/src/cache-epoch.js";
import { prepareGitObjectTwins, type GitObjectTwinResult } from "../../launcher/src/git-object-twins.js";
import { stateAxes } from "../lib/axes.js";
import { VOIDED_CACHES_PREFIX, historyRecheckNotice, isHistoryRecheckNotice, voidedCachesLine } from "../../launcher/src/cache-seals.js";
import { compactNotice, noteShow } from "../../launcher/src/launch-banner.js";

stateAxes("secrets"); // the confidentiality axis is what the object twins and their seals serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...a: string[]): string => execFileSync("git", a, { cwd, encoding: "utf8", env: ENV });
const KEY = ["PARITY", "SEALED", "PACK", "KEY", "Rt".repeat(14)].join("_");

function inflated(buf: Buffer): string {
  let out = "";
  for (let i = 12; i < buf.length - 2; i++) {
    if (buf[i] !== 0x78) continue;
    try { out += `${inflateSync(buf.subarray(i)).toString("latin1")}\n`; } catch { /* not a stream start */ }
  }
  return out;
}
const servedPack = (got: GitObjectTwinResult): string => got.twins.find((x) => x.kind === "object" && x.targetPath.endsWith(".pack"))!.twinPath;

interface Rig { dir: string; ws: string; secret: string; sock: string; humanSock: string; server: ArbiterServer; human: ArbiterClient; data: ArbiterClient; close: () => Promise<void> }

async function rig(): Promise<Rig> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-seals-parity-"));
  const ws = join(dir, "ws");
  git(dir, "init", "-q", ws);
  writeFileSync(join(ws, "README"), "readme\n");
  const secret = join(ws, ".env");
  writeFileSync(secret, `TOKEN=${KEY}\n`);
  git(ws, "add", ".");
  git(ws, "commit", "-qm", "one");
  writeFileSync(secret, "TOKEN=rotated\n");
  git(ws, "commit", "-qam", "two");
  git(ws, "repack", "-adq");
  const sock = join(dir, "a.sock");
  const humanSock = join(dir, "human", "h.sock");
  const server = new ArbiterServer({
    socketPath: sock, humanSocketPath: humanSock, dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPollMs: 0, packDir: null,
  });
  await server.listen();
  const human = new ArbiterClient(humanSock);
  const data = new ArbiterClient(sock);
  return {
    dir, ws, secret, sock, humanSock, server, human, data,
    close: async () => { human.close(); data.close(); await server.close(); rmSync(dir, { recursive: true, force: true }); },
  };
}

function twinOpts(r: Rig): { cacheDir: string; denyFile: string; walkCacheDir: string } {
  const denyFile = join(r.dir, "denied");
  if (!existsSync(denyFile)) { writeFileSync(denyFile, ""); chmodSync(denyFile, 0o000); }
  return { cacheDir: join(r.dir, "home", ".mandu", "cache", "object-twins"), denyFile, walkCacheDir: join(r.dir, "home", ".mandu", "state", "object-walks") };
}

test("parity: the launcher's adapter and the arbiter's client answer the same seals over the human socket; the data socket refuses them", async () => {
  const r = await rig();
  try {
    const launcher = socketSecretArbiter(r.sock, { humanSock: r.humanSock });
    const client = sealClientOf(launcher)!;
    assert.ok(client, "the production adapter carries the seal ops");
    const entry = { kind: "history-walk", key: "0123abcd", sha256: "b".repeat(64), size: 12 };
    await client.record([entry], []);
    const viaLauncher = await client.lookup("history-walk", ["0123abcd", "nope"]);
    const viaClient = await r.human.cacheSeals("history-walk", ["0123abcd", "nope"]);
    assert.deepEqual(viaLauncher, viaClient, "one answer through both adapters");
    assert.deepEqual(viaClient.seals, [{ key: "0123abcd", sha256: "b".repeat(64), size: 12 }]);
    assert.equal(viaClient.honoured, true);

    const onData = socketSecretArbiter(r.sock, { humanSock: r.sock });
    await assert.rejects(() => onData.cacheSeals!("history-walk", ["0123abcd"]), /human-plane: 'cacheSeals'/);
    await assert.rejects(() => onData.sealCacheEntries!([entry], []), /human-plane: 'sealCacheEntries'/);
    await assert.rejects(() => ndjsonCall(r.sock, "beginLaunch", { pid: process.pid, mode: "off", posture: "off", writeProtect: false }, 5000), /human-plane: 'beginLaunch'/);
  } finally {
    await r.close();
  }
});

test("e2e: the object twins seal through the real arbiter; a planted pack under a clean .idx is refused and rebuilt; an off launch's end voids the seals", async () => {
  const r = await rig();
  try {
    const seals = sealClientOf(socketSecretArbiter(r.sock, { humanSock: r.humanSock }))!;
    const opts = { ...twinOpts(r), seals };
    const first = await prepareGitObjectTwins([r.secret], opts);
    assert.equal(first.packsRebuilt, 1);
    const again = await prepareGitObjectTwins([r.secret], opts);
    assert.equal(again.cacheHits, 1, "sealed through the real arbiter: a relaunch is a cache hit");
    assert.deepEqual(again.walks, { hit: 1, incremental: 0, full: 0 });

    // Planted: the real pack's bytes under the sanitized name, the clean .idx kept.
    const planted = servedPack(again);
    const realDir = join(r.ws, ".git", "objects", "pack");
    const real = join(realDir, readdirSync(realDir).find((n) => n.endsWith(".pack"))!);
    rmSync(planted);
    writeFileSync(planted, readFileSync(real));
    assert.ok(inflated(readFileSync(planted)).includes(KEY), "precondition: the planted pack holds the key");
    const logs: string[] = [];
    const after = await prepareGitObjectTwins([r.secret], { ...opts, log: (m) => logs.push(m) });
    assert.equal(after.cacheHits, 0);
    assert.equal(after.packsRebuilt, 1, "rebuilt");
    assert.ok(!inflated(readFileSync(servedPack(after))).includes(KEY), "the pack served holds no byte of the key");
    const events = await r.human.events(ADMIN_SESSION_ID);
    const rejected = events.map((e) => (e as unknown as { cacheSeal?: { action: string; entries: Array<{ kind: string; key: string; reason: string }> } }).cacheSeal)
      .filter((c) => c?.action === "rejected");
    assert.deepEqual(rejected.at(-1)!.entries, [{ kind: "object-twin", key: planted.split("/").slice(-2).join("/"), reason: "mismatch" }]);
    assert.ok(!JSON.stringify(events).includes(KEY) && logs.every((l) => !l.includes(KEY)), "no event or log line carries the key");

    // An `off` launch, recorded the way run.ts records it.
    const deps: CacheEpochDeps = { call: (s, op, a) => ndjsonCall(s, op, a, 5000), log: (m) => logs.push(m), purge: () => { throw new Error("no purge expected"); } };
    const rec = await beginLaunchRecord(r.humanSock, { pid: process.pid, mode: "off", posture: "off", writeProtect: false, sessionId: "claude-off-7", workspace: r.ws }, deps);
    assert.equal(rec.token !== null && !rec.confined && !rec.purgeAtEnd, true, JSON.stringify(rec));
    const duringLogs: string[] = [];
    const during = await prepareGitObjectTwins([r.secret], { ...opts, log: (m) => duringLogs.push(m) });
    assert.equal(during.cacheHits, 0, "while it runs nothing cached is used");
    assert.deepEqual(during.walks, { hit: 0, incremental: 0, full: 1 });
    // Plan 14 §11.2.1: the launch that finds the caches void names the one
    // that voids them, through the production wiring (the arbiter recorded
    // its workspace and why; the launcher's adapter carried the names).
    const voided = duringLogs.filter((l) => l.startsWith(VOIDED_CACHES_PREFIX));
    assert.deepEqual(voided, [voidedCachesLine([{ pid: process.pid, mode: "off", posture: "off", why: "protection off", workspace: r.ws, session: "claude-off-7" }])], duringLogs.join("\n"));
    assert.equal(compactNotice(voided[0]!), `mandu: ! git history rebuilt (slower) while a Mandu launch runs without protection (pid ${process.pid} in ${r.ws} (session claude-off-7): protection off); to end it: quit its agent, or \`kill ${process.pid}\``);
    await endLaunchRecord(r.humanSock, rec, deps);
    const nextLogs: string[] = [];
    const next = await prepareGitObjectTwins([r.secret], { ...opts, log: (m) => nextLogs.push(m) });
    assert.equal(next.cacheHits, 0, "its end voided every older seal: the next launch rebuilds");
    // Plan 14 §11.2.1 "The rebuild notice": that launch says why, once,
    // before the rebuild; the cause rode the production wiring.
    assert.deepEqual(nextLogs.filter(isHistoryRecheckNotice), [historyRecheckNotice("unprotected-ended", 1)], nextLogs.join("\n"));
    const settledLogs: string[] = [];
    const settled = await prepareGitObjectTwins([r.secret], { ...opts, log: (m) => settledLogs.push(m) });
    assert.equal(settled.cacheHits, 1, "and seals again");
    assert.deepEqual(settledLogs.filter(isHistoryRecheckNotice), [], "warm: silent");

    // A confined launch voids nothing.
    const conf = await beginLaunchRecord(r.humanSock, { pid: process.pid, mode: "secrets", posture: "confined", writeProtect: true }, deps);
    assert.equal(conf.confined, true);
    await endLaunchRecord(r.humanSock, conf, deps);
    assert.equal((await prepareGitObjectTwins([r.secret], opts)).cacheHits, 1);
  } finally {
    await r.close();
  }
});

test("e2e, plan 14 §11.2.1 the rebuild notice: after a gated launch recorded by the launcher ends, the next launch prints ONE plain line before it rebuilds, at once in the compact display; cold, warm and while it runs, none", async () => {
  const r = await rig();
  try {
    const seals = sealClientOf(socketSecretArbiter(r.sock, { humanSock: r.humanSock }))!;
    const opts = { ...twinOpts(r), seals };
    const launch = async (): Promise<{ got: GitObjectTwinResult; logs: string[] }> => {
      const logs: string[] = [];
      const got = await prepareGitObjectTwins([r.secret], { ...opts, log: (m) => logs.push(m) });
      return { got, logs };
    };
    const cold = await launch();
    assert.equal(cold.got.packsRebuilt, 1);
    assert.deepEqual(cold.logs.filter(isHistoryRecheckNotice), [], "the first build is not a re-check");
    assert.deepEqual((await launch()).logs.filter(isHistoryRecheckNotice), [], "warm: silent");

    // A `gated` launch (what `--no-net-guard` gives), recorded the way run.ts records it.
    const deps: CacheEpochDeps = { call: (s, op, a) => ndjsonCall(s, op, a, 5000), log: () => {}, purge: () => { throw new Error("no purge expected"); } };
    const rec = await beginLaunchRecord(r.humanSock, { pid: process.pid, mode: "secrets", posture: "gated", writeProtect: true, workspace: r.ws }, deps);
    assert.equal(rec.confined, false);
    const during = await launch();
    assert.deepEqual(during.logs.filter(isHistoryRecheckNotice), [], "while it runs the voided line names it instead");
    assert.ok(during.logs.some((l) => l.startsWith(VOIDED_CACHES_PREFIX)), during.logs.join("\n"));
    await endLaunchRecord(r.humanSock, rec, deps);

    const after = await launch();
    assert.equal(after.got.packsRebuilt, 1, "its end voided the seals: every pack rebuilt");
    const said = after.logs.filter(isHistoryRecheckNotice);
    assert.deepEqual(said, ["mandu: ! an earlier Mandu session without protection has ended, so Mandu is re-checking the git history of 1 repository (slower this once)"], after.logs.join("\n"));
    assert.ok(after.logs.findIndex((l) => l.startsWith("mandu: sanitizing ")) > after.logs.indexOf(said[0]!), "said before the rebuild starts");
    assert.deepEqual(noteShow(said[0]!, "compact"), { kind: "print" }, "printed at once, before the agent starts, not collected under the banner");
    assert.ok(after.logs.every((l) => !l.includes(KEY)));
    assert.deepEqual((await launch()).logs.filter(isHistoryRecheckNotice), [], "re-sealed: the next launch is silent");
  } finally {
    await r.close();
  }
});

test("parity: the launcher's reading of the classification (launchConfinedLocally) and the arbiter's answer to the launcher's own record agree on every claim, the macOS homeSealed ones included", async () => {
  const r = await rig();
  try {
    const deps: CacheEpochDeps = { call: (s, op, a) => ndjsonCall(s, op, a, 5000), log: () => {}, purge: () => { throw new Error("no purge expected: the arbiter recorded every launch"); } };
    const modes = ["secrets", "full", "off", "injection"];
    const postures = ["confined", "read-blocked", "gated", "off"];
    let confinedSeen = 0;
    for (const mode of modes) {
      for (const posture of postures) {
        for (const writeProtect of [true, false]) {
          for (const homeSealed of [undefined, true, false] as const) {
            const claim: LaunchClaim = { pid: process.pid, mode, posture, writeProtect, ...(homeSealed !== undefined ? { homeSealed } : {}) };
            const rec = await beginLaunchRecord(r.humanSock, claim, deps);
            assert.ok(rec.token !== null, JSON.stringify(claim));
            assert.equal(rec.confined, launchConfinedLocally(claim), `the mirrors agree: ${JSON.stringify(claim)}`);
            const want = writeProtect && (mode === "secrets" || mode === "full") && (posture === "confined" || (posture === "read-blocked" && homeSealed === true));
            assert.equal(rec.confined, want, JSON.stringify(claim));
            if (rec.confined) confinedSeen++;
            await endLaunchRecord(r.humanSock, rec, deps);
          }
        }
      }
    }
    assert.equal(confinedSeen, 2 * 3 + 2, "secrets/full × (confined: any seal field, read-blocked: homeSealed true)");
  } finally {
    await r.close();
  }
});

test("e2e, macOS: a read-blocked launch recorded with homeSealed keeps the caches' seals (the relaunch is served from the cache); one without voids them", async () => {
  const r = await rig();
  try {
    const launcher = socketSecretArbiter(r.sock, { humanSock: r.humanSock });
    const opts = { ...twinOpts(r), seals: sealClientOf(launcher)!, labels: [], blobLocks: [] };
    await prepareGitObjectTwins([r.secret], opts);
    assert.equal((await prepareGitObjectTwins([r.secret], opts)).cacheHits, 1, "precondition: sealed and served from the cache");
    const deps: CacheEpochDeps = { call: (s, op, a) => ndjsonCall(s, op, a, 5000), log: () => {}, purge: () => { throw new Error("no purge expected"); } };
    const sealed = await beginLaunchRecord(r.humanSock, { pid: process.pid, mode: "secrets", posture: "read-blocked", writeProtect: true, homeSealed: true }, deps);
    assert.equal(sealed.confined, true);
    assert.equal((await prepareGitObjectTwins([r.secret], opts)).cacheHits, 1, "while it runs the cache is used");
    await endLaunchRecord(r.humanSock, sealed, deps);
    assert.equal((await prepareGitObjectTwins([r.secret], opts)).cacheHits, 1, "its end voided nothing");
    const open = await beginLaunchRecord(r.humanSock, { pid: process.pid, mode: "secrets", posture: "read-blocked", writeProtect: true }, deps);
    assert.equal(open.confined, false);
    assert.equal((await prepareGitObjectTwins([r.secret], opts)).cacheHits, 0, "an unsealed macOS launch: nothing cached is used");
    await endLaunchRecord(r.humanSock, open, deps);
    assert.equal((await prepareGitObjectTwins([r.secret], opts)).cacheHits, 0, "and its end voided every older seal");
  } finally {
    await r.close();
  }
});

test("mirror: the arbiter's darwin start-time pieces equal the launcher's (PS_ENV; parseLstartUtc over padded, two-digit, localized, empty, bad-month and whitespace inputs)", () => {
  assert.deepEqual({ ...ARBITER_PS_ENV }, { ...LAUNCHER_PS_ENV }, "cache-seals.ts PS_ENV = platform/proc-tree.ts PS_ENV");
  const table = [
    "Thu Oct  1 03:04:05 2026", // a space-padded day
    "Wed Sep 30 20:01:39 2026", // a two-digit day
    "Wed Sep 30 20:01:39 2026\n",
    "  Wed Sep 30 20:01:39 2026  ", // surrounding whitespace
    "\tMon Feb 29 00:00:00 2028\n",
    "mer 30 sep 2026 20:01:39 CEST", // a localized shape
    "Mi 30 Sep 20:01:39 2026",
    "", // ps printed nothing
    "   ",
    "Wed Foo 30 20:01:39 2026", // a bad month
    "Wed sep 30 20:01:39 2026",
    "Wed Sep 30 20:01 2026",
    "Wed Sep 30 20:01:39 26",
    "Wed Sep 30 20:01:39 2026 extra",
  ];
  for (const text of table) {
    assert.equal(arbiterParseLstartUtc(text), launcherParseLstartUtc(text), JSON.stringify(text));
  }
  assert.equal(arbiterParseLstartUtc(table[0]!), Date.UTC(2026, 9, 1, 3, 4, 5), "the table exercises a real parse");
  assert.equal(arbiterParseLstartUtc(""), null);
});

test("mirror, darwin: the arbiter's pid-reuse token for a live process is the launcher's start time for it", { skip: process.platform !== "darwin" ? "darwin only (Linux reads /proc field 22, another unit)" : false }, () => {
  const arbiter = procStartTime(process.pid);
  const launcher = processStartMs(process.pid);
  assert.ok(arbiter !== null && launcher !== null, `${String(arbiter)} ${String(launcher)}`);
  assert.equal(arbiter, String(launcher));
});

test("e2e: a launcher handed the data socket as the human one is refused, and the unprotected launch falls back to deleting the caches at its end", async () => {
  const r = await rig();
  try {
    const logs: string[] = [];
    let purged = 0;
    const deps: CacheEpochDeps = { call: (s, op, a) => ndjsonCall(s, op, a, 5000), log: (m) => logs.push(m), purge: () => { purged++; } };
    const rec = await beginLaunchRecord(r.sock, { pid: process.pid, mode: "secrets", posture: "gated", writeProtect: true }, deps);
    assert.deepEqual(rec, { token: null, confined: false, purgeAtEnd: true, others: [] });
    assert.match(logs[0]!, /could not record this unprotected launch \(human-plane: 'beginLaunch'/);
    await endLaunchRecord(r.sock, rec, deps);
    assert.equal(purged, 1);
  } finally {
    await r.close();
  }
});
