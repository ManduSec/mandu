/**
 * The enforcement caches' seals, the launcher's half
 * (confidentiality-plan-14-policy-suggestions.md §11.2; cache-seals.ts,
 * cache-epoch.ts, the seal checks in git-object-twins.ts), with a REAL
 * repository and the in-memory seal service (test/lib/memory-seals.ts; the
 * real wiring over an ArbiterServer is
 * tests/stack/cache-seals-parity.test.ts):
 *
 *   - a pack replaced under a clean `.idx` (the REAL pack's bytes, which the
 *     `.idx` check alone let through) is refused and rebuilt, and the pack
 *     served holds no byte of the protected version;
 *   - a walk entry with a version removed is refused and the history walked
 *     again: the version stays hidden;
 *   - while an unconfined launch is live (no seal honoured), after a
 *     rotation, and with no seal service at all, nothing cached is used;
 *   - the rebuild notice (plan 14 §11.2.1): the first launch after a
 *     rotation says once, before the rebuild, why and how many
 *     repositories; a cold, warm, live-voided or tampered launch does not;
 *   - the per-launch hash memo, the wire shape check, the report;
 *   - the launch record: the fallback purge for an unprotected launch the
 *     arbiter could not record.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateSync } from "node:zlib";
import { SealSession, VOIDED_CACHES_PREFIX, asCacheSeals, hashFile, historyRecheckNotice, isHistoryRecheckNotice, voidedCachesLine, type CacheSealClient } from "../../src/cache-seals.js";
import { compactNotice, noteShow } from "../../src/launch-banner.js";
import { beginLaunchRecord, concurrentLaunchNotice, endLaunchRecord, launchConfinedLocally, purgeEnforcementCaches, unrecordedExposureRefusal, type CacheEpochDeps } from "../../src/cache-epoch.js";
import { idxObjectNames, parseWalkCache, prepareGitObjectTwins, type GitObjectTwinResult } from "../../src/git-object-twins.js";
import { sealClientOf, socketSecretArbiter } from "../../src/secret-setup.js";
import { stateAxes } from "../axes.js";
import { memorySeals } from "../lib/memory-seals.js";

stateAxes("secrets"); // the confidentiality axis is what the object twins and their caches serve

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@x", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@x",
  GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
};
const git = (cwd: string, ...args: string[]): string => execFileSync("git", args, { cwd, encoding: "utf8", env: ENV });
/** A key-shaped canary assembled at run time (no key literal in the file). */
const KEY = ["SEALED", "CACHE", "CANARY", "7731", "Qz".repeat(14)].join("_");

interface Fixture { tmp: string; ws: string; secret: string; opts: { cacheDir: string; denyFile: string; walkCacheDir: string }; done: () => void }

/** A repository whose history holds the canary in a file that is protected
 *  now (and a second version, so the walk has history to find). */
function fixture(): Fixture {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-seals-"));
  const ws = join(tmp, "ws");
  git(tmp, "init", "-q", ws);
  writeFileSync(join(ws, "README"), "readme\n");
  const secret = join(ws, ".env");
  writeFileSync(secret, `TOKEN=${KEY}\n`);
  git(ws, "add", ".");
  git(ws, "commit", "-qm", "one");
  writeFileSync(secret, "TOKEN=rotated\n");
  git(ws, "commit", "-qam", "two");
  git(ws, "repack", "-adq");
  const denyFile = join(tmp, "denied");
  writeFileSync(denyFile, "");
  chmodSync(denyFile, 0o000);
  return {
    tmp, ws, secret,
    opts: { cacheDir: join(tmp, "cache"), denyFile, walkCacheDir: join(tmp, "walks") },
    done: () => rmSync(tmp, { recursive: true, force: true }),
  };
}

/** Every zlib stream a pack holds, inflated (what an agent reading the raw
 *  pack would get). */
function inflated(buf: Buffer): string {
  let out = "";
  for (let i = 12; i < buf.length - 2; i++) {
    if (buf[i] !== 0x78) continue;
    try { out += `${inflateSync(buf.subarray(i)).toString("latin1")}\n`; } catch { /* not a stream start */ }
  }
  return out;
}

const servedPack = (got: GitObjectTwinResult): string => got.twins.find((x) => x.kind === "object" && x.targetPath.endsWith(".pack"))!.twinPath;
const servedIdx = (got: GitObjectTwinResult): string => got.twins.find((x) => x.kind === "object" && x.targetPath.endsWith(".idx"))!.twinPath;
const realPack = (ws: string): string => {
  const dir = join(ws, ".git", "objects", "pack");
  return join(dir, readdirSync(dir).find((n) => n.endsWith(".pack"))!);
};
const oldBlob = (ws: string): string => execFileSync("git", ["hash-object", "--stdin"], { cwd: ws, input: `TOKEN=${KEY}\n`, encoding: "utf8", env: ENV }).trim();

test("a pack replaced under a clean .idx (the real pack's bytes) is refused and rebuilt; the pack served holds no byte of the protected version", async () => {
  const f = fixture();
  try {
    const seals = memorySeals();
    const logs: string[] = [];
    const first = await prepareGitObjectTwins([f.secret], { ...f.opts, seals, log: (m) => logs.push(m) });
    assert.equal(first.packsRebuilt, 1);
    assert.ok(seals.seals.some((s) => s.kind === "object-twin" && s.key.endsWith(".pack")), "the built pack is sealed");
    assert.ok(seals.seals.some((s) => s.kind === "object-twin" && s.key.endsWith(".idx")) && seals.seals.some((s) => s.kind === "history-walk"));
    assert.ok(!inflated(readFileSync(servedPack(first))).includes(KEY), "the sanitized pack holds no byte of the key");

    // An unconfined writer plants the REAL pack under the sanitized name,
    // keeping the sanitized (clean) .idx: the old `.idx` check passes it.
    const planted = servedPack(first);
    rmSync(planted); // git writes packs read-only; the writer replaces it
    writeFileSync(planted, readFileSync(realPack(f.ws)));
    assert.ok(inflated(readFileSync(planted)).includes(KEY), "precondition: the planted pack holds the key's bytes");
    assert.ok(!idxObjectNames(readFileSync(servedIdx(first))).includes(oldBlob(f.ws)), "precondition: the .idx beside it is clean");

    const second = await prepareGitObjectTwins([f.secret], { ...f.opts, seals, log: (m) => logs.push(m) });
    assert.equal(second.cacheHits, 0, "the planted pack is not served");
    assert.equal(second.packsRebuilt, 1, "it is rebuilt");
    assert.ok(!inflated(readFileSync(servedPack(second))).includes(KEY), "the pack served holds no byte of the key");
    const key = `${planted.split("/").slice(-2).join("/")}`;
    assert.deepEqual(seals.rejected, [{ kind: "object-twin", key, reason: "mismatch" }], "reported by kind and key, no content");
    assert.ok(logs.some((l) => /WARNING: mandu: 1 git-history cache entry did not match its seal and was rebuilt/.test(l)), logs.join("\n"));
    assert.ok(logs.every((l) => !l.includes(KEY)));

    const third = await prepareGitObjectTwins([f.secret], { ...f.opts, seals });
    assert.equal(third.cacheHits, 1, "the rebuilt pack is sealed and served next time");
    assert.equal(third.packsRebuilt, 0);
  } finally { f.done(); }
});

test("a walk entry with a version removed is refused and the history walked again; the version stays hidden", async () => {
  const f = fixture();
  try {
    const seals = memorySeals();
    const first = await prepareGitObjectTwins([f.secret], { ...f.opts, seals });
    assert.deepEqual(first.walks, { hit: 0, incremental: 0, full: 1 });
    const again = await prepareGitObjectTwins([f.secret], { ...f.opts, seals });
    assert.deepEqual(again.walks, { hit: 1, incremental: 0, full: 0 }, "a sealed entry is a hit");

    // Drop the old version from the entry, well-formed: without the seal it
    // would be a hit that leaves the version in the sanitized pack.
    const file = join(f.opts.walkCacheDir, readdirSync(f.opts.walkCacheDir).find((n) => n.endsWith(".json"))!);
    const entry = parseWalkCache(readFileSync(file, "utf8"))!;
    const old = oldBlob(f.ws);
    assert.ok(entry.blobs.includes(old), "precondition: the walk found the old version");
    writeFileSync(file, JSON.stringify({ ...entry, blobs: entry.blobs.filter((b) => b !== old) }));
    // And the pack cache, so the pack is rebuilt from what the walk says.
    rmSync(f.opts.cacheDir, { recursive: true, force: true });

    const after = await prepareGitObjectTwins([f.secret], { ...f.opts, seals });
    assert.deepEqual(after.walks, { hit: 0, incremental: 0, full: 1 }, "the tampered entry is not used");
    assert.ok(seals.rejected.some((r) => r.kind === "history-walk" && r.reason === "mismatch"), JSON.stringify(seals.rejected));
    assert.ok(!idxObjectNames(readFileSync(servedIdx(after))).includes(old), "the removed version is hidden all the same");
    assert.ok(!inflated(readFileSync(servedPack(after))).includes(KEY));
  } finally { f.done(); }
});

test("nothing cached is used while no seal is honoured (an unconfined launch live), after a rotation (reported unsealed), or with no seal service", async () => {
  const f = fixture();
  try {
    const seals = memorySeals();
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals });

    seals.unconfined = true;
    const logs: string[] = [];
    const live = await prepareGitObjectTwins([f.secret], { ...f.opts, seals, log: (m) => logs.push(m) });
    assert.equal(live.cacheHits, 0);
    assert.deepEqual(live.walks, { hit: 0, incremental: 0, full: 1 });
    assert.deepEqual(seals.rejected, [], "not honoured is not a rejection");
    assert.equal(logs.filter((l) => /git-history caches are not trusted this launch \(1 unconfined launch is live\)/.test(l)).length, 1, `said once: ${logs.join("\n")}`);
    seals.unconfined = false;

    seals.rotate();
    const rotated = await prepareGitObjectTwins([f.secret], { ...f.opts, seals });
    assert.equal(rotated.cacheHits, 0, "an older epoch's seal is void");
    assert.deepEqual(rotated.walks, { hit: 0, incremental: 0, full: 1 });
    const rej = seals.rejected as Array<{ reason: string }>; // (deepEqual above narrowed the type)
    assert.ok(rej.length > 0 && rej.every((r) => r.reason === "unsealed"), JSON.stringify(rej));
    const next = await prepareGitObjectTwins([f.secret], { ...f.opts, seals });
    assert.equal(next.cacheHits, 1, "re-sealed in the new epoch");

    const none = await prepareGitObjectTwins([f.secret], { ...f.opts });
    assert.equal(none.cacheHits, 0, "no seal service: fail closed, nothing cached is trusted");
    assert.deepEqual(none.walks, { hit: 0, incremental: 0, full: 1 });
  } finally { f.done(); }
});

test("SealSession: one hash per file per launch (path, inode, size, mtime, ctime), a changed file hashed again; a failed lookup trusts nothing; the report is one call", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-sealsess-"));
  try {
    const p = join(tmp, "f.pack");
    writeFileSync(p, "one");
    let hashes = 0;
    const counting = (path: string) => { hashes++; return hashFile(path); };
    const seals = memorySeals();
    const s1 = new SealSession(seals, undefined, counting);
    await s1.sealFile("object-twin", "k/f.pack", p);
    await s1.flush();
    const s2 = new SealSession(seals, undefined, counting);
    hashes = 0;
    assert.equal(await s2.verifyFiles("object-twin", [{ key: "k/f.pack", path: p }]), true);
    assert.equal(await s2.verifyFiles("object-twin", [{ key: "k/f.pack", path: p }]), true);
    assert.equal(hashes, 1, "hashed once in one launch");
    writeFileSync(p, "two!");
    assert.equal(await s2.verifyFiles("object-twin", [{ key: "k/f.pack", path: p }]), false, "a changed file is hashed again and refused");
    assert.equal(hashes, 2);
    assert.deepEqual(s2.rejected, [{ kind: "object-twin", key: "k/f.pack", reason: "mismatch" }]);

    const failing: CacheSealClient = { lookup: async () => { throw new Error("socket gone"); }, record: async () => ({}) };
    const logs: string[] = [];
    const s3 = new SealSession(failing, (m) => logs.push(m));
    assert.equal(await s3.verifyBytes("history-walk", "abc", Buffer.from("x")), false);
    assert.equal(await s3.verifyBytes("history-walk", "abd", Buffer.from("x")), false);
    assert.equal(logs.length, 1, "said once");
    assert.match(logs[0]!, /not trusted this launch \(the seal lookup failed: socket gone\)/);
    const junk: CacheSealClient = { lookup: async () => ({ epoch: "e", honoured: true, seals: [{ key: "abc", sha256: "not hex", size: 1 }] }) as never, record: async () => ({}) };
    assert.equal(await new SealSession(junk).verifyBytes("history-walk", "abc", Buffer.from("x")), false, "a malformed answer trusts nothing");

    const s4 = new SealSession(undefined);
    assert.equal(s4.enabled, false);
    assert.equal(await s4.verifyBytes("history-walk", "abc", Buffer.from("x")), false);
    s4.sealBytes("history-walk", "abc", Buffer.from("x"));
    assert.deepEqual(s4.entries, [], "no client: nothing to seal");

    let calls = 0;
    const recording: CacheSealClient = { lookup: seals.lookup, record: async () => { calls++; throw new Error("refused"); } };
    const s5 = new SealSession(recording, (m) => logs.push(m));
    s5.sealBytes("history-walk", "abc", Buffer.from("x"));
    s5.sealBytes("history-walk", "abc", Buffer.from("x"));
    await s5.flush();
    assert.equal(calls, 1, "one report per launch");
    assert.match(logs.at(-1)!, /could not record the git-history cache seals \(refused\); the next launch rebuilds them/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("plan 14 §11.2.1: caches void because another launch runs unconfined: the launch names it (pid, workspace, why) and how to end it, once, and the compact display shows one `mandu: !` line", async () => {
  const f = fixture();
  try {
    const seals = memorySeals();
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals });
    seals.unconfined = true;
    seals.live = [{ pid: 4242, mode: "off", posture: "off", why: "protection off", workspace: "/home/u/wt-a", session: "claude-off-1" }];
    const logs: string[] = [];
    const got = await prepareGitObjectTwins([f.secret], { ...f.opts, seals, log: (m) => logs.push(m) });
    assert.equal(got.cacheHits, 0, "the rule is unchanged: nothing cached is used");
    const said = logs.filter((l) => l.startsWith(VOIDED_CACHES_PREFIX));
    assert.equal(said.length, 1, `said once: ${logs.join("\n")}`);
    assert.equal(said[0], voidedCachesLine(seals.live));
    assert.equal(
      said[0],
      "mandu: the git-history caches are not trusted this launch: a Mandu launch runs without protection " +
      "(pid 4242 in /home/u/wt-a (session claude-off-1): protection off), and while one does nothing it could have written is trusted; " +
      "rebuilding the sanitized git history (slower). The caches are trusted again once it ends: quit its agent, or `kill 4242`.",
    );
    assert.equal(
      compactNotice(said[0]!),
      "mandu: ! git history rebuilt (slower) while a Mandu launch runs without protection " +
      "(pid 4242 in /home/u/wt-a (session claude-off-1): protection off); to end it: quit its agent, or `kill 4242`",
    );
    // An older arbiter (no names): the old line, which is not a notice.
    seals.live = undefined;
    const older: string[] = [];
    await prepareGitObjectTwins([f.secret], { ...f.opts, seals, log: (m) => older.push(m) });
    const old = older.find((l) => /git-history caches are not trusted/.test(l))!;
    assert.match(old, /not trusted this launch \(1 unconfined launch is live\); rebuilding what they hold$/);
    assert.equal(compactNotice(old), null);
  } finally { f.done(); }
});

test("plan 14 §11.2.1: several launches are named (three, then a count), the first one's pid to kill; a launch without the arbiter's words is named by its mode", () => {
  const live = [
    { pid: 11, mode: "secrets", posture: "gated", why: "no file guard", workspace: "/w/one" },
    { pid: 12, mode: "off", posture: "off" },
    { pid: 13, mode: "injection", posture: "confined" },
    { pid: 14, mode: "off", posture: "off" },
  ];
  const line = voidedCachesLine(live);
  assert.match(line, /: 4 Mandu launches run without protection \(pid 11 in \/w\/one: no file guard; pid 12: protection off; pid 13: mode injection, posture confined; and 1 more\)/);
  assert.match(line, /once they end: quit their agents, or `kill 11`\.$/);
  assert.equal(
    compactNotice(line),
    "mandu: ! git history rebuilt (slower) while 4 Mandu launches run without protection " +
    "(pid 11 in /w/one: no file guard; pid 12: protection off; pid 13: mode injection, posture confined; and 1 more); to end them: quit their agents, or `kill 11`",
  );
});

/** The history re-check notices among a launch's log lines (plan 14 §11.2.1 "The rebuild notice"). */
const rechecks = (logs: readonly string[]): string[] => logs.filter(isHistoryRecheckNotice);

test("plan 14 §11.2.1 the rebuild notice: the first launch after an unprotected one ended says so ONCE, before the rebuild; a cold first launch, a warm one, a live unprotected launch and a planted pack do not", async () => {
  const f = fixture();
  try {
    const seals = memorySeals();
    const run = async (): Promise<{ got: GitObjectTwinResult; logs: string[] }> => {
      const logs: string[] = [];
      const got = await prepareGitObjectTwins([f.secret], { ...f.opts, seals, log: (m) => logs.push(m) });
      return { got, logs };
    };
    const cold = await run();
    assert.equal(cold.got.packsRebuilt, 1);
    assert.deepEqual(rechecks(cold.logs), [], "nothing on disk yet: nothing to re-check (the first build is not a re-check)");
    const warm = await run();
    assert.equal(warm.got.cacheHits, 1);
    assert.deepEqual(rechecks(warm.logs), [], "warm: silent");

    // An unprotected launch ended: the arbiter started a new epoch.
    seals.rotate("unprotected-ended");
    const after = await run();
    assert.equal(after.got.packsRebuilt, 1, "every pack rebuilt");
    assert.deepEqual(after.got.walks, { hit: 0, incremental: 0, full: 1 }, "and the history walked again");
    assert.deepEqual(rechecks(after.logs), [
      "mandu: ! an earlier Mandu session without protection has ended, so Mandu is re-checking the git history of 1 repository (slower this once)",
    ], after.logs.join("\n"));
    const said = after.logs.findIndex(isHistoryRecheckNotice);
    const work = after.logs.findIndex((l) => l.startsWith("mandu: sanitizing "));
    assert.ok(work > said, `said before the first pack is rebuilt: ${after.logs.join("\n")}`);
    assert.deepEqual(rechecks((await run()).logs), [], "re-sealed: the next launch is warm and silent");

    // While an unprotected launch runs, the voided line says why instead.
    seals.unconfined = true;
    seals.live = [{ pid: 4242, mode: "off", posture: "off", why: "protection off" }];
    const during = await run();
    assert.deepEqual(rechecks(during.logs), []);
    assert.equal(during.logs.filter((l) => l.startsWith(VOIDED_CACHES_PREFIX)).length, 1);
    seals.unconfined = false;
    seals.live = undefined;

    // A planted pack is a mismatch (a WARNING), not a re-check.
    await run();
    const planted = servedPack((await run()).got);
    rmSync(planted);
    writeFileSync(planted, readFileSync(realPack(f.ws)));
    const tampered = await run();
    assert.equal(tampered.got.packsRebuilt, 1);
    assert.deepEqual(rechecks(tampered.logs), []);
    assert.ok(tampered.logs.some((l) => l.startsWith("WARNING: mandu: 1 git-history cache entry did not match")));
  } finally { f.done(); }
});

test("plan 14 §11.2.1 the rebuild notice: the count is the repositories the step covers (one line for two); an older arbiter's answer (no cause) and an unclean stop get their own why", async () => {
  const f = fixture();
  const g = fixture();
  try {
    const seals = memorySeals();
    const opts = { ...f.opts, seals };
    await prepareGitObjectTwins([f.secret, g.secret], opts);
    seals.rotate("unclean-stop");
    const logs: string[] = [];
    const got = await prepareGitObjectTwins([f.secret, g.secret], { ...opts, log: (m) => logs.push(m) });
    assert.equal(got.packsRebuilt, 2);
    assert.deepEqual(rechecks(logs), [historyRecheckNotice("unclean-stop", 2)], "one line for both repositories, never one per pack");
    assert.equal(rechecks(logs)[0], "mandu: ! Mandu's protection service restarted after an unprotected or abrupt stop, so Mandu is re-checking the git history of 2 repositories (slower this once)");
    seals.rotate();
    const older: string[] = [];
    await prepareGitObjectTwins([f.secret, g.secret], { ...opts, log: (m) => older.push(m) });
    assert.deepEqual(rechecks(older), ["mandu: ! Mandu's earlier checks could not be vouched for, so Mandu is re-checking the git history of 2 repositories (slower this once)"]);
  } finally { f.done(); g.done(); }
});

test("plan 14 §11.2.1 the rebuild notice: SealSession calls onRecheck once, with the honoured answer's cause, on the first entry with no seal; a throwing callback changes nothing; the line's words and display", async () => {
  const seals = memorySeals();
  seals.rotate("unprotected-ended");
  const causes: unknown[] = [];
  const s = new SealSession(seals);
  s.onRecheck = (c) => { causes.push(c); throw new Error("stderr closed"); };
  assert.equal(await s.verifyBytes("history-walk", "a1", Buffer.from("x")), false, "unsealed: not trusted, whatever the callback did");
  assert.equal(await s.verifyBytes("history-walk", "a2", Buffer.from("y")), false);
  assert.deepEqual(causes, ["unprotected-ended"], "once");
  assert.deepEqual(s.rejected.map((r) => r.reason), ["unsealed", "unsealed"], "the report is unchanged");

  // The words: plain (no epoch, seal or pack), singular and plural, and the
  // display prints the line AT ONCE in both modes (noteShow), never under
  // the banner after the wait it explains.
  for (const cause of ["unprotected-ended", "unclean-stop", "first-start", undefined] as const) {
    for (const n of [0, 1, 3]) {
      const line = historyRecheckNotice(cause, n);
      assert.ok(isHistoryRecheckNotice(line), line);
      assert.match(line, /^mandu: ! /);
      assert.doesNotMatch(line, /epoch|seal|pack|cache/i, line);
      assert.match(line, n <= 1 ? / of 1 repository \(/ : / of 3 repositories \(/);
      assert.equal(compactNotice(line), null, "not collected under the banner");
      assert.deepEqual(noteShow(line, "compact"), { kind: "print" });
      assert.deepEqual(noteShow(line, "full"), { kind: "print" });
    }
  }
  assert.equal(historyRecheckNotice("first-start", 1), historyRecheckNotice(undefined, 1), "no known cause: the generic why");
  assert.equal(isHistoryRecheckNotice(voidedCachesLine([{ pid: 1, mode: "off", posture: "off" }])), false);
  assert.equal(isHistoryRecheckNotice("mandu: sanitizing pack-1.pack (1 MiB) of /w: it holds 1 protected version(s)"), false);
  // The display's other kinds (packaging.md §5, 2026-10-18): the voided
  // caches are a notice the banner counts (its text in `mandu log`), an
  // all-is-well line is kept for the log, a caller's own notice is counted,
  // a warning is one posture line.
  const voided = voidedCachesLine([{ pid: 9, mode: "off", posture: "off" }]);
  assert.notEqual(compactNotice(voided), null, "a known notice");
  assert.deepEqual(noteShow(voided, "compact"), { kind: "notice" });
  assert.deepEqual(noteShow(voided, "full"), { kind: "print" });
  assert.deepEqual(noteShow("mandu: sanitizing pack-1.pack (1 MiB) of /w: it holds 1 protected version(s)", "compact"), { kind: "keep" });
  assert.deepEqual(noteShow("mandu: something quiet", "compact", true), { kind: "notice" });
  assert.deepEqual(noteShow("WARNING: mandu: x", "compact"), { kind: "short", line: "mandu: WARNING: x (more: `mandu log`)" });
});

test("asCacheSeals: the epoch's cause is display only: a known one kept, anything else dropped", () => {
  const base = { epoch: "e1", honoured: true, seals: [] };
  assert.equal(asCacheSeals({ ...base, epochCause: "unprotected-ended" }).epochCause, "unprotected-ended");
  assert.equal(asCacheSeals({ ...base, epochCause: "unclean-stop" }).epochCause, "unclean-stop");
  assert.equal(asCacheSeals({ ...base, epochCause: "first-start" }).epochCause, "first-start");
  for (const bad of ["x", "unprotected-ended\n", 3, null]) assert.equal("epochCause" in asCacheSeals({ ...base, epochCause: bad }), false, String(bad));
});

test("asCacheSeals: the named launches are display only and checked: a control character or a bad pid drops the field or the entry; at most five", () => {
  const base = { epoch: "e1", honoured: false, reason: "2 unconfined launches are live", seals: [] };
  const got = asCacheSeals({
    ...base,
    live: [
      { pid: 7, mode: "off", posture: "off", why: "protection off", workspace: "/x\u001b[2J", session: "s\nforged" },
      { pid: -1, mode: "off", posture: "off" },
      { pid: "8", mode: "off", posture: "off" },
      null,
      { pid: 9, mode: "secrets\u0007", posture: "gated", walled: true, begunAt: 5 },
    ],
  });
  assert.deepEqual(got.live, [
    { pid: 7, mode: "off", posture: "off", why: "protection off" },
    { pid: 9, mode: "unknown", posture: "gated" },
  ]);
  assert.equal(asCacheSeals({ ...base, live: [] }).live, undefined, "an empty list is none");
  assert.equal(asCacheSeals({ ...base, live: "x" }).live, undefined);
  assert.equal(asCacheSeals({ ...base, live: Array.from({ length: 9 }, (_, i) => ({ pid: i + 1, mode: "off", posture: "off" })) }).live!.length, 5);
});

test("asCacheSeals: the arbiter's answer unchanged; any other shape throws (the caller trusts nothing)", () => {
  const good = { epoch: "e1", honoured: true, seals: [{ key: "k", sha256: "a".repeat(64), size: 3 }] };
  assert.deepEqual(asCacheSeals(good), good);
  assert.deepEqual(asCacheSeals({ epoch: "e1", honoured: false, reason: "why", seals: [] }), { epoch: "e1", honoured: false, reason: "why", seals: [] });
  for (const bad of [null, {}, { epoch: "e", honoured: "yes", seals: [] }, { epoch: "e", honoured: true, seals: [{ key: "k", sha256: "A".repeat(64), size: 1 }] }, { epoch: "e", honoured: true, seals: [{ key: "k", sha256: "a".repeat(64), size: 1.5 }] }]) {
    assert.throws(() => asCacheSeals(bad), /not \{epoch, honoured, seals\[\]\}/);
  }
});

test("the seal ops ride only the human socket: no human socket, no seal client (nothing cached is trusted)", () => {
  assert.equal(sealClientOf(socketSecretArbiter("/tmp/nobody.sock")), undefined);
  const a = socketSecretArbiter("/tmp/nobody.sock", { humanSock: "/tmp/nobody-human.sock" });
  assert.equal(typeof a.cacheSeals, "function");
  assert.equal(typeof a.sealCacheEntries, "function");
  assert.notEqual(sealClientOf(a), undefined);
  assert.equal(sealClientOf({ discoverSecrets: async () => [], registerSecret: async () => ({ symbol: null, reason: "" }) }), undefined, "a mock without the ops");
});

test("launch record: the launcher's reading of the rule; begin/end over the human socket; an unprotected launch the arbiter could not record deletes the caches at its end", async () => {
  const claim = { pid: 42, mode: "secrets", posture: "confined", writeProtect: true };
  assert.equal(launchConfinedLocally(claim), true);
  assert.equal(launchConfinedLocally({ ...claim, mode: "full" }), true);
  for (const bad of [{ mode: "off" }, { mode: "injection" }, { posture: "gated" }, { posture: "read-blocked" }, { posture: "off" }, { writeProtect: false }, { mode: "Secrets" }]) {
    assert.equal(launchConfinedLocally({ ...claim, ...bad }), false, JSON.stringify(bad));
  }

  const calls: Array<{ sock: string; op: string; args: Record<string, unknown> }> = [];
  let purged = 0;
  const logs: string[] = [];
  const deps = (answer: (op: string) => unknown): CacheEpochDeps => ({
    call: async (sock, op, args) => { calls.push({ sock, op, args }); const a = answer(op); if (a instanceof Error) throw a; return a; },
    log: (m) => logs.push(m),
    purge: () => { purged++; },
  });

  const ok = deps((op) => (op === "beginLaunch" ? { token: "tok", confined: false, epoch: "e" } : { ended: true, rotated: true, epoch: "e2" }));
  const rec = await beginLaunchRecord("/h.sock", { ...claim, posture: "gated" }, ok);
  assert.deepEqual(rec, { token: "tok", confined: false, purgeAtEnd: false, others: [] });
  assert.deepEqual(calls[0], { sock: "/h.sock", op: "beginLaunch", args: { pid: 42, mode: "secrets", posture: "gated", writeProtect: true } });
  await endLaunchRecord("/h.sock", rec, ok);
  assert.deepEqual(calls[1], { sock: "/h.sock", op: "endLaunch", args: { token: "tok" } });
  assert.equal(purged, 0);
  assert.deepEqual(logs, []);

  // No human socket: an unprotected launch says so and purges at its end.
  const off = await beginLaunchRecord(null, { ...claim, mode: "off", posture: "off", writeProtect: false }, ok);
  assert.deepEqual(off, { token: null, confined: false, purgeAtEnd: true, others: [] });
  assert.match(logs[0]!, /^WARNING: mandu: the protection service could not record this unprotected launch \(it reported no human socket\); Mandu's git-history caches will be deleted when it ends$/);
  await endLaunchRecord(null, off, ok);
  assert.equal(purged, 1);
  // A confined one needs nothing.
  logs.length = 0;
  assert.deepEqual(await beginLaunchRecord(undefined, claim, ok), { token: null, confined: true, purgeAtEnd: false, others: [] });
  assert.deepEqual(logs, []);
  // A failed call or a malformed answer is the same fallback.
  const failing = deps(() => new Error("human-plane: refused"));
  assert.equal((await beginLaunchRecord("/h.sock", { ...claim, posture: "gated" }, failing)).purgeAtEnd, true);
  assert.equal((await beginLaunchRecord("/h.sock", { ...claim, posture: "gated" }, deps(() => ({ token: 3 })))).purgeAtEnd, true);
  // endLaunch failing never throws (the arbiter reaps by pid).
  await endLaunchRecord("/h.sock", { token: "t", confined: false, purgeAtEnd: false, others: [] }, failing);
});

test("plan 10 §11.13: the launch record carries the launch's HOME and session to the human socket, for the arbiter's catalog places", async () => {
  const calls: Array<{ sock: string; op: string; args: Record<string, unknown> }> = [];
  const deps: CacheEpochDeps = {
    call: async (sock, op, args) => { calls.push({ sock, op, args }); return { token: "tok", confined: true, epoch: "e" }; },
    log: () => {},
    purge: () => {},
  };
  await beginLaunchRecord("/h.sock", { pid: 7, mode: "secrets", posture: "confined", writeProtect: true, sessionId: "scope-1", home: "/tmp/other-home" }, deps);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.sock, "/h.sock", "on the human socket only");
  assert.equal(calls[0]!.args["home"], "/tmp/other-home");
  assert.equal(calls[0]!.args["sessionId"], "scope-1");
});

test("plan 13 D9 leftovers: an unwalled launch the arbiter could not record is refused unless --best-effort; walled, off, or no human socket is not", () => {
  const claim = { pid: 42, mode: "secrets", posture: "gated", writeProtect: false, humanPlaneWalled: false };
  const unrec = { token: null, confined: false, purgeAtEnd: true, others: [] };
  const r = unrecordedExposureRefusal("/h.sock", claim, unrec, { bestEffort: false });
  assert.equal(r?.refuse, true);
  assert.match(r!.message, /can reach Mandu's human-plane socket/);
  assert.match(r!.message, /--best-effort/);
  assert.equal(unrecordedExposureRefusal("/h.sock", claim, unrec, { bestEffort: true })?.refuse, false);
  assert.match(unrecordedExposureRefusal("/h.sock", claim, unrec, { bestEffort: true })!.message, /^WARNING: /);
  // an older launcher's claim (no field) counts as unwalled
  const { humanPlaneWalled: _w, ...older } = claim;
  assert.equal(unrecordedExposureRefusal("/h.sock", older, unrec, { bestEffort: false })?.refuse, true);
  assert.equal(unrecordedExposureRefusal("/h.sock", { ...claim, humanPlaneWalled: true }, unrec, { bestEffort: false }), null, "walled");
  assert.equal(unrecordedExposureRefusal("/h.sock", { ...claim, mode: "off", posture: "off" }, unrec, { bestEffort: false }), null, "off observes only");
  assert.equal(unrecordedExposureRefusal(null, claim, unrec, { bestEffort: false }), null, "no human plane to expose");
  assert.equal(unrecordedExposureRefusal("/h.sock", claim, { ...unrec, token: "t" }, { bestEffort: false }), null, "recorded");
});

test("plan 13 D9 leftovers: a confined launch warns of unconfined launches beside it, and refuses under --require-confinement", async () => {
  assert.deepEqual(concurrentLaunchNotice("confined", [], { requireConfinement: true }), { lines: [], refuse: false });
  const others = [{ pid: 7, mode: "secrets", posture: "gated", walled: false }];
  assert.deepEqual(concurrentLaunchNotice("gated", others, { requireConfinement: true }), { lines: [], refuse: false }, "only a confined launch has anything to lose");
  const n = concurrentLaunchNotice("confined", others, { requireConfinement: false });
  assert.equal(n.refuse, false);
  assert.match(n.lines[0]!, /^WARNING: mandu: 1 other Mandu launch runs without confinement beside this one: pid 7 \(secrets, gated, can reach Mandu's state\)/);
  assert.match(n.lines[1]!, /rewrite this launch's placeholder files\.$/);
  // the guard's lost attestation is the human-plane watch's to say (with the fix), not this notice's
  assert.doesNotMatch(n.lines.join("\n"), /not believed/);
  const strict = concurrentLaunchNotice("confined", others, { requireConfinement: true });
  assert.equal(strict.refuse, true);
  assert.match(strict.lines.at(-1)!, /Refusing to launch \(--require-confinement\)/);
  // the arbiter's `others`, carried through the record (an older arbiter: none)
  const deps: CacheEpochDeps = { call: async () => ({ token: "t", confined: true, epoch: "e", others: [{ pid: 7, mode: "secrets", posture: "gated", walled: false }, { bogus: 1 }] }), log: () => {}, purge: () => {} };
  assert.deepEqual((await beginLaunchRecord("/h.sock", { pid: 1, mode: "secrets", posture: "confined", writeProtect: true, humanPlaneWalled: true }, deps)).others, others);
});

test("launch record, macOS: read-blocked counts as confined only with homeSealed; the claim carries it to the arbiter; without it the fallback purges", async () => {
  const mac = { pid: 43, mode: "secrets", posture: "read-blocked", writeProtect: true, homeSealed: true, humanPlaneWalled: true, sessionId: "mac-scope", workspace: "/workspace" };
  assert.equal(launchConfinedLocally(mac), true);
  assert.equal(launchConfinedLocally({ ...mac, mode: "full" }), true);
  for (const bad of [{ homeSealed: false }, { homeSealed: undefined }, { writeProtect: false }, { mode: "off" }, { posture: "gated" }]) {
    assert.equal(launchConfinedLocally({ ...mac, ...bad }), false, JSON.stringify(bad));
  }
  assert.equal(launchConfinedLocally({ ...mac, posture: "gated" }), false, "homeSealed never lifts another posture");
  assert.equal(launchConfinedLocally({ pid: 1, mode: "secrets", posture: "confined", writeProtect: true }), true, "the Linux claim needs no seal field");

  const calls: Array<{ op: string; args: Record<string, unknown> }> = [];
  let purged = 0;
  const deps = (answer: unknown): CacheEpochDeps => ({
    call: async (_s, op, args) => { calls.push({ op, args }); if (answer instanceof Error) throw answer; return answer; },
    log: () => {},
    purge: () => { purged++; },
  });
  const rec = await beginLaunchRecord("/h.sock", mac, deps({ token: "t", confined: true, epoch: "e" }));
  assert.deepEqual(rec, { token: "t", confined: true, purgeAtEnd: false, others: [] });
  assert.deepEqual(calls[0], { op: "beginLaunch", args: mac }, "the claim reaches the arbiter whole");
  // The arbiter unreachable: the launcher's own reading decides the fallback.
  const down = deps(new Error("ECONNREFUSED"));
  assert.deepEqual(await beginLaunchRecord("/h.sock", mac, down), { token: null, confined: true, purgeAtEnd: false, others: [] }, "a sealed macOS launch purges nothing");
  const unsealed = await beginLaunchRecord("/h.sock", { ...mac, homeSealed: false }, down);
  assert.deepEqual(unsealed, { token: null, confined: false, purgeAtEnd: true, others: [] }, "an unsealed one deletes the caches at its end");
  await endLaunchRecord("/h.sock", unsealed, down);
  assert.equal(purged, 1);
});

test("purgeEnforcementCaches removes the sanitized packs and the walks (the scan cache inside them) under MANDU_HOME, nothing else", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-purge-"));
  try {
    const home = join(tmp, "mh");
    const env = { MANDU_HOME: home };
    for (const d of ["cache/object-twins/k", "state/object-walks/history-scan", "state"]) mkdirSync(join(home, d), { recursive: true });
    writeFileSync(join(home, "state", "mandu.db"), "db");
    writeFileSync(join(home, "state", "object-walks", "w.json"), "{}");
    purgeEnforcementCaches(env, tmp);
    assert.equal(existsSync(join(home, "cache", "object-twins")), false);
    assert.equal(existsSync(join(home, "state", "object-walks")), false);
    assert.equal(readFileSync(join(home, "state", "mandu.db"), "utf8"), "db", "the DB stays");
    purgeEnforcementCaches(env, tmp); // absent: no error
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
