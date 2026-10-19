/**
 * update-check unit tests (packaging.md §11.5): semver precedence with
 * prereleases, which release a running version is told of and when it is a
 * security release, the gate (opt-out, CI, source checkout, terminal), the
 * test URL override, cache freshness and its refusals, the refresh's error
 * paths (each silent, each stamping the day), and the launch and doctor
 * answers over injected deps (no network, no real home).
 *
 * No arbiter and no secret: the check carries nothing of a session. The
 * real request over a local server is the component test
 * (test/component/update-check.test.ts).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, mkdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  cacheFresh, compareVersions, doctorUpdateFacts, installLine, isUpdateNotice, launchUpdateCheck, newerRelease,
  parseReleases, parseVersion, readUpdateCache, refreshUpdateCache, releasesUrl, RELEASES_URL, SECURITY_MARKER,
  UPDATE_CHECK_INTERVAL_MS, updateCachePath, updateCheckGate, updateNotice, updateRows, writeUpdateCache,
  type UpdateCache, type UpdateCheckDeps,
} from "../../src/update-check.js";
import { compactNotice, isAttentionNote } from "../../src/launch-banner.js";
import { loadConfigEnv } from "../../src/config.js";

const dir = mkdtempSync(join(tmpdir(), "mdu-update-check-"));
after(() => rmSync(dir, { recursive: true, force: true }));

const v = (s: string) => {
  const p = parseVersion(s);
  assert.ok(p, s);
  return p;
};

test("semver precedence: prereleases before their release, numeric identifiers numerically", () => {
  const order = [
    "0.1.0", "0.2.0-alpha", "0.2.0-alpha.1", "0.2.0-alpha.beta", "0.2.0-beta", "0.2.0-beta.2",
    "0.2.0-beta.3", "0.2.0-beta.4", "0.2.0-beta.11", "0.2.0-rc.1", "0.2.0", "0.2.1", "0.10.0", "1.0.0",
  ];
  for (let i = 0; i < order.length; i++) {
    for (let j = 0; j < order.length; j++) {
      const c = Math.sign(compareVersions(v(order[i]!), v(order[j]!)));
      assert.equal(c, Math.sign(i - j), `${order[i]} vs ${order[j]}`);
    }
  }
  assert.equal(compareVersions(v("v1.2.3"), v("1.2.3+build.7")), 0, "a leading v and build metadata do not count");
  for (const bad of ["", "1.2", "01.2.3", "1.2.3-", "1.2.3.4", "latest", "v", "1.2.3-beta..1"]) {
    assert.equal(parseVersion(bad), null, bad);
  }
});

test("parseReleases: tags v<semver> only, drafts dropped, the security marker read from the notes", () => {
  const got = parseReleases([
    { tag_name: "v0.2.0-beta.4", draft: false, body: `Fixes.\n\n${SECURITY_MARKER}\n` },
    { tag_name: "v0.2.0-beta.3", draft: false, body: "Faster launch." },
    { tag_name: "v0.3.0", draft: true, body: "" },
    { tag_name: "nightly", draft: false },
    { tag_name: "0.9.0", draft: false },
    { tag_name: "v0.2.0-beta.5", body: "<!--  MANDU:  security-release  -->" },
    { tag_name: "v0.2.0-beta.6", body: "This is not a security release." },
    null, 7, "x",
  ]);
  assert.deepEqual(got, [
    { version: "0.2.0-beta.4", security: true },
    { version: "0.2.0-beta.3", security: false },
    { version: "0.2.0-beta.5", security: true },
    { version: "0.2.0-beta.6", security: false },
  ]);
  assert.equal(parseReleases({ message: "Not Found" }), null, "a 404 body is not a list");
  assert.equal(parseReleases(null), null);
});

test("newerRelease: a beta hears of the next beta and of the release; a release hears of releases only", () => {
  const rel = [
    { version: "0.2.0-beta.3", security: false },
    { version: "0.2.0-beta.4", security: false },
  ];
  assert.deepEqual(newerRelease("0.2.0-beta.3", rel), { newest: "0.2.0-beta.4", security: false });
  assert.equal(newerRelease("0.2.0-beta.4", rel), null, "up to date");
  const ga = [...rel, { version: "0.2.0", security: false }];
  assert.deepEqual(newerRelease("0.2.0-beta.3", ga), { newest: "0.2.0", security: false });
  assert.equal(newerRelease("0.2.0", ga), null);
  const next = [...ga, { version: "0.2.1-beta.1", security: true }];
  assert.equal(newerRelease("0.2.0", next), null, "a release user is not offered a prerelease");
  assert.deepEqual(newerRelease("0.2.0-beta.4", next), { newest: "0.2.1-beta.1", security: true });
  assert.equal(newerRelease("0.3.0", next), null, "ahead of every release (a dev build)");
  assert.equal(newerRelease("unknown", next), null, "an unreadable own version compares to nothing");
});

test("newerRelease: SECURITY when any release after the running one carries the marker, not only the newest", () => {
  const rel = [
    { version: "0.2.0-beta.2", security: true },
    { version: "0.2.0-beta.3", security: true },
    { version: "0.2.0-beta.4", security: false },
  ];
  assert.deepEqual(newerRelease("0.2.0-beta.2", rel), { newest: "0.2.0-beta.4", security: true }, "beta.3 fixed leaks");
  assert.deepEqual(newerRelease("0.2.0-beta.3", rel), { newest: "0.2.0-beta.4", security: false }, "the one already installed does not count");
});

test("the notice: one line, the install line of that release, SECURITY said plainly; the compact display keeps it as is", () => {
  const plain = updateNotice("0.2.0-beta.3", { newest: "0.2.0", security: false });
  assert.equal(plain, `mandu: ! Mandu 0.2.0 is out (you have 0.2.0-beta.3); to update: ${installLine("0.2.0")}`);
  assert.equal(installLine("0.2.0"), "curl -fsSL https://github.com/ManduSec/mandu/releases/download/v0.2.0/install.sh | sh");
  const sec = updateNotice("0.2.0-beta.3", { newest: "0.2.0-beta.4", security: true });
  assert.match(sec, /^mandu: ! Mandu 0\.2\.0-beta\.4 is out with SECURITY fixes \(you have 0\.2\.0-beta\.3\); update now: curl /);
  for (const n of [plain, sec]) {
    assert.ok(!n.includes("\n"));
    assert.ok(isUpdateNotice(n));
    assert.equal(compactNotice(n), n, "the compact display prints it unchanged");
    assert.equal(isAttentionNote(n), false, "a notice, not a degrade");
  }
  assert.equal(isUpdateNotice("mandu: ! Claude Code 9.0.0 is newer than Mandu has tested (up to 2.1.0); see `mandu doctor`"), false);
});

test("the gate: MANDU_UPDATE_CHECK=0 wins; unset it runs only installed, outside CI, at a terminal; =1 forces", () => {
  const on = { installed: true, interactive: true };
  assert.deepEqual(updateCheckGate({}, on), { on: true });
  for (const off of ["0", "false", "off", "no", " FALSE "]) {
    const g = updateCheckGate({ MANDU_UPDATE_CHECK: off }, on);
    assert.equal(g.on, false, off);
    assert.ok(!g.on && g.optedOut);
  }
  for (const ci of ["true", "1", "yes"]) assert.equal(updateCheckGate({ CI: ci }, on).on, false, `CI=${ci}`);
  assert.equal(updateCheckGate({ CI: "false" }, on).on, true, "CI=false is not CI");
  assert.equal(updateCheckGate({}, { installed: false, interactive: true }).on, false, "a source checkout");
  assert.equal(updateCheckGate({}, { installed: true, interactive: false }).on, false, "not a terminal");
  assert.deepEqual(updateCheckGate({ MANDU_UPDATE_CHECK: "1", CI: "true" }, { installed: false, interactive: false }), { on: true });
  // config.toml `update-check = false` seeds MANDU_UPDATE_CHECK=0.
  const cfg = loadConfigEnv({ HOME: "/h" }, () => "update-check = false\n");
  assert.equal(cfg["MANDU_UPDATE_CHECK"], "0");
  assert.equal(updateCheckGate(cfg, on).on, false);
});

test("the URL: GitHub's release list by default; a test's override only when https or loopback http", () => {
  assert.equal(RELEASES_URL, "https://api.github.com/repos/ManduSec/mandu/releases?per_page=30");
  assert.equal(releasesUrl({}), RELEASES_URL);
  assert.equal(releasesUrl({ MANDU_UPDATE_CHECK_URL: "http://127.0.0.1:4321/r" }), "http://127.0.0.1:4321/r");
  assert.equal(releasesUrl({ MANDU_UPDATE_CHECK_URL: "http://localhost:1/r" }), "http://localhost:1/r");
  assert.equal(releasesUrl({ MANDU_UPDATE_CHECK_URL: "https://mirror.example/r" }), "https://mirror.example/r");
  for (const bad of ["http://evil.example/r", "file:///etc/passwd", "not a url", "ftp://127.0.0.1/"]) {
    assert.equal(releasesUrl({ MANDU_UPDATE_CHECK_URL: bad }), RELEASES_URL, bad);
  }
});

const entry = (over: Partial<UpdateCache> = {}): UpdateCache => ({
  v: 1, checkedAt: 1_000_000, ok: true, releases: [{ version: "0.2.0", security: false }], releasesAt: 1_000_000, ...over,
});

test("cache freshness: younger than a day; a checkedAt in the future is stale (a forged entry cannot silence it for good)", () => {
  const c = entry();
  assert.equal(cacheFresh(c, c.checkedAt), true);
  assert.equal(cacheFresh(c, c.checkedAt + UPDATE_CHECK_INTERVAL_MS - 1), true);
  assert.equal(cacheFresh(c, c.checkedAt + UPDATE_CHECK_INTERVAL_MS), false);
  assert.equal(cacheFresh(entry({ checkedAt: 10 * UPDATE_CHECK_INTERVAL_MS }), 1_000_000), false, "from the future");
});

test("the cache file: under the Mandu home's cache/, written 0600, read back; links, others' writes and junk are misses", () => {
  const home = join(dir, "home-a");
  const path = updateCachePath({ MANDU_HOME: home });
  assert.equal(path, join(home, "cache", "update-check.json"));
  assert.equal(readUpdateCache(path), null, "absent");
  assert.ok(writeUpdateCache(path, entry()));
  assert.deepEqual(readUpdateCache(path), entry());
  chmodSync(path, 0o622);
  assert.equal(readUpdateCache(path), null, "writable by others");
  chmodSync(path, 0o600);
  assert.equal(readUpdateCache(path, (process.getuid?.() ?? 0) + 1), null, "not this user's");
  const link = join(dir, "link.json");
  symlinkSync(path, link);
  assert.equal(readUpdateCache(link), null, "a symbolic link is not followed");
  for (const junk of ["{", "[]", JSON.stringify({ ...entry(), v: 2 }), JSON.stringify({ ...entry(), releases: [{ version: "x", security: false }] })]) {
    writeFileSync(path, junk, { mode: 0o600 });
    assert.equal(readUpdateCache(path), null, junk);
  }
  writeFileSync(path, "x".repeat(300 * 1024), { mode: 0o600 });
  assert.equal(readUpdateCache(path), null, "too large");
  assert.equal(writeUpdateCache("/dev/null/no/update-check.json", entry()), false, "an unwritable home fails quietly");
});

/** Deps over an in-memory cache; `fetch` answers from `answers` in turn. */
function memDeps(answers: Array<string | null | Error>, now = 5_000_000_000, start: UpdateCache | null = null) {
  let cache = start;
  const urls: string[] = [];
  const deps: UpdateCheckDeps = {
    fetch: async (url) => {
      urls.push(url);
      const a = answers.shift();
      if (a instanceof Error) throw a;
      return a ?? null;
    },
    now: () => now,
    read: () => cache,
    write: (_p, c) => { cache = c; return true; },
  };
  return { deps, urls, cache: () => cache };
}

const LIST = JSON.stringify([{ tag_name: "v0.2.0", body: SECURITY_MARKER }, { tag_name: "v0.2.0-beta.3", body: "" }]);

test("refresh: a good list is kept; every failure is silent, keeps the last list and still stamps the day", async () => {
  const m = memDeps([LIST]);
  const first = await refreshUpdateCache({}, 100, m.deps);
  assert.equal(first.ok, true);
  assert.deepEqual(first.releases, [{ version: "0.2.0", security: true }, { version: "0.2.0-beta.3", security: false }]);
  assert.equal(m.urls[0], RELEASES_URL);
  for (const failure of [null, "{\"message\":\"Not Found\"}", "<html>rate limited</html>", new Error("ECONNREFUSED")]) {
    const m2 = memDeps([failure], 6_000_000_000, first);
    const e = await refreshUpdateCache({}, 100, m2.deps, first);
    assert.equal(e.ok, false, String(failure));
    assert.equal(e.checkedAt, 6_000_000_000, "the attempt is stamped: the next waits a day");
    assert.deepEqual(e.releases, first.releases, "the last good list is kept");
    assert.equal(e.releasesAt, first.releasesAt);
  }
  const never = await refreshUpdateCache({}, 100, memDeps([null]).deps, null);
  assert.deepEqual({ ok: never.ok, releases: never.releases, releasesAt: never.releasesAt }, { ok: false, releases: [], releasesAt: null });
});

const LAUNCH = { env: {}, version: "0.2.0-beta.3", installed: true, interactive: true };

test("launch: the notice comes from the cache at once; a stale cache is refreshed in the background, a fresh one is not", async () => {
  const now = 5_000_000_000;
  // No cache yet: no notice, one background request.
  const m = memDeps([LIST], now);
  const r = launchUpdateCheck(LAUNCH, m.deps);
  assert.equal(r.notice, null, "the first launch has nothing to say yet");
  assert.ok(r.refresh);
  await r.refresh;
  assert.equal(m.urls.length, 1);
  // The next launch reads that answer and asks nothing.
  const r2 = launchUpdateCheck(LAUNCH, m.deps);
  assert.equal(r2.notice, updateNotice("0.2.0-beta.3", { newest: "0.2.0", security: true }));
  assert.equal(r2.refresh, null);
  assert.equal(m.urls.length, 1, "at most once a day");
  // A day later: the cached notice still prints, and a refresh starts.
  const later = memDeps([null], now + UPDATE_CHECK_INTERVAL_MS, m.cache());
  const r3 = launchUpdateCheck(LAUNCH, later.deps);
  assert.match(r3.notice ?? "", /SECURITY/);
  assert.ok(r3.refresh);
  await r3.refresh;
  assert.equal(later.cache()?.ok, false);
  assert.equal(launchUpdateCheck(LAUNCH, later.deps).notice, r3.notice, "a failed refresh keeps the last answer");
  // Up to date: no line.
  assert.equal(launchUpdateCheck({ ...LAUNCH, version: "0.2.0" }, m.deps).notice, null);
});

test("launch: off asks nothing and reads nothing; a throwing dep never reaches the launch", async () => {
  let touched = 0;
  const deps: UpdateCheckDeps = {
    fetch: async () => { touched++; return LIST; }, now: () => 0,
    read: () => { touched++; return entry(); }, write: () => { touched++; return true; },
  };
  for (const ctx of [
    { ...LAUNCH, env: { MANDU_UPDATE_CHECK: "0" } },
    { ...LAUNCH, env: { CI: "true" } },
    { ...LAUNCH, installed: false },
    { ...LAUNCH, interactive: false },
  ]) {
    assert.deepEqual(launchUpdateCheck(ctx, deps), { notice: null, refresh: null });
  }
  assert.equal(touched, 0);
  const boom: UpdateCheckDeps = { ...deps, read: () => { throw new Error("EIO"); } };
  assert.deepEqual(launchUpdateCheck(LAUNCH, boom), { notice: null, refresh: null });
});

test("doctor: always asks afresh (a forged 'up to date' cache cannot hide a release), falls back to the cached list", async () => {
  const forged = entry({ checkedAt: 5_000_000_000, releases: [], releasesAt: 5_000_000_000 });
  const m = memDeps([LIST], 5_000_000_000, forged);
  const f = await doctorUpdateFacts(LAUNCH, m.deps);
  assert.equal(f.state, "newer");
  assert.ok(f.state === "newer" && f.answer.security && f.fresh);
  assert.equal(m.urls.length, 1);
  const rows = updateRows(f, { ok: "✓", no: "✗", dot: "·" });
  assert.equal(rows.length, 1);
  assert.match(rows[0]!, /^ {2}✗ Mandu 0\.2\.0 is out with SECURITY fixes \(you have 0\.2\.0-beta\.3\); update now: curl -fsSL https:\/\/github\.com\/ManduSec\/mandu\/releases\/download\/v0\.2\.0\/install\.sh \| sh$/);
  // GitHub does not answer: the last list, said to be old.
  const offline = memDeps([null], 6_000_000_000, m.cache());
  const g = await doctorUpdateFacts(LAUNCH, offline.deps);
  assert.ok(g.state === "newer" && !g.fresh);
  assert.match(updateRows(g, { ok: "✓", no: "✗", dot: "·" })[0]!, /GitHub did not answer now; as of 1970-02-27\)/);
  // Never answered: unknown.
  const none = await doctorUpdateFacts(LAUNCH, memDeps([null]).deps);
  assert.equal(none.state, "unknown");
  assert.match(updateRows(none, { ok: "✓", no: "✗", dot: "·" })[0]!, /could not ask GitHub/);
  // Up to date.
  const cur = await doctorUpdateFacts({ ...LAUNCH, version: "0.2.0" }, memDeps([LIST]).deps);
  assert.equal(cur.state, "current");
  assert.match(updateRows(cur, { ok: "✓", no: "✗", dot: "·" })[0]!, /✓ Mandu 0\.2\.0 is the newest release$/);
  // Off: says why, asks nothing.
  const off = memDeps([LIST]);
  const o = await doctorUpdateFacts({ ...LAUNCH, env: { MANDU_UPDATE_CHECK: "0" } }, off.deps);
  assert.deepEqual(o, { version: "0.2.0-beta.3", state: "off", why: "turned off (MANDU_UPDATE_CHECK=0)" });
  assert.equal(off.urls.length, 0);
});

test("mkdir: the cache directory is made 0700 when the home has none", () => {
  const home = join(dir, "home-b");
  mkdirSync(home, { mode: 0o700 });
  const path = updateCachePath({ MANDU_HOME: home });
  assert.ok(writeUpdateCache(path, entry()));
  assert.equal(statSync(join(home, "cache")).mode & 0o777, 0o700);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});
