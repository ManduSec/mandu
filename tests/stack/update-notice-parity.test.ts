/**
 * update-notice-parity — Settings › About Mandu's *A newer release* gives
 * the launcher's answers (dashboard.md §4.25; packaging.md §11.5). The
 * dashboard ships standalone and mirrors launcher/src/update-check.ts
 * (dashboard/src/update-notice.ts) rather than importing it, as it mirrors
 * the docs base (about-mandu-parity.test.ts). This keeps the two equal over
 * a table of inputs: version order, which release to name, the security
 * flag, the channel, the install line, freshness and the cache reader's
 * verdict on each kind of file. Pure but for a temp folder: no server, no
 * arbiter, nothing enforced, so no axis is in play. Mandu-new.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as dash from "../../dashboard/src/update-notice.js";
import * as launcher from "../../launcher/src/update-check.js";

const VERSIONS = [
  "0.1.0", "0.2.0-alpha", "0.2.0-beta", "0.2.0-beta.2", "0.2.0-beta.3", "0.2.0-beta.10", "0.2.0-beta.x", "0.2.0-rc.1",
  "0.2.0", "v0.2.0", "0.2.0+build.7", "1.0.0", " 1.0.1 ", "unknown", "", "1.2", "01.2.3", "1.0.0; rm -rf ~", "1.0.0\n2",
];

const RELEASE_TABLES: Array<Array<{ version: string; security: boolean }>> = [
  [],
  [{ version: "0.2.0-beta.8", security: true }, { version: "0.2.0-beta.9", security: false }],
  [{ version: "0.2.0", security: false }, { version: "0.3.0-beta.1", security: true }],
  [{ version: "0.2.0-beta.6", security: true }, { version: "1.0.0", security: false }, { version: "bogus", security: true }],
  [{ version: "0.2.0-beta.10", security: false }, { version: "0.2.0-beta.9", security: true }],
];

test("version parsing and order are the launcher's", () => {
  for (const a of VERSIONS) {
    assert.deepEqual(dash.parseVersion(a), launcher.parseVersion(a), JSON.stringify(a));
    for (const b of VERSIONS) {
      const da = dash.parseVersion(a), db = dash.parseVersion(b);
      if (da && db) assert.equal(dash.compareVersions(da, db), launcher.compareVersions(da, db), `${a} vs ${b}`);
    }
  }
});

test("newerRelease names the launcher's release and security flag for every running version", () => {
  for (const current of VERSIONS) {
    for (const releases of RELEASE_TABLES) {
      assert.deepEqual(dash.newerRelease(current, releases), launcher.newerRelease(current, releases), `${JSON.stringify(current)} over ${JSON.stringify(releases)}`);
    }
  }
});

test("the install line and the channel are the launcher's", () => {
  for (const version of ["0.2.0-beta.9", "1.0.0"]) {
    for (const channel of ["npm", "release"] as const) assert.equal(dash.installLine(version, channel), launcher.installLine(version, channel));
    assert.equal(dash.installLine(version), launcher.installLine(version), "the default channel");
  }
  assert.equal(dash.RELEASE_REPO, launcher.RELEASE_REPO);
  for (const mode of ["installed", "dev"] as const) {
    for (const marked of [true, false]) {
      const exists = (p: string) => marked && p === "/pkg/.mandu-installer";
      assert.equal(dash.updateChannel({ mode, pkgRoot: "/pkg" }, exists), launcher.updateChannel({ mode, pkgRoot: "/pkg" }, exists), `${mode} ${marked}`);
    }
  }
});

test("freshness and the limits are the launcher's", () => {
  const now = Date.UTC(2026, 9, 22);
  for (const checkedAt of [now, now - 3_600_000, now - 86_400_000, now - 86_399_999, now + 60_000, now + 3_600_000]) {
    const c = { v: 1 as const, checkedAt, ok: true, releases: [], releasesAt: checkedAt };
    assert.equal(dash.cacheFresh(c, now), launcher.cacheFresh(c, now), String(checkedAt - now));
  }
  assert.equal(dash.MAX_CACHE_BYTES, launcher.MAX_CACHE_BYTES);
  assert.equal(dash.MAX_RELEASES, launcher.MAX_RELEASES);
  assert.equal(dash.UPDATE_CHECK_INTERVAL_MS, launcher.UPDATE_CHECK_INTERVAL_MS);
});

const tmp = mkdtempSync(join(tmpdir(), "mandu-update-parity-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

test("the cache reader gives the launcher's verdict on every kind of file", () => {
  const good = { v: 1, checkedAt: 1, ok: true, releases: [{ version: "0.2.0-beta.9", security: true }], releasesAt: 1 };
  const files: Array<[string, string, number]> = [
    ["good", JSON.stringify(good), 0o600],
    ["readable by others", JSON.stringify(good), 0o644],
    ["group-writable", JSON.stringify(good), 0o620],
    ["other-writable", JSON.stringify(good), 0o602],
    ["bad JSON", "{", 0o600],
    ["another version", JSON.stringify({ ...good, v: 2 }), 0o600],
    ["shell text as a version", JSON.stringify({ ...good, releases: [{ version: "1.0.0 && id", security: true }] }), 0o600],
    ["no list yet", JSON.stringify({ ...good, ok: false, releases: [], releasesAt: null }), 0o600],
    ["more than the kept releases", JSON.stringify({ ...good, releases: Array.from({ length: 150 }, (_, i) => ({ version: `0.0.${i}`, security: false })) }), 0o600],
    ["oversized", " ".repeat(dash.MAX_CACHE_BYTES + 1), 0o600],
  ];
  for (const [name, body, mode] of files) {
    const p = join(tmp, name.replace(/\W+/g, "-") + ".json");
    writeFileSync(p, body, { mode });
    chmodSync(p, mode);
    assert.deepEqual(dash.readUpdateCache(p), launcher.readUpdateCache(p), name);
  }
  const link = join(tmp, "link.json");
  symlinkSync(join(tmp, "good.json"), link);
  assert.equal(dash.readUpdateCache(link), null);
  assert.equal(launcher.readUpdateCache(link), null);
  const other = (process.getuid?.() ?? 0) + 1;
  assert.deepEqual(dash.readUpdateCache(join(tmp, "good.json"), other), launcher.readUpdateCache(join(tmp, "good.json"), other));
  assert.equal(dash.readUpdateCache(join(tmp, "absent.json")), launcher.readUpdateCache(join(tmp, "absent.json")));
  assert.ok(dash.readUpdateCache(join(tmp, "good.json")), "the good file is read");
});
