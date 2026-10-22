/**
 * release-version.test — the release the dashboard says it runs, and the
 * public docs base its help links start from (Settings › About Mandu,
 * dashboard.md §4.25 *About Mandu*). Temp files only (and one esbuild
 * bundle of the module, as the package ships it), no server, no arbiter;
 * nothing here is enforced, so no axis is in play. Mandu-new test.
 *
 * docs-lane-exempt: docs/usage.md is only a path joined to the docs base
 * here; no doc is read (tests/stack/about-mandu-parity reads it).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

import { DOCS_BASE_URL, RELEASE_PACKAGE_JSON, docsUrl, readReleaseVersion, releaseVersion, releaseVersionFrom } from "../../src/release-version.js";

const DASHBOARD = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const tmp = mkdtempSync(join(tmpdir(), "mandu-release-version-"));
after(() => rmSync(tmp, { recursive: true, force: true }));
const pkg = (name: string, body: string): string => {
  const p = join(tmp, name);
  writeFileSync(p, body);
  return p;
};

test("it reads dashboard/package.json's version, one level above the module (the bundle's rule too)", () => {
  assert.equal(RELEASE_PACKAGE_JSON, join(DASHBOARD, "package.json"));
  const want = (JSON.parse(readFileSync(join(DASHBOARD, "package.json"), "utf8")) as { version: string }).version;
  assert.match(want, /^\d+\.\d+\.\d+/);
  assert.equal(releaseVersion(), want);
});

test("bundled as dist/dashboard.mjs, it reads the package root's package.json beside dist/ (the installed layout)", async () => {
  const root = join(tmp, "pkg");
  mkdirSync(join(root, "dist"), { recursive: true });
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "@mandusec/mandu", version: "9.8.7-bundle.1" }));
  await build({
    entryPoints: [join(DASHBOARD, "src", "release-version.ts")], outfile: join(root, "dist", "dashboard.mjs"),
    bundle: true, platform: "node", format: "esm", logLevel: "silent",
  });
  const mod = (await import(pathToFileURL(join(root, "dist", "dashboard.mjs")).href)) as typeof import("../../src/release-version.js");
  assert.equal(mod.RELEASE_PACKAGE_JSON, join(root, "package.json"));
  assert.equal(mod.releaseVersion(), "9.8.7-bundle.1");
});

test("a missing, unreadable or unparsable file, or no / an empty / a non-string version, gives \"unknown\"", () => {
  assert.equal(readReleaseVersion(join(tmp, "nope.json")), "unknown", "missing");
  assert.equal(readReleaseVersion(tmp), "unknown", "a directory");
  assert.equal(readReleaseVersion(pkg("bad.json", "{ not json")), "unknown", "not JSON");
  assert.equal(readReleaseVersion(pkg("none.json", "{}")), "unknown", "no version");
  assert.equal(readReleaseVersion(pkg("empty.json", JSON.stringify({ version: "  " }))), "unknown", "blank");
  assert.equal(readReleaseVersion(pkg("num.json", JSON.stringify({ version: 2 }))), "unknown", "not a string");
  assert.equal(readReleaseVersion(pkg("null.json", "null")), "unknown", "null");
  if (process.getuid?.() !== 0) {
    const locked = pkg("locked.json", JSON.stringify({ version: "1.0.0" }));
    chmodSync(locked, 0o000);
    assert.equal(readReleaseVersion(locked), "unknown", "unreadable");
  }
  assert.equal(readReleaseVersion(pkg("ok.json", JSON.stringify({ version: " 1.2.3-beta.4 " }))), "1.2.3-beta.4", "trimmed");
});

test("the value is read once: a later change to the file is not read", () => {
  const p = pkg("once.json", JSON.stringify({ version: "1.0.0" }));
  const get = releaseVersionFrom(p);
  assert.equal(get(), "1.0.0");
  writeFileSync(p, JSON.stringify({ version: "2.0.0" }));
  assert.equal(get(), "1.0.0", "cached");
  rmSync(p);
  assert.equal(get(), "1.0.0", "still cached once the file is gone");
  // An unknown is cached too: no read per poll of a file that is not there.
  const gone = releaseVersionFrom(join(tmp, "later.json"));
  assert.equal(gone(), "unknown");
  pkg("later.json", JSON.stringify({ version: "3.0.0" }));
  assert.equal(gone(), "unknown");
});

test("the docs base is the public repository's tree, and docsUrl joins a repo path to it", () => {
  assert.match(DOCS_BASE_URL, /^https:\/\/[^/]+\/.+\/$/);
  assert.equal(docsUrl("docs/usage.md"), DOCS_BASE_URL + "docs/usage.md");
  assert.equal(docsUrl("/docs/usage.md#troubleshooting"), DOCS_BASE_URL + "docs/usage.md#troubleshooting");
  assert.equal(docsUrl("./docs/usage.md"), DOCS_BASE_URL + "docs/usage.md");
});
