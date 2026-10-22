// release-assets.test.mjs — the files a GitHub release carries beside the
// tarball (scripts/ci/release-assets.mjs; packaging.md §11.3): a release copy
// of install.sh naming that release's tarball URL and SHA-256, the notes from
// the tag's message, and a bad checksum writing nothing. Offline.
//
// Run: node --test scripts/test/release-assets.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";
import { parseArgs, readBuild, releaseInstaller, releaseNotes, tarballUrl } from "../ci/release-assets.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCRIPT = join(REPO, "scripts", "ci", "release-assets.mjs");
const INSTALL = join(REPO, "scripts", "install.sh");

function build(dir, { version = "9.9.9-beta.1", tamper = false } = {}) {
  mkdirSync(dir, { recursive: true });
  const name = `mandusec-mandu-${version}.tgz`;
  writeFileSync(join(dir, name), "tarball bytes\n");
  const bytes = readFileSync(join(dir, name));
  const sum = createHash("sha256").update(bytes).digest("hex");
  writeFileSync(join(dir, "SHA256SUMS"), `${tamper ? "0".repeat(64) : sum}  ${name}\n`);
  return { name, sum, sha1: createHash("sha1").update(bytes).digest("hex") };
}

function run(args, env = {}) {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8", env: { ...process.env, GITHUB_REPOSITORY: "", ...env } });
  return { code: r.status, out: r.stdout, err: r.stderr };
}

test("releaseInstaller sets the default package and hash; refuses a script without the hook", () => {
  const src = readFileSync(INSTALL, "utf8");
  const out = releaseInstaller(src, "https://x/y.tgz", "b".repeat(64));
  assert.match(out, /^PACKAGE_DEFAULT="https:\/\/x\/y\.tgz"$/m);
  assert.match(out, new RegExp(`^PACKAGE_DEFAULT_SHA256="${"b".repeat(64)}"$`, "m"));
  assert.throws(() => releaseInstaller("#!/bin/sh\n", "u", "b".repeat(64)), /no PACKAGE_DEFAULT/);
  assert.throws(() => releaseInstaller(src, "u", "xyz"), /not a SHA-256/);
});

test("the tarball URL is the versioned release path of the named repository", () => {
  assert.equal(tarballUrl("ManduSec/mandu", "0.2.0-beta.1"),
    "https://github.com/ManduSec/mandu/releases/download/v0.2.0-beta.1/mandusec-mandu-0.2.0-beta.1.tgz");
});

test("readBuild checks the tarball against SHA256SUMS and reports npm's SHA-1", () => {
  const ok = tmpDir("ra-build-");
  const b = build(ok);
  assert.deepEqual(readBuild(ok), { name: b.name, version: "9.9.9-beta.1", sha256: b.sum, sha1: b.sha1 });
  const bad = tmpDir("ra-build-");
  build(bad, { tamper: true });
  assert.throws(() => readBuild(bad), /SHA256SUMS says 0+, the file is/);
  assert.throws(() => readBuild(tmpDir("ra-empty-")), /expected one mandusec-mandu-<v>\.tgz, found 0/);
});

test("releaseNotes: the tag's message, its signature dropped, then the tarball line; an empty tag is refused", () => {
  const sig = "-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n";
  assert.equal(releaseNotes(`Mandu 1.0\n\n- a fix\n${sig}`, "t.tgz", "c".repeat(64)),
    `Mandu 1.0\n\n- a fix\n\n\`t.tgz\` sha256 \`${"c".repeat(64)}\`\n`);
  assert.match(releaseNotes("x\n<!-- mandu: security-release -->\n", "t.tgz", "c".repeat(64)),
    /<!-- mandu: security-release -->/, "the security marker the update notice reads survives");
  assert.throws(() => releaseNotes(`\n${sig}`, "t.tgz", "c".repeat(64)), /no message/);
});

test("args: --dir required, --repo OWNER/NAME (from GITHUB_REPOSITORY by default), notes in and out together", () => {
  assert.throws(() => parseArgs([], {}), /--dir is required/);
  assert.equal(parseArgs(["--dir", "d"], {}).repo, "ManduSec/mandu");
  assert.equal(parseArgs(["--dir", "d"], { GITHUB_REPOSITORY: "o/n" }).repo, "o/n");
  assert.throws(() => parseArgs(["--dir", "d", "--repo", "bad"], {}), /OWNER\/NAME/);
  assert.throws(() => parseArgs(["--dir", "d", "--notes-in", "x"], {}), /go together/);
});

test("e2e: writes the release install.sh and the notes, and prints the outputs the workflow reads", () => {
  const dir = tmpDir("ra-e2e-");
  const b = build(dir, { version: "0.3.0" });
  writeFileSync(join(dir, "tag.txt"), "Mandu 0.3.0\n\n- New: a thing\n");
  const r = run(["--dir", dir, "--repo", "ManduSec/mandu", "--notes-in", join(dir, "tag.txt"), "--notes-out", join(dir, "notes.md")]);
  assert.equal(r.code, 0, r.err);
  assert.deepEqual(r.out.trim().split("\n"),
    ["version=0.3.0", "tag=v0.3.0", `tarball=${b.name}`, `sha256=${b.sum}`, `sha1=${b.sha1}`]);
  const inst = readFileSync(join(dir, "install.sh"), "utf8");
  assert.match(inst, /^PACKAGE_DEFAULT="https:\/\/github\.com\/ManduSec\/mandu\/releases\/download\/v0\.3\.0\/mandusec-mandu-0\.3\.0\.tgz"$/m);
  assert.match(inst, new RegExp(`^PACKAGE_DEFAULT_SHA256="${b.sum}"$`, "m"));
  assert.ok(statSync(join(dir, "install.sh")).mode & 0o100, "the release install.sh is executable");
  assert.match(readFileSync(join(dir, "notes.md"), "utf8"), new RegExp(`- New: a thing\\n\\n\`${b.name}\` sha256 \`${b.sum}\`\\n$`));
});

test("e2e: a tarball that does not match SHA256SUMS writes nothing and exits 1", () => {
  const dir = tmpDir("ra-bad-");
  build(dir, { tamper: true });
  const r = run(["--dir", dir]);
  assert.equal(r.code, 1);
  assert.match(r.err, /SHA256SUMS says/);
  assert.ok(!existsSync(join(dir, "install.sh")));
});
