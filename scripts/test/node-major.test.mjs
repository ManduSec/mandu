// Unit tests for scripts/matrix/lib/node-major.mjs, the fresh-agents host
// prep's choice of the guest's Node major (docs/design/testing/os-test-matrix.md
// §10.14, "Versions"). Run: node --test <this file>.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { tmpDir } from "./lib/tmp-dir.mjs";
import { satisfies, pickNodeMajor, parseVersion } from "../matrix/lib/node-major.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "matrix", "lib", "node-major.mjs");
const HOST_PREP = join(HERE, "..", "matrix", "suites", "fresh-agents.host.sh");
// nodejs.org's dist/index.json lists newest first.
const INDEX = [{ version: "v26.11.1" }, { version: "v26.1.0" }, { version: "v24.21.0" }, { version: "v24.16.0" }, { version: "v22.23.3" }, { version: "v20.19.0" }];

test("OpenClaw 2026.9.x's range (>=24.16.0 <25 || >=26.1.0) picks 24", () => {
  assert.equal(pickNodeMajor(">=24.16.0 <25 || >=26.1.0", INDEX), "24");
});

test("a range the README's 22 satisfies keeps 22; no range keeps 22", () => {
  assert.equal(pickNodeMajor(">=22.22.3", INDEX), "22");
  assert.equal(pickNodeMajor("", INDEX), "22");
  assert.equal(pickNodeMajor(undefined, INDEX), "22");
});

test("the lowest satisfying major wins, and a range nothing satisfies falls back to 22", () => {
  assert.equal(pickNodeMajor(">=26", INDEX), "26");
  assert.equal(pickNodeMajor("^24.16.0 || ^26", INDEX), "24");
  assert.equal(pickNodeMajor(">=30", INDEX), "22");
  assert.equal(pickNodeMajor(">=24", [{ version: "v26.0.0" }, { version: "v22.1.0" }]), "26", "a major with no release is skipped");
});

test("comparators, caret, tilde, x-ranges and hyphen ranges, as npm reads them", () => {
  const yes = [
    ["24.16.0", ">=24.16.0 <25"], ["24.21.0", ">=24.16.0 <25"], ["26.1.0", ">=24.16.0 <25 || >=26.1.0"],
    ["22.22.3", ">=22.22.3"], ["22.23.0", ">22.22"], ["22.22.9", "<=22.22"], ["24.0.0", "24"], ["24.9.1", "24.x"],
    ["24.9.1", "*"], ["24.9.1", ""], ["24.9.1", "^24.1.0"], ["24.1.9", "~24.1.2"], ["24.5.0", "~24"],
    ["0.0.3", "^0.0.3"], ["0.1.7", "^0.1.2"], ["24.0.0", "22 - 24"], ["24.3.0", "22.1 - 24.3.0"],
    ["24.16.0", ">= 24.16.0"], ["24.16.0", "=24.16.0"], ["24.16.0", "v24.16.0"],
  ];
  const no = [
    ["24.15.9", ">=24.16.0 <25"], ["25.0.0", ">=24.16.0 <25"], ["26.0.0", ">=24.16.0 <25 || >=26.1.0"],
    ["22.22.2", ">=22.22.3"], ["22.22.9", ">22.22"], ["22.23.0", "<=22.22"], ["25.0.0", "^24.1.0"],
    ["24.2.0", "~24.1.2"], ["0.0.4", "^0.0.3"], ["0.2.0", "^0.1.2"], ["25.0.0", "22 - 24"], ["24.3.1", "22.1 - 24.3.0"],
    ["24.16.1", "=24.16.0"], ["24.0.0", "<24"],
  ];
  for (const [v, r] of yes) assert.equal(satisfies(v, r), true, `${v} satisfies '${r}'`);
  for (const [v, r] of no) assert.equal(satisfies(v, r), false, `${v} does not satisfy '${r}'`);
});

test("syntax it does not know is an error, never a silent match", () => {
  assert.throws(() => satisfies("24.0.0", "latest"), /unparseable/);
  assert.equal(parseVersion("24.0.0-rc.1"), null);
});

test("the CLI prints the major, and falls back to 22 with a reason on stderr", () => {
  const dir = tmpDir("node-major-");
  const index = join(dir, "index.json");
  writeFileSync(index, JSON.stringify(INDEX));
  const run = (...a) => spawnSync(process.execPath, [CLI, ...a], { encoding: "utf8" });
  let r = run(">=24.16.0 <25 || >=26.1.0", index);
  assert.equal(r.status, 0); assert.equal(r.stdout.trim(), "24");
  r = run(">=24.16.0", join(dir, "missing.json"));
  assert.equal(r.status, 0); assert.equal(r.stdout.trim(), "22");
  assert.match(r.stderr, /node major defaults to 22/);
  r = run("", join(dir, "missing.json"));
  assert.equal(r.stdout.trim(), "22"); assert.equal(r.stderr, "", "no range needs no index");
});

test("host prep no longer looks for npm's semver under `npm root -g` (absent from Debian's npm)", () => {
  const s = readFileSync(HOST_PREP, "utf8");
  assert.doesNotMatch(s, /npm root -g/);
  assert.doesNotMatch(s, /node_modules["', ]+semver/);
  assert.match(s, /lib\/node-major\.mjs/);
});
