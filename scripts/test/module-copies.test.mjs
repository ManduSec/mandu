// Unit tests for scripts/copies/module-copies.mjs, the table of modules that
// ship byte-identical in more than one package (docs/development.md §3), and
// THE parity test for those copies: it fails when any copy differs from its
// source.
// Run: node --test scripts/test/module-copies.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { GROUPS, expectedCopies, generate, staleCopies, tableProblems } from "../copies/module-copies.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCRIPT = join(ROOT, "scripts", "copies", "module-copies.mjs");

/** A scratch tree holding every source and copy of the real repo. */
function scratchTree() {
  const scratch = mkdtempSync(join(tmpdir(), "module-copies-"));
  for (const grp of GROUPS) {
    for (const p of [grp.source, ...grp.copies]) {
      mkdirSync(dirname(join(scratch, p)), { recursive: true });
      cpSync(join(ROOT, p), join(scratch, p));
    }
  }
  return scratch;
}

test("the table is sound", () => {
  assert.deepEqual(tableProblems(), []);
});

test("every copy is its source's bytes (run `node scripts/copies/module-copies.mjs generate`)", () => {
  assert.deepEqual(staleCopies(), []);
  const r = spawnSync(process.execPath, [SCRIPT, "check"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
});

test("both model proxies carry every proxy module in the table", () => {
  // A group marked `proxies: false` is shared by other packages only.
  for (const grp of GROUPS.filter((x) => !x.source.includes("/test/") && x.proxies !== false)) {
    const files = [grp.source, ...grp.copies];
    const proxies = files.filter((p) => /^interceptors\/(anthropic|openai)-proxy\//.test(p));
    assert.equal(proxies.length, 2, `${grp.name}: both proxies: ${JSON.stringify(files)}`);
  }
});

test("check names a stale or missing copy and exits 1; generate repairs it", () => {
  const scratch = scratchTree();
  try {
    assert.deepEqual(staleCopies(scratch), []);
    const [first, last] = [expectedCopies()[0], expectedCopies().at(-1)];
    writeFileSync(join(scratch, first.path), readFileSync(join(scratch, first.path), "utf8") + "\n// drift\n");
    rmSync(join(scratch, last.path));
    assert.deepEqual(staleCopies(scratch), [first.path, last.path]);

    // The CLI checks its own tree; copy the script into the scratch tree.
    mkdirSync(join(scratch, "scripts", "copies"), { recursive: true });
    cpSync(SCRIPT, join(scratch, "scripts", "copies", "module-copies.mjs"));
    const cli = join(scratch, "scripts", "copies", "module-copies.mjs");
    const r = spawnSync(process.execPath, [cli, "check"], { encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.ok(r.stderr.includes(`${first.path} differs from its source ${first.source}`), r.stderr);
    assert.ok(r.stderr.includes(last.path), r.stderr);

    assert.deepEqual(generate(scratch), [first.path, last.path]);
    assert.deepEqual(staleCopies(scratch), []);
    assert.equal(spawnSync(process.execPath, [cli, "check"], { encoding: "utf8" }).status, 0);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("a change in the source reaches every copy, and nothing else", () => {
  const scratch = scratchTree();
  try {
    const grp = GROUPS.find((x) => x.copies.length > 1);
    writeFileSync(join(scratch, grp.source), readFileSync(join(scratch, grp.source), "utf8") + "\n// changed\n");
    assert.deepEqual(staleCopies(scratch), grp.copies);
    assert.deepEqual(generate(scratch), grp.copies);
    for (const c of grp.copies) assert.ok(readFileSync(join(scratch, c), "utf8").endsWith("// changed\n"));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
