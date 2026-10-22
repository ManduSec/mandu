/**
 * Unit: locked-memory (a security fix, 2026-10-21; confidentiality.md
 * §7.2a "A version once locked stays locked"): the record's exact shape,
 * the union written atomically and read again before each write, only the
 * paths protected now applied, and anything unreadable read as empty (the
 * walk's own answer). The end-to-end attacks: test/component/locked-memory.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { lockedMemoryFile, parseLockedMemory, readLockedMemory, rememberedVersions, rememberLocked } from "../../src/locked-memory.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the memory serves the confidentiality axis's object twins

const A = "a".repeat(40);
const B = "b".repeat(40);
const C = "c".repeat(64);

test("the record: exactly its shape, its store's; anything else reads as empty", () => {
  const ok = JSON.stringify({ v: 1, commonDir: "/r/.git", paths: { ".env": [A], "deploy/key": [B, C] } });
  assert.deepEqual([...parseLockedMemory(ok, "/r/.git")!].map(([p, s]) => [p, [...s]]), [[".env", [A]], ["deploy/key", [B, C]]]);
  assert.equal(parseLockedMemory(ok, "/other/.git"), null, "another store's record");
  for (const bad of [
    "{torn",
    JSON.stringify({ v: 2, commonDir: "/r/.git", paths: {} }),
    JSON.stringify({ v: 1, commonDir: "/r/.git", paths: { "/abs": [A] } }),
    JSON.stringify({ v: 1, commonDir: "/r/.git", paths: { ".env": ["not-a-name"] } }),
    JSON.stringify({ v: 1, commonDir: "/r/.git", paths: [] }),
  ]) assert.equal(parseLockedMemory(bad, "/r/.git"), null, bad);
});

test("remember: the union, written atomically, read again before the write; only paths protected now are applied", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-memory-unit-"));
  try {
    const file = lockedMemoryFile(dir, "/r/.git");
    assert.match(file, /\/locked-memory\/[0-9a-f]{32}\.json$/);
    rememberLocked(file, "/r/.git", [[A, ".env"]]);
    rememberLocked(file, "/r/.git", [[B, ".env"], [C, "deploy/key"], ["junk", ".env"], [A, "/abs"]]);
    const mem = readLockedMemory(file, "/r/.git");
    assert.deepEqual([...mem.get(".env")!].sort(), [A, B], "both launches' versions kept; junk dropped");
    assert.deepEqual(rememberedVersions(mem, (p) => p === ".env"), [A, B], "only the protected path's versions");
    assert.deepEqual(rememberedVersions(mem, () => false), []);
    assert.deepEqual(readdirSync(dirname(file)), [file.split("/").at(-1)], "no temp file left");
    // Unreadable: a link, a garbled file, an oversized one: empty, and the
    // next write starts again from what the walk found.
    const link = lockedMemoryFile(dir, "/link/.git");
    mkdirSync(dirname(link), { recursive: true });
    symlinkSync(file, link);
    assert.equal(readLockedMemory(link, "/link/.git").size, 0, "a symlink is not followed");
    writeFileSync(file, "{garbled");
    assert.equal(readLockedMemory(file, "/r/.git").size, 0);
    assert.equal(readLockedMemory(join(dir, "absent.json"), "/r/.git").size, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
