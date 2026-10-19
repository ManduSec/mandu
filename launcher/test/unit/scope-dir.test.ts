/**
 * scope-dir.test — a launch makes its own scope run dir and never adopts one
 * someone else prepared (scope-dir.ts; runtime-instances.md §2).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createScopeDir } from "../../src/scope-dir.js";
import { stateAxes } from "../axes.js";

stateAxes("off"); // filesystem only: no arbiter, no axis in play

function withBase(fn: (base: string) => void): void {
  const root = mkdtempSync(join(tmpdir(), "mandu-scopedir-"));
  try {
    fn(join(root, "mandu"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("a minted scope: the base and the dir are made, the dir 0700", () => {
  withBase((base) => {
    const dir = join(base, "1790000000-4242");
    createScopeDir({ scopeRunDir: dir, scopeIdGenerated: true });
    assert.ok(statSync(dir).isDirectory());
    assert.equal(statSync(dir).mode & 0o777, 0o700);
  });
});

test("a minted scope that already exists is REFUSED and left as it was: a real dir, a link to someone's folder, a file", () => {
  withBase((base) => {
    const victim = join(base, "..", "victim");
    mkdirSync(victim, { recursive: true });
    writeFileSync(join(victim, "notes.txt"), "keep me\n");
    mkdirSync(base, { recursive: true });
    // Made in advance with a link planted inside: launch.log would land in ~/.zshrc.
    const planted = join(base, "1790000000-1");
    mkdirSync(planted);
    symlinkSync(join(victim, "notes.txt"), join(planted, "launch.log"));
    symlinkSync(victim, join(base, "1790000000-2"));
    writeFileSync(join(base, "1790000000-3"), "");
    for (const id of ["1790000000-1", "1790000000-2", "1790000000-3"]) {
      assert.throws(
        () => createScopeDir({ scopeRunDir: join(base, id), scopeIdGenerated: true }),
        /refusing to launch: the session folder .* already exists, and this launch did not make it/,
        id,
      );
    }
    assert.deepEqual(readdirSync(planted), ["launch.log"], "nothing was written into it");
    assert.deepEqual(readdirSync(victim), ["notes.txt"]);
  });
});

test("the same process making the same minted dir twice (an in-process caller of main(), the tests) adopts its own", () => {
  withBase((base) => {
    const dir = join(base, "1790000001-4242");
    createScopeDir({ scopeRunDir: dir, scopeIdGenerated: true });
    assert.doesNotThrow(() => createScopeDir({ scopeRunDir: dir, scopeIdGenerated: true }));
  });
});

test("a named scope: an existing real dir of this uid is the caller's to reuse; a link or a file is refused; a foreign owner is refused", () => {
  withBase((base) => {
    mkdirSync(join(base, "named"), { recursive: true });
    assert.doesNotThrow(() => createScopeDir({ scopeRunDir: join(base, "named"), scopeIdGenerated: false }));
    symlinkSync(join(base, "named"), join(base, "linked"));
    assert.throws(() => createScopeDir({ scopeRunDir: join(base, "linked"), scopeIdGenerated: false }), /is not a real directory \(a link or a file\)/);
    writeFileSync(join(base, "file"), "");
    assert.throws(() => createScopeDir({ scopeRunDir: join(base, "file"), scopeIdGenerated: false }), /is not a real directory/);
    const uid = process.getuid?.() ?? 1000;
    assert.throws(
      () => createScopeDir({ scopeRunDir: join(base, "named"), scopeIdGenerated: false }, { uid: uid + 1 }),
      /is owned by uid \d+, not \d+/,
    );
    // A fresh named one is made like a minted one.
    createScopeDir({ scopeRunDir: join(base, "fresh"), scopeIdGenerated: false });
    assert.equal(statSync(join(base, "fresh")).mode & 0o777, 0o700);
    assert.ok(!existsSync(join(base, "named", "launch.log")));
  });
});
