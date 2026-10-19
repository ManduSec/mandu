/**
 * port-file.test — the dashboard publishes its bound port (port-file.ts;
 * runtime-instances.md §8) atomically, and never through a link planted at
 * the temp name or the file's own name (§2, "planted paths", 2026-09-30).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { publishPortFile } from "../../src/port-file.js";

function withDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-portfile-"));
  try {
    fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("publishPortFile writes the port and leaves no temp file", () => {
  withDir((dir) => {
    const f = join(dir, "dashboard-4242.port");
    publishPortFile(f, 45123);
    assert.equal(readFileSync(f, "utf8"), "45123");
    assert.deepEqual(readdirSync(dir), ["dashboard-4242.port"]);
  });
});

test("a link planted at the temp name, or at the file's own name, is replaced, never written through", () => {
  withDir((dir) => {
    const victim = join(dir, "victim.rc");
    writeFileSync(victim, "keep me\n");
    const f = join(dir, "dashboard-4242.port");
    symlinkSync(victim, `${f}.tmp`);
    publishPortFile(f, 45123);
    assert.equal(readFileSync(victim, "utf8"), "keep me\n", "the temp name's link was not followed");
    assert.equal(readFileSync(f, "utf8"), "45123");
    rmSync(f);
    symlinkSync(victim, f);
    publishPortFile(f, 45124);
    assert.equal(readFileSync(victim, "utf8"), "keep me\n", "the rename replaced the link itself");
    assert.ok(!lstatSync(f).isSymbolicLink());
    assert.equal(readFileSync(f, "utf8"), "45124");
  });
});

test("a link RE-planted between the unlink and the write makes it fail (O_EXCL), never follow", () => {
  withDir((dir) => {
    const victim = join(dir, "victim.rc");
    const f = join(dir, "dashboard-4242.port");
    const tmp = `${f}.tmp`;
    const fs = createRequire(import.meta.url)("node:fs") as typeof import("node:fs");
    const realUnlink = fs.unlinkSync;
    let replanted = false;
    fs.unlinkSync = ((p: Parameters<typeof realUnlink>[0]) => {
      try {
        realUnlink(p);
      } finally {
        if (p === tmp && !replanted) { replanted = true; fs.symlinkSync(victim, tmp); }
      }
    }) as typeof realUnlink;
    syncBuiltinESMExports();
    try {
      assert.throws(() => publishPortFile(f, 45123), (e: NodeJS.ErrnoException) => e.code === "EEXIST");
    } finally {
      fs.unlinkSync = realUnlink;
      syncBuiltinESMExports();
    }
    assert.ok(replanted, "the race was staged");
    assert.equal(existsSync(victim), false, "the link's (absent) target was not created");
    assert.equal(existsSync(f), false, "no port published from a refused write");
  });
});
