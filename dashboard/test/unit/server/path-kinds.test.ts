/**
 * path-kinds.test — which rule paths are files on disk, the look the panel,
 * the by-who card and the Secrets labels take so a rule reaching everything
 * inside a file is worded as that file (dashboard.md §4.25f *A rule on a file
 * reads as a file*). Mandu-new.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { filePaths } from "../../../src/server/path-kinds.js";

test("filePaths: a file and a link to one are files; a folder, a link to one, a missing path, a pattern (even one a file is named after) and a relative path are not", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-path-kinds-"));
  try {
    const file = join(tmp, "deploy.token");
    const dir = join(tmp, "secrets");
    writeFileSync(file, "x\n");
    // A pattern's rule is never one file, even when a file bears its name.
    writeFileSync(join(tmp, "*.token"), "x\n");
    mkdirSync(dir);
    symlinkSync(file, join(tmp, "to-file"));
    symlinkSync(dir, join(tmp, "to-dir"));
    const got = await filePaths([
      file, dir, join(tmp, "to-file"), join(tmp, "to-dir"), join(tmp, "missing"),
      join(tmp, "*.token"), "deploy.token", file,
    ]);
    assert.deepEqual([...got].sort(), [file, join(tmp, "to-file")].sort());
    assert.equal((await filePaths([])).size, 0);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("filePaths: a look that does not answer in time (a hung mount) lists nothing for that path, so its rule keeps the words it says", async () => {
  let answerLate: (() => void) | undefined;
  const look = (p: string) => p === "/hung/deploy.token"
    ? new Promise<{ isDirectory(): boolean }>((resolve) => { answerLate = () => resolve({ isDirectory: () => false }); })
    : Promise.resolve({ isDirectory: () => false });
  const started = Date.now();
  const got = await filePaths(["/hung/deploy.token", "/w/deploy.token"], { timeoutMs: 30, look });
  assert.ok(Date.now() - started < 2_000, "the answer does not wait for the hung look");
  assert.deepEqual([...got], ["/w/deploy.token"], "the look that answered is kept");
  // What answers later changes nothing already returned.
  answerLate!();
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual([...got], ["/w/deploy.token"]);
});
