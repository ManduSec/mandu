/**
 * tmp-dir.ts — temp dirs a test file removes when it ends.
 *
 * Each `tmpDir(prefix)` is a fresh `mkdtempSync(join(tmpdir(), prefix))` that
 * is removed when this process exits, whether its tests passed or failed (the
 * test runner gives every test file its own process). Without it the suites
 * left tens of thousands of inodes per run in a shared `/tmp`; the runner now
 * fails a suite that leaves anything in its TMPDIR
 * (docs/design/testing/test-organization.md §8.5).
 *
 * A child process a test spawns must be stopped by the test (or its `after`
 * hook) before the process exits, or it may write into a removed dir.
 */
import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const made = new Set<string>();
let hooked = false;

/** Remove `dir`, also a tree a test made read-only (each directory gets its
 *  owner's rwx back first). Never throws. */
export function removeTmpDir(dir: string): void {
  made.delete(dir);
  try {
    rmSync(dir, { recursive: true, force: true });
    return;
  } catch { /* below */ }
  const stack = [dir];
  while (stack.length) {
    const p = stack.pop()!;
    try {
      if (!lstatSync(p).isDirectory()) continue;
      chmodSync(p, 0o700);
      for (const x of readdirSync(p)) stack.push(join(p, x));
    } catch { /* gone, or not ours */ }
  }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* the runner reports what is left */ }
}

/** A fresh temp dir under `tmpdir()`, removed when this process exits. */
export function tmpDir(prefix: string): string {
  if (!hooked) {
    hooked = true;
    process.once("exit", () => { for (const d of [...made]) removeTmpDir(d); });
  }
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.add(dir);
  return dir;
}
