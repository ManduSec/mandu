/**
 * tmp-dir.ts — temp dirs a test file removes when its process exits, passed
 * or failed (docs/design/testing/test-organization.md §5.3: a suite leaves nothing in
 * its TMPDIR; the runner fails one that does). One copy per package.
 */
import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const made = new Set<string>();
let hooked = false;

/** Remove `dir`, also when the test left a read-only directory in it. */
export function removeDir(dir: string): void {
  made.delete(dir);
  try { rmSync(dir, { recursive: true, force: true }); return; } catch { /* below */ }
  const stack = [dir];
  while (stack.length) {
    const p = stack.pop()!;
    try {
      if (!lstatSync(p).isDirectory()) continue;
      chmodSync(p, 0o700);
      for (const x of readdirSync(p)) stack.push(join(p, x));
    } catch { /* gone */ }
  }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* the runner reports it */ }
}

/** `mkdtempSync(join(tmpdir(), prefix))`, removed when the process exits. */
export function tmpDir(prefix: string): string {
  if (!hooked) {
    hooked = true;
    process.once("exit", () => { for (const d of [...made]) removeDir(d); });
  }
  const d = mkdtempSync(join(tmpdir(), prefix));
  made.add(d);
  return d;
}
