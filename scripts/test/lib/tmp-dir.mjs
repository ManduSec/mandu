// tmp-dir.mjs — temp dirs a test file removes when it ends
// (docs/design/testing/test-organization.md §8.5). Each is made under os.tmpdir()
// (the suite's own TMPDIR under run-suites) and removed when the test process
// exits, whether its tests passed or failed; run-suites fails a suite that
// leaves anything in its TMPDIR. A test that scopes a dir itself may still
// remove it early (removeDir, in a finally or t.after).

import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const made = new Set();
let hooked = false;

/** Remove a tree, also one a test made read-only (each directory gets its
 *  owner's rwx back first). Never throws. */
export function removeDir(dir) {
  made.delete(dir);
  try { rmSync(dir, { recursive: true, force: true }); return; } catch { /* below */ }
  const stack = [dir];
  while (stack.length) {
    const p = stack.pop();
    try {
      if (!lstatSync(p).isDirectory()) continue;
      chmodSync(p, 0o700);
      for (const x of readdirSync(p)) stack.push(join(p, x));
    } catch { /* gone, or not ours */ }
  }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* reported by run-suites */ }
}

/** mkdtempSync(join(tmpdir(), prefix)), removed when this process exits. */
export function tmpDir(prefix) {
  if (!hooked) {
    hooked = true;
    process.once("exit", () => { for (const d of [...made]) removeDir(d); });
  }
  const dir = mkdtempSync(join(tmpdir(), prefix));
  made.add(dir);
  return dir;
}
