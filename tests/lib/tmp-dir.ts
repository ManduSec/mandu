/**
 * tmp-dir.ts — temp dirs a test process removes when it ends, pass or fail
 * (docs/design/testing/test-organization.md §8.5: a suite leaves nothing in its
 * TMPDIR; run-suites fails one that does).
 *
 * `tmpDir(prefix)` is `mkdtempSync(join(tmpdir(), prefix))` registered for
 * removal on the process's "exit" (each node:test file runs in a process of
 * its own, so that is the end of the file). A test that stops a child using
 * the dir does so in its own finally, before the exit; `removeTmp` removes one
 * early. A runner's timeout kill skips the hook: run-suites removes the
 * suite's whole TMPDIR then.
 */
import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const made = new Set<string>();
let hooked = false;

/** Remove a tree, also one a test made read-only (each dir gets u+rwx first). */
export function removeTmp(dir: string): void {
  made.delete(dir);
  try {
    rmSync(dir, { recursive: true, force: true });
    return;
  } catch {
    /* below */
  }
  const stack = [dir];
  while (stack.length) {
    const p = stack.pop()!;
    try {
      if (!lstatSync(p).isDirectory()) continue;
      chmodSync(p, 0o700);
      for (const x of readdirSync(p)) stack.push(join(p, x));
    } catch {
      /* gone, or not ours */
    }
  }
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best effort: run-suites reports what is left */
  }
}

/** Remove a path this process is done with, when it ends (not now). */
export function removeAtExit(path: string): string {
  if (!hooked) {
    hooked = true;
    process.once("exit", () => {
      for (const d of [...made]) removeTmp(d);
    });
  }
  made.add(path);
  return path;
}

/** A fresh temp dir under TMPDIR, removed when this process exits. */
export function tmpDir(prefix: string): string {
  return removeAtExit(mkdtempSync(join(tmpdir(), prefix)));
}
