/**
 * entrypoint.test — the realpath-aware CLI entry guard (src/entrypoint.ts).
 *
 * Node hands the main module its REAL path as import.meta.url while argv[1]
 * keeps the typed spelling; on darwin /tmp and /var are symlinks, so the old
 * literal comparison made `node /tmp/…/dist/mandu.mjs` exit 0 with no output.
 * Pinned here against a real symlink on disk (portable: Linux too).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { isEntrypoint } from "../../src/entrypoint.js";

test("isEntrypoint: the literal path, a symlinked directory and a symlinked file all name the entry; anything else does not", () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-entry-"));
  try {
    const real = join(root, "real");
    mkdirSync(real);
    const mod = join(real, "mandu.mjs");
    writeFileSync(mod, "");
    writeFileSync(join(real, "other.mjs"), "");
    symlinkSync(real, join(root, "link-dir"));
    symlinkSync(mod, join(root, "link-file.mjs"));
    const url = pathToFileURL(mod).href;

    assert.equal(isEntrypoint(url, mod), true, "the literal spelling");
    assert.equal(isEntrypoint(url, join(root, "link-dir", "mandu.mjs")), true, "through a symlinked directory (darwin /tmp → /private/tmp)");
    assert.equal(isEntrypoint(url, join(root, "link-file.mjs")), true, "through a symlink to the file");
    assert.equal(isEntrypoint(url, relative(process.cwd(), join(root, "link-dir", "mandu.mjs"))), true, "a relative argv resolves against the cwd");

    assert.equal(isEntrypoint(url, join(real, "other.mjs")), false, "another module (a test runner, a wrapper)");
    assert.equal(isEntrypoint(url, join(root, "missing.mjs")), false, "an unresolvable argv is not the entry");
    assert.equal(isEntrypoint(url, undefined), false, "no argv[1] (node -e, the REPL)");
    assert.equal(isEntrypoint(url, ""), false);
    assert.equal(isEntrypoint("data:text/javascript,0", mod), false, "a non-file module URL");
    // The literal comparison needs no file on disk, exactly as before.
    assert.equal(isEntrypoint(pathToFileURL(join(root, "gone.mjs")).href, join(root, "gone.mjs")), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
