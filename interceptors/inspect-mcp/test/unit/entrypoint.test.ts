/**
 * entrypoint.test — the realpath-aware entry guard of server-main.ts
 * (src/entrypoint.ts, a copy of launcher/src/entrypoint.ts).
 *
 * Node hands the main module its REAL path as import.meta.url while argv[1]
 * keeps the typed spelling; on darwin /tmp and /var are symlinks, so the old
 * literal comparison made a server started under a symlinked spelling exit 0
 * before serving anything. Pinned against a real symlink on disk; the spawned
 * server is test/component/entry-symlink.test.ts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { isEntrypoint } from "../../src/entrypoint.js";

test("isEntrypoint: the literal path and a symlinked directory name the entry; another module, a missing path or no argv do not", () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-inspect-entry-"));
  try {
    const real = join(root, "real");
    mkdirSync(real);
    const mod = join(real, "server-main.mjs");
    writeFileSync(mod, "");
    writeFileSync(join(real, "other.mjs"), "");
    symlinkSync(real, join(root, "link"));
    const url = pathToFileURL(mod).href;
    assert.equal(isEntrypoint(url, mod), true);
    assert.equal(isEntrypoint(url, join(root, "link", "server-main.mjs")), true, "through a symlinked directory (darwin /tmp → /private/tmp)");
    assert.equal(isEntrypoint(url, join(real, "other.mjs")), false);
    assert.equal(isEntrypoint(url, join(root, "missing.mjs")), false);
    assert.equal(isEntrypoint(url, undefined), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
