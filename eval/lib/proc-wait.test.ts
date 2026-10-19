/**
 * proc-wait.test.ts — the port-file wait the live stack boots its proxy by
 * (port 0 + MANDU_PORT_FILE instead of a picked-then-released port,
 * test-organization.md §8.4). Offline: temp files only.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { waitForPortFile } from "./proc-wait.js";

test("waitForPortFile: returns the port once the daemon writes it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "proc-wait-"));
  try {
    const file = join(dir, "proxy.port");
    setTimeout(() => writeFileSync(file, "43127\n"), 150);
    assert.equal(await waitForPortFile(file, 20), 43127);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("waitForPortFile: null when the file never appears or never holds a port", async () => {
  const dir = mkdtempSync(join(tmpdir(), "proc-wait-"));
  try {
    assert.equal(await waitForPortFile(join(dir, "absent.port"), 3), null);
    const junk = join(dir, "junk.port");
    writeFileSync(junk, "not-a-port");
    assert.equal(await waitForPortFile(junk, 3), null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
