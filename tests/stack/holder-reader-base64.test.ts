/**
 * holder-reader-base64.test — `workingBase64` (tests/lib/holder-reader.ts),
 * the decoder the launcher suites name by absolute path on the reader's pipe
 * (https-proxy-taint, tainted-egress).
 *
 * A host can shadow coreutils with a `base64` that does not run (a dev
 * host's /usr/local/bin/base64 was a dead pip entry point, 2026-10-04): the
 * pick skips it for the next one that decodes, and says null when none does
 * so the suite SKIPs with a reason instead of failing on host plumbing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { base64Decodes, workingBase64 } from "../lib/holder-reader.js";

const REAL = workingBase64();

function bin(dir: string, body: string): string {
  mkdirSync(dir, { recursive: true });
  const p = join(dir, "base64");
  writeFileSync(p, `#!/bin/sh\n${body}\n`);
  chmodSync(p, 0o755);
  return p;
}

test("workingBase64: a dead `base64` first on PATH is passed over for the next one that decodes", { skip: REAL === null ? "no base64 decodes on this host" : false }, () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-b64-"));
  try {
    const dead = bin(join(tmp, "dead"), "echo 'ModuleNotFoundError: No module named codext' >&2; exit 1");
    const good = bin(join(tmp, "good"), `exec ${REAL} "$@"`);
    assert.equal(base64Decodes(dead), false);
    assert.equal(base64Decodes(good), true);
    assert.equal(workingBase64(`${join(tmp, "dead")}:${join(tmp, "good")}`, []), good);
    // The fallbacks come after PATH: a PATH holding only the dead one still finds the host's.
    const viaFallback = workingBase64(join(tmp, "dead"));
    assert.ok(viaFallback !== null && viaFallback !== dead, `fell back to ${viaFallback}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("workingBase64: null when no candidate decodes (a wrong decoding is not a decoder)", () => {
  const tmp = mkdtempSync(join(tmpdir(), "mdu-b64-"));
  try {
    bin(join(tmp, "dead"), "exit 1");
    bin(join(tmp, "liar"), "cat");
    assert.equal(workingBase64(`${join(tmp, "dead")}:${join(tmp, "liar")}:relative/dir`, []), null);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
