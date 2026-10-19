/**
 * ca-dir.test — the egress CA's key dir is this uid's private directory or
 * nothing (src/ca.ts ensureCa / caDirProblem; on-disk-layout.md §1 records this
 * fix). The standalone default sits in the shared
 * TMPDIR, so a dir another account made first, or a link it planted, must
 * never hold (or hand the proxy) the key every certificate is signed with.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readdirSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";

import { caDirProblem, defaultCaDir, ensureCa, opensslAvailable } from "../../src/ca.js";
import { tmpDir } from "../tmp-dir.js";

test("defaultCaDir is a per-uid name", () => {
  const uid = process.getuid?.() ?? 0;
  assert.equal(defaultCaDir("/tmp"), `/tmp/mandu-egress-mitm-ca-${uid}`);
});

test("caDirProblem: a private dir of this uid passes; a link, a file and a shared mode do not", () => {
  const d = tmpDir("mandu-ca-dir-");
  try {
    const own = join(d, "own");
    mkdirSync(own, { mode: 0o700 });
    chmodSync(own, 0o700);
    assert.equal(caDirProblem(own), null);
    chmodSync(own, 0o755);
    assert.match(caDirProblem(own) ?? "", /is shared/);
    symlinkSync(own, join(d, "link"));
    assert.match(caDirProblem(join(d, "link")) ?? "", /is a symlink/);
    assert.match(caDirProblem(join(d, "absent")) ?? "", /cannot be checked/);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("ensureCa refuses a planted link and mints nothing through it; an own dir with a loose mode is tightened and used", { skip: opensslAvailable() ? false : "openssl is not installed" }, () => {
  const d = tmpDir("mandu-ca-squat-");
  try {
    const theirs = join(d, "theirs");
    mkdirSync(theirs);
    const ca = join(d, "ca");
    symlinkSync(theirs, ca);
    assert.throws(() => ensureCa(ca), /is a symlink; refusing to keep a CA key there/);
    assert.deepEqual(readdirSync(theirs), [], "no key written into the other account's dir");
    rmSync(ca);
    mkdirSync(ca);
    chmodSync(ca, 0o777);
    const m = ensureCa(ca);
    assert.equal(caDirProblem(ca), null, "our own dir is made private before the key goes in");
    assert.ok(existsSync(m.keyPath));
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});
