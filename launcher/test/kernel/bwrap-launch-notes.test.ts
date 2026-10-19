/**
 * bwrap-launch-notes e2e — the per-launch bubblewrap check
 * (src/bwrap-grant.ts `bwrapLaunchNotes`; rootless-confinement-ubuntu-2404.md
 * §12.3) over REAL files and the REAL `bwrap --version`: a copy of this host's
 * bwrap in a temp dir stands in for /usr/lib/mandu/bin/bwrap (the trusted path
 * cannot be moved by any env var, so the test passes the paths in-process).
 * An identical copy is silent; a copy that differs by one byte (a stand-in for
 * a bubblewrap update) is named with both real version strings. Self-SKIPs
 * where this host has no bwrap.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bwrapLaunchNotes, bwrapVersion, realBwrapLaunchDeps } from "../../src/bwrap-grant.js";

const SYS = "/usr/bin/bwrap";
const skip = !existsSync(SYS) || bwrapVersion(SYS) === null ? "no runnable /usr/bin/bwrap on this host" : false;

function rig(): { dir: string; copy: string; aa: string } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-bwrap-notes-"));
  const aa = join(dir, "apparmor.d");
  mkdirSync(aa);
  const copy = join(dir, "bwrap");
  copyFileSync(SYS, copy);
  return { dir, copy, aa };
}

test("an identical copy of the system bwrap: no launch line", { skip }, () => {
  const r = rig();
  try {
    assert.deepEqual(bwrapLaunchNotes(realBwrapLaunchDeps, { copy: r.copy, system: SYS, apparmorDir: r.aa }), []);
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});

test("a copy that differs from the system bwrap: one WARNING naming both real versions", { skip }, () => {
  const r = rig();
  try {
    appendFileSync(r.copy, Buffer.from([0])); // still a runnable ELF, different bytes
    const version = bwrapVersion(SYS)!;
    assert.equal(bwrapVersion(r.copy), version, "the modified copy still runs --version");
    const notes = bwrapLaunchNotes(realBwrapLaunchDeps, { copy: r.copy, system: SYS, apparmorDir: r.aa });
    assert.equal(notes.length, 1);
    assert.match(notes[0]!, /^mandu: WARNING/);
    assert.ok(notes[0]!.includes(`${r.copy}, ${version}`), notes[0]);
    assert.ok(notes[0]!.includes(`${SYS}, ${version}`), notes[0]);
    assert.match(notes[0]!, /same version string, a different build/);
    assert.match(notes[0]!, /fix: mandu setup/);
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});

test("an old Mandu grant file next to Ubuntu's profile: the host-wide WARNING", { skip }, () => {
  const r = rig();
  try {
    writeFileSync(join(r.aa, "bwrap"), "# Mandu: grant\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n");
    writeFileSync(join(r.aa, "bwrap-userns-restrict"), "profile bwrap /usr/bin/bwrap {}\n");
    const notes = bwrapLaunchNotes(realBwrapLaunchDeps, { copy: r.copy, system: SYS, apparmorDir: r.aa });
    assert.equal(notes.length, 1);
    assert.match(notes[0]!, /older Mandu grant is still installed .*switches Ubuntu's user-namespace restriction off/);
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});

test("both old grant files, as a real do-release-upgrade leaves them: the unshare hazard is named too", { skip }, () => {
  const r = rig();
  try {
    writeFileSync(join(r.aa, "bwrap"), "# Mandu: grant\nprofile bwrap /usr/bin/bwrap flags=(unconfined) {\n  userns,\n}\n");
    writeFileSync(join(r.aa, "unshare"), "# Mandu: the same grant for util-linux unshare\nprofile unshare /usr/bin/unshare flags=(unconfined) {\n  userns,\n}\n");
    writeFileSync(join(r.aa, "bwrap-userns-restrict"), "profile bwrap /usr/bin/bwrap {}\n");
    const notes = bwrapLaunchNotes(realBwrapLaunchDeps, { copy: r.copy, system: SYS, apparmorDir: r.aa });
    assert.equal(notes.length, 1);
    assert.match(notes[0]!, /the bwrap one shares the name of Ubuntu's own `bwrap` profile/);
    assert.match(notes[0]!, /the unshare one lets every program on this machine create a user namespace through unshare; fix: mandu setup/);
  } finally { rmSync(r.dir, { recursive: true, force: true }); }
});
