/**
 * remote-mounts.test — "refuse raw if visible" at launch and in doctor
 * (confidentiality plan 13 §4.9, 2026-10-07; src/remote-mounts.ts):
 *   - the classification is the guard's: every case of the table both test
 *     suites read (net-supervisor src/visible_mounts.json) classifies here
 *     as the guard's `counts_for_lookups` does, with the same destination;
 *   - trust entries match by mount point (trailing / ignored, `~` expanded)
 *     and type (case-insensitive);
 *   - the launch notes name each untrusted mount, how to trust it and how to
 *     bind it, and list the trusted ones; nothing visible, no note;
 *   - applyTrustLookups writes the guard policy file's `trustLookups` only
 *     where the launch already has a guard policy file (no secret file, no
 *     raw open to withhold);
 *   - readTrustLookups: the arbiter's answer shape-checked, null when it
 *     cannot be asked;
 *   - doctor's rows: none visible (✓), untrusted (with the fix), trusted.
 *
 * No privilege. The trust only ever relaxes the confidentiality axis's
 * guard; the suite states `secrets`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  applyTrustLookups, countsForLookups, expandTrust, isTrusted, mountDestination, readTrustLookups, remoteMountNotes, visibleRemoteMounts,
} from "../../src/remote-mounts.js";
import { remoteMountRows } from "../../src/doctor.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const HERE = dirname(fileURLToPath(import.meta.url));
const TABLE = resolve(HERE, "../../../interceptors/net-supervisor/src/visible_mounts.json");

test("every case of the shared table classifies as the guard classifies it", () => {
  const { cases } = JSON.parse(readFileSync(TABLE, "utf8")) as { cases: { line: string; counts: boolean; dest?: string }[] };
  assert.ok(cases.length >= 20);
  for (const c of cases) {
    const v = visibleRemoteMounts(c.line);
    assert.equal(v.length > 0, c.counts, c.line);
    if (c.dest !== undefined) assert.equal(mountDestination(v[0]!), c.dest, c.line);
  }
});

test("countsForLookups: 9p by its transport, automounts but systemd's local ones", () => {
  assert.equal(countsForLookups("9p", "rw,trans=tcp", "/m"), true);
  assert.equal(countsForLookups("9p", "rw", "/m"), true);
  assert.equal(countsForLookups("9p", "rw,trans=virtio", "/m"), false);
  assert.equal(countsForLookups("9p", "trans=virtio,trans=tcp", "/m"), true, "the last value counts");
  assert.equal(countsForLookups("autofs", "fd=7", "/net"), true);
  assert.equal(countsForLookups("autofs", "fd=7", "/boot/efi/"), false);
  assert.equal(countsForLookups("ext4", "rw", "/"), false);
});

const NFS = "98 22 0:51 / /home rw,relatime - nfs4 nas:/home rw,vers=4.2\n";
const SSHFS = "120 22 0:60 / /h/u/remote rw - fuse.sshfs u@host:/srv rw\n";
const ROOT = "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n";

test("trust entries: by point (trailing / and ~ expanded) and type (case-insensitive)", () => {
  const [home, remote] = visibleRemoteMounts(ROOT + NFS + SSHFS);
  assert.ok(home && remote);
  const trust = expandTrust([{ mount: "/home/", type: "NFS4" }, { mount: "~/remote", type: "fuse.sshfs" }], "/h/u");
  assert.deepEqual(trust, [{ mount: "/home", type: "NFS4" }, { mount: "/h/u/remote", type: "fuse.sshfs" }]);
  assert.equal(isTrusted(home, trust), true);
  assert.equal(isTrusted(remote, trust), true);
  assert.equal(isTrusted(home, [{ mount: "/home", type: "nfs" }]), false, "another type is another mount");
  assert.deepEqual(expandTrust([{ mount: "~/x", type: "nfs" }], undefined), [], "no HOME: a ~ entry trusts nothing");
});

test("the launch notes: each untrusted mount with how to trust or bind it; the trusted ones; nothing visible, nothing said", () => {
  const visible = visibleRemoteMounts(ROOT + NFS + SSHFS);
  const notes = remoteMountNotes(visible, [{ mount: "/h/u/remote", type: "fuse.sshfs" }]);
  assert.equal(notes.length, 2);
  assert.match(notes[0]!, /network or FUSE mount visible to the AI's programs: \/home \(nfs4 from nas:\/home\)\./);
  assert.match(notes[0]!, /gets the placeholder copy instead of the real file/);
  assert.match(notes[0]!, /remote_mounts: trust_lookups: \[\{ mount: \/home, type: nfs4 \}\]/);
  assert.match(notes[0]!, /mount:nfs4:nas:\/home/);
  assert.match(notes[0]!, /Writes there stay refused unless bound/);
  assert.match(notes[1]!, /trusted for lookups \(policy\.yaml remote_mounts\): \/h\/u\/remote \(fuse\.sshfs\)/);
  assert.deepEqual(remoteMountNotes(visibleRemoteMounts(ROOT), []), []);
  assert.match(remoteMountNotes(visible, [])[0]!, /mounts visible/, "two: the plural");
});

test("applyTrustLookups: written into an existing guard policy file only, ~ expanded", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-remote-mounts-"));
  try {
    const deps = { scopeRunDir: dir, agentExe: "/bin/agent", session: "s", home: "/h/u" };
    const none: Record<string, string> = {};
    assert.equal(applyTrustLookups([{ mount: "/home", type: "nfs4" }], none, deps), false, "no guard policy file: nothing to withhold, none made");
    assert.equal(none["MANDU_NET_GUARD_SECRETS"], undefined);
    const policy = join(dir, "secret-policy.json");
    writeFileSync(policy, JSON.stringify({ agentExe: "/bin/agent", secrets: [{ path: "/h/u/.env", twin: "/t", level: "no-model" }] }));
    const env: Record<string, string> = { MANDU_NET_GUARD_SECRETS: policy };
    assert.equal(applyTrustLookups([], env, deps), false, "nothing trusted: the file is left as it is");
    assert.equal(applyTrustLookups([{ mount: "~/remote/", type: "fuse.sshfs" }, { mount: "/home", type: "nfs4" }], env, deps), true);
    const written = JSON.parse(readFileSync(policy, "utf8")) as { trustLookups: unknown; secrets: unknown[] };
    assert.deepEqual(written.trustLookups, [{ mount: "/h/u/remote", type: "fuse.sshfs" }, { mount: "/home", type: "nfs4" }]);
    assert.equal(written.secrets.length, 1, "merged, not replaced");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("readTrustLookups: the arbiter's answer shape-checked; null when it cannot be asked", async () => {
  assert.deepEqual(await readTrustLookups("/s", async (_s, op) => {
    assert.equal(op, "guardSettings");
    return { trustLookups: [{ mount: "/home", type: "nfs4" }, { mount: 1 }, null] };
  }), [{ mount: "/home", type: "nfs4" }]);
  assert.deepEqual(await readTrustLookups("/s", async () => ({ unixAllow: [] })), [], "an older arbiter: none");
  assert.equal(await readTrustLookups("/s", async () => { throw new Error("ECONNREFUSED"); }), null);
});

test("doctor's rows: none visible, untrusted with the fix, trusted, and policy.yaml unread", () => {
  assert.deepEqual(remoteMountRows(undefined), []);
  assert.match(remoteMountRows({ visible: [], trusted: [] })[0]!, /✓ no network or FUSE mount is visible/);
  const visible = visibleRemoteMounts(ROOT + NFS + SSHFS);
  const rows = remoteMountRows({ visible, trusted: [{ mount: "/h/u/remote", type: "fuse.sshfs" }] });
  assert.match(rows[0]!, /\/home \(nfs4 from nas:\/home\) is a network or FUSE mount: while it is visible, a program you named as a reader gets the placeholder/);
  assert.match(rows[1]!, /remote_mounts: trust_lookups: \[\{ mount: \/home, type: nfs4 \}\], or bind the secret to mount:nfs4:nas:\/home/);
  assert.match(rows[2]!, /\/h\/u\/remote \(fuse\.sshfs from u@host:\/srv\): trusted for lookups in policy\.yaml/);
  const unread = remoteMountRows({ visible, trusted: null });
  assert.match(unread[unread.length - 1]!, /policy\.yaml remote_mounts: not read/);
});
