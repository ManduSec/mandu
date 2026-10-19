/**
 * Parity and e2e — policy.yaml `remote_mounts.trust_lookups` from the law to
 * the guard's policy file (confidentiality plan 13 §4.9, "refuse raw if
 * visible", 2026-10-07), over the PRODUCTION wiring: a REAL ArbiterServer
 * whose policy.yaml trusts two mounts, the launcher's own reads of it
 * (`readGuardSettings` and doctor's `readTrustLookups`, both over
 * `ndjsonCall` as run.ts and doctor call them), and `applyTrustLookups`
 * writing the guard policy file the secret setup made:
 *
 *   - both launcher reads answer the arbiter's compiled entries (trailing /
 *     trimmed, a repeat once); a relaxing disk edit adding a third is HELD
 *     and neither read sees it until a human approves;
 *   - the guard policy file gets `trustLookups` with `~` expanded, in the
 *     shape the guard parses (`visible_mounts::TrustLookup`, its unit test
 *     `the_policy_file_spelling_parses`); the secrets it held stay;
 *   - an arbiter that cannot be asked: the launch trusts nothing (tighter)
 *     and doctor says it could not read the key.
 *
 * The kernel oracle (a reader gets the twin while an untrusted, unbound
 * mount is visible; the real file when trusted, bound or with none) is
 * net-supervisor `local_exits_integration.rs` (V), in the kernel lane.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { readGuardSettings } from "../../launcher/src/guard-policy-file.js";
import { applyTrustLookups, readTrustLookups } from "../../launcher/src/remote-mounts.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // the trust relaxes the confidentiality axis's guard only

const LAW = [
  "version: 1",
  "remote_mounts:",
  "  trust_lookups:",
  "    - { mount: /home/, type: nfs4 }",
  "    - { mount: ~/remote, type: fuse.sshfs }",
  "    - { mount: /home, type: NFS4 }",
  "",
].join("\n");

test("remote_mounts.trust_lookups reaches the guard's policy file through the real arbiter and the launcher's reads", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-trust-lookups-"));
  const file = join(dir, "policy.yaml");
  writeFileSync(file, LAW);
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath: file, policyPollMs: 25,
  });
  await server.listen();
  const sock = join(dir, "a.sock");
  try {
    const logs: string[] = [];
    const g = await readGuardSettings(sock, (m) => logs.push(m));
    assert.deepEqual(logs, []);
    const want = [{ mount: "/home", type: "nfs4" }, { mount: "~/remote", type: "fuse.sshfs" }];
    assert.deepEqual(g.trustLookups, want, "the launch's read: compiled, a repeat by point and type once");
    assert.deepEqual(await readTrustLookups(sock), want, "doctor's read: the same answer");

    // A relaxing hand edit (a third mount trusted) is held: neither read sees it.
    writeFileSync(file, LAW.replace("    - { mount: /home, type: NFS4 }\n", "    - { mount: /mnt/smb, type: cifs }\n"));
    const t = new Date(Date.now() + 5_000);
    utimesSync(file, t, t);
    await new Promise((r) => setTimeout(r, 400));
    assert.deepEqual((await readGuardSettings(sock, () => {})).trustLookups, want, "THE RELAXATION applied without a human");
    assert.deepEqual(await readTrustLookups(sock), want);
    // The arbiter is reading the file: a tightening edit (one trust
    // dropped) applies at once.
    writeFileSync(file, LAW.replace("    - { mount: ~/remote, type: fuse.sshfs }\n", ""));
    const t2 = new Date(Date.now() + 10_000);
    utimesSync(file, t2, t2);
    const deadline = Date.now() + 5_000;
    while ((await readTrustLookups(sock))?.length !== 1 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 25));
    assert.deepEqual(await readTrustLookups(sock), [want[0]], "a tightening edit applies at once");

    // The guard policy file the secret setup wrote gets the entries the
    // launch read (`g`), ~ expanded.
    const policy = join(dir, "secret-policy.json");
    writeFileSync(policy, JSON.stringify({ agentExe: "/bin/agent", secrets: [{ path: "/h/u/.env", twin: "/t/.env", level: "no-model" }] }));
    const env: Record<string, string> = { MANDU_NET_GUARD_SECRETS: policy };
    assert.equal(applyTrustLookups(g.trustLookups, env, { scopeRunDir: dir, agentExe: "/bin/agent", session: "s", home: "/h/u" }), true);
    const written = JSON.parse(readFileSync(policy, "utf8")) as { trustLookups: { mount: string; type: string }[]; secrets: unknown[] };
    assert.deepEqual(written.trustLookups, [{ mount: "/home", type: "nfs4" }, { mount: "/h/u/remote", type: "fuse.sshfs" }]);
    assert.equal(written.secrets.length, 1);
  } finally {
    await server.close();
  }

  // The arbiter gone: the launch trusts nothing, doctor says it could not ask.
  const gone = await readGuardSettings(sock, () => {});
  assert.deepEqual(gone.trustLookups, []);
  assert.equal(await readTrustLookups(sock), null);
  rmSync(dir, { recursive: true, force: true });
});
