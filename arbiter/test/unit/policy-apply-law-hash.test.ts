/**
 * policy-apply-law-hash.test — the whole-file apply names the law it was
 * built from (policy-surface.md §8.4.6 "A whole-file apply names the law it
 * was built from", after !1973), over a REAL ArbiterServer and its sockets:
 *
 *   - `policyDocument` answers the law's version (`lawHash`) on every
 *     channel, the same value for the same law;
 *   - `applyPolicyDocument` without `lawHash` is refused, nothing written:
 *     no apply lands on a newer law unchecked;
 *   - one built before an agent's tightening (the data socket's
 *     `policyPropose`) is refused as stale, naming the lock, and the lock
 *     stays the law and in the file;
 *   - one built from the law in force is written.
 *
 * The store-level cases (a hand edit, a held edit, an unknown version) are
 * in policy-disk-hold.test.ts. No privilege.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4); the check reads none

const INITIAL = "# the team's policy\nversion: 1\npaths:\n  - { path: /home/u/repo/.env, level: no-model }   # prod\n";

async function up() {
  const dir = mkdtempSync(join(tmpdir(), "mandu-law-hash-"));
  const policyPath = join(dir, "policy.yaml");
  writeFileSync(policyPath, INITIAL);
  const server = new ArbiterServer({
    socketPath: join(dir, "arbiter.sock"),
    adminSocketPath: join(dir, "admin.sock"),
    dbPath: join(dir, "symbols.db"),
    eventDir: join(dir, "events"),
    log: () => {},
    policyPath,
    policyPollMs: 0,
  });
  await server.listen();
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  const data = new ArbiterClient(join(dir, "arbiter.sock"));
  await admin.connect();
  await data.connect();
  return {
    policyPath, admin, data,
    close: async () => {
      admin.close();
      data.close();
      await server.close();
      rmSync(dir, { recursive: true, force: true });
      resetCurrentPolicyForTests("claude-code");
    },
  };
}

const locked = (doc: unknown): string[] => ((doc as PolicyFileConfig | null)?.paths ?? []).map((p) => p.path).sort();

test("policyDocument answers the law's version on every channel; an apply without it is refused, nothing written", async () => {
  const h = await up();
  try {
    const a = await h.admin.policyDocument();
    const d = await h.data.policyDocument();
    assert.match(a.lawHash ?? "", /^[0-9a-f]{32}$/);
    assert.equal(d.lawHash, a.lawHash, "the same law reads the same version on the data socket");
    const raw = h.admin as unknown as { request(op: string, body: unknown): Promise<unknown> };
    const doc = { ...(a.inForce as PolicyFileConfig), paths: [...locked(a.inForce).map((path) => ({ path, level: "no-model" })), { path: "/home/u/k", level: "no-model" }] };
    for (const body of [{ document: doc }, { document: doc, lawHash: "" }, { document: doc, lawHash: 7 }]) {
      await assert.rejects(raw.request("applyPolicyDocument", body), /needs lawHash/, JSON.stringify(body.lawHash));
    }
    assert.equal(readFileSync(h.policyPath, "utf8"), INITIAL, "nothing was written");
  } finally {
    await h.close();
  }
});

test("a document read before an agent's tightening is refused as stale, naming it; built again from the law in force it is written", async () => {
  const h = await up();
  try {
    const read = await h.admin.policyDocument();
    const built = (from: unknown): PolicyFileConfig => {
      const law = structuredClone((from ?? {}) as PolicyFileConfig);
      return { ...law, paths: [...(law.paths ?? []), { path: "/home/u/k", level: "no-model" }] };
    };
    // The confined agent locks a file in between (a tightening applies at once).
    const t = await h.data.policyPropose({ edits: [{ op: "lock-path", path: "/home/u/repo/id_rsa", level: "no-model" }], sessionKey: "s1" });
    assert.equal(t.applied, true);
    const bytes = readFileSync(h.policyPath, "utf8");
    await assert.rejects(
      h.admin.applyPolicyDocument(built(read.inForce), "dashboard lists", read.lawHash!),
      (e: Error) => /changed since this document was read/.test(e.message) && e.message.includes("paths /home/u/repo/id_rsa") && /nothing was written/.test(e.message),
    );
    assert.equal(readFileSync(h.policyPath, "utf8"), bytes, "nothing was written");
    const now = await h.admin.policyDocument();
    assert.ok(locked(now.inForce).includes("/home/u/repo/id_rsa"), "the agent's lock is still the law");
    assert.ok(!locked(now.inForce).includes("/home/u/k"));
    assert.notEqual(now.lawHash, read.lawHash);

    await h.admin.applyPolicyDocument(built(now.inForce), "dashboard lists", now.lawHash!);
    const after = await h.admin.policyDocument();
    assert.deepEqual(locked(after.inForce), ["/home/u/k", "/home/u/repo/.env", "/home/u/repo/id_rsa"]);
    const text = readFileSync(h.policyPath, "utf8");
    assert.deepEqual(locked(yaml.load(text)), ["/home/u/k", "/home/u/repo/.env", "/home/u/repo/id_rsa"], "the file has both");
    assert.ok(text.includes("# the team's policy") && text.includes("# prod"), "and the person's comments");
  } finally {
    await h.close();
  }
});
