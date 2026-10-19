/**
 * policy-stale-apply e2e — a whole-file apply built from a law that moved
 * since it was read is refused as stale, and the change that landed in
 * between is never undone (policy-surface.md §8.4.6 "A whole-file apply
 * names the law it was built from", what !1973 left).
 *
 * Across the real components: a REAL ArbiterServer (file-backed law), the
 * confined agent's data socket for its own tightening (`policyPropose`), the
 * dashboard's production wiring (`makeApprovalsArbiter`: the policy
 * document surface over the admin channel) and the public route handler
 * (`postPolicyDocument`, mounted on a plain HTTP server):
 *
 *   1. the dashboard reads the law and its version (`lawHash`);
 *   2. the agent locks `id_rsa` (a tightening, in force at once);
 *   3. the document built from the read is refused as stale over the wiring
 *      (naming the lock) and over the route (409, `stale: true`); a POST
 *      naming no law is 400; nothing is written;
 *   4. THE INVARIANT: the lock is still the law and in policy.yaml (the
 *      agent's view of `id_rsa` stays masked), and no answer carries the
 *      secret;
 *   5. built again from a fresh read, the apply is written, the lock kept.
 *
 * Secrets axes (confidentiality ON, integrity OFF), stated below.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { resetCurrentPolicyForTests } from "../../arbiter/policy/compiled-policy.js";
import type { PolicyFileConfig } from "../../arbiter/policy/load-policy.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { postPolicyDocument } from "../../dashboard/src/server/policy-doc-routes.js";
import { randomSecretBody } from "../../arbiter/test/helpers/random-secret.js";
import { stateAxes } from "../lib/axes.js";

stateAxes("secrets"); // confidentiality ON, integrity OFF: the server pins them below

// Assembled at run time: no key-shaped literal in this file.
const KEY_BODY = randomSecretBody(32);

const dirs: string[] = [];
after(() => {
  resetCurrentPolicyForTests("claude-code");
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test("§8.4.6 [secrets]: a whole-file apply read before the agent's lock is refused as stale over the wiring and the route; the lock is never undone", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-stale-apply-"));
  dirs.push(dir);
  const ws = join(dir, "ws");
  mkdirSync(ws, { recursive: true });
  const env = join(ws, ".env");
  const key = join(ws, "id_rsa");
  writeFileSync(env, "PORT=8080\n");
  writeFileSync(key, `-----KEY-----\n${KEY_BODY}\n`);
  const policy = join(dir, "policy.yaml");
  writeFileSync(policy, `# the team's policy\nversion: 1\npaths:\n  - path: ${env}   # prod\n    level: no-model\n`);
  const dataSock = join(dir, "a.sock");
  const adminSock = join(dir, "admin.sock");
  const arbiter = new ArbiterServer({
    socketPath: dataSock, adminSocketPath: adminSock,
    dbPath: join(dir, "mandu.db"), eventDir: join(dir, "events"),
    policyPath: policy, policyPollMs: 30, confidentiality: true, integrity: false, log: () => {},
  });
  await arbiter.listen();
  const data = new ArbiterClient(dataSock);
  await data.connect();
  const wired = await makeApprovalsArbiter(dataSock, () => ({ socketPath: adminSock }));
  assert.ok(wired?.policyDoc, "the dashboard's wiring has the policy document surface");
  const docs = wired.policyDoc;
  const route = createServer((req, res) => { void postPolicyDocument(docs, req, res); });
  await new Promise<void>((r) => route.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(route.address() as AddressInfo).port}/`;
  const answers: string[] = [];
  const post = async (body: unknown) => {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const t = await r.text();
    answers.push(t);
    return { status: r.status, body: JSON.parse(t) as { error?: string; stale?: boolean } };
  };
  const lawLocks = async (): Promise<string[]> => (((await data.policyDocument()).inForce as PolicyFileConfig | null)?.paths ?? []).map((p) => p.path);
  /** The locked paths policy.yaml names (each entry is a `path:` line). */
  const fileLocks = (): string[] => [...readFileSync(policy, "utf8").matchAll(/path: ("?)(\S+?)\1(?:\s|$)/g)].map((m) => m[2]!);
  const withList = (doc: unknown): PolicyFileConfig => ({ ...(structuredClone(doc ?? {}) as PolicyFileConfig), lists: { mine: ["api.example.com"] } });

  try {
    // 1. The read.
    const read = await docs.policyDocument();
    assert.match(read.lawHash ?? "", /^[0-9a-f]{32}$/);

    // 2. The agent's lock lands.
    const t = await data.policyPropose({ edits: [{ op: "lock-path", path: key, level: "no-model" }], sessionKey: "agent-1" });
    assert.equal(t.applied, true, JSON.stringify(t));
    const bytes = readFileSync(policy, "utf8");

    // 3. The stale apply, over the wiring and over the route.
    await assert.rejects(
      docs.applyPolicyDocument(withList(read.inForce), "dashboard lists", read.lawHash!),
      (e: Error) => /changed since this document was read/.test(e.message) && e.message.includes(`paths ${key}`),
    );
    const r = await post({ document: withList(read.inForce), lawHash: read.lawHash, requestedBy: "dashboard lists" });
    assert.equal(r.status, 409, JSON.stringify(r.body));
    assert.equal(r.body.stale, true);
    const unnamed = await post({ document: withList(read.inForce), requestedBy: "dashboard lists" });
    assert.equal(unnamed.status, 400, "a document that names no law");
    assert.equal(readFileSync(policy, "utf8"), bytes, "nothing was written");

    // 4. The invariant: the lock is still the law and in the file.
    assert.ok((await lawLocks()).includes(key), "the agent's lock is the law");
    assert.ok(fileLocks().includes(key), "and in policy.yaml");
    const level = (await data.pathLevels([key])).levels[0];
    assert.equal(level?.level, "no-model", JSON.stringify(level));

    // 5. Built again from a fresh read: written, the lock kept.
    const fresh = await docs.policyDocument();
    const ok = await post({ document: withList(fresh.inForce), lawHash: fresh.lawHash, requestedBy: "dashboard lists" });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.ok((await lawLocks()).includes(key) && fileLocks().includes(key), "the lock stays");
    assert.deepEqual(((await data.policyDocument()).inForce as PolicyFileConfig).lists, { mine: ["api.example.com"] });
    assert.match(readFileSync(policy, "utf8"), /api\.example\.com/);
    assert.match(readFileSync(policy, "utf8"), /# the team's policy/);

    for (const a of answers) assert.equal(a.includes(KEY_BODY.slice(0, 12)), false, "no answer carries the key");
  } finally {
    await new Promise<void>((r) => route.close(() => r()));
    wired.close();
    data.close();
    await arbiter.close();
  }
});
