/**
 * store-seed e2e — a store a REAL ArbiterServer wrote and closed, seeded
 * read-only into a fresh one (db/store-seed.ts), and a second ArbiterServer
 * started on the copy: its `whyPath`, `whyHost` and `testFlow` answers are
 * the first one's, byte for byte (the remembered Always allow decides the
 * send, the hand edit waiting in Approvals is named and stays held, the law
 * in force is the content approved before it). `mandu why` with no Mandu
 * running asks such a server (comparisons.md §3.2); the CLI side is proven
 * in tests/stack/why-offline-store.test.ts.
 *
 * And the copy holds no original: the registered value is in neither the
 * copy's bytes nor any answer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { seedStoreFrom } from "../../db/store-seed.js";
import { resetCurrentPolicyForTests } from "../../policy/compiled-policy.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // confidentiality ON: levels, bindings and the egress gate exist on this axis

const VALUE = "sk_live_SEEDCOMP_0123456789";
const law = (env: string, bound: boolean): string => `version: 1\npaths:\n  - path: ${env}\n    level: no-model\n${bound ? "    bindings: [api.stripe.com]\n" : ""}`;

async function waitFor<T>(what: string, probe: () => Promise<T | undefined>): Promise<T> {
  for (let i = 0; i < 300; i++) {
    const v = await probe();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${what}`);
}

async function start(dir: string, db: string, policyPath: string) {
  mkdirSync(join(dir, "human"), { recursive: true, mode: 0o700 });
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), adminSocketPath: join(dir, "admin.sock"),
    dbPath: db, eventDir: join(dir, "events"), policyPath, policyPollMs: 30, confidentiality: true, integrity: false, log: () => {},
  });
  await server.listen();
  const data = new ArbiterClient(join(dir, "a.sock")); await data.connect();
  const human = new ArbiterClient(join(dir, "human", "h.sock")); await human.connect();
  const admin = new ArbiterClient(join(dir, "admin.sock")); await admin.connect();
  const answers = async (env: string) => JSON.stringify({
    path: await human.whyPath(env, join(dir, "..", "home")),
    host: await data.whyHost("collector.example"),
    stripe: await data.whyHost("api.stripe.com"),
    flow: await data.testFlow({ source: { tool: "Read", origin: env }, destination: "collector.example" }),
    proposals: (await admin.policyProposals("pending")).proposals.map((p) => p.id),
  });
  return { data, human, admin, answers, close: async () => { data.close(); human.close(); admin.close(); await server.close(); } };
}

test("a server on the seeded copy answers why as the server that wrote the store did, and the copy holds no original", async () => {
  const root = mkdtempSync(join(tmpdir(), "mdu-seed-e2e-"));
  try {
    const home = join(root, "home");
    mkdirSync(join(home, "proj"), { recursive: true });
    const env = join(home, "proj", ".env");
    writeFileSync(env, `STRIPE_KEY=${VALUE}\n`);
    const policy = join(root, "policy.yaml");
    writeFileSync(policy, law(env, false));
    const store = join(root, "resident", "mandu.db");
    mkdirSync(join(root, "resident"), { recursive: true });

    const a = await start(join(root, "resident"), store, policy);
    let live: string;
    try {
      const twin = (await a.data.registerSecret({ path: env })).twin ?? "";
      const field = /\$MDU:[A-Za-z_]+\[[0-9a-f]+\]\.STRIPE_KEY/.exec(twin)?.[0];
      assert.ok(field);
      const ask = await a.human.desymbolizationDecision({ symbol: field, boundary: "network", destination: "collector.example", sessionKey: "s-seed" });
      await a.admin.resolveEgressApproval((ask as { approvalId?: string }).approvalId!, true, "always");
      writeFileSync(policy, law(env, true)); // a relaxing hand edit: held
      await waitFor("the held card", async () => ((await a.admin.policyProposals("pending")).proposals.length ? true : undefined));
      live = await a.answers(env);
    } finally {
      await a.close();
    }
    assert.match(live, /"stage":"verdict"/, "the remembered answer decided the send");
    assert.match(live, /"pending":\[\{"id":"pp-/, "the held edit is named");

    // What `mandu why`'s temporary arbiter does: a copy of the policy file
    // and a store seeded read-only from the resident one.
    const tmp = join(root, "tmp");
    mkdirSync(tmp);
    const policyCopy = join(tmp, "policy.yaml");
    copyFileSync(policy, policyCopy);
    const seeded = join(tmp, "state", "mandu.db");
    const r = seedStoreFrom({ from: store, to: seeded, policy: { from: policy, to: policyCopy } });
    assert.ok(r.ok, JSON.stringify(r));
    assert.ok(!readFileSync(seeded).includes(VALUE), "no original in the copy");

    resetCurrentPolicyForTests("claude-code");
    const b = await start(tmp, seeded, policyCopy);
    try {
      const offline = await b.answers(env);
      assert.equal(offline, live, "the answers the resident arbiter gave");
      assert.doesNotMatch(offline, new RegExp(VALUE), "never a value");
    } finally {
      await b.close();
    }
    assert.equal(readFileSync(policy, "utf8"), law(env, true), "the person's policy.yaml is untouched");
  } finally {
    resetCurrentPolicyForTests("claude-code");
    rmSync(root, { recursive: true, force: true });
  }
});
