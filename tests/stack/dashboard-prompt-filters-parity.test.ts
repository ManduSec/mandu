/**
 * dashboard-prompt-filters-parity — the dashboard's Prompt filters panel over
 * a REAL ArbiterServer through the PRODUCTION wiring (`makeApprovalsArbiter`,
 * no mock; CONTRIBUTING.md arbiter-client pattern: the mock proves the package,
 * only the parity test proves the wiring). Confidentiality plan 15 §8.1.
 *
 * Proves: the adapter's `promptFilters` (a data-socket read) is answered by
 * the real op; its `filterPromptDryRun` reaches the real `filterPrompt` on the
 * HUMAN socket with `dryRun: true` and is served there (on the data socket the
 * arbiter refuses a dry run, which this test also shows, so a wiring that
 * slid the bench onto the data socket would fail here); a registered key
 * comes back as its own symbol, `postgres` passes in human text and is
 * masked in harness text, and the dry run mints nothing. The exceptions:
 * the data-socket `promptFilters` lists them with no pattern,
 * `promptExceptions` is refused there, and the adapter reads the patterns
 * on the human plane (plan 15 §13.7 item 4). The policy reads: on the data
 * socket `policyDocument`, `policyProposals` and `policyChanges` carry the
 * placeholder in place of every pattern, and the production adapter reads
 * them on the human plane, so the dashboard shows the real ones.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../arbiter/ipc/server.js";
import { ArbiterClient } from "../../arbiter/ipc/client.js";
import { makeApprovalsArbiter } from "../../dashboard/src/arbiter-adapter.js";
import { stateAxes } from "../lib/axes.js";
import { humanSockIn } from "../lib/human-plane.js";

stateAxes("secrets"); // the confidentiality axis the prompt filter serves; integrity off

const KEY = "sk-live-DashParity7Hq2Zx9Lw4Rt";

test("the panel's adapter over the REAL arbiter: filters on data, the dry run on the human plane (secrets axes)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-pf-dash-parity-"));
  const socketPath = join(tmp, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSockIn(tmp), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false,
  });
  await server.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const adapters = await makeApprovalsArbiter(socketPath, () => undefined);
  try {
    const reg = await data.registerEnvSecrets({ vars: [{ name: "STRIPE_API_KEY", value: KEY }, { name: "DB_PASSWORD", value: "postgres" }] });
    const keySym = reg.vars[0]!.symbol!;
    assert.match(keySym, /^\$MDU:/);
    const pf = adapters!.policyDoc!;
    assert.ok(pf.promptFilters && pf.filterPromptDryRun, "the production adapter exposes both ops");

    const filters = await pf.promptFilters!();
    assert.equal(filters.filters[0]!.id, "registered-value");
    assert.equal(filters.enforcing, true);
    const before = filters.registeredValues;

    const human = await pf.filterPromptDryRun!({ agent: "dashboard", segments: [{ id: "bench", origin: "human", text: `use ${KEY} as postgres` }] });
    assert.equal(human.dryRun, true);
    assert.equal(human.segments[0]!.text, `use ${keySym} as postgres`, "the key as its own symbol; postgres passes in human text");
    const harness = await pf.filterPromptDryRun!({ agent: "dashboard", segments: [{ id: "bench", origin: "harness", text: "DB_PASSWORD=postgres" }] });
    assert.ok(!harness.segments[0]!.text!.includes("postgres"), "postgres is masked in harness text");
    assert.equal((await pf.promptFilters!()).registeredValues, before, "a dry run mints nothing");

    // The plane the dry run must ride: the data socket refuses it.
    await assert.rejects(
      () => data.filterPrompt({ agent: "dashboard", dryRun: true, segments: [{ id: "b", origin: "human", text: KEY }] }),
      /human-plane/,
    );
  } finally {
    adapters?.close();
    data.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the exceptions' patterns ride the human plane: the data answer lists them bare, the adapter puts them back from promptExceptions (plan 15 §13.7 item 4; secrets axes)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-pf-exc-parity-"));
  const socketPath = join(tmp, "arbiter.sock");
  const policyPath = join(tmp, "policy.yaml");
  const WORDS = "*@my-own-private-words.example";
  writeFileSync(policyPath, `version: 1\nprompt_filters:\n  exceptions:\n    - { category: secret.shape, match: '${WORDS}' }\n`);
  const server = new ArbiterServer({
    socketPath, humanSocketPath: humanSockIn(tmp), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0,
    promptPackDir: join(tmp, "packs"), adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(tmp, "keys"),
  });
  await server.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const adapters = await makeApprovalsArbiter(socketPath, () => undefined);
  try {
    const bare = await data.promptFilters();
    assert.deepEqual(bare.exceptions, [{ category: "secret.shape", setBy: "you", inForce: true }]);
    assert.ok(!JSON.stringify(bare).includes("my-own-private-words"), "no pattern on the data socket");
    await assert.rejects(() => data.promptExceptions(), /human-plane/);
    const viaAdapter = await adapters!.policyDoc!.promptFilters!();
    assert.deepEqual(viaAdapter.exceptions, [{ category: "secret.shape", match: WORDS, setBy: "you", inForce: true }], "the production wiring reads the patterns on the human plane");
  } finally {
    adapters?.close();
    data.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("the policy reads over the production wiring: the data socket answers with the placeholder, the adapter reads the patterns on the human plane (plan 15 §13.7 item 4; secrets axes)", async () => {
  const tmp = mkdtempSync(join(tmpdir(), "mandu-pf-doc-parity-"));
  const socketPath = join(tmp, "arbiter.sock");
  const adminSock = join(tmp, "admin.sock");
  const policyPath = join(tmp, "policy.yaml");
  const WORDS = "*@my-own-private-words.example";
  const ADDED = "ACME-2*";
  writeFileSync(policyPath, `version: 1\nprompt_filters:\n  exceptions:\n    - { category: secret.shape, match: '${WORDS}' }\n`);
  const server = new ArbiterServer({
    socketPath, adminSocketPath: adminSock, humanSocketPath: humanSockIn(tmp), dbPath: join(tmp, "symbols.sqlite"), eventDir: join(tmp, "events"),
    log: () => {}, confidentiality: true, integrity: false, policyPath, policyPollMs: 0,
    promptPackDir: join(tmp, "packs"), adminPromptPackDir: null, adminPolicyDir: null, packDir: null, packKeysDir: join(tmp, "keys"),
  });
  await server.listen();
  const data = new ArbiterClient(socketPath);
  await data.connect();
  const adapters = await makeApprovalsArbiter(socketPath, () => ({ socketPath: adminSock }));
  try {
    const doc = adapters!.policyDoc!;
    // Settings' write path: proposed and approved on the admin channel.
    const filed = await doc.policyPropose!({ edits: [{ op: "add-prompt-exception", category: "secret.shape", match: ADDED }], requestedBy: "human:settings" });
    assert.ok("proposalId" in filed && filed.proposalId, JSON.stringify(filed));
    const approved = await doc.resolvePolicyProposal!(String(filed.proposalId), "approved", "human:settings");
    assert.ok(approved.changeId);

    const reads = {
      policyDocument: [await data.policyDocument(), await doc.policyDocument()],
      policyProposals: [await data.policyProposals("approved"), await doc.policyProposals!("approved")],
      policyChanges: [await data.policyChanges(10), await doc.policyChanges!(10)],
    } as const;
    for (const [op, [onData, viaAdapter]] of Object.entries(reads)) {
      const d = JSON.stringify(onData);
      for (const p of [WORDS, ADDED]) assert.ok(!d.includes(p), `${op} on the data socket carries '${p}'`);
      assert.ok(d.includes("<pattern hidden"), `${op} on the data socket carries the placeholder`);
      assert.ok(JSON.stringify(viaAdapter).includes(ADDED), `${op} through the production adapter shows the real pattern`);
    }
    const shown = reads.policyDocument[1] as { onDisk: { text: string } };
    assert.ok(shown.onDisk.text.includes(WORDS) && shown.onDisk.text.includes(ADDED), "the dashboard reads the file as written, the patterns in it");
  } finally {
    adapters?.close();
    data.close();
    await server.close();
    rmSync(tmp, { recursive: true, force: true });
  }
});
