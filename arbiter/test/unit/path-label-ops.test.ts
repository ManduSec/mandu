/**
 * path-label-ops.test — the labeling ops END TO END through the arbiter (Plan 6).
 *
 * The headline assertion is the one that names the whole plan: with a
 * `any-model` label on a path, `symbolize` on that origin mints a
 * `$MDU:anymodel_*` symbol. Before Plan 6 this was IMPOSSIBLE — the catalog yields
 * only public/strict, so no input to the system could produce the level, and
 * every downstream branch that handles `model-ok` was dead code.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import { stateAxes } from "../axes.js";

stateAxes("injection"); // this suite states its axes (protection-modes.md §4)

async function withArbiter(
  confidentiality: boolean,
  fn: (c: ArbiterClient) => Promise<void>,
): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-label-ops-"));
  const socketPath = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    dbPath: join(dir, "symbols.sqlite"),
    adminSocketPath: join(dir, "admin.sock"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality,
  });
  await server.listen();
  const client = new ArbiterClient(join(dir, "admin.sock"));
  try {
    await fn(client);
  } finally {
    client.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("THE PLAN: a model-ok label makes symbolize mint a `anymodel_` symbol", async () => {
  await withArbiter(true, async (c) => {
    const home = process.env.HOME ?? "/root";
    const contracts = join(home, "contracts");

    // Before the label: an ordinary path is public, so an ordinary symbol.
    const before = await c.symbolizeFull({
      tool: "Read", value: "Q3 revenue was $4.2M", field: "content",
      origin: join(contracts, "q3.pdf"),
    });
    assert.ok(!before.symbol.includes("anymodel_"), `pre-label symbol should be plain, got ${before.symbol}`);

    // The labeling act.
    const set = await c.setPathLabel({ path: contracts, confidentiality: "any-model" });
    assert.equal(set.level, "any-model");
    assert.equal(set.declassifies, false);

    // After: the SAME origin now mints a model-ok symbol. Note the value
    // differs so this is a fresh allocation, not the reuse path.
    const after = await c.symbolizeFull({
      tool: "Read", value: "Q4 revenue was $5.1M", field: "content",
      origin: join(contracts, "q4.pdf"),
    });
    assert.ok(
      after.symbol.includes("anymodel_"),
      `a model-ok label must mint a anymodel_ symbol, got ${after.symbol}`,
    );
    assert.equal(after.confidentiality, "any-model");
  });
});

test("a directory label reaches a file DEEP under it", async () => {
  await withArbiter(true, async (c) => {
    const home = process.env.HOME ?? "/root";
    await c.setPathLabel({ path: join(home, "contracts"), confidentiality: "any-model" });
    const r = await c.symbolizeFull({
      tool: "Read", value: "deep content", field: "content",
      origin: join(home, "contracts", "2026", "q1", "deal.pdf"),
    });
    assert.equal(r.confidentiality, "any-model");
  });
});

test("THE DECLASSIFICATION: a `public` label on a catalog secret is honored AND flagged", async () => {
  await withArbiter(true, async (c) => {
    const home = process.env.HOME ?? "/root";
    const fixture = join(home, "proj", "test", "fixtures", ".env");

    // The catalog's `.env*` shape calls this a credential.
    const pre = await c.symbolizeFull({
      tool: "Read", value: "FAKE_KEY=not-a-real-key", field: "content", origin: fixture,
    });
    assert.equal(pre.confidentiality, "no-model");

    // The human says: it is a fixture.
    const set = await c.setPathLabel({ path: fixture, confidentiality: "public" });
    assert.equal(set.level, "public");
    assert.equal(set.declassifies, true, "weaker than the catalog ⇒ a declassification, and the surface must say so");

    const post = await c.symbolizeFull({
      tool: "Read", value: "FAKE_KEY=still-not-real", field: "content", origin: fixture,
    });
    assert.equal(post.confidentiality, "public");
    assert.ok(!post.symbol.includes("nomodel_"), "no secret marker on a declassified fixture");

    // ...and an unlabeled .env elsewhere is STILL strict. The override is
    // per-path, not a global weakening of the shape rule.
    const other = await c.symbolizeFull({
      tool: "Read", value: "REAL_KEY=abc", field: "content", origin: join(home, "proj", ".env"),
    });
    assert.equal(other.confidentiality, "no-model");
  });
});

test("bindings on a label reach the symbol row without any client forwarding them", async () => {
  await withArbiter(true, async (c) => {
    const home = process.env.HOME ?? "/root";
    await c.setPathLabel({
      path: join(home, "deals"),
      confidentiality: "any-model",
      bindings: ["docs.corp.example"],
    });
    // The client sends NO bindings — a standing release rule must not depend on
    // a caller remembering to forward it. `integrity: trusted` so the row lands
    // in the registry view the standing surface renders.
    const r = await c.symbolizeFull({
      tool: "Read", value: "the deal terms", field: "content",
      origin: join(home, "deals", "acme.pdf"),
      integrity: "trusted",
    });
    assert.equal(r.confidentiality, "any-model");

    const state = await c.confidentialityState();
    const entry = state.secrets.find((s) => s.symbol === r.symbol);
    assert.deepEqual(entry?.bindings, ["docs.corp.example"], "the binding reached the symbol row server-side");
  });
});

test("a model-ok label + a strict catalog secret in one command ⇒ strict wins", async () => {
  await withArbiter(true, async (c) => {
    const home = process.env.HOME ?? "/root";
    await c.setPathLabel({ path: join(home, "deals"), confidentiality: "any-model" });
    const r = await c.symbolizeFull({
      tool: "Bash", value: "output", field: "content",
      origin: `cat ${join(home, "deals", "a.pdf")} ${join(home, ".aws", "credentials")}`,
    });
    assert.equal(r.confidentiality, "no-model", "the strictest datum in the flow sets the level");
  });
});

test("the standing surface lists every label, and flags the declassifying ones", async () => {
  await withArbiter(true, async (c) => {
    const home = process.env.HOME ?? "/root";
    await c.setPathLabel({ path: join(home, "contracts"), confidentiality: "any-model" });
    await c.setPathLabel({ path: join(home, "proj/test/fixtures/.env"), confidentiality: "public" });

    const state = await c.confidentialityState();
    assert.equal(state.enabled, true);
    assert.equal(state.labels.length, 2);

    const modelOk = state.labels.find((l) => l.level === "any-model");
    assert.ok(modelOk, "the model-ok surface must be visible — it is a standing grant of model readability");
    assert.equal(modelOk?.declassifies, false);

    const declass = state.labels.find((l) => l.declassifies);
    assert.ok(declass, "a declassification must be visible — it is a standing release rule");
    assert.equal(declass?.level, "public");
  });
});

test("labels round-trip and remove", async () => {
  await withArbiter(true, async (c) => {
    const home = process.env.HOME ?? "/root";
    const p = join(home, "contracts");
    await c.setPathLabel({ path: p, confidentiality: "no-model", bindings: ["api.example"] });

    const labels = await c.pathLabels();
    assert.equal(labels.length, 1);
    assert.equal(labels[0].path, p);
    assert.equal(labels[0].level, "no-model");
    assert.deepEqual(labels[0].bindings, ["api.example"]);
    assert.equal(labels[0].recursive, true);

    assert.equal(await c.removePathLabel(p), true);
    assert.equal((await c.pathLabels()).length, 0);
    assert.equal(await c.removePathLabel(p), false, "removing a missing label is not an error");
  });
});

test("an invalid labeling act is REJECTED by the op, not coerced", async () => {
  await withArbiter(true, async (c) => {
    await assert.rejects(
      () => c.setPathLabel({ path: "/tmp/x", confidentiality: "moddel-ok" }),
      /invalid label/,
      "a typo'd level must not silently become no-model — say so",
    );
    await assert.rejects(
      () => c.setPathLabel({ path: "relative/path", confidentiality: "public" }),
      /invalid label/,
      "a relative path has no stable identity — it cannot be labeled",
    );
    assert.equal((await c.pathLabels()).length, 0);
  });
});

test("AXIS OFF: labels are stored but NEVER consulted — the wire is integrity-only", async () => {
  // §11: "Labels minted while ON are retained but not consulted while OFF" —
  // the switch disables ENFORCEMENT. And OFF must be byte-identical to the
  // integrity-only system: no marker, no level field.
  await withArbiter(false, async (c) => {
    const home = process.env.HOME ?? "/root";
    const p = join(home, "contracts");
    await c.setPathLabel({ path: p, confidentiality: "any-model" });

    const r = await c.symbolizeFull({
      tool: "Read", value: "the contract", field: "content", origin: join(p, "q3.pdf"),
    });
    assert.ok(!r.symbol.includes("anymodel_"), "no wire marker while the axis is OFF");
    assert.equal(r.confidentiality, undefined, "no level field on the OFF wire");

    const state = await c.confidentialityState();
    assert.equal(state.enabled, false);
    assert.equal(state.secrets.length, 0);
  });
});
