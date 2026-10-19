/**
 * e2e — plan 11 phase 0 through the REAL arbiter: a `local-model` datum
 * reaches a model only at an endpoint the law declares `local: true`
 * (docs/design/confidentiality/model-endpoints.md §1 D1-D4).
 *
 * The invariant half: the quarantined helper's deep resolve refuses a
 * local-model value with no endpoint, at an unknown one, and at a declared
 * external one, and admits it only at a declared local one; nested symbols
 * expand by their OWN admission; no-model is refused everywhere; the helper's
 * answer inherits local-model (so it reaches the T-LLM only as a token); and
 * rung 3 refuses local-model into the T-LLM's context.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { stateAxes } from "../axes.js";
import { pollDiskApproving } from "../held-disk.js";

stateAxes("secrets"); // this suite states its axes (protection-modes.md §4)

const CONTRACT = "Acme agrees to pay $4,200,000 on 2026-09-30. LOCAL_CANARY_2026";
const KEY = "AWS_SECRET_ACCESS_KEY=wJalrNOMODEL";
const DEAL = "Deal memo: margin 31%. ANY_CANARY";

const LAW: PolicyFileConfig = {
  version: 1,
  models: [
    { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
    { name: "gateway", url: "https://llm.corp.example", local: false },
  ],
  paths: [
    { path: "/h/notes/contract.md", level: "local-model" },
    { path: "/h/notes/key.txt", level: "no-model" },
    { path: "/h/notes/deal.md", level: "any-model" },
    { path: "/h/notes/wrap-any.md", level: "any-model" },
  ],
};

// `human` = the human-plane client (arbiter-human-plane.md): the SHALLOW
// resolve of the gated egress paths returns originals and is refused on data.
async function withLaw(doc: PolicyFileConfig, fn: (c: ArbiterClient, human: ArbiterClient) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-cleared-e2e-"));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyDocument: doc, policyPollMs: 0,
  });
  await server.listen();
  const c = new ArbiterClient(join(dir, "a.sock"));
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  try {
    await c.connect();
    await fn(c, human);
  } finally {
    c.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

async function read(c: ArbiterClient, path: string, value: string) {
  return c.symbolizeFull({ tool: "Read", value, field: "content", origin: path });
}

test("a local-model file mints $MDU:localmodel_; its bytes never ride in the token", async () => {
  await withLaw(LAW, async (c) => {
    const r = await read(c, "/h/notes/contract.md", CONTRACT);
    assert.equal(r.confidentiality, "local-model");
    assert.match(r.symbol, /^\$MDU:localmodel_Read\[[0-9a-f]+\]/);
    assert.ok(!r.symbol.includes("LOCAL_CANARY"));
    assert.deepEqual(await c.pathLevel("/h/notes/contract.md"), { level: "local-model", bindings: [], axis: true, rule: "label:/h/notes/contract.md" });
  });
});

test("deep resolve admits local-model ONLY at a declared local endpoint", async () => {
  await withLaw(LAW, async (c) => {
    const { symbol } = await read(c, "/h/notes/contract.md", CONTRACT);
    for (const [endpoint, why] of [
      [undefined, "no endpoint named: the default helper is external"],
      ["gateway", "a declared endpoint that is not local"],
      ["nope", "an undeclared name is external"],
      ["OLLAMA", "names are exact"],
    ] as const) {
      const r = await c.resolveFull(symbol, { deep: true, ...(endpoint ? { endpoint } : {}) });
      assert.equal(r.value, null, `refused: ${why}`);
    }
    const ok = await c.resolveFull(symbol, { deep: true, endpoint: "ollama" });
    assert.equal(ok.value, CONTRACT, "the user's own model may read it");
    assert.equal(ok.confidentiality, "local-model", "and the caller is told what to inherit");
    assert.equal(ok.location, "local");
  });
});

test("no-model is refused at every endpoint, including a declared local one; any-model is admitted at every endpoint", async () => {
  await withLaw(LAW, async (c) => {
    const key = await read(c, "/h/notes/key.txt", KEY);
    for (const endpoint of [undefined, "gateway", "ollama"]) {
      assert.equal((await c.resolveFull(key.symbol, { deep: true, ...(endpoint ? { endpoint } : {}) })).value, null, String(endpoint));
    }
    const deal = await read(c, "/h/notes/deal.md", DEAL);
    for (const endpoint of [undefined, "gateway", "ollama"]) {
      assert.equal((await c.resolveFull(deal.symbol, { deep: true, ...(endpoint ? { endpoint } : {}) })).value, DEAL, String(endpoint));
    }
  });
});

test("nesting follows admission: a local-model token inside an any-model value expands at the local endpoint only", async () => {
  await withLaw(LAW, async (c) => {
    const inner = await read(c, "/h/notes/contract.md", CONTRACT);
    const key = await read(c, "/h/notes/key.txt", KEY);
    const outer = await read(c, "/h/notes/wrap-any.md", `Summary of ${inner.symbol}; deploy key ${key.symbol}.`);
    assert.equal(outer.confidentiality, "any-model");

    const ext = await c.resolveFull(outer.symbol, { deep: true });
    assert.ok(ext.value!.includes(inner.symbol), "external: the local-model token stays a token");
    assert.ok(!ext.value!.includes("LOCAL_CANARY"));
    assert.ok(ext.value!.includes(key.symbol) && !ext.value!.includes("wJalrNOMODEL"));

    const loc = await c.resolveFull(outer.symbol, { deep: true, endpoint: "ollama" });
    assert.ok(loc.value!.includes("LOCAL_CANARY"), "local: the local-model datum expands");
    assert.ok(loc.value!.includes(key.symbol) && !loc.value!.includes("wJalrNOMODEL"), "no-model stays a token even there");
  });
});

test("the helper's answer inherits local-model server-side, so it reaches the T-LLM only as $MDU:localmodel_", async () => {
  await withLaw(LAW, async (c) => {
    const src = await read(c, "/h/notes/contract.md", CONTRACT);
    const answer = await c.symbolizeFull({ tool: "inspect_symbol", value: "Acme owes 4.2M by Sept 30.", field: "result", origin: src.symbol });
    assert.equal(answer.confidentiality, "local-model");
    assert.match(answer.symbol, /^\$MDU:localmodel_/);
  });
});

test("with NO models declared, local-model is refused at every endpoint name (it behaves as no-model at every model)", async () => {
  await withLaw({ version: 1, paths: [{ path: "/h/notes/contract.md", level: "local-model" }] }, async (c, human) => {
    const { symbol } = await read(c, "/h/notes/contract.md", CONTRACT);
    for (const endpoint of [undefined, "ollama"]) {
      assert.equal((await c.resolveFull(symbol, { deep: true, ...(endpoint ? { endpoint } : {}) })).value, null, String(endpoint));
    }
    assert.deepEqual(await c.modelEndpoints(), []);
    assert.equal(await human.resolve(symbol), CONTRACT, "shallow resolve (the gated egress path, human plane) is unchanged");
  });
});

test("modelEndpoints returns the declared list with defaults applied; rung 3 refuses local-model into context", async () => {
  await withLaw(LAW, async (c) => {
    assert.deepEqual(await c.modelEndpoints(), [
      { name: "ollama", url: "http://127.0.0.1:11434", wire: "openai-chat", model: "llama3.2", local: true },
      { name: "gateway", url: "https://llm.corp.example", wire: "anthropic", local: false },
    ]);
    // TRUSTED data, so the integrity refusal cannot be what answers: the
    // any-model control is allowed, and the local-model datum is refused by
    // the level alone (this session was never bound to a declared local model;
    // the bound case is test/component/session-upstream.test.ts).
    const mint = (path: string, value: string) => c.symbolizeFull({
      tool: "Read", value, field: "content", origin: path, integrity: "trusted", sessionKey: "s-plan11",
    });
    const control = await c.declassifySymbol({ symbol: (await mint("/h/notes/deal.md", DEAL)).symbol, sessionKey: "s-plan11" });
    assert.equal(control.allowed, true, `control: a trusted any-model datum is declassifiable (${control.reason})`);
    const local = await c.declassifySymbol({ symbol: (await mint("/h/notes/contract.md", CONTRACT)).symbol, sessionKey: "s-plan11" });
    assert.equal(local.allowed, false);
    assert.equal(local.requiresApproval, false, "no approval opens it");
    assert.equal(local.value, null, "the bytes never come back from rung 3");
    assert.match(local.reason, /local-model data is readable only by the user's own model/);
  });
});

test("hot reload: resolve(deep, endpoint) refuses the old endpoint name once an edit withdraws local: true, renames or removes the entry", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-cleared-reload-"));
  const file = join(dir, "policy.yaml");
  const yaml = (models: string): string => ["version: 1", models, "paths:", "  - { path: /h/notes/contract.md, level: local-model }", ""].join("\n");
  const OLLAMA = (name: string, local: boolean): string => `models:\n  - { name: ${name}, url: "http://127.0.0.1:11434", wire: openai-chat, local: ${local} }`;
  writeFileSync(file, yaml(OLLAMA("ollama", true)));
  const server = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "symbols.sqlite"), eventDir: join(dir, "events"),
    log: () => {}, confidentiality: true, policyPath: file, policyPollMs: 0,
  });
  await server.listen();
  const c = new ArbiterClient(join(dir, "a.sock"));
  const human = new ArbiterClient(join(dir, "human", "h.sock"));
  let bump = 0;
  // A hand edit, picked up by the store's own mtime/size poll (called
  // directly here so the test does not wait on the 2 s timer).
  const edit = (text: string): void => {
    writeFileSync(file, text);
    const t = new Date(Date.now() + 5_000 + ++bump * 1_000);
    utimesSync(file, t, t);
    // Any change to `models:` relaxes (§3.2), so it is held and approved (§4.6).
    assert.equal(pollDiskApproving(server), true, "the edit was reloaded");
  };
  try {
    await c.connect();
    const { symbol } = await read(c, "/h/notes/contract.md", CONTRACT);
    assert.equal(await c.resolve(symbol, { deep: true, endpoint: "ollama" }), CONTRACT, "admitted before the edit");

    edit(yaml(OLLAMA("ollama", false)));
    assert.deepEqual((await c.modelEndpoints()).map((e) => [e.name, e.local]), [["ollama", false]]);
    assert.equal(await c.resolve(symbol, { deep: true, endpoint: "ollama" }), null, "local: true withdrawn");

    edit(yaml(OLLAMA("mine", true)));
    assert.equal(await c.resolve(symbol, { deep: true, endpoint: "ollama" }), null, "renamed: the old name is undeclared, so external");
    assert.equal(await c.resolve(symbol, { deep: true, endpoint: "mine" }), CONTRACT, "the new name is the law now");

    edit(yaml(""));
    assert.deepEqual(await c.modelEndpoints(), []);
    for (const endpoint of ["mine", "ollama"]) {
      assert.equal(await c.resolve(symbol, { deep: true, endpoint }), null, `removed: ${endpoint} refused`);
    }
    assert.equal(await human.resolve(symbol), CONTRACT, "the shallow (gated egress, human plane) resolve is unaffected");
  } finally {
    c.close();
    human.close();
    await server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
