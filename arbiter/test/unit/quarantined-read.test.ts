/**
 * quarantined-read.test — §3.3 rung 2 (Plan 7).
 *
 * Two properties, and the second is the one that makes the first SAFE:
 *
 *   1. `resolve(deep)` — the U-LLM quarantine's resolution path — admits a
 *      `any-model` symbol (the provider is a cleared reader for that
 *      datum) and still REFUSES a `no-model` one (the U-LLM is the
 *      provider; that refusal is the residency claim).
 *
 *   2. A symbol DERIVED from a secret symbol inherits its level SERVER-SIDE.
 *      Without this, admitting model-ok into the quarantine would launder it in
 *      one hop: `inspect_symbol` re-symbolizes the U-LLM's answer with the SOURCE
 *      SYMBOL as origin, and the path catalog cannot see a level in
 *      `$MDU:anymodel_Read[3fa9]` — it looks for filesystem paths. The whole label
 *      would have rested on the client remembering to send it.
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

async function withArbiter(fn: (c: ArbiterClient) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mdu-quarantine-"));
  const socketPath = join(dir, "arbiter.sock");
  const server = new ArbiterServer({
    socketPath,
    dbPath: join(dir, "symbols.sqlite"),
    adminSocketPath: join(dir, "admin.sock"),
    eventDir: join(dir, "events"),
    log: () => {},
    confidentiality: true,
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

const HOME = process.env.HOME ?? "/root";
const CONTRACT = "Acme agrees to pay $4,200,000 on 2026-09-30.";

/** Mint a model-ok symbol the honest way: label a path, then symbolize from it. */
async function mintModelOk(c: ArbiterClient, value = CONTRACT): Promise<string> {
  await c.setPathLabel({ path: join(HOME, "contracts"), confidentiality: "any-model" });
  const r = await c.symbolizeFull({
    tool: "Read", value, field: "content", origin: join(HOME, "contracts", "acme.pdf"),
  });
  assert.equal(r.confidentiality, "any-model");
  return r.symbol;
}

async function mintStrict(c: ArbiterClient, value = "AWS_SECRET_ACCESS_KEY=wJalr"): Promise<string> {
  const r = await c.symbolizeFull({
    tool: "Read", value, field: "content", origin: join(HOME, ".aws", "credentials"),
  });
  assert.equal(r.confidentiality, "no-model");
  return r.symbol;
}

// ── the level split at the quarantine door ───────────────────────────────────

test("rung 2: a model-ok symbol IS admitted to the quarantine, with its level", async () => {
  await withArbiter(async (c) => {
    const sym = await mintModelOk(c);
    const r = await c.resolveFull(sym, { deep: true });
    assert.equal(r.value, CONTRACT, "the U-LLM may read a model-ok datum — that is what the label grants");
    assert.equal(r.confidentiality, "any-model", "and the caller is told what to inherit");
  });
});

test("a strict symbol is STILL refused — the residency claim never relaxes", async () => {
  await withArbiter(async (c) => {
    const sym = await mintStrict(c);
    const r = await c.resolveFull(sym, { deep: true });
    assert.equal(r.value, null, "no vendor model reads a strict secret, including the U-LLM");
  });
});

test("a nested STRICT symbol stays opaque inside an admitted model-ok value", async () => {
  await withArbiter(async (c) => {
    const key = await mintStrict(c);
    // A model-ok contract that quotes a strict credential.
    await c.setPathLabel({ path: join(HOME, "contracts"), confidentiality: "any-model" });
    const doc = await c.symbolizeFull({
      tool: "Read", value: `Deploy with the key ${key} to prod.`, field: "content",
      origin: join(HOME, "contracts", "runbook.md"),
    });

    const r = await c.resolveFull(doc.symbol, { deep: true });
    assert.ok(r.value !== null, "the model-ok wrapper resolves");
    assert.ok(r.value!.includes(key), "the nested STRICT token stays a TOKEN — partial resolution, fail-closed");
    assert.ok(!r.value!.includes("wJalr"), "the strict secret's bytes never reach the quarantine");
  });
});

test("shallow resolve is untouched by the split", async () => {
  await withArbiter(async (c) => {
    const sym = await mintStrict(c);
    // Gated egress paths run desymbolizationDecision FIRST and then resolve
    // shallow; the deep-resolve exclusion is not their gate and must not become
    // one by accident.
    assert.equal(await c.resolve(sym), "AWS_SECRET_ACCESS_KEY=wJalr");
  });
});

// ── the soundness fix: server-side inheritance ───────────────────────────────

test("THE LAUNDERING FIX: a symbol derived from a secret symbol inherits its level — with the client sending NOTHING", async () => {
  await withArbiter(async (c) => {
    const src = await mintModelOk(c);

    // Exactly what inspect_symbol does with the U-LLM's answer: re-symbolize
    // with the SOURCE SYMBOL as origin — and, here, no confidentiality field at
    // all. Before Plan 7 this minted `public` and the secret was laundered.
    const derived = await c.symbolizeFull({
      tool: "inspect_symbol",
      value: "The contract is a $4.2M payment agreement due in Q3.",
      field: "result",
      origin: src,
    });

    assert.equal(
      derived.confidentiality, "any-model",
      "the SUMMARY of a secret is a secret — derived server-side, not on the client's honor",
    );
    assert.ok(derived.symbol.includes("anymodel_"));
  });
});

test("inheritance carries the BINDINGS too — a derived datum is for the same destinations", async () => {
  await withArbiter(async (c) => {
    await c.setPathLabel({
      path: join(HOME, "deals"), confidentiality: "any-model", bindings: ["docs.corp"],
    });
    const src = await c.symbolizeFull({
      tool: "Read", value: "deal terms", field: "content",
      origin: join(HOME, "deals", "acme.pdf"),
    });
    assert.equal(src.confidentiality, "any-model");

    const derived = await c.symbolizeFull({
      tool: "inspect_symbol", value: "a summary", field: "result", origin: src.symbol,
    });
    // Read the derived row back through the quarantine door (it is model-ok, so
    // it is admitted) — which is also how the U-LLM would see it.
    const row = await c.resolveFull(derived.symbol, { deep: true });
    assert.equal(row.confidentiality, "any-model");
    assert.deepEqual(
      row.bindings, ["docs.corp"],
      "the summary of a bound datum is bound to the same destinations",
    );
  });
});

test("inheritance is MONOTONE: a client cannot under-label a derivation of a STRICT symbol", async () => {
  await withArbiter(async (c) => {
    const src = await mintStrict(c);
    const derived = await c.symbolizeFull({
      tool: "inspect_symbol", value: "leaked-ish text", field: "result",
      origin: src,
      confidentiality: "public", // a malicious or buggy client insists
    });
    assert.equal(
      derived.confidentiality, "no-model",
      "max() over {client, catalog, ORIGIN SYMBOL} — the client can only ever RAISE",
    );
  });
});

test("a derivation of a PUBLIC symbol stays public (no over-tainting)", async () => {
  await withArbiter(async (c) => {
    const src = await c.symbolizeFull({
      tool: "Read", value: "ordinary notes", field: "content", origin: join(HOME, "notes.md"),
    });
    const derived = await c.symbolizeFull({
      tool: "inspect_symbol", value: "a summary of notes", field: "result", origin: src.symbol,
    });
    assert.equal(derived.confidentiality, "public");
  });
});
