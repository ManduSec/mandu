/**
 * registeredFileSymbols — the placeholders a real send of a registered file
 * carries (secret-registry/registry.ts; policy-surface.md §4 "Test a flow",
 * tour 1): the structured twin's field symbols, or the whole-file symbol;
 * every active registration; nothing for another file, a proxy-minted row of
 * the file, or an obsoleted row.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { allocateSymbol, loadSymbolMap, obsoleteSymbol } from "../../symbol-table/symbol-table.js";
import { registerSecret, registeredFileSymbols } from "../../secret-registry/registry.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the registry is the confidentiality axis's

function fixture(): { dir: string; dbPath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-rfs-"));
  return { dir, dbPath: join(dir, "symbols.db"), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("a structured twin's field symbols; a whole-file twin's base symbol; nothing for an unregistered file", () => {
  const { dir, dbPath, cleanup } = fixture();
  try {
    const map = loadSymbolMap(dbPath);
    const env = join(dir, ".env");
    writeFileSync(env, "PORT=3000\nSTRIPE_KEY=sk_live_RFS_aaaaaaaaaaaaaaaa\nGITHUB_TOKEN=ghp_RFSbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n");
    const r = registerSecret(map, { path: env }, dbPath);
    assert.equal(r.fields, 2);
    const got = registeredFileSymbols(map, env);
    assert.deepEqual(got.map((g) => g.symbol).sort(), [`${r.symbol}.GITHUB_TOKEN`, `${r.symbol}.STRIPE_KEY`].sort());
    assert.ok(got.every((g) => g.level === "no-model"));
    for (const g of got) assert.ok(r.twin!.includes(g.symbol), "each is a placeholder the twin carries");

    // A whole-file twin (no known shape): the base symbol.
    const key = join(dir, "id_rsa");
    writeFileSync(key, "-----BEGIN OPENSSH PRIVATE KEY-----\nRFSkeymaterial\n-----END OPENSSH PRIVATE KEY-----\n");
    const k = registerSecret(map, { path: key, resolveLabel: (p) => (p === key ? { level: "no-model", bindings: [], via: key } : null) }, dbPath);
    assert.ok(k.symbol, k.reason);
    assert.equal(k.twin, undefined, "no structure: the whole-file twin");
    assert.deepEqual(registeredFileSymbols(map, key), [{ symbol: k.symbol, level: "no-model" }]);

    assert.deepEqual(registeredFileSymbols(map, join(dir, "other.env")), []);
    assert.deepEqual(registeredFileSymbols(map, env + "x"), [], "exact origin only");
  } finally {
    cleanup();
  }
});

test("every active registration counts; an obsoleted row and a proxy-minted row of the file do not", () => {
  const { dir, dbPath, cleanup } = fixture();
  try {
    const map = loadSymbolMap(dbPath);
    const env = join(dir, ".env");
    writeFileSync(env, "STRIPE_KEY=sk_live_RFS_old_cccccccccccc\n");
    const a = registerSecret(map, { path: env }, dbPath);
    writeFileSync(env, "STRIPE_KEY=sk_live_RFS_new_dddddddddddd\n");
    const b = registerSecret(map, { path: env }, dbPath);
    assert.notEqual(a.symbol, b.symbol);
    assert.deepEqual(
      registeredFileSymbols(map, env).map((g) => g.symbol).sort(),
      [`${a.symbol}.STRIPE_KEY`, `${b.symbol}.STRIPE_KEY`].sort(),
      "both registrations: a session launched before the change carries the old one",
    );

    // A proxy's Read result of the file (a call id, untrusted) is no twin placeholder.
    allocateSymbol(map, { tool: "Read", field: "content", value: "x", origin: env, callId: "toolu_1", confidentiality: "no-model" });
    assert.equal(registeredFileSymbols(map, env).length, 2);

    obsoleteSymbol(map, `${a.symbol}.STRIPE_KEY`, "human", dbPath);
    obsoleteSymbol(map, a.symbol!, "human", dbPath);
    assert.deepEqual(registeredFileSymbols(map, env).map((g) => g.symbol), [`${b.symbol}.STRIPE_KEY`]);
  } finally {
    cleanup();
  }
});
