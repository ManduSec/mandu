/**
 * value-sources — one secret value held by several labelled files
 * (confidentiality.md §2.1 "One value, several sources", 2026-10-19).
 *
 * The bug: two labelled files holding the SAME value minted two rows, each
 * bound to its own file's hosts, and whatever named the value later (the
 * prompt filter's mask of a page's copy, the egress tripwire) judged one row
 * alone: the bindings of the file registered first won. These tests drive
 * the registry over a real on-disk symbol table and the pure egress gate
 * through `valueSourceView`, as the arbiter's symbol lookup does.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { allocateSymbol, getSymbolEntry, loadSymbolMap, type SymbolEntry, type SymbolMap } from "../../symbol-table/symbol-table.js";
import { registerEnvSecret, registerSecret } from "../../secret-registry/registry.js";
import { declaredBindingsReader } from "../../secret-registry/current-bindings.js";
import {
  isValueSourceRow, siblingDeclaredBindings, sourceHoldsNow, valueSiblings, valueSourceLevel, valueSourceView, type ValueSourceOptions,
} from "../../secret-registry/value-sources.js";
import { decideDesymbolization } from "../../policy/policy-interface.js";
import type { LabelLookup } from "../../policy/secret-catalog.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: bindings are its standing releases

const CARD = "4242424242424242";
const KEY = "sk_live_fake_VALSRC_8c1e44d2";
const EXTRACT = ":[ \\t]*(\\S+)";

interface Fixture {
  dir: string;
  dbPath: string;
  details: string;
  wallet: string;
  labels: Map<string, { level: ConfidentialityLevel; bindings: string[]; extract?: string }>;
  lookup: LabelLookup;
  cleanup: () => void;
}

/** Two labelled files holding the same card number: the person's details
 *  (bound to the vehicle registry) and a wallet (bound to the expense tool). */
function fixture(): Fixture {
  const dir = mkdtempSync(join(tmpdir(), "mandu-valsrc-"));
  const details = join(dir, "my-details.yaml");
  const wallet = join(dir, "wallet.yaml");
  writeFileSync(details, `driving_licence_number: DL99887766\ncard_number: ${CARD}\n`);
  writeFileSync(wallet, `company_card_number: ${CARD}\n`);
  const labels = new Map<string, { level: ConfidentialityLevel; bindings: string[]; extract?: string }>([
    [details, { level: "no-model", bindings: ["vehicles.example"], extract: EXTRACT }],
    [wallet, { level: "no-model", bindings: ["expenses.example"], extract: EXTRACT }],
  ]);
  const lookup: LabelLookup = (p) => {
    const l = labels.get(p);
    return l ? { level: l.level, bindings: [...l.bindings], via: p, ...(l.extract ? { extract: l.extract } : {}) } : null;
  };
  return { dir, dbPath: join(dir, "symbols.db"), details, wallet, labels, lookup, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

function opts(map: SymbolMap, lookup: LabelLookup): ValueSourceOptions {
  return { declared: declaredBindingsReader(map, lookup) };
}

/** The egress gate as the arbiter wires it: the lookup returns the value's view. */
function gate(map: SymbolMap, lookup: LabelLookup, symbol: string, host: string): string {
  const d = decideDesymbolization(
    { symbol, boundary: "network", destination: host },
    (n) => { const e = getSymbolEntry(map, n); return e ? valueSourceView(map, e, opts(map, lookup)) : undefined; },
    () => false,
    { confidentiality: true },
  );
  return d.ruleRef?.id ?? (d.allow ? "allow" : "deny");
}

function register(f: Fixture, map: SymbolMap, order: Array<"details" | "wallet">): { details: string; wallet: string } {
  const out: Record<string, string> = {};
  for (const which of order) {
    const r = registerSecret(map, { path: f[which], resolveLabel: f.lookup }, f.dbPath);
    assert.ok(r.symbol, r.reason);
    assert.equal(r.fields, which === "details" ? 2 : 1, `${which}: one field per value (${r.reason})`);
    out[which] = r.symbol!;
  }
  // An `extract:` label names its values by position (extract_1, …).
  return { details: `${out["details"]}.extract_2`, wallet: `${out["wallet"]}.extract_1` };
}

for (const order of [["details", "wallet"], ["wallet", "details"]] as Array<Array<"details" | "wallet">>) {
  test(`two files, one value (registered ${order.join(" then ")}): each placeholder is released where EITHER file binds it, an unbound host still refused`, () => {
    const f = fixture();
    try {
      const map = loadSymbolMap(f.dbPath);
      const sym = register(f, map, order);
      // The stored rows are untouched: each carries its own file's law.
      assert.deepEqual(getSymbolEntry(map, sym.details)?.bindings, ["vehicles.example"]);
      assert.deepEqual(getSymbolEntry(map, sym.wallet)?.bindings, ["expenses.example"]);
      for (const s of [sym.details, sym.wallet]) {
        assert.equal(gate(map, f.lookup, s, "vehicles.example"), "egress:secret-bound-trusted", `${s} at the registry`);
        assert.equal(gate(map, f.lookup, s, "expenses.example"), "egress:secret-bound-trusted", `${s} at the expense tool`);
        assert.equal(gate(map, f.lookup, s, "evil.example"), "egress:secret-unbound", `${s} at an unbound host`);
      }
      // The value the other file does not share keeps its own file's hosts.
      const licence = sym.details.replace(/\.extract_2$/, ".extract_1");
      assert.equal(gate(map, f.lookup, licence, "vehicles.example"), "egress:secret-bound-trusted");
      assert.equal(gate(map, f.lookup, licence, "expenses.example"), "egress:secret-unbound", "a value only one file holds gains nothing");
      // The whole files hold different bytes: their base rows are no siblings.
      assert.equal(gate(map, f.lookup, sym.wallet.replace(/\.extract_1$/, ""), "vehicles.example"), "egress:secret-unbound");
    } finally {
      f.cleanup();
    }
  });
}

test("the view's bindings are the same set whichever order the files were registered in", () => {
  const views: string[][] = [];
  for (const order of [["details", "wallet"], ["wallet", "details"]] as Array<Array<"details" | "wallet">>) {
    const f = fixture();
    try {
      const map = loadSymbolMap(f.dbPath);
      const sym = register(f, map, order);
      for (const s of [sym.details, sym.wallet]) views.push([...(valueSourceView(map, getSymbolEntry(map, s)!, opts(map, f.lookup)).bindings ?? [])].sort());
    } finally {
      f.cleanup();
    }
  }
  for (const v of views) assert.deepEqual(v, ["expenses.example", "vehicles.example"]);
});

test("levels disagree: the strictest source governs clearance to a model, whichever file's placeholder is asked", () => {
  const f = fixture();
  try {
    f.labels.get(f.wallet)!.level = "any-model";
    const map = loadSymbolMap(f.dbPath);
    const sym = register(f, map, ["wallet", "details"]);
    assert.equal(getSymbolEntry(map, sym.wallet)?.confidentiality, "any-model", "the stored row keeps its own label");
    assert.equal(valueSourceLevel(map, getSymbolEntry(map, sym.wallet)!), "no-model", "the other file's no-model governs");
    assert.equal(valueSourceLevel(map, getSymbolEntry(map, sym.details)!), "no-model");
    assert.equal(valueSourceView(map, getSymbolEntry(map, sym.wallet)!, opts(map, f.lookup)).confidentiality, "no-model");
    // And the bindings still unite: a level is about models, a binding about hosts.
    assert.equal(gate(map, f.lookup, sym.wallet, "vehicles.example"), "egress:secret-bound-trusted");
  } finally {
    f.cleanup();
  }
});

test("removing one source drops only its bindings: unlabelled, edited away, or deleted", () => {
  for (const how of ["unlabel", "edit", "delete"] as const) {
    const f = fixture();
    try {
      const map = loadSymbolMap(f.dbPath);
      const sym = register(f, map, ["details", "wallet"]);
      assert.equal(gate(map, f.lookup, sym.details, "expenses.example"), "egress:secret-bound-trusted", `${how}: before`);
      if (how === "unlabel") f.labels.delete(f.wallet);
      if (how === "edit") writeFileSync(f.wallet, "company_card_number: 5555444433332222\n");
      if (how === "delete") unlinkSync(f.wallet);
      assert.equal(gate(map, f.lookup, sym.details, "expenses.example"), "egress:secret-unbound", `${how}: the wallet no longer speaks for the value`);
      assert.equal(gate(map, f.lookup, sym.details, "vehicles.example"), "egress:secret-bound-trusted", `${how}: the details file's own binding stays`);
      if (how !== "unlabel") {
        // The other direction is unchanged: the details file still holds
        // the value and binds it, so the wallet's old placeholder still
        // gains the registry.
        assert.equal(gate(map, f.lookup, sym.wallet, "vehicles.example"), "egress:secret-bound-trusted", `${how}: the remaining source still speaks`);
      }
      // A level only narrows: the wallet's live row still counts.
      assert.equal(valueSourceLevel(map, getSymbolEntry(map, sym.details)!), "no-model");
    } finally {
      f.cleanup();
    }
  }
});

test("the union is recomputed from the stored rows after an arbiter restart (the table reloaded from SQLite)", () => {
  const f = fixture();
  try {
    const first = loadSymbolMap(f.dbPath);
    const sym = register(f, first, ["details", "wallet"]);
    const map = loadSymbolMap(f.dbPath);
    assert.ok(getSymbolEntry(map, sym.details) && getSymbolEntry(map, sym.wallet), "both rows persisted");
    assert.equal(gate(map, f.lookup, sym.details, "expenses.example"), "egress:secret-bound-trusted");
    assert.equal(gate(map, f.lookup, sym.wallet, "vehicles.example"), "egress:secret-bound-trusted");
    assert.equal(gate(map, f.lookup, sym.wallet, "evil.example"), "egress:secret-unbound");
  } finally {
    f.cleanup();
  }
});

test("only labelled sources give or get the union: a tool result's row with the same bytes neither widens nor is widened", () => {
  const f = fixture();
  try {
    const map = loadSymbolMap(f.dbPath);
    const sym = register(f, map, ["details"]);
    const other = allocateSymbol(map, {
      tool: "WebFetch", field: "content", value: CARD, origin: "https://evil.example/page",
      confidentiality: "no-model", bindings: ["evil.example"], integrity: "untrusted",
    });
    const otherRow = getSymbolEntry(map, other)!;
    assert.equal(isValueSourceRow(otherRow), false);
    assert.deepEqual(valueSiblings(map, otherRow), [], "a non-source row has no siblings");
    assert.equal(valueSourceView(map, otherRow, opts(map, f.lookup)), otherRow, "and is judged as stored");
    assert.equal(gate(map, f.lookup, sym.details, "evil.example"), "egress:secret-unbound", "its host does not reach the file's placeholder");
  } finally {
    f.cleanup();
  }
});

test("only DECLARED hosts cross: a host Mandu added to one row on its own (a grant) stays with that row", () => {
  const f = fixture();
  try {
    const map = loadSymbolMap(f.dbPath);
    const sym = register(f, map, ["details", "wallet"]);
    // As an auth or wire grant leaves it: a host the label never declared.
    getSymbolEntry(map, sym.wallet)!.bindings = ["expenses.example", "grant.example"];
    const extra = siblingDeclaredBindings(map, getSymbolEntry(map, sym.details)!, opts(map, f.lookup));
    assert.deepEqual(extra, ["expenses.example"]);
    assert.equal(gate(map, f.lookup, sym.details, "grant.example"), "egress:secret-unbound");
  } finally {
    f.cleanup();
  }
});

test("a masked environment variable holding the same value as a labelled file: each gives its declared hosts to the other", () => {
  const f = fixture();
  try {
    const env = join(f.dir, ".env");
    writeFileSync(env, `STRIPE_KEY=${KEY}\n`);
    f.labels.set(env, { level: "no-model", bindings: ["api.stripe.com"] });
    const map = loadSymbolMap(f.dbPath);
    const file = registerSecret(map, { path: env, resolveLabel: f.lookup }, f.dbPath);
    const fileField = `${file.symbol}.STRIPE_KEY`;
    const v = registerEnvSecret(map, { name: "STRIPE_KEY", value: KEY, rules: { secrets: ["STRIPE_KEY"] }, bindings: ["dashboard.example"] }, f.dbPath);
    assert.ok(v.symbol, v.reason);
    const envLaw = (name: string): string[] => (name === "STRIPE_KEY" ? ["dashboard.example"] : []);
    const fileDeclared = declaredBindingsReader(map, f.lookup);
    const o: ValueSourceOptions = { declared: (n, e) => (e.origin === "env:STRIPE_KEY" ? envLaw("STRIPE_KEY") : fileDeclared(n, e)) };
    const view = (s: string): SymbolEntry => valueSourceView(map, getSymbolEntry(map, s)!, o);
    assert.deepEqual([...(view(fileField).bindings ?? [])].sort(), ["api.stripe.com", "dashboard.example"]);
    assert.deepEqual([...(view(v.symbol!).bindings ?? [])].sort(), ["api.stripe.com", "dashboard.example"]);
    assert.equal(sourceHoldsNow(getSymbolEntry(map, v.symbol!)!), true, "an env row's law, not a file, says where it goes");
  } finally {
    f.cleanup();
  }
});
