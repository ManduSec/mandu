/**
 * current-bindings — a symbol's bound destinations follow the label law in
 * force, not the law at its mint (confidentiality.md §2.1, 2026-10-05).
 *
 * The bug: `registerSecret` reused a file's rows by value and never touched
 * their `bindings`, so a binding added to policy.yaml after Mandu first saw
 * `.env` was never applied (held as `egress:secret-unbound` while `mandu why`
 * said released), and a binding removed kept releasing. These tests drive the
 * registry and the pure egress gate over a real on-disk symbol table.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  allocateDerivedSymbol,
  allocateSymbol,
  getSymbolEntry,
  loadSymbolMap,
  obsoleteSymbol,
  symbolMapGeneration,
  recordWireGrant,
  wireGrantOf,
  type SymbolMap,
} from "../../symbol-table/symbol-table.js";
import { registerEnvSecret, registerSecret, wireServableTwin } from "../../secret-registry/registry.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { resolvePathLabel } from "../../policy/path-labels.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { releaseRestsOnWireGrant, syncCurrentBindings, syncRegisteredBindings } from "../../secret-registry/current-bindings.js";
import { SymbolSourceStore } from "../../symbol-table/symbol-sources.js";
import { decideDesymbolization } from "../../policy/policy-interface.js";
import type { LabelLookup } from "../../policy/secret-catalog.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: bindings are its standing releases

const ENV = "STRIPE_KEY=sk_live_fake_CURBIND_123456\nDEBUG=1\n";

function fixture(files: Record<string, string> = { ".env": ENV }): { dir: string; dbPath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "mandu-curbind-"));
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(join(dir, rel, ".."), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  return { dir, dbPath: join(dir, "symbols.db"), cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** A human label on `path` whose bindings the test changes, as a policy edit does. */
function mutableLabel(path: string): { lookup: LabelLookup; set: (b: string[] | null) => void } {
  let bindings: string[] | null = [];
  return {
    lookup: (p) => (p === path && bindings !== null ? { level: "no-model", bindings: [...bindings], via: path } : null),
    set: (b) => { bindings = b; },
  };
}

/** The egress gate's decision for `symbol` at `host`, from the table as it stands. */
function gate(map: SymbolMap, symbol: string, host: string): string {
  const d = decideDesymbolization(
    { symbol, boundary: "network", destination: host },
    (n) => getSymbolEntry(map, n) ?? undefined,
    () => false,
    { confidentiality: true },
  );
  return d.ruleRef?.id ?? (d.allow ? "allow" : "deny");
}

test("bind after first sight: a binding added to the label applies to the rows minted before it (re-registration reuses them)", () => {
  const { dir, dbPath, cleanup } = fixture();
  try {
    const env = join(dir, ".env");
    const law = mutableLabel(env);
    const map = loadSymbolMap(dbPath);
    const first = registerSecret(map, { path: env, resolveLabel: law.lookup }, dbPath);
    assert.ok(first.symbol, first.reason);
    const field = `${first.symbol}.STRIPE_KEY`;
    assert.equal(getSymbolEntry(map, field)?.bindings, null, "minted with no binding");
    assert.equal(gate(map, field, "api.stripe.com"), "egress:secret-unbound");

    law.set(["api.stripe.com"]);
    const again = registerSecret(map, { path: env, resolveLabel: law.lookup }, dbPath);
    assert.equal(again.symbol, first.symbol, "the same rows, reused by value");
    assert.deepEqual(getSymbolEntry(map, first.symbol!)?.bindings, ["api.stripe.com"], "the base row follows the label");
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["api.stripe.com"], "the field row follows the label");
    assert.equal(gate(map, field, "api.stripe.com"), "egress:secret-bound-trusted", "released at the now-bound host");
    assert.equal(gate(map, field, "evil.example"), "egress:secret-unbound", "an unbound host stays held");

    // Persisted: a restarted arbiter reads what the gate decided.
    const reloaded = loadSymbolMap(dbPath);
    assert.deepEqual(getSymbolEntry(reloaded, field)?.bindings, ["api.stripe.com"]);
  } finally {
    cleanup();
  }
});

test("a sync with no re-registration applies an added binding, and a removed one stops releasing at once", () => {
  const { dir, dbPath, cleanup } = fixture();
  try {
    const env = join(dir, ".env");
    const law = mutableLabel(env);
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: env, resolveLabel: law.lookup }, dbPath);
    const field = `${r.symbol}.STRIPE_KEY`;

    law.set(["api.stripe.com"]);
    const gen = symbolMapGeneration(map);
    assert.deepEqual(syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath).sort(), [r.symbol!, field].sort());
    assert.ok(symbolMapGeneration(map) > gen, "the change bumps the map generation (the value index rebuilds)");
    assert.equal(gate(map, field, "api.stripe.com"), "egress:secret-bound-trusted");
    assert.deepEqual(syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath), [], "idempotent");

    // Tightening: the binding removed.
    law.set([]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.equal(getSymbolEntry(map, field)?.bindings, null);
    assert.equal(gate(map, field, "api.stripe.com"), "egress:secret-unbound", "a removed binding no longer releases");
    assert.equal(getSymbolEntry(loadSymbolMap(dbPath), field)?.bindings, null, "persisted");

    // The label removed entirely: the catalog's verdict (`.env` is a
    // credential shape) carries no binding.
    law.set(["api.stripe.com"]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    law.set(null);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.equal(gate(map, field, "api.stripe.com"), "egress:secret-unbound", "no label, no binding");
  } finally {
    cleanup();
  }
});

test("copies of a registered value narrow to the source's current bindings and are never widened", () => {
  const { dir, dbPath, cleanup } = fixture();
  try {
    const env = join(dir, ".env");
    const law = mutableLabel(env);
    law.set(["a.example", "b.example"]);
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: env, resolveLabel: law.lookup }, dbPath);
    const field = `${r.symbol}.STRIPE_KEY`;
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["a.example", "b.example"]);

    // A split of the field (lineage in derived_from), an inspection result
    // whose origin is the field symbol, and a proxy Read result of the file
    // (a call id, the path as origin): each minted at the file's bindings.
    const split = allocateDerivedSymbol(map, { parentSymName: field, value: "sk_live", lineStart: 0, lineEnd: 1, splitIndex: 0 }, dbPath);
    const inspected = allocateSymbol(map, { tool: "inspect_symbol", value: "its first chars", origin: field, confidentiality: "no-model", bindings: ["a.example", "b.example"], integrity: "untrusted" }, dbPath);
    const read = allocateSymbol(map, { tool: "Read", field: "content", value: ENV, origin: env, callId: "toolu_1", confidentiality: "no-model", bindings: ["a.example", "b.example"], integrity: "untrusted" }, dbPath);
    // Unrelated: a URL-origin secret with its own binding is not touched.
    const other = allocateSymbol(map, { tool: "WebFetch", value: "tok", origin: "https://x.example/k", confidentiality: "no-model", bindings: ["b.example"], integrity: "untrusted" }, dbPath);

    law.set(["a.example"]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    for (const s of [field, split, inspected, read]) {
      assert.deepEqual(getSymbolEntry(map, s)?.bindings, ["a.example"], `${s} narrowed`);
      assert.equal(gate(map, s, "b.example"), "egress:secret-unbound", `${s}: b.example no longer releases`);
    }
    assert.deepEqual(getSymbolEntry(map, other)?.bindings, ["b.example"], "a row with no reference to the file keeps its own");

    // Widening the label reaches the file's own rows, not the copies (fail-closed).
    law.set(["a.example", "b.example", "c.example"]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["a.example", "b.example", "c.example"]);
    for (const s of [split, inspected, read]) assert.deepEqual(getSymbolEntry(map, s)?.bindings, ["a.example"], `${s} not widened`);

    // Every binding removed: every copy is bound nowhere.
    law.set([]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    for (const s of [field, split, inspected, read]) {
      assert.equal(getSymbolEntry(map, s)?.bindings, null, `${s} bound nowhere`);
      assert.equal(gate(map, s, "a.example").startsWith("egress:secret-bound"), false);
    }
  } finally {
    cleanup();
  }
});

test("a path whose label is gone binds its copies nowhere", () => {
  const { dir, dbPath, cleanup } = fixture({ "notes.md": "board minutes\n" });
  try {
    const doc = join(dir, "notes.md");
    const law = mutableLabel(doc);
    law.set(["docs.example"]);
    const map = loadSymbolMap(dbPath);
    const read = allocateSymbol(map, { tool: "Read", field: "content", value: "board minutes\n", origin: doc, callId: "toolu_2", confidentiality: "any-model", bindings: ["docs.example"], integrity: "untrusted" }, dbPath);
    law.set(null); // no label: the catalog says public
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.equal(getSymbolEntry(map, read)?.bindings, null);
    assert.equal(getSymbolEntry(map, read)?.confidentiality, "any-model", "the level is not lowered");
  } finally {
    cleanup();
  }
});

test("the launch HOME's .npmrc: a field keeps its own registry (the wire grant) whatever the label binds", () => {
  const NPMRC = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_CURBIND_1\n";
  const { dir: home, dbPath, cleanup } = fixture({ ".npmrc": NPMRC });
  try {
    const npmrc = join(home, ".npmrc");
    const law = mutableLabel(npmrc);
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup }, dbPath);
    assert.equal(r.fields, 1, r.reason);
    const field = [...map.symbols.entries()].find(([, e]) => e.origin === npmrc && e.field !== null)![0];
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"]);

    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"], "the wire grant survives a sync");
    assert.equal(wireServableTwin(map, npmrc).servable, true);

    law.set(["mirror.example"]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.deepEqual([...(getSymbolEntry(map, field)?.bindings ?? [])].sort(), ["mirror.example", "registry.npmjs.org"]);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["mirror.example"], "the base row: the label only");

    law.set([]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"]);
    assert.equal(getSymbolEntry(map, r.symbol!)?.bindings, null);

    // A WORKSPACE copy never had the wire grant: a label binding equal to
    // the registry is the label's, and leaves with it.
    const { dir: ws, dbPath: db2, cleanup: c2 } = fixture({ ".npmrc": NPMRC });
    try {
      const wsNpmrc = join(ws, ".npmrc");
      const wsLaw = mutableLabel(wsNpmrc);
      wsLaw.set(["registry.npmjs.org"]);
      const map2 = loadSymbolMap(db2);
      registerSecret(map2, { path: wsNpmrc, resolveLabel: wsLaw.lookup }, db2);
      const f2 = [...map2.symbols.entries()].find(([, e]) => e.origin === wsNpmrc && e.field !== null)![0];
      assert.deepEqual(getSymbolEntry(map2, f2)?.bindings, ["registry.npmjs.org"]);
      wsLaw.set([]);
      syncRegisteredBindings(map2, { resolveLabel: wsLaw.lookup }, db2);
      assert.equal(getSymbolEntry(map2, f2)?.bindings, null, "the label's binding left with the label");
    } finally {
      c2();
    }
  } finally {
    cleanup();
  }
});

// ── 2026-10-17: the wire grant is a RECORD (wire_grants), not an inference
// from "the field holds a host its base row lacks" (confidentiality.md §2.1,
// "The wire grant is recorded"). The inference failed both ways: ──

test("wire grant recorded: a label binding on the registry's own host removed leaves the HOME .npmrc grant, in the running sync and after a restart (it was dropped until the next launch)", () => {
  const NPMRC = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_CURBIND_SAMEHOST_1\n";
  const { dir: home, dbPath, cleanup } = fixture({ ".npmrc": NPMRC });
  try {
    const npmrc = join(home, ".npmrc");
    const law = mutableLabel(npmrc);
    law.set(["registry.npmjs.org"]);
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup }, dbPath);
    const field = [...map.symbols.entries()].find(([, e]) => e.origin === npmrc && e.field !== null)![0];
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["registry.npmjs.org"], "the base row: the label's host");
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"]);
    assert.equal(wireGrantOf(map, field), "registry.npmjs.org", "the registration recorded the grant");

    law.set([]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.equal(getSymbolEntry(map, r.symbol!)?.bindings, null, "the label's binding left the base row");
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"], "the grant is the field's own: it stays");
    assert.equal(gate(map, field, "registry.npmjs.org"), "egress:secret-bound-trusted");
    assert.equal(releaseRestsOnWireGrant(map, field, "registry.npmjs.org", { resolveLabel: law.lookup }), true, "and is automatic again");

    // A restarted arbiter (the map reloaded from mandu.db, no registration).
    const reloaded = loadSymbolMap(dbPath);
    assert.equal(wireGrantOf(reloaded, field), "registry.npmjs.org", "the record survives a restart");
    getSymbolEntry(reloaded, field)!.bindings = null; // even a row that lost it
    syncCurrentBindings(reloaded, { resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(reloaded, field)?.bindings, ["registry.npmjs.org"], "the sync gives the field its grant back from the record");
    assert.equal(getSymbolEntry(reloaded, r.symbol!)?.bindings, null, "never the base row");
  } finally {
    cleanup();
  }
});

test("security fix: a WORKSPACE .npmrc token's own registry bound by values:, then removed, stops releasing (it was kept as if a wire grant, across every sync and restart)", () => {
  const NPMRC = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_CURBIND_VALUES_1\n";
  const { dir: ws, dbPath, cleanup } = fixture({ ".npmrc": NPMRC });
  try {
    const npmrc = join(ws, ".npmrc");
    const doc = (values?: unknown): PolicyFileConfig =>
      ({ version: 1, paths: [{ path: npmrc, level: "no-model", bindings: [], ...(values ? { values } : {}) }] } as PolicyFileConfig);
    let labels = compilePolicy({ specId: "claude-code", document: doc({ "*": { bindings: ["registry.npmjs.org"] } }) }).pathLabels;
    const lookup: LabelLookup = (p) => resolvePathLabel(p, labels);
    const map = loadSymbolMap(dbPath);
    // No `home`: a workspace file, which the agent can write, gets no grant.
    const r = registerSecret(map, { path: npmrc, resolveLabel: lookup }, dbPath);
    const field = [...map.symbols.entries()].find(([, e]) => e.origin === npmrc && e.field !== null && !e.field.endsWith(".encoded"))![0];
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"], "the user's value binding");
    assert.equal(getSymbolEntry(map, r.symbol!)?.bindings, null, "the whole file: the intersection, nowhere");
    assert.equal(wireGrantOf(map, field), undefined, "no grant recorded for a workspace file");
    assert.equal(gate(map, field, "registry.npmjs.org"), "egress:secret-bound-trusted");

    // The human removes the value binding.
    labels = compilePolicy({ specId: "claude-code", document: doc() }).pathLabels;
    syncCurrentBindings(map, { resolveLabel: lookup }, dbPath);
    assert.equal(getSymbolEntry(map, field)?.bindings, null, "the removed binding leaves the field");
    assert.equal(gate(map, field, "registry.npmjs.org"), "egress:secret-unbound", "a removed binding no longer releases");
    const reloaded = loadSymbolMap(dbPath);
    syncCurrentBindings(reloaded, { resolveLabel: lookup }, dbPath);
    assert.equal(getSymbolEntry(reloaded, field)?.bindings, null, "nor after a restart");
    registerSecret(reloaded, { path: npmrc, resolveLabel: lookup }, dbPath);
    assert.equal(getSymbolEntry(reloaded, field)?.bindings, null, "nor after the next launch's registration");
  } finally {
    cleanup();
  }
});

test("wireGrant: false (a data-socket registration, 2026-10-17): the HOME .npmrc is registered with no grant and no record, and a later one leaves a recorded grant in place", () => {
  const NPMRC = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_CURBIND_NOGRANT_1\n";
  const { dir: home, dbPath, cleanup } = fixture({ ".npmrc": NPMRC });
  try {
    const npmrc = join(home, ".npmrc");
    const law = mutableLabel(npmrc);
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup, wireGrant: false }, dbPath);
    assert.equal(r.fields, 1, r.reason);
    const field = [...map.symbols.entries()].find(([, e]) => e.origin === npmrc && e.field !== null)![0];
    assert.equal(getSymbolEntry(map, field)?.bindings, null, "registered, bound nowhere");
    assert.equal(wireGrantOf(map, field), undefined, "nothing recorded");
    assert.equal(gate(map, field, "registry.npmjs.org"), "egress:secret-unbound");

    registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"], "the trusted registration grants");
    registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup, wireGrant: false }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"], "an untrusted one does not take it away");
    assert.equal(wireGrantOf(loadSymbolMap(dbPath), field), "registry.npmjs.org");
  } finally {
    cleanup();
  }
});

test("wire grant recorded: a row with no record (minted before the table, schema v15 and earlier) keeps no inferred grant until a registration records it (fail-closed)", () => {
  const NPMRC = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_CURBIND_UNRECORDED_1\n";
  const { dir: home, dbPath, cleanup } = fixture({ ".npmrc": NPMRC });
  try {
    const npmrc = join(home, ".npmrc");
    const law = mutableLabel(npmrc);
    const map = loadSymbolMap(dbPath);
    registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup }, dbPath);
    const field = [...map.symbols.entries()].find(([, e]) => e.origin === npmrc && e.field !== null)![0];
    // What an adopted v15 file looks like: the row bound to its registry, no record.
    map.wireGrants?.delete(field);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.equal(getSymbolEntry(map, field)?.bindings, null, "no record: no grant (the old inference is gone)");
    registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"], "the next launch's registration records it");
    assert.equal(wireGrantOf(loadSymbolMap(dbPath), field), "registry.npmjs.org", "persisted");
  } finally {
    cleanup();
  }
});

// ── 2026-10-09: an AUTOMATIC binding (the wire grant) told from one the user
// declared, per destination (releaseRestsOnWireGrant; the egress gate puts
// an automatically bound credential back only in the Authorization header) ──

test("releaseRestsOnWireGrant: the HOME .npmrc token at its own registry rests on the wire grant; the label's hosts, the base row, other hosts and a workspace copy do not", () => {
  const NPMRC = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_CURBIND_WIRE_1\n";
  const { dir: home, dbPath, cleanup } = fixture({ ".npmrc": NPMRC });
  try {
    const npmrc = join(home, ".npmrc");
    const law = mutableLabel(npmrc);
    const map = loadSymbolMap(dbPath);
    const r = registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup }, dbPath);
    const field = [...map.symbols.entries()].find(([, e]) => e.origin === npmrc && e.field !== null)![0];
    const wire = (symbol: string, dest: string) => releaseRestsOnWireGrant(map, symbol, dest, { resolveLabel: law.lookup });
    assert.equal(wire(field, "registry.npmjs.org"), true, "bound there by its own file alone");
    assert.equal(wire(field, "registry.npmjs.org:443"), true, "the gate ignores the port, so does this");
    assert.equal(wire(`${field}.x`, "registry.npmjs.org"), true, "a mutated token answers as the row the gate's lookup finds");
    assert.equal(wire(field, "evil.example"), false, "not bound there: the unbound branches decide");
    assert.equal(wire(r.symbol!, "registry.npmjs.org"), false, "the base row never had the wire grant");
    assert.equal(wire("$MDU:nomodel_Read[ffff].nope", "registry.npmjs.org"), false, "unknown");

    // The label declares a host: that host is the user's binding.
    law.set(["mirror.example"]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.equal(wire(field, "mirror.example"), false);
    assert.equal(wire(field, "registry.npmjs.org"), true, "the registry is still the grant's alone");
    // The label declares the registry itself (or a suffix of it): the user's.
    for (const declared of [["registry.npmjs.org"], ["npmjs.org"]]) {
      law.set(declared);
      syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
      assert.equal(wire(field, "registry.npmjs.org"), false, `declared ${declared}`);
    }
    // Removed again: the grant's alone once more, at the sync (the grant is
    // recorded, 2026-10-17; it used to leave with the label until the next
    // launch registered the file), and after that registration.
    law.set([]);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"]);
    assert.equal(wire(field, "registry.npmjs.org"), true);
    registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"]);
    assert.equal(wire(field, "registry.npmjs.org"), true);

    // A copy of the token keeps the grant's character: a split of the field
    // (lineage), and a row whose origin is the field symbol.
    const split = allocateDerivedSymbol(map, { parentSymName: field, value: "npm_CURBIND", lineStart: 0, lineEnd: 1, splitIndex: 0 }, dbPath);
    const inspected = allocateSymbol(map, { tool: "inspect_symbol", value: "its first chars", origin: field, confidentiality: "no-model", bindings: ["registry.npmjs.org"], integrity: "trusted" }, dbPath);
    for (const s of [split, inspected]) assert.equal(wire(s, "registry.npmjs.org"), true, `${s} is a copy of the token`);
    // A multi-input join that took the token among its sources.
    const joined = allocateSymbol(map, { tool: "Bash", value: "joined", origin: "echo", confidentiality: "no-model", bindings: ["registry.npmjs.org"], integrity: "trusted" }, dbPath);
    const sources = new Map([[joined, [field]]]);
    assert.equal(releaseRestsOnWireGrant(map, joined, "registry.npmjs.org", { resolveLabel: law.lookup, sourcesOf: (s) => sources.get(s) }), true);
    assert.equal(releaseRestsOnWireGrant(map, joined, "registry.npmjs.org", { resolveLabel: law.lookup }), false, "without its recorded sources it refers to nothing");
  } finally {
    cleanup();
  }
  // A WORKSPACE copy never gets the grant: a label binding to the registry is the user's.
  const { dir: ws, dbPath: db2, cleanup: c2 } = fixture({ ".npmrc": NPMRC });
  try {
    const wsNpmrc = join(ws, ".npmrc");
    const wsLaw = mutableLabel(wsNpmrc);
    wsLaw.set(["registry.npmjs.org"]);
    const map2 = loadSymbolMap(db2);
    registerSecret(map2, { path: wsNpmrc, resolveLabel: wsLaw.lookup }, db2);
    const f2 = [...map2.symbols.entries()].find(([, e]) => e.origin === wsNpmrc && e.field !== null)![0];
    assert.equal(releaseRestsOnWireGrant(map2, f2, "registry.npmjs.org", { resolveLabel: wsLaw.lookup }), false);
  } finally {
    c2();
  }
});

test("releaseRestsOnWireGrant: an OBSOLETED .npmrc field row, and a copy whose only parent it is, still rest on the wire grant (2026-10-10: they read as the user's binding); the label naming the registry makes them the user's", () => {
  const NPMRC = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_CURBIND_OBSOLETE_1\n";
  const { dir: home, dbPath, cleanup } = fixture({ ".npmrc": NPMRC });
  try {
    const npmrc = join(home, ".npmrc");
    const law = mutableLabel(npmrc);
    const map = loadSymbolMap(dbPath);
    registerSecret(map, { path: npmrc, home, resolveLabel: law.lookup }, dbPath);
    const field = [...map.symbols.entries()].find(([, e]) => e.origin === npmrc && e.field !== null)![0];
    const wire = (symbol: string) => releaseRestsOnWireGrant(map, symbol, "registry.npmjs.org", { resolveLabel: law.lookup });
    // Two copies of the token (a split, and a row whose origin is the
    // field), then the field is obsoleted: rule 1 no longer keeps its
    // bindings, so they stay frozen with the registry in them.
    const split = allocateDerivedSymbol(map, { parentSymName: field, value: "npm_CURBIND_OBSOLETE_1", lineStart: 0, lineEnd: 1, splitIndex: 0 }, dbPath);
    const copy = allocateSymbol(map, { tool: "inspect_symbol", value: "npm_CURBIND_OBSOLETE_1", origin: field, confidentiality: "no-model", bindings: ["registry.npmjs.org"], integrity: "trusted" }, dbPath);
    obsoleteSymbol(map, field, "human", dbPath);
    for (const s of [field, split, copy, `${field}.x`]) assert.equal(wire(s), true, `${s}: bound there by the file's own wire grant alone`);
    // The sync: the obsoleted row and the copy keep the registry (the copy
    // narrows to its origin symbol's frozen bindings); the split narrows to
    // its path's label, which names no host, so it is bound there no more.
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, field)?.bindings, ["registry.npmjs.org"]);
    assert.deepEqual(getSymbolEntry(map, copy)?.bindings, ["registry.npmjs.org"]);
    assert.equal(getSymbolEntry(map, split)?.bindings, null);
    assert.equal(wire(field), true);
    assert.equal(wire(copy), true, "the copy whose only parent is the obsoleted row");
    assert.equal(wire(split), false, "not bound there: the unbound branches decide");
    // The label declares the registry: the user's binding, as for a live row.
    law.set(["registry.npmjs.org"]);
    assert.equal(wire(field), false);
    assert.equal(wire(copy), false);
  } finally {
    cleanup();
  }
});

test("releaseRestsOnWireGrant: a pip index variable's own host is automatic, an env.sources binding is the user's; with no env law every host counts as automatic (fail-closed)", () => {
  const { dbPath, cleanup } = fixture({});
  try {
    const map = loadSymbolMap(dbPath);
    const pip = registerEnvSecret(map, { name: "PIP_INDEX_URL", value: "https://me:s3cr%21t@pypi.corp.example/simple" }, dbPath).symbol!;
    const gh = registerEnvSecret(map, { name: "GH_TOKEN", value: "ghp_CURBINDwire0123456789abcdefABCDEF", bindings: ["api.github.com"] }, dbPath).symbol!;
    const law = (name: string) => (name === "GH_TOKEN" ? ["api.github.com"] : name === "PIP_INDEX_URL" ? ["mirror.example"] : []);
    assert.equal(releaseRestsOnWireGrant(map, pip, "pypi.corp.example", { envBindings: law }), true, "bound there by its own URL alone");
    assert.equal(releaseRestsOnWireGrant(map, pip, "pypi.corp.example", { envBindings: () => ["pypi.corp.example"] }), false, "the user's env.sources names it too");
    assert.equal(releaseRestsOnWireGrant(map, gh, "api.github.com", { envBindings: law }), false, "an env.sources binding is the user's");
    assert.equal(releaseRestsOnWireGrant(map, gh, "api.github.com", {}), true, "no law handed over: nothing proven declared (fail-closed)");
  } finally {
    cleanup();
  }
});

test("registerEnvSecret: a reused row takes the bindings of the launch registering it", () => {
  const { dbPath, cleanup } = fixture({});
  try {
    const map = loadSymbolMap(dbPath);
    const reg = (bindings: string[]) => registerEnvSecret(map, { name: "PLAIN_NAME", value: "tok-curbind-1", rules: { secrets: ["PLAIN_NAME"] }, bindings }, dbPath);
    const a = reg(["api.github.com"]);
    assert.deepEqual(getSymbolEntry(map, a.symbol!)?.bindings, ["api.github.com"]);
    const b = reg([]);
    assert.equal(b.symbol, a.symbol);
    assert.equal(getSymbolEntry(map, a.symbol!)?.bindings, null, "a source binding removed leaves the row");
    reg(["api.github.com", "uploads.github.com"]);
    assert.deepEqual(getSymbolEntry(map, a.symbol!)?.bindings, ["api.github.com", "uploads.github.com"]);
    assert.deepEqual(getSymbolEntry(loadSymbolMap(dbPath), a.symbol!)?.bindings, ["api.github.com", "uploads.github.com"], "persisted");
  } finally {
    cleanup();
  }
});

// ── 2026-10-05, the residuals of the first pass: env rows (rule 3), command
// text whose label is gone, multi-input joins (rule 2's recorded sources) ──

test("rule 3: a masked environment variable's row carries exactly the law's env bindings, in both directions, with no relaunch", () => {
  const { dbPath, cleanup } = fixture({});
  try {
    const map = loadSymbolMap(dbPath);
    let law: string[] = ["api.github.com"];
    const opts = { envBindings: (name: string) => (name === "MY_TOKEN" ? law : []) };
    const r = registerEnvSecret(map, { name: "MY_TOKEN", value: "tok-curbind-env", rules: { secrets: ["MY_TOKEN"] }, bindings: law }, dbPath);
    assert.equal(gate(map, r.symbol!, "api.github.com"), "egress:secret-bound-trusted");

    law = [];
    assert.deepEqual(syncCurrentBindings(map, opts, dbPath), [r.symbol]);
    assert.equal(gate(map, r.symbol!, "api.github.com"), "egress:secret-unbound", "a removed env.sources binding stops releasing at once");
    assert.equal(getSymbolEntry(loadSymbolMap(dbPath), r.symbol!)?.bindings, null, "persisted");

    law = ["api.github.com", "uploads.github.com"];
    syncCurrentBindings(map, opts, dbPath);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["api.github.com", "uploads.github.com"], "an added one releases at once");
    assert.deepEqual(syncCurrentBindings(map, opts, dbPath), [], "idempotent");

    // No env law handed to the sync (a caller that does not own it): untouched.
    law = [];
    syncCurrentBindings(map, {}, dbPath);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["api.github.com", "uploads.github.com"]);
  } finally {
    cleanup();
  }
});

test("rule 3: a pip index variable keeps its own wire host while this process knows it, and loses it (fail-closed) when it does not", () => {
  const { dbPath, cleanup } = fixture({});
  try {
    const map = loadSymbolMap(dbPath);
    const r = registerEnvSecret(map, { name: "PIP_INDEX_URL", value: "https://me:s3cr%21t@pypi.corp.example/simple" }, dbPath);
    assert.equal(r.wireHost, "pypi.corp.example");
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["pypi.corp.example"]);
    const known = new Map([[r.symbol!, r.wireHost!]]);
    syncCurrentBindings(map, { envBindings: () => [], envWire: (s) => known.get(s) }, dbPath);
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["pypi.corp.example"], "the wire grant survives a sync");
    syncCurrentBindings(map, { envBindings: () => ["mirror.example"], envWire: (s) => known.get(s) }, dbPath);
    assert.deepEqual([...(getSymbolEntry(map, r.symbol!)?.bindings ?? [])].sort(), ["mirror.example", "pypi.corp.example"]);
    // An arbiter that never saw the registration (restarted under the session)
    // and holds no record of it (a data-plane registration is memory only).
    syncCurrentBindings(map, { envBindings: () => [] }, dbPath);
    assert.equal(getSymbolEntry(map, r.symbol!)?.bindings, null, "unknown wire host: bound nowhere until the next launch registers it");
  } finally {
    cleanup();
  }
});

test("rule 3, recorded (2026-10-17): a pip index variable's grant a human-plane registration recorded survives a restart; a removed env.sources host does not; the row obsoleted takes the record with it", () => {
  const { dbPath, cleanup } = fixture({});
  try {
    const map = loadSymbolMap(dbPath);
    const r = registerEnvSecret(map, { name: "PIP_INDEX_URL", value: "https://me:s3cr%21t@pypi.corp.example/simple", bindings: ["mirror.example"] }, dbPath);
    assert.equal(r.wireHost, "pypi.corp.example");
    assert.equal(wireGrantOf(map, r.symbol!), undefined, "registerEnvSecret alone records nothing: the server decides by channel");
    recordWireGrant(map, r.symbol!, r.wireHost!, dbPath);

    // A restart: the map reloaded from mandu.db, no memory of the registration,
    // and the env.sources entry that bound mirror.example gone from the law.
    const reloaded = loadSymbolMap(dbPath);
    assert.equal(wireGrantOf(reloaded, r.symbol!), "pypi.corp.example", "the record survives");
    syncCurrentBindings(reloaded, { envBindings: () => [] }, dbPath);
    assert.deepEqual(getSymbolEntry(reloaded, r.symbol!)?.bindings, ["pypi.corp.example"], "the grant kept, the removed source's host not");
    assert.equal(releaseRestsOnWireGrant(reloaded, r.symbol!, "pypi.corp.example", { envBindings: () => [] }), true, "automatic: the Authorization header only");
    assert.equal(gate(reloaded, r.symbol!, "mirror.example"), "egress:secret-unbound");

    // A later grant for the same row replaces the host (one per row, as the
    // memory map did): the same password at another index.
    recordWireGrant(reloaded, r.symbol!, "pypi.other.example", dbPath);
    syncCurrentBindings(reloaded, { envBindings: () => [] }, dbPath);
    assert.deepEqual(getSymbolEntry(reloaded, r.symbol!)?.bindings, ["pypi.other.example"]);

    // The row goes: its record goes with it, in memory and in mandu.db.
    obsoleteSymbol(reloaded, r.symbol!, "human", dbPath);
    assert.equal(wireGrantOf(reloaded, r.symbol!), undefined);
    assert.equal(wireGrantOf(loadSymbolMap(dbPath), r.symbol!), undefined, "persisted");
  } finally {
    cleanup();
  }
});

test("a command-text row: an unchanged label keeps its binding, a label removed entirely binds it nowhere", () => {
  const { dir, dbPath, cleanup } = fixture({ "notes.txt": "figures\n" });
  try {
    const notes = join(dir, "notes.txt");
    const law = mutableLabel(notes);
    law.set(["api.notes.example"]);
    const map = loadSymbolMap(dbPath);
    const row = allocateSymbol(map, { tool: "Bash", value: "figures", origin: `cat ${notes}`, callId: "toolu_3", confidentiality: "no-model", bindings: ["api.notes.example"], integrity: "trusted" }, dbPath);
    assert.deepEqual(syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath), [], "the law that minted it gives back its binding");
    assert.equal(gate(map, row, "api.notes.example"), "egress:secret-bound-trusted");

    law.set(null);
    syncCurrentBindings(map, { resolveLabel: law.lookup }, dbPath);
    assert.equal(getSymbolEntry(map, row)?.bindings, null);
    assert.equal(gate(map, row, "api.notes.example"), "egress:secret-unbound", "the label is gone and its binding with it");
    assert.equal(getSymbolEntry(map, row)?.confidentiality, "no-model", "the level is not lowered");
  } finally {
    cleanup();
  }
});

test("a multi-input join narrows to its recorded sources' current bindings; a source gone binds it nowhere", () => {
  const { dir, dbPath, cleanup } = fixture({ "a.md": "A\n", "b.md": "B\n" });
  try {
    const a = join(dir, "a.md");
    const b = join(dir, "b.md");
    const labels = new Map<string, string[]>([[a, ["h1.example", "h2.example"]], [b, ["h1.example", "h2.example"]]]);
    const lookup: LabelLookup = (p) => (labels.has(p) ? { level: "any-model", bindings: [...labels.get(p)!], via: p } : null);
    const map = loadSymbolMap(dbPath);
    const sa = allocateSymbol(map, { tool: "Read", field: "content", value: "A\n", origin: a, callId: "toolu_a", confidentiality: "any-model", bindings: ["h1.example", "h2.example"], integrity: "untrusted" }, dbPath);
    const sb = allocateSymbol(map, { tool: "Read", field: "content", value: "B\n", origin: b, callId: "toolu_b", confidentiality: "any-model", bindings: ["h1.example", "h2.example"], integrity: "untrusted" }, dbPath);
    const joined = allocateSymbol(map, { tool: "inspect_symbol", field: "result", value: "the two, merged", origin: sa, derivedFrom: sa, confidentiality: "any-model", bindings: ["h1.example", "h2.example"], integrity: "untrusted" }, dbPath);
    const recorded = new Map<string, string[]>([[joined, [sa, sb]]]);
    const opts = { resolveLabel: lookup, sourcesOf: (s: string) => recorded.get(s) };

    labels.set(b, ["h1.example"]);
    syncCurrentBindings(map, { resolveLabel: lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, joined)?.bindings, ["h1.example", "h2.example"], "without its sources, the join kept the second source's removed binding");
    syncCurrentBindings(map, opts, dbPath);
    assert.deepEqual(getSymbolEntry(map, joined)?.bindings, ["h1.example"], "with them, it narrows");

    // Widened sources do not widen the join (rule 2 never widens).
    labels.set(b, ["h1.example", "h2.example"]);
    syncCurrentBindings(map, opts, dbPath);
    assert.deepEqual(getSymbolEntry(map, joined)?.bindings, ["h1.example"]);

    // A recorded source that no longer exists: nowhere.
    recorded.set(joined, [sa, "$MDU:Read[0000]"]);
    syncCurrentBindings(map, opts, dbPath);
    assert.equal(getSymbolEntry(map, joined)?.bindings, null);
  } finally {
    cleanup();
  }
});

test("SymbolSourceStore: a join's sources are recorded once and survive a restart", () => {
  const { dbPath, cleanup } = fixture({});
  try {
    const s1 = new SymbolSourceStore({ dbPath });
    assert.equal(s1.get("$MDU:anymodel_inspect[ab12].result"), undefined);
    s1.record("$MDU:anymodel_inspect[ab12].result", ["$MDU:Read[0001]", "$MDU:Read[0002]"]);
    s1.record("$MDU:anymodel_inspect[ab12].result", ["$MDU:Read[0002]"]);
    assert.deepEqual(s1.get("$MDU:anymodel_inspect[ab12].result"), ["$MDU:Read[0001]", "$MDU:Read[0002]"]);
    s1.close();
    const s2 = new SymbolSourceStore({ dbPath });
    assert.deepEqual([...(s2.get("$MDU:anymodel_inspect[ab12].result") ?? [])].sort(), ["$MDU:Read[0001]", "$MDU:Read[0002]"]);
    s2.close();
  } finally {
    cleanup();
  }
});
