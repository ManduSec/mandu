/**
 * per-value-bindings.test.ts — confidentiality plan 13 §5.2: a structured
 * file's values bound one by one (`values:` in policy.yaml).
 *
 *   - the pure rules (value-bindings.ts): which key names which field, a
 *     value's release, a symbol holding several values, the whole file;
 *   - the validator, the compiler and the resolver (`LabelDecision.bindings`
 *     is the WHOLE file's, the intersection);
 *   - `policyDelta`: adding a binding to a value is a relaxation, removing
 *     one a tightening, a key added or removed a relaxation;
 *   - the save path (`lock-path`) keeps `values:`;
 *   - the registry rows and the pure egress gate: a value is released at its
 *     own hosts and no other value is; the whole-file row and a row whose
 *     names cannot be read back take the whole file's;
 *   - a raw holder over IPC (`taintedProcessBindings` on a real
 *     ArbiterServer): the intersection over the values, never one value's.
 *
 * Mandu-new test (no reference origin).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ArbiterServer } from "../../ipc/server.js";
import { ArbiterClient } from "../../ipc/client.js";
import {
  compileValueRules, holderFileBindings, oneValueBindings, valueBindings, valueKeyMatches, valueRulesToDocument, wholeFileBindings,
} from "../../policy/value-bindings.js";
import { validatePolicyDocument } from "../../policy/policy-file-validate.js";
import { compilePolicy } from "../../policy/compiled-policy.js";
import { resolvePathLabel } from "../../policy/path-labels.js";
import { policyDelta } from "../../policy/policy-delta.js";
import { applyEdits } from "../../policy/policy-edit.js";
import type { PolicyFileConfig } from "../../policy/load-policy.js";
import { pathConfidentiality, type LabelLookup } from "../../policy/secret-catalog.js";
import { composedLabel } from "../../policy/label-lookup.js";
import { getSymbolEntry, loadSymbolMap, type SymbolMap } from "../../symbol-table/symbol-table.js";
import { registerSecret } from "../../secret-registry/registry.js";
import { releaseRestsOnWireGrant, syncCurrentBindings } from "../../secret-registry/current-bindings.js";
import { decideDesymbolization } from "../../policy/policy-interface.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: where each value's bytes may go

const STRIPE = "sk_live_fake_PERVALUE_7f3a91aa";
const AWS_ID = "AKIAIOSFODNN7PERVAL1";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYPERVALUE01";
const ENV_TEXT = `STRIPE_KEY=${STRIPE}\nAWS_ACCESS_KEY_ID=${AWS_ID}\nAWS_SECRET_ACCESS_KEY=${AWS_SECRET}\nDATABASE_URL=postgres://u:pw_PERVALUE_secret99@db.internal:5432/app\nDEBUG=1\n`;
// A binding names a host and every host under it (the egress gate's
// `destinationMatchesBindings`), so `amazonaws.com` covers s3.amazonaws.com.
const VALUES = { STRIPE_KEY: { bindings: ["api.stripe.com"] }, "AWS_*": { bindings: ["amazonaws.com"] } };

// ── the pure rules ──────────────────────────────────────────────────────────

test("valueKeyMatches: the name, a * glob, and the sub-fields of what it names; never a prefix of a longer name", () => {
  assert.equal(valueKeyMatches("STRIPE_KEY", "STRIPE_KEY"), true);
  assert.equal(valueKeyMatches("STRIPE_KEY", "STRIPE_KEY.encoded"), true, "the file's own spelling of the value");
  assert.equal(valueKeyMatches("DATABASE_URL", "DATABASE_URL.password"), true, "a part of the value it names");
  assert.equal(valueKeyMatches("STRIPE", "STRIPE_KEY"), false, "not a prefix of a longer name");
  assert.equal(valueKeyMatches("STRIPE_KEY", "STRIPE_KEY_2"), false);
  assert.equal(valueKeyMatches("AWS_*", "AWS_SECRET_ACCESS_KEY"), true);
  assert.equal(valueKeyMatches("AWS_*", "XAWS_KEY"), false, "anchored");
  assert.equal(valueKeyMatches("*.aws_secret_access_key", "default.aws_secret_access_key"), true);
  assert.equal(valueKeyMatches("stripe_key", "STRIPE_KEY"), false, "case-sensitive, as a variable's name is");
  assert.equal(valueKeyMatches("A.B", "AxB"), false, "a dot is literal");
  assert.equal(valueKeyMatches("bad key", "bad key"), false, "a key with a space names nothing");
});

test("a value's release: its matching entries' intersection, else the file's; several values in one symbol: every one must allow it", () => {
  const values = compileValueRules({ ...VALUES, AWS_SECRET_ACCESS_KEY: { bindings: ["amazonaws.com", "evil.example"] } })!;
  assert.deepEqual(oneValueBindings(["files.example"], values, "STRIPE_KEY"), ["api.stripe.com"]);
  assert.deepEqual(oneValueBindings(["files.example"], values, "DEBUG"), ["files.example"], "no entry: the file's bindings");
  assert.deepEqual(oneValueBindings([], values, "AWS_SECRET_ACCESS_KEY"), ["amazonaws.com"],
    "two matching entries: a more specific key never widens the broader one (evil.example is in only one)");
  assert.deepEqual(valueBindings([], values, ["STRIPE_KEY", "AWS_ACCESS_KEY_ID"]), [], "a merged span holding both: nowhere");
  assert.deepEqual(valueBindings(["x.example"], values, null), [], "names unknown: the whole file's");
  assert.deepEqual(valueBindings(["x.example"], undefined, ["STRIPE_KEY"]), ["x.example"], "no values: the file's bindings, as before");
});

test("the whole file: the file's bindings and every entry's at once (plan 13 D1 inside one file)", () => {
  const values = compileValueRules(VALUES)!;
  assert.deepEqual(wholeFileBindings([], values), [], "the plan's example: nowhere without asking");
  assert.deepEqual(wholeFileBindings(["*.amazonaws.com", "api.stripe.com"], compileValueRules({ "AWS_*": { bindings: ["s3.amazonaws.com", "api.stripe.com"] } })),
    ["api.stripe.com", "s3.amazonaws.com"], "a narrower host inside a wildcard is kept");
  assert.deepEqual(wholeFileBindings(["a.example"], undefined), ["a.example"]);
});

test("holderFileBindings: a whole-file holder gets the label's bindings and only the hosts Mandu added, never a value's own", () => {
  const values = compileValueRules(VALUES)!;
  const label = { bindings: [], values, fileBindings: [] };
  assert.deepEqual(holderFileBindings(label, ["api.stripe.com", "amazonaws.com", "registry.npmjs.org"]), ["registry.npmjs.org"],
    "the field rows' per-value hosts are dropped; an auto host (a wire grant) stays");
  assert.deepEqual(holderFileBindings({ bindings: ["a.example"] }, ["b.example"]), ["a.example", "b.example"], "no values: unchanged");
});

// ── validator, compiler, resolver ───────────────────────────────────────────

const doc = (entry: Record<string, unknown>): PolicyFileConfig => ({ version: 1, paths: [{ path: "/home/u/ws/.env", level: "no-model", ...entry }] } as PolicyFileConfig);

test("the validator accepts values: and refuses each malformed shape", () => {
  assert.deepEqual(validatePolicyDocument(doc({ values: VALUES })), []);
  assert.deepEqual(validatePolicyDocument(doc({ level: "public", values: VALUES })), [], "kept under public: it decides nothing there");
  const bad = (values: unknown, re: RegExp) => assert.match(validatePolicyDocument(doc({ values })).join("\n"), re, JSON.stringify(values));
  bad([{ STRIPE_KEY: ["api.stripe.com"] }], /values: must be a mapping of field names/);
  bad({}, /values: must be a mapping of field names/);
  bad({ "STRIPE KEY": { bindings: ["a"] } }, /a field name has no space or control character/);
  bad({ STRIPE_KEY: ["api.stripe.com"] }, /must be a mapping \{ bindings/);
  bad({ STRIPE_KEY: {} }, /bindings: required/);
  bad({ STRIPE_KEY: { bindings: "api.stripe.com" } }, /bindings: must be a list of strings/);
  bad({ STRIPE_KEY: { bindings: [""] } }, /must be a non-empty string/);
  bad({ STRIPE_KEY: { bindings: ["a"], level: "public" } }, /unknown key 'level'/);
});

test("the compiler keeps values:; the resolver answers the whole file's bindings and the declared ones beside them", () => {
  const c = compilePolicy({ specId: "claude-code", document: doc({ bindings: ["files.example"], values: VALUES }) });
  const l = c.pathLabels.get("/home/u/ws/.env")!;
  assert.deepEqual(l.values, [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }, { key: "AWS_*", bindings: ["amazonaws.com"] }]);
  assert.deepEqual(l.bindings, ["files.example"], "the document's own bindings, as written");
  const d = resolvePathLabel("/home/u/ws/.env", c.pathLabels)!;
  assert.deepEqual(d.bindings, [], "the whole file: files.example ∩ api.stripe.com ∩ amazonaws.com");
  assert.deepEqual(d.fileBindings, ["files.example"]);
  assert.deepEqual(d.values, l.values);
  const plain = compilePolicy({ specId: "claude-code", document: doc({ bindings: ["files.example"] }) });
  const p = resolvePathLabel("/home/u/ws/.env", plain.pathLabels)!;
  assert.deepEqual(p.bindings, ["files.example"]);
  assert.equal(p.values, undefined, "no values: the decision is as before");
  assert.deepEqual(valueRulesToDocument(l.values!), VALUES, "round-trips to the document form");
});

test("a copy made from a file with values: holds it whole (its sources' whole-file bindings), and carries no values of its own", () => {
  const c = compilePolicy({ specId: "claude-code", document: { version: 1, paths: [
    { path: "/home/u/ws/.env", level: "no-model", values: VALUES },
    { path: "/home/u/out", level: "no-model", bindings: ["api.stripe.com"], values: { STRIPE_KEY: { bindings: ["api.stripe.com"] } } },
  ] } as PolicyFileConfig });
  const derived = new Map([["/home/u/out/copy.txt", { path: "/home/u/out/copy.txt", confidentiality: "no-model" as const, bindings: [], sessionKey: "s", tool: null, sources: ["/home/u/ws/.env"], createdAt: 0, updatedAt: 0 }]]);
  const d = composedLabel("/home/u/out/copy.txt", { human: c.pathLabels, derived: derived as never, clientKeys: [] }, { sourceBindings: () => ["api.stripe.com", "amazonaws.com"] })!;
  assert.deepEqual(d.bindings, [], "the source held whole may go nowhere; its field rows' per-value hosts are not the copy's");
  assert.equal(d.values, undefined, "the ancestor's values: do not apply to a copy");
  assert.equal(d.fileBindings, undefined);
  // A file a high session wrote (sources unknown) under a label with values:
  // its fields may hold any secret the session read, so no value's hosts.
  const written = new Map([["/home/u/out/new.env", { path: "/home/u/out/new.env", confidentiality: "no-model" as const, bindings: [], sessionKey: "s", tool: "Write", sources: null, createdAt: 0, updatedAt: 0 }]]);
  const w = composedLabel("/home/u/out/new.env", { human: c.pathLabels, derived: written as never, clientKeys: [] })!;
  assert.equal(w.values, undefined, "no per-value widening for a written file");
  assert.deepEqual(w.bindings, ["api.stripe.com"], "the ancestor's whole-file bindings stay");
  // The same ancestor on a file nobody wrote: its values apply.
  assert.ok(composedLabel("/home/u/out/real.env", { human: c.pathLabels, derived: written as never, clientKeys: [] })!.values);
});

// ── policyDelta ─────────────────────────────────────────────────────────────

function delta(before: Record<string, unknown>, after: Record<string, unknown>) {
  return policyDelta(compilePolicy({ specId: "claude-code", document: doc(before) }), compilePolicy({ specId: "claude-code", document: doc(after) }));
}

test("policyDelta: a binding added to a value is a relaxation; one removed is a tightening; a key added or removed is a relaxation", () => {
  const added = delta({ values: VALUES }, { values: { ...VALUES, STRIPE_KEY: { bindings: ["api.stripe.com", "hooks.slack.com"] } } });
  assert.equal(added.relaxations.length, 1);
  assert.match(added.relaxations[0]!.detail, /STRIPE_KEY in \/home\/u\/ws\/\.env is bound to hooks\.slack\.com on its own/);
  assert.equal(added.tightenings.length, 0);

  const removed = delta({ values: VALUES }, { values: { ...VALUES, STRIPE_KEY: { bindings: [] } } });
  assert.deepEqual(removed.relaxations, []);
  assert.match(removed.tightenings[0]!.detail, /no longer released to STRIPE_KEY: api\.stripe\.com/);

  const newKey = delta({ values: VALUES }, { values: { ...VALUES, GITHUB_TOKEN: { bindings: ["api.github.com"] } } });
  assert.match(newKey.relaxations[0]!.detail, /GITHUB_TOKEN in .* is bound to api\.github\.com on its own/);

  const dropKey = delta({ bindings: ["files.example"], values: VALUES }, { bindings: ["files.example"], values: { "AWS_*": VALUES["AWS_*"] } });
  assert.match(dropKey.relaxations[0]!.detail, /STRIPE_KEY in .* now goes where the file may \(files\.example\)/, "its value falls back to the file's, which may be wider");

  const firstValues = delta({}, { values: VALUES });
  assert.ok(firstValues.relaxations.length >= 1, "values: added to a lock: a relaxation");

  assert.deepEqual(delta({ values: VALUES }, { values: { "AWS_*": VALUES["AWS_*"], STRIPE_KEY: VALUES.STRIPE_KEY } }), { relaxations: [], tightenings: [] }, "order is not meaning");

  const plain = delta({ values: VALUES }, {});
  assert.deepEqual(plain.relaxations, [], "becoming plain strict drops every value's hosts: a tightening");

  // A new lock carrying values is no plain strict lock.
  const fresh = policyDelta(compilePolicy({ specId: "claude-code", document: { version: 1 } }), compilePolicy({ specId: "claude-code", document: doc({ values: VALUES }) }));
  assert.match(fresh.relaxations[0]!.detail, /only a plain strict lock \(no bindings, values, readers, others or extract\) is provably tighter/);
});

// ── the save path ───────────────────────────────────────────────────────────

test("lock-path (the dashboard's save) keeps values: at every level, as it keeps readers, others and extract", () => {
  const before = doc({ bindings: ["files.example"], values: VALUES, readers: ["ssh-add"], others: "twin" });
  for (const level of ["any-model", "no-model", "public"]) {
    const r = applyEdits(before, [{ op: "lock-path", path: "/home/u/ws/.env", level, bindings: ["other.example"] }]);
    assert.ok(r.ok, JSON.stringify(r));
    const e = r.document.paths![0]!;
    assert.deepEqual(e.values, VALUES, `values kept at ${level}`);
    assert.deepEqual(e.bindings, ["other.example"]);
    assert.deepEqual(e.readers, ["ssh-add"]);
  }
});

// ── the registry rows and the egress gate ───────────────────────────────────

function gate(map: SymbolMap, symbol: string, host: string): string {
  const d = decideDesymbolization(
    { symbol, boundary: "network", destination: host },
    (n) => getSymbolEntry(map, n) ?? undefined,
    () => false,
    { confidentiality: true },
  );
  return d.ruleRef?.id ?? (d.allow ? "allow" : "deny");
}

function withEnv(values: unknown, fn: (env: string, map: SymbolMap, dbPath: string, lookup: LabelLookup, setValues: (v: unknown) => void) => void, fileBindings: string[] = []): void {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pervalue-"));
  try {
    const env = join(dir, ".env");
    writeFileSync(env, ENV_TEXT);
    let labels = compilePolicy({ specId: "claude-code", document: { version: 1, paths: [{ path: env, level: "no-model", bindings: fileBindings, ...(values ? { values } : {}) }] } as PolicyFileConfig }).pathLabels;
    const lookup: LabelLookup = (p) => resolvePathLabel(p, labels);
    const setValues = (v: unknown) => {
      labels = compilePolicy({ specId: "claude-code", document: { version: 1, paths: [{ path: env, level: "no-model", bindings: fileBindings, ...(v ? { values: v } : {}) }] } as PolicyFileConfig }).pathLabels;
    };
    const dbPath = join(dir, "symbols.db");
    fn(env, loadSymbolMap(dbPath), dbPath, lookup, setValues);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a value's symbol is released at its own hosts, and no other value's is; the whole-file row goes nowhere", () => {
  withEnv(VALUES, (env, map, dbPath, lookup) => {
    const r = registerSecret(map, { path: env, resolveLabel: lookup }, dbPath);
    assert.ok(r.symbol, r.reason);
    const stripe = `${r.symbol}.STRIPE_KEY`;
    const awsId = `${r.symbol}.AWS_ACCESS_KEY_ID`;
    const awsSecret = `${r.symbol}.AWS_SECRET_ACCESS_KEY`;
    const db = `${r.symbol}.DATABASE_URL.password`;
    assert.deepEqual(getSymbolEntry(map, stripe)?.bindings, ["api.stripe.com"], "from its first registration");
    assert.deepEqual(getSymbolEntry(map, awsSecret)?.bindings, ["amazonaws.com"]);
    assert.equal(getSymbolEntry(map, db)?.bindings, null, "no entry: the file's bindings (none)");
    assert.equal(getSymbolEntry(map, r.symbol!)?.bindings, null, "the whole-file row: the intersection, nowhere");

    assert.equal(gate(map, stripe, "api.stripe.com"), "egress:secret-bound-trusted", "STRIPE_KEY at its host");
    assert.equal(gate(map, awsSecret, "api.stripe.com"), "egress:secret-unbound", "the AWS key is NOT released at Stripe");
    assert.equal(gate(map, awsId, "api.stripe.com"), "egress:secret-unbound");
    assert.equal(gate(map, awsSecret, "s3.amazonaws.com"), "egress:secret-bound-trusted", "the AWS key at its own host");
    assert.equal(gate(map, stripe, "s3.amazonaws.com"), "egress:secret-unbound", "the Stripe key is NOT released at AWS");
    assert.equal(gate(map, db, "api.stripe.com"), "egress:secret-unbound");
    assert.equal(gate(map, r.symbol!, "api.stripe.com"), "egress:secret-unbound", "the whole file is released at neither");
    assert.equal(gate(map, r.symbol!, "s3.amazonaws.com"), "egress:secret-unbound");

    // The user's own binding, not a wire grant: the gate need not confine it
    // to the Authorization header.
    assert.equal(releaseRestsOnWireGrant(map, stripe, "api.stripe.com", { resolveLabel: lookup }), false);
    // Persisted: a restarted arbiter reads the same.
    assert.deepEqual(getSymbolEntry(loadSymbolMap(dbPath), stripe)?.bindings, ["api.stripe.com"]);
  });
});

test("the values follow the law in force: a value's binding removed stops releasing at once; values: removed falls back to the file's", () => {
  withEnv(VALUES, (env, map, dbPath, lookup, setValues) => {
    const r = registerSecret(map, { path: env, resolveLabel: lookup }, dbPath);
    const stripe = `${r.symbol}.STRIPE_KEY`;
    setValues({ ...VALUES, STRIPE_KEY: { bindings: [] } });
    syncCurrentBindings(map, { resolveLabel: lookup }, dbPath);
    assert.equal(gate(map, stripe, "api.stripe.com"), "egress:secret-unbound", "a removed value binding no longer releases");
    setValues(null);
    syncCurrentBindings(map, { resolveLabel: lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, stripe)?.bindings, ["files.example"], "no values: the file's bindings, for every value");
    assert.deepEqual(getSymbolEntry(map, r.symbol!)?.bindings, ["files.example"]);
  }, ["files.example"]);
});

test("fail-closed: a field row whose names cannot be read back (its base row's text gone) takes the whole file's bindings", () => {
  withEnv(VALUES, (env, map, dbPath, lookup) => {
    const r = registerSecret(map, { path: env, resolveLabel: lookup }, dbPath);
    const stripe = `${r.symbol}.STRIPE_KEY`;
    // The base row no longer parses to that field (as a row of an older
    // extractor, or a corrupt cell): the field's value names are unknown.
    getSymbolEntry(map, r.symbol!)!.value = "not a dotenv file at all";
    syncCurrentBindings(map, { resolveLabel: lookup }, dbPath);
    assert.equal(getSymbolEntry(map, stripe)?.bindings, null, "the whole file's: nowhere, never STRIPE_KEY's host");
    assert.equal(gate(map, stripe, "api.stripe.com"), "egress:secret-unbound");
  }, ["files.example", "api.stripe.com"]);
});

test("a value with no entry takes the file's bindings; a key matching nothing only narrows the whole file", () => {
  withEnv({ STRIPE_KEY: { bindings: ["api.stripe.com"] }, NOT_IN_FILE: { bindings: [] } }, (env, map, dbPath, lookup) => {
    const r = registerSecret(map, { path: env, resolveLabel: lookup }, dbPath);
    assert.deepEqual(getSymbolEntry(map, `${r.symbol}.AWS_ACCESS_KEY_ID`)?.bindings, ["files.example"]);
    assert.deepEqual(getSymbolEntry(map, `${r.symbol}.STRIPE_KEY`)?.bindings, ["api.stripe.com"]);
    assert.equal(getSymbolEntry(map, r.symbol!)?.bindings, null, "files.example ∩ api.stripe.com ∩ ∅");
    assert.deepEqual(pathConfidentiality(env, undefined, lookup).bindings, []);
  }, ["files.example"]);
});

// ── a raw holder over IPC ───────────────────────────────────────────────────

test("a raw holder of a file with values: may send only where EVERY value may go (here nowhere), never one value's host", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-pervalue-ipc-"));
  const env = join(dir, ".env");
  writeFileSync(env, ENV_TEXT);
  const other = join(dir, "other.env");
  writeFileSync(other, `OTHER_KEY=sk_live_fake_PERVALUE_other99\n`);
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), humanSocketPath: join(dir, "human", "h.sock"), dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {},
    confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [
      { path: env, level: "no-model", readers: ["ssh-add"], values: VALUES },
      { path: other, level: "no-model", readers: ["ssh-add"], bindings: ["api.stripe.com", "s3.amazonaws.com"],
        values: { OTHER_KEY: { bindings: ["api.stripe.com", "s3.amazonaws.com"] } } },
    ] } as PolicyFileConfig,
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock"));
  await c.connect();
  try {
    assert.ok((await c.registerSecret({ path: env })).symbol);
    assert.ok((await c.registerSecret({ path: other })).symbol);
    assert.equal((await c.decideSecretOpen({ path: env, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "pv-sh-1", parentKey: "pv-agent-0" })).verdict, "raw");
    const b = await c.taintedProcessBindings({ procKey: "pv-sh-1" });
    assert.equal(b.tainted, true);
    assert.deepEqual(b.bindings, [], "the whole file: api.stripe.com ∩ amazonaws.com is empty; the field rows' own hosts do not count");
    // A file whose every value and itself share hosts: the holder keeps them.
    assert.equal((await c.decideSecretOpen({ path: other, exe: "/usr/bin/ssh-add", isAgent: false, exeSystem: true, openerEnv: [], procKey: "pv-sh-2", parentKey: "pv-agent-0" })).verdict, "raw");
    assert.deepEqual((await c.taintedProcessBindings({ procKey: "pv-sh-2" })).bindings, ["api.stripe.com", "s3.amazonaws.com"]);
    // `pathLevels` (the Rules page) says both.
    const lv = (await c.pathLevels([env])).levels[0]!;
    assert.deepEqual(lv.bindings, []);
    assert.deepEqual(lv.values, [{ key: "STRIPE_KEY", bindings: ["api.stripe.com"] }, { key: "AWS_*", bindings: ["amazonaws.com"] }]);
    assert.deepEqual(lv.fileBindings, []);
  } finally {
    c.close();
    await s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
