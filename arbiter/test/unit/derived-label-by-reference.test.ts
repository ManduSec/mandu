/**
 * derived-label-by-reference.test.ts — confidentiality plan 13 §4.6: a file a
 * process holding secrets wrote refers to its sources' labels,
 * `Release(copy) = ∩ Release(source)`, evaluated when checked.
 *
 * Before (plan 13 D4 as built): a derived copy carried no bindings at all, so
 * a program a human let read the copy raw could reach only the session's
 * proxies, even where every source was bound to the destination; and a
 * source's level raised after the copy was made did not reach the copy.
 * Asserted here:
 *
 *   - one source: the copy goes where the source goes; two: only where both
 *     go (the intersection, D1's join); a source bound nowhere empties it;
 *   - by reference: a binding revoked on a source leaves the copy at once; a
 *     source raised to a stricter level raises the copy; a source lowered
 *     never lowers the copy below its own row;
 *   - fail-closed: unknown sources (a high session's write) stay bound
 *     nowhere; a source that no longer classifies secret contributes
 *     nothing; a cycle of copies is bound nowhere; a copy of a copy follows
 *     the chain;
 *   - an exact human label on the copy decides alone; an ancestor human
 *     label's destinations are intersected with the sources';
 *   - the registry's rows for a source count (`sourceBindings`);
 *   - over a real ArbiterServer: a program the human let read a reader's
 *     copy raw may send it where both sources may go (`taintedProcessBindings`),
 *     and nowhere when one source is bound nowhere.
 *
 * The e2e under the real guard and arbiter is
 * launcher/test/derived-label-live.test.sh steps (7)-(8).
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
import type { DerivedLabel } from "../../policy/derived-labels.js";
import { composedLabel, snapshotLookup, type LabelSnapshot } from "../../policy/label-lookup.js";
import type { PathLabel } from "../../policy/path-labels.js";
import { pathConfidentiality } from "../../policy/secret-catalog.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets"); // the confidentiality axis: where a copy of a secret may be sent

const A = "/srv/plan13/a.secret";
const B = "/srv/plan13/b.secret";
const COPY = "/srv/out/copy.txt";

function human(...rows: Array<{ path: string; level?: ConfidentialityLevel; bindings?: string[]; recursive?: boolean }>): Map<string, PathLabel> {
  return new Map(rows.map((r) => [r.path, {
    path: r.path, confidentiality: r.level ?? "no-model", bindings: r.bindings ?? [],
    recursive: r.recursive ?? false, source: "user" as const, updatedAt: 1,
  }]));
}

function derived(...rows: Array<{ path: string; level?: ConfidentialityLevel; sources: string[] | null }>): Map<string, DerivedLabel> {
  return new Map(rows.map((r) => [r.path, {
    path: r.path, confidentiality: r.level ?? "no-model", bindings: [], sessionKey: "s", tool: "process",
    sources: r.sources, createdAt: 1, updatedAt: 1,
  }]));
}

function snap(h: Map<string, PathLabel>, d: Map<string, DerivedLabel>): LabelSnapshot {
  return { human: h, derived: d, clientKeys: [] };
}

test("one source: the copy goes where its source goes (before: nowhere)", () => {
  const s = snap(human({ path: A, bindings: ["api.stripe.com"] }), derived({ path: COPY, sources: [A] }));
  const l = composedLabel(COPY, s);
  assert.equal(l?.origin, "derived");
  assert.equal(l?.level, "no-model");
  assert.deepEqual(l?.bindings, ["api.stripe.com"]);
  // and so does every caller that classifies through the lookup
  assert.deepEqual(pathConfidentiality(COPY, undefined, snapshotLookup(s)).bindings, ["api.stripe.com"]);
});

test("two sources: only where both may go (the intersection); a source bound nowhere empties it", () => {
  const h = human({ path: A, bindings: ["api.stripe.com", "hooks.slack.com"] }, { path: B, bindings: ["api.stripe.com", "*.amazonaws.com"] });
  assert.deepEqual(composedLabel(COPY, snap(h, derived({ path: COPY, sources: [A, B] })))?.bindings, ["api.stripe.com"]);
  const h2 = human({ path: A, bindings: ["api.stripe.com"] }, { path: B, bindings: [] });
  assert.deepEqual(composedLabel(COPY, snap(h2, derived({ path: COPY, sources: [A, B] })))?.bindings, [], "the union this refuses would send B's bytes to Stripe");
  // a wildcard keeps the narrower host below it (D1's rule)
  const h3 = human({ path: A, bindings: ["*.amazonaws.com"] }, { path: B, bindings: ["s3.amazonaws.com"] });
  assert.deepEqual(composedLabel(COPY, snap(h3, derived({ path: COPY, sources: [A, B] })))?.bindings, ["s3.amazonaws.com"]);
});

test("by reference: a binding revoked on a source leaves the copy at once; a raised source raises the copy; a lowered one never lowers it", () => {
  const d = derived({ path: COPY, level: "any-model", sources: [A] });
  assert.deepEqual(composedLabel(COPY, snap(human({ path: A, level: "any-model", bindings: ["x.example", "y.example"] }), d))?.bindings, ["x.example", "y.example"]);
  const revoked = composedLabel(COPY, snap(human({ path: A, level: "any-model", bindings: ["y.example"] }), d));
  assert.deepEqual(revoked?.bindings, ["y.example"], "the revoked x.example is gone from the copy too");
  const raised = composedLabel(COPY, snap(human({ path: A, level: "no-model", bindings: ["y.example"] }), d));
  assert.equal(raised?.level, "no-model", "the source raised to no-model raises its copy");
  const lowered = composedLabel(COPY, snap(human({ path: A, level: "any-model", bindings: ["y.example"] }), derived({ path: COPY, level: "no-model", sources: [A] })));
  assert.equal(lowered?.level, "no-model", "a machine row is a floor: a lower source never lowers it");
});

test("fail-closed: unknown sources stay bound nowhere; a source no longer secret contributes nothing", () => {
  const h = human({ path: A, bindings: ["api.stripe.com"] });
  assert.deepEqual(composedLabel(COPY, snap(h, derived({ path: COPY, sources: null })))?.bindings, [], "a high session's write (Plan 9): unknown sources");
  assert.deepEqual(composedLabel(COPY, snap(h, derived({ path: COPY, sources: [] })))?.bindings, []);
  // the source's label removed: it classifies public now (no catalog match)
  const gone = composedLabel(COPY, snap(human(), derived({ path: COPY, sources: [A] })));
  assert.equal(gone?.level, "no-model", "the copy keeps its own level");
  assert.deepEqual(gone?.bindings, [], "a source whose label is gone is bound nowhere, never everywhere");
  // lowered to public by an exact human label: the same
  const pub = composedLabel(COPY, snap(human({ path: A, level: "public", bindings: ["api.stripe.com"] }), derived({ path: COPY, sources: [A] })));
  assert.deepEqual(pub?.bindings, []);
});

test("a copy of a copy follows the chain; a cycle of copies is bound nowhere", () => {
  const COPY2 = "/srv/out/copy2.txt";
  const h = human({ path: A, bindings: ["api.stripe.com"] }, { path: B, bindings: ["api.stripe.com"] });
  assert.deepEqual(composedLabel(COPY2, snap(h, derived({ path: COPY, sources: [A] }, { path: COPY2, sources: [COPY, B] })))?.bindings, ["api.stripe.com"]);
  const cyc = derived({ path: COPY, sources: [COPY2, A] }, { path: COPY2, sources: [COPY] });
  assert.deepEqual(composedLabel(COPY, snap(h, cyc))?.bindings, []);
  assert.deepEqual(composedLabel(COPY2, snap(h, cyc))?.bindings, []);
  // a chain deeper than the bound is bound nowhere
  const chain = new Map<string, DerivedLabel>();
  let prev = A;
  for (let i = 0; i < 12; i++) {
    const p = `/srv/out/c${i}.txt`;
    chain.set(p, { path: p, confidentiality: "no-model", bindings: [], sessionKey: "s", tool: "process", sources: [prev], createdAt: 1, updatedAt: 1 });
    prev = p;
  }
  assert.deepEqual(composedLabel("/srv/out/c2.txt", snap(h, chain))?.bindings, ["api.stripe.com"]);
  assert.deepEqual(composedLabel("/srv/out/c11.txt", snap(h, chain))?.bindings, []);
});

test("an exact human label on the copy decides alone; an ancestor human label is intersected with the sources", () => {
  const exact = human({ path: A, bindings: ["api.stripe.com"] }, { path: COPY, level: "no-model", bindings: ["smtp.example"] });
  const e = composedLabel(COPY, snap(exact, derived({ path: COPY, sources: [A] })));
  assert.notEqual(e?.origin, "derived");
  assert.deepEqual(e?.bindings, ["smtp.example"], "the release act on the artifact is the human's");
  // ~/out is a folder the human labelled no-model, bound to two hosts; the
  // copy of A lands there: only the host A may go to as well survives
  const folder = human({ path: A, level: "any-model", bindings: ["api.stripe.com"] }, { path: "/srv/out", level: "no-model", bindings: ["api.stripe.com", "smtp.example"], recursive: true });
  const f = composedLabel(COPY, snap(folder, derived({ path: COPY, level: "any-model", sources: [A] })));
  assert.equal(f?.level, "no-model");
  assert.deepEqual(f?.bindings, ["api.stripe.com"], "before: the folder's smtp.example too, a host the source may never reach");
});

test("the registry's rows for a source count, as for a holder of the source itself", () => {
  const s = snap(human({ path: A, bindings: [] }), derived({ path: COPY, sources: [A] }));
  assert.deepEqual(composedLabel(COPY, s)?.bindings, []);
  assert.deepEqual(composedLabel(COPY, s, { sourceBindings: (p) => (p === A ? ["registry.npmjs.org"] : []) })?.bindings, ["registry.npmjs.org"]);
});

// ── over IPC on a real ArbiterServer ─────────────────────────────────────────

test("a program the human let read a reader's copy may send it only where every source may go (taintedProcessBindings)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-ref-"));
  const a = join(dir, "a.env"); writeFileSync(a, "STRIPE_KEY=sk_live_REFCANARY000000001\n");
  const b = join(dir, "b.env"); writeFileSync(b, "OTHER_KEY=sk_live_REFCANARY000000002\n");
  const c0 = join(dir, "c.env"); writeFileSync(c0, "LOCAL_KEY=sk_live_REFCANARY000000003\n");
  const s = new ArbiterServer({
    socketPath: join(dir, "a.sock"), adminSocketPath: join(dir, "admin.sock"), humanSocketPath: join(dir, "human", "h.sock"),
    dbPath: join(dir, "db.sqlite"), eventDir: join(dir, "events"), log: () => {}, confidentiality: true, integrity: false,
    policyDocument: { version: 1, paths: [
      { path: a, level: "no-model", readers: ["ssh"], bindings: ["api.stripe.com", "hooks.slack.com"] },
      { path: b, level: "no-model", readers: ["ssh"], bindings: ["api.stripe.com"] },
      { path: c0, level: "no-model", readers: ["ssh"] },
    ] },
  });
  await s.listen();
  const c = new ArbiterClient(join(dir, "human", "h.sock")); // the guard's channel (plan 13 D9)
  const admin = new ArbiterClient(join(dir, "admin.sock"));
  await c.connect(); await admin.connect();
  const opener = { exe: "/usr/bin/ssh", sha256: "c".repeat(64), isAgent: false, exeSystem: true, openerEnv: [] as string[] };
  try {
    // ssh reads a and b raw and writes the copy: its derived label records both
    assert.equal((await c.decideSecretOpen({ path: a, ...opener, procKey: "ref-cp-1" })).verdict, "raw");
    assert.equal((await c.decideSecretOpen({ path: b, ...opener, procKey: "ref-cp-1" })).verdict, "raw");
    const copy = join(dir, "copy.txt");
    writeFileSync(copy, "STRIPE_KEY=sk_live_REFCANARY000000001\nOTHER_KEY=sk_live_REFCANARY000000002\n");
    assert.equal((await c.labelWrittenPathTainted({ path: copy, procKey: "ref-cp-1" })).labeled, true);
    // a program with no reader right to the copy asks; the human allows it once
    const curl = { exe: "/usr/bin/mytool", // a made-up leaf program (curl is a printer since the !437 leftover (1))
      sha256: "d".repeat(64), isAgent: false, exeSystem: true, openerEnv: [] as string[], ask: "always" as const };
    const held = await c.decideSecretOpen({ path: copy, ...curl, procKey: "ref-curl-2" });
    assert.equal(held.verdict, "ask", held.reason);
    await admin.resolveEgressApproval(held.approvalId!, true, "once");
    assert.equal((await c.decideSecretOpen({ path: copy, ...curl, procKey: "ref-curl-2" })).verdict, "raw");
    const t = await c.taintedProcessBindings({ procKey: "ref-curl-2" });
    assert.equal(t.tainted, true);
    assert.deepEqual(t.files, [copy]);
    assert.deepEqual(t.bindings, ["api.stripe.com"], "only the host both sources may go to (before: none)");
    // a copy of a and of c (bound nowhere) may go nowhere
    assert.equal((await c.decideSecretOpen({ path: c0, ...opener, procKey: "ref-cp-3" })).verdict, "raw");
    assert.equal((await c.decideSecretOpen({ path: a, ...opener, procKey: "ref-cp-3" })).verdict, "raw");
    const copy2 = join(dir, "copy2.txt");
    writeFileSync(copy2, "x\n");
    assert.equal((await c.labelWrittenPathTainted({ path: copy2, procKey: "ref-cp-3" })).labeled, true);
    const held2 = await c.decideSecretOpen({ path: copy2, ...curl, procKey: "ref-curl-4" });
    assert.equal(held2.verdict, "ask");
    await admin.resolveEgressApproval(held2.approvalId!, true, "once");
    assert.equal((await c.decideSecretOpen({ path: copy2, ...curl, procKey: "ref-curl-4" })).verdict, "raw");
    assert.deepEqual((await c.taintedProcessBindings({ procKey: "ref-curl-4" })).bindings, []);
    // openers are not inherited: ssh, a reader of both sources, gets the copy
    // only as a holder of them (D4), never by its reader entry
    assert.equal((await c.decideSecretOpen({ path: copy, ...opener, procKey: "ref-cp-5" })).verdict, "twin");
  } finally {
    c.close(); admin.close(); await s.close(); rmSync(dir, { recursive: true, force: true });
  }
});
