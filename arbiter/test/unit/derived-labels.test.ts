/**
 * derived-labels.test — the ON-DISK label a HIGH session's write leaves behind
 * (Plan 9, confidentiality.md §4/§8).
 *
 * The pure oracles. Two rules carry the whole design, and both are here:
 *
 *   1. A derived label RAISES; it never lowers. A machine may taint, never
 *      declassify — otherwise a `model-ok` session writing `~/.ssh/id_ed25519`
 *      would mint a `model-ok` label on a path the catalog calls a KEY.
 *   2. An EXACT human label beats it, in either direction (§8's first-class
 *      declassification). An ANCESTOR label does not — a bulk default is not a
 *      decision about the artifact.
 *
 * The stateful half (the op, the cross-session read) is derived-label-ops.test.ts.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DerivedLabelStore,
  resolveDerivedLabel,
  resolveWithDerived,
  type DerivedLabel,
} from "../../policy/derived-labels.js";
import type { PathLabel } from "../../policy/path-labels.js";
import { pathConfidentiality } from "../../policy/secret-catalog.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";

const HOME = "/home/u";

function humanLabels(...rows: Array<Partial<PathLabel> & { path: string }>): Map<string, PathLabel> {
  const m = new Map<string, PathLabel>();
  for (const r of rows) {
    m.set(r.path, {
      path: r.path,
      confidentiality: r.confidentiality ?? "no-model",
      bindings: r.bindings ?? [],
      recursive: r.recursive ?? true,
      source: r.source ?? "user",
      updatedAt: r.updatedAt ?? 1,
    });
  }
  return m;
}

function derivedLabels(
  ...rows: Array<{ path: string; level: ConfidentialityLevel; bindings?: string[] }>
): Map<string, DerivedLabel> {
  const m = new Map<string, DerivedLabel>();
  for (const r of rows) {
    m.set(r.path, {
      path: r.path,
      confidentiality: r.level,
      bindings: r.bindings ?? [],
      sessionKey: "sess-A",
      tool: "Write",
      sources: null,
      createdAt: 1,
      updatedAt: 1,
    });
  }
  return m;
}

/** The lookup the arbiter server hands every confidentiality derivation. */
function lookup(human: Map<string, PathLabel>, derived: Map<string, DerivedLabel>) {
  return (p: string) => resolveWithDerived(p, human, derived, HOME);
}

// ── The composition ─────────────────────────────────────────────────────────

test("no derived row ⇒ byte-identical to the pre-Plan-9 answer", () => {
  const human = humanLabels({ path: "/home/u/docs", confidentiality: "any-model" });
  const none = derivedLabels();
  assert.equal(resolveWithDerived("/home/u/docs/a.md", human, none, HOME)?.level, "any-model");
  assert.equal(resolveWithDerived("/home/u/other/a.md", human, none, HOME), null);
});

test("a derived row on an unlabeled path RAISES the (public) catalog default", () => {
  const derived = derivedLabels({ path: "/home/u/notes/summary.md", level: "any-model" });
  const m = pathConfidentiality(
    "/home/u/notes/summary.md", HOME, lookup(humanLabels(), derived),
  );
  assert.equal(m.level, "any-model");
  assert.equal(m.rule, "derived:/home/u/notes/summary.md");
});

test("THE HOLE THAT WOULD HAVE BEEN: a derived model-ok row NEVER lowers a strict catalog path", () => {
  // A high (model-ok) session writes ~/.ssh/id_ed25519. The catalog calls
  // that path no-model. If the derived row won, a MACHINE would have
  // declassified a key to "the model may read it".
  const derived = derivedLabels({ path: "/home/u/.ssh/id_ed25519", level: "any-model" });
  const m = pathConfidentiality(
    "/home/u/.ssh/id_ed25519", HOME, lookup(humanLabels(), derived),
  );
  assert.equal(m.level, "no-model");
  assert.equal(m.rule, "prefix:~/.ssh");
});

test("a derived row never lowers a HUMAN ancestor label either", () => {
  const human = humanLabels({ path: "/home/u/vault", confidentiality: "no-model" });
  const derived = derivedLabels({ path: "/home/u/vault/out.md", level: "any-model" });
  const m = pathConfidentiality("/home/u/vault/out.md", HOME, lookup(human, derived));
  assert.equal(m.level, "no-model");
  assert.equal(m.rule, "label:/home/u/vault");
});

test("a derived row RAISES a human ancestor label that is weaker — and the catalog stays overridden", () => {
  // ~/fixtures is a human `public` override of a catalog-secret shape. A high
  // session writes ~/fixtures/.env. The taint raises it to model-ok — but the
  // CATALOG (which would say no-model for a `.env`) must NOT come back: the
  // human already spoke about this subtree, and re-imposing the catalog on top of
  // the taint would silently un-do their override.
  const human = humanLabels({ path: "/home/u/fixtures", confidentiality: "public" });
  const derived = derivedLabels({ path: "/home/u/fixtures/.env", level: "any-model" });
  const m = pathConfidentiality("/home/u/fixtures/.env", HOME, lookup(human, derived));
  assert.equal(m.level, "any-model");
  assert.equal(m.rule, "derived:/home/u/fixtures/.env");
});

test("§8 RELEASE: an EXACT human label beats the derived row — including a `public` one", () => {
  // The declassification act: the human looked at THIS artifact and released it.
  const human = humanLabels({ path: "/home/u/notes/summary.md", confidentiality: "public" });
  const derived = derivedLabels({ path: "/home/u/notes/summary.md", level: "any-model" });
  const m = pathConfidentiality("/home/u/notes/summary.md", HOME, lookup(human, derived));
  assert.equal(m.level, "public");
  assert.equal(m.rule, "label:/home/u/notes/summary.md");
});

test("an ANCESTOR `public` label does NOT release a derived file under it", () => {
  // The counterpart to the test above, and the reason the rule is EXACT-match: a
  // bulk default on a directory must not silently release every secret-derived
  // file a high session ever drops into it.
  const human = humanLabels({ path: "/home/u/notes", confidentiality: "public" });
  const derived = derivedLabels({ path: "/home/u/notes/summary.md", level: "any-model" });
  const m = pathConfidentiality("/home/u/notes/summary.md", HOME, lookup(human, derived));
  assert.equal(m.level, "any-model");
});

test("derived labels do NOT inherit: a taint on one file never touches its siblings", () => {
  const derived = derivedLabels({ path: "/home/u/notes/summary.md", level: "any-model" });
  assert.equal(resolveDerivedLabel("/home/u/notes/other.md", derived, HOME), null);
  assert.equal(
    pathConfidentiality("/home/u/notes/other.md", HOME, lookup(humanLabels(), derived)).level,
    "public",
  );
});

test("a derived verdict is bound NOWHERE — the taint carries the level, never a release", () => {
  // The store never mints bindings on a derived row (derived-labels.ts), so this
  // pins the OTHER half: a derived verdict that wins a composition must not hand a
  // future session a standing release. `[]` reads as "bound nowhere" everywhere in
  // the system — never as "anywhere".
  const derived = derivedLabels({ path: "/home/u/notes/summary.md", level: "any-model" });
  const m = pathConfidentiality("/home/u/notes/summary.md", HOME, lookup(humanLabels(), derived));
  assert.equal(m.level, "any-model");
  assert.deepEqual(m.bindings, []);
});

test("a HUMAN label's bindings survive a derived row that does NOT outrank it", () => {
  // The human granted `docs.corp` on ~/proj at model-ok; a model-ok write inside it
  // must not strip that grant (the human label still decides — max keeps it).
  const human = humanLabels({
    path: "/home/u/proj", confidentiality: "any-model", bindings: ["docs.corp"],
  });
  const derived = derivedLabels({ path: "/home/u/proj/out.md", level: "any-model" });
  const m = pathConfidentiality("/home/u/proj/out.md", HOME, lookup(human, derived));
  assert.equal(m.level, "any-model");
  assert.deepEqual(m.bindings, ["docs.corp"]);
});

// ── The store ───────────────────────────────────────────────────────────────

function withStore(fn: (s: DerivedLabelStore, dbPath: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "mdu-derived-"));
  const dbPath = join(dir, "symbols.sqlite");
  const store = new DerivedLabelStore({ dbPath });
  try {
    fn(store, dbPath);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

test("store: a write records the watermark, with the provenance §8 needs — and NO bindings", () => {
  withStore((s) => {
    const row = s.raise("/w/out.md", "any-model", { sessionKey: "sess-A", tool: "Write" });
    assert.equal(row?.confidentiality, "any-model");
    assert.equal(row?.sessionKey, "sess-A");
    assert.equal(row?.tool, "Write");
    // A machine may TAINT; it may not grant a RELEASE. Bindings are standing
    // release rules, and this row is not a human decision.
    assert.deepEqual(row?.bindings, []);
  });
});

test("store: MONOTONE — a later, LOWER write never lowers the row", () => {
  withStore((s) => {
    s.raise("/w/out.md", "no-model", { sessionKey: "sess-A" });
    // A public session overwriting the file does not clear the taint: we cannot
    // tell an overwrite from an append, so the label stands and the HUMAN clears
    // it. (A `public` level cannot even reach here — the op refuses to record for
    // a non-high session — but the store must hold the line on its own.)
    const row = s.raise("/w/out.md", "any-model", { sessionKey: "sess-B" });
    assert.equal(row?.confidentiality, "no-model");
  });
});

test("store: raising to a HIGHER level does raise it, and re-attributes provenance", () => {
  withStore((s) => {
    s.raise("/w/out.md", "any-model", { sessionKey: "sess-A", tool: "Write" });
    const row = s.raise("/w/out.md", "no-model", { sessionKey: "sess-B", tool: "Edit" });
    assert.equal(row?.confidentiality, "no-model");
    assert.equal(row?.sessionKey, "sess-B"); // the newest bytes' provenance
    assert.equal(row?.tool, "Edit");
  });
});

test("store: a relative path has no stable identity — refused, not guessed", () => {
  withStore((s) => {
    assert.equal(s.raise("out.md", "any-model", { sessionKey: "sess-A" }), null);
    assert.equal(s.list().length, 0);
  });
});

test("store: survives a restart — the whole point (the watermark outlives the process)", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-derived-"));
  const dbPath = join(dir, "symbols.sqlite");
  try {
    const first = new DerivedLabelStore({ dbPath });
    first.raise("/w/out.md", "any-model", { sessionKey: "sess-A", tool: "Write" });
    first.close();

    const second = new DerivedLabelStore({ dbPath });
    const row = resolveDerivedLabel("/w/out.md", second.map());
    assert.equal(row?.confidentiality, "any-model");
    assert.equal(row?.sessionKey, "sess-A");
    second.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("store: the human's CLEAR act removes the record (§8 declassification, blunt form)", () => {
  withStore((s) => {
    s.raise("/w/out.md", "any-model", { sessionKey: "sess-A" });
    assert.equal(s.remove("/w/out.md"), true);
    assert.equal(s.remove("/w/out.md"), false);
    assert.equal(
      pathConfidentiality("/w/out.md", HOME, lookup(humanLabels(), new Map())).level,
      "public",
    );
  });
});
