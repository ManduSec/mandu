/**
 * path-labels.test — the user labeling store (Plan 6, confidentiality.md §6).
 *
 * The two properties that matter:
 *   1. A user label is AUTHORITATIVE over the catalog (it is a DEFAULT), and a
 *      label BELOW the catalog's verdict is a declassification the surface must
 *      show — not something the store refuses.
 *   2. Inheritance is longest-SEGMENT-prefix. A raw string prefix would make
 *      `~/docs-public` inherit from `~/docs` — a silent mislabeling, which §6
 *      names as the failure that kills DLP deployments.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import DatabaseCtor from "../../db/sqlite.js";
import {
  PathLabelStore,
  resolvePathLabel,
  outrankedStricterPatterns,
  normalizeLabelPath,
  isPathPrefix,
  type PathLabel,
} from "../../policy/path-labels.js";

const HOME = "/home/u";

function labels(...rows: Array<Partial<PathLabel> & { path: string }>): Map<string, PathLabel> {
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

// ── the resolver (pure) ──────────────────────────────────────────────────────

test("an exact label wins over an ancestor's", () => {
  const m = labels(
    { path: "/home/u/docs", confidentiality: "any-model" },
    { path: "/home/u/docs/keys.txt", confidentiality: "no-model" },
  );
  assert.equal(resolvePathLabel("/home/u/docs/keys.txt", m, HOME)?.level, "no-model");
  assert.equal(resolvePathLabel("/home/u/docs/memo.md", m, HOME)?.level, "any-model");
});

test("the LONGEST ancestor wins — specificity, not restrictiveness", () => {
  // A public subtree carved out of a secret tree. If the most-RESTRICTIVE
  // ancestor won instead of the most SPECIFIC one, this would be impossible —
  // and carving an exception is the second thing every user needs.
  const m = labels(
    { path: "/home/u/private", confidentiality: "no-model" },
    { path: "/home/u/private/public-notes", confidentiality: "public" },
  );
  assert.equal(resolvePathLabel("/home/u/private/taxes.pdf", m, HOME)?.level, "no-model");
  assert.equal(resolvePathLabel("/home/u/private/public-notes/todo.md", m, HOME)?.level, "public");
});

test("SEGMENT boundary: ~/docs-public does NOT inherit from ~/docs", () => {
  // The bug a raw string prefix would introduce. It is silent: the file would
  // simply be secret, or (worse, with the levels reversed) simply not be.
  const m = labels({ path: "/home/u/docs", confidentiality: "no-model" });
  assert.equal(resolvePathLabel("/home/u/docs/a.txt", m, HOME)?.level, "no-model");
  assert.equal(resolvePathLabel("/home/u/docs-public/a.txt", m, HOME), null);
  assert.equal(resolvePathLabel("/home/u/docsomething", m, HOME), null);
});

test("a non-recursive label covers only itself", () => {
  const m = labels({ path: "/home/u/docs", confidentiality: "no-model", recursive: false });
  assert.equal(resolvePathLabel("/home/u/docs", m, HOME)?.level, "no-model");
  assert.equal(resolvePathLabel("/home/u/docs/a.txt", m, HOME), null);
});

test("`via` reports the label that decided, so an inherited label is never mistaken for a direct one", () => {
  const m = labels({ path: "/home/u/docs", confidentiality: "any-model" });
  assert.equal(resolvePathLabel("/home/u/docs/deep/a.md", m, HOME)?.via, "/home/u/docs");
});

test("no label ⇒ null ⇒ the caller falls through to the catalog (fail-closed default)", () => {
  assert.equal(resolvePathLabel("/home/u/.aws/credentials", labels(), HOME), null);
});

test("bindings ride the label, including through inheritance", () => {
  const m = labels({ path: "/home/u/keys", confidentiality: "no-model", bindings: ["api.example.com"] });
  assert.deepEqual(resolvePathLabel("/home/u/keys/prod.key", m, HOME)?.bindings, ["api.example.com"]);
});

// ── normalization ────────────────────────────────────────────────────────────

test("paths normalize: ~, trailing slash, ..", () => {
  assert.equal(normalizeLabelPath("~/docs", HOME), "/home/u/docs");
  assert.equal(normalizeLabelPath("~/docs/", HOME), "/home/u/docs");
  assert.equal(normalizeLabelPath("/home/u/docs/../keys", HOME), "/home/u/keys");
  assert.equal(normalizeLabelPath("~", HOME), "/home/u");
  // A relative path has no stable identity — it cannot be labeled.
  assert.equal(normalizeLabelPath("docs/a.txt", HOME), null);
  assert.equal(normalizeLabelPath("", HOME), null);
});

test("a store keyed by un-normalized paths would MISS, so ~/x and /home/u/x are the same key", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-labels-"));
  const store = new PathLabelStore({ dbPath: join(dir, "a.db") });
  try {
    store.set({ path: "~/docs/", confidentiality: "any-model" }, HOME);
    assert.equal(store.resolve("/home/u/docs/x.md", HOME)?.level, "any-model");
    assert.equal(store.list().length, 1);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("isPathPrefix is segment-aware", () => {
  assert.ok(isPathPrefix("/a/b", "/a/b"));
  assert.ok(isPathPrefix("/a/b", "/a/b/c"));
  assert.ok(!isPathPrefix("/a/b", "/a/bc"));
  assert.ok(!isPathPrefix("/a/b", "/a/b-x"));
});

// ── the store ────────────────────────────────────────────────────────────────

test("set/resolve/remove round-trip, and labels PERSIST across a restart", () => {
  const dir = mkdtempSync(join(tmpdir(), "mdu-labels-"));
  const dbPath = join(dir, "a.db");
  try {
    const s1 = new PathLabelStore({ dbPath });
    s1.set({ path: "/home/u/contracts", confidentiality: "any-model", bindings: ["docs.corp"] }, HOME);
    s1.close();

    // A label is security state — it must survive an arbiter restart, or the
    // next session silently reclassifies the file by catalog default.
    const s2 = new PathLabelStore({ dbPath });
    const d = s2.resolve("/home/u/contracts/q3.pdf", HOME);
    assert.equal(d?.level, "any-model");
    assert.deepEqual(d?.bindings, ["docs.corp"]);

    assert.ok(s2.remove("/home/u/contracts", HOME));
    assert.equal(s2.resolve("/home/u/contracts/q3.pdf", HOME), null);
    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("THE OVERRIDE: a user `public` label beats the catalog's no-model", () => {
  // The point of the store. `test/fixtures/.env` matches the catalog's `.env*`
  // shape, but it is a fixture. max(catalog, user) could not express this, which
  // is why the user label is authoritative — see the module header.
  const dir = mkdtempSync(join(tmpdir(), "mdu-labels-"));
  const store = new PathLabelStore({ dbPath: join(dir, "a.db") });
  try {
    store.set({ path: "/home/u/proj/test/fixtures/.env", confidentiality: "public" }, HOME);
    assert.equal(store.resolve("/home/u/proj/test/fixtures/.env", HOME)?.level, "public");
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an invalid labeling act is REJECTED, not coerced", () => {
  // A missing level must NOT become `public` (that would be an accidental
  // declassification) and a typo must not become `no-model` (that would
  // silently label the wrong thing). A labeling act is explicit or it is not an
  // act — the caller gets null and must say what it meant.
  const dir = mkdtempSync(join(tmpdir(), "mdu-labels-"));
  const store = new PathLabelStore({ dbPath: join(dir, "a.db") });
  try {
    assert.equal(store.set({ path: "/home/u/x", confidentiality: "moddel-ok" }, HOME), null);
    assert.equal(store.set({ path: "/home/u/y", confidentiality: undefined }, HOME), null);
    assert.equal(store.set({ path: "relative/p", confidentiality: "public" }, HOME), null);
    assert.equal(store.list().length, 0, "nothing invalid was stored");
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hydration of a CORRUPT row still fails closed to no-model", () => {
  // The store rejects bad input, but a hand-edited or newer-build DB row must
  // never degrade to `public` in an older build. Different question, different
  // answer: reject at the door, fail closed on what is already inside.
  const dir = mkdtempSync(join(tmpdir(), "mdu-labels-"));
  const dbPath = join(dir, "a.db");
  try {
    const s1 = new PathLabelStore({ dbPath });
    s1.set({ path: "/home/u/x", confidentiality: "public" }, HOME);
    s1.close();

    const raw = new DatabaseCtor(dbPath);
    raw.prepare("UPDATE path_labels SET confidentiality = ? WHERE path = ?")
      .run("level-from-the-future", "/home/u/x");
    raw.close();

    const s2 = new PathLabelStore({ dbPath });
    assert.equal(s2.resolve("/home/u/x", HOME)?.level, "no-model");
    s2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the outranked-pattern hint (pure, observability only; confidentiality.md §6.1) ──

function mixed(...rows: Array<Partial<PathLabel> & { path: string }>): Map<string, PathLabel> {
  const m = labels(...rows);
  for (const r of rows) if (r.glob) m.get(r.path)!.glob = true;
  return m;
}

test("outrankedStricterPatterns: a stricter `**` pattern that lost to a closer directory label is reported; the decision is untouched", () => {
  const m = mixed(
    { path: "/home/u/notes", confidentiality: "any-model" },
    { path: "**/*.pem", confidentiality: "no-model", glob: true },
    { path: "**/k.*", confidentiality: "no-model", glob: true },
    { path: "**/*.md", confidentiality: "no-model", glob: true }, // does not match
  );
  const before = resolvePathLabel("~/notes/k.pem", m, HOME);
  assert.deepEqual(outrankedStricterPatterns("~/notes/k.pem", m, HOME), [
    { pattern: "**/*.pem", level: "no-model" },
    { pattern: "**/k.*", level: "no-model" },
  ], "every stricter loser, sorted by pattern text");
  assert.deepEqual(resolvePathLabel("~/notes/k.pem", m, HOME), before);
  assert.equal(before?.via, "/home/u/notes");
  assert.equal(before?.level, "any-model", "the hint never changes who wins");
});

test("outrankedStricterPatterns: silent unless a literal DIRECTORY label won over a STRICTER matching pattern", () => {
  // a pattern that is equal or LOOSER than the winner is not a surprise worth a note
  assert.deepEqual(outrankedStricterPatterns("/home/u/notes/k.pem", mixed(
    { path: "/home/u/notes", confidentiality: "no-model" },
    { path: "**/*.pem", confidentiality: "any-model", glob: true },
    { path: "**/k.pem", confidentiality: "no-model", glob: true },
  ), HOME), []);
  // an EXACT literal label is a deliberate act on this very file
  assert.deepEqual(outrankedStricterPatterns("/home/u/notes/k.pem", mixed(
    { path: "/home/u/notes/k.pem", confidentiality: "public", recursive: false },
    { path: "**/*.pem", confidentiality: "no-model", glob: true },
  ), HOME), []);
  // a pattern WON (longer literal prefix than the directory label): nothing lost to a literal
  assert.deepEqual(outrankedStricterPatterns("/home/u/notes/k.pem", mixed(
    { path: "/home/u", confidentiality: "public" },
    { path: "/home/u/notes/*.pem", confidentiality: "any-model", glob: true },
    { path: "**/*.pem", confidentiality: "no-model", glob: true },
  ), HOME), []);
  // no label at all, a non-matching pattern, an un-normalizable path, no path
  assert.deepEqual(outrankedStricterPatterns("/srv/k.pem", mixed({ path: "**/*.pem", glob: true }), HOME), [], "the pattern itself decided");
  assert.deepEqual(outrankedStricterPatterns("/srv/k.txt", mixed({ path: "/srv", confidentiality: "public" }, { path: "**/*.pem", glob: true }), HOME), []);
  assert.deepEqual(outrankedStricterPatterns("relative/k.pem", mixed({ path: "**/*.pem", glob: true }), HOME), []);
  assert.deepEqual(outrankedStricterPatterns(null, mixed({ path: "**/*.pem", glob: true }), HOME), []);
});

test("outrankedStricterPatterns: a public directory carve-out reports both stricter levels that lost", () => {
  const m = mixed(
    { path: "/ws/fixtures", confidentiality: "public" },
    { path: "**/.env*", confidentiality: "no-model", glob: true },
    { path: "**/*.local", confidentiality: "any-model", glob: true },
  );
  assert.deepEqual(outrankedStricterPatterns("/ws/fixtures/.env.local", m, HOME), [
    { pattern: "**/*.local", level: "any-model" },
    { pattern: "**/.env*", level: "no-model" },
  ]);
});
