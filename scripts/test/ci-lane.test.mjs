// ci-lane.test.mjs — the MR pipeline's lane choice (scripts/ci/lane.mjs,
// docs/design/testing/continuous-integration.md §5.5, §5.8): a documentation-only diff runs the
// manifest's docs-lane entries; a diff whose code paths are all in declared
// scopes runs the entries that can reach them (their files, those files'
// imports and scripts, a scope's marks); anything else the per-push kinds, and
// every doubt (git error, bad base, empty diff, a rename out of code, a path in
// no scope) is the full run. Pure node plus git in a throwaway repository; no
// network, no privilege.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { FULL, classify, docsLaneIds, entryReach, isDocsPath, reachWhy, resolveImport, scopedSelection, selection } from "../ci/lane.mjs";
import { PER_PUSH_KINDS, loadManifest, selectEntries } from "../suites.mjs";

const MANIFEST = { entries: [{ id: "a", docsLane: true }, { id: "b" }, { id: "c", docsLane: true }] };

function repo() {
  const dir = mkdtempSync(join(tmpdir(), "ci-lane-"));
  const g = (...a) => execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t.invalid", "-c", "commit.gpgsign=false", ...a],
    { cwd: dir, encoding: "utf8" }).trim();
  const put = (p, s) => { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, p), s); };
  put("docs/design/x.md", "# x\n"); put("arbiter/src/a.ts", "export {};\n"); put("README.md", "# r\n");
  g("init", "-q", "-b", "main"); g("add", "-A"); g("commit", "-qm", "base");
  const commit = (msg) => { g("add", "-A"); g("commit", "-qm", msg, "--allow-empty"); return g("rev-parse", "HEAD"); };
  return { dir, g, put, commit, base: g("rev-parse", "HEAD"), done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("docs paths: docs/ and markdown; code, config and the CI files are not", () => {
  for (const p of ["docs/design/testing/continuous-integration.md", "docs/design/confidentiality/figures/a.svg", "README.md", "private/notes/x.md", "arbiter/README.md"]) {
    assert.equal(isDocsPath(p), true, p);
  }
  for (const p of ["arbiter/src/a.ts", ".gitlab-ci.yml", "scripts/ci/lane.mjs", "tests/suites.mjs", "package.json", "docs", "mdfile",
    "launcher/README.md", "arbiter/test/fixtures/handling-prompt-full.md"]) {
    assert.equal(isDocsPath(p), false, p);
  }
});

test("classify: all docs → docs; one code path or nothing → full", () => {
  assert.equal(classify(["docs/a.md", "README.md"]), "docs");
  assert.equal(classify(["docs/a.md", "arbiter/src/a.ts"]), "full");
  assert.equal(classify([]), "full");
});

test("docsLaneIds reads the manifest flag", () => {
  assert.deepEqual(docsLaneIds(MANIFEST.entries), ["a", "c"]);
});

test("a docs-only diff selects the docs lane's entries", async () => {
  const r = repo();
  try {
    r.put("docs/design/x.md", "# x\nmore\n"); r.put("arbiter/README.md", "# a\n");
    const head = r.commit("docs");
    const s = await selection({ base: r.base, head, cwd: r.dir, manifest: MANIFEST });
    assert.equal(s.lane, "docs"); assert.equal(s.line, "--only a,c");
  } finally { r.done(); }
});

test("one code path, or a rename out of code, selects the full run", async () => {
  const r = repo();
  try {
    r.put("docs/design/x.md", "# y\n"); r.put("arbiter/src/a.ts", "export const a = 1;\n");
    let s = await selection({ base: r.base, head: r.commit("mixed"), cwd: r.dir, manifest: MANIFEST });
    assert.equal(s.lane, "full"); assert.equal(s.line, FULL); assert.match(s.why, /arbiter\/src\/a\.ts/);

    const base = r.g("rev-parse", "HEAD");
    renameSync(join(r.dir, "arbiter/src/a.ts"), join(r.dir, "docs/a.md"));
    s = await selection({ base, head: r.commit("move"), cwd: r.dir, manifest: MANIFEST });
    assert.equal(s.lane, "full", "the deleted source path is in the diff");
  } finally { r.done(); }
});

test("every doubt is the full run: empty diff, bad or unknown base, no docs-lane entry, no manifest", async () => {
  const r = repo();
  try {
    const empty = r.commit("empty");
    assert.equal((await selection({ base: r.base, head: empty, cwd: r.dir, manifest: MANIFEST })).lane, "full");
    assert.equal((await selection({ base: "", head: empty, cwd: r.dir, manifest: MANIFEST })).lane, "full");
    assert.equal((await selection({ base: "HEAD~1; rm -rf /", head: empty, cwd: r.dir, manifest: MANIFEST })).lane, "full");
    assert.equal((await selection({ base: "0".repeat(40), head: empty, cwd: r.dir, manifest: MANIFEST })).lane, "full");
    r.put("docs/z.md", "z\n");
    const head = r.commit("docs");
    assert.equal((await selection({ base: r.base, head, cwd: r.dir, manifest: { entries: [{ id: "b" }] } })).lane, "full");
    assert.equal((await selection({ base: r.base, head, cwd: r.dir, manifest: {} })).lane, "full");
  } finally { r.done(); }
});

test("the CLI prints one vm-run.sh selection line and the reason on stderr", () => {
  const r = repo();
  try {
    r.put("arbiter/src/a.ts", "export const b = 2;\n");
    const head = r.commit("code");
    const out = execFileSync("node", [join(import.meta.dirname, "..", "ci", "lane.mjs"), "--base", r.base, "--head", head],
      { cwd: r.dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    // The CLI diffs the repository it lives in, where these SHAs do not exist: full.
    assert.equal(out, `${FULL}\n`);
    assert.equal(FULL, `--kind ${PER_PUSH_KINDS.join(",")}`);
    assert.equal(FULL, "--kind unit,component,stack,replay-drill,sandbox", "the five per-push kinds (test-reorganization.md §3)");
  } finally { r.done(); }
});

test("the real manifest's docs lane: non-empty, per-push kinds, never frozen, ids that select", async () => {
  const m = await loadManifest();
  const ids = docsLaneIds(m.entries);
  assert.ok(ids.length > 0, "some entry is in the docs lane");
  assert.ok(ids.includes("scripts.suites-manifest"), "the manifest check always runs");
  for (const id of ids) {
    const x = m.entries.find((e) => e.id === id);
    assert.ok(PER_PUSH_KINDS.includes(x.kind), `${id} is of a per-push kind (${x.kind})`);
    assert.ok(!x.frozen, `${id} is not in the frozen lane`);
    assert.ok(!x.flaky, `${id} is not flaky`);
  }
  const sel = selectEntries(m.entries, { only: ids });
  assert.deepEqual(sel.unknown, []);
  assert.ok(sel.selected.length >= ids.length, "every docs-lane id selects its entry (shards expand)");
});

test("idOnly entries run when named, never with their kind", async () => {
  const m = await loadManifest();
  const idOnly = m.entries.filter((x) => x.idOnly === true).map((x) => x.id);
  assert.ok(idOnly.length > 0);
  const kindRun = selectEntries(m.entries, { kinds: PER_PUSH_KINDS }).selected.map((x) => x.id);
  for (const id of idOnly) assert.ok(!kindRun.includes(id), `${id} is not in a kind run`);
  assert.deepEqual(selectEntries(m.entries, { only: idOnly }).selected.map((x) => x.id).sort(), [...idOnly].sort());
});

// ── scoped lanes (§5.8) ─────────────────────────────────────────────────────────

// A repository with a scope `side` (side/**) and four entries: one that
// imports into it through a .js specifier of a .ts file, one whose shell
// script runs a script that names it (a mark), one apart from it, and one
// that claims no file at the root (open). Comments and a fixture's text that
// name the scope are not edges.
function scopedRepo() {
  const r = repo();
  r.put("side/x.ts", "export const x = 1;\n");
  r.put("t/lib/index.ts", "export { x } from \"../../side/x.js\";\n");
  r.put("t/in.test.mjs", "import { x } from \"./lib\";\n");
  r.put("t/run.sh", "# not an edge: side/x.ts and t/fake.sh\nbash \"$HERE/t/helper.sh\"\n");
  r.put("t/helper.sh", "echo uses-the-side-door\n");
  r.put("t/apart.test.mjs", [
    "// import { x } from \"../side/x.js\";",
    "/* require(\"../side/x.ts\") */",
    "const fixture = `import { y } from \"./not-here.js\";`;",
    "import { ok } from \"node:assert\";",
    "",
  ].join("\n"));
  r.put("pkg/a.ts", "export const a = 1;\n");
  r.put("pkg/package.json", "{}\n");
  r.g("add", "-A"); r.g("commit", "-qm", "scoped");
  const base = r.g("rev-parse", "HEAD");
  const entry = (id, more) => ({ id, kind: "unit", cwd: ".", needs: ["node"], ...more });
  const entries = [
    entry("imports", { cmd: ["node", "--test", "t/in.test.mjs"] }),
    entry("marked", { cmd: ["bash", "t/run.sh"] }),
    entry("apart", { cmd: ["node", "--test", "t/apart.test.mjs"] }),
    entry("pkg-tsc", { cmd: ["npx", "tsc", "--noEmit"], cwd: "pkg" }),
    entry("root-open", { cmd: ["make"] }),
    entry("guard", { cmd: ["node", "--test", "t/apart.test.mjs"], docsLane: true }),
  ];
  const scope = { id: "side", owns: (p) => p.startsWith("side/"), marks: [/side-door/], via: [], runs: (x) => x.id === "always" };
  return { ...r, base, entries, scope };
}

test("resolveImport: a .js specifier finds its .ts source; a directory its index; nothing is null", () => {
  const r = scopedRepo();
  try {
    assert.equal(resolveImport("t/lib/index.ts", "../../side/x.js", r.dir), "side/x.ts");
    assert.equal(resolveImport("t/in.test.mjs", "./lib", r.dir), "t/lib/index.ts");
    assert.equal(resolveImport("t/in.test.mjs", "./absent.js", r.dir), null);
  } finally { r.done(); }
});

test("entryReach follows imports and scripts, not comments or a fixture's text; no claims is the package, or open at the root", () => {
  const r = scopedRepo();
  try {
    const by = Object.fromEntries(r.entries.map((x) => [x.id, x]));
    assert.deepEqual([...entryReach(by.imports, r.dir).files].sort(), ["side/x.ts", "t/in.test.mjs", "t/lib/index.ts"]);
    assert.deepEqual([...entryReach(by.marked, r.dir).files].sort(), ["t/helper.sh", "t/run.sh"], "a comment's path is no edge");
    const apart = entryReach(by.apart, r.dir);
    assert.equal(apart.open, false, "an import in a comment or a string is not followed, nor does it open the entry");
    assert.deepEqual([...apart.files], ["t/apart.test.mjs"]);
    assert.deepEqual([...entryReach(by["pkg-tsc"], r.dir).files].sort(), ["pkg/a.ts", "pkg/package.json"]);
    assert.equal(entryReach(by["root-open"], r.dir).open, true);
  } finally { r.done(); }
});

test("reachWhy: an owned file, a via file, a mark, or open; else null", () => {
  const read = (p) => ({ "a.sh": "uses-the-side-door", "b.ts": "plain" })[p];
  const scope = { owns: (p) => p.startsWith("side/"), marks: [/side-door/], via: ["v.mjs"] };
  assert.match(reachWhy({ files: new Set(["side/x.ts"]), open: false }, scope, read), /runs side\/x\.ts/);
  assert.match(reachWhy({ files: new Set(["v.mjs"]), open: false }, scope, read), /runs v\.mjs/);
  assert.match(reachWhy({ files: new Set(["b.ts", "a.sh"]), open: false }, scope, read), /a\.sh names side-door/);
  assert.match(reachWhy({ files: new Set(), open: true, why: "claims no file" }, scope, read), /^open/);
  assert.equal(reachWhy({ files: new Set(["b.ts"]), open: false }, scope, read), null);
});

test("scopedSelection: a path in no scope is stray; else the entries that reach, the scope runs, or the docs lane holds", () => {
  const r = scopedRepo();
  try {
    assert.deepEqual(scopedSelection(["side/x.ts", "arbiter/src/a.ts"], r.entries, [r.scope], { root: r.dir }), { stray: "arbiter/src/a.ts" });
    assert.equal(scopedSelection(["side/x.ts"], r.entries, [], { root: r.dir }), null, "no scope: no scoped lane");
    const s = scopedSelection(["side/x.ts"], [...r.entries, { id: "always", kind: "unit", cmd: ["true"], cwd: "." }], [r.scope], { root: r.dir });
    assert.deepEqual(s.touched, ["side"]);
    assert.deepEqual(s.kept.map((x) => x.id), ["imports", "marked", "root-open", "guard", "always"]);
    assert.deepEqual(s.skipped.map((x) => x.id), ["apart", "pkg-tsc"]);
    assert.equal(s.kept.find((x) => x.id === "always").why, "scope side runs it");
  } finally { r.done(); }
});

test("selection: a scope-only diff (docs alongside) is the scoped lane; a stray path or every entry reaching is full", async () => {
  const r = scopedRepo();
  try {
    const manifest = { entries: r.entries, scopes: [r.scope] };
    r.put("side/x.ts", "export const x = 2;\n"); r.put("docs/design/x.md", "# x\nchanged\n");
    const scoped = r.commit("scoped");
    let s = await selection({ base: r.base, head: scoped, cwd: r.dir, root: r.dir, manifest });
    assert.equal(s.lane, "scoped");
    assert.equal(s.line, "--only imports,marked,root-open,guard");
    assert.match(s.why, /2 paths in scope side; 4 entries run, 2 skipped/);

    r.put("pkg/a.ts", "export const a = 2;\n");
    const stray = r.commit("stray");
    s = await selection({ base: r.base, head: stray, cwd: r.dir, root: r.dir, manifest });
    assert.equal(s.lane, "full"); assert.match(s.why, /pkg\/a\.ts is not docs and in no scope/);

    const all = { entries: r.entries.filter((x) => x.id !== "apart" && x.id !== "pkg-tsc"), scopes: [r.scope] };
    s = await selection({ base: r.base, head: scoped, cwd: r.dir, root: r.dir, manifest: all });
    assert.equal(s.lane, "full"); assert.match(s.why, /every entry reaches it/);

    s = await selection({ base: r.base, head: scoped, cwd: r.dir, root: r.dir, manifest: { entries: r.entries, scopes: [{ id: "bad", owns: () => true, marks: [], runs: () => { throw new Error("boom"); } }] } });
    assert.equal(s.lane, "full", "a scope that throws is the full run"); assert.match(s.why, /boom/);
  } finally { r.done(); }
});
