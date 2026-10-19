/**
 * D (2026-10-17, confidentiality.md §6 "Read by a program the launch did not
 * see"): the human labels' places are discovery roots of their own.
 *
 * Before, a labelled file the launch's walk did not reach (outside HOME and
 * the workspace, deeper than MAX_DEPTH from them, past MAX_FILES) was never
 * registered, so its values were unknown to the value backstop and a
 * recursive read (`grep -r`, `tar`, `os.walk`) printed it to the model in
 * clear. Each of the walk tests below failed that way (the file was not in
 * `files`).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discoverSecretsReport, MAX_DEPTH, MAX_FILES, MAX_LABEL_FILES } from "../../policy/secret-discovery.js";
import { guardLabelRoots, labelRootKeys, labelWalkRoots, snapshotLookup, type LabelSnapshot } from "../../policy/label-lookup.js";
import type { PathLabel } from "../../policy/path-labels.js";
import type { ConfidentialityLevel } from "../../symbol-table/confidentiality.js";
import { stateAxes } from "../axes.js";

stateAxes("secrets");

const label = (path: string, confidentiality: ConfidentialityLevel, glob = false): PathLabel => ({
  path, confidentiality, bindings: [], recursive: true, source: "policy-file", updatedAt: 0, ...(glob ? { glob: true as const } : {}),
});
const snapshot = (labels: PathLabel[]): LabelSnapshot => ({ human: new Map(labels.map((l) => [l.path, l])), derived: new Map(), clientKeys: [] });

function tree(): { dir: string; home: string; put: (rel: string, body?: string) => string; cleanup: () => void } {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-label-roots-")));
  const home = join(dir, "home");
  mkdirSync(home);
  const put = (rel: string, body = "password: hunter2-label-root\n"): string => {
    const p = join(dir, rel);
    mkdirSync(join(p, ".."), { recursive: true });
    writeFileSync(p, body);
    return p;
  };
  return { dir, home, put, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test("labelWalkRoots: a literal label's path, a pattern's literal prefix; never `/`, never a label at public", () => {
  const h = new Map([
    ["/srv/vault", label("/srv/vault", "no-model")],
    ["/srv/notes/*.md", label("/srv/notes/*.md", "local-model", true)],
    ["**/*.pem", label("**/*.pem", "no-model", true)],
    ["/srv/open", label("/srv/open", "public")],
    ["/srv/vault/readme.md", label("/srv/vault/readme.md", "no-model")],
  ]);
  assert.deepEqual(labelWalkRoots(h, "/home/u"), ["/srv/notes", "/srv/vault", "/srv/vault/readme.md"]);
  // The keys change when a label is added or raised, not otherwise.
  const before = labelRootKeys(h, "/home/u");
  const raised = new Map(h);
  raised.set("/srv/notes/*.md", label("/srv/notes/*.md", "no-model", true));
  const after = labelRootKeys(raised, "/home/u");
  assert.ok(after.has("no-model /srv/notes") && !before.has("no-model /srv/notes"), "a raised pattern is a new key");
  assert.equal(labelRootKeys(new Map(h), "/home/u").size, before.size);
});

test("a labelled folder OUTSIDE HOME and the workspace is walked as a root of its own: its files are discovered", () => {
  const t = tree();
  try {
    const plan = t.put("elsewhere/vault/plan.md");
    t.put("elsewhere/vault/sub/deeper.md");
    const s = snapshot([label(join(t.dir, "elsewhere", "vault"), "no-model")]);
    const without = discoverSecretsReport([t.home], t.home, snapshotLookup(s), {});
    assert.ok(!without.files.some((f) => f.path === plan), "the bug: no root reaches it");
    const r = discoverSecretsReport([t.home], t.home, snapshotLookup(s), { labelRoots: labelWalkRoots(s.human, t.home) });
    assert.ok(r.files.some((f) => f.path === plan && f.level === "no-model"), JSON.stringify(r.files));
    assert.ok(r.files.some((f) => f.path.endsWith("/sub/deeper.md")));
    assert.equal(r.limits.maxLabelFiles, MAX_LABEL_FILES);
  } finally {
    t.cleanup();
  }
});

test("a labelled folder deeper than MAX_DEPTH from HOME is walked from its own top", () => {
  const t = tree();
  try {
    const deep = ["a", "b", "c", "d", "e", "vault"].join("/");
    assert.ok(deep.split("/").length > MAX_DEPTH);
    const plan = t.put(`home/${deep}/plan.md`);
    const s = snapshot([label(join(t.home, deep), "no-model")]);
    const without = discoverSecretsReport([t.home], t.home, snapshotLookup(s), {});
    assert.ok(!without.files.some((f) => f.path === plan), "the bug: below the depth cap");
    const r = discoverSecretsReport([t.home], t.home, snapshotLookup(s), { labelRoots: labelWalkRoots(s.human, t.home) });
    assert.ok(r.files.some((f) => f.path === plan), JSON.stringify(r.files));
    // Walked once: the labelled folder is not entered by the HOME walk too.
    assert.equal(r.files.filter((f) => f.path === plan).length, 1);
  } finally {
    t.cleanup();
  }
});

test("past MAX_FILES the label roots keep their own budget: a HOME full of catalog matches does not crowd a labelled folder out, nor the reverse", () => {
  const t = tree();
  try {
    for (let i = 0; i < MAX_FILES + 10; i++) t.put(`home/p${String(i).padStart(3, "0")}/.env`, "K=v\n");
    const plan = t.put("home/zz/vault/plan.md");
    const s = snapshot([label(join(t.home, "zz", "vault"), "no-model")]);
    const without = discoverSecretsReport([t.home], t.home, snapshotLookup(s), {});
    assert.ok(without.truncated && !without.files.some((f) => f.path === plan), "the bug: the cap left it raw");
    const r = discoverSecretsReport([t.home], t.home, snapshotLookup(s), { labelRoots: labelWalkRoots(s.human, t.home) });
    assert.ok(r.files.some((f) => f.path === plan), "the labelled file has a budget of its own");
    assert.equal(r.files.filter((f) => f.path.endsWith("/.env")).length, MAX_FILES, "the catalog's finds keep MAX_FILES");
  } finally {
    t.cleanup();
  }
});

test("the label pass is bounded: MAX_LABEL_FILES files at most, the rest named `count`", () => {
  const t = tree();
  try {
    for (let i = 0; i < MAX_LABEL_FILES + 5; i++) t.put(`big/f${i}.md`);
    const s = snapshot([label(join(t.dir, "big"), "no-model")]);
    const r = discoverSecretsReport([t.home], t.home, snapshotLookup(s), { labelRoots: labelWalkRoots(s.human, t.home) });
    assert.equal(r.files.length, MAX_LABEL_FILES);
    assert.ok(r.truncated);
    assert.ok(r.counts.count >= 5, JSON.stringify(r.counts));
  } finally {
    t.cleanup();
  }
});

test("a pattern's prefix is only where to look: the label lookup decides which files there are secret", () => {
  const t = tree();
  try {
    const md = t.put("notes/plan.md");
    const txt = t.put("notes/readme.txt", "hello\n");
    const s = snapshot([label(`${join(t.dir, "notes")}/*.md`, "no-model", true)]);
    const roots = labelWalkRoots(s.human, t.home);
    assert.deepEqual(roots, [join(t.dir, "notes")]);
    const r = discoverSecretsReport([t.home], t.home, snapshotLookup(s), { labelRoots: roots });
    assert.ok(r.files.some((f) => f.path === md));
    assert.ok(!r.files.some((f) => f.path === txt), "a file the pattern does not match is not a secret");
  } finally {
    t.cleanup();
  }
});

test("a labelled FILE is a root too; a label root spelled through a symlink is not walked (a bind there bricks the launch)", () => {
  const t = tree();
  try {
    const one = t.put("lone/key.txt");
    t.put("real/vault/plan.md");
    symlinkSync(join(t.dir, "real"), join(t.dir, "link"));
    const s = snapshot([label(one, "no-model"), label(join(t.dir, "link", "vault"), "no-model")]);
    const r = discoverSecretsReport([t.home], t.home, snapshotLookup(s), { labelRoots: labelWalkRoots(s.human, t.home) });
    assert.ok(r.files.some((f) => f.path === one));
    assert.ok(!r.files.some((f) => f.path.includes("/link/")), JSON.stringify(r.files));
    assert.ok(r.skipped.some((k) => k.path === join(t.dir, "link", "vault") && k.reason === "symlinked-directory"));
  } finally {
    t.cleanup();
  }
});

test("guardLabelRoots (C, the guard's list): literals, a pattern's prefix with its last segment's anchors, `/` for no prefix, no shape after `**`, client keys; never public", () => {
  const h = new Map([
    ["/srv/vault", label("/srv/vault", "no-model")],
    ["/srv/notes/secret-*.md", label("/srv/notes/secret-*.md", "local-model", true)],
    ["**/*.pem", label("**/*.pem", "no-model", true)],
    ["/proj/*/secrets", label("/proj/*/secrets", "no-model", true)],
    ["/srv/all/**", label("/srv/all/**", "no-model", true)],
    ["/srv/open", label("/srv/open", "public")],
  ]);
  const roots = guardLabelRoots(h, ["/etc/model/client.key"], "/home/u");
  assert.deepEqual(roots, [
    { path: "/", shape: { head: "", tail: ".pem", exact: false } },
    { path: "/etc/model/client.key" },
    { path: "/proj", shape: { head: "secrets", tail: "secrets", exact: true } },
    { path: "/srv/all" },
    { path: "/srv/notes", shape: { head: "secret-", tail: ".md", exact: false } },
    { path: "/srv/vault" },
  ]);
});
