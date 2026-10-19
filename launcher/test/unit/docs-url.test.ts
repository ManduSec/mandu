/**
 * docs-url — user-facing text points at the PUBLIC docs URL, never at a
 * repo-relative `docs/…` path an npm install does not ship (release checklist
 * d7). Also pins that every document a `docsUrl("…")` call names exists in the
 * tree, so the URL resolves once the tree is published, and that the npm
 * README links only to absolute URLs (the npm page has no repo to resolve a
 * relative link against).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DOCS_BASE_URL, docsUrl } from "../../src/docs-url.js";
import { usageText } from "../../src/usage.js";
import { nativeBinBuildHint } from "../../src/services/native-bins.js";

const PKG_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO_ROOT = join(PKG_ROOT, "..");

/** A repo-relative doc path standing on its own (not already inside a URL). */
const BARE_DOC_PATH = /(^|[\s("'`])docs\/[\w./-]+\.md/m;

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith(".ts") ? [p] : [];
  });
}

test("docsUrl: one base, the public repository at its default branch", () => {
  assert.equal(DOCS_BASE_URL, "https://github.com/mandusec/mandu/blob/main/");
  assert.equal(docsUrl("docs/usage.md"), "https://github.com/mandusec/mandu/blob/main/docs/usage.md");
  assert.equal(docsUrl("/docs/usage.md"), docsUrl("docs/usage.md"));
  assert.equal(docsUrl("./docs/usage.md"), docsUrl("docs/usage.md"));
});

test("--help names the public guide URL and no repo-relative docs path", () => {
  const help = usageText();
  assert.ok(help.includes(docsUrl("docs/usage.md")), "help does not name the guide URL");
  assert.ok(help.includes(docsUrl("docs/guarantees.md")), "help does not name the guarantees URL");
  assert.doesNotMatch(help, BARE_DOC_PATH, "help still points at a docs/ path an npm install does not ship");
});

test("the installed native-bin hint names a URL, not an unshipped docs/ path", () => {
  const hint = nativeBinBuildHint(true);
  assert.ok(hint.includes(DOCS_BASE_URL), hint);
  assert.doesNotMatch(hint, BARE_DOC_PATH);
});

test("every docsUrl(\"…\") in the launcher source names a document that exists in the tree", () => {
  const calls = walk(join(PKG_ROOT, "src")).flatMap((f) =>
    [...readFileSync(f, "utf8").matchAll(/docsUrl\("([^"]+)"\)/g)].map((m) => ({ f, path: m[1]! })));
  assert.ok(calls.length >= 3, `expected the help and hint call sites, found ${calls.length}`);
  for (const { f, path } of calls) {
    const file = path.replace(/#.*$/, "");
    assert.ok(existsSync(join(REPO_ROOT, file)), `${f}: docsUrl("${path}") names a file that does not exist`);
  }
});

test("the npm README exists and links only to absolute URLs", () => {
  const readme = readFileSync(join(PKG_ROOT, "README.md"), "utf8");
  assert.match(readme, /^# Mandu\n/);
  assert.match(readme, /npm install -g @mandusec\/mandu/);
  // The copy CONTRIBUTING.md requires: secrets mode does NOT mask untrusted text.
  assert.match(readme, /does not mask untrusted text/);
  const targets = [...readme.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]!);
  assert.ok(targets.length > 0);
  for (const t of targets) assert.match(t, /^https:\/\//, `relative link ${t} cannot resolve on the npm page`);
});
