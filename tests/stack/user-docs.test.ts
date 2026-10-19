/**
 * The user-facing documentation (README.md, docs/*.md) holds together: every
 * relative link names a file that exists, every #anchor names a heading that
 * exists (GitHub's slug rule), the docs home links every user page, and the
 * front page keeps the copy CONTRIBUTING.md requires and stays a front page,
 * and the first-session tour has a section for every supported agent.
 * Structure: docs/README.md "How these docs are organized".
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { TESTED_AGENT_VERSIONS, type VersionedAgent } from "../../launcher/src/agent-versions.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

const USER_DOCS = [
  "README.md",
  ...readdirSync(join(REPO, "docs"))
    .filter((f) => f.endsWith(".md"))
    .map((f) => `docs/${f}`),
];

/** Markdown with fenced code blocks and inline code spans removed. */
function prose(md: string): string {
  return md.replace(/^(```|~~~)[\s\S]*?^\1/gm, "").replace(/`[^`\n]*`/g, "``");
}

/** GitHub's heading anchors for one markdown file. */
function anchors(md: string): Set<string> {
  const seen = new Map<string, number>();
  const out = new Set<string>();
  const body = md.replace(/^(```|~~~)[\s\S]*?^\1/gm, "");
  for (const m of body.matchAll(/^#{1,6}\s+(.+?)\s*#*\s*$/gm)) {
    const base = m[1]!
      .toLowerCase()
      .replace(/[^\p{L}\p{N}\s_-]/gu, "")
      .replace(/\s/g, "-");
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.add(n === 0 ? base : `${base}-${n}`);
  }
  return out;
}

function links(md: string): string[] {
  return [...prose(md).matchAll(/\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)].map((m) => m[1]!);
}

test("every relative link and anchor in the user docs resolves", () => {
  const problems: string[] = [];
  for (const doc of USER_DOCS) {
    const md = readFileSync(join(REPO, doc), "utf8");
    for (const target of links(md)) {
      if (/^[a-z]+:/i.test(target)) continue; // https:, mailto:
      const [path, anchor] = target.split("#") as [string, string | undefined];
      const file = path === "" ? join(REPO, doc) : resolve(join(REPO, dirname(doc)), path);
      if (!existsSync(file)) {
        problems.push(`${doc}: ${target} (no such file)`);
        continue;
      }
      if (anchor && file.endsWith(".md") && !anchors(readFileSync(file, "utf8")).has(anchor)) {
        problems.push(`${doc}: ${target} (no heading #${anchor} in ${relative(REPO, file)})`);
      }
    }
  }
  assert.deepEqual(problems, []);
});

test("the docs home links every user page", () => {
  const home = links(readFileSync(join(REPO, "docs/README.md"), "utf8")).map((t) => t.split("#")[0]);
  for (const doc of USER_DOCS) {
    if (doc === "README.md" || doc === "docs/README.md") continue;
    assert.ok(home.includes(doc.slice("docs/".length)), `docs/README.md does not link ${doc}`);
  }
});

test("the front page says secrets mode does not mask untrusted text, and stays a front page", () => {
  const readme = readFileSync(join(REPO, "README.md"), "utf8");
  // CONTRIBUTING.md: user-facing copy must say `secrets` mode does NOT mask untrusted text.
  assert.match(readme.replace(/\s+/g, " "), /does not mask untrusted text/);
  for (const page of ["docs/getting-started.md", "docs/usage.md", "docs/guarantees.md", "docs/development.md"]) {
    assert.ok(readme.includes(`](${page}`), `README.md links ${page}`);
  }
  // Developer internals live in docs/development.md, not on the front page.
  const lines = readme.split("\n").length;
  assert.ok(lines <= 240, `README.md is ${lines} lines; move detail into docs/ (docs/README.md)`);
});

test("the first-session tour has a section for every supported agent that starts it under mandu", () => {
  const tour = readFileSync(join(REPO, "docs/first-session.md"), "utf8");
  const sections = new Map<string, string>();
  for (const part of tour.split(/^## /m).slice(1)) {
    const nl = part.indexOf("\n");
    sections.set(part.slice(0, nl).trim(), part.slice(nl));
  }
  for (const [agent, range] of Object.entries(TESTED_AGENT_VERSIONS) as [VersionedAgent, { name: string }][]) {
    const body = sections.get(range.name);
    assert.ok(body, `docs/first-session.md has no "## ${range.name}" section`);
    assert.match(body, new RegExp(`^mandu ${agent}\\b`, "m"), `the ${range.name} section starts it with \`mandu ${agent}\``);
    const slug = range.name.toLowerCase().replace(/\s/g, "-");
    assert.ok(tour.includes(`](#${slug})`), `the tour's agent list links #${slug}`);
  }
});
