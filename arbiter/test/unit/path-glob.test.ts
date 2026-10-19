/**
 * path-glob — gitignore-style `paths:` patterns (confidentiality.md §6.1).
 * The matcher is security-relevant in both directions: an UNDER-match leaves a
 * secret unlabeled, an OVER-match on a `public` pattern declassifies by accident.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { compilePathGlob, hasGlobMeta, pathGlobMatches, MAX_GLOB_SEGMENTS } from "../../policy/path-glob.js";
import { resolvePathLabel, type PathLabel } from "../../policy/path-labels.js";
import { resolveWithDerived, type DerivedLabel } from "../../policy/derived-labels.js";

const HOME = "/home/u";
function glob(p: string) {
  const r = compilePathGlob(p, HOME);
  assert.ok("glob" in r, `expected ${p} to compile: ${"errors" in r ? r.errors.join("; ") : ""}`);
  return r.glob;
}
const m = (p: string, path: string, recursive = false): boolean => pathGlobMatches(glob(p), path, recursive);

test("hasGlobMeta: only an UNESCAPED * ? [ makes an entry a pattern", () => {
  assert.equal(hasGlobMeta("/a/b.txt"), false);
  assert.equal(hasGlobMeta("/a/*.txt"), true);
  assert.equal(hasGlobMeta("/a/b?.txt"), true);
  assert.equal(hasGlobMeta("/a/[ab].txt"), true);
  assert.equal(hasGlobMeta("/a/\\*.txt"), false, "an escaped star is a literal file name");
});

test("* and ? stay inside ONE segment; ** spans segments; matching is segment-aware", () => {
  assert.equal(m("/ws/*.pem", "/ws/a.pem"), true);
  assert.equal(m("/ws/*.pem", "/ws/sub/a.pem"), false, "* never crosses a '/'");
  assert.equal(m("/ws/*.pem", "/ws/a.pem.bak"), false, "anchored at both ends: no over-match on a longer name");
  assert.equal(m("/ws/*", "/ws/.env"), true, "dotfiles are files");
  assert.equal(m("/ws/id_?sa", "/ws/id_rsa"), true);
  assert.equal(m("/ws/id_?sa", "/ws/id_sa"), false);
  assert.equal(m("/ws/**/*.pem", "/ws/a.pem"), true, "** matches zero segments");
  assert.equal(m("/ws/**/*.pem", "/ws/x/y/a.pem"), true);
  assert.equal(m("**/*.pem", "/anywhere/at/all/k.pem"), true);
  assert.equal(m("**/ws-*/contracts/**", "/run/ws-c4/contracts/acme.md"), true);
  assert.equal(m("**/ws-*/contracts/**", "/run/ws-c4/contracts-public/acme.md"), false, "`contracts` never covers `contracts-public`");
  assert.equal(m("/ws/docs/**", "/ws/docs-public/a"), false);
  assert.equal(m("~/notes/*.md", "/home/u/notes/a.md"), true, "~ expands to the home");
});

test("character sets, negation, ranges and escapes", () => {
  assert.equal(m("/k/id_[rd]sa", "/k/id_rsa"), true);
  assert.equal(m("/k/id_[rd]sa", "/k/id_xsa"), false);
  assert.equal(m("/k/v[0-9].key", "/k/v7.key"), true);
  assert.equal(m("/k/v[!0-9].key", "/k/v7.key"), false);
  assert.equal(m("/k/v[!0-9].key", "/k/vx.key"), true);
  assert.equal(m("/k/a\\*b", "/k/a*b"), true);
  assert.equal(m("/k/a\\*b", "/k/aXb"), false, "an escaped star matches only a star");
});

test("recursive: a matched path covers what is below it; recursive:false covers the match alone", () => {
  assert.equal(m("/ws/con*", "/ws/contracts/deep/a.md", true), true);
  assert.equal(m("/ws/con*", "/ws/contracts/deep/a.md", false), false);
  assert.equal(m("/ws/con*", "/ws/contracts", false), true);
  assert.equal(m("/ws/con*", "/other/contracts/a.md", true), false, "recursive never loosens the anchor");
});

test("a pattern that is not one is REFUSED with a reason (the validator prints these)", () => {
  const bad = (p: string, re: RegExp): void => {
    const r = compilePathGlob(p, HOME);
    assert.ok("errors" in r, `${p} should not compile`);
    assert.match(r.errors.join("; "), re);
  };
  bad("*.pem", /anchored/);
  bad("contracts/*.md", /anchored/);
  bad("/ws/a**b", /whole path segment/);
  bad("/ws/[abc", /never closed/);
  bad("/ws/[z-a]", /reversed/);
  bad("/ws/../*.md", /not allowed/);
  bad("**", /every path/);
  bad("/**/**", /every path/);
  bad("/" + Array(MAX_GLOB_SEGMENTS + 1).fill("*").join("/"), /segments/);
  bad("/ws/x\\", /escapes nothing/);
});

test("no input is exponential: a many-star pattern against a long non-matching name answers at once", () => {
  // CPU time, not the wall clock (a loaded CI host stretches the wall clock;
  // an exponential match is far past the bound either way).
  const cpuMs = (c0: NodeJS.CpuUsage) => { const c = process.cpuUsage(c0); return Math.round((c.user + c.system) / 1000); };
  const g = glob("/ws/" + "*a".repeat(30) + "*b");
  const t0 = process.cpuUsage();
  assert.equal(pathGlobMatches(g, "/ws/" + "a".repeat(400), false), false);
  assert.ok(cpuMs(t0) < 500, `took ${cpuMs(t0)} ms of CPU`);
  const deep = glob("/**/x/**/y/**/z/**/nope");
  const t1 = process.cpuUsage();
  assert.equal(pathGlobMatches(deep, "/" + Array(300).fill("x/y/z").join("/"), false), false);
  assert.ok(cpuMs(t1) < 500, `took ${cpuMs(t1)} ms of CPU`);
});

// ── precedence through the label resolver ────────────────────────────────────
function labels(...rows: Array<[string, PathLabel["confidentiality"], Partial<PathLabel>?]>): Map<string, PathLabel> {
  const out = new Map<string, PathLabel>();
  for (const [p, confidentiality, extra] of rows) {
    const isGlob = hasGlobMeta(p);
    const path = isGlob ? glob(p).pattern : p;
    out.set((isGlob ? "glob:" : "") + path, { path, confidentiality, bindings: [], recursive: true, source: "policy-file", updatedAt: 0, ...(isGlob ? { glob: true as const } : {}), ...extra });
  }
  return out;
}

test("precedence: exact literal > longest literal prefix (patterns included) > on a tie the pattern, then the STRICTER pattern", () => {
  const L = labels(
    ["/ws/contracts", "any-model"],
    ["/ws/contracts/*.pub.md", "public"],
    ["/ws/contracts/keys/*", "no-model"],
    ["**/*.md", "no-model"],
    ["/ws/contracts/keys/readme.md", "public", { recursive: false }],
  );
  const r = (p: string) => resolvePathLabel(p, L, HOME);
  assert.deepEqual(r("/ws/contracts/deal.md"), { level: "any-model", bindings: [], via: "/ws/contracts" },
    "a `**` pattern has an EMPTY literal prefix: the directory label closer to the file beats it");
  assert.deepEqual(r("/ws/contracts/terms.pub.md"), { level: "public", bindings: [], via: "/ws/contracts/*.pub.md", glob: true },
    "equal literal prefix: the pattern names more of the path than the directory label");
  assert.equal(r("/ws/contracts/keys/k1")!.level, "no-model");
  assert.equal(r("/ws/contracts/keys/readme.md")!.level, "public", "a literal label on exactly this path beats every pattern");
  assert.equal(r("/elsewhere/notes.md")!.via, "**/*.md");
  assert.equal(r("/elsewhere/notes.txt"), null, "no label: the catalog decides (fail-closed default)");

  const tie = labels(["/ws/*.cfg", "public"], ["/ws/app.*", "no-model"]);
  assert.equal(resolvePathLabel("/ws/app.cfg", tie, HOME)!.level, "no-model",
    "two patterns, equal specificity: we do not know which the human meant, so the stricter wins");
  const tieReversed = labels(["/ws/app.*", "no-model"], ["/ws/*.cfg", "public"]);
  assert.equal(resolvePathLabel("/ws/app.cfg", tieReversed, HOME)!.level, "no-model", "…whatever the order in the file");
});

test("a pattern is never the EXACT release act on a derived (HIGH-session-written) file: it may not lower the taint", () => {
  const derived = new Map<string, DerivedLabel>([["/ws/out/*.md", {
    path: "/ws/out/*.md", confidentiality: "any-model", bindings: [], sessionKey: "s", tool: "Write", sources: null, createdAt: 0, updatedAt: 0,
  } as DerivedLabel]]);
  // a file literally named `*.md`, and a public pattern whose TEXT equals its path
  const human = labels(["/ws/out/*.md", "public"]);
  const d = resolveWithDerived("/ws/out/*.md", human, derived, HOME);
  assert.equal(d!.level, "any-model", "the pattern is a statement about a class of files, not a release of this artifact");
  assert.equal(d!.origin, "derived");
});
