// dep-audit.test.mjs — scripts/dep-audit.mjs, the dependency audit
// (docs/design/testing/continuous-integration.md §14.2): reading npm's and
// cargo-audit's JSON reports, the allow-list's rules (a reason, an expiry at
// most 180 days out, an expired entry allows nothing), the run's verdict (a
// finding fails unless allowed; no network or no tool is a SKIP, never a
// pass; a partial audit fails), and the committed allow-list is valid.
// Offline: no npm audit, no cargo-audit is run (the CLI cases point the tools
// at nothing).
//
// Run: node --test scripts/test/dep-audit.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ALLOW_FILE, MAX_ALLOW_DAYS, cargoFindings, judge, npmFindings, npmPackageDirs, parseAllowList, report,
} from "../dep-audit.mjs";
import { parseCounts } from "../run-suites.mjs";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SCRIPT = path.join(REPO, "scripts/dep-audit.mjs");

// npm audit --json (auditReportVersion 2), trimmed: js-yaml carries two
// advisories, `parent` is vulnerable only through it.
const NPM_REPORT = {
  auditReportVersion: 2,
  vulnerabilities: {
    "js-yaml": {
      name: "js-yaml", severity: "high", isDirect: true, range: ">=4.0.0 <4.3.2", fixAvailable: true,
      via: [
        { source: 1, name: "js-yaml", title: "quadratic merge keys", url: "https://github.com/advisories/GHSA-52cp-r559-cp3m", severity: "high", range: ">=4.0.0 <4.3.0" },
        { source: 2, name: "js-yaml", title: "omap", url: "https://github.com/advisories/GHSA-5p4m-2wfm-xmqj", severity: "moderate", range: ">=4.0.0 <4.3.1" },
      ],
    },
    parent: { name: "parent", severity: "high", isDirect: true, via: ["js-yaml"], fixAvailable: { name: "parent", version: "2.0.0", isSemVerMajor: true } },
  },
  metadata: { vulnerabilities: { high: 2 } },
};

const CARGO_REPORT = {
  database: { "advisory-count": 1 },
  vulnerabilities: {
    found: true, count: 1,
    list: [{
      advisory: { id: "RUSTSEC-2099-0001", title: "a bug", url: "https://rustsec.org/advisories/RUSTSEC-2099-0001.html", cvss: null },
      package: { name: "foo", version: "1.0.0" }, versions: { patched: [">=1.0.1"] },
    }],
  },
  warnings: {
    unmaintained: [{ kind: "unmaintained", advisory: { id: "RUSTSEC-2099-0002", title: "foo is unmaintained" }, package: { name: "bar", version: "0.1.0" } }],
    yanked: [{ kind: "yanked", advisory: null, package: { name: "baz", version: "0.2.0" } }],
  },
};

const entry = (o = {}) => ({
  id: "GHSA-52cp-r559-cp3m", ecosystem: "npm", package: "js-yaml",
  reason: "no fixed release yet; only our own policy files are parsed", added: "2026-10-01", expires: "2026-12-01", ...o,
});

test("npmFindings: one finding per advisory per vulnerable package, the GHSA id, the fix; a `via`-only entry adds none", () => {
  const r = npmFindings(NPM_REPORT, "arbiter");
  assert.equal(r.ok, true);
  assert.deepEqual(r.findings.map((f) => [f.package, f.id, f.severity, f.where, f.fix]), [
    ["js-yaml", "GHSA-52cp-r559-cp3m", "high", "arbiter", "npm audit fix"],
    ["js-yaml", "GHSA-5p4m-2wfm-xmqj", "moderate", "arbiter", "npm audit fix"],
  ]);
  assert.deepEqual(npmFindings({ auditReportVersion: 2, vulnerabilities: {} }, "x"), { ok: true, findings: [] });
});

test("npmFindings: no report (offline, a registry error) is not a clean report", () => {
  const off = npmFindings({ error: { code: "ENOTFOUND", summary: "request to https://registry.npmjs.org failed\nmore" } }, "x");
  assert.equal(off.ok, false);
  assert.match(off.reason, /^ENOTFOUND: request to/);
  assert.equal(npmFindings(null, "x").ok, false);
  assert.equal(npmFindings({ metadata: {} }, "x").ok, false);
});

test("cargoFindings: vulnerabilities and every warning kind; a yanked crate with no advisory gets a stable id", () => {
  const r = cargoFindings(CARGO_REPORT, "interceptors");
  assert.equal(r.ok, true);
  assert.deepEqual(r.findings.map((f) => [f.id, f.kind, f.package, f.fix]), [
    ["RUSTSEC-2099-0001", "vulnerability", "foo", ">=1.0.1"],
    ["RUSTSEC-2099-0002", "unmaintained", "bar", "none"],
    ["yanked:baz@0.2.0", "yanked", "baz", "none"],
  ]);
  assert.equal(cargoFindings({}, "interceptors").ok, false);
});

test("parseAllowList: a valid entry; every rule refuses its violation; an invalid file allows nothing", () => {
  const ok = parseAllowList(JSON.stringify({ allow: [entry({ where: ["arbiter"] })] }));
  assert.deepEqual(ok.errors, []);
  assert.equal(ok.entries.length, 1);
  const bad = (o, re) => {
    const r = parseAllowList(JSON.stringify({ allow: [entry(o)] }));
    assert.ok(r.errors.some((e) => re.test(e)), `${JSON.stringify(o)} → ${JSON.stringify(r.errors)}`);
    assert.deepEqual(r.entries, [], "an invalid file allows nothing");
  };
  bad({ reason: "because" }, /reason must say why/);
  bad({ ecosystem: "pip" }, /ecosystem/);
  bad({ expires: "2026-09-30" }, /after added/);
  bad({ expires: "2027-12-01" }, new RegExp(`at most ${MAX_ALLOW_DAYS}`));
  bad({ added: "yesterday" }, /added must be/);
  bad({ where: [] }, /where must be/);
  bad({ severity: "low" }, /unknown field severity/);
  bad({ id: "" }, /no id/);
  assert.match(parseAllowList("{").errors[0], /not JSON/);
  assert.match(parseAllowList("{}").errors[0], /no `allow` array/);
});

test("judge: a live entry allows its finding; an expired one does not; `where` narrows; unused entries are named", () => {
  const { findings } = npmFindings(NPM_REPORT, "arbiter");
  const live = entry();
  const other = entry({ id: "GHSA-5p4m-2wfm-xmqj", where: ["dashboard"] });
  const stale = entry({ id: "GHSA-xxxx-xxxx-xxxx" });
  const r = judge(findings, [live, other, stale], "2026-10-09", ["npm"]);
  assert.deepEqual(r.allowed.map((x) => x.finding.id), ["GHSA-52cp-r559-cp3m"]);
  assert.deepEqual(r.failing.map((x) => [x.finding.id, x.expired]), [["GHSA-5p4m-2wfm-xmqj", null]], "where: dashboard does not cover arbiter");
  assert.deepEqual(r.unused.map((e) => e.id).sort(), ["GHSA-5p4m-2wfm-xmqj", "GHSA-xxxx-xxxx-xxxx"]);
  // The day after its expiry the entry allows nothing, and the failure says so.
  const later = judge(findings, [live], "2026-12-02", ["npm"]);
  assert.deepEqual(later.failing.map((x) => [x.finding.id, x.expired]), [["GHSA-52cp-r559-cp3m", "2026-12-01"], ["GHSA-5p4m-2wfm-xmqj", null]]);
  assert.equal(judge(findings, [live], "2026-12-01", ["npm"]).allowed.length, 1, "the expiry day itself still allows");
  // A cargo entry is not reported unused by the npm audit.
  assert.deepEqual(judge([], [entry({ ecosystem: "cargo" })], "2026-10-09", ["npm"]).unused, []);
});

test("report: findings fail, allowed ones pass; none reachable is a SKIP; a partial audit fails; run-suites reads the footer", () => {
  const { findings } = npmFindings(NPM_REPORT, "arbiter");
  const clean = { where: "launcher", ok: true, findings: [] };
  const dirty = { where: "arbiter", ok: true, findings };
  const off = (where) => ({ where, ok: false, reason: "npm audit: ENOTFOUND: offline" });

  const red = report("npm", [clean, dirty], [], "2026-10-09");
  assert.equal(red.code, 1);
  assert.match(red.lines.at(-1), /^dep-audit npm: 1 passed, 1 failed$/);
  assert.ok(red.lines.some((l) => l.includes("GHSA-52cp-r559-cp3m js-yaml")));
  assert.deepEqual([parseCounts(red.lines.join("\n")).pass, parseCounts(red.lines.join("\n")).fail], [1, 1]);

  const allowed = report("npm", [clean, dirty], [entry(), entry({ id: "GHSA-5p4m-2wfm-xmqj" })], "2026-10-09");
  assert.equal(allowed.code, 0);
  assert.match(allowed.lines.at(-1), /: 2 passed, 0 failed$/);

  const skip = report("npm", [off("a"), off("b")], [], "2026-10-09");
  assert.equal(skip.code, 0);
  assert.equal(skip.skipped, true);
  assert.equal(skip.lines[0], "SKIP: npm audit: ENOTFOUND: offline", "the reason, once");
  const counts = parseCounts(skip.lines.join("\n"));
  assert.deepEqual([counts.pass, counts.fail, counts.skip], [0, 0, 1], "a skip, which --strict-skips with ci.maxSkip 0 turns red");

  const partial = report("npm", [clean, off("b")], [], "2026-10-09");
  assert.equal(partial.code, 1);
  assert.match(partial.lines.at(-1), /: 1 passed, 1 failed$/);
});

test("npmPackageDirs: every lockfile directory, never inside node_modules, build output or a dot-directory", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dep-audit-"));
  try {
    for (const d of ["a", "b/c", "a/node_modules/x", ".claude/worktrees/w/a", "interceptors/target/t", "d"]) {
      fs.mkdirSync(path.join(root, d), { recursive: true });
      if (d !== "d") fs.writeFileSync(path.join(root, d, "package-lock.json"), "{}");
    }
    assert.deepEqual(npmPackageDirs(root), ["a", "b/c"]);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the CLI: no cargo-audit is a SKIP with the reason; an invalid allow-list fails before any audit", () => {
  const run = (args, env = {}) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8", env: { ...process.env, ...env } });
  const none = run(["cargo"], { CARGO_AUDIT: path.join(os.tmpdir(), "no-such-cargo-audit-bin") });
  assert.equal(none.status, 0, none.stderr);
  assert.match(none.stdout, /^SKIP: .*no-such-cargo-audit-bin is not installed/m);
  assert.match(none.stdout, /dep-audit cargo: 0 passed, 0 failed \(skipped\)/);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dep-audit-allow-"));
  try {
    const bad = path.join(dir, "allow.json");
    fs.writeFileSync(bad, JSON.stringify({ allow: [entry({ reason: "x" })] }));
    const r = run(["cargo", "--allow", bad], { CARGO_AUDIT: path.join(os.tmpdir(), "no-such-cargo-audit-bin") });
    assert.equal(r.status, 1);
    assert.match(r.stdout, /reason must say why/);
    assert.match(r.stdout, /dep-audit cargo: 0 passed, 1 failed/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(run(["pip"]).status, 2);
});

test("the committed allow-list is valid", () => {
  const { errors } = parseAllowList(fs.readFileSync(ALLOW_FILE, "utf8"));
  assert.deepEqual(errors, []);
});
