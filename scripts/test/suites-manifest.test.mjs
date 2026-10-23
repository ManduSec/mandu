// suites-manifest.test.mjs — the completeness check of the suite manifest
// (tests/suites.mjs; docs/design/testing/test-organization.md §5): every test file and
// every `test*` npm script is claimed by exactly one entry, every path an entry
// names exists, every entry has a valid kind and axis, integrity-ON suites sit
// in the frozen lane unless they are a named canary or carry a re-pin todo, and
// a unit, component or stack entry needs nothing beyond node, cargo and base
// shell tools (test-reorganization.md §3: kinds, §5.1: proves). This
// is the check that stops a suite from going missing again.
//
// A private manifest's own problems (its `problems(root)`) are part of the
// check where the tree has one, BLOCKING. In the source repository those are
// the drill catalog's; the tests against the catalog, its scripts and the
// drill entries are the source repository's (suites-drills.test.mjs, beside
// this file there).
//
// The docs-lane sweep (continuous-integration.md §5.5) is part of the check too: a
// per-push test that reads the repository's docs at run time runs in a
// `docsLane` entry, or says why not in a `docs-lane-exempt: <reason>` comment.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import {
  COSTS_FILE, PRIVATE_COSTS_FILE, CREDENTIALS, COVERAGE_KINDS, DEFAULT_COST, ENV_NEEDS, HOST_FREE_KINDS, KINDS, KIND_NOTES, NATIVE_BIN_KINDS, NEEDS, NIGHTLY_KINDS,
  PER_PUSH_KINDS, PROPERTIES, REPO_ROOT, SUITES_DOC, checkManifest, costsFromRuns, costsFromSummary, coverage, coverageProblems, docsLaneSweep, docsReaderModules, docsReads, unmarkedDocsReaders,
  needsKernel, nightlyRuns, nonBlocking, planPhases, renderCoverage, runsEveryPush, usesNativeBins,
  COMMAND_FLAGS, bundlePackageDirs, entryClaims,
  expandGlob, expandShards, flakyBudget, freezeCanaries, loadAllCosts, loadCosts, loadManifest, main, orderByCost, parseFlags, renderSuitesDoc, scriptPathTokens, selectEntries, sharedQueueOrder,
  runEntry, sessionProblems, suitesDocProblem, walkTestFiles, isDrill,
} from "../suites.mjs";
import { filterMatch } from "../ci/github-rules.mjs";
import { isDocsPath } from "../ci/lane.mjs";
import { devViewFile } from "../dev-view.mjs";

const SUITES = join(REPO_ROOT, "scripts", "suites.mjs");

test("runEntry: the entry's cmd in its cwd with its env and extra args; its exit code; a self-loop is refused", () => {
  const probe = (code) => ({
    id: "probe.x", cwd: "scripts",
    cmd: ["node", "-e", `const fs=require("fs");process.exit(fs.existsSync("suites.mjs") && process.env.X === "7" && process.argv[1] === "a1" ? ${code} : 99)`],
    env: { X: "7" },
  });
  // cwd is the entry's (scripts/ holds suites.mjs), env X comes from the entry, "a1" from args.
  assert.equal(runEntry(probe(0), { args: ["a1"], stdio: "ignore" }), 0);
  assert.equal(runEntry(probe(3), { args: ["a1"], stdio: "ignore" }), 3);
  // The child is told which entry it runs; running that entry again from inside is a loop.
  assert.equal(runEntry(probe(0), { args: ["a1"], stdio: "ignore", env: { ...process.env, MANDU_SUITES_RUN: "probe.x" } }), 2);
  // A missing binary is 127, not a throw.
  assert.equal(runEntry({ id: "probe.y", cwd: ".", cmd: ["/nonexistent/bin"] }, { stdio: "ignore" }), 127);
});

// ── the CLI's flags (test-reorganization.md §11.4) ────────────────────────────

const cliRun = (...args) => spawnSync(process.execPath, [SUITES, ...args], { cwd: REPO_ROOT, encoding: "utf8" });

test("CLI: an unknown flag, a stray positional or a missing value is refused with exit 2 and the usage, for every command", () => {
  const refused = [
    ["list", "--kind", "unit", "--bogus"],
    ["list", "--kinds", "unit"], // a typo of --kind once selected every entry
    ["list", "--kind"], // no value
    ["list", "stray"],
    ["list", "--json=yes"], // a boolean takes no value
    ["packages", "--json"],
    ["check", "--kind", "unit"],
    ["coverage", "--ids"],
    ["doc", "--json"],
    ["costs", "--json"],
    ["costs"],
    ["costs", "--private"],
    ["costs", "--private", "--json"],
    ["run", "scripts.suites-manifest", "--bogus"], // the entry's own arguments go after --
    ["run", "scripts.suites-manifest", "extra"],
    ["nope"],
    [],
  ];
  for (const args of refused) {
    const r = cliRun(...args);
    assert.equal(r.status, 2, `${args.join(" ")}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /^usage: node scripts\/suites\.mjs list /m, args.join(" "));
    assert.equal(r.stdout, "", args.join(" "));
  }
  // The refusal names what it refused.
  assert.match(cliRun("list", "--bogus").stderr, /--bogus/);
  assert.match(cliRun("run", "scripts.suites-manifest", "extra").stderr, /unexpected 'extra'/);
});

test("CLI: the retired --tier and --flaky-tiers are refused with their new names", () => {
  for (const [args, re] of [[["list", "--tier", "offline"], /--tier is now --kind/], [["list", "--tier=offline"], /--tier is now --kind/],
    [["packages", "--flaky-tiers", "unit"], /--flaky-tiers is now --flaky-kinds/]]) {
    const r = cliRun(...args);
    assert.equal(r.status, 2, args.join(" "));
    assert.match(r.stderr, re, args.join(" "));
  }
});

test("parseFlags: every command takes its own flags, in both spellings, and only those", () => {
  assert.deepEqual(parseFlags("list", ["--kind", "unit,stack", "--platform=linux", "--ids", "--include-flaky", "--needs-within", "offline"]),
    { kind: "unit,stack", platform: "linux", ids: true, "include-flaky": true, "needs-within": "offline" });
  assert.deepEqual(parseFlags("list", []), {});
  for (const [cmd, flags] of Object.entries(COMMAND_FLAGS)) {
    const argv = Object.entries(flags).flatMap(([k, o]) => (o.type === "string" ? [`--${k}`, "v"] : [`--${k}`]));
    const got = parseFlags(cmd, argv);
    assert.ok(!got.error, `${cmd}: ${got.error}`);
    assert.deepEqual(Object.keys(got).sort(), Object.keys(flags).sort(), cmd);
    // A flag of another command is not this one's.
    for (const other of new Set(Object.values(COMMAND_FLAGS).flatMap((f) => Object.keys(f)))) {
      if (!Object.hasOwn(flags, other)) assert.ok(parseFlags(cmd, [`--${other}`, "v"]).error, `${cmd} --${other}`);
    }
  }
});

test("CLI: the known flags still select (list, packages)", () => {
  const r = cliRun("list", "--kind=unit", "--platform", "linux", "--public", "--unsharded", "--ids");
  assert.equal(r.status, 0, r.stderr);
  assert.ok(r.stdout.trim().split(",").includes("scripts.suites-manifest"), r.stdout);
  const p = cliRun("packages", "--kind", "unit", "--public");
  assert.equal(p.status, 0, p.stderr);
  assert.match(p.stdout, /^arbiter$/m);
});

test("every caller of the suites.mjs CLI in scripts/, CI and the dashboard passes only that command's flags", () => {
  // Shell and YAML callers: `suites.mjs <cmd> …` up to the end of the command
  // (a trailing backslash continues it). A flag the command does not take would
  // now fail the caller, so this is the list to keep honest.
  const files = [
    "scripts/test-all.sh", ".github/workflows/ci.yml", ".gitlab-ci.yml",
    ...["pipeline.sh", "vm-run.sh", "nightly.sh", "claude-latest-lane.sh"].map((f) => join("scripts", "ci", f)),
    "scripts/test/test-all-native.test.sh",
  ];
  const calls = [];
  for (const rel of files) {
    let text;
    try { text = readFileSync(join(REPO_ROOT, rel), "utf8"); } catch { continue; }
    text = text.replace(/\\\n\s*/g, " ");
    for (const line of text.split("\n")) {
      if (/^\s*#/.test(line)) continue;
      for (const m of line.matchAll(/suites\.mjs"? (list|packages|check|coverage|doc|costs|run)\b([^|)`;]*)/g)) {
        calls.push({ where: rel, cmd: m[1], flags: [...m[2].matchAll(/(?<![\w-])--([a-z][a-z-]*)/g)].map((f) => f[1]) });
      }
    }
  }
  // The developer view reads the manifest through the CLI (its
  // test-runs/suite-manifest.ts), where this checkout has it.
  const devManifest = devViewFile("src/test-runs/suite-manifest.ts");
  if (devManifest !== null) {
    const dash = readFileSync(devManifest, "utf8");
    const argv = dash.match(/\[MANIFEST_CLI, "(\w+)"([^\]]*)\]/);
    assert.ok(argv, "the developer view's suite-manifest.ts: the CLI argv moved; update this test");
    calls.push({ where: "the developer view's suite-manifest.ts", cmd: argv[1], flags: [...argv[2].matchAll(/"--([a-z-]+)"/g)].map((f) => f[1]) });
  }
  assert.ok(calls.length >= 5, `found only ${calls.length} callers: ${JSON.stringify(calls)}`);
  for (const c of calls) {
    if (c.cmd === "run" || c.cmd === "costs") continue;
    for (const f of c.flags) assert.ok(Object.hasOwn(COMMAND_FLAGS[c.cmd], f), `${c.where}: suites.mjs ${c.cmd} --${f} is not a flag of ${c.cmd}`);
  }
});

test("the flaky budget: reason, since and revisit dates; two revisits is an error; overdue is only a note", () => {
  const ok = { reason: "PTY timing", since: "2026-09-28", revisit: "2026-10-28" };
  assert.deepEqual(flakyBudget(ok, "2026-10-01"), { errors: [], notes: [] });
  assert.deepEqual(flakyBudget({ ...ok, revisits: 1 }, "2026-10-01").errors, []);
  // Overdue: a note, never an error (an unrelated push must not fail on a date).
  const late = flakyBudget(ok, "2026-11-02");
  assert.deepEqual(late.errors, []);
  assert.match(late.notes.join(), /overdue \(due 2026-10-28\)/);
  // The budget: a flag that outlives two revisits is a bug to fix or a suite to delete.
  assert.match(flakyBudget({ ...ok, revisits: 2 }, "2026-10-01").errors.join(), /outlived 2 revisits/);
  // Shape.
  assert.match(flakyBudget({ reason: "x", since: "2026-09-28" }).errors.join(), /needs revisit/);
  assert.match(flakyBudget({ ...ok, revisit: "2026-09-01" }).errors.join(), /after since/);
  assert.match(flakyBudget({ ...ok, reason: "" }).errors.join(), /needs a reason/);
  assert.match(flakyBudget({ ...ok, since: "yesterday" }).errors.join(), /needs since/);
});

test("the manifest is complete: every test file and test* script claimed once, every path real, axes honest", async () => {
  const { entries, aggregates } = await loadManifest({ includePrivate: false });
  const { errors: all, notes } = checkManifest(entries, aggregates);
  for (const n of notes) console.log(`note: ${n}`);
  // In the source repository, a file or script a private entry claims (the
  // drills, kept out of the public snapshot) is not the public manifest's to
  // claim; the snapshot has no such file, so there the check is whole.
  const priv = (await loadManifest()).entries.filter((x) => x.private);
  const privClaims = new Set(priv.flatMap((x) => { const c = entryClaims(x); return [...c.files, ...c.scripts]; }));
  const errors = all.filter((e) => { const m = /^unclaimed (?:test file|npm script): (.+)$/.exec(e); return !(m && privClaims.has(m[1])); });
  assert.deepEqual(errors, [], `the manifest check failed:\n  ${errors.join("\n  ")}`);
});

test("the private entries (when private/ is present) pass the same entry checks", async () => {
  const { entries, aggregates, privateLoaded } = await loadManifest({ includePrivate: true });
  if (!privateLoaded) return;
  const { errors } = checkManifest(entries, aggregates);
  assert.deepEqual(errors, [], errors.join("\n"));
});

test("`suites.mjs check` reports a private manifest's own problems (its `problems(root)`), and --public leaves them out", async () => {
  const root = tree({
    "tests/suites.mjs": "export const entries = [];\nexport const aggregates = [];\n",
    "docs/design/architecture/protection-modes.md": FREEZE,
    "docs/testing/suites.md": "",
    "private/suites.mjs": "export const entries = [];\nexport async function problems(root) { return [`at ${root}`, \"two\"]; }\n",
  });
  const run = async (...args) => {
    let out = "";
    const code = await main(args, { root, stdout: { write: (s) => { out += s; } } });
    return { code, out };
  };
  try {
    assert.equal((await run("doc")).code, 0);
    const r = await run("check");
    assert.equal(r.code, 1, r.out);
    assert.ok(r.out.includes(`ERROR: drill: at ${root}\n`), r.out);
    assert.match(r.out, /ERROR: drill: two\n/);
    const json = JSON.parse((await run("check", "--json")).out);
    assert.deepEqual(json.drill, [`at ${root}`, "two"]);
    // without a private manifest (the public snapshot), no private problems (the
    // empty tree fails the public check on its own: no canary entry, no coverage)
    rmSync(join(root, "private"), { recursive: true });
    const pub = await run("check");
    assert.doesNotMatch(pub.out, /ERROR: drill:/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("every entry id fits the CI summary's id rule and every kind is a known one", async () => {
  const { entries } = await loadManifest();
  for (const x of entries) {
    assert.match(x.id, /^[A-Za-z0-9._:-]{1,120}$/, x.id);
    assert.ok(KINDS.includes(x.kind), `${x.id}: ${x.kind}`);
    assert.ok(!("tier" in x) && !("lane" in x) && !("byHand" in x), `${x.id}: a retired field`);
  }
});

test("the kind lists partition the kinds (test-reorganization.md §3)", () => {
  assert.deepEqual(KINDS, ["unit", "component", "stack", "replay-drill", "sandbox", "live-drill", "env", "eval", "install"]);
  assert.deepEqual([...PER_PUSH_KINDS, ...NIGHTLY_KINDS, "install"].sort(), [...KINDS].sort());
  assert.ok(HOST_FREE_KINDS.every((k) => PER_PUSH_KINDS.includes(k)));
  assert.ok(COVERAGE_KINDS.every((k) => PER_PUSH_KINDS.includes(k) && k !== "unit"));
  assert.ok([...NATIVE_BIN_KINDS].every((k) => PER_PUSH_KINDS.includes(k)));
  assert.deepEqual(CREDENTIALS, ["subscription", "api-key"]);
  for (const k of [...KINDS, "frozen"]) assert.ok(KIND_NOTES[k], k);
  assert.ok(Object.hasOwn(NEEDS, "kernel") && Object.hasOwn(NEEDS, "cli-latest"));
  for (const n of ENV_NEEDS) assert.ok(Object.hasOwn(NEEDS, n), n);
  assert.equal(new Set(PROPERTIES).size, PROPERTIES.length);
});

test("the per-push kinds hold what test-organization.md §6 and today's test-all.sh require", async () => {
  const { entries } = await loadManifest({ includePrivate: false });
  const byId = Object.fromEntries(entries.map((x) => [x.id, x]));
  const kindOf = (id) => byId[id]?.kind;
  // The AgentDojo eval is integrity-only (protection-modes.md §10.2): frozen, never per push.
  for (const id of ["eval.deterministic", "eval.run-live"]) assert.equal(byId[id].frozen, true, id);
  // What the offline tier held: unit, component or stack now, none frozen, none in the kernel lane.
  for (const id of ["arbiter", "launcher", "integration", "conformance", "rust", "fs-preload.redirect",
    "launcher.net-proxy-live", "launcher.net-proxy-mitm-live", "launcher.exec-wrap-live", "launcher.reply-filter-live",
    "scripts.require-userns", "scripts.docker-run", "scripts.suites-manifest", "scripts.run-suites", "matrix.smoke"]) {
    assert.ok(HOST_FREE_KINDS.includes(kindOf(id)) && !byId[id].frozen && !needsKernel(byId[id]), `${id}: ${kindOf(id)}`);
  }
  assert.equal(kindOf("integration"), "stack");
  assert.equal(kindOf("arbiter"), "component", "a package's npm test takes the kind of its most-real files");
  // What the kernel tier held: the kernel lane, sandbox kind but for the one that drives claude.
  for (const id of ["rust.kernel", "launcher.net-guard-live", "launcher.exec-box-live", "launcher.landlock-net-live",
    "launcher.secret-twins-live", "launcher.secret-readers-live", "launcher.guard-death-live",
    "integration.launcher-real-home", "integration.launcher-fixture-homes"]) {
    assert.ok(needsKernel(byId[id]), `${id} needs kernel`);
    assert.equal(kindOf(id), "sandbox", id);
  }
  const wire = entries.find((x) => x.id === "launcher.wire-release-live");
  assert.equal(wire.internet, true, "wire-release-live reaches httpbin.org: internet, never per push");
  for (const x of entries.filter((y) => PER_PUSH_KINDS.includes(y.kind) && !y.frozen && !needsKernel(y))) {
    assert.ok(x.timeout <= 5400, `${x.id}: a per-push entry with a timeout over 90 minutes`);
  }
  const kernel = entries.filter((x) => needsKernel(x) && !x.frozen);
  assert.ok(kernel.every((x) => x.ci && Number.isInteger(x.ci.maxSkip)), "every kernel-lane entry states its skip budget");
  const typecheck = entries.filter((x) => x.id.startsWith("typecheck."));
  assert.ok(typecheck.length >= 15 && typecheck.every((x) => x.kind === "unit"));
});

// ── the check itself, on a throwaway tree ──────────────────────────────────────

function tree(files) {
  const root = mkdtempSync(join(tmpdir(), "suites-check-"));
  for (const [p, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), body);
  }
  return root;
}

const FREEZE = "## 5. Test lanes\n\n- **Default lane** (`npm test`): every test, plus the **canaries**:\n  `pkg/test/unit/canary.test.ts`.\n- **Frozen lane** (x)\n";
const base = (o) => ({
  id: "x", kind: "component", axis: "secrets", cwd: "pkg", cmd: ["npm", "test"], env: {}, needs: ["node"], timeout: 60,
  parallel: true, gate: null, select: null, flaky: null, internet: false, platforms: ["linux"], doc: "docs/d.md", ...o,
});

function fixture() {
  return tree({
    "docs/design/architecture/protection-modes.md": FREEZE,
    "docs/d.md": "doc\n",
    "pkg/package.json": JSON.stringify({ scripts: { test: "MANDU_AXES_STRICT=1 tsx --test test/unit/*.test.ts", "test:unit": "tsx --test test/unit/*.test.ts", "test:live": "tsx --test test/live/*.test.ts", typecheck: "tsc" } }),
    "pkg/test/unit/a.test.ts": "",
    "pkg/test/unit/canary.test.ts": "",
    "pkg/test/live/l.test.ts": "",
    "scripts/test/s.test.sh": "",
  });
}

test("check: a complete tiny manifest passes", () => {
  const root = fixture();
  try {
    const entries = [
      base({ id: "pkg", scripts: ["test:unit"] }),
      base({ id: "pkg.live", kind: "replay-drill", cmd: ["npm", "run", "test:live"], needs: ["node", "claude"] }),
      base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] }),
    ];
    assert.deepEqual(checkManifest(entries, [], root).errors, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("check: unclaimed, twice-claimed, missing paths, bad kind/axis, frozen axis, host-free needs, variants", () => {
  const root = fixture();
  try {
    const entries = [
      base({ id: "pkg" }),
      base({ id: "dup", cmd: ["npx", "tsx", "--test", "test/unit/a.test.ts"] }),
      base({ id: "ghost", cwd: ".", cmd: ["bash", "scripts/test/nope.test.sh"], needs: ["bash"] }),
      base({ id: "weird", kind: "nightly", axis: "integrity", cmd: ["true"] }),
      base({ id: "int", axis: "full", cmd: ["true"] }),
      base({ id: "int-ok", axis: "injection", cmd: ["true"], todo: "re-pin to secrets (§7.1)" }),
      base({ id: "needy", cmd: ["true"], needs: ["claude"] }),
      base({ id: "var", cmd: ["npm", "run", "test:nope"], variantOf: "missing" }),
      base({ id: "pkg", cmd: ["true"] }),
    ];
    const { errors } = checkManifest(entries, [], root);
    const has = (re) => assert.ok(errors.some((e) => re.test(e)), `expected an error matching ${re}:\n${errors.join("\n")}`);
    has(/test file claimed twice: pkg\/test\/unit\/a\.test\.ts \(pkg, dup\)/);
    has(/unclaimed test file: pkg\/test\/live\/l\.test\.ts/);
    has(/unclaimed test file: scripts\/test\/s\.test\.sh/);
    has(/ghost: path 'scripts\/test\/nope\.test\.sh'.*matches nothing/);
    has(/weird: kind 'nightly' is not one of unit, component/);
    has(/weird: axis 'integrity'/);
    has(/int: axis 'full' switches integrity on outside the frozen lane \(kind component/);
    has(/needy: component entry needs 'claude'/);
    has(/var: npm script 'test:nope' not in pkg\/package\.json/);
    has(/var: variantOf 'missing' is no entry/);
    has(/unclaimed npm script: pkg#test:unit/);
    has(/unclaimed npm script: pkg#test:live/);
    has(/pkg: duplicate id/);
    assert.ok(!errors.some((e) => e.startsWith("int-ok:")), "a re-pin todo admits the integrity axis outside the frozen lane");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("check: a canary must run per push; a named canary must be in the freeze note", () => {
  const root = fixture();
  try {
    const entries = [
      base({ id: "pkg", frozen: true, scripts: ["test:unit"], canaries: ["pkg/test/unit/not-a-canary.test.ts"] }),
      base({ id: "pkg.live", kind: "replay-drill", cmd: ["npm", "run", "test:live"], needs: ["node", "claude"] }),
      base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] }),
    ];
    const { errors } = checkManifest(entries, [], root);
    assert.ok(errors.some((e) => /canary pkg\/test\/unit\/canary\.test\.ts is not in a per-push kind/.test(e)), errors.join("\n"));
    assert.ok(errors.some((e) => /not-a-canary\.test\.ts' is not named in protection-modes\.md/.test(e)), errors.join("\n"));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("check: the retired fields tier, lane and byHand are errors, each naming its new field", () => {
  const root = fixture();
  try {
    const ok = [
      base({ id: "pkg", scripts: ["test:unit"] }),
      base({ id: "pkg.live", kind: "replay-drill", cmd: ["npm", "run", "test:live"], needs: ["node", "claude"] }),
      base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] }),
    ];
    for (const extra of [{ tier: "offline" }, { lane: "subscription" }, { byHand: "a batch" }]) {
      const errs = checkManifest(ok.map((x) => (x.id === "pkg" ? { ...x, ...extra } : x)), [], root).errors;
      assert.ok(errs.some((e) => /^pkg: tier, lane and byHand are now kind, credential and manual/.test(e)), `${JSON.stringify(extra)}: ${errs.join("\n")}`);
    }
    const noKind = checkManifest(ok.map((x) => (x.id === "pkg" ? { ...x, kind: undefined } : x)), [], root).errors;
    assert.ok(noKind.some((e) => /^pkg: kind 'undefined' is not one of/.test(e)), noKind.join("\n"));
    const badFrozen = checkManifest(ok.map((x) => (x.id === "pkg" ? { ...x, frozen: "yes" } : x)), [], root).errors;
    assert.ok(badFrozen.some((e) => /^pkg: frozen is true or absent/.test(e)), badFrozen.join("\n"));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("check: proves lists known properties, at least one, none twice", () => {
  const root = fixture();
  try {
    const s = base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] });
    const live = base({ id: "pkg.live", kind: "replay-drill", cmd: ["npm", "run", "test:live"], needs: ["node", "claude"] });
    const run = (proves) => checkManifest([base({ id: "pkg", scripts: ["test:unit"], proves }), live, s], [], root).errors;
    assert.deepEqual(run(["model-ingress/file", "fs/twin"]), []);
    assert.deepEqual(run(undefined), [], "proves is optional");
    const has = (errs, re) => assert.ok(errs.some((e) => re.test(e)), errs.join("\n"));
    has(run(["model-ingress/telepathy"]), /pkg: proves 'model-ingress\/telepathy', which is not a property/);
    has(run([]), /pkg: proves is a non-empty list of properties/);
    has(run("fs/twin"), /pkg: proves is a non-empty list of properties/);
    has(run(["fs/twin", "fs/twin"]), /pkg: proves lists a property twice/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("check: a nightly-kind entry claims proves or says why it proves none (provesNone), never both; the manifest's nightly entries all do", async () => {
  const root = fixture();
  try {
    const s = base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] });
    const run = (kind, o) => checkManifest([base({ id: "pkg", scripts: ["test:unit"] }),
      base({ id: "pkg.n", kind, cmd: ["npm", "run", "test:live"], needs: ["node", "ollama"],
        ...(kind === "live-drill" ? { agent: "goose", needs: ["node", "ollama", "goose"] } : {}), ...o }), s], [], root).errors
      .filter((e) => e.startsWith("pkg.n:"));
    const has = (errs, re) => assert.ok(errs.some((e) => re.test(e)), errs.join("\n"));
    for (const kind of ["live-drill", "env", "eval"]) {
      has(run(kind, {}), /pkg\.n: a nightly entry claims `proves` .* or says why it proves none \(`provesNone`/);
      assert.deepEqual(run(kind, { proves: ["ullm/local-endpoint"] }), [], kind);
      assert.deepEqual(run(kind, { provesNone: "scores a metric" }), [], kind);
      has(run(kind, { proves: ["ullm/local-endpoint"], provesNone: "x" }), /pkg\.n: proves and provesNone together/);
      for (const bad of ["", "  ", true, "x".repeat(301)]) has(run(kind, { provesNone: bad }), /pkg\.n: provesNone is a reason of at most 300 characters/);
    }
    // a frozen nightly-kind entry, and a per-push one, need neither
    assert.deepEqual(run("live-drill", { frozen: true, axis: "full" }).filter((e) => /proves/.test(e)), []);
    assert.deepEqual(run("stack", { needs: ["node"] }).filter((e) => /proves/.test(e)), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
  // The real manifest: every nightly-kind entry outside the frozen lane says one or the other.
  const { entries } = await loadManifest();
  const nightly = entries.filter((x) => ["live-drill", "env", "eval"].includes(x.kind) && !x.frozen);
  assert.ok(nightly.length >= 5, `${nightly.length} nightly entries`);
  for (const x of nightly) assert.ok((x.proves?.length > 0) !== (typeof x.provesNone === "string"), x.id);
  // the claims made 2026-10-02 (test-reorganization.md §11.1)
  const byId = Object.fromEntries(entries.map((x) => [x.id, x]));
  assert.deepEqual(byId["integration.local-model"].proves, ["model-ingress/file", "ullm/local-endpoint", "ullm/quarantine", "reply/desymbolize"]);
  assert.match(byId["integration.ollama-doctor"].provesNone, /doctor/);
});

test("check: the kernel need is the sandbox kind's, and only sandbox, replay-drill or stack carry it", () => {
  const root = fixture();
  try {
    const s = base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] });
    const errs = (o) => checkManifest([base({ id: "pkg", scripts: ["test:unit"] }),
      base({ id: "pkg.live", cmd: ["npm", "run", "test:live"], ci: { maxSkip: 0, minPass: 1 }, ...o }), s], [], root).errors
      .filter((e) => e.startsWith("pkg.live:"));
    assert.deepEqual(errs({ kind: "sandbox", needs: ["kernel", "node", "userns"] }), []);
    assert.deepEqual(errs({ kind: "replay-drill", needs: ["kernel", "node", "claude"] }), []);
    assert.match(errs({ kind: "sandbox", needs: ["node", "userns"] }).join(), /a sandbox entry needs `kernel`/);
    for (const kind of ["unit", "component", "live-drill"]) {
      assert.match(errs({ kind, needs: ["kernel", "node"], credential: kind === "live-drill" ? "subscription" : undefined, ...(kind === "live-drill" ? { needs: ["kernel", "node", "claude-login"] } : {}) }).join(),
        new RegExp(`kind ${kind} cannot carry the kernel need`), kind);
    }
    // A kernel-lane entry says whether it is safe beside the others: parallel is a boolean, never "sandbox".
    assert.match(errs({ kind: "sandbox", needs: ["kernel", "node"], parallel: "sandbox" }).join(), /kernel-lane entry's parallel is true/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("check: an env entry names what the host decides (an ENV_NEEDS need, or internet)", () => {
  const root = fixture();
  try {
    const s = base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] });
    const errs = (o) => checkManifest([base({ id: "pkg", scripts: ["test:unit"] }),
      base({ id: "pkg.live", kind: "env", cmd: ["npm", "run", "test:live"], provesNone: "a fixture", ...o }), s], [], root).errors
      .filter((e) => e.startsWith("pkg.live:"));
    assert.deepEqual(errs({ needs: ["node", "ollama"] }), []);
    assert.deepEqual(errs({ needs: ["node", "claude", "claude-login"], credential: "subscription" }), []);
    assert.deepEqual(errs({ needs: ["node", "claude", "cli-latest"] }), []);
    assert.deepEqual(errs({ needs: ["node", "curl"], internet: true }), []);
    assert.match(errs({ needs: ["node", "claude"] }).join(), /an env entry names what the host decides: one of ollama, claude-login/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("claims: npm script globs, cmd paths, env prefixes and flags", () => {
  assert.deepEqual(scriptPathTokens("MANDU_E2E_ONLY=a,b tsx --test --test-name-pattern=x test/live/a.test.ts && tsx lib/u.ts"), ["test/live/a.test.ts", "lib/u.ts"]);
  assert.deepEqual(scriptPathTokens("export A=1 B=2 && tsx run.ts"), ["run.ts"]);
  const root = fixture();
  try {
    assert.deepEqual(expandGlob("test/unit/*.test.ts", join(root, "pkg"), root), ["pkg/test/unit/a.test.ts", "pkg/test/unit/canary.test.ts"]);
    assert.deepEqual(expandGlob("pkg/**/*.test.ts", root, root).length, 3);
    const c = entryClaims(base({ id: "pkg", scripts: ["test:unit"] }), root);
    assert.deepEqual([...c.scripts].sort(), ["pkg#test", "pkg#test:unit"]);
    assert.deepEqual([...c.files].sort(), ["pkg/test/unit/a.test.ts", "pkg/test/unit/canary.test.ts"]);
    const v = entryClaims(base({ id: "v", cmd: ["npm", "run", "test:live"], variantOf: "pkg" }), root);
    assert.deepEqual([...v.files], [], "a variant claims no files");
    assert.deepEqual([...v.scripts], ["pkg#test:live"]);
    assert.ok(walkTestFiles(root).includes("scripts/test/s.test.sh"));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("freezeCanaries reads protection-modes.md §10.5", () => {
  const c = freezeCanaries();
  assert.ok(c.includes("launcher/test/component/golden-path.test.ts"), c.join(","));
  assert.ok(c.includes("tests/conformance/lib/unit_symbolization.ts"), c.join(","));
  assert.ok(!c.includes("scripts/test-all.sh"));
});

// ── the CLI ────────────────────────────────────────────────────────────────────

const cli = (...args) => execFileSync(process.execPath, [SUITES, ...args], { encoding: "utf8", cwd: REPO_ROOT });

test("cli: list --json / --ids, packages, check", () => {
  const sandbox = JSON.parse(cli("list", "--kind", "sandbox", "--json"));
  assert.ok(sandbox.length >= 10 && sandbox.every((x) => x.kind === "sandbox" && !x.frozen && x.needs.includes("kernel")));
  const ids = cli("list", "--kind", "unit", "--only", "typecheck.*", "--ids").trim().split(",");
  assert.ok(ids.includes("typecheck.arbiter") && ids.every((i) => i.startsWith("typecheck.")));
  const hostFree = cli("list", "--kind", "unit,component,stack", "--platform", "linux", "--ids").trim().split(",");
  assert.ok(!hostFree.includes("launcher.wire-release-live"), "internet entries stay out of a kind listing");
  assert.ok(!hostFree.includes("arbiter.integrity"), "frozen entries stay out of a kind listing");
  // --native-bins: what scripts/test-all.sh builds the native bins for.
  assert.equal(cli("list", "--kind", "unit,component,stack", "--native-bins", "--ids").trim(), "");
  const native = cli("list", "--kind", "replay-drill,sandbox,live-drill", "--native-bins", "--ids").trim().split(",");
  assert.ok(native.includes("rust.kernel") && native.length >= 20, native.join(","));
  // --frozen alone: the frozen lane, whatever its kinds.
  const frozenOffline = cli("list", "--frozen", "--needs-within", "offline", "--ids").trim().split(",");
  assert.ok(frozenOffline.includes("arbiter.integrity") && !frozenOffline.includes("integration.claude-e2e"));
  const frozen = JSON.parse(cli("list", "--frozen", "--json"));
  assert.ok(frozen.length >= 10 && frozen.every((x) => x.frozen === true), "--frozen lists only the frozen lane");
  assert.ok(new Set(frozen.map((x) => x.kind)).size > 1, "the frozen lane holds entries of several kinds");
  // No --kind, no --frozen: everything.
  const all = cli("list", "--ids").trim().split(",");
  assert.ok(all.includes("arbiter.integrity") && all.includes("rust.kernel") && all.includes("install.matrix"));
  assert.throws(() => execFileSync(process.execPath, [SUITES, "list", "--kind", "offline"], { cwd: REPO_ROOT, stdio: "pipe" }), /unknown kind 'offline'/);
  assert.throws(() => execFileSync(process.execPath, [SUITES, "list", "--lane", "api"], { cwd: REPO_ROOT, stdio: "pipe" }), /--lane is subscription or api-key/);
  const pk = cli("packages").trim().split("\n");
  for (const d of ["arbiter", "launcher", "eval", "tests", "interceptors/anthropic-proxy"]) assert.ok(pk.includes(d), d);
  // --kind keeps only the packages of entries of those kinds (frozen entries left out).
  const pkStack = cli("packages", "--kind", "stack").trim().split("\n");
  assert.ok(pkStack.includes("tests") && !pkStack.includes("arbiter"), pkStack.join(","));
  // --bundle: what the launcher's bundle build reads (the OS test matrix installs it).
  assert.deepEqual(cli("packages", "--bundle").trim().split("\n"), bundlePackageDirs());
  assert.throws(() => execFileSync(process.execPath, [SUITES, "packages", "--bundle", "--kind", "unit"], { cwd: REPO_ROOT, stdio: "pipe" }), /takes no --kind/);
  assert.match(cli("check"), /0 error\(s\)/);
  assert.match(cli("coverage"), /^property\s+unit\s+component/m);
  const cov = JSON.parse(cli("coverage", "--json"));
  assert.deepEqual(cov.rows.map((r) => r.property), PROPERTIES);
});

test("bundlePackageDirs: the nearest package of each bundle source, optional ones only when present, launcher always", () => {
  const root = mkdtempSync(join(tmpdir(), "mandu-bundle-pkgs-"));
  try {
    const file = (rel, text = "") => { mkdirSync(dirname(join(root, rel)), { recursive: true }); writeFileSync(join(root, rel), text); };
    for (const p of ["launcher", "svc", "deep/pkg", "dash", "dev"]) file(`${p}/package.json`, "{}");
    file("launcher/bundle-manifest.json", JSON.stringify({
      services: { svc: "svc/src/main.ts", mandu: "launcher/src/run.ts" },
      modules: { m: "deep/pkg/a/b/c.ts" },
      assets: { "apparmor/x": "loose/apparmor/x" },
      assetDirs: { "dash/public": "dash/public" },
      optionalModules: { dev: "dev/src/index.ts", gone: "absent/src/index.ts" },
      optionalAssetDirs: { "dash/dev": "dev/pages" },
    }));
    file("dev/src/index.ts");
    file("dev/pages/index.html");
    assert.deepEqual(bundlePackageDirs(root), ["dash", "deep/pkg", "dev", "launcher", "svc"]);
    rmSync(join(root, "dev", "src"), { recursive: true });
    rmSync(join(root, "dev", "pages"), { recursive: true });
    assert.deepEqual(bundlePackageDirs(root), ["dash", "deep/pkg", "launcher", "svc"], "an optional source that is not here adds no package");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("shards: an entry runs as its shards, each with the parent's fields and its own cmd/env; naming the parent selects them all", async () => {
  const parent = {
    id: "pkg", kind: "component", axis: "secrets", cwd: "arbiter", cmd: ["npm", "test"], env: { A: "1" }, timeout: 100,
    parallel: true, platforms: ["linux"], needs: ["node"], internet: false, doc: "CONTRIBUTING.md",
    shards: [{ id: "one", env: { B: "2" } }, { id: "two", cmd: ["npx", "tsx", "--test", "x.test.ts"], timeout: 50 }],
  };
  const other = { ...parent, id: "other", shards: undefined };
  const ex = expandShards([parent, other]);
  assert.deepEqual(ex.map((x) => x.id), ["pkg.one", "pkg.two", "other"]);
  assert.deepEqual(ex[0].env, { A: "1", B: "2" });
  assert.deepEqual(ex[0].cmd, ["npm", "test"]);
  assert.deepEqual(ex[1].cmd, ["npx", "tsx", "--test", "x.test.ts"]);
  assert.equal(ex[1].timeout, 50);
  assert.equal(ex[0].shardOf, "pkg");
  assert.ok(!("shards" in ex[0]));
  assert.deepEqual(selectEntries([parent, other], { only: ["pkg"], platform: "linux" }).selected.map((x) => x.id), ["pkg.one", "pkg.two"]);
  assert.deepEqual(selectEntries([parent, other], { only: ["pkg.two"], platform: "linux" }).selected.map((x) => x.id), ["pkg.two"]);
  assert.deepEqual(selectEntries([parent, other], { kinds: ["component"], platform: "linux" }).selected.map((x) => x.id), ["pkg.one", "pkg.two", "other"]);
  const bad = checkManifest([{ ...parent, shards: [{ id: "one" }, { id: "one" }, { id: "b a d" }] }], []);
  assert.ok(bad.errors.some((e) => /duplicate shard 'one'/.test(e)), bad.errors.join("\n"));
  assert.ok(bad.errors.some((e) => /shard id 'b a d'/.test(e)), bad.errors.join("\n"));
});

test("the sharded manifest entries still claim every file their shards run (launcher)", async () => {
  const { entries } = await loadManifest({ includePrivate: false });
  const launcher = entries.find((x) => x.id === "launcher");
  assert.ok(Array.isArray(launcher.shards) && launcher.shards.length >= 2);
  const run = new Set(launcher.shards.flatMap((sh) => sh.cmd.filter((t) => t.endsWith(".test.ts")).map((t) => `launcher/${t}`)));
  const claimed = [...entryClaims(launcher).files].filter((f) => /^launcher\/test\/(unit|component)\/[^/]+\.test\.ts$/.test(f));
  assert.deepEqual([...run].sort(), claimed.sort(), "the shards run exactly the files npm test runs");
});

test("costs: longest first, manifest order among equals, an unknown entry at the default cost", () => {
  const xs = ["a", "b", "c", "d", "e"].map((id) => ({ id }));
  const order = orderByCost(xs, { a: 1, b: 50, c: 50, e: DEFAULT_COST + 1 }).map((x) => x.id);
  assert.deepEqual(order, ["b", "c", "e", "d", "a"]);
  assert.deepEqual(orderByCost(xs, {}).map((x) => x.id), ["a", "b", "c", "d", "e"], "no table: manifest order");
});

test("costs: the shared queue weights a kernel entry by slots ÷ kernel jobs, so the narrow lane starts early (§5.4)", () => {
  const xs = [{ id: "p1" }, { id: "k1", k: true }, { id: "p2" }, { id: "k2", k: true }];
  const costs = { p1: 300, k1: 100, p2: 120, k2: 20 };
  const isKernel = (x) => x.k === true;
  // 11 slots, 3 kernel jobs: k1 orders as ~367 s, k2 as ~73 s
  assert.deepEqual(sharedQueueOrder(xs, costs, { slots: 11, kernelJobs: 3, isKernel }).map((x) => x.id), ["k1", "p1", "p2", "k2"]);
  // a lane as wide as the queue: no weight, the plain order
  assert.deepEqual(sharedQueueOrder(xs, costs, { slots: 3, kernelJobs: 3, isKernel }).map((x) => x.id), orderByCost(xs, costs).map((x) => x.id));
  assert.deepEqual(sharedQueueOrder(xs, costs, { slots: 11, kernelJobs: 0, isKernel }).map((x) => x.id)[0], "k1", "kernelJobs 0 is taken as 1");
});

test("costs: a shard's queueAs orders it over the table (test-reorganization.md §6.9); the other shards keep the table", async () => {
  const parent = { id: "p", shards: [{ id: "late", queueAs: 25 }, { id: "early" }] };
  const ex = expandShards([parent]);
  assert.equal(ex.find((x) => x.id === "p.late").queueAs, 25);
  assert.equal("queueAs" in ex.find((x) => x.id === "p.early"), false);
  const order = orderByCost([...ex, { id: "mid" }], { "p.late": 40, "p.early": 37, mid: 30 }).map((x) => x.id);
  assert.deepEqual(order, ["p.early", "mid", "p.late"], "queued as 25 s, though the table says 40");
});

test("costs: the table from a summary keeps what ran, to a tenth of a second, ids sorted", () => {
  const t = costsFromSummary({ entries: [
    { id: "z", result: "pass", duration_s: 12.345 }, { id: "a", result: "fail", duration_s: 3 },
    { id: "s", result: "skip", duration_s: 0.1 }, { id: "t", result: "timeout", duration_s: 900 },
  ] });
  assert.deepEqual(Object.keys(t), ["a", "t", "z"], "a skip ran nothing worth timing");
  assert.equal(t.z, 12.3);
  assert.throws(() => costsFromSummary({}), /not a run summary/);
  assert.deepEqual(costsFromSummary({ entries: [{ id: "a", result: "pass", duration_s: 1 }, { id: "b", result: "pass", duration_s: 2 }] }, (id) => id === "b"), { b: 2 });
});

/** A run summary for the costs tests: `n` filler entries (f0…) plus `entries`. */
const runOf = (started, result, entries, n = 0) => ({
  kind: "mandu-ci-run", started, result,
  entries: [...entries, ...Array.from({ length: n }, (_, i) => ({ id: `f${i}`, result: "pass", duration_s: 1 }))],
});

test("costs from runs: each entry's median over the last green full runs; red, small (docs-lane, --only) and older runs left out", () => {
  const runs = [
    runOf("2026-10-01T00:00:00Z", "pass", [{ id: "k", result: "pass", duration_s: 1000 }], 20), // older than the last 3
    runOf("2026-10-02T00:00:00Z", "pass", [{ id: "k", result: "pass", duration_s: 250 }], 20),
    runOf("2026-10-03T00:00:00Z", "pass", [{ id: "k", result: "pass", duration_s: 260 }, { id: "new", result: "pass", duration_s: 40 }], 20),
    runOf("2026-10-04T00:00:00Z", "pass", [{ id: "k", result: "pass", duration_s: 300 }, { id: "new", result: "pass", duration_s: 45 }], 20),
    runOf("2026-10-05T00:00:00Z", "fail", [{ id: "k", result: "pass", duration_s: 9 }], 20), // a red run
    runOf("2026-10-06T00:00:00Z", "pass", [{ id: "k", result: "pass", duration_s: 5 }], 1), // a docs-lane run: 2 of 22 entries
    { kind: "mandu-ci-run", result: "pass" }, // no entries
    null,
  ];
  const t = costsFromRuns(runs, { last: 3 });
  assert.equal(t.k, 260, "the median of 250, 260, 300; neither the older 1000, the red run's 9 nor the docs lane's 5");
  assert.equal(t.new, 42.5, "an even count: the mean of the middle two");
  assert.deepEqual(Object.keys(t), [...Object.keys(t)].sort(), "ids sorted");
  assert.equal(costsFromRuns(runs, { last: 3, keep: (id) => id === "new" }).k, undefined, "keep filters the ids");
  // An entry that did not pass in a run is not timed by that run.
  const t2 = costsFromRuns([runOf("2026-10-07T00:00:00Z", "pass", [{ id: "s", result: "skip", duration_s: 0.1 }, { id: "x", result: "pass", duration_s: 12.345 }])]);
  assert.deepEqual(t2, { x: 12.3 });
  assert.deepEqual(costsFromRuns([]), {}, "no run: an empty table (the runner then uses the checked-in ones)");
});

test("costs CLI over a runs directory: --all names every entry that ran without reading the manifest; --last; one summary keeps its old meaning", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-costs-runs-"));
  try {
    const runs = join(dir, "runs");
    const put = (name, s) => { mkdirSync(join(runs, name), { recursive: true }); writeFileSync(join(runs, name, "summary.json"), JSON.stringify(s)); };
    put("gl-1-1", runOf("2026-10-01T00:00:00Z", "pass", [{ id: "scripts.suites-manifest", result: "pass", duration_s: 2 }, { id: "gone.entry", result: "pass", duration_s: 10 }]));
    put("gl-2-2", runOf("2026-10-02T00:00:00Z", "pass", [{ id: "scripts.suites-manifest", result: "pass", duration_s: 4 }, { id: "gone.entry", result: "pass", duration_s: 20 }]));
    mkdirSync(join(runs, "gl-3-3")); writeFileSync(join(runs, "gl-3-3", "summary.json"), "{ not json"); // skipped
    mkdirSync(join(runs, "no-summary"));
    const all = cliRun("costs", "--all", runs);
    assert.equal(all.status, 0, all.stderr);
    assert.deepEqual(JSON.parse(all.stdout), { "gone.entry": 15, "scripts.suites-manifest": 3 });
    const last1 = cliRun("costs", "--all", "--last", "1", runs);
    assert.deepEqual(JSON.parse(last1.stdout), { "gone.entry": 20, "scripts.suites-manifest": 4 }, "the most recent run only");
    const pub = cliRun("costs", runs);
    assert.deepEqual(JSON.parse(pub.stdout), { "scripts.suites-manifest": 3 }, "the public table: only the manifest's entries");
    const one = cliRun("costs", "--all", join(runs, "gl-1-1", "summary.json"));
    assert.deepEqual(JSON.parse(one.stdout), { "gone.entry": 10, "scripts.suites-manifest": 2 }, "one summary: that run's durations");
    for (const bad of [["costs", "--all", "--private", runs], ["costs", "--last", "0", runs], ["costs", "--last", "x", runs], ["costs", "--all", join(dir, "absent")]]) {
      assert.equal(cliRun(...bad).status, 2, bad.join(" "));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("costs CLI: the public table names only public entries, --private only private/suites.mjs's (a public snapshot has no private entry to time)", async () => {
  const { entries, privateLoaded } = await loadManifest();
  const priv = expandShards(entries).find((x) => x.private);
  const dir = mkdtempSync(join(tmpdir(), "mandu-costs-cli-"));
  try {
    const summary = join(dir, "summary.json");
    writeFileSync(summary, JSON.stringify({ entries: [
      { id: "scripts.suites-manifest", result: "pass", duration_s: 1.04 },
      { id: "gone.entry", result: "pass", duration_s: 5 },
      ...(priv ? [{ id: priv.id, result: "pass", duration_s: 7 }] : []),
    ] }));
    const pub = cliRun("costs", summary);
    assert.equal(pub.status, 0, pub.stderr);
    assert.deepEqual(JSON.parse(pub.stdout), { "scripts.suites-manifest": 1 }, "neither a private entry nor one the manifest lacks");
    const p = cliRun("costs", "--private", summary);
    if (privateLoaded) {
      assert.equal(p.status, 0, p.stderr);
      assert.deepEqual(JSON.parse(p.stdout), { [priv.id]: 7 });
    } else {
      assert.equal(p.status, 2);
      assert.match(p.stderr, /no private\/suites\.mjs/);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("costs: loadCosts refuses a malformed table; an absent default table is empty; the checked-in table names only real entries", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-costs-"));
  try {
    assert.deepEqual(loadCosts(join(dir, "absent.json")), {});
    assert.throws(() => loadCosts(join(dir, "absent.json"), { required: true }), /not found/);
    writeFileSync(join(dir, "neg.json"), JSON.stringify({ a: -1 }));
    assert.throws(() => loadCosts(join(dir, "neg.json")), /not a number of seconds/);
    writeFileSync(join(dir, "arr.json"), "[]");
    assert.throws(() => loadCosts(join(dir, "arr.json")), /not an object/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  // Both default tables merge; the private one may be absent (the public snapshot).
  const root = mkdtempSync(join(tmpdir(), "mandu-costs-root-"));
  try {
    mkdirSync(join(root, "tests"));
    writeFileSync(join(root, COSTS_FILE), JSON.stringify({ a: 1 }));
    assert.deepEqual(loadAllCosts(root), { a: 1 });
    mkdirSync(join(root, "private"));
    writeFileSync(join(root, PRIVATE_COSTS_FILE), JSON.stringify({ b: 2 }));
    assert.deepEqual(loadAllCosts(root), { a: 1, b: 2 });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  // The public table names only entries of the public manifest, so it holds in
  // the public snapshot too; the private table only private/suites.mjs's.
  const table = loadCosts(join(REPO_ROOT, COSTS_FILE), { required: true });
  const { entries: pubEntries } = await loadManifest({ includePrivate: false });
  const pubIds = new Set(expandShards(pubEntries).map((x) => x.id));
  const stale = Object.keys(table).filter((id) => !pubIds.has(id));
  assert.deepEqual(stale, [], `${COSTS_FILE} names entries the public manifest does not have (removed, or private): regenerate it (node scripts/suites.mjs costs <summary.json>)`);
  const { entries, privateLoaded } = await loadManifest();
  if (privateLoaded) {
    const privIds = new Set(expandShards(entries).filter((x) => x.private).map((x) => x.id));
    const privStale = Object.keys(loadCosts(join(REPO_ROOT, PRIVATE_COSTS_FILE))).filter((id) => !privIds.has(id));
    assert.deepEqual(privStale, [], `${PRIVATE_COSTS_FILE} names entries private/suites.mjs does not have: regenerate it (node scripts/suites.mjs costs --private <summary.json>)`);
  }
});

// ── list --unsharded / --public ────────────────────────────────────────────────

test("cli: list --unsharded keeps a sharded entry whole (its shards array kept); --public leaves private/ out", () => {
  const whole = JSON.parse(cli("list", "--kind", "unit,component,stack", "--platform", "linux", "--unsharded", "--public", "--json"));
  const launcher = whole.find((x) => x.id === "launcher");
  assert.ok(launcher, "the sharded launcher entry is listed as itself");
  assert.ok(Array.isArray(launcher.shards) && launcher.shards.length >= 2, "it keeps its shards");
  assert.ok(!whole.some((x) => x.shardOf), "no shard entries");
  assert.ok(whole.every((x) => !x.private), "--public: no private entry");
  const split = JSON.parse(cli("list", "--kind", "unit,component,stack", "--platform", "linux", "--public", "--json"));
  assert.ok(!split.some((x) => x.id === "launcher") && split.some((x) => x.shardOf === "launcher"), "without --unsharded the shards are listed");
  assert.deepEqual(selectEntries([{ id: "p", kind: "component", platforms: ["linux"], shards: [{ id: "a" }, { id: "b" }] }],
    { kinds: ["component"], platform: "linux", unsharded: true }).selected.map((x) => x.id), ["p"]);
});

// ── the GitHub workflow reads the manifest (public-ci §1, §3) ─────────────────
// There is no GitHub remote to run .github/workflows/ci.yml on, so these run
// the workflow's own `run:` blocks (the packages, shell and rust list
// steps) against the current manifest and check that every offline, Linux,
// public entry lands in exactly one job.

const WORKFLOW = join(REPO_ROOT, ".github", "workflows", "ci.yml");
const PRIVATE_REPO_GATE_TERM = "!github.event.repository.private || github.event_name == 'workflow_dispatch'";
const PRIVATE_REPO_GATE = `\${{ ${PRIVATE_REPO_GATE_TERM} }}`;

/**
 * A root job's `if`: the private-repository gate alone, or `(gate) && (more)`
 * with `more` one parenthesized group, so nothing outside it can OR past the gate.
 */
function isPrivateGated(expr) {
  if (expr === PRIVATE_REPO_GATE) return true;
  const head = `\${{ (${PRIVATE_REPO_GATE_TERM}) && (`;
  if (typeof expr !== "string" || !expr.startsWith(head) || !expr.endsWith(") }}")) return false;
  const rest = expr.slice(head.length - 1, -3); // "( … )"
  let depth = 0;
  for (let i = 0; i < rest.length; i++) {
    depth += rest[i] === "(" ? 1 : rest[i] === ")" ? -1 : 0;
    if (depth === 0 && i < rest.length - 1) return false; // the group closed before the end
  }
  return depth === 0;
}

test("isPrivateGated: the gate alone, or the gate AND-ed with one further group; nothing that bypasses it", () => {
  assert.ok(isPrivateGated(PRIVATE_REPO_GATE));
  assert.ok(isPrivateGated(`\${{ (${PRIVATE_REPO_GATE_TERM}) && (github.event.action != 'labeled' || github.event.label.name == 'run-ci') }}`));
  assert.ok(!isPrivateGated(`\${{ ${PRIVATE_REPO_GATE_TERM} && x }}`), "unparenthesized: && binds tighter, so the dispatch term would bypass x");
  assert.ok(!isPrivateGated(`\${{ (${PRIVATE_REPO_GATE_TERM}) && (a) || (b) }}`), "a top-level || bypasses the gate");
  assert.ok(!isPrivateGated(`\${{ x && (${PRIVATE_REPO_GATE_TERM}) }}`));
  assert.ok(!isPrivateGated("${{ github.event_name == 'pull_request' }}"));
  assert.ok(!isPrivateGated(undefined));
});

/**
 * The `run: |` block of the step `id: <stepId>` in job <job> of a workflow,
 * de-indented. A line-based reader for the file's own layout (two-space jobs,
 * `- id:` steps, block-scalar `run: |`), so it needs no YAML package.
 */
function workflowStepRun(yml, job, stepId) {
  const lines = yml.split("\n");
  const start = lines.findIndex((l) => l === `  ${job}:`);
  if (start < 0) throw new Error(`no job ${job}`);
  let end = lines.findIndex((l, i) => i > start && /^ {0,2}\S/.test(l));
  if (end < 0) end = lines.length;
  const at = lines.findIndex((l, i) => i > start && i < end && new RegExp(`^\\s*-?\\s*id: ${stepId}\\s*$`).test(l));
  if (at < 0) throw new Error(`no step id ${stepId} in job ${job}`);
  const dash = lines[at].search(/-/);
  for (let i = at + 1; i < end; i++) {
    if (new RegExp(`^ {${dash}}- `).test(lines[i])) break; // the next step
    const m = /^(\s*)run: \|\s*$/.exec(lines[i]);
    if (!m) continue;
    const body = [];
    for (let j = i + 1; j < end; j++) {
      if (lines[j].trim() && lines[j].search(/\S/) <= m[1].length) break;
      body.push(lines[j]);
    }
    const ind = Math.min(...body.filter((l) => l.trim()).map((l) => l.search(/\S/)));
    return body.map((l) => l.slice(ind)).join("\n").trimEnd() + "\n";
  }
  throw new Error(`step ${stepId} in job ${job} has no run: | block`);
}

/** Run a step's script as the runner does (bash -e), returning its $GITHUB_OUTPUT as {key: value}. */
function runStep(script, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "gh-step-"));
  try {
    const out = join(dir, "output");
    writeFileSync(out, "");
    execFileSync("bash", ["--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script],
      { cwd: REPO_ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env, GITHUB_OUTPUT: out } });
    const kv = {};
    for (const l of readFileSync(out, "utf8").split("\n").filter(Boolean)) {
      const i = l.indexOf("=");
      assert.ok(i > 0, `a GITHUB_OUTPUT line is key=value on one line: ${l}`);
      assert.ok(!(l.slice(0, i) in kv), `the step sets ${l.slice(0, i)} once`);
      kv[l.slice(0, i)] = l.slice(i + 1);
    }
    return kv;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test("workflowStepRun: the step's run block, de-indented, scoped to its job", () => {
  const yml = ["jobs:", "  a:", "    steps:", "      - id: list", "        run: |", "          echo a", "            nested", "",
    "      - name: next", "        run: |", "          echo other", "  b:", "    steps:", "      - id: list", "        name: n",
    "        run: |", "          echo b", ""].join("\n");
  assert.equal(workflowStepRun(yml, "a", "list"), "echo a\n  nested\n");
  assert.equal(workflowStepRun(yml, "b", "list"), "echo b\n");
  assert.throws(() => workflowStepRun(yml, "c", "list"), /no job c/);
  assert.throws(() => workflowStepRun(yml, "a", "find"), /no step id find in job a/);
  assert.throws(() => workflowStepRun("jobs:\n  a:\n    steps:\n      - id: x\n        uses: y\n      - run: |\n          z\n", "a", "x"),
    /has no run: \| block/, "the next step's run block is not the step's");
});

test("ci.yml: the packages, shell and rust steps build valid outputs, and every offline entry lands in exactly one job",
  { skip: !["jq", "git"].every((c) => { try { execFileSync("sh", ["-c", `command -v ${c}`], { stdio: "ignore" }); return true; } catch { return false; } }) && "needs jq and git (the packages step)" },
  () => {
    const yml = readFileSync(WORKFLOW, "utf8");
    // packages: a JSON array of the package directories `suites.mjs packages` names, less private/.
    const packages = JSON.parse(runStep(workflowStepRun(yml, "packages", "find")).list);
    const named = cli("packages").trim().split("\n").filter((d) => d && !d.startsWith("private/"));
    assert.deepEqual([...packages].sort(), [...named].sort(), "the lockfile discovery finds the manifest's packages");

    // shell: a comma list of ids run-suites.mjs --only takes, run in one job.
    const shellIds = runStep(workflowStepRun(yml, "shell", "list")).ids.split(",");
    assert.ok(shellIds.length > 0 && shellIds.every(Boolean), "a non-empty id list");
    assert.equal(new Set(shellIds).size, shellIds.length, "no id twice");

    // rust: a comma list of ids run-suites.mjs --only takes.
    const rustIds = runStep(workflowStepRun(yml, "rust", "list")).ids.split(",");
    for (const id of ["rust", "rust.check-aarch64", "fs-preload.redirect"]) assert.ok(rustIds.includes(id), `rust runs ${id}`);

    // The split: each unit, component or stack (the old offline tier), Linux, public entry is exactly one job's.
    const listed = JSON.parse(cli("list", "--kind", "unit,component,stack", "--platform", "linux", "--json", "--public"));
    const byId = new Map(listed.map((x) => [x.id, x]));
    for (const id of [...shellIds, ...rustIds]) assert.ok(byId.has(id), `${id} is an offline, Linux, public entry`);
    const ts = (x) => packages.includes(x.cwd) && (
      (x.cmd[0] === "npm" && (x.cmd[1] === "test" || (x.cmd[1] === "run" && x.cmd[2] === "typecheck"))) ||
      (x.cmd[0] === "npx" && x.cmd[1] === "tsx" && x.cmd[2] === "--test" && Boolean(x.shardOf)));
    for (const x of listed) {
      const jobs = [ts(x) && "ts", shellIds.includes(x.id) && "shell", rustIds.includes(x.id) && "rust"].filter(Boolean);
      assert.equal(jobs.length, 1, `${x.id} (${x.cmd.join(" ")}) runs in exactly one GitHub job, not [${jobs.join(", ")}]`);
    }
    // A kernel, internet or frozen entry never gets a cell.
    for (const id of [...shellIds, ...rustIds]) {
      const x = byId.get(id);
      assert.ok(HOST_FREE_KINDS.includes(x.kind) && !x.frozen && !x.internet && !x.private, id);
    }
  });

// Every workflow GitHub would run. The release workflow is the one a tag
// starts; every other one is the pull-request / manual kind.
const WORKFLOWS = readdirSync(join(REPO_ROOT, ".github", "workflows")).filter((f) => /\.ya?ml$/.test(f)).sort();
const RELEASE_WORKFLOW = "release.yml";

test("every workflow parses as YAML, and each job's needs and outputs name what exists",
  { skip: (() => { try { execFileSync("python3", ["-c", "import yaml"], { stdio: "ignore" }); return false; } catch { return "needs python3 with PyYAML"; } })() },
  () => {
    for (const f of WORKFLOWS) {
      const doc = JSON.parse(execFileSync("python3", ["-c",
        "import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1])), default=str))",
        join(REPO_ROOT, ".github", "workflows", f)], { encoding: "utf8" }));
      assert.ok(doc.jobs && Object.keys(doc.jobs).length, `${f} has jobs`);
      // On a private repository (the free plan's metered minutes) only a manual
      // run starts a job; a job that needs another skips with it (§12). The
      // release workflow (a v* tag, never a pull request) refuses a private
      // repository in its own first step instead (scripts/test/release-workflow.test.mjs).
      for (const [name, job] of Object.entries(doc.jobs)) {
        if (job.needs || f === RELEASE_WORKFLOW) continue;
        assert.ok(isPrivateGated(job.if), `${f}: root job ${name} runs on a private repository only when started by hand (if: ${job.if})`);
      }
      for (const [name, job] of Object.entries(doc.jobs)) {
        for (const n of [job.needs ?? []].flat()) assert.ok(n in doc.jobs, `${f}: ${name} needs ${n}, which is a job`);
        const stepIds = new Set((job.steps ?? []).map((s) => s.id).filter(Boolean));
        for (const [k, v] of Object.entries(job.outputs ?? {})) {
          const m = /steps\.([\w-]+)\.outputs\./.exec(v);
          assert.ok(m && stepIds.has(m[1]), `${f}: ${name}.outputs.${k} reads a step of ${name}`);
        }
        for (const s of job.steps ?? []) {
          for (const m of JSON.stringify(s).matchAll(/steps\.([\w-]+)\.outputs\./g)) assert.ok(stepIds.has(m[1]), `${f}: ${name} reads step ${m[1]}`);
          for (const m of JSON.stringify(s).matchAll(/needs\.([\w-]+)\.outputs\.([\w-]+)/g)) {
            assert.ok(doc.jobs[m[1]]?.outputs?.[m[2]], `${f}: ${name} reads ${m[1]}.outputs.${m[2]}, which exists`);
          }
        }
        for (const m of JSON.stringify(job.strategy ?? {}).matchAll(/needs\.([\w-]+)\.outputs\.([\w-]+)/g)) {
          assert.ok([job.needs].flat().includes(m[1]) && doc.jobs[m[1]]?.outputs?.[m[2]], `${f}: ${name}'s matrix reads ${m[1]}.outputs.${m[2]}`);
        }
      }
      if (f === "ci.yml") {
        assert.ok(doc.jobs.ts.steps.every((s) => !/eval:deterministic/.test(s.run ?? "")), "the frozen AgentDojo corpus is not run");
        assert.match(doc.jobs.rust.steps.map((s) => s.run ?? "").join("\n"), /--target aarch64-unknown-linux-gnu/,
          "the rust job installs the aarch64 target, so rust.check-aarch64 does not skip");
      }
    }
  });

// ── when GitHub runs (continuous-integration.md §12, "When GitHub runs") ──────
// Only where GitHub is the only signal: the release check (ci.yml called by
// release.yml on a v* tag), a manual run, and a pull request once the
// repository is public. No macOS: a maintainer runs the darwin entries on a
// Mac by hand (decided 2026-10-09). Never a snapshot push to main/master
// (GitLab ran a superset on the commit); a v* tag starts only release.yml.

const NO_PYYAML = (() => { try { execFileSync("python3", ["-c", "import yaml"], { stdio: "ignore" }); return false; } catch { return "needs python3 with PyYAML"; } })();
const workflowDoc = (f) => JSON.parse(execFileSync("python3", ["-c",
  "import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1])), default=str))",
  join(REPO_ROOT, ".github", "workflows", f)], { encoding: "utf8" }));
// PyYAML reads the key `on` as YAML 1.1's boolean true.
const triggers = (doc) => doc.on ?? doc.true;

test("workflows: no push, tag or schedule trigger runs a job; a pull request, a manual run and the release's call do", { skip: NO_PYYAML }, () => {
  for (const f of WORKFLOWS.filter((w) => w !== RELEASE_WORKFLOW)) {
    const doc = workflowDoc(f);
    const on = triggers(doc);
    assert.deepEqual(Object.keys(on).sort(), ["pull_request", "workflow_call", "workflow_dispatch"], `${f}: triggers`);
    assert.ok(!JSON.stringify(on).includes("tags"), `${f}: no tag filter`);
    assert.ok(!("branches" in (on.pull_request ?? {})), `${f}: a pull request against any branch`);
    // A newer push to a pull request cancels the older run; nothing else does.
    assert.equal(doc.concurrency["cancel-in-progress"], "${{ github.event_name == 'pull_request' }}", `${f}: cancel-in-progress`);
  }
  // The release workflow: a v* tag push and nothing else (no branch push).
  const rel = triggers(workflowDoc(RELEASE_WORKFLOW));
  assert.deepEqual(rel, { push: { tags: ["v*"] } }, `${RELEASE_WORKFLOW}: a v* tag only`);
});

test("ci.yml: a documentation-only pull request runs nothing, the same cut as the GitLab docs lane (lane.mjs isDocsPath)",
  { skip: NO_PYYAML }, () => {
    const pr = triggers(workflowDoc("ci.yml")).pull_request;
    assert.deepEqual(Object.keys(pr), ["paths"], "the paths filter only (paths-ignore cannot re-include the docs lane's exceptions)");
    const runs = (p) => filterMatch(pr.paths, p);
    for (const p of ["arbiter/src/a.ts", ".github/workflows/ci.yml", "launcher/README.md", "arbiter/test/fixtures/handling-prompt-full.md", "tests/suites.mjs"]) {
      assert.equal(runs(p), true, `${p} runs CI`);
    }
    for (const p of ["docs/README.md", "docs/design/confidentiality/figures/a.svg", "README.md", "interceptors/README.md", "CHANGELOG.md"]) {
      assert.equal(runs(p), false, `${p} alone runs nothing`);
    }
    // GitHub runs the workflow when ANY changed path is selected: docs plus code runs.
    assert.ok(["docs/a.md", "arbiter/src/a.ts"].some(runs));
    // Every tracked file: CI runs on it exactly when the docs lane would not take it.
    const tracked = execFileSync("git", ["ls-files", "-z"], { cwd: REPO_ROOT, encoding: "utf8" }).split("\0").filter(Boolean);
    const differ = tracked.filter((p) => runs(p) === isDocsPath(p));
    assert.deepEqual(differ, [], "ci.yml's paths filter and lane.mjs's isDocsPath disagree");
  });

test("workflows: no job runs on a macOS runner (the darwin entries run on a Mac by hand, development.md)", { skip: NO_PYYAML }, () => {
  assert.deepEqual(WORKFLOWS, ["ci.yml", RELEASE_WORKFLOW], "CI and the release; a new one is checked by the tests above");
  for (const f of WORKFLOWS) {
    for (const [name, job] of Object.entries(workflowDoc(f).jobs)) {
      const where = JSON.stringify([job["runs-on"], job.strategy ?? {}]);
      assert.doesNotMatch(where, /macos/i, `${f}: ${name} runs on macOS (${where})`);
    }
  }
});

// ── the `session` field (the dashboard's test-session class) ──────────────────

test("check: session { cls, file, label }: class shape, a claimed existing file, a label, no other key, a unique class", () => {
  const root = fixture();
  try {
    const ok = base({ id: "pkg.live", kind: "replay-drill", cmd: ["npm", "run", "test:live"], needs: ["node", "claude"],
      session: { cls: "pkg-e2e", file: "test/live/l.test.ts", label: "pkg-e2e: a live run" } });
    assert.deepEqual(sessionProblems(ok, entryClaims(ok, root), root), []);
    const probs = (session) => sessionProblems({ ...ok, session }, entryClaims(ok, root), root).join("\n");
    assert.match(probs({ cls: "Pkg_E2E", file: "test/live/l.test.ts", label: "x" }), /session\.cls 'Pkg_E2E' must match/);
    assert.match(probs({ cls: "pkg", file: "test/live/l.test.ts", label: "x" }), /session\.cls 'pkg' must match/);
    assert.match(probs({ cls: "pkg-e2e", file: "test/live/nope.test.ts", label: "x" }), /session\.file 'test\/live\/nope\.test\.ts' does not exist/);
    assert.match(probs({ cls: "pkg-e2e", file: "test/unit/a.test.ts", label: "x" }), /is not a file this entry claims/);
    assert.match(probs({ cls: "pkg-e2e", file: "test/live/l.test.ts", label: " " }), /session\.label must be a non-empty string/);
    assert.match(probs({ cls: "pkg-e2e", file: "test/live/l.test.ts", label: "x", kind: "live" }), /unknown key 'kind'/);
    assert.match(probs("pkg-e2e"), /session must be an object/);
    const entries = [
      base({ id: "pkg", scripts: ["test:unit"], session: { cls: "pkg-e2e", file: "test/unit/a.test.ts", label: "unit" } }),
      ok,
      base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] }),
    ];
    const { errors } = checkManifest(entries, [], root);
    assert.ok(errors.some((e) => /pkg\.live: session class 'pkg-e2e' is also entry pkg's/.test(e)), errors.join("\n"));
    assert.deepEqual(checkManifest([{ ...entries[0], session: undefined }, ok, entries[2]], [], root).errors, []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// ── the generated table: docs/testing/suites.md ────────────────────────────────

test("docs/testing/suites.md is the generator's output for the public manifest (run `node scripts/suites.mjs doc`)", async () => {
  const { entries } = await loadManifest({ includePrivate: false });
  assert.equal(suitesDocProblem(entries), null);
  const doc = renderSuitesDoc(entries);
  for (const t of [...KINDS, "frozen"]) assert.match(doc, new RegExp(`^## ${t}$`, "m"));
  for (const x of entries) assert.ok(doc.includes(`| \`${x.id}\` |`), `${x.id} has a row`);
  assert.ok(!doc.includes("private/"), "no private path in the public page");
});

test("renderSuitesDoc: single-line cells, escaped pipes, shard counts, flags, proves, session, relative doc links", () => {
  const doc = renderSuitesDoc([
    base({ id: "a", cmd: ["bash", "-c", "x | y\nz"], flaky: { reason: "r", since: "s" }, parallel: false, doc: "docs/design/d.md",
      session: { cls: "a-e2e", file: "t", label: "l" }, gate: "G", proves: ["fs/twin", "model-ingress/file"] }),
    base({ id: "b", kind: "sandbox", shards: [{ id: "1" }, { id: "2" }], parallel: "sandbox", todo: "t", internet: true }),
    base({ id: "c", kind: "live-drill", manual: "a batch", credential: "subscription" }),
  ]);
  const row = doc.split("\n").find((l) => l.startsWith("| `a` |"));
  assert.equal(row, "| `a` | secrets | `pkg` | `bash -c x \\| y z` | node | flaky, serial, gate `G` | fs/twin, model-ingress/file | `a-e2e` | [design/d.md](../design/d.md) |");
  assert.match(doc, /\| `b` \| .* \| `npm test` \(2 shards\) \| node \| internet, sandbox, todo \|/);
  assert.match(doc, /\| `c` \| .* \| manual, credential subscription \|/);
  assert.doesNotMatch(doc, /\d+ entries|^## \S+ \(\d+\)$/m, "no counts: they make every added entry touch shared lines");
  assert.match(doc, /^## replay-drill$/m, "an empty kind keeps its heading");
  assert.match(doc, /^## frozen$/m, "the frozen lane keeps its heading even when empty");
  assert.equal(renderSuitesDoc([base({ id: "a" })]), renderSuitesDoc([base({ id: "a" })]), "deterministic");
});

test("renderSuitesDoc: groups by kind in KINDS order, the frozen lane last with each entry's kind", () => {
  const doc = renderSuitesDoc([
    base({ id: "f", kind: "stack", frozen: true }),
    base({ id: "s", kind: "sandbox", needs: ["kernel"] }),
    base({ id: "u", kind: "unit" }),
  ]);
  const heads = doc.split("\n").filter((l) => l.startsWith("## ")).map((l) => l.slice(3));
  assert.deepEqual(heads, [...KINDS, "frozen"]);
  const section = (h) => doc.split(`## ${h}\n`)[1].split("\n## ")[0];
  assert.match(section("unit"), /\| `u` \|/);
  assert.match(section("sandbox"), /\| `s` \|/);
  assert.doesNotMatch(section("stack"), /\| `f` \|/, "a frozen entry is not listed under its kind");
  assert.match(section("frozen"), /\| `f` \| .* \| kind stack \|/);
  assert.doesNotMatch(section("unit"), /kind unit/, "the kind flag is the frozen section's only");
});

test("renderSuitesDoc: rows are sorted by id within a kind, whatever the manifest order", () => {
  const doc = renderSuitesDoc([base({ id: "m" }), base({ id: "c" }), base({ id: "x" }), base({ id: "a.b" })]);
  const ids = doc.split("\n").filter((l) => l.startsWith("| `")).map((l) => /^\| `([^`]+)`/.exec(l)[1]);
  assert.deepEqual(ids, ["a.b", "c", "m", "x"]);
});

// The 2026-09-30 failure: two MRs each added an offline entry and regenerated the page from their
// own base; the count lines conflicted (!187) or merged stale (pipeline #7814). git's three-way
// merge of the two pages must now be clean AND equal to the page of the merged manifest.
test("renderSuitesDoc: two branches' pages merge cleanly into the merged manifest's page (git merge-file)", () => {
  const dir = mkdtempSync(join(tmpdir(), "suites-doc-merge-"));
  try {
    const kernel = new Set(["a.one", "g.seven"]);
    const E = Object.fromEntries(["a.one", "b.two", "c.three", "d.four", "e.five", "f.six", "g.seven", "h.eight"].map((id) =>
      [id, base({ id, kind: kernel.has(id) ? "sandbox" : "component" })]));
    const merge = (baseEntries, ours, theirs) => {
      const [o, b, t] = ["ours", "base", "theirs"].map((n) => join(dir, n));
      writeFileSync(o, renderSuitesDoc(ours)); writeFileSync(b, renderSuitesDoc(baseEntries)); writeFileSync(t, renderSuitesDoc(theirs));
      const r = spawnSync("git", ["merge-file", "-p", o, b, t], { encoding: "utf8" });
      return { conflicts: r.status, text: r.stdout };
    };
    const cases = [
      // both add in one kind with one existing row between them (the !185/!187 shape)
      { base: ["a.one", "c.three", "g.seven"], ours: ["b.two"], theirs: ["d.four"] },
      // both add in different kinds, one of them the kind's first entry
      { base: ["b.two", "c.three"], ours: ["a.one"], theirs: ["h.eight"] },
      // one adds, one removes, in the same kind
      { base: ["b.two", "c.three", "e.five", "f.six"], ours: ["h.eight"], theirs: [], drop: "c.three" },
      // one changes a row (a flag), the other adds a row further down
      { base: ["b.two", "c.three", "e.five"], ours: [], theirs: ["f.six"], flag: "b.two" },
    ].map((c) => ({ ...c, base: c.base.map((id) => E[id]), ours: c.ours.map((id) => E[id]), theirs: c.theirs.map((id) => E[id]) }));
    for (const c of cases) {
      const flagged = (xs) => xs.map((x) => (x.id === c.flag ? { ...x, flaky: { reason: "r", since: "s" } } : x));
      const ours = flagged([...c.base, ...c.ours]);
      const theirs = [...c.base.filter((x) => x.id !== c.drop), ...c.theirs];
      const merged = flagged([...c.base.filter((x) => x.id !== c.drop), ...c.ours, ...c.theirs]);
      const r = merge(c.base, ours, theirs);
      assert.equal(r.conflicts, 0, `no conflict: ${JSON.stringify(c.ours.map((x) => x.id))} vs ${JSON.stringify(c.theirs.map((x) => x.id))}`);
      assert.equal(r.text, renderSuitesDoc(merged), "the merged page is the merged manifest's page (not stale)");
    }
    // The residual (test-organization.md §9.2): two new ids with no existing row between them insert
    // at one spot and still conflict; the later rebase regenerates the page, master never goes stale.
    const r = merge([E["e.five"]], [E["b.two"], E["e.five"]], [E["d.four"], E["e.five"]]);
    assert.ok(r.conflicts > 0, "adjacent new ids conflict (a rebase conflict, not a red master)");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("`suites.mjs doc` writes the page; `doc --check` and `check` fail while it is stale", async () => {
  const root = tree({
    "tests/suites.mjs": "export const entries = [];\nexport const aggregates = [];\n",
    "docs/design/architecture/protection-modes.md": FREEZE,
    "docs/testing/README.md": "# Testing\n", // the page's directory, without the page
  });
  const run = async (...args) => {
    let out = "";
    const code = await main(args, { root, stdout: { write: (s) => { out += s; } } });
    return { code, out };
  };
  try {
    const missing = await run("check");
    assert.equal(missing.code, 1);
    assert.match(missing.out, /ERROR: doc: docs\/testing\/suites\.md is missing/);
    assert.equal((await run("doc")).code, 0);
    assert.equal((await run("doc", "--check")).code, 0);
    writeFileSync(join(root, SUITES_DOC), "# hand edited\n");
    assert.equal((await run("doc", "--check")).code, 1);
    const stale = await run("check");
    assert.equal(stale.code, 1);
    assert.match(stale.out, /ERROR: doc: docs\/testing\/suites\.md is stale: run node scripts\/suites\.mjs doc/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// ── the docs-lane sweep (continuous-integration.md §5.5) ────────────────────────────

test("docsReads: a whole docs/ literal or a repo root joined with docs or a .md name, in code, that the tree has", () => {
  const root = tree({ "docs/design/d.md": "d\n", "README.md": "r\n" });
  try {
    const js = (body) => docsReads(`import { readFileSync } from "node:fs";\n${body}\n`, "pkg/test/unit/x.test.ts", root);
    assert.deepEqual(js('readFileSync(join(REPO, "docs/design/d.md"), "utf8");'), ["docs/design/d.md"]);
    assert.deepEqual(js('const all = readdirSync(join(REPO_ROOT, "docs"));'), ["docs"]);
    assert.deepEqual(js('readFileSync(join(ROOT, "README.md"));'), ["README.md"]);
    assert.deepEqual(js('const p = "../../docs/design/d.md"; readFileSync(p);'), ["docs/design/d.md"]);
    // Not reads of the repository's docs:
    assert.deepEqual(js('// see docs/design/d.md\n/* "docs/design/d.md" */ readFileSync(x);'), [], "comments");
    assert.deepEqual(js('readFileSync(join(REPO, "docs/design/missing.md"));'), [], "a path the tree lacks");
    assert.deepEqual(js('const doc = "docs/design/d.md §4"; readFileSync(x);'), [], "a doc reference, not a path");
    assert.deepEqual(js('readFileSync(join(tmp, "README.md"));'), [], "a temp dir's README");
    assert.deepEqual(docsReads('const doc = "docs/design/d.md";\n', "a.test.ts", root), [], "JS/TS with no filesystem read");
    // Shell: no read call needed; `#` comments stripped.
    assert.deepEqual(docsReads('grep -q x "$ROOT/docs/design/d.md"\n', "t.test.sh", root), ["docs/design/d.md"]);
    assert.deepEqual(docsReads('# cat "$ROOT/docs/design/d.md"\necho hi\n', "t.test.sh", root), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("docsLaneSweep: a per-push test that reads docs is flagged until a docs-lane entry runs it or it is marked exempt", () => {
  const reads = 'import { readFileSync } from "node:fs";\nreadFileSync(join(REPO, "docs/d.md"), "utf8");\n';
  const root = tree({
    "docs/design/architecture/protection-modes.md": FREEZE,
    "docs/d.md": "doc\n",
    "pkg/package.json": JSON.stringify({ scripts: { test: "tsx --test test/unit/*.test.ts", "test:live": "tsx --test test/live/*.test.ts" } }),
    "pkg/test/unit/canary.test.ts": "",
    "pkg/test/unit/reads.test.ts": reads,
    "pkg/test/unit/exempt.test.ts": `// docs-lane-exempt: its docs path is fixture data\n${reads}`,
    "pkg/test/live/l.test.ts": reads,
  });
  try {
    const entries = [
      base({ id: "pkg" }),
      base({ id: "pkg.live", kind: "live-drill", cmd: ["npm", "run", "test:live"], agent: "claude", needs: ["node", "claude", "claude-login"], credential: "subscription", proves: ["utility/task"] }),
    ];
    const s = docsLaneSweep(entries, root);
    assert.deepEqual(s.unclaimed, [{ file: "pkg/test/unit/reads.test.ts", reads: ["docs/d.md"] }],
      "the live file is outside the per-push kinds the lane can hold");
    assert.deepEqual(s.exempt, ["pkg/test/unit/exempt.test.ts"]);
    const { errors, notes } = checkManifest(entries, [], root);
    assert.ok(errors.some((e) => /^docs lane: pkg\/test\/unit\/reads\.test\.ts reads docs\/d\.md at run time and no docsLane entry runs it/.test(e)),
      errors.join("\n"));
    assert.ok(notes.some((n) => /docs-lane-exempt \(pkg\/test\/unit\/exempt\.test\.ts\)/.test(n)), notes.join("\n"));
    // A docs-lane variant that runs the file (claiming none) covers it, and the check passes.
    const lane = base({ id: "pkg.docs", cmd: ["npx", "tsx", "--test", "test/unit/reads.test.ts"], variantOf: "pkg", docsLane: true, idOnly: true });
    assert.deepEqual(docsLaneSweep([...entries, lane], root).unclaimed, []);
    assert.deepEqual(checkManifest([...entries, lane], [], root).errors, []);
    assert.deepEqual([...entryClaims(lane, root).files], [], "the variant still claims nothing");
    assert.deepEqual([...entryClaims(lane, root, { runs: true }).files], ["pkg/test/unit/reads.test.ts"]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("docsReads: git ls-files over a repo root, and a test that names a docs-reader module's entry point", () => {
  const root = tree({
    "docs/d.md": "d\n",
    "pkg/src/pack.ts": "/**\n * Builds the pack from docs/.\n * docs-reader: `buildPack`, `/api/pack.md`\n */\nexport function buildPack() {}\n",
    "pkg/src/other.ts": 'const hint = "docs-reader: `notAMarker`"; // a string, not a comment line\n',
    "pkg/test/unit/pack.test.ts": "// docs-reader: `ignoredInTests`\n",
  });
  try {
    const readers = docsReaderModules(root);
    assert.deepEqual(readers, [{ module: "pkg/src/pack.ts", names: ["buildPack", "/api/pack.md"] }],
      "a marker counts on a comment line of a non-test file only");
    const reads = (body, file = "pkg/test/unit/x.test.ts") => docsReads(body, file, root, readers);
    assert.deepEqual(reads('spawnSync("git", ["-C", REPO_ROOT, "ls-files", "-z"]);'), ["git ls-files"]);
    assert.deepEqual(reads('git -C "$ROOT" grep -n x\n', "t.test.sh"), ["git ls-files"]);
    assert.deepEqual(reads('execFileSync("git", ["grep", "-l", "x"], { cwd: REPO });'), ["git ls-files"]);
    assert.deepEqual(reads('git -C "$REPO" commit -q -m x && grep -q ok out\n', "t.test.sh"), [], "a plain grep after git");
    assert.deepEqual(reads('gitIn(tmp, ["ls-files"]);'), [], "ls-files in a temp repo");
    assert.deepEqual(reads('// REPO_ROOT ls-files\nfoo();'), [], "comments");
    assert.deepEqual(reads('await fetch(`${base}/api/pack.md`);'), ["pkg/src/pack.ts (/api/pack.md)"]);
    assert.deepEqual(reads('import { buildPack } from "../../src/pack.js";\nbuildPack(REPO);'), ["pkg/src/pack.ts (buildPack)"]);
    assert.deepEqual(reads('// calls buildPack\nfoo();'), [], "a name in a comment");
    assert.deepEqual(reads("buildPack();", "pkg/src/pack.ts"), [], "the module itself");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("unmarkedDocsReaders: a module that reads docs without a docs-reader: marker fails the check with its file and line", () => {
  const reads = 'import { readFileSync } from "node:fs";\nimport { join } from "node:path";\n\nexport function pack(REPO) {\n  return readFileSync(join(REPO, "docs/d.md"), "utf8");\n}\n';
  const root = tree({
    "docs/design/architecture/protection-modes.md": FREEZE,
    "docs/d.md": "d\n",
    "pkg/package.json": JSON.stringify({ scripts: { test: "tsx --test test/unit/*.test.ts" } }),
    "pkg/test/unit/canary.test.ts": "",
    // A test that reaches the module only through its import: the path
    // heuristic sees nothing in the test itself.
    "pkg/test/unit/uses.test.ts": 'import { pack } from "../../src/unmarked.js";\npack(process.cwd());\n',
    "pkg/src/unmarked.ts": `/** Packs the docs. */\n${reads}`,
    "pkg/src/marked.ts": `/** docs-reader: \`packMarked\` */\n${reads}`,
    "pkg/src/exempt.ts": `// docs-lane-exempt: writes docs/d.md, reads none\n${reads}`,
    "pkg/src/mention.ts": `// say why in a \`docs-lane-exempt: <reason>\` comment\n${reads}`,
    "pkg/src/link.ts": 'import { readFileSync } from "node:fs";\nexport const help = () => `see ${docsUrl("docs/d.md")}`;\nreadFileSync("/etc/hostname");\n',
    "pkg/src/names.sh": '#!/bin/sh\n# reads "$ROOT/docs/d.md" in a comment only\necho hi\n',
  });
  try {
    assert.deepEqual(unmarkedDocsReaders(root), [
      { module: "pkg/src/mention.ts", line: 6, reads: ["docs/d.md"] },
      { module: "pkg/src/unmarked.ts", line: 6, reads: ["docs/d.md"] },
    ], "the marked, the exempt, a doc link and a comment are not readers; a mention of the exemption's syntax is no exemption");
    const { errors } = checkManifest([base({ id: "pkg" })], [], root);
    assert.ok(errors.some((e) => /^docs lane: pkg\/src\/unmarked\.ts:6 reads docs\/d\.md at run time and declares no `docs-reader:` marker/.test(e)),
      errors.join("\n"));
    // With the marker naming its entry point, the sweep sees the test that calls it.
    writeFileSync(join(root, "pkg/src/unmarked.ts"), `/** docs-reader: \`pack\` */\n${reads}`);
    writeFileSync(join(root, "pkg/src/mention.ts"), `// docs-lane-exempt: a fixture\n${reads}`);
    assert.deepEqual(unmarkedDocsReaders(root), []);
    assert.deepEqual(docsLaneSweep([base({ id: "pkg" })], root).unclaimed,
      [{ file: "pkg/test/unit/uses.test.ts", reads: ["pkg/src/unmarked.ts (pack)"] }]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("the manifest: every docs-lane re-run holds only files the sweep sees read docs (no hand-kept member)", async () => {
  // continuous-integration.md §5.5: the lane's idOnly re-runs are derived from the
  // sweep, so a file on them that the sweep does not see is a reader it misses.
  const { entries } = await loadManifest({ includePrivate: false });
  const readers = docsReaderModules();
  const lane = entries.filter((x) => x.docsLane === true && x.idOnly === true);
  assert.ok(lane.length >= 3, lane.map((x) => x.id).join(" "));
  for (const x of lane) {
    for (const f of entryClaims(x, REPO_ROOT, { runs: true }).files) {
      const reads = docsReads(readFileSync(join(REPO_ROOT, f), "utf8"), f, REPO_ROOT, readers);
      assert.ok(reads.length, `${x.id}: ${f} is in the docs lane but the sweep sees no docs read in it`);
    }
  }
});

test("check: manual is the reason an entry runs only when named, a non-empty string", () => {
  const root = fixture();
  try {
    const ok = [
      base({ id: "pkg", scripts: ["test:unit"] }),
      base({ id: "pkg.live", kind: "live-drill", cmd: ["npm", "run", "test:live"], agent: "claude", needs: ["node", "claude"], manual: "a maintainer's batch", provesNone: "a metric" }),
      base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] }),
    ];
    assert.deepEqual(checkManifest(ok, [], root).errors, []);
    for (const bad of ["", "  ", true, 1]) {
      const errs = checkManifest(ok.map((x) => (x.id === "pkg.live" ? { ...x, manual: bad } : x)), [], root).errors;
      assert.ok(errs.some((e) => /pkg\.live: manual is the reason/.test(e)), `${JSON.stringify(bad)}: ${errs.join("\n")}`);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("selectEntries: a manual entry never runs with its kind, is excluded with its reason, and runs when named", () => {
  const xs = [base({ id: "a", kind: "live-drill" }), base({ id: "b", kind: "live-drill", manual: "a maintainer's batch" })];
  const t = selectEntries(xs, { kinds: ["live-drill"], platform: "linux", flakyKinds: ["live-drill"] });
  assert.deepEqual(t.selected.map((x) => x.id), ["a"]);
  assert.deepEqual(t.excluded, [{ id: "b", reason: "manual: a maintainer's batch" }]);
  assert.deepEqual(selectEntries(xs, { only: ["b"], platform: "linux" }).selected.map((x) => x.id), ["b"]);
});

test("selectEntries: a frozen entry never runs with its kind; `frozen` adds every frozen entry, whatever its kind", () => {
  const xs = [
    base({ id: "u", kind: "unit" }), base({ id: "uf", kind: "unit", frozen: true }),
    base({ id: "lf", kind: "live-drill", frozen: true }), base({ id: "c", kind: "component" }),
  ];
  const ids = (o) => selectEntries(xs, { platform: "linux", ...o }).selected.map((x) => x.id);
  assert.deepEqual(ids({ kinds: ["unit"] }), ["u"]);
  assert.deepEqual(ids({ kinds: ["unit", "live-drill"] }), ["u"], "a kinds run never takes a frozen entry");
  assert.deepEqual(ids({ frozen: true }), ["uf", "lf"], "frozen alone: the whole frozen lane");
  assert.deepEqual(ids({ kinds: ["component"], frozen: true }), ["uf", "lf", "c"]);
  assert.deepEqual(ids({ only: ["uf"] }), ["uf"], "naming a frozen entry runs it");
});

test("selectEntries: flakyKinds adds only the flaky entries of more kinds, never a frozen one", () => {
  const flaky = { reason: "r", since: "2026-09-28", revisit: "2026-10-28" };
  const xs = [
    base({ id: "l", kind: "live-drill" }),
    base({ id: "c", kind: "component" }), base({ id: "cf", kind: "component", flaky }),
    base({ id: "ff", kind: "component", flaky, frozen: true }),
  ];
  const r = selectEntries(xs, { kinds: ["live-drill"], flakyKinds: ["component"], platform: "linux" });
  assert.deepEqual(r.selected.map((x) => x.id), ["l", "cf"]);
  const pushed = selectEntries(xs, { kinds: ["component"], platform: "linux" });
  assert.deepEqual(pushed.selected.map((x) => x.id), ["c"]);
  assert.deepEqual(pushed.excluded, [{ id: "cf", reason: "flaky: r" }]);
});

test("planPhases: the entries that need kernel are the kernel lane; the rest by their parallel flag", () => {
  const xs = [
    base({ id: "p", kind: "component" }),
    base({ id: "q", kind: "component", parallel: false }),
    base({ id: "sb", kind: "component", parallel: "sandbox" }),
    base({ id: "k", kind: "sandbox", needs: ["kernel", "userns"] }),
    base({ id: "ks", kind: "sandbox", needs: ["kernel"], parallel: false }),
    base({ id: "rk", kind: "replay-drill", needs: ["kernel", "claude"] }),
    base({ id: "s2", kind: "sandbox", needs: ["userns"] }),
  ];
  const ids = (ph) => Object.fromEntries(Object.entries(ph).map(([k, v]) => [k, v.map((x) => x.id)]));
  assert.deepEqual(ids(planPhases(xs)), { parallel: ["p", "s2"], serial: ["q", "sb"], kernel: ["k", "rk"], kernelSerial: ["ks"] });
  assert.deepEqual(ids(planPhases(xs, { sandboxed: true })).parallel, ["p", "sb", "s2"]);
  assert.ok(needsKernel(xs[3]) && !needsKernel(xs[6]), "the lane is the kernel need, not the kind");
});

test("usesNativeBins: a replay-drill or sandbox entry outside the frozen lane, or one that needs native-bins", () => {
  assert.ok(usesNativeBins(base({ kind: "replay-drill" })));
  assert.ok(usesNativeBins(base({ kind: "sandbox" })));
  assert.ok(!usesNativeBins(base({ kind: "replay-drill", frozen: true })));
  assert.ok(usesNativeBins(base({ kind: "live-drill", needs: ["native-bins"] })));
  assert.ok(!usesNativeBins(base({ kind: "stack" })));
});

test("coverage: ok when a per-push suite above unit proves it, warn when only unit or nightly suites do, none otherwise", () => {
  const xs = [
    base({ id: "u", kind: "unit", proves: ["fs/twin", "exec/box"] }),
    base({ id: "c", kind: "component", proves: ["model-ingress/file"] }),
    base({ id: "l", kind: "live-drill", proves: ["reply/desymbolize"] }),
    base({ id: "fz", kind: "stack", frozen: true, proves: ["exec/box", "fs/open-raw"] }),
    base({ id: "s", kind: "sandbox", needs: ["kernel"], proves: ["exec/box"] }),
  ];
  const { rows } = coverage(xs);
  assert.deepEqual(rows.map((r) => r.property), PROPERTIES);
  const st = Object.fromEntries(rows.map((r) => [r.property, r.status]));
  assert.equal(st["model-ingress/file"], "ok");
  assert.equal(st["exec/box"], "ok", "a sandbox suite counts");
  assert.equal(st["fs/twin"], "warn", "a unit-only mark is a WARN");
  assert.equal(st["reply/desymbolize"], "warn", "a nightly-only mark is a WARN");
  assert.equal(st["fs/open-raw"], "none", "a frozen entry is ignored");
  assert.equal(st["network-egress/dns"], "none");
  const byKind = rows.find((r) => r.property === "exec/box").byKind;
  assert.deepEqual(byKind, { unit: ["u"], sandbox: ["s"] });
  const text = renderCoverage(xs);
  assert.match(text.split("\n")[0], /^property\s+unit\s+component\s+stack\s+replay-drill\s+sandbox\s+live-drill\s+env\s+eval\s+status$/);
  assert.match(text, /^fs\/twin\s+1\s+·.*WARN$/m);
  assert.match(text, /^model-ingress\/file\s+·\s+1.*OK$/m);
});

test("coverage: a property no per-push suite above unit proves is an ERROR of the check (test-reorganization.md §11.1)", async () => {
  // Every property proved by a per-push suite above unit: no problem.
  const full = PROPERTIES.map((p, i) => base({ id: `s${i}`, kind: "sandbox", needs: ["kernel"], proves: [p] }));
  assert.deepEqual(coverageProblems(full), []);
  // One property left to a unit suite (WARN) and one to nobody (NONE): one
  // error each, naming the property and what claims it.
  const gap = full.filter((x) => !["network-egress/dns", "fs/twin"].includes(x.proves[0]));
  gap.push(base({ id: "u", kind: "unit", proves: ["network-egress/dns"] }));
  const errs = coverageProblems(gap);
  assert.equal(errs.length, 2, errs.join("\n"));
  assert.match(errs.find((e) => e.includes("network-egress/dns")) ?? "", /is WARN.*only unit: u/);
  assert.match(errs.find((e) => e.includes("fs/twin")) ?? "", /is NONE/);
  // A nightly or a frozen claim is not coverage either.
  const nightly = full.filter((x) => x.proves[0] !== "exec/box");
  nightly.push(base({ id: "n", kind: "live-drill", proves: ["exec/box"] }), base({ id: "f", kind: "sandbox", frozen: true, proves: ["exec/box"] }));
  assert.equal(coverageProblems(nightly).length, 1);
  // The real manifest has none (the gap the check used to note is closed).
  const { entries } = await loadManifest();
  assert.deepEqual(coverageProblems(entries), []);
});

// ── the nightly's two lanes (continuous-integration.md §9.8) ─────────────────────
test("selectEntries: --lane keeps only the entries holding that credential (none: the subscription lane) and says why the others are out", () => {
  const xs = [
    base({ id: "s", kind: "live-drill", credential: "subscription" }),
    base({ id: "a", kind: "live-drill", credential: "api-key" }),
    base({ id: "n", kind: "live-drill" }),
  ];
  const sub = selectEntries(xs, { kinds: ["live-drill"], platform: "linux", lane: "subscription" });
  assert.deepEqual(sub.selected.map((x) => x.id), ["s", "n"], "an entry that needs no login runs in the subscription lane");
  assert.deepEqual(sub.excluded, [{ id: "a", reason: "credential api-key (this run: subscription)" }]);
  const api = selectEntries(xs, { kinds: ["live-drill"], platform: "linux", lane: "api-key" });
  assert.deepEqual(api.selected.map((x) => x.id), ["a"]);
  assert.deepEqual(api.excluded, [
    { id: "s", reason: "credential subscription (this run: api-key)" },
    { id: "n", reason: "no credential: the subscription lane runs it (this run: api-key)" },
  ]);
  // --only still names entries, but only within the lane: a lane never runs another lane's entry.
  assert.deepEqual(selectEntries(xs, { only: ["a"], platform: "linux", lane: "subscription" }).selected, []);
  assert.deepEqual(selectEntries(xs, { kinds: ["live-drill"], platform: "linux" }).selected.map((x) => x.id), ["s", "a", "n"], "no lane: every entry");
});

test("check: a live-drill entry names the agent it drives (and a U-LLM agent), each among its needs; a list only when frozen", () => {
  const root = fixture();
  try {
    const live = { kind: "live-drill", cmd: ["npm", "run", "test:live"], provesNone: "a fixture", credential: "subscription" };
    const s = base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] });
    const run = (x) => checkManifest([base({ id: "pkg", scripts: ["test:unit"] }), base({ id: "pkg.live", ...live, ...x }), s], [], root).errors;
    const has = (errs, re) => assert.ok(errs.some((e) => re.test(e)), errs.join("\n"));
    const claude = ["node", "claude", "claude-login"];
    assert.deepEqual(run({ agent: "claude", needs: claude }), []);
    assert.deepEqual(run({ agent: "codex", ullm: "claude", needs: ["node", "codex", "chatgpt-login", "claude"] }), []);
    assert.deepEqual(run({ agent: "opencode2", needs: ["node", "opencode2", "claude-login"] }), [], "OpenCode 2 is an agent of its own");
    has(run({ needs: claude }), /pkg\.live: a live-drill entry names the agent it drives \(`agent`/);
    has(run({ agent: "claude-code", needs: claude }), /pkg\.live: agent is one of claude, codex, openclaw, opencode, opencode2, goose/);
    has(run({ agent: "codex", needs: claude }), /pkg\.live: it drives codex: its needs name that CLI/);
    has(run({ agent: ["claude", "codex"], needs: [...claude, "codex"] }), /pkg\.live: agent is a list only on a frozen entry/);
    has(run({ agent: [], needs: claude }), /pkg\.live: agent is one of/);
    has(run({ agent: ["claude", "claude"], needs: claude, frozen: true, axis: "full" }), /pkg\.live: agent is one of .* \(a list of distinct ones only on a frozen entry\)/);
    assert.deepEqual(run({ agent: ["claude", "codex"], needs: [...claude, "codex"], frozen: true, axis: "full", credential: undefined }), []);
    has(run({ agent: "codex", ullm: "claude", needs: ["node", "codex", "chatgpt-login"] }), /pkg\.live: its U-LLM is claude: its needs name that CLI/);
    has(run({ agent: "claude", ullm: "claude", needs: claude }), /pkg\.live: ullm names another agent/);
    has(run({ agent: "claude", ullm: "gpt", needs: claude }), /pkg\.live: ullm is one of/);
    // A browser agent (devtools-relay.md) is named from its own list, not the registry's.
    const jev = { needs: ["node", "python3", "chromium", "typesafe-api-key", "openrouter-api-key"], credential: "api-key", manual: "spends the keys" };
    assert.deepEqual(run({ browserAgent: "jev", ...jev }), []);
    has(run({ browserAgent: "selenium", ...jev }), /pkg\.live: browserAgent is one of jev/);
    // Another kind may name its agent, and need not.
    const replay = base({ id: "pkg.replay", kind: "replay-drill", cmd: ["npm", "run", "test:live"], needs: ["node", "claude"] });
    const kinds = (x) => checkManifest([base({ id: "pkg", scripts: ["test:unit"] }), { ...replay, ...x }, s], [], root).errors;
    assert.deepEqual(kinds({}), []);
    assert.deepEqual(kinds({ agent: "claude" }), []);
    has(kinds({ ullm: "codex" }), /pkg\.replay: ullm \(the agent serving as the U-LLM\) needs an agent/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("check: aliases are former ids, none an entry's id or another's alias; an alias selects its entry (--only, a pattern too)", () => {
  const root = fixture();
  try {
    const s = base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] });
    const pkg = base({ id: "pkg", scripts: ["test:unit"] });
    const live = base({ id: "pkg.new", kind: "replay-drill", cmd: ["npm", "run", "test:live"], needs: ["node", "claude"] });
    const run = (o, more = []) => checkManifest([pkg, { ...live, ...o }, s, ...more], [], root).errors;
    const has = (errs, re) => assert.ok(errs.some((e) => re.test(e)), errs.join("\n"));
    assert.deepEqual(run({ aliases: ["pkg.old", "pkg.older"] }), []);
    has(run({ aliases: [] }), /pkg\.new: aliases is a non-empty list of former ids/);
    has(run({ aliases: "pkg.old" }), /pkg\.new: aliases is a non-empty list/);
    has(run({ aliases: ["a b"] }), /pkg\.new: alias 'a b' is not an id/);
    has(run({ aliases: ["s"] }), /pkg\.new: alias 's' is an entry's id/);
    has(run({ aliases: ["pkg.old"] }, [{ ...s, id: "s2", aliases: ["pkg.old"] }]), /alias 'pkg\.old' is another entry's alias too/);
  } finally { rmSync(root, { recursive: true, force: true }); }
  const xs = [{ id: "drill.conf.claude", kind: "live-drill", aliases: ["drill.secrets.conf"], platforms: ["linux"] }, { id: "other", kind: "unit", platforms: ["linux"] }];
  assert.deepEqual(selectEntries(xs, { only: ["drill.secrets.conf"], platform: "linux" }).selected.map((x) => x.id), ["drill.conf.claude"]);
  assert.deepEqual(selectEntries(xs, { only: ["drill.secrets.*"], platform: "linux" }).selected.map((x) => x.id), ["drill.conf.claude"]);
  assert.deepEqual(selectEntries(xs, { only: ["drill.nope"], platform: "linux" }).unknown, ["drill.nope"]);
});

test("the merged manifest: every live-drill entry names its agent (a registry agent, or a browser agent)", async () => {
  const { entries } = await loadManifest();
  const live = entries.filter((x) => x.kind === "live-drill");
  assert.ok(live.length > 0 || !entries.some(isDrill), "the drill entries are live-drills");
  for (const x of live) assert.ok(x.agent != null || x.browserAgent != null, `${x.id} names no agent`);
});

test("check: every entry a nightly runs that needs a login names one credential, the one it needs; one that needs none names none", () => {
  const root = fixture();
  try {
    const live = { kind: "live-drill", cmd: ["npm", "run", "test:live"], provesNone: "a fixture" };
    const s = base({ id: "s", cwd: ".", cmd: ["bash", "scripts/test/s.test.sh"], needs: ["bash"] });
    // The agent rule has its own test (below): only the credential's errors here.
    const agentRule = /names the agent it drives|its needs name that CLI/;
    const run = (x) => checkManifest([base({ id: "pkg", scripts: ["test:unit"] }), base({ id: "pkg.live", ...live, ...x }), s], [], root).errors.filter((e) => !agentRule.test(e));
    assert.deepEqual(run({ needs: ["node", "claude", "claude-login"], credential: "subscription" }), []);
    assert.deepEqual(run({ needs: ["node", "codex", "openai-api-key"], credential: "api-key" }), []);
    const has = (errs, re) => assert.ok(errs.some((e) => re.test(e)), errs.join("\n"));
    has(run({ needs: ["node", "claude", "claude-login"] }), /pkg\.live: the nightly runs it and it needs a login: say its credential \(subscription or api-key/);
    // No login, no credential (test-reorganization.md §8 step 2): the subscription lane runs it.
    assert.deepEqual(run({ needs: ["node", "ollama"] }), []);
    has(run({ needs: ["node", "ollama"], credential: "subscription" }), /pkg\.live: credential 'subscription' on an entry that needs no login/);
    has(run({ needs: ["node"], credential: "api" }), /credential 'api' is not one of subscription, api-key/);
    has(run({ needs: ["node"], credential: "chatgpt" }), /credential 'chatgpt' is not one of subscription, api-key/);
    has(run({ needs: ["node", "claude", "claude-login"], credential: "api-key" }), /credential api-key, but it needs no API key/);
    has(run({ needs: ["node", "anthropic-api-key", "claude-login"], credential: "api-key" }), /needs claude-login, a subscription sign-in, which the api-key lane never holds/);
    has(run({ needs: ["node", "openai-api-key"], credential: "subscription" }), /needs an API key, which only credential api-key holds/);
    // The Codex ChatGPT sign-in (§9.8) is a subscription sign-in: credential
    // subscription holds it, beside the Claude login; api-key never does.
    assert.deepEqual(run({ needs: ["node", "codex", "chatgpt-login"], credential: "subscription" }), []);
    assert.deepEqual(run({ needs: ["node", "codex", "chatgpt-login", "claude", "claude-login"], credential: "subscription" }), []);
    has(run({ needs: ["node", "codex", "chatgpt-login", "openai-api-key"], credential: "api-key" }), /needs chatgpt-login, a subscription sign-in, which the api-key lane never holds/);
    has(run({ needs: ["node", "codex", "chatgpt-login", "openai-api-key"], credential: "subscription" }), /needs an API key, which only credential api-key holds/);
    assert.ok(Object.hasOwn(NEEDS, "chatgpt-login") && /MANDU_CI_CODEX_AUTH/.test(NEEDS["chatgpt-login"]));
    // A per-push entry holds no credential; a flaky one that needs a login does
    // (the nightly runs every flaky entry), and one that needs none does not.
    const errs = checkManifest([base({ id: "pkg", scripts: ["test:unit"], credential: "subscription" })], [], root).errors;
    has(errs, /pkg: credential 'subscription' on an entry no nightly runs/);
    const flaky = { reason: "r", since: "2026-09-28", revisit: "2026-10-28" };
    has(checkManifest([base({ id: "pkg", scripts: ["test:unit"], flaky, needs: ["node", "claude-login"] })], [], root).errors, /pkg: the nightly runs it and it needs a login: say its credential/);
    assert.deepEqual(checkManifest([base({ id: "pkg", scripts: ["test:unit"], flaky })], [], root).errors.filter((e) => e.startsWith("pkg:")), []);
    // A frozen or manual entry is no nightly's: a frozen one needs no credential.
    assert.deepEqual(run({ needs: ["node", "claude", "claude-login"], frozen: true, axis: "full" }), []);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("the manifest: the two credentials split the nightly's selection with nothing lost and nothing in both", async () => {
  const { entries } = await import("../../tests/suites.mjs");
  const sel = (lane) => selectEntries(entries, { kinds: NIGHTLY_KINDS, platform: "linux", includeInternet: true,
    flakyKinds: KINDS, ...(lane ? { lane } : {}) }).selected.map((x) => x.id);
  const all = sel(null), sub = sel("subscription"), api = sel("api-key");
  assert.deepEqual([...sub, ...api].sort(), [...all].sort());
  assert.ok(!sub.some((id) => api.includes(id)));
  // Everything on the Claude login stays with the subscription (the vendor-key
  // entries are the source repository's drills, private/suites-drills.mjs).
  for (const id of ["integration.local-model", "integration.ollama-doctor"]) assert.ok(sub.includes(id), id);
});

test("check: select says where the scenario list lives and holds exactly what the entry runs; a drill entry must have one", () => {
  const root = fixture();
  try {
    const cut = (o) => base({ id: "cut", kind: "replay-drill", cmd: ["npm", "run", "test:live"], needs: ["node", "claude"], ...o });
    const errs = (x) => checkManifest([base({ id: "pkg", scripts: ["test:unit"] }), x], [], root).errors.filter((e) => e.startsWith(`${x.id}:`));
    assert.deepEqual(errs(cut({ env: { ONLY: "a,b" }, select: { env: "ONLY", values: ["a", "b"] } })), []);
    assert.match(errs(cut({ env: { ONLY: "a" }, select: { env: "ONLY", values: ["a", "b"] } })).join(), /select\.env ONLY must hold the list/);
    assert.match(errs(cut({ select: { values: ["a"] } })).join(), /exactly one of env or arg/);
    assert.match(errs(cut({ select: { env: "ONLY", values: [] } })).join(), /non-empty list/);
    assert.deepEqual(errs(cut({ cmd: ["npm", "run", "test:live", "--", "--ids", "a,b"], select: { arg: "--ids", values: ["a", "b"] } })), []);
    assert.match(errs(cut({ cmd: ["npm", "run", "test:live", "--", "--ids", "a"], select: { arg: "--ids", values: ["a", "b"] } })).join(),
      /select\.arg --ids must be followed in cmd by the list/);
    assert.match(errs(cut({ id: "drill.X" })).join(), /a drill entry names its scenarios in select/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("the manifest: eval.paired (an injection-mode wrapped leg) is manual with its reason and frozen", async () => {
  const { entries } = await import("../../tests/suites.mjs");
  const byId = Object.fromEntries(entries.map((x) => [x.id, x]));
  assert.equal(byId["eval.paired"].frozen, true);
  assert.equal(byId["eval.paired"].kind, "eval");
  assert.equal(byId["eval.paired"].axis, "injection");
  assert.match(byId["eval.paired"].manual, /--out <new dir> --model <id> --inspection-model <id>/);
});

test("the manifest: eval's npm test (eval.lib) owns the offline run-live half; the frozen eval.run-live owns the live smoke", async () => {
  // continuous-integration.md §12.4: the GitHub eval cell runs eval's whole `npm test`, so the
  // live smoke must stay out of its glob and the offline normalizer inside it.
  const { entries } = await import("../../tests/suites.mjs");
  const byId = Object.fromEntries(entries.map((x) => [x.id, x]));
  const lib = [...entryClaims(byId["eval.lib"]).files];
  const live = [...entryClaims(byId["eval.run-live"]).files];
  assert.ok(lib.includes("eval/lib/run-live.test.ts"), lib.join("\n"));
  assert.ok(!lib.some((f) => f.startsWith("eval/live/")), "no live file in eval's npm test");
  assert.deepEqual(live, ["eval/live/run-live.eval.test.ts"]);
  assert.equal(byId["eval.run-live"].frozen, true);
});

test("selectEntries: a `nightly` entry of a per-push kind never runs with its kind, the nightly's flakyKinds takes it; a `reported` one runs per push", () => {
  const xs = [
    base({ id: "r", kind: "replay-drill" }),
    base({ id: "rn", kind: "replay-drill", nightly: "the whole catalog" }),
    base({ id: "rr", kind: "replay-drill", reported: "until the budget holds" }),
  ];
  const push = selectEntries(xs, { kinds: ["replay-drill"], platform: "linux" });
  assert.deepEqual(push.selected.map((x) => x.id), ["r", "rr"], "per push: the reported entry runs, the nightly one does not");
  assert.deepEqual(push.excluded, [{ id: "rn", reason: "nightly: the whole catalog" }]);
  const night = selectEntries(xs, { kinds: NIGHTLY_KINDS, flakyKinds: KINDS, platform: "linux" });
  assert.deepEqual(night.selected.map((x) => x.id), ["rn"], "the nightly takes it with the flaky entries");
  assert.deepEqual(selectEntries(xs, { only: ["rn"], platform: "linux" }).selected.map((x) => x.id), ["rn"], "naming it runs it");
  assert.equal(nonBlocking(xs[0]), false);
  assert.equal(nonBlocking(xs[1]), true);
  assert.equal(nonBlocking(xs[2]), true);
  assert.equal(nonBlocking(base({ flaky: { reason: "r", since: "2026-10-01" } })), true);
  assert.equal(nightlyRuns(xs[1]), true, "a nightly entry is the nightly's (its credential rule applies)");
  assert.equal(nightlyRuns(xs[2]), false);
  assert.equal(runsEveryPush(xs[2]), false, "a reported entry does not count as a per-push gate in the coverage");
  assert.equal(runsEveryPush(xs[0]), true);
});

test("check: reported and nightly are a per-push kind's, each a non-empty reason, never together nor beside flaky", () => {
  const root = fixture();
  try {
    const ok = [base({ id: "pkg", kind: "replay-drill", reported: "until the budget holds" }), base({ id: "pkg2", kind: "replay-drill", cwd: "pkg", nightly: "the whole catalog", scripts: [], variantOf: "pkg" })];
    const errsOf = (xs) => checkManifest(xs, [], root).errors.filter((e) => /reported|nightly/.test(e));
    assert.deepEqual(errsOf(ok), []);
    assert.ok(errsOf([base({ id: "pkg", reported: "" })]).some((e) => /reported is the reason/.test(e)));
    assert.ok(errsOf([base({ id: "pkg", kind: "live-drill", nightly: "x" })]).some((e) => /nightly applies to a per-push kind's entry/.test(e)));
    assert.ok(errsOf([base({ id: "pkg", reported: "x", nightly: "y" })]).some((e) => /reported and nightly together/.test(e)));
    assert.ok(errsOf([base({ id: "pkg", reported: "x", flaky: { reason: "r", since: "2026-10-01" } })]).some((e) => /reported and flaky together/.test(e)));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

