// tests/suites.mjs — THE list of Mandu's test suites (docs/design/testing/test-organization.md §5).
//
// Every reader that enumerates suites reads this file instead of keeping its own
// list: scripts/test-all.sh and the CI pipeline run it through
// scripts/run-suites.mjs, bash reaches it through `node scripts/suites.mjs list`,
// and scripts/test/suites-manifest.test.mjs fails when a test file or a `test*`
// npm script is claimed by no entry (or by two), when an entry names a path that
// does not exist, or when a suite that switches the frozen integrity axis on runs
// automatically (outside the frozen lane).
//
// A plain ES module so node reads it with no dependency and comments are allowed.
// It reflects the tree AS IT IS (2026-09-29): the test/kernel moves (§8.1) and
// the re-pins (§7.1, §7.3) are done; an entry that still has something wrong
// says so in a `todo` field instead of pretending.
//
// Entry fields (test-organization.md §5):
//   id         unique; the log file name (logs/<id>.log) and the --only handle
//   kind       what is real in the suite, which decides when it runs
//              (test-reorganization.md §3): unit | component | stack |
//              replay-drill | sandbox (every push, blocking) · live-drill | env |
//              eval (nightly, reported) · install (release)
//   frozen     true: the integrity lane (protection-modes.md §10); runs only with
//              --frozen (run-suites) / --integrity (test-all.sh), never with its kind
//   proves     the properties the suite proves (PROPERTIES in scripts/suites.mjs,
//              test-reorganization.md §5.1); `suites.mjs coverage` tables them
//   axis       secrets | off | injection | full — what the suite pins (§4). A
//              package-level entry names its dominant axis; `canaries` lists the
//              protection-modes.md §10.5 canaries inside it.
//   cwd        repo-relative working directory
//   cmd        argv (no shell); `npm test` / `npm run <script>` entries claim the
//              files their package.json script globs
//   env        extra environment (the runner always adds MANDU_AXES_STRICT=1,
//              MANDU_POLICY_FILE=/dev/null/mandu-test-no-policy.yaml and
//              MANDU_HOME=/dev/null/mandu-test-home, which override the entry's
//              own: a suite needing a home makes a temp one)
//   needs      what the host must provide (NEEDS in scripts/suites.mjs); `kernel`
//              puts a per-push entry in the kernel lane (the kernel guest)
//   timeout    seconds, enforced by the runner (process-group kill)
//   queueAs    seconds: the queue orders this entry (or shard) as if it cost
//              this much, over tests/suite-costs.json (scripts/suites.mjs
//              costOf); for a shard that must not start in the opening burst
//              (test-reorganization.md §6.9). Orders only.
//   parallel   true: safe beside other suites; false: alone; "sandbox": safe only
//              inside the per-entry sandbox (a §8.4 hazard not fixed yet), so it
//              runs alone when the runner has no --sandbox
//   gate       the env var that switches the suite on, when it has one (`env`
//              sets it, so selecting the entry runs it)
//   select     a scenario subset: { env, values } (the MANDU_E2E_ONLY lists) or
//              { arg, values } (the drills' `--ids`); the check holds it equal to
//              what the entry runs, and `--drills` narrows it (narrowSelect)
//   flaky      null, or { reason, since } — runs at its kind's cadence, never blocks
//   reported   a per-push kind's entry that runs every push and never blocks: the
//              reason (test-reorganization.md §6.9: the replay runner's per-push
//              subset, reported until the budget holds)
//   nightly    a per-push kind's entry that runs in the nightly instead, with the
//              flaky entries, and never blocks: the reason (the whole catalog's
//              replay)
//   internet   true: reaches the public internet; runs only when selected by id
//              or with --include-internet
//   platforms  ["linux"] | ["linux", "darwin"]
//   doc        the design note the suite proves
// Optional:
//   credential the login a nightly entry needs, its nightly lane: subscription
//              (the Claude and ChatGPT sign-ins) | api-key (continuous-integration.md §9.8);
//              an entry that needs no login holds none, and the subscription
//              lane runs it (test-reorganization.md §8 step 2)
//   manual     the reason the entry runs only when named, never with its kind
//   scripts    npm scripts (in cwd's package.json) this entry IS, beyond the one
//              its cmd runs (aliases such as test:unit / test:component / test:stack)
//   files      extra repo-relative paths/globs this entry claims
//   variantOf  id(s) of the entry whose files this one re-runs with other env
//              (a cut, a posture); a variant claims only its npm scripts
//   canary     true when the entry itself is a protection-modes.md §10.5 canary
//   canaries   canary files inside a package-level entry
//   todo       open work on the entry; "re-pin …" marks a suite that switches
//              integrity on outside the frozen lane until it is re-pinned
//   ci         { maxSkip, minPass } — the counts --strict-skips enforces (kernel)
//   note       anything else a reader needs
//   shards     [{ id, cmd?, env?, timeout?, queueAs? }] — run the entry as these parts, side
//              by side (scripts/suites.mjs expandShards): `<id>.<shard id>`
//   session    { cls, file, label } — the e2e TEST-session class the entry's runs
//              mint (ids `<cls>-<scenario>-<ms>`, test titles `<cls>[<scenario>]:`),
//              the suite file (cwd-relative) that declares its SCENARIOS, and the
//              one-line meaning the dashboard shows (its runner, setup banner and
//              spec browser read these; dashboard.md §4.10). Its session kind is
//              `offline` for a unit, component or stack entry, else `live`; its repro
//              gate is `gate`.
//   docsLane   true: runs in the docs lane, what an MR that changes documentation
//              only runs instead of the per-push kinds (scripts/ci/lane.mjs,
//              continuous-integration.md §5.5)
//   idOnly     true: runs only when selected by id (--only), never with its kind;
//              a docs-lane re-run of files its parent entry already runs
//   watchStore true: a live-drill or replay-drill entry that is not a `drill.*`
//              entry but runs the live runner (the demo battery): run-suites
//              appends `--store <the watch store>` to its cmd, as for a drill
//              entry, so its runs land where the CI guest collects them
//              (scripts/suites.mjs recordsLive)

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const L = ["linux"];
export const LD = ["linux", "darwin"];

/** Defaults every entry shares; an entry spells out only what differs. */
export function e(o) {
  return {
    env: {}, needs: [], parallel: true, gate: null, select: null, flaky: null,
    internet: false, platforms: L, ...o,
  };
}

export const KERNEL_CI = { maxSkip: 0, minPass: 1 };
// A frozen-lane entry that starts its own arbiter with integrity ON needs the
// frozen axis's opt-in (protection-modes.md §10.4); without it the arbiter refuses
// to start and the suite SKIPs to green.
export const INTEGRITY_OPT_IN = { MANDU_EXPERIMENTAL_INTEGRITY: "1" };

// ── unit: typecheck ────────────────────────────────────────────────────────────
// `npm test` runs through tsx, which transpiles per file and masks type errors;
// every TS package's tsc --noEmit is its own entry.
const TS_PACKAGES = [
  ["arbiter", "arbiter"],
  ["anthropic-proxy", "interceptors/anthropic-proxy"],
  ["openai-proxy", "interceptors/openai-proxy"],
  ["net-proxy", "interceptors/net-proxy"],
  ["cdp-relay", "interceptors/cdp-relay"],
  ["inspect-mcp", "interceptors/inspect-mcp"],
  ["policy-mcp", "interceptors/policy-mcp"],
  ["openclaw-inspect-plugin", "interceptors/openclaw-inspect-plugin"],
  ["exec-wrap", "interceptors/exec-wrap"],
  ["reply-filter", "interceptors/reply-filter"],
  ["fs-sync", "fs-sync"],
  ["dashboard", "dashboard"],
  ["launcher", "launcher"],
  ["eval", "eval"],
  ["integration", "tests"],
  ["conformance", "tests/conformance"],
];

// The packages whose typecheck and whole `npm test` (unit + e2e) run green on
// macOS (development.md §6, "Developing and testing on macOS"; verified on
// macOS 26.5 arm64, 2026-09-29, under the short TMPDIR run-suites.mjs gives a
// darwin run). The launcher and reply-filter are the wrapper layer the macOS
// posture ships (packaging.md §6); the rest are the TS units with no
// /proc-only or bwrap-only test left. Every other entry stays Linux.
const DARWIN_PACKAGES = new Set([
  "launcher", "reply-filter", "arbiter",
  "anthropic-proxy", "net-proxy", "exec-wrap", "inspect-mcp", "policy-mcp",
]);
// The dashboard's npm test is not on the list yet: its test-runner suites
// (manifest-runner, suite-manifest) expect the Linux manifest (`sandbox`
// entries, Linux-only ids) that a macOS run filters out. Its typecheck is.
// Typecheck is host-independent where the package's deps install; these ran here.
const DARWIN_TYPECHECK = new Set([...DARWIN_PACKAGES, "arbiter", "dashboard"]);

const typecheck = TS_PACKAGES.map(([name, cwd]) => e({
  id: `typecheck.${name}`, kind: "unit", axis: "off", cwd,
  cmd: ["npm", "run", "typecheck", "--silent"], needs: ["node"], timeout: 600,
  platforms: DARWIN_TYPECHECK.has(name) ? LD : L,
  doc: "docs/development.md",
}));

// ── component: each package's npm test (test/unit + test/component) ────────────
// One entry per package takes the kind of its most-real files: splitting it
// would change what CI runs (test-reorganization.md §10, third revision).
function pkg(id, cwd, o = {}) {
  return e({
    id, kind: "component", axis: "secrets", cwd, cmd: ["npm", "test", "--silent"],
    needs: ["node"], timeout: 900, scripts: [], platforms: DARWIN_PACKAGES.has(id) ? LD : L, ...o,
  });
}

const packages = [
  pkg("arbiter", "arbiter", {
    scripts: ["test:unit", "test:component"], timeout: 900, doc: "docs/design/architecture/mandu.md",
    canaries: [
      "arbiter/test/component/invariant-oracle.test.ts",
      "arbiter/test/unit/claude-code-policy.test.ts",
      "arbiter/test/unit/egress-gate.test.ts",
    ],
  }),
  pkg("anthropic-proxy", "interceptors/anthropic-proxy", { scripts: ["test:unit", "test:component"], doc: "docs/design/architecture/architecture-map.md" }),
  pkg("openai-proxy", "interceptors/openai-proxy", { scripts: ["test:unit", "test:component"], doc: "docs/design/architecture/architecture-map.md" }),
  pkg("net-proxy", "interceptors/net-proxy", { scripts: ["test:unit", "test:component"], doc: "docs/design/architecture/architecture-map.md" }),
  pkg("cdp-relay", "interceptors/cdp-relay", { scripts: ["test:unit", "test:component"], doc: "docs/design/agents/devtools-relay.md" }),
  pkg("inspect-mcp", "interceptors/inspect-mcp", { scripts: ["test:unit", "test:component"], doc: "docs/design/integrity/symbol-quality.md" }),
  pkg("policy-mcp", "interceptors/policy-mcp", { kind: "unit", scripts: ["test:unit"], doc: "docs/design/ui/policy-surface.md" }),
  pkg("openclaw-inspect-plugin", "interceptors/openclaw-inspect-plugin", { kind: "unit", scripts: ["test:unit"], doc: "docs/design/agents/supported-agents.md" }),
  pkg("exec-wrap", "interceptors/exec-wrap", { scripts: ["test:unit", "test:component"], doc: "docs/design/integrity/exec-routing.md" }),
  pkg("reply-filter", "interceptors/reply-filter", {
    scripts: ["test:unit", "test:component"], platforms: LD, doc: "docs/design/ui/reply-row-reservation.md",
  }),
  pkg("fs-sync", "fs-sync", { scripts: ["test:unit", "test:component"], doc: "docs/design/integrity/fs-sync.md" }),
  pkg("dashboard", "dashboard", {
    scripts: ["test:unit", "test:component", "test:product-only"], doc: "docs/design/ui/dashboard.md",
    note: "§8.4 swept 2026-09-29: kernel-assigned ports and port files throughout (the supervisor " +
      "harness since !46), temp runtime/state/event dirs; safe beside other suites.",
  }),
  pkg("integration", "tests", {
    kind: "stack", scripts: ["test:stack"], parallel: "sandbox", timeout: 1800, doc: "docs/design/architecture/implementation-plan.md",
    session: {
      cls: "replay-e2e", file: "stack/proxy-replay.test.ts",
      label: "proxy-replay — a deterministic canned-transcript replay through the real proxy + arbiter (no agent, no model; sessions replay-e2e-*)",
    },
    canaries: [
      "tests/stack/full-stack.test.ts",
      "tests/stack/proxy-replay.test.ts",
    ],
    note: "The files that need bwrap, user namespaces or the kernel-feature binaries are " +
      "tests/sandbox/ (integration.kernel, test-reorganization.md §5.3).",
  }),
  pkg("conformance", "tests/conformance", {
    kind: "stack", axis: "injection", canary: true, doc: "docs/design/architecture/protection-modes.md",
    note: "lib/unit_symbolization.ts — a protection-modes.md §10.5 canary (integrity ON, confidentiality OFF).",
  }),
  pkg("launcher", "launcher", {
    scripts: ["test:unit", "test:component"], parallel: "sandbox", timeout: 1800, platforms: LD,
    // The longest suite of the per-push run (304 s in one run, 2026-09-28): its
    // files split into shards the parallel stage runs side by side. run.test.ts
    // once had a shard of its own (293 s); that was its mock arbiter never
    // answering, 3 s per launch-time read (test/lib/unanswered-arbiter.ts), and
    // it now takes about 26 s like its neighbours (continuous-integration.md §5.1).
    shards: [
      ...fileShards("launcher", ["test/unit"], 2, "unit"),
      ...fileShards("launcher", ["test/component"], 3, "component", ["test/component/native-multiarch-bundle.test.ts"]),
    ],
    doc: "docs/design/distribution/portable-wrapper.md",
    canaries: ["launcher/test/component/golden-path.test.ts"],
    note: "§8.4: no file writes under the real HOME (the files that launch import " +
      "test/lib/private-home.ts: npm cache, symbol DB and agent config dirs in temp; a tripwire " +
      "test fails a file that forgets). npm-pack.test.ts has an online retry (§4 internet). " +
      "The files that need bwrap, user namespaces or the kernel-feature binaries are test/kernel/ " +
      "(launcher.kernel, §8.1).",
  }),
];

// ── the docs lane (continuous-integration.md §5.5) ──────────────────────────────────
// An MR whose diff is documentation only runs these and `scripts.suites-manifest`
// instead of the per-push kinds (scripts/ci/lane.mjs). Each re-runs the files of
// its parent entry that read docs or markdown at run time; `idOnly` keeps them out
// of a kind run, where the parent runs the same files. A new test that reads docs
// joins one of these (or the lane misses it until the next full run on master):
// `suites.mjs check` sweeps the test files for run-time docs reads (a docs path,
// git ls-files over the repo, a docs-reader module's entry point) and fails on
// one no docs-lane entry runs, unless it carries a `docs-lane-exempt: <reason>`
// comment (docsLaneSweep). The source repo's private/suites.mjs adds the public
// export check to this lane (private.export-check).
// docs-lane-exempt: this manifest names each entry's doc as data and reads none;
// scripts/suites.mjs, which reads them, is a docs-reader.
export const tsxTest = (...files) => ["npx", "tsx", "--test", ...files];
const docsLane = [
  e({
    id: "arbiter.docs-sweep", kind: "unit", axis: "off", cwd: "arbiter", variantOf: "arbiter",
    cmd: tsxTest("test/unit/symbol-prefix-sweep.test.ts"), needs: ["node", "git"], timeout: 300,
    docsLane: true, idOnly: true, doc: "docs/design/architecture/mandu.md",
    note: "every tracked text file, docs included, is free of the retired symbol spellings",
  }),
  e({
    id: "integration.user-docs", kind: "unit", axis: "off", cwd: "tests", variantOf: "integration",
    cmd: tsxTest("stack/user-docs.test.ts", "stack/agent-versions-parity.test.ts", "stack/about-mandu-parity.test.ts"),
    needs: ["node"], timeout: 300, docsLane: true, idOnly: true, doc: "docs/README.md",
    note: "README.md and docs/*.md: links and anchors resolve, required copy, the agents table, About Mandu's links",
  }),
  e({
    id: "integration.tour-fixture", kind: "stack", axis: "secrets", cwd: "tests", variantOf: "integration",
    cmd: tsxTest("stack/first-session-fixture.test.ts"),
    env: { MANDU_AXES_STRICT: "1", MANDU_HOME: "/dev/null/mandu-test-home", MANDU_POLICY_FILE: "/dev/null/mandu-test-no-policy.yaml" },
    needs: ["node", "git"], timeout: 300, docsLane: true, idOnly: true, doc: "docs/design/confidentiality/secret-discovery.md",
    note: "docs/first-session.md's folder through the real arbiter: step 3's file is not found by the default catalog, " +
      "the launch notice and `mandu policy suggest` say what the tour shows (secret-discovery.md §2.9)",
  }),
  e({
    id: "launcher.docs", kind: "unit", axis: "off", cwd: "launcher", variantOf: "launcher",
    cmd: tsxTest("test/unit/docs-url.test.ts", "test/unit/license-manifest.test.ts"),
    needs: ["node"], timeout: 300, docsLane: true, idOnly: true, doc: "docs/design/distribution/packaging.md",
    note: "every docsUrl() target exists; licensing.md is DECIDED",
  }),
];

// ── eval package ───────────────────────────────────────────────────────────────
/** Split a package's test files into shards of `npx tsx --test <files…>` (the
 *  same files and runner its `npm test` uses): each file in `solo` alone (a
 *  long file: its tests run one after another, so it bounds its shard), the
 *  rest sorted and dealt round-robin into `n`. */
function fileShards(cwd, dirs, n, prefix, solo = []) {
  const files = [];
  for (const d of dirs) {
    for (const f of readdirSync(join(ROOT, cwd, d)).sort()) if (f.endsWith(".test.ts")) files.push(`${d}/${f}`);
  }
  const alone = solo.filter((f) => files.includes(f));
  const rest = files.filter((f) => !alone.includes(f));
  const groups = Array.from({ length: n }, () => []);
  rest.forEach((f, i) => groups[i % n].push(f));
  const tsx = (g) => ["npx", "tsx", "--test", ...g];
  return [
    ...alone.map((f) => ({ id: `${prefix}-${f.replace(/^.*\//, "").replace(/\.test\.ts$/, "")}`, cmd: tsx([f]) })),
    ...groups.filter((g) => g.length).map((g, i) => ({ id: `${prefix}${i + 1}`, cmd: tsx(g) })),
  ];
}

const evalEntries = [
  e({
    id: "eval.deterministic", kind: "eval", frozen: true, axis: "injection", cwd: "eval",
    cmd: ["npx", "tsx", "run.ts", "--defense", "both"], scripts: ["eval:deterministic"],
    needs: ["node"], timeout: 900, parallel: "sandbox", doc: "docs/design/testing/evaluation.md",
    note: "the AgentDojo integrity corpus (NONE→ASR 100% vs FULL→ASR 0%); frozen with its axis " +
      "(protection-modes.md §10.2: the AgentDojo eval), re-pinning cannot apply: secrets mode masks no untrusted text.",
  }),
  e({
    id: "eval.lib", kind: "unit", axis: "secrets", cwd: "eval",
    cmd: ["npm", "test", "--silent"], scripts: ["test"],
    needs: ["node"], timeout: 900, parallel: "sandbox", doc: "docs/design/testing/evaluation.md",
    note: "§8.4: lib/launcher-run.ts and lib/paired/paired-runner.ts write under the real HOME.",
  }),
];

// ── component: the wrapper-layer shell suites ────────────────────────────────
function launcherSh(name, o) {
  return e({
    id: `launcher.${name}`, cwd: "launcher", cmd: ["bash", `test/${name}.test.sh`],
    timeout: 600, doc: "docs/design/architecture/architecture-map.md", ...o,
  });
}

const wrapperShell = [
  launcherSh("net-proxy-live", {
    kind: "component", axis: "secrets", ci: { maxSkip: 0, minPass: 1 }, needs: ["node", "curl"],
    note: "needs the 127.0.0.2 loopback alias.",
  }),
  launcherSh("net-proxy-mitm-live", {
    kind: "component", axis: "secrets", ci: { maxSkip: 0, minPass: 1 }, needs: ["node", "curl", "openssl"],
    note: "needs the 127.0.0.2 loopback alias.",
  }),
  launcherSh("exec-wrap-live", {
    kind: "component", axis: "secrets", ci: { maxSkip: 0, minPass: 1 }, needs: ["node", "curl"],
    doc: "docs/design/integrity/exec-routing.md", note: "needs the 127.0.0.2 loopback alias.",
  }),
  launcherSh("reply-filter-live", {
    kind: "component", axis: "secrets", ci: { maxSkip: 0, minPass: 1 }, needs: ["node", "script"],
    doc: "docs/design/ui/reply-row-reservation.md",
  }),
  // The live suites above (and the sandbox ones where their prerequisites
  // hold) run with a 1 ms readiness budget: each must FAIL with the arbiter's
  // log tail, never SKIP (test-organization.md §8.11).
  launcherSh("arbiter-start-fail", {
    kind: "component", axis: "secrets", ci: { maxSkip: 0, minPass: 4 }, needs: ["node", "curl", "openssl", "script"],
    doc: "docs/design/testing/test-organization.md", note: "needs the 127.0.0.2 loopback alias (the suites it runs do).",
  }),
  launcherSh("wire-release-live", {
    kind: "component", axis: "secrets", needs: ["node", "curl", "openssl", "nc"], internet: true,
    doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "calls httpbin.org (§8.1: leaves the default run; runs only when selected).",
  }),
  // The macOS whole-agent Seatbelt profile run for real (confidentiality.md
  // §7.3): each rule under /usr/bin/sandbox-exec, then a `mandu --target
  // shell` launch against a real arbiter. darwin only (it SKIPs elsewhere).
  // Kind `component`, not `sandbox`: the macOS sandbox needs no kernel lane,
  // and a `sandbox` entry runs in the Linux kernel lane (test-reorganization.md
  // §3), so it would never run on a Mac.
  e({
    id: "launcher.darwin-seatbelt", kind: "component", axis: "secrets", cwd: "launcher",
    cmd: ["npx", "tsx", "--test", "test/darwin/seatbelt-live.test.ts"],
    needs: ["node", "git"], timeout: 600, platforms: ["darwin"], doc: "docs/design/confidentiality/confidentiality.md",
    note: "Scratch dirs under /tmp (a Unix socket path must fit 104 bytes), kernel-assigned ports; the " +
      "launch leg spawns arbiter/ipc/server-main.ts, so the arbiter package's node_modules must be installed.",
  }),
  // The macOS git sandbox run for real (git-hardening.md §5.2): a hostile
  // repository's programs cannot start under /usr/bin/sandbox-exec, what one
  // could do if it did, Mandu's own git (launcher and arbiter) working inside
  // it, and no nesting. darwin only (it SKIPs elsewhere). Kind `component`
  // for the reason given at launcher.darwin-seatbelt.
  e({
    id: "launcher.darwin-git-sandbox", kind: "component", axis: "secrets", cwd: "launcher",
    cmd: ["npx", "tsx", "--test", "test/darwin/git-sandbox-live.test.ts"],
    needs: ["node", "git"], timeout: 300, platforms: ["darwin"], doc: "docs/design/architecture/write-protection.md",
    note: "Scratch dirs under /tmp (a Unix socket path must fit 104 bytes), kernel-assigned ports; the arbiter's " +
      "runners are loaded from arbiter/ by path, so the arbiter package's node_modules must be installed.",
  }),
];

// ── unit, component: scripts/test/* ────────────────────────────────────────────────
export function scriptTest(id, file, o = {}) {
  const cmd = file.endsWith(".mjs") ? ["node", "--test", file] : ["bash", file];
  return e({
    // A node test of a script's module is a unit; a bash test drives the script
    // through its command line (one tool through its real interface).
    id: `scripts.${id}`, kind: file.endsWith(".mjs") ? "unit" : "component", axis: "off", cwd: ".", cmd,
    needs: file.endsWith(".mjs") ? ["node"] : ["bash"], timeout: 300, ...o,
  });
}

const scriptTests = [
  scriptTest("require-userns", "scripts/test/require-userns.test.sh", { doc: "docs/design/testing/docker-e2e.md" }),
  scriptTest("kernel-tests", "scripts/test/kernel-tests.test.sh", { doc: "docs/design/architecture/privilege-model.md" }),
  scriptTest("docker-run", "scripts/test/docker-run.test.sh", { doc: "docs/design/testing/docker-e2e.md" }),
  scriptTest("reduce-credential", "scripts/test/reduce-credential.test.mjs", { doc: "docs/design/testing/os-test-matrix.md" }),
  scriptTest("bootstrap-empty-arrays", "scripts/test/bootstrap-empty-arrays.test.mjs", { doc: "docs/development.md" }),
  scriptTest("fresh-agents-fake-model", "scripts/test/fresh-agents-fake-model.test.mjs", { doc: "docs/design/testing/os-test-matrix.md" }),
  // The host prep's agents are the agent registry's npm agents.
  scriptTest("fresh-agents-host", "scripts/test/fresh-agents-host.test.mjs", { doc: "docs/design/testing/os-test-matrix.md" }),
  scriptTest("node-major", "scripts/test/node-major.test.mjs", { doc: "docs/design/testing/os-test-matrix.md" }),
  // The npm release gate's host prep (what the guest installs, which
  // credentials it may hold) and its access-token-only Codex login.
  scriptTest("npm-release-host", "scripts/test/npm-release-host.test.mjs", { doc: "docs/design/testing/os-test-matrix.md" }),
  scriptTest("reduce-codex-auth", "scripts/test/reduce-codex-auth.test.mjs", { doc: "docs/design/testing/os-test-matrix.md" }),
  scriptTest("secrets-to-env", "scripts/test/secrets-to-env.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
  scriptTest("set-api-key", "scripts/test/set-api-key.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
  // The one path table: fails when a generated copy differs from it.
  scriptTest("mandu-paths", "scripts/test/mandu-paths.test.mjs", { doc: "docs/design/architecture/on-disk-layout.md" }),
  scriptTest("matrix-provision", "scripts/test/matrix-provision.test.sh", { doc: "docs/design/testing/os-test-matrix.md" }),
  scriptTest("matrix-reboot", "scripts/test/matrix-reboot.test.sh", { doc: "docs/design/testing/os-test-matrix.md" }),
  scriptTest("matrix-record", "scripts/test/matrix-record.test.sh", { doc: "docs/design/testing/os-test-matrix.md" }),
  // The qemu guests every VM harness registers for `mandu reap`.
  scriptTest("guest-registry", "scripts/test/guest-registry.test.sh", { needs: ["bash", "node"], doc: "docs/design/testing/os-test-matrix.md" }),
  // scripts/dev-arbiter.sh: a real dev arbiter, and its `stop` leaves no process of it.
  scriptTest("dev-arbiter", "scripts/test/dev-arbiter.test.sh", { axis: "secrets", needs: ["bash", "node"], timeout: 300, doc: "docs/design/architecture/runtime-instances.md" }),
  // scripts/lib/ready-deadline.sh: the readiness budget of a dev or test arbiter start.
  scriptTest("ready-deadline", "scripts/test/ready-deadline.test.sh", { needs: ["bash", "node"], doc: "docs/design/architecture/runtime-instances.md" }),
  scriptTest("suites-manifest", "scripts/test/suites-manifest.test.mjs", { docsLane: true, platforms: LD, doc: "docs/design/testing/test-organization.md" }),
  scriptTest("ci-lane", "scripts/test/ci-lane.test.mjs", { needs: ["node", "git"], doc: "docs/design/testing/continuous-integration.md" }),
  // scripts/ci/master-check.mjs: the hourly master check's skip and record (§7.1).
  scriptTest("ci-master-check", "scripts/test/ci-master-check.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
  // GitHub's paths-filter semantics, which suites-manifest checks ci.yml's
  // docs filter with (§12).
  scriptTest("github-rules", "scripts/test/github-rules.test.mjs", { needs: ["node"], doc: "docs/design/testing/continuous-integration.md" }),
  scriptTest("run-suites", "scripts/test/run-suites.test.mjs", { platforms: LD, doc: "docs/design/testing/test-organization.md" }),
  scriptTest("run-suites-timeout", "scripts/test/run-suites-timeout.test.mjs", { doc: "docs/design/testing/test-organization.md" }),
  // scripts/tmp-gc.mjs: the pruner of this user's stale temp files (test-organization.md §8.5.1).
  scriptTest("tmp-gc", "scripts/test/tmp-gc.test.mjs", { doc: "docs/design/testing/test-organization.md" }),
  // scripts/drill-tree.mjs: where the drill tree is, or none (the public tree).
  scriptTest("drill-tree", "scripts/test/drill-tree.test.mjs", { doc: "docs/design/testing/test-organization.md" }),
  // A package's "mandu.siblings" covers every package whose sources it compiles.
  scriptTest("install-deps", "scripts/test/install-deps.test.mjs", { doc: "docs/development.md" }),
  // scripts/tour-screenshots.mjs: the browser it finds, the tour it seeds, the clip.
  scriptTest("tour-screenshots", "scripts/test/tour-screenshots.test.mjs", { doc: "docs/development.md" }),
  // scripts/test-all.sh builds the native bins before the entries that run them.
  scriptTest("test-all-native", "scripts/test/test-all-native.test.sh", { needs: ["bash", "node"], doc: "docs/design/testing/test-organization.md" }),
  scriptTest("test-all-lanes", "scripts/test/test-all-lanes.test.sh", { needs: ["bash", "node"], doc: "docs/design/testing/test-organization.md" }),
  // The CI pipeline's own plumbing (scripts/ci/): the untrusted-archive
  // collector, the image key, vm-run's qemu argv and job file, the pins, the
  // summaries pipeline.sh writes itself. ci-ns-run is a sandbox suite.
  scriptTest("ci-collect-results", "scripts/test/ci-collect-results.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
  // scripts/ci/live-events.mjs: the guest side of a CI live session's event lanes.
  scriptTest("ci-live-events", "scripts/test/ci-live-events.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
  // scripts/ci/replay-retention.mjs: the replay store's retention (the collector applies it; a developer by hand).
  scriptTest("replay-retention", "scripts/test/replay-retention.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
  scriptTest("ci-image-key", "scripts/test/ci-image-key.test.sh", { needs: ["bash", "git"], doc: "docs/design/testing/continuous-integration.md" }),
  scriptTest("ci-vm-run", "scripts/test/ci-vm-run.test.sh", { needs: ["bash", "git"], doc: "docs/design/testing/continuous-integration.md" }),
  scriptTest("agent-latest", "scripts/test/agent-latest.test.sh", { needs: ["bash"], doc: "docs/design/testing/test-organization.md" }),
  scriptTest("ci-pins", "scripts/test/ci-pins.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
  // The release path: release.yml's gates and credential (no stored token,
  // trusted publishing, the approval, the snapshot checks) and
  // release-pack.sh's refusals of a tree that is not the public one.
  scriptTest("release-workflow", "scripts/test/release-workflow.test.mjs", { doc: "docs/design/distribution/packaging.md", needs: ["node", "bash"] }),
  scriptTest("release-assets", "scripts/test/release-assets.test.mjs", { doc: "docs/design/distribution/packaging.md" }),
  scriptTest("ci-pipeline", "scripts/test/ci-pipeline.test.sh", { needs: ["bash", "node"], doc: "docs/design/testing/continuous-integration.md" }),
  scriptTest("ci-port-bridge", "scripts/test/ci-port-bridge.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
  // scripts/dep-audit.mjs: the reports read, the allow-list's rules, skip vs fail (§14.2).
  scriptTest("dep-audit", "scripts/test/dep-audit.test.mjs", { doc: "docs/design/testing/continuous-integration.md" }),
];

// ── unit: the GitHub Action's pure logic (packaging/github-action/lib) ─────────
// Its end-to-end test is tests/stack/github-action.test.ts (integration).
const githubAction = [
  e({
    id: "github-action", kind: "unit", axis: "secrets", cwd: "packaging/github-action",
    cmd: ["node", "--test", "test/*.test.mjs"], needs: ["node"], timeout: 300,
    doc: "docs/design/distribution/github-action.md",
    note: "inputs, the policy source and assembly, the summary (names and hosts only), the launch argv and env, action.yml against the code and the pins.",
  }),
];

// ── unit, component: Rust, fs-preload, the matrix plumbing─────────────────────────
const rustOffline = [
  e({
    id: "rust", kind: "unit", axis: "off", cwd: "interceptors", cmd: ["cargo", "test", "--quiet"],
    needs: ["cargo"], timeout: 1800, doc: "docs/design/architecture/privilege-model.md",
    note: "default features: the privilege-free decision logic; the kernel legs are rust.kernel.",
  }),
  e({
    id: "rust.check-aarch64", kind: "unit", axis: "off", cwd: "interceptors",
    cmd: ["bash", "-c",
      "if ! rustup target list --installed 2>/dev/null | grep -qx aarch64-unknown-linux-gnu; then " +
      "echo 'SKIP: the aarch64-unknown-linux-gnu target is not installed'; " +
      "echo 'rust.check-aarch64: 0 passed, 0 failed (skipped)'; exit 0; fi; " +
      "cargo check --workspace --target aarch64-unknown-linux-gnu && " +
      "echo 'rust.check-aarch64: 1 passed, 0 failed'"],
    needs: ["cargo"], timeout: 1800, doc: "docs/design/distribution/packaging.md",
    note: "test-organization.md §6.1; skips where the aarch64 target is not installed (rustup).",
  }),
  e({
    // The workspace's lint gate (continuous-integration.md §14.1): every crate at
    // default features AND at `kernel` (the attachment code a default build
    // leaves out), every target, warnings are errors. The lint policy is
    // interceptors/Cargo.toml [workspace.lints.clippy], each relaxation reasoned.
    id: "rust.clippy", kind: "unit", axis: "off", cwd: "interceptors",
    cmd: ["bash", "-c",
      "if ! cargo clippy --version >/dev/null 2>&1; then " +
      "echo 'SKIP: clippy is not installed (rustup component add clippy)'; " +
      "echo 'rust.clippy: 0 passed, 0 failed (skipped)'; exit 0; fi; " +
      "cargo clippy --workspace --all-targets --quiet -- -D warnings && " +
      "cargo clippy --workspace --all-targets --features kernel --quiet -- -D warnings && " +
      "echo 'rust.clippy: 2 passed, 0 failed'"],
    needs: ["cargo"], timeout: 1800, ci: { maxSkip: 0, minPass: 2 },
    doc: "docs/design/testing/continuous-integration.md",
    note: "skips where the clippy component is not installed; the CI image and the GitHub rust job install it, so a skip is red there.",
  }),
  e({
    id: "fs-preload.redirect", kind: "component", axis: "off", cwd: ".",
    cmd: ["bash", "interceptors/fs-preload/test/preload-redirect.test.sh"],
    needs: ["cargo"], timeout: 900, doc: "docs/design/architecture/privilege-model.md",
    note: "a retired rung, kept green while the crate is in tree.",
  }),
  e({
    id: "matrix.smoke", kind: "component", axis: "off", cwd: ".",
    cmd: ["bash", "scripts/matrix/run.sh", "host", "smoke"], env: { MANDU_MATRIX_RECORD: "0" },
    files: ["scripts/matrix/suites/smoke.sh"],
    needs: ["bash"], timeout: 300, doc: "docs/design/testing/os-test-matrix.md",
  }),
];

// ── one test file of tests/ as its own entry ───────────────────────────────────
/** One test file of the tests/ package as its own entry; `file` is relative to
 *  tests/ (sandbox/launcher, sandbox/guard or env, by kind; the maintainers'
 *  drills are entries of the source repository's private manifest). */
export function suite(id, file, o) {
  return e({
    id: `integration.${id}`, cwd: "tests",
    cmd: ["npx", "tsx", "--test", file], timeout: 900,
    doc: "docs/design/testing/agent-e2e-harness.md", ...o,
  });
}

// ── sandbox: the real sandbox, no agent (needs `kernel`: the kernel lane) ───────
const kernel = [
  // Longest first (continuous-integration.md §5.1): the kernel lane starts its
  // `parallel: true` entries in this order, --kernel-jobs at a time, beside the
  // parallel stage. `parallel: true` here means safe beside the other kernel
  // entries (each works in its own mktemp dirs, on kernel-assigned ports, with
  // a private arbiter); `false` runs alone in the lane after them.
  suite("launcher-fixture-homes", "sandbox/launcher/launcher-fixture-homes.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 1800, doc: "docs/design/confidentiality/secret-discovery.md",
    note: "was run by nothing before the manifest (test-organization.md §1). withStack mode " +
      "`secrets` (throwaway HOME); the integrity form (the AgentView copies reached through " +
      "the view map) is frozen: tests/integrity/launcher-fixture-homes.test.ts.",
    // 20 independent launches one after another (117 s for 18 in the per-push
    // guest, the longest entry, 2026-09-29): three shards of six or seven
    // (tests/lib/shard.ts).
    shards: [1, 2, 3].map((k) => ({ id: `s${k}`, env: { MANDU_FIXTURE_SHARD: `${k}/3` } })),
  }),
  // The package files that need bwrap, user namespaces or the kernel-feature
  // binaries (test-organization.md §8.1): each package's test/kernel/, which its
  // `npm test` does not glob. Each file self-SKIPs where a prerequisite is
  // missing; here a skip is counted.
  e({
    id: "launcher.kernel", kind: "sandbox", axis: "secrets", cwd: "launcher",
    cmd: ["npm", "run", "test:kernel", "--silent"],
    needs: ["kernel", "node", "git", "python3", "bwrap", "userns", "landlock", "seccomp", "native-bins"],
    timeout: 900, parallel: true, ci: KERNEL_CI, doc: "docs/design/confidentiality/rootless-confinement-ubuntu-2404.md",
    note: "claude-sandbox, codex-sandbox, secret-bind-nesting, wsl-interop, wsl-windows-secrets, " +
      "bwrap-launch-notes, git-object-twins, git-sandbox, guard-death, inspect-mcp-confine, goose-keyring (a keyring-only Goose " +
      "login never reaches the session bus under the guard and the launch names both fixes; a secrets.yaml login sends its key " +
      "and a tool's read of the file reaches the model masked; self-SKIPs without goose, and uses a counting listener where " +
      "python3-dbus is absent), goose-readers (load_skill of a labelled skill file reaches the model only as its twin under " +
      "the guard, and masked whole without it; self-SKIPs without goose, the guarded case without a live guard). codex-sandbox and " +
      "guard-death launch with MANDU_MODE=off. §8.4: wsl-interop makes its dir under /tmp/mdu-wsl- " +
      "and git-object-twins its second-filesystem dir under /dev/shm, /var/tmp or $XDG_RUNTIME_DIR " +
      "(mkdtemp, so safe beside the other kernel entries); guard-death imports test/lib/private-home.ts, " +
      "so its launch's symbol DB and agent config dirs are temp.",
  }),
  e({
    id: "integration.kernel", kind: "sandbox", axis: "secrets", cwd: "tests",
    cmd: ["npm", "run", "test:sandbox", "--silent"],
    needs: ["kernel", "node", "openssl", "python3", "bwrap", "userns", "landlock", "seccomp", "native-bins"],
    timeout: 900, parallel: true, ci: KERNEL_CI, doc: "docs/design/architecture/implementation-plan.md",
    note: "write-protect, write-protect-registry (Mandu's runtime registries on the Linux list: no write, rename over `current`, temp link, port file or base rename from the agent, runtime-instances.md §2), sdk-route-protected (the SDK route's file, its hook copies and the PATH shims on the Linux list: an SDK host can neither rewrite, remove nor rename them, and its claude stays routed, agent-sdks.md §3.6), unix-allow-list, human-plane-wall (secrets: the agent world cannot connect to " +
      "the arbiter's human-plane socket, docs/design/architecture/arbiter-human-plane.md), dashboard-sign-in-wall (the launcher prints a working one-time dashboard sign-in link; the agent world cannot reach the dashboard's sign-in socket, policy-surface.md §2.6), dashboard-via-net-proxy (a program the agent runs reaches neither the real dashboard nor a loopback service holding a secret, directly or relayed through the session's net-proxy in any spelling: the proxy relays nothing to this machine, exec-routing.md §7.5; self-SKIPs without curl), exposed-human-plane (a gated launch with no " +
      "wall reaches that socket, and its forged reports are claims while it runs, plan 13 D9 leftovers), store-links-launch " +
      "(a store in the Mandu home swapped for a symlink outside it refuses the launch, plan 14 §11.2 (c)), unconfined-launch-notice " +
      "(plan 14 §11.2.1: a live unconfined launch is named in the next launch's one notice, counted on its banner and in full in its log; packaging.md §5.2: a launch from " +
      "a git worktree with no bins of its own is confined by its main checkout's bins when their provenance matches, refused and gated " +
      "on one source byte of difference), wrap-pid-namespace, wrap-clone-filter (no sibling in the tree: clone(CLONE_PARENT) EPERM, clone3 ENOSYS, every ordinary spawn and thread still works under the real wrap, and a Go program built from net-supervisor's tests/fixtures/clone-probe.go (threads, os/exec, loopback TCP, HTTP, a Unix socket) works while its raw and Cloneflags CLONE_PARENT are refused and its UseCgroupFD clone3 spawn answers ENOSYS, the Go leg left out without go, exec-routing.md §7.5 gap (d)), wrap-open-fast-path (under the net-only wrap alone the guard's opens skip the Landlock mirror, every decision unchanged, the guard's own count of which path ran; plan 10 §4.1a, the cost of the mirror), guard-direct-open-mode (the agent's O_DIRECTORY open of its own tmp dir with Bun's stray 0666 opens with --no-landlock-net, the guard's one-step open, and with the rung on, and a create keeps its mode under the umask; plan 10 §4.1 step 3), guard-written-exec (a program the agent's tree has just copied runs at once, never ETXTBSY: the guard closes a write descriptor it handed over before the tracee resumes, confidentiality plan 10 §4.1a), guard-mirror-records (400 short-lived self-sandboxed processes: every one confined, the guard's mirror threads never one per process, a live sandbox and its later child still confined after the sweeps; plan 10 §4.1a, the mirror's records over a session),bind-only-posture, placeholder-commit-warning (a tracked protected file: the agent's `git commit -a` of its EDITED twin is named after the session with a remove-only repair that works, a commit of another file is not, a killed session's commit is named by the next launch, an untracked and an ignored protected file staged after the commit are unstaged first by the printed repair, so its amend takes neither placeholder, a walk cache swapped for a link outside the home is refused before any record behind it is read or removed, TWO SESSIONS, a killed one's `git add -A` of a never-tracked file and the next one's `git commit -a`, and THE BRANCH SWITCH, the agent's commit on a branch that never held the real files: each printed repair, run as printed, leaves the real value in no tip that moved, not in the index, and in no commit a branch that did not hold it reaches, since no command puts any version of the file back; confidentiality.md §7.2a), probe-cache-launch (a poisoned kept userns pass fails closed and is dropped, a failed probe is asked again, `mandu setup` clears the per-boot probe cache, a real pass is kept and still enacted, packaging.md §5.4), " +
      "policy-restore-and-guard-settings, endpoint-added-mid-session, perimeter-netns, codex-sandbox-exec-wrap (the exec-wrap shim inside " +
      "Codex's own sandbox: network off, its seccomp refuses the arbiter dial and the shim says so, exit 77; network on, a no-model " +
      "secret's curl runs with its placeholder left as written (the sink gets the placeholder, never the value; confidentiality.md " +
      "§7.1) and a plain one reaches the sink, supported-agents.md §6.4; self-SKIPs without a codex " +
      "whose sandbox starts), git-history-locks " +
      "(plan 14 §9: C17 closed and the inline key through the real launch, the admin channel and the model proxy, with the " +
      "bind and with the guard alone, confidentiality.md §7.2a; K8: a pack planted under a clean .idx is refused by its " +
      "seal and rebuilt, plan 14 §11.2; K12: a workspace file's token gone from the model after a terminal apply, plan 14 §13.9; K13: a labelled Office document's text gone from the model after its mapped label's suggestion is applied, plan 14 §14.1; K14: git works in C of an A ← B ← C `clone --shared` chain from the copies the arbiter prepared two links deep, confidentiality.md §7.2a; K16: the agent's history rewrite and gc succeed, every file it creates right after is made (none taken for the removed twinned pack by its reused inode number), the old index goes with its pack and no notice prints, with the guard alone and with the bind; K17: an index beside a pack (one twinned only by identity through a hard-linked clone, or an untwinned locked one) cannot be removed, once its pack is gone it can, confidentiality.md §7.2a), secret-moved-folder (guard only: a protected file moved with its folder, `mv ~/.aws ~/.aws2` or a renamed project folder, reads as a placeholder past the 2 s identity rebuild, the guard holding it by its inode; a save over it before the move, the registered path recreated, RENAME_EXCHANGE either way, a move to another filesystem, and a labelled file in the next session too; a folder exchange that would put one registered file on another's path is refused; past the pin budget the folder rename is refused; guard-file-identity.md §2), secret-labelled-opens (a file created mid-session under a labelled folder, read by cat, grep -r, tar and os.walk, yields its placeholder at the program and at the model, with the guard alone and with the bind; then an append and an in-place write land in its placeholder copy, sed -i's rename over it is refused, the real file keeps its bytes and the session's end names it; confidentiality.md §6), secret-catalog-opens (a .env deeper than the walk and a key file created mid-session read by cat, grep -r, tar and os.walk yield their placeholders; a .env.example, a node_modules .env, a plain file and source files named like a credential (credentials.ts at the launch, a credentials.py python imports) read raw, their credentials.json sibling gated; with the guard alone and with the bind; confidentiality.md §6, secret-discovery.md §1.12), prepared-copies-sandbox (the arbiter's R3 builds run in the git sandbox, " +
      "their work directory the only writable bind, write-protection.md §8.5), policy-classifier-confine (plan 14 §14.3: " +
      "the names-only model's classifier reaches only its endpoint's port under the arbiter's Landlock wrap), prompt-plugin-confine " +
      "(plan 15 §4.3: a prompt filter plugin under the real net-guard, Landlock and seccomp legs reaches only its cleared " +
      "local model, reads nothing outside its roots, and the probe sees through a guard that confines nothing): a private " +
      "in-process arbiter, throwaway HOMEs, kernel-assigned ports. write-protect pins `injection` " +
      "on purpose (write protection must hold with the confidentiality axis OFF).",
  }),
  launcherSh("secret-readers-live", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "nc", "native-bins"], parallel: true,
    ci: KERNEL_CI, doc: "docs/design/confidentiality/rootless-confinement-ubuntu-2404.md",
  }),
  launcherSh("pipe-taint-live", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "python3", "curl", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "the real arbiter and guard (the gated shape): a file opened for writing BEFORE the reader's raw read " +
      "(`python3 reader > out.txt`) takes the derived label at the read (plan 13 D5); an untainted redirect does not. " +
      "D2: `python3 reader | curl` sends nothing to an unbound listener, `x=$(reader); curl` neither, `reader | tee copy.txt` " +
      "labels copy.txt; controls: `echo | curl` reaches it, `cat x.txt | grep` still prints (callTaint masks it). " +
      "Printers admit nothing (plan 13 D8): `cat`, `curl file://` and a GNU cat renamed and pinned by path and hash, " +
      "each listed, get no byte (the !437 leftovers (1) and (2)); the reader is a holder the test builds with cc.",
  }),
  suite("tainted-egress", "sandbox/launcher/tainted-egress.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 900, doc: "docs/design/integrity/exec-routing.md",
    note: "the real launcher in `secrets` around a shell agent, in an unprivileged user + network namespace with a DNS " +
      "server the test owns on a second namespace ('the other machine', the resolver) and one on 127.0.0.1:53: a process " +
      "holding a secret (node reading ~/.npmrc, its default reader; bash sourcing a .env with readers) sends its canary by " +
      "no road (resolver lookup, sendto, connected UDP, DNS over TCP, a socket connected before the read); the same probes " +
      "from a process holding none reach both servers (exec-routing.md §7.5, 2026-10-01).",
  }),
  suite("holder-accept", "sandbox/launcher/holder-accept.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "python3", "bwrap", "userns", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 900, doc: "docs/design/integrity/exec-routing.md",
    note: "§7.5 gap (a), a holder's accept, through the real launcher in `secrets` in an unprivileged user + network " +
      "namespace with 'the other machine' on a second namespace: python3 servers in the agent's tree, one holding nothing, " +
      "one holding an unbound file and one a file bound to 10.77.0.2 (each through its reader's pipe); a connection from " +
      "the other machine to a holder is reset and its accept answers ECONNABORTED unless it comes from the bound host, " +
      "while loopback, the connection's own local address and a Unix client are served; the non-holder serves every peer.",
  }),
  suite("opencode2-own-server", "sandbox/guard/opencode2-own-server.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "landlock", "seccomp", "native-bins"], parallel: true,
    // The three OpenCode 2 tests SKIP with the reason where no OpenCode 2
    // binary is installed (MANDU_OPENCODE_V2_BIN, or `opencode2` on PATH),
    // the kernel guest's case today; the build-freshness test always runs.
    ci: { maxSkip: 3, minPass: 1 }, timeout: 900, doc: "docs/design/agents/supported-agents.md",
    note: "supported-agents.md §2.3.1, exec-routing.md §7.5: the REAL launcher, mandu-net-guard and landlock-net wrap " +
      "around the REAL OpenCode 2 (`--standalone`) against a scripted upstream: in mode `off` (`mandu opencode`, " +
      "supported by default) and in `secrets` (a shell-target session, the guard's allowance named by the " +
      "test), the client and its private server run a model turn and a shell tool call, while that tool's command is " +
      "refused a connect to the private server's port and to an outside listener, and nested `opencode run`s fail with " +
      "no model request; without the allowance the private server cannot start.",
  }),
  suite("opencode2-agent-identity", "sandbox/guard/opencode2-agent-identity.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "landlock", "seccomp", "native-bins"], parallel: true,
    // The OpenCode 2 test SKIPs with the reason where no OpenCode 2 binary
    // is installed (the kernel guest today), or no C compiler builds the
    // pinned reader; the build-freshness test always runs.
    ci: { maxSkip: 1, minPass: 1 }, timeout: 900, doc: "docs/design/agents/supported-agents.md",
    note: "supported-agents.md §2.3.1 (the agent is the server): the REAL launcher, guard and landlock-net wrap, the " +
      "launcher-started model proxy and a REAL ArbiterServer with a policy.yaml on disk, around the REAL OpenCode 2 in " +
      "`secrets`: the server's `shell` call runs a pinned reader of a labelled file; the call is bound by the call-root " +
      "recorder (masked from the call's own tree, not the session fallback), no request carries the canary, and the " +
      "server, not made a holder by the reader's output, opens a new model connection for the follow-up.",
  }),
  suite("opencode2-shell-output", "sandbox/guard/opencode2-shell-output.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "landlock", "seccomp", "native-bins"], parallel: true,
    // The OpenCode 2 test SKIPs with the reason where no OpenCode 2 binary is
    // installed (MANDU_OPENCODE_V2_BIN, or `opencode2` on PATH); the
    // build-freshness test always runs.
    ci: { maxSkip: 1, minPass: 1 }, timeout: 900, doc: "docs/design/agents/supported-agents.md",
    note: "supported-agents.md §2.3 item 10: the REAL launcher stack (its autostarted proxy, mandu-net-guard, landlock-net) " +
      "around the REAL OpenCode 2 in `secrets`: run 1's shell writes and keeps its sh_<id>.out (OpenCode's data directory " +
      "is a catalog location, never twinned); run 2, on a fresh arbiter, reads that file with `read` and `shell cat` and " +
      "neither result carries the output, while its own shell works.",
  }),
  suite("opencode-project-plugins", "sandbox/guard/opencode-project-plugins.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "landlock", "seccomp", "native-bins"], parallel: true,
    // Each generation's tests (2.x five, 1.x seven) SKIP with the reason
    // where its binary is not installed (MANDU_OPENCODE_V1_BIN / `opencode`
    // 1.x, and MANDU_OPENCODE_V2_BIN / `opencode2`), or no C compiler builds
    // the pinned reader; the build-freshness test always runs.
    ci: { maxSkip: 12, minPass: 1 }, timeout: 1200, doc: "docs/design/agents/supported-agents.md",
    note: "supported-agents.md §2.3 items 11 and 12: the REAL launcher (`mandu opencode` / `mandu opencode2`), guard and " +
      "landlock-net wrap, the launcher-started model proxy and a REAL ArbiterServer in `secrets`, around the REAL " +
      "OpenCode 1 and 2 with a probe plugin that copies a pinned reader's raw output and another agent's credential " +
      "store into the system prompt, planted in the project's `.opencode/plugin`, the user's `~/.config/opencode/plugin`, " +
      "or (1.x) named by the user's global opencode.json: both generations leave it out (2.x from the configuration the " +
      "launcher builds, 1.x through OPENCODE_PURE; never loaded, no request carries either value); the controls " +
      "(MANDU_OPENCODE_PROJECT_PLUGINS=1 / MANDU_OPENCODE_GLOBAL_PLUGINS=1) load it and the model receives the secret raw; " +
      "an agent's shell write to the global opencode.json waits in Approvals and, unanswered, is refused, while " +
      "OpenCode's own start is not held.",
    // Twelve launches one after another, ~290 s in the per-push guest, the
    // kernel lane's longest entry (2026-10-12; each OpenCode 1 control ~78 s):
    // three shards of four, a control in each (tests/lib/shard.ts shardPicker).
    shards: [1, 2, 3].map((k) => ({ id: `s${k}`, env: { MANDU_OPENCODE_PLUGINS_SHARD: `${k}/3` } })),
  }),
  suite("guard-provenance", "sandbox/guard/guard-provenance.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "test-reorganization.md §11.1: the REAL mandu-net-guard writes the taint records (exec roots with argv, raw " +
      "reads) for an agent tree in `secrets` (policy.yaml: ~/.pgpass, readers cat and node): a Bash call whose cat reads " +
      "the file and transforms it, and two stdio MCP servers from the agent's own config, registered by the launcher's " +
      "reader (one reads the file raw). Through the AnthropicProxy over HTTP and the openai-proxy's rewrite, both in " +
      "their production wiring, the tainted results are masked whole and the clean ones stay raw (plan 10 §4.2, §11.13).",
  }),
  suite("reader-output-rule", "sandbox/guard/reader-output-rule.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D3: the REAL mandu-net-guard writes the taint records for an agent tree in `secrets`, against a " +
      "policy.yaml on disk where cat is the reader of .pgpass with `output: clear` and of the board minutes with no rule. " +
      "Through the AnthropicProxy in its production wiring: cat on .pgpass alone reaches the model as printed; cat on the " +
      "minutes, and one cat holding both, reach it as a symbol (no byte of the minutes, hex-transformed past the value " +
      "scan); the first-use pin the arbiter writes keeps the entry's output.",
  }),
  suite("script-reader-pin", "sandbox/guard/script-reader-pin.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "python3", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 §9 R5: the REAL mandu-net-guard reads the script an interpreter runs; policy.yaml pins " +
      "`{ app: python3, script: <stdlib base64.py>, output: clear }` as the reader of .pgpass. Only `python3 -I base64.py` " +
      "reads raw and its output reaches the model as printed through the AnthropicProxy in its production wiring; " +
      "inline code, a workspace copy, a relative path, PYTHONPATH and no isolation (user site-packages) get no byte; the " +
      "first-use pin names the interpreter, the script and its hash.",
  }),
  suite("args-code-reader", "sandbox/guard/args-code-reader.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "git", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D8, code by argument: the REAL mandu-net-guard reads each opener's command line and environment " +
      "(args_code.rs); policy.yaml lists git, less, sed, vim and sha256sum as readers of ~/.env. sha256sum (a leaf) " +
      "reads it raw (the control); handed code (`git -c alias.x=…`, `GIT_PAGER`, `less +G`, `LESSOPEN`, `sed '1e …'`) " +
      "none reads a byte, vim (always code) never does, the printers git, less and sed not even with a plain command " +
      "line, git's store helper reads the twin of ~/.git-credentials, and no byte reaches the model " +
      "through the AnthropicProxy in its production wiring.",
  }),
  suite("ssh-config-write-protect", "sandbox/guard/ssh-config-write-protect.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 300, doc: "docs/design/architecture/write-protection.md",
    note: "P0 (D): the REAL mandu-net-guard with the write-protect list the launcher builds in production for a " +
      "throwaway HOME whose ~/.ssh/config includes config.d/*: a new or changed file in the included directory, " +
      "~/.ssh moved aside and a planted directory put in its place are held and refused at the ceiling (a real " +
      "ArbiterServer answers decideProtectedWrite, nobody answers the Inbox); an ordinary file is written at once.",
  }),
  suite("guard-session-events", "sandbox/guard/guard-session-events.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 300, doc: "docs/design/integrity/exec-routing.md",
    note: "exec-routing.md §7.5 'Whose session' (the first-session tour, 2026-10-07): the REAL launcher (guard-only) " +
      "around bash with an outer launch's MANDU_SESSION_ID in its environment; the REAL mandu-net-guard refuses a " +
      "connect to 192.0.2.1:9 and its net_action deny is in the launch's own session log (its --id), never the " +
      "sessionless net-guard log nor the outer launch's.",
  }),
  suite("printer-downstream", "sandbox/guard/printer-downstream.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "python3", "curl", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D8's residual (decision (b)): agent code downstream of a listed printer (`cat .env | python3 -c …`) " +
      "holds the raw bytes; under the REAL guard every exit it has is held: its output reaches the model as a symbol " +
      "through the AnthropicProxy, it sends only to the file's binding (TCP and UDP to another host refused), a curl it " +
      "execs or runs as a child is refused, the file it writes takes the secret's level and reads as a twin in a later " +
      "call, and a later call cannot read its background child's argv from /proc. `file -f .env` (file listed, a " +
      "printer since 2026-10-04, D8 (9)) prints the twin's lines and nothing downstream gets a byte; with no reader " +
      "list too; `git diff --no-index /dev/null .env` and `git grep --no-index` (git listed, a printer since " +
      "2026-10-04, §4.9 option (a)) print the twin's lines WHOLE (the guard-only stat trap answers git's lstat with the " +
      "twin's size, confidentiality.md §7.2a), nothing downstream gets a byte; no byte on the model's wire.",
  }),
  suite("git-transport-printer", "sandbox/guard/git-transport-printer.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "git", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D8 (11), continued 2026-10-07: git's separately built transports `git-http-fetch` and " +
      "`git-http-push` (libcurl opens ~/.netrc for them) are printers. Under the REAL mandu-net-guard, with " +
      "`{ app: git-http-fetch, prints: nothing }` (and -push) on ~/.netrc and a 401-Basic server on its bound host, " +
      "each runs with GIT_TRACE_CURL=1 GIT_TRACE_REDACT=0 and reaches the server (the control), and no form of the " +
      "password (raw, or base64 in the Authorization header) reaches the agent's output, the server, or the model " +
      "through the AnthropicProxy in its production wiring. Red before: both printed and sent the login. The " +
      "`git-credential-` prefix class (2026-10-07): the test's own reader built as `git-credential-mdu`, pinned by path " +
      "and hash with prints: nothing, reads no byte of a labelled ~/.env; the same program as `mdu-holder` does (the control).",
  }),
  suite("build-tool-reader", "sandbox/guard/build-tool-reader.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "python3", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D8 (10), 2026-10-04: a build tool runs its build file's code, so as a reader it admits nothing; under " +
      "the REAL guard `cmake -P` of a .env listing cmake reads the twin (red before: the raw bytes), the program it hands " +
      "the value to sees no byte, and nothing reaches the model through the AnthropicProxy. Self-skips (said) without cmake; the CI guest installs it.",
  }),
  suite("reader-allow-list", "sandbox/guard/reader-allow-list.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D8 (12), the allow-list (2026-10-04): under the REAL guard a program named in a file's readers " +
      "without `prints: nothing` reads the twin (red before: the raw file), with it reads raw, and a vetted reader " +
      "(ssh-add, to an agent the test starts) reads its key raw; no canary reaches the model through the AnthropicProxy.",
  }),
  suite("report-channel-restart", "sandbox/guard/report-channel-restart.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/architecture/arbiter-human-plane.md",
    note: "§5.1, 2026-10-07: the arbiter restarts under the REAL guard on a new human socket; the guard's report client " +
      "re-learns it from the data socket's `hello`, so its reports stay believed and a reader vouched for with " +
      "`prints: nothing` still reads raw (red before: every open a twin until the session ended).",
  }),
  suite("report-channel-start", "sandbox/guard/report-channel-start.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/architecture/arbiter-human-plane.md",
    note: "§5.2/§5.3, 2026-10-17: at the REAL guard's start a human-plane socket served by another process than the " +
      "data socket's arbiter is not believed (red before: it granted a raw read); MANDU_NET_GUARD_EVENTS=0 silences " +
      "the guard's events only (red before: no report at all, a vouched reader got the twin).",
  }),
  suite("report-channel-late", "sandbox/guard/report-channel-late.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 900, doc: "docs/design/architecture/arbiter-human-plane.md",
    note: "§5.2, 2026-10-17: the REAL guard starts with no human plane (its first open a claim: the twin), the human " +
      "plane comes up in its walled directory, the guard moves (same listening process, outside its tree) and its next " +
      "report is believed (the vouched reader reads raw; red before: the guard stayed on the data socket); and a guard " +
      "with no human plane all session still holds a HIGH session's command (red before: it reached an unbound listener).",
  }),
  suite("call-tree", "sandbox/guard/call-tree.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D7: the REAL guard reports each exec's and each secret open's live ancestor chain, so a reader inside " +
      "a subshell that never execs (`( cat x; true ) | …`, `$(cat x; true)`, `{ cat x; true; } | …`) is in its tool " +
      "call's tree; through the AnthropicProxy in its production wiring each reader's hex-encoded output is masked whole " +
      "and a clean call stays raw.",
  }),
  suite("high-session-command", "sandbox/guard/high-session-command.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "python3", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality.md",
    note: "§4 (2026-10-11, the session taint): the REAL guard asks the arbiter at a tool call's shell exec whether the " +
      "session read secret content into context; in a HIGH session the command is a holder of what was read, so it " +
      "reaches the listener the memo is bound to and is refused at another, and the file it writes is labeled at the " +
      "memo's level; the same command in a session that read nothing reaches both and writes an unlabeled file. " +
      "2026-10-12, a held command's refused connection: the refusal files the session's question (session-net × the " +
      "address); after Allow once the retry connects and sends on its connection (sendmsg), and the third try is refused.",
  }),
  suite("relative-path-label", "sandbox/guard/relative-path-label.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality.md",
    note: "§6 (2026-10-04): the REAL guard reports the directory the kernel says each Claude Code Bash call's shell " +
      "started in (`/proc/<pid>/cwd` at the exec); through the AnthropicProxy in its production wiring a public-labelled " +
      "file read by a relative path reaches the model in clear, from the workspace and from a subdirectory, while a file " +
      "no label covers, the workspace .env and a `cd` in the command stay masked.",
  }),
  suite("relative-base-shell-cwd", "sandbox/guard/relative-base-shell-cwd.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality.md",
    note: "§6 (2026-10-17, \"The base follows the shell\"): the REAL guard around an agent that keeps Claude Code's " +
      "session directory (each Bash shell spawned where the last one ended, EnterWorktree moving it with no shell); " +
      "after `cd vault` in one call, a Read of `plan.md` (the agent's own open, reported by the guard) and a `cat " +
      "plan.md` (the shell's kernel start directory) reach the model masked at their first exposure, and after " +
      "EnterWorktree too (red before for the Read: the plan in clear); after `cd ..` the open plan and a `cd test` " +
      "public fixture stay in clear.",
  }),
  suite("socket-flow", "sandbox/guard/socket-flow.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "curl", "python3", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 §9 R1: the REAL guard around a Codex-shaped agent; call 1 leaves a dev server running that read a " +
      "no-model file (a holder outside every later call's tree); a later call's `curl` of it is a holder (the guard " +
      "makes it one at the holder's accept and records the flow at the arbiter): its output reaches the model masked " +
      "through the AnthropicProxy in its production wiring, and `x=$(curl …); curl --data-binary \"$x\" <sink>` sends " +
      "nothing to an unbound listener; a clean call and a client of an untainted server stay raw.",
  }),
  suite("agent-flow", "sandbox/guard/agent-flow.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "python3", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 §4.5.1 (decision 2026-10-02: mask, do not refuse): the REAL guard around an agent (a node copy, the " +
      "launch's agentExe) whose Bash call leaves local servers running; the agent ITSELF fetches one that read a no-model " +
      "file (WebFetch) and asks another over a keep-alive it held before that server read the file (an HTTP MCP " +
      "server, whose raw open the guard refused before). Through the AnthropicProxy in its production wiring the " +
      "summarizer's side call and both results reach the model masked; a later fetch of a clean server and a file " +
      "tool's result stay raw. Since 2026-10-02 also a named pipe a holder writes (opened before its taint, so it " +
      "carries no label) that the agent reads ITSELF: its Read result is masked by the guard's FIFO agent flow; a log " +
      "a holder appends to is masked by its label.",
  }),
  suite("task-output-twin", "sandbox/guard/task-output-twin.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D4 (2026-10-04): the REAL guard around an agent (a node copy, the launch's agentExe) that runs a " +
      "Bash call the Claude Code 2.1.288 way, its output through a task file it reads back with an identity check " +
      "(lstat, open O_NOFOLLOW, fstat, st_dev/st_ino equal). The call's reader holds .env, so the task file is " +
      "labelled and the agent is served its twin: the twin's descriptor sits at the twin base and reports the task " +
      "file's identity (red before: 'could not be read (unknown)', drill conf-hold-once); the agent holds one symbol, " +
      "the AnthropicProxy in its production wiring masks the result, and the human plane's deep desymbolize of the " +
      "symbol the model saw is the real output.",
  }),
  suite("cwd-file-holder", "sandbox/guard/cwd-file-holder.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D4 (2026-10-04): the REAL guard around an agent (a node copy, the launch's agentExe) running Bash " +
      "calls the Claude Code way (`<command> && pwd -P >| /tmp/claude-<n>-cwd`, read back after the call). A call that " +
      "cds and then runs .env's reader leaves a cwd file its shell (a holder) wrote, labelled; its twin is its own text " +
      "(only a directory's name, plan 13 §4.9), so the next call runs in the new directory (red before: a symbol, " +
      "ignored); a holder that writes the secret into the cwd file gets a symbol and the directory stays; through the " +
      "AnthropicProxy in its production wiring no form of the secret reaches the model.",
  }),
  suite("cwd-secret-name", "sandbox/guard/cwd-secret-name.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D4's cwd-file residual, checked: under the REAL guard a holder names a directory with the RAW " +
      "registered value and cds into it; the agent's next call runs there (the cwd file, !554), and its pwd, like an ls " +
      "of the directory, reaches neither the AnthropicProxy's nor the openai-proxy's wire raw (the registered-value " +
      "scan masks it). The same name base64-encoded passes through the cwd file and through ls alike: plan 13 §4.9's " +
      "names channel, pinned.",
  }),
  suite("forged-reports", "sandbox/guard/forged-reports.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D9: the REAL guard reports on the arbiter's human-plane socket (found by `hello`), the agent world is " +
      "walled off from it (`unixDeny`); a program of the agent forges a false parent for a waiting subshell over the data " +
      "socket before it `exec`s cat, and a raw open of a workspace copy of cat as a system binary. Through the " +
      "AnthropicProxy in its production wiring (a data and a human client) the reader's hex dump is masked and a clean " +
      "call raw; nothing is pinned, the copy gets no raw byte, the system cat still reads.",
  }),
  suite("twin-format-fidelity", "sandbox/launcher/twin-format-fidelity.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins", "git", "python3"],
    parallel: true, ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "plan 10 §11.13: the real launcher in `secrets` (twin binds + guard) around a shell agent in withStack's " +
      "throwaway HOME: ssh parses the twinned ~/.ssh/config (and its Include), known_hosts is the real file, pip's " +
      "RawConfigParser (and pip where installed) reads both pip.conf twins, git's store helper parses the store's twin " +
      "(git, its known consumer, is a printer since 2026-10-04, plan 13 §4.9), a withheld ProxyCommand fails with Mandu's notice (its line, why, the way out; plan 10 " +
      "§11.13.3), and no canary reaches the agent's output. F6, in both postures (the bind, and --no-secret-bind): a " +
      "reader that sizes its read by a stat of the path (git diff/grep --no-index, Python lstat + read) reads the " +
      "twins whole (confidentiality.md §7.2a \"The size a reader sees\"). The model-boundary half is tests/stack/config-twin-fidelity.",
  }),
  suite("tar-secret", "sandbox/guard/tar-secret.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "plan 10 §4.1a step 4 (2026-10-03): the REAL guard around tar, against a policy.yaml on disk (a file with no " +
      "reader list, one with `others: twin`, one with tar listed, one with `others: deny`), with the stat twins off and on. " +
      "tar archives a relative dir/file, an absolute path, a gzip tree and `-h` with exit 0 (its openat2 O_PATH of an " +
      "argument's parent was EINVAL); every non-reader member is the twin and no archive holds the canary; the listed " +
      "reader archives the real file; `others: deny` refuses the open. Self-SKIPs without tar and gzip.",
  }),
  suite("tar-twin", "sandbox/launcher/tar-twin.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "plan 10 §4.1a step 4 (2026-10-03): the real launcher in `secrets` around a shell agent, with the twin binds " +
      "and guard-only (`--no-secret-bind`): tar archives the workspace's .env and conf/.env and ~/.aws/credentials " +
      "(relative dir/file, absolute, a directory, a bare name) with exit 0 and no size complaint; each member is what the " +
      "agent's cat sees (the twin) and no archive or output holds a canary.",
  }),
  suite("twin-write-notice", "sandbox/launcher/twin-write-notice.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "plan 10 §4.1 (2026-10-09): the real launcher in `secrets` around a shell agent that appends to the workspace's " +
      ".env and overwrites conf/.env with a fresh token: both writes succeed in the session (into the placeholder copy), " +
      "the launch ends with one notice line naming each of the two files by path (in the compact display too) and none " +
      "for ~/.aws/credentials, which it only read; no notice or event carries a canary or what was written; the real files " +
      "are byte-identical; the session_exit event names the same two paths. A launch that only reads prints no notice. " +
      "Each line says the real file is unchanged only when it checked: a real .env edited outside the session meanwhile " +
      "is named as changed too (with the scope dir kept, the line says the copy stays until mandu reap, and the launch " +
      "removes its snapshot file). A launcher SIGKILLed mid-session prints nothing; mandu reap then names the two files " +
      "before it removes the scope dir. The default posture (the mount layer, with the guard where built) and guard-only " +
      "(--no-secret-bind; skipped where the guard is not built).",
  }),
  suite("hard-link-twin-meta", "sandbox/launcher/hard-link-twin-meta.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/confidentiality.md",
    note: "P0 4c, the bind posture (2026-10-09): the real launcher in `secrets` around a shell agent, with the " +
      "workspace's .env hard-linked as notes.bak before the launch: both names show the placeholder file's size, " +
      "inode, link count and mtime by stat, stat -L and Python's os.stat/os.lstat (the launcher turned the guard's " +
      "stat trap on and said so), and the canary never reaches the agent.",
  }),
  suite("twin-git-clean", "sandbox/launcher/twin-git-clean.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality.md",
    note: "§7.2a, a tracked protected file looks clean to git in the agent's world (demo-c4, 2026-10-17): the real " +
      "launcher in `secrets` around a shell agent, in the bind and the guard-only posture. `git filter-branch " +
      "--index-filter 'git rm --cached .env' -- --all` without untracking first runs and rewrites every commit, the " +
      "key never reaches the agent and the human's .env keeps it; a `commit -a` after an unrelated edit leaves .env " +
      "out; an edited twin shows modified and its commit is named after the session; the trade-off pinned (the human's own " +
      "git shows .env ` M` with no diff during the session, clean after); a launcher SIGKILLed mid-session repaired by the " +
      "next launch from its crash record; bind-only (no guard, gated) never patched (a human's stash there would replace the " +
      "real file and detach the bind); two overlapping launches with their own Mandu homes, the first ending first, leave " +
      "the human's git clean (2026-10-21: the second's end wrote the first's twin stat back); only the launch's own " +
      "repositories are patched: another repository under HOME keeps its index, the human's git there clean during the session.",
  }),
  suite("npmrc-wire-twin", "sandbox/launcher/npmrc-wire-twin.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "openssl", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "plan 10 §11.13.1: the real launcher in `secrets` (guard, egress proxy with TLS inspection) around a shell agent " +
      "running `npx -y` against a fake HTTPS registry behind the proxy's host route: a servable ~/.npmrc is the twin to npm, " +
      "the registry gets the real token (put back by the proxy), no process is tainted and the npx server is `clean`; a " +
      "`_password` file (2026-10-03) works the same through HTTP Basic; the opt-out (MANDU_WIRE_TWIN=0) and a labelled " +
      "workspace .npmrc are twins too (plan 13 decision (b)); the credential built from the twin never reaches a decoy host.",
  }),
  suite("pip-wire-twin", "sandbox/launcher/pip-wire-twin.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "openssl", "bwrap", "userns", "seccomp", "native-bins", "python3"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "plan 10 §11.13.1 (2026-10-03): the real launcher in `secrets` (guard, egress proxy with TLS inspection) around a " +
      "shell agent whose pip client (pip's credential path in the standard library; real pip where installed) reads the " +
      "~/.config/pip/pip.conf twin, or PIP_INDEX_URL's, against a fake HTTPS index behind the proxy's host route: the index " +
      "gets the real password (put back in HTTP Basic by the proxy), a workspace pip.conf's symbol is refused, a decoy host " +
      "gets nothing, no taint, no canary in the agent's output.",
  }),
  suite("https-proxy-taint", "sandbox/launcher/https-proxy-taint.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "openssl", "curl", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D6: the real launcher in `secrets` (guard, egress proxy with TLS inspection) around a shell agent, " +
      "two HTTPS listeners behind the proxy's host routes: a reader (bash sourcing a .env bound to one of them) curls its " +
      "key over the session HTTPS_PROXY, raw and base64, to the unbound host (403, nothing arrives) and to the bound host " +
      "(200, it arrives); the agent's own shell reaches the unbound host (the control).",
  }),
  suite("blind-tunnel-fork", "sandbox/launcher/blind-tunnel-fork.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins", "python3"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D6, a blind tunnel's chunks (the P0 triage's 2a, 2026-10-07): the real launcher in `secrets` with " +
      "`--no-net-proxy-mitm` around a shell agent whose python program opens a blind tunnel through HTTPS_PROXY to a " +
      "recording listener behind the proxy's host route, then forks: a child that reads the .env through its reader's " +
      "pipe and writes the key into the inherited tunnel gets nothing through; a child holding nothing does (the control).",
  }),
  suite("launch-cwd-pwd", "sandbox/launcher/launch-cwd-pwd.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 600, doc: "docs/design/distribution/packaging.md",
    note: "packaging.md §1 \"The launch directory\" (2026-10-07): the real launcher in `secrets` started with its cwd in " +
      "the workspace and a PWD naming a decoy folder (a parent that chdir'd without exporting PWD) launches for the " +
      "workspace: the agent runs there with a PWD naming it, its .env is the twin, and the canary never reaches the agent.",
  }),
  suite("other-agent-logins", "sandbox/launcher/other-agent-logins.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bash", "bwrap", "userns", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 600, doc: "docs/design/confidentiality/secret-discovery.md",
    note: "secret-discovery.md §1.10 (2026-10-09): the real launcher in `secrets` over one throwaway HOME holding Codex's " +
      "and Claude Code's logins: a shell launch reads ~/.codex/auth.json as its twin (keys kept, a placeholder, never the key) " +
      "and ~/.claude/.credentials.json raw; a codex launch reads ~/.claude.json as its twin and ~/.codex/auth.json raw; " +
      "`mandu doctor --secrets --target <agent>` agrees with each launch. Each launch's agent also sends Codex's token " +
      "through its session's HTTP_PROXY to auth.openai.com (a host route to a recording listener): the shell launch is " +
      "refused (the tripwire) and the codex launch gets through though the shell launch registered the token (2026-10-10).",
  }),
  suite("secret-placeholder-argv", "sandbox/launcher/secret-placeholder-argv.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "openssl", "curl", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality.md",
    note: "confidentiality.md §7.1 (2026-10-05): the real launcher in `secrets` (guard, exec-wrap's curl shim, egress " +
      "proxy with TLS inspection) around a shell agent that sources a placeholder .env and runs curl with the secret's " +
      "placeholder on its command line (`-u \"$KEY:\"`, a Bearer header, a body): curl runs, the bound host gets the real " +
      "value from the proxy, the unbound host gets nothing (403, held), and no exec's argv the guard recorded holds the value. " +
      "The listeners read raw bytes and are as strict as nginx (one Host): each released request is byte-exact what plain " +
      "curl sends with the real value, apart from the proxy's `Accept-Encoding: identity` (the tour's Stripe 400, 2026-10-05).",
  }),
  suite("codex-shell-network", "sandbox/launcher/codex-shell-network.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "openssl", "curl", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/agents/supported-agents.md",
    note: "supported-agents.md §6.5: the real launcher in `secrets` around a stand-in `codex` that runs its work inside " +
      "the REAL `codex sandbox` (workspace-write) with the sandbox overrides it was given. Default launch: the launcher adds " +
      "`-c sandbox_workspace_write.network_access=true` and says so, the curl shim reaches the arbiter from inside Codex's " +
      "sandbox, the bound host gets the real value from the proxy, the unbound host nothing (403). " +
      "`--no-codex-shell-network`: no override, the shim says Codex's sandbox refused it (exit 77), no host gets a request. " +
      "Self-SKIPs without a codex whose sandbox starts here.",
  }),
  suite("codex-sandbox-refusal-note", "sandbox/launcher/codex-sandbox-refusal-note.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "openssl", "curl", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality-plan-10-flow-taint.md",
    note: "plan 10 §11.8, \"Blocked commands\" (tour 8): the real launcher in `secrets` runs the REAL `codex exec` against a " +
      "scripted Responses model (no key); one call `cat secret.txt; curl …` (masked: it names a labelled file). The user's " +
      "config keeps Codex's sandbox network off: the shim fails closed naming Codex's sandbox, the host gets nothing, and the " +
      "masked result carries the codex_sandbox `blocked:` line (from the guard's record of Codex's helper, the call unbound). " +
      "Control, the config silent: the launch opens the network, curl reaches the host, no `blocked:` line. " +
      "Self-SKIPs without a codex whose sandbox starts here.",
  }),
  suite("codex-sandbox-call-binding", "sandbox/launcher/codex-sandbox-call-binding.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "seccomp", "native-bins"],
    parallel: true, ci: KERNEL_CI, timeout: 900, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D7, Codex under its own sandbox: the real launcher in `secrets` runs the REAL `codex exec` (workspace-write) " +
      "against a scripted Responses model (no key). Call 1: a pinned python3 base64.py reader reads the labelled file raw " +
      "(masked by its call's tree). Call 2: `echo clean-$((6*7))` in the same session: bound to its own sandbox helper, it " +
      "reaches the model as `clean-42` (before: unbound, masked at the session's level), in well under 2 s. No request " +
      "carries the secret. " +
      "Two legs: `codex` as found on PATH (npm's wrapper script in the CI guest: the launch names the native binary it runs as " +
      "the agent, plan 13 §4.5.1) and that native binary launched directly (SKIPped where `codex` is no npm wrapper). " +
      "Self-SKIPs without a codex whose sandbox starts here.",
  }),
  suite("launcher-real-home", "sandbox/launcher/launcher-real-home.test.ts", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "native-bins"], parallel: true,
    ci: KERNEL_CI, doc: "docs/design/confidentiality/secret-discovery.md",
    note: "withStack mode `secrets`: the developer-shaped HOME is built in withStack's throwaway " +
      "HOME. The integrity form (the AgentView twin inheriting claude and codex trust) is " +
      "frozen: tests/integrity/launcher-real-home.test.ts.",
  }),
  e({
    id: "rust.kernel", kind: "sandbox", axis: "off", cwd: ".",
    cmd: ["bash", "scripts/kernel-tests.sh", "--include-ignored"],
    // One skip is structural: exec-supervisor's 0111-directory test needs a
    // caller that cannot list such a directory, and kernel-tests.sh runs the
    // crates as root of their user namespace (which can). net-supervisor's
    // cgroup test needs a user-owned cgroup, which the guest's boot.sh
    // delegates to `ci` (continuous-integration.md §3), so it must run.
    // Everything else runs.
    // 1200 s: a CI run takes 200-290 s, a host's cold build of the kernel
    // feature a few minutes more. It was 3600 s, past the CI guest's whole
    // 2700 s: a hung kernel test (pipelines 10978, 11050, 11099) ran out the
    // guest instead of this timeout (continuous-integration.md §3).
    needs: ["kernel", "cargo", "userns"], timeout: 1200, parallel: true, ci: { maxSkip: 1, minPass: 300 },
    doc: "docs/design/architecture/privilege-model.md",
    note: "cargo test --features kernel -- --include-ignored per crate inside the namespaces " +
      "kernel-tests.sh sets up: the #[ignore]d attachment tests AND the kernel-only tests that " +
      "`-- --ignored` never ran (test-organization.md §1). clone_filter_integration's Go leg (c) builds " +
      "net-supervisor's tests/fixtures/clone-probe.go with go (the guest's golang-go, provision.sh) and " +
      "prints a SKIP without it, which the two allowed (structural) skips cannot absorb.",
  }),
  // scripts/ci/ns-run.sh's isolation, for real: it creates namespaces, so it
  // never runs inside ns-run itself; in the guest its bwrap has overlay support
  // and nothing may skip.
  scriptTest("ci-ns-run", "scripts/test/ci-ns-run.test.sh", {
    kind: "sandbox", needs: ["kernel", "bash", "bwrap", "userns", "python3"], parallel: true,
    ci: { maxSkip: 0, minPass: 20 }, doc: "docs/design/testing/continuous-integration.md",
  }),
  launcherSh("net-guard-live", {
    kind: "sandbox", axis: "off", needs: ["kernel", "node", "native-bins", "seccomp"], parallel: true, ci: KERNEL_CI,
    doc: "docs/design/architecture/privilege-model.md",
  }),
  launcherSh("exec-box-live", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "native-bins", "curl"], parallel: true,
    ci: KERNEL_CI, doc: "docs/design/integrity/exec-routing.md",
    note: "was run by nothing before the manifest (test-organization.md §1). Its integrity form (the writable " +
      "AgentView leg) is the frozen launcher.exec-box-live.integrity. §3g (2026-10-01): the `secrets` workspace is " +
      "writable in the box (sed -i / sort -o; the replay over-block) while a no-model labelled file under the " +
      "twin wrap stays a symbol (exec-routing.md §7.2); since 2026-10-19 the same flag shows the box the agent's " +
      "own /tmp (a boxed cat reads what the agent wrote there, a /tmp socket masked). §3h (2026-10-09): the box's `bwrap --help`, kept by the " +
      "bubblewrap's content hash, skips the probe, re-probes changed bytes, and a forged answer fails closed " +
      "(exec-routing.md §4).",
  }),
  launcherSh("landlock-net-live", {
    kind: "sandbox", axis: "off", needs: ["kernel", "node", "landlock", "native-bins"], parallel: true, ci: KERNEL_CI,
    doc: "docs/design/architecture/privilege-model.md",
    note: "Landlock ABI 4 (kernel ≥ 6.7). Was run by nothing before the manifest (test-organization.md §1).",
  }),
  launcherSh("derived-label-live", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "curl", "nc", "python3", "seccomp", "native-bins"], parallel: true,
    ci: KERNEL_CI, doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "plan 13 D4: the real guard and arbiter; a reader (cp) copies a no-model .env, then fresh untainted cat " +
      "and curl --data-binary of the copy, after mv and after ln, in the same guard run and a new one, send no byte " +
      "of the key to a listener on 127.0.0.2 (it receives the twin); the next launch's discovery lists the copies; (9) a copy moved with its folder, opened or not, stays gated in the next guard run.",
  }),
  launcherSh("secret-twins-live", {
    kind: "sandbox", axis: "secrets", needs: ["kernel", "node", "bwrap", "userns", "nc"], parallel: true, ci: KERNEL_CI,
    doc: "docs/design/confidentiality/confidentiality.md",
  }),
  launcherSh("guard-death-live", {
    kind: "sandbox", axis: "off", needs: ["kernel", "node", "bwrap", "userns", "python3", "native-bins"], parallel: true,
    ci: KERNEL_CI, doc: "docs/design/confidentiality/rootless-confinement-ubuntu-2404.md",
  }),
];

// ── env: a local Ollama, no vendor budget ───────────────────────────────────────
const localModel = [
  suite("local-main-model", "env/local-main-model.test.ts", {
    kind: "env", axis: "secrets", cmd: ["npm", "run", "test:env:local-main-model", "--silent"],
    env: { MANDU_LIVE_LOCAL_MAIN_MODEL: "1" }, gate: "MANDU_LIVE_LOCAL_MAIN_MODEL",
    needs: ["node", "ollama"], timeout: 1800, parallel: false,
    session: {
      cls: "local-main-model-e2e", file: "env/local-main-model.test.ts",
      label: "local-main-model-e2e — the plan 11 phase 3 drill: the REAL launcher + `claude -p` whose MAIN model is your own Ollama",
    },
    doc: "docs/design/confidentiality/model-endpoints.md",
  }),
  suite("network-model", "env/network-model.test.ts", {
    kind: "env", axis: "secrets", cmd: ["npm", "run", "test:env:network-model", "--silent"],
    env: { MANDU_LIVE_NETWORK_MODEL: "1" }, gate: "MANDU_LIVE_NETWORK_MODEL",
    needs: ["node", "ollama"], timeout: 1800, parallel: false,
    doc: "docs/design/confidentiality/model-endpoints.md",
  }),
  suite("ollama-doctor", "env/ollama-doctor.test.ts", {
    kind: "env", axis: "secrets", env: { MANDU_LIVE_OLLAMA: "1" }, gate: "MANDU_LIVE_OLLAMA",
    needs: ["node", "ollama"], timeout: 600, parallel: false,
    doc: "docs/design/confidentiality/model-endpoints.md",
    note: "had no npm script, button or CI job before the manifest (test-organization.md §1).",
  }),
];

// ── live-drill, env, eval: a vendor login or key; spends budget ─────────────────
const realModel = [
  suite("local-model", "env/local-model.test.ts", {
    kind: "env", axis: "secrets", cmd: ["npm", "run", "test:env:local-model", "--silent"],
    env: { MANDU_LIVE_LOCAL_MODEL: "1" }, gate: "MANDU_LIVE_LOCAL_MODEL",
    needs: ["node", "claude", "claude-login", "ollama"], timeout: 2400, parallel: false, credential: "subscription",
    doc: "docs/design/confidentiality/model-endpoints.md",
    session: {
      cls: "local-model-e2e", file: "env/local-model.test.ts",
      label: "local-model-e2e — the plan 11 drill: the REAL launcher + `claude -p`, a local-model file summarized by your own Ollama model",
    },
    note: "LM1, LM2 (secrets by default); the T-LLM is Anthropic's, so real-model, not local-model.",
  }),
  suite("local-model-netns", "env/local-model.test.ts", {
    kind: "env", axis: "secrets", cmd: ["npm", "run", "test:env:local-model-netns", "--silent"],
    variantOf: "integration.local-model", internet: true,
    env: { MANDU_LIVE_LOCAL_MODEL: "1", MANDU_LIVE_LOCAL_MODEL_NETNS: "1" }, gate: "MANDU_LIVE_LOCAL_MODEL_NETNS",
    needs: ["node", "claude", "claude-login", "ollama", "userns"], timeout: 2400, parallel: false, credential: "subscription",
    doc: "docs/design/confidentiality/model-endpoints.md",
  }),
  suite("subscription", "env/subscription.test.ts", {
    kind: "env", axis: "secrets", env: { MANDU_E2E_SUBSCRIPTION: "1" }, gate: "MANDU_E2E_SUBSCRIPTION",
    needs: ["node", "claude", "claude-login"], timeout: 600, parallel: false, credential: "subscription",
    doc: "docs/design/agents/agent-sign-in.md",
    note: "a login, no spend. Its integrity form is in tests/integrity/ (integration.integrity, test-organization.md §7.3).",
  }),
  suite("subscription-real", "env/subscription-real.test.ts", {
    kind: "env", axis: "secrets", env: { MANDU_E2E_SUBSCRIPTION_LIVE: "1" }, gate: "MANDU_E2E_SUBSCRIPTION_LIVE",
    needs: ["node", "claude", "claude-login"], timeout: 600, parallel: false, credential: "subscription",
    doc: "docs/design/agents/agent-sign-in.md",
  }),
  e({
    id: "eval.run-live", kind: "eval", frozen: true, axis: "injection", cwd: "eval", env: INTEGRITY_OPT_IN,
    cmd: ["npm", "run", "test:eval", "--silent"], scripts: ["test:eval"], needs: ["node", "claude", "claude-login"],
    timeout: 900, parallel: false, doc: "docs/design/testing/evaluation.md",
    note: "its live stack pins integrity ON, confidentiality OFF (the AgentDojo eval, protection-modes.md §10.2); " +
      "without the opt-in the arbiter refuses it (ledger §7, 2026-09-29).",
  }),
  // The two evals are maintainer-run batches with chosen models (their CLIs
  // require --model/--inspection-model; without --out the output dir is a new
  // ~/.mandu/runs/eval/<run>, on-disk-layout.md §9.3), not nightly signal
  // (2026-09-29, continuous-integration.md §9.7).
  e({
    id: "eval.paired", kind: "eval", frozen: true, axis: "injection", cwd: "eval", cmd: ["npm", "run", "eval:paired", "--silent"],
    env: INTEGRITY_OPT_IN,
    needs: ["node", "claude", "claude-login"], timeout: 7200, parallel: false, doc: "docs/design/testing/evaluation.md",
    manual: "a maintainer's batch: `npm run eval:paired -- --out <new dir> --model <id> --inspection-model <id> --mode subscription`, and its review",
    note: "its wrapped leg runs `injection` (run-paired.ts): the paper's integrity defense, so the frozen lane " +
      "(protection-modes.md §10.7, 2026-09-29); it sat in real-model as `secrets`.",
  }),
  // Re-pinned 2026-09-29 (test-organization.md §7.3): each pinned full
  // incidentally; their integrity scenarios are frozen in tests/integrity/.
];

// ── install: the VM matrix ─────────────────────────────────────────────────────
const install = [
  e({
    id: "install.matrix", kind: "install", axis: "secrets", cwd: ".", cmd: ["bash", "scripts/matrix/run-matrix.sh"],
    files: [
      "scripts/matrix/suites/fresh-install.sh", "scripts/matrix/suites/fresh-install.host.sh",
      "scripts/matrix/suites/fresh-agents.sh", "scripts/matrix/suites/fresh-agents.host.sh",
      "scripts/matrix/suites/kernel.sh", "scripts/matrix/suites/all.sh", "scripts/matrix/suites/wrapper.sh",
    ],
    needs: ["kvm", "qemu", "network"], timeout: 60 * 60 * 6, parallel: false, doc: "docs/design/testing/os-test-matrix.md",
    note: "every target × its declared SUITES (scripts/matrix/targets/*.conf).",
  }),
  e({
    id: "install.release-upgrade", kind: "install", axis: "secrets", cwd: ".",
    cmd: ["bash", "scripts/matrix/run.sh", "ubuntu-2404", "release-upgrade"],
    files: ["scripts/matrix/suites/release-upgrade.sh", "scripts/matrix/suites/release-upgrade.host.sh"],
    needs: ["kvm", "qemu", "network"], timeout: 60 * 60 * 4, parallel: false, doc: "docs/design/testing/os-test-matrix.md",
    note: "about 30 minutes and 4 boots; by hand.",
  }),
  e({
    id: "install.npm-release", kind: "install", axis: "secrets", cwd: ".",
    cmd: ["bash", "scripts/matrix/run.sh", "ubuntu-2404", "npm-release"],
    files: [
      "scripts/matrix/suites/npm-release.sh", "scripts/matrix/suites/npm-release.host.sh",
      "scripts/matrix/suites/npm-release/timing-leg.sh",
    ],
    needs: ["kvm", "qemu", "network"], timeout: 60 * 60 * 3, parallel: false, doc: "docs/design/testing/os-test-matrix.md",
    note: "the npm release gate (private release runbook): the candidate tarball before publish, the registry after; both Ubuntu targets; by hand.",
  }),
  e({
    id: "install.kernel-vm", kind: "install", axis: "off", cwd: ".", cmd: ["bash", "scripts/kernel-vm.sh"],
    needs: ["kvm", "qemu", "network"], timeout: 60 * 60 * 2, parallel: false, doc: "docs/design/testing/os-test-matrix.md",
    note: "the alternate-kernel vehicle.",
  }),
];

// ── frozen lane: runs only when the integrity axis is revived ──────────────────
function integrityLane(name, cwd, o = {}) {
  return e({
    id: `${name}.integrity`, kind: "component", frozen: true, axis: "injection", cwd,
    cmd: ["npm", "run", "test:integrity", "--silent"], needs: ["node"], timeout: 1800,
    doc: "docs/design/architecture/protection-modes.md", ...o,
  });
}

// A launcher shell suite's integrity form, moved to launcher/test/integrity/
// when its default-lane form was re-pinned to secrets (protection-modes.md §10.7).
function launcherShFrozen(name, o) {
  return e({
    id: `launcher.${name}.integrity`, kind: "component", frozen: true, axis: "injection", cwd: "launcher",
    cmd: ["bash", `test/integrity/${name}.test.sh`], env: INTEGRITY_OPT_IN, timeout: 600,
    parallel: "sandbox", doc: "docs/design/architecture/protection-modes.md", ...o,
  });
}

const frozen = [
  integrityLane("arbiter", "arbiter"),
  integrityLane("fs-sync", "fs-sync"),
  integrityLane("launcher", "launcher", { parallel: "sandbox" }),
  integrityLane("integration", "tests", { kind: "stack", parallel: "sandbox" }),
  integrityLane("conformance", "tests/conformance", { kind: "stack", note: "the conformance corpus: run.ts and lib/unit_egress_gate.ts." }),
  launcherShFrozen("net-proxy-live", {
    needs: ["node", "curl"], note: "an untrusted symbol → 403 at the net-proxy; §8.4: free_port race.",
  }),
  launcherShFrozen("net-proxy-mitm-live", {
    needs: ["node", "curl", "openssl"], note: "an untrusted symbol in an HTTPS body → 403; §8.4: free_port race.",
  }),
  launcherShFrozen("exec-box-live", {
    kind: "sandbox", needs: ["kernel", "node", "bwrap", "userns", "native-bins"], parallel: true, ci: KERNEL_CI,
    note: "the writable AgentView leg (the fs-view co-design) with the box's shared legs.",
  }),
  launcherShFrozen("exec-wrap-live", {
    needs: ["node", "curl"], note: "an untrusted symbol on curl's argv → the shim blocks; §8.4: free_port race.",
  }),
  // The integrity forms of openclaw-e2e / opencode-e2e (test-organization.md §7.3),
  // tests/integrity/ copies that integration.integrity also runs; these run one agent.
  ...["openclaw", "opencode"].map((agent) => e({
    id: `integration.${agent}-e2e.integrity`, kind: "replay-drill", frozen: true, axis: "injection", cwd: "tests",
    cmd: ["npx", "tsx", "--test", `integrity/${agent}-e2e.test.ts`], variantOf: "integration.integrity",
    env: { MANDU_E2E_AXES: "injection", ...INTEGRITY_OPT_IN }, needs: ["node", agent], timeout: 1800,
    doc: "docs/design/architecture/protection-modes.md",
    note: "stored-ipi, fs-view-writeback, net-exfil-blocked, inspect-extract of untrusted data (needs a Claude login).",
  })),
  e({
    id: "integration.agents-real.integrity", kind: "live-drill", frozen: true, axis: "injection", cwd: "tests",
    agent: ["openclaw", "opencode"],
    cmd: ["npx", "tsx", "--test", "integrity/openclaw-e2e.test.ts", "integrity/opencode-e2e.test.ts"],
    variantOf: "integration.integrity",
    env: { MANDU_TEST_UPSTREAM: "real", MANDU_E2E_AXES: "injection", ...INTEGRITY_OPT_IN },
    needs: ["node", "openclaw", "opencode", "claude-login"], timeout: 3600, parallel: false,
    doc: "docs/design/architecture/protection-modes.md",
  }),
];

// ── env: the TLS-compat matrix, reaches the public internet ────────────────────
const internetOnly = [
  suite("tls-compat", "env/tls-compat.test.ts", {
    kind: "env", axis: "off", needs: ["node", "curl", "openssl"], internet: true, timeout: 900,
    // Nightly since test-reorganization.md §8 step 2 (it was `offline`, run
    // only by id): it needs no login, so it runs in the subscription lane's
    // guest, the one with the network (continuous-integration.md §9.8).
    env: { MANDU_LIVE_TLS_COMPAT: "1" }, gate: "MANDU_LIVE_TLS_COMPAT",
    doc: "docs/design/confidentiality/confidentiality-plan-13-reader-set-labels.md",
    note: "every HTTPS client installed on the host fetches a public page through the inspecting proxy.",
  }),
];

// ── env: the launch-time budget, the host's speed against a recorded baseline ──
// runtime-instances.md §14.11: warm `mandu <agent> --version` launches from an
// empty directory and a repository, medians against
// tests/env/launch-budget-baseline.json (recorded in the CI guest). Nightly,
// in the subscription lane's guest (it needs no login), alone (a timing beside
// another suite is that suite's); never per push: a shared runner is too noisy
// to block on, and a night is soon enough to hear of a slower launch.
const launchBudget = [
  suite("launch-budget", "env/launch-budget.test.ts", {
    kind: "env", axis: "secrets", env: { MANDU_LAUNCH_BUDGET: "1" }, gate: "MANDU_LAUNCH_BUDGET",
    needs: ["node", "git", "claude", "codex", "bwrap", "userns", "native-bins", "timing-baseline"],
    files: ["tests/env/launch-budget-baseline.json"],
    timeout: 1800, parallel: false, doc: "docs/design/architecture/runtime-instances.md",
    note: "fails a cell more than 50% and 300 ms over its baseline wall time, WARNs past 20% and 150 ms " +
      "(tests/lib/launch-budget.ts); cells: claude and codex from an empty dir, a repo and a developer-sized home; " +
      "prints every step either way; re-baseline: runtime-instances.md §14.11.",
  }),
];

// ── env: the dependency audit, reaches the advisory databases ───────────────────
// continuous-integration.md §14.2: the GitLab `audit` job (the schedule, v* tags,
// an MR that changes a lockfile) and GitHub's `audit` job run them by id, with
// --strict-skips, so no network or no cargo-audit is red there. Not the nightly's:
// an advisory is a finding about the tree, not a flake, and its job blocks.
const AUDIT_MANUAL = "the audit jobs run it by id (continuous-integration.md §14.2); a new advisory is news about the tree, never per push";
const depAudit = [
  e({
    id: "deps.audit-npm", kind: "env", axis: "off", cwd: ".", cmd: ["node", "scripts/dep-audit.mjs", "npm"],
    needs: ["node"], internet: true, manual: AUDIT_MANUAL, ci: { maxSkip: 0, minPass: 1 }, timeout: 900,
    files: ["scripts/dep-audit-allow.json"],
    doc: "docs/design/testing/continuous-integration.md",
    note: "`npm audit` over every package-lock.json (lockfile only, no install); findings judged against scripts/dep-audit-allow.json.",
  }),
  e({
    id: "deps.audit-cargo", kind: "env", axis: "off", cwd: ".", cmd: ["node", "scripts/dep-audit.mjs", "cargo"],
    needs: ["node", "cargo-audit"], internet: true, manual: AUDIT_MANUAL, ci: { maxSkip: 0, minPass: 1 }, timeout: 900,
    doc: "docs/design/testing/continuous-integration.md",
    note: "`cargo audit` over interceptors/Cargo.lock: vulnerabilities and unmaintained, unsound or yanked crates.",
  }),
];

/** Composite npm scripts: the union of several entries (run the entries instead). None
 *  today; the drills' composites are `drills:*` scripts (private/suites.mjs). */
export const aggregates = [];

// ── proves: the properties each suite proves (test-reorganization.md §5.1-§5.2) ─
// One table, so `node scripts/suites.mjs coverage` and a reviewer read the same
// claims. A claim is the author's: the suite drives the REAL path for the
// property (the proxy, arbiter, gate or sandbox wired together), not a stand-in.
// A package entry runs test/unit and test/component together; its claims are its component
// files'. A unit-kind entry's claims show as WARN cells (the function, not the
// path). First cut 2026-10-01 from a read of each suite's files (the MR that
// added it lists file:line evidence per claim). The nightly entries
// (live-drill, env, eval) were claimed 2026-10-02 the same way, each claim a
// HARD assertion of the suite in its nightly configuration (its env, its cut);
// a soft check (a WARN when the model does not try) claims nothing. A nightly
// entry with no claim says why in NO_PROVES; `suites.mjs check` holds every
// nightly entry to one or the other (test-reorganization.md §11.1).
//
// The weak claims of test-reorganization.md §11.1, strengthened 2026-10-02:
// model-ingress/web (stack/web-fetch-secret-ingress: a loopback page holding a
// registered secret, each agent's web tool, the real proxy over HTTP),
// ullm/quarantine (stack/ullm-quarantine-stdio: the real inspect-mcp stdio
// server against a stub U-LLM, so it never skips), exec/provenance and
// model-ingress/mcp (integration.guard-provenance: the REAL guard writes the
// taint records the proxies act on; the arbiter's and the stack's own claims
// fold records handed in). git-history/* is claimed by the sandbox entries
// only: a lock holds by the object twins' bind and the guard's backstop, both
// kernel mechanisms, so the arbiter's and the stack's suites (the lock filed,
// resolved and handed to the launcher) are no claim that it holds.
const PROVES = {
  // component: one package through its real interface, the arbiter mocked
  // unless said otherwise
  arbiter: ["fs/twin", "exec/provenance", "ullm/quarantine", "ullm/local-endpoint", "policy/monotonic",
    "policy/suggestion"],
  "anthropic-proxy": ["model-ingress/file", "model-ingress/web", "model-ingress/exec-output", "model-ingress/mcp", "model-ingress/prompt",
    "exec/symbol-command", "exec/provenance", "network-egress/upload", "fs/agentview", "fs/open-raw", "utility/no-over-block"],
  "openai-proxy": ["model-ingress/exec-output", "model-ingress/mcp", "model-ingress/prompt", "exec/symbol-command", "exec/provenance",
    "fs/agentview", "utility/no-over-block"],
  "net-proxy": ["network-egress/upload", "network-egress/mitm", "utility/no-over-block"],
  // the DevTools relay: a page's text reaching a browser agent, a typed
  // placeholder put back only for a bound origin (devtools-relay.md §7)
  "cdp-relay": ["model-ingress/web", "utility/no-over-block"],
  "inspect-mcp": ["ullm/quarantine", "ullm/local-endpoint", "policy/suggestion"],
  "exec-wrap": ["exec/symbol-command", "utility/no-over-block"],
  "reply-filter": ["reply/desymbolize"],
  "fs-sync": ["fs/agentview"],
  // reply/desymbolize includes `goose acp`'s JSON-aware editor pass
  // (component/goose-acp-real.test.ts "display": the REAL goose, the editor
  // reads the original, the model only the symbol, an echo masked; the
  // integration entry's stack/goose-acp-display.test.ts holds the production
  // resolver over the human plane, the data socket and the arbiter gone).
  launcher: ["model-ingress/file", "reply/desymbolize", "fs/agentview", "launcher/fail-closed", "utility/task"],
  "launcher.net-proxy-live": ["network-egress/upload", "utility/no-over-block"],
  "launcher.net-proxy-mitm-live": ["network-egress/mitm", "network-egress/upload"],
  "launcher.exec-wrap-live": ["exec/symbol-command", "network-egress/upload", "utility/no-over-block"],
  "launcher.reply-filter-live": ["reply/desymbolize", "launcher/fail-closed"],
  "launcher.wire-release-live": ["network-egress/mitm", "network-egress/upload", "fs/twin"],
  // unit: the decision logic only (WARN cells)
  "policy-mcp": ["policy/monotonic"],
  "openclaw-inspect-plugin": ["ullm/quarantine"],
  rust: ["network-egress/dns", "launcher/confine", "exec/symbol-command", "exec/box"],
  // stack: the real arbiter and proxies wired together, a scripted model
  integration: ["model-ingress/file", "model-ingress/exec-output", "model-ingress/web", "model-ingress/mcp",
    "model-ingress/git", "model-ingress/prompt", "reply/desymbolize", "network-egress/upload", "fs/twin", "fs/agentview",
    "exec/symbol-command", "exec/provenance", "ullm/quarantine", "ullm/local-endpoint", "policy/monotonic",
    "policy/suggestion", "utility/no-over-block"],
  // sandbox: the real sandbox, no agent
  "integration.launcher-fixture-homes": ["fs/twin", "utility/no-over-block"],
  "launcher.kernel": ["git-history/locked-path", "fs/open-raw", "fs/twin", "ullm/local-endpoint", "launcher/confine",
    "launcher/fail-closed", "utility/no-over-block"],
  "integration.kernel": ["model-ingress/git", "git-history/locked-path", "git-history/locked-blob", "policy/suggestion",
    "policy/monotonic", "ullm/local-endpoint", "launcher/confine", "launcher/fail-closed"],
  "launcher.secret-readers-live": ["fs/open-raw", "fs/twin", "exec/provenance"],
  "launcher.pipe-taint-live": ["fs/open-raw", "model-ingress/file", "network-egress/upload", "utility/no-over-block"],
  "integration.guard-provenance": ["exec/provenance", "model-ingress/mcp", "model-ingress/exec-output", "fs/open-raw"],
  "integration.reader-output-rule": ["exec/provenance", "model-ingress/exec-output", "fs/open-raw", "utility/no-over-block"],
  "integration.script-reader-pin": ["fs/open-raw", "model-ingress/exec-output", "utility/no-over-block"],
  "integration.args-code-reader": ["fs/open-raw", "model-ingress/exec-output", "utility/no-over-block"],
  "integration.ssh-config-write-protect": ["fs/open-raw", "launcher/confine", "utility/no-over-block"],
  "integration.printer-downstream": ["exec/provenance", "model-ingress/exec-output", "network-egress/upload", "network-egress/dns", "fs/open-raw"],
  "integration.git-transport-printer": ["fs/open-raw", "model-ingress/exec-output", "network-egress/upload"],
  "integration.build-tool-reader": ["fs/open-raw", "fs/twin", "model-ingress/exec-output"],
  "integration.reader-allow-list": ["fs/open-raw", "fs/twin", "model-ingress/exec-output"],
  "integration.call-tree": ["exec/provenance", "model-ingress/exec-output", "fs/open-raw", "utility/no-over-block"],
  "integration.high-session-command": ["exec/provenance", "network-egress/upload", "fs/open-raw"],
  "integration.report-channel-restart": ["fs/open-raw", "utility/no-over-block"],
  "integration.report-channel-late": ["fs/open-raw", "network-egress/upload", "utility/no-over-block"],
  "integration.report-channel-start": ["fs/open-raw", "fs/twin", "utility/no-over-block"],
  "integration.socket-flow": ["exec/provenance", "model-ingress/exec-output", "network-egress/upload", "utility/no-over-block"],
  "integration.agent-flow": ["model-ingress/web", "model-ingress/mcp", "model-ingress/prompt", "fs/open-raw", "utility/no-over-block"],
  "integration.task-output-twin": ["fs/twin", "model-ingress/exec-output", "reply/desymbolize", "utility/no-over-block"],
  "integration.cwd-file-holder": ["fs/twin", "model-ingress/exec-output", "utility/no-over-block"],
  "integration.cwd-secret-name": ["model-ingress/exec-output", "fs/twin"],
  "integration.forged-reports": ["exec/provenance", "model-ingress/exec-output", "fs/open-raw", "utility/no-over-block"],
  "integration.tainted-egress": ["network-egress/dns", "network-egress/upload", "fs/open-raw"],
  "integration.holder-accept": ["network-egress/upload", "fs/open-raw", "utility/no-over-block"],
  "integration.https-proxy-taint": ["network-egress/upload", "network-egress/mitm", "fs/open-raw", "utility/no-over-block"],
  "integration.blind-tunnel-fork": ["network-egress/upload", "fs/open-raw", "utility/no-over-block"],
  "integration.secret-placeholder-argv": ["exec/symbol-command", "network-egress/upload", "network-egress/mitm", "fs/twin", "utility/no-over-block"],
  "integration.codex-sandbox-refusal-note": ["model-ingress/exec-output", "launcher/fail-closed"],
  "integration.codex-sandbox-call-binding": ["model-ingress/exec-output", "utility/no-over-block"],
  "integration.codex-shell-network": ["network-egress/upload", "network-egress/mitm", "fs/twin", "launcher/confine", "utility/no-over-block"],
  "integration.launcher-real-home": ["fs/open-raw", "utility/no-over-block"],
  "integration.twin-format-fidelity": ["fs/twin", "fs/open-raw", "utility/no-over-block"],
  "integration.tar-secret": ["fs/twin", "fs/open-raw", "utility/no-over-block"],
  "integration.tar-twin": ["fs/twin", "launcher/confine", "utility/no-over-block"],
  "integration.hard-link-twin-meta": ["fs/twin", "launcher/confine"],
  "integration.twin-git-clean": ["fs/twin", "model-ingress/git", "utility/task", "utility/no-over-block"],
  "integration.twin-write-notice": ["fs/twin", "launcher/confine"],
  "integration.launch-cwd-pwd": ["fs/twin", "launcher/confine"],
  "integration.other-agent-logins": ["fs/twin", "fs/open-raw", "network-egress/upload", "utility/no-over-block"],
  "integration.npmrc-wire-twin": ["fs/twin", "fs/open-raw", "network-egress/upload", "network-egress/mitm", "model-ingress/mcp", "utility/no-over-block"],
  "integration.pip-wire-twin": ["fs/twin", "fs/open-raw", "network-egress/upload", "network-egress/mitm", "utility/no-over-block"],
  "rust.kernel": ["exec/symbol-command", "exec/box", "exec/provenance", "fs/open-raw", "fs/agentview",
    "launcher/confine", "network-egress/upload"],
  "launcher.net-guard-live": ["launcher/confine"],
  "launcher.exec-box-live": ["exec/box", "exec/symbol-command", "network-egress/upload", "launcher/fail-closed",
    "fs/twin", "utility/no-over-block"],
  "launcher.landlock-net-live": ["launcher/confine"],
  "launcher.secret-twins-live": ["fs/open-raw", "fs/twin"],
  "launcher.derived-label-live": ["fs/open-raw", "fs/twin", "network-egress/upload"],
  "launcher.guard-death-live": ["launcher/fail-closed", "fs/open-raw"],
  // env: the host decides (a local model server, a login, the internet)
  // tls-compat: real clients through the real MITM net-proxy with the
  // launcher's trust env; the arbiter is a mock and nothing secret is sent, so
  // it proves the inspecting path is reached and trusted, not that it judges.
  "integration.tls-compat": ["network-egress/mitm"],
  // the real launcher, arbiter and proxy, a real Ollama as the helper: the
  // canary never on the vendor wire, the model sees the `localmodel_` /
  // `anymodel_` symbol, `ullm_call` names the declared local endpoint, the
  // launcher's reply filter puts the helper's answer in the human's reply
  // (tests/lib/local-model-oracle.ts)
  "integration.local-model": ["model-ingress/file", "ullm/local-endpoint", "ullm/quarantine", "reply/desymbolize"],
  "integration.local-model-netns": ["model-ingress/file", "ullm/local-endpoint", "reply/desymbolize"],
  // the helper's answer a `localmodel_` symbol, an outside address refused
  "integration.network-model": ["ullm/local-endpoint"],
  // a real `claude` Read through the real proxy and arbiter: one symbol, no canary
  "integration.subscription": ["model-ingress/file"],
};

// The nightly entries that prove no property, and why (2026-10-02). The
// check (`suites.mjs check`) wants every nightly entry of a nightly kind to
// claim `proves` or name its reason here.
const NO_PROVES = {
  "integration.local-main-model": "the local model is the MAIN model (plan 11 §7): the session binds to the declared endpoint and the vendor sees nothing, which no property in the list names (ullm/local-endpoint is the helper's)",
  "integration.ollama-doctor": "checks what `mandu doctor` reports about a real Ollama",
  "integration.subscription-real": "relay mechanics with a real login (a token echoed, the OAuth credential relayed); no labelled data",
  "integration.launch-budget": "a launch-time budget (the host's speed against a recorded baseline), not a data path",
  "deps.audit-npm": "a supply-chain check of the lockfiles against published advisories, not a data path",
  "deps.audit-cargo": "a supply-chain check of the Cargo lockfile against the RustSec database, not a data path",
};

export const entries = [
  ...typecheck,
  ...packages,
  ...evalEntries,
  ...wrapperShell,
  ...scriptTests,
  ...githubAction,
  ...docsLane,
  ...rustOffline,
  ...kernel,
  ...localModel,
  ...realModel,
  ...install,
  ...frozen,
  ...internetOnly,
  ...launchBudget,
  ...depAudit,
];

for (const [id, proves] of Object.entries(PROVES)) {
  const x = entries.find((y) => y.id === id);
  if (!x) throw new Error(`tests/suites.mjs: PROVES names '${id}', which is no entry`);
  x.proves = proves;
}
for (const [id, why] of Object.entries(NO_PROVES)) {
  const x = entries.find((y) => y.id === id);
  if (!x) throw new Error(`tests/suites.mjs: NO_PROVES names '${id}', which is no entry`);
  x.provesNone = why;
}

// Every `test*` aggregate script names the entries it spans (`entries`): none
// is derived from the files it runs (the last derivation read the drill tree,
// 2026-10-10).
for (const a of aggregates) a.entries ??= [];

export default entries;
