/**
 * layout — unit oracle for the packaging.md §5 layout resolver: the dev source
 * form runs each entry as ONE node process through the package-local tsx (no
 * npm); installed and a checkout's fresh build (§5.1) target dist/<name>.mjs
 * and pin MANDU_ARBITER_CLIENT_MODULE; detect() picks the layout from where the
 * launcher runs (src, a checkout's dist, an installed dist) with env overrides.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
import { Layout, SERVICE_SOURCES, isCheckoutBuild } from "../../src/services/layout.js";

const REPO = "/repo";
const PKG = "/opt/mandu"; // an installed @mandusec/mandu package root

// ── dev mode: verbatim from-source spawns ────────────────────────────────────

test("dev daemon → ONE node process: node --import <package tsx> <entry.ts>, in the source package dir (never npm run serve)", () => {
  const d = Layout.dev(REPO).daemon("anthropic-proxy", join("interceptors", "anthropic-proxy"));
  assert.equal(d.cmd, "node");
  assert.deepEqual(d.args, [
    "--import", "file:///repo/interceptors/anthropic-proxy/node_modules/tsx/dist/esm/index.mjs",
    "/repo/interceptors/anthropic-proxy/src/server-main.ts",
  ]);
  assert.equal(d.cwd, "/repo/interceptors/anthropic-proxy");
  assert.deepEqual(d.env, {}); // no client-module env from source
  const a = Layout.dev(REPO).daemon("arbiter", "arbiter", false);
  assert.deepEqual(a.args, ["--import", "file:///repo/arbiter/node_modules/tsx/dist/esm/index.mjs", "/repo/arbiter/ipc/server-main.ts"]);
  assert.equal(a.cwd, "/repo/arbiter");
  for (const [name, sub] of [["net-proxy", "interceptors/net-proxy"], ["openai-proxy", "interceptors/openai-proxy"], ["dashboard", "dashboard"]] as const) {
    const s = Layout.dev(REPO).daemon(name, sub);
    assert.equal(s.cmd, "node", name);
    assert.ok(!s.args.includes("serve") && !s.args.some((t) => /\/\.bin\/tsx$/.test(t)), `${name}: no npm, no tsx binary`);
  }
});

// Dev helpers run `node --import <file URL of the package-local tsx ESM
// entry> <entry.ts>`, never the tsx BINARY: that binary re-spawns node with a
// CJS `--require` preload, and a preload makes node parse the CWD's
// package.json — a whole-file symbol twin in an AgentView worktree under an
// integrity-ON mode (ERR_INVALID_PACKAGE_CONFIG; the reply filter, the
// exec-wrap shim and inspect-mcp all died at launch in any Node workspace,
// 2026-09-24). The file URL resolves nothing from the cwd.
const TSX = (pkg: string): string => `file:///repo/${pkg}/node_modules/tsx/dist/esm/index.mjs`;

test("dev inspect-mcp → node --import <tsx esm> over server-main.ts, no client env", () => {
  const m = Layout.dev(REPO).inspectMcp();
  assert.equal(m.command, "node");
  assert.deepEqual(m.args, ["--import", TSX("interceptors/inspect-mcp"), "/repo/interceptors/inspect-mcp/src/server-main.ts"]);
  assert.deepEqual(m.env, {});
});

test("dev fs-sync one-shot and watch: both node --import <tsx esm>", () => {
  const dev = Layout.dev(REPO);
  const one = dev.fsSyncCli();
  assert.equal(one.cmd, "node");
  assert.deepEqual(one.baseArgs, ["--import", TSX("fs-sync"), "/repo/fs-sync/src/fs-sync-cli.ts"]);
  assert.equal(one.cwd, "/repo/fs-sync");
  const watch = dev.fsSyncWatch();
  assert.equal(watch.cmd, "node");
  assert.deepEqual(watch.baseArgs, one.baseArgs);
});

test("dev exec-shim → node --import <tsx esm> over wrap.ts", () => {
  const e = Layout.dev(REPO).execShim();
  assert.deepEqual(e.tokens, ["node", "--import", TSX("interceptors/exec-wrap"), "/repo/interceptors/exec-wrap/src/wrap.ts"]);
  assert.deepEqual(e.env, {});
});

test("dev reply-filter → node --import <tsx esm> over run.ts; the tsx entry is the required file", () => {
  const r = Layout.dev(REPO).replyFilter();
  assert.deepEqual(r.tokens, ["node", "--import", TSX("interceptors/reply-filter"), "/repo/interceptors/reply-filter/src/run.ts"]);
  assert.equal(r.requiredFile, "/repo/interceptors/reply-filter/node_modules/tsx/dist/esm/index.mjs");
});

test("no dev helper token is the tsx binary or a bare --require/--import specifier (the cwd package.json hazard)", () => {
  const dev = Layout.dev(REPO);
  const all = [
    dev.inspectMcp().command, ...dev.inspectMcp().args,
    dev.fsSyncCli().cmd, ...dev.fsSyncCli().baseArgs,
    dev.fsSyncWatch().cmd, ...dev.fsSyncWatch().baseArgs,
    ...dev.execShim().tokens, ...dev.replyFilter().tokens,
  ];
  for (const t of all) assert.ok(!/\/\.bin\/tsx$/.test(t), `tsx binary in dev tokens: ${t}`);
  for (let i = 0; i < all.length; i++) {
    if (all[i] === "--require") assert.fail(`a --require preload in dev tokens (index ${i})`);
    if (all[i] === "--import") assert.ok(all[i + 1]!.startsWith("file:///"), `--import must name a file URL, got ${all[i + 1]}`);
  }
});

test("REGRESSION: the dev --import form runs a .ts entry from a cwd whose package.json is not JSON", () => {
  // The real hazard, end to end: node + the launcher's own tsx (this package
  // has one) run a TypeScript entry with the cwd's package.json holding a
  // symbol token, exactly what an AgentView worktree holds under `full`.
  const here = dirname(fileURLToPath(import.meta.url));
  const launcherRoot = resolve(here, "..", "..");
  const entry = join(launcherRoot, "node_modules", "tsx", "dist", "esm", "index.mjs");
  if (!existsSync(entry)) { console.log("# skip: no package-local tsx (npm install)"); return; }
  // The entry lives in its own (valid) package, like every helper's src/;
  // only the CWD is the agent's poisoned worktree.
  const root = mkdtempSync(join(tmpdir(), "mandu-badpkg-"));
  const cwd = join(root, "agentview");
  const pkg = join(root, "helper");
  try {
    mkdirSync(cwd); mkdirSync(pkg);
    writeFileSync(join(cwd, "package.json"), "$MDU:Read[625b].package.json\n");
    writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "helper", type: "module" }));
    writeFileSync(join(pkg, "entry.ts"), "const n: number = 1; process.stdout.write(`ok${n}`);\n");
    const good = spawnSync("node", ["--import", pathToFileURL(entry).href, join(pkg, "entry.ts")], { cwd, encoding: "utf8" });
    assert.equal(good.status, 0, `the --import form must survive the cwd: ${good.stderr}`);
    assert.equal(good.stdout, "ok1");
    // and the tsx BINARY form is the one that does not (the class this pins)
    const bin = join(launcherRoot, "node_modules", ".bin", "tsx");
    if (existsSync(bin)) {
      const bad = spawnSync(bin, [join(pkg, "entry.ts")], { cwd, encoding: "utf8" });
      assert.notEqual(bad.status, 0, "the tsx binary form is expected to fail from this cwd (if it no longer does, the helper can go back to it)");
      assert.match(bad.stderr, /ERR_INVALID_PACKAGE_CONFIG/);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

// ── installed mode: dist bundles + arbiter-client module ─────────────────────

const CLIENT = { MANDU_ARBITER_CLIENT_MODULE: "/opt/mandu/dist/arbiter-client.mjs" };

test("installed daemon → node dist/<name>.mjs with the client module env", () => {
  const d = Layout.installed(PKG).daemon("net-proxy", join("interceptors", "net-proxy"));
  assert.equal(d.cmd, "node");
  assert.deepEqual(d.args, ["--no-warnings=ExperimentalWarning", "/opt/mandu/dist/net-proxy.mjs"]);
  assert.equal(d.cwd, PKG);
  assert.deepEqual(d.env, CLIENT);
});

test("installed dashboard daemon also gets the U-LLM module (the Describe box, policy-surface.md §8.5.2); dev gets none", () => {
  const d = Layout.installed(PKG).daemon("dashboard", "dashboard");
  assert.deepEqual(d.env, { ...CLIENT, MANDU_ULLM_MODULE: "/opt/mandu/dist/ullm-client.mjs" });
  assert.deepEqual(Layout.installed(PKG).daemon("net-proxy", join("interceptors", "net-proxy")).env, CLIENT, "only the dashboard");
});

test("installed arbiter daemon gets NO client module (it never imports its own client)", () => {
  const d = Layout.installed(PKG).daemon("arbiter", "arbiter", false);
  assert.deepEqual(d.args, ["--no-warnings=ExperimentalWarning", "/opt/mandu/dist/arbiter.mjs"]);
  assert.deepEqual(d.env, {}); // needsClient=false
});

test("installed inspect-mcp / fs-sync / exec-shim → dist bundles + client env", () => {
  const l = Layout.installed(PKG);
  const m = l.inspectMcp();
  assert.equal(m.command, "node");
  assert.deepEqual(m.args, ["--no-warnings=ExperimentalWarning", "/opt/mandu/dist/inspect-mcp.mjs"]);
  assert.deepEqual(m.env, CLIENT);

  const one = l.fsSyncCli();
  assert.equal(one.cmd, "node");
  assert.deepEqual(one.baseArgs, ["--no-warnings=ExperimentalWarning", "/opt/mandu/dist/fs-sync-cli.mjs"]);
  assert.deepEqual(one.env, CLIENT);
  // installed watch is the SAME single node process as the one-shot (no tsx wrapper)
  assert.deepEqual(l.fsSyncWatch().baseArgs, one.baseArgs);

  const e = l.execShim();
  assert.deepEqual(e.tokens, ["node", "--no-warnings=ExperimentalWarning", "/opt/mandu/dist/exec-shim.mjs"]);
  assert.deepEqual(e.env, CLIENT);
});

// ── detect(): mode from where the launcher runs, with env overrides ──────────

test("detect: running from src/ → dev; from dist/ → installed", () => {
  const devUrl = pathToFileURL("/repo/launcher/src/run.ts").href;
  const dev = Layout.detect(devUrl, {});
  assert.equal(dev.mode, "dev");
  assert.equal(dev.repoRoot, "/repo"); // parent of the launcher package

  const instUrl = pathToFileURL("/opt/mandu/dist/mandu.mjs").href;
  const inst = Layout.detect(instUrl, {});
  assert.equal(inst.mode, "installed");
  assert.equal(inst.pkgRoot, "/opt/mandu");
});

test("detect: MANDU_LAYOUT and MANDU_DEV_REPO force the mode", () => {
  const instUrl = pathToFileURL("/opt/mandu/dist/mandu.mjs").href;
  // a dist launcher forced back to dev against an explicit repo
  const forcedDev = Layout.detect(instUrl, { MANDU_DEV_REPO: "/src/tree" });
  assert.equal(forcedDev.mode, "dev");
  assert.equal(forcedDev.repoRoot, "/src/tree");

  const srcUrl = pathToFileURL("/repo/launcher/src/run.ts").href;
  const forcedInstalled = Layout.detect(srcUrl, { MANDU_LAYOUT: "installed" });
  assert.equal(forcedInstalled.mode, "installed");
});

// ── a checkout running its own fresh build (packaging.md §5.1) ───────────────

const DEVPKG = "/repo/launcher";
const DEV_CLIENT = { MANDU_ARBITER_CLIENT_MODULE: "/repo/launcher/dist/arbiter-client.mjs" };

test("dev bundled: every per-session service runs its launcher/dist bundle with the client module, exactly as installed", () => {
  const l = Layout.dev(REPO, DEVPKG, { bundled: true });
  assert.equal(l.mode, "dev");
  assert.equal(l.bundled, true);
  for (const [name, sub, client] of [
    ["arbiter", "arbiter", false], ["anthropic-proxy", "interceptors/anthropic-proxy", true],
    ["openai-proxy", "interceptors/openai-proxy", true], ["net-proxy", "interceptors/net-proxy", true],
  ] as const) {
    const d = l.daemon(name, sub, client);
    assert.equal(d.cmd, "node", name);
    assert.deepEqual(d.args, ["--no-warnings=ExperimentalWarning", `/repo/launcher/dist/${name}.mjs`], name);
    assert.deepEqual(d.env, client ? DEV_CLIENT : {}, name);
  }
  assert.deepEqual(l.execShim(), { tokens: ["node", "--no-warnings=ExperimentalWarning", "/repo/launcher/dist/exec-shim.mjs"], env: DEV_CLIENT });
  assert.deepEqual(l.replyFilter(), {
    tokens: ["node", "--no-warnings=ExperimentalWarning", "/repo/launcher/dist/reply-filter.mjs"], env: DEV_CLIENT,
    requiredFile: "/repo/launcher/dist/reply-filter.mjs",
  });
  assert.deepEqual(l.inspectMcp().args, ["--no-warnings=ExperimentalWarning", "/repo/launcher/dist/inspect-mcp.mjs"]);
  assert.deepEqual(l.policyMcp().args, ["--no-warnings=ExperimentalWarning", "/repo/launcher/dist/policy-mcp.mjs"]);
  assert.deepEqual(l.fsSyncCli().baseArgs, ["--no-warnings=ExperimentalWarning", "/repo/launcher/dist/fs-sync-cli.mjs"]);
  assert.deepEqual(l.policyClassifier(() => true), [process.execPath, "--no-warnings=ExperimentalWarning", "/repo/launcher/dist/policy-classifier.mjs"]);
});

test("dev bundled: the resident dashboard runs the same build (it knows a checkout's build: dashboard server-main), and assets come from the checkout", () => {
  const l = Layout.dev(REPO, DEVPKG, { bundled: true });
  const d = l.daemon("dashboard", "dashboard");
  assert.equal(d.cmd, "node");
  assert.deepEqual(d.args, ["--no-warnings=ExperimentalWarning", "/repo/launcher/dist/dashboard.mjs"]);
  assert.equal(d.cwd, DEVPKG);
  assert.deepEqual(d.env, { ...DEV_CLIENT, MANDU_ULLM_MODULE: "/repo/launcher/dist/ullm-client.mjs" }, "the Describe box's U-LLM module from the same build");
  assert.equal(l.asset("apparmor/mandu-bwrap"), "/repo/scripts/apparmor/mandu-bwrap");
  // A source launch keeps the dashboard on source: one node process.
  const s = Layout.dev(REPO, DEVPKG).daemon("dashboard", "dashboard");
  assert.deepEqual(s.args, ["--import", "file:///repo/dashboard/node_modules/tsx/dist/esm/index.mjs", "/repo/dashboard/src/server-main.ts"]);
  assert.deepEqual(s.env, {}, "no bundle modules for a source dashboard");
});

test("isCheckoutBuild: a dist/ beside src/run.ts is a checkout's build; an installed dist (no src/) is not", () => {
  const has = (paths: string[]) => (p: string) => paths.includes(p);
  assert.equal(isCheckoutBuild("/repo/launcher/dist", has(["/repo/launcher/src/run.ts"])), true);
  assert.equal(isCheckoutBuild("/opt/mandu/dist", has([])), false);
  assert.equal(isCheckoutBuild("/repo/launcher/src", has(["/repo/launcher/src/run.ts"])), false, "only a dist/");
});

test("detect: a checkout's own launcher/dist → dev, bundled; an installed dist stays installed; MANDU_DEV_REPO keeps the source form", () => {
  const url = pathToFileURL("/repo/launcher/dist/mandu.mjs").href;
  const exists = (p: string) => p === "/repo/launcher/src/run.ts";
  const l = Layout.detect(url, {}, exists);
  assert.equal(l.mode, "dev");
  assert.equal(l.bundled, true);
  assert.equal(l.repoRoot, "/repo");
  assert.equal(l.pkgRoot, "/repo/launcher");

  const inst = Layout.detect(pathToFileURL("/opt/mandu/dist/mandu.mjs").href, {}, exists);
  assert.equal(inst.mode, "installed");
  assert.equal(inst.bundled, true);

  const src = Layout.detect(pathToFileURL("/repo/launcher/src/run.ts").href, {}, exists);
  assert.equal(src.mode, "dev");
  assert.equal(src.bundled, false, "a launcher run through tsx runs its services through tsx");

  // Another tree's services were not built into this dist.
  const other = Layout.detect(url, { MANDU_DEV_REPO: "/elsewhere" }, exists);
  assert.equal(other.bundled, false);
  assert.equal(other.repoRoot, "/elsewhere");
  assert.equal(Layout.detect(url, { MANDU_LAYOUT: "installed" }, exists).mode, "installed");
});

test("SERVICE_SOURCES mirrors bundle-manifest.json services (the built set is the spawned set)", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const manifest = JSON.parse(readFileSync(resolve(here, "..", "..", "bundle-manifest.json"), "utf8")) as { services: Record<string, string> };
  assert.deepEqual({ ...SERVICE_SOURCES }, manifest.services);
});
