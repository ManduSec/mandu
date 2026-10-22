/**
 * supervisor-defs-installed.test — the INSTALLED layout's service definitions
 * (packaging.md §5; os-test-matrix.md §10.11 finding 2): from the
 * @mandusec/mandu bundle there is no checkout, so every service must be spawned
 * as `node --no-warnings=ExperimentalWarning <pkgRoot>/dist/<name>.mjs` with
 * cwd pkgRoot, and the proxies pointed at the co-located arbiter-client
 * bundle — exactly what the launcher's layout resolver does. Without
 * `layout` the checkout definitions apply (packaging.md §5.1): the source form
 * as one `node --import <tsx>` process, carrying the bundled form the
 * supervisor picks while the bundle is fresh
 * (supervisor-checkout-bundle.test.ts).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { buildDefinitions, bundledSpawn, DEFAULTS, type ResolvedSupervisorOptions } from "../../../src/supervisor/supervisor-defs.js";
import { Supervisor } from "../../../src/supervisor/supervisor.js";

const base = (extra: Partial<ResolvedSupervisorOptions> = {}): ResolvedSupervisorOptions => ({
  repoRoot: "/repo",
  arbiterSock: "/run/mdu/arbiter.sock",
  ...DEFAULTS,
  autoStartArbiter: true,
  axisEnv: () => ({}),
  log: () => {},
  gitRev: () => "nogit",
  gitChangedInRange: () => [],
  procCmdline: () => null,
  killPid: () => {},
  discoverSocketOwner: () => null,
  replaceStaleOnAdopt: true,
  liveSessions: () => [],
  onCrash: () => {},
  bundleFresh: async () => ({ fresh: false, reason: "test" }),
  ownArbiterBuild: () => ({ version: null, bundle: null, installed: false }),
  ...extra,
});

test("dev (no layout): every service is ONE node process from source (no `npm run serve`), with the checkout's bundled form beside it", () => {
  const d = buildDefinitions(base(), {});
  const tsx = (pkg: string): string => pathToFileURL(join("/repo", pkg, "node_modules", "tsx", "dist", "esm", "index.mjs")).href;
  const want: Array<[keyof typeof d, string, string]> = [
    ["arbiter", "arbiter", "arbiter/ipc/server-main.ts"],
    ["test-arbiter", "arbiter", "arbiter/ipc/server-main.ts"],
    ["anthropic-proxy", "interceptors/anthropic-proxy", "interceptors/anthropic-proxy/src/server-main.ts"],
    ["openai-proxy", "interceptors/openai-proxy", "interceptors/openai-proxy/src/server-main.ts"],
    ["net-proxy", "interceptors/net-proxy", "interceptors/net-proxy/src/server-main.ts"],
  ];
  for (const [id, pkg, entry] of want) {
    assert.equal(d[id].command, process.execPath, `${id}: node itself, never npm`);
    assert.deepEqual(d[id].args.slice(0, 3), ["--import", tsx(pkg), join("/repo", entry)], `${id}: the package's own tsx, one process`);
    assert.equal(d[id].cwd, join("/repo", pkg));
    assert.ok(!d[id].args.includes("serve") && d[id].command !== "npm", `${id}: no npm run serve`);
    const b = d[id].checkoutBundle!;
    assert.ok(b, `${id}: carries the bundled form`);
    assert.equal(b.distDir, join("/repo", "launcher", "dist"));
    assert.equal(b.repoRoot, "/repo");
    assert.equal(b.cwd, join("/repo", "launcher"));
    const name = id === "test-arbiter" ? "arbiter" : id;
    assert.deepEqual(b.args.slice(0, 2), ["--no-warnings=ExperimentalWarning", join("/repo", "launcher", "dist", `${name}.mjs`)]);
    // The tail is the same in both forms (no classifier under /repo; where
    // there is one, each form runs its own: arbiter-classifier-args.test.ts).
    assert.deepEqual(b.args.slice(2), d[id].args.slice(3), `${id}: the same tail arguments`);
  }
  assert.equal(d["anthropic-proxy"].env.MANDU_ARBITER_CLIENT_MODULE, undefined, "the source form imports the client from source");
  assert.equal(d["anthropic-proxy"].checkoutBundle!.env.MANDU_ARBITER_CLIENT_MODULE, join("/repo", "launcher", "dist", "arbiter-client.mjs"));
  assert.equal(d.arbiter.checkoutBundle!.env.MANDU_ARBITER_CLIENT_MODULE, undefined, "the arbiter never imports its own client");
  assert.equal(d.arbiter.adminChannel, true, "the admin channel survives: a direct node spawn either way");
  // A private build (a test) names its own dist.
  const p = buildDefinitions(base({ checkoutDist: "/tmp/build/out" }), {});
  assert.equal(p["net-proxy"].checkoutBundle!.args[1], "/tmp/build/out/net-proxy.mjs");
  assert.equal(p["net-proxy"].checkoutBundle!.env.MANDU_ARBITER_CLIENT_MODULE, "/tmp/build/out/arbiter-client.mjs");
});

test("installed: every service is its bundle under <pkgRoot>/dist, cwd pkgRoot, proxies get the arbiter-client bundle; the arbiter keeps its admin channel", () => {
  const pkg = "/home/u/.nvm/versions/node/v22/lib/node_modules/@mandusec/mandu";
  const d = buildDefinitions(base({ repoRoot: pkg, layout: { mode: "installed", pkgRoot: pkg } }), {});
  for (const id of ["arbiter", "anthropic-proxy", "openai-proxy", "net-proxy", "test-arbiter"] as const) {
    assert.equal(d[id].command, process.execPath, `${id}: spawned by node directly`);
    assert.equal(d[id].cwd, pkg, `${id}: cwd is the package root, which exists`);
    assert.equal(d[id].args[0], "--no-warnings=ExperimentalWarning", `${id}: the bundle node flag`);
    assert.ok(!d[id].args.includes("serve") && !d[id].args.some((a) => a.includes("tsx")), `${id}: no npm/tsx from an npm install`);
    assert.equal(d[id].checkoutBundle, undefined, `${id}: installed has no second form to choose`);
  }
  assert.equal(d.arbiter.args[1], join(pkg, "dist", "arbiter.mjs"));
  assert.equal(d["test-arbiter"].args[1], join(pkg, "dist", "arbiter.mjs"));
  assert.equal(d["anthropic-proxy"].args[1], join(pkg, "dist", "anthropic-proxy.mjs"));
  assert.equal(d["openai-proxy"].args[1], join(pkg, "dist", "openai-proxy.mjs"));
  assert.equal(d["net-proxy"].args[1], join(pkg, "dist", "net-proxy.mjs"));
  // the interceptors dynamic-import the arbiter client: the co-located bundle
  const client = join(pkg, "dist", "arbiter-client.mjs");
  assert.equal(d["anthropic-proxy"].env.MANDU_ARBITER_CLIENT_MODULE, client);
  assert.equal(d["openai-proxy"].env.MANDU_ARBITER_CLIENT_MODULE, client);
  assert.equal(d["net-proxy"].env.MANDU_ARBITER_CLIENT_MODULE, client);
  assert.equal(d.arbiter.env.MANDU_ARBITER_CLIENT_MODULE, undefined, "the arbiter never imports its own client");
  // everything else about the definitions is unchanged by the layout
  assert.equal(d.arbiter.adminChannel, true);
  assert.equal(d.arbiter.env.MANDU_TENANT, "live");
  assert.equal(d["anthropic-proxy"].env.MANDU_PROXY_PORT, String(DEFAULTS.modelProxyPort));
  assert.deepEqual(d["anthropic-proxy"].requires, ["arbiter"]);
});

test("bundledSpawn is the launcher's Layout.daemon shape (layout.ts): node flags + dist/<name>.mjs + the client env only when asked", () => {
  const s = bundledSpawn("/opt/mandu", "net-proxy", true);
  assert.equal(s.command, process.execPath);
  assert.deepEqual(s.args, ["--no-warnings=ExperimentalWarning", "/opt/mandu/dist/net-proxy.mjs"]);
  assert.equal(s.cwd, "/opt/mandu");
  assert.deepEqual(s.clientEnv, { MANDU_ARBITER_CLIENT_MODULE: "/opt/mandu/dist/arbiter-client.mjs" });
  assert.deepEqual(bundledSpawn("/opt/mandu", "arbiter", false).clientEnv, {});
});

test("the Supervisor CARRIES the layout into its definitions (the constructor once dropped it: the bundled dashboard spawned checkout cwds)", () => {
  const pkg = "/opt/mandu";
  const sup = new Supervisor({ repoRoot: pkg, arbiterSock: "/run/mdu/arbiter.sock", layout: { mode: "installed", pkgRoot: pkg }, log: () => {} });
  // the runtime table is private; the regression is worth the reach
  const services = (sup as unknown as { services: Record<string, { def: { cwd: string; args: string[] } }> }).services;
  assert.equal(services["arbiter"]!.def.cwd, pkg);
  assert.equal(services["arbiter"]!.def.args[1], join(pkg, "dist", "arbiter.mjs"));
  assert.equal(services["anthropic-proxy"]!.def.cwd, pkg);
});
