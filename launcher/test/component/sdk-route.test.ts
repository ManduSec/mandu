/**
 * sdk-route.test — E2E of the SDK route (docs/design/agents/agent-sdks.md)
 * with stand-in agent CLIs that record what they were started with:
 *   - the preload's hooks in a real Node: every way a host starts a child
 *     (ESM `spawn`, `execFileSync`, `spawnSync`, `exec` with a shell
 *     string) keeps the routing, a `codex` child gets the provider splice,
 *     an unrouted agent CLI throws and never runs;
 *   - the launcher's wiring through main(): `mandu --target codex|claude --
 *     node host.mjs`, whose host starts the stand-in with an `env` that
 *     REPLACES its environment (the SDKs' option), as the SDKs do.
 * The real SDKs and CLIs against a scripted model:
 * agent-sdk.test.ts.
 *
 * PROJECT INVARIANT: an agent CLI a host program starts reaches its model
 * through the launch's proxy, or it does not start.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createServer, type Server } from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { CODEX_UPLOADS_OFF_OVERRIDES } from "../../src/codex-argv.js";
import { SDK_ROUTE_ENV, type SdkRoute } from "../../src/sdk-route.js";
import { stageSdkRoute } from "../lib/sdk-route-stage.js";
import { claudeRouteEnv } from "../../src/claude-route.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

// Axes: stated per launch (MANDU_MODE: "off"); routing is axis-independent.

const PRELOAD = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src", "sdk-route-preload.cjs");

/** A stand-in agent CLI named `name` in `dir`: records argv and env. */
function standIn(dir: string, name: string): { bin: string; record: string } {
  const record = join(dir, `${name}.json`);
  const bin = join(dir, name);
  writeFileSync(
    bin,
    `#!/usr/bin/env node\nconst fs=require("fs");const p=${JSON.stringify(record)};` +
      "const all=fs.existsSync(p)?JSON.parse(fs.readFileSync(p,'utf8')):[];" +
      "all.push({argv:process.argv.slice(2),env:process.env});fs.writeFileSync(p,JSON.stringify(all));\n",
    { mode: 0o755 },
  );
  return { bin, record };
}

interface Run { argv: string[]; env: Record<string, string> }
const runs = (record: string): Run[] => (existsSync(record) ? JSON.parse(readFileSync(record, "utf8")) as Run[] : []);

/** A route as composeSdkRoute builds one; its launch values are those of
 *  its `env` (the launch's delta, nothing inherited) unless given. */
function route(over: Partial<SdkRoute> = {}): SdkRoute {
  const r: Omit<SdkRoute, "launchRouting"> = {
    v: 1, target: "codex",
    env: { MANDU_SCOPE_ID: "sid", HTTPS_PROXY: "http://127.0.0.1:9", MANDU_ARBITER_SOCK: "/nonexistent/arbiter.sock" },
    path: process.env["PATH"] ?? "/usr/bin:/bin", pathPrefix: ["/run/mandu/sid/shims"], require: PRELOAD,
    anthropic: false,
    codex: { provider: "mandu", toml: { OPENAI_API_KEY: '{name="mandu",env_key="OPENAI_API_KEY"}', CODEX_API_KEY: '{name="mandu",env_key="CODEX_API_KEY"}', "sign-in": '{name="mandu",requires_openai_auth=true}' } },
    ...over,
  };
  return { launchRouting: claudeRouteEnv(r.env), ...r };
}

test("preload hooks: ESM spawn, execFileSync, spawnSync and a shell string all keep the routing; codex gets the splice", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-route-"));
  try {
    const codex = standIn(dir, "codex");
    const r = stageSdkRoute(dir, route());
    // The host: each start passes an `env` that REPLACES the child's (no MANDU_*, no proxy).
    const host = [
      'import { spawn, execFileSync, spawnSync, exec } from "node:child_process";',
      `const codex = ${JSON.stringify(codex.bin)};`,
      'const own = { PATH: process.env.PATH, OPENAI_API_KEY: "sk-host" };',
      'await new Promise((res, rej) => { const c = spawn(codex, ["exec", "--experimental-json", "a"], { env: own }); c.on("exit", res); c.on("error", rej); });',
      'execFileSync(codex, ["exec", "b"], { env: own });',
      'spawnSync(codex, ["exec", "c"], { env: { PATH: process.env.PATH } });',
      `await new Promise((res) => exec(${JSON.stringify(`${codex.bin} exec d`)}, { env: own }, res));`,
    ].join("\n");
    const res = spawnSync(process.execPath, ["--input-type=module", "-e", host], {
      env: { PATH: process.env["PATH"], NODE_OPTIONS: `--require=${r.require}`, ...r.env },
      encoding: "utf8", timeout: 30_000,
    });
    assert.equal(res.status, 0, res.stderr);
    const got = runs(codex.record);
    assert.equal(got.length, 4, JSON.stringify(got.map((g) => g.argv)));
    const [a, b, c, d] = got as [Run, Run, Run, Run];
    for (const g of [a, b, c, d]) {
      assert.equal(g.env["MANDU_SCOPE_ID"], "sid", `routing env restored: ${g.argv.join(" ")}`);
      assert.equal(g.env["HTTPS_PROXY"], "http://127.0.0.1:9");
      assert.ok(g.env["PATH"]!.startsWith("/run/mandu/sid/shims:"), "the shims at the head of PATH");
      assert.match(g.env["NODE_OPTIONS"] ?? "", /--require=.*sdk-route-preload\.cjs/);
    }
    for (const g of [a, b, c]) {
      assert.deepEqual(g.argv.slice(0, 4), ["-c", "model_provider=mandu", "-c", g.argv[3]], "the root level");
      assert.equal(g.argv[g.argv.indexOf("exec") + 2], "model_provider=mandu", "the exec level holds the provider too");
      // Codex's own uploads off, at both levels (codex-argv.ts CODEX_UPLOADS_OFF).
      for (const kv of CODEX_UPLOADS_OFF_OVERRIDES.filter((t) => t !== "-c")) {
        assert.equal(g.argv.filter((t) => t === kv).length, 2, `${kv} at the root and the exec level: ${JSON.stringify(g.argv)}`);
      }
    }
    assert.match(a.argv.join(" "), /env_key="OPENAI_API_KEY"/, "the child's own key decides env_key");
    assert.match(c.argv.join(" "), /requires_openai_auth=true/, "no key: the sign-in provider");
    assert.deepEqual(d.argv, ["exec", "d"], "a shell command string is not read (its env is restored; the shell's codex is not spliced)");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("preload hooks: an agent CLI the route does not serve throws, and never runs", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-route-"));
  try {
    const codex = standIn(dir, "codex");
    const claude = standIn(dir, "claude");
    const claudeRoute = stageSdkRoute(dir, route({ target: "claude", anthropic: true, codex: null, env: { ANTHROPIC_BASE_URL: "http://127.0.0.1:8788" } }));
    const host = [
      'const { spawn, execFileSync } = require("node:child_process");',
      `try { spawn(${JSON.stringify(codex.bin)}, ["exec", "x"], { env: {} }); console.log("SPAWNED"); } catch (e) { console.log("REFUSED " + e.code); }`,
      `try { execFileSync(${JSON.stringify(codex.bin)}, ["exec", "x"]); console.log("SPAWNED"); } catch (e) { console.log("REFUSED " + e.code); }`,
      `execFileSync(${JSON.stringify(claude.bin)}, ["-p", "x"], { env: { ANTHROPIC_BASE_URL: "https://api.anthropic.com" } });`,
    ].join("\n");
    const res = spawnSync(process.execPath, ["-e", host], {
      env: { PATH: process.env["PATH"], NODE_OPTIONS: `--require=${claudeRoute.require}`, ...claudeRoute.env },
      encoding: "utf8", timeout: 30_000,
    });
    assert.equal(res.status, 0, res.stderr);
    assert.deepEqual(res.stdout.trim().split("\n"), ["REFUSED MANDU_ROUTE_REFUSED", "REFUSED MANDU_ROUTE_REFUSED"]);
    assert.equal(runs(codex.record).length, 0, "the unrouted codex never ran");
    const [cl] = runs(claude.record) as [Run];
    assert.equal(cl.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "claude keeps the launch's proxy over the host's own base URL");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("preload hooks: attached-equals provider overrides refuse to start a routed codex", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-route-"));
  try {
    const codex = standIn(dir, "codex");
    const overrides = [
      "-c=model_provider=openai",
      '-c=model_providers={x={base_url="https://e"}}',
      '-c=model_providers.x.base_url="https://e"',
    ];
    const host = [
      'const { spawn, execFileSync } = require("node:child_process");',
      `for (const flag of ${JSON.stringify(overrides)}) {`,
      '  for (const start of [spawn, execFileSync]) {',
      `    try { start(${JSON.stringify(codex.bin)}, ["exec", flag, "hi"], { env: {} }); console.log("SPAWNED"); }`,
      '    catch (e) { console.log("REFUSED " + e.code); }',
      '  }',
      '}',
    ].join("\n");
    const res = spawnSync(process.execPath, ["-e", host], {
      env: { PATH: process.env["PATH"], NODE_OPTIONS: `--require=${stageSdkRoute(dir, route()).require}` },
      encoding: "utf8", timeout: 30_000,
    });
    assert.equal(res.status, 0, res.stderr);
    assert.deepEqual(res.stdout.trim().split("\n"), Array(overrides.length * 2).fill("REFUSED MANDU_ROUTE_REFUSED"));
    assert.equal(runs(codex.record).length, 0, "none of the provider overrides started the codex child");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── through the launcher ────────────────────────────────────────────────────

async function withLauncher(fn: (dir: string, env: (extra?: Record<string, string>) => Record<string, string | undefined>) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-route-e2e-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  const env = (extra: Record<string, string> = {}) => ({
    HOME: process.env["HOME"], PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], CODEX_HOME: join(dir, "codex-home"),
    MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", XDG_RUNTIME_DIR: dir, ...extra,
  });
  try { await fn(dir, env); } finally {
    srv.close(); rmSync(dir, { recursive: true, force: true });
  }
}

/** A host program (the SDKs' shape): starts `bin` with an env that REPLACES its own. */
function hostScript(dir: string, bin: string, args: string[]): string {
  const host = join(dir, "host.mjs");
  writeFileSync(host, [
    'import { spawn } from "node:child_process";',
    `const c = spawn(${JSON.stringify(bin)}, ${JSON.stringify(args)}, { env: { PATH: process.env.PATH, OPENAI_API_KEY: "sk-host" }, stdio: "inherit" });`,
    'c.on("exit", (code) => process.exit(code ?? 1));',
    'c.on("error", (e) => { console.error(e.message); process.exit(1); });',
  ].join("\n"));
  return host;
}

test("mandu --target codex -- node host.mjs: the codex the host starts gets the launch's provider splice and routing env (no `node -c`)", async () => {
  await withLauncher(async (dir, env) => {
    const codex = standIn(dir, "codex");
    const host = hostScript(dir, codex.bin, ["exec", "--experimental-json", "--config", 'openai_base_url="https://api.openai.com/v1"', "hi"]);
    const code = await main(["--target", "codex", "--no-scope", "--no-reply-filter", "--", "node", host], env({ OPENAI_API_KEY: "sk-test-only" }));
    assert.equal(code, 0);
    const [g] = runs(codex.record) as [Run];
    assert.ok(g, "the stand-in codex ran");
    const execAt = g.argv.indexOf("exec");
    assert.equal(g.argv[execAt + 2], "model_provider=mandu", `the exec level holds the Mandu provider: ${JSON.stringify(g.argv)}`);
    assert.match(g.argv[execAt + 4]!, /^model_providers\.mandu=\{name="mandu",base_url="http:\/\/127\.0\.0\.1:\d+\/v1",wire_api="responses",env_key="OPENAI_API_KEY"\}$/);
    assert.ok(g.argv.slice(execAt).includes("features.apps=false"), `the exec level turns ChatGPT apps off: ${JSON.stringify(g.argv)}`);
    assert.ok(g.argv.slice(execAt).includes("analytics.enabled=false"), "and Codex's analytics");
    assert.ok(g.env["MANDU_SCOPE_ID"], "the routing env is back though the host replaced it");
    assert.match(g.env["NODE_OPTIONS"] ?? "", /--require=\S*\/sdk-route\/sdk-route-preload\.cjs/, "the launch's own copy of the preload rides on to its children");
    assert.equal(g.env[SDK_ROUTE_ENV], undefined, "the route rides the launch's file, never the environment (agent-sdks.md §3.6)");
    assert.equal(g.env["MANDU_ARBITER_HUMAN_SOCK"], undefined, "never the human-plane socket");
  });
});

test("mandu --target claude -- node host.mjs: the claude the host starts keeps ANTHROPIC_BASE_URL; a codex it starts is refused", async () => {
  await withLauncher(async (dir, env) => {
    const claude = standIn(dir, "claude");
    const code = await main(["--target", "claude", "--no-scope", "--no-reply-filter", "--no-mcp", "--", "node", hostScript(dir, claude.bin, ["-p", "hi"])], env());
    assert.equal(code, 0);
    const [g] = runs(claude.record) as [Run];
    assert.match(g.env["ANTHROPIC_BASE_URL"] ?? "", /^http:\/\/127\.0\.0\.1:\d+$/, "the claude child is routed though the host replaced its env");
    assert.match(g.env["ANTHROPIC_CUSTOM_HEADERS"] ?? "", /x-mandu-session-id: /);
    // …and in its last --settings, so no settings source re-points it (claude-route.ts).
    const at = g.argv.lastIndexOf("--settings");
    assert.ok(at >= 0, `the claude child carries Mandu's --settings: ${JSON.stringify(g.argv)}`);
    const overlay = JSON.parse(g.argv[at + 1]!) as { env: Record<string, string> };
    assert.equal(overlay.env["ANTHROPIC_BASE_URL"], g.env["ANTHROPIC_BASE_URL"], "the overlay carries the launch's own proxy");
    assert.equal(overlay.env["CLAUDE_CODE_USE_BEDROCK"], "0");

    const codex = standIn(dir, "codex");
    const refused = await main(["--target", "claude", "--no-scope", "--no-reply-filter", "--no-mcp", "--", "node", hostScript(dir, codex.bin, ["exec", "hi"])], env());
    assert.notEqual(refused, 0, "the host's codex start failed");
    assert.equal(runs(codex.record).length, 0, "the unrouted codex never ran");
  });
});
