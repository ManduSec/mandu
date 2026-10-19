/**
 * sdk-route-gaps.test — E2E of the SDK route's deliveries beyond the Node
 * preload (docs/design/agents/agent-sdks.md §3, §4), with stand-in agent
 * CLIs that record what they were started with:
 *   - the PATH shims: an agent CLI a shell command string names (`exec("codex
 *     …")`) is routed, or refused, and a shim with no route refuses;
 *   - the shapes the preload now knows: `node cli.js` (Claude Code run as a
 *     script), a renamed CLI speaking the SDKs' command line, one started
 *     through another program (refused);
 *   - the Python hook: a Python host whose `env` overrides
 *     ANTHROPIC_BASE_URL (the Python Claude Agent SDK's merge), asyncio's
 *     subprocesses, the Python Codex SDK's `codex app-server` (refused),
 *     and the parity of its route_env with the preload's routeEnv;
 *   - through main(): `mandu --target claude|codex -- python3 host.py`,
 *     `mandu --target codex -- node host.mjs` with a shell-string codex, and
 *     the launch refusal for a Bun host under --target codex;
 *   - the route's source (agent-sdks.md §3.6, 2026-10-18): the hooks and the
 *     shims read it from the launch's own file beside the preload copy,
 *     never from MANDU_SDK_ROUTE, so a route a host forges there (a shell
 *     string `MANDU_SDK_ROUTE='{…}' claude …`, a Node or Python host
 *     started that way) is ignored, and a copy whose route file is gone
 *     refuses. Red before (the forged base URL reached the claude).
 *
 * PROJECT INVARIANT: an agent CLI a host program starts reaches its model
 * through the launch's proxy, or it does not start.
 */
import { test } from "node:test";
import "../lib/private-home.js"; // daemons' npm cache, the Mandu home and agent trust files go to temp (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { createServer, type Server } from "node:net";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js";
import { SDK_ROUTE_DIR, SDK_ROUTE_ENV, sdkRouteFiles, writeSdkShims, type SdkRoute } from "../../src/sdk-route.js";
import { stageSdkRoute } from "../lib/sdk-route-stage.js";
import { claudeRouteEnv } from "../../src/claude-route.js";
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

// Axes: stated per launch (MANDU_MODE: "off"); routing is axis-independent.

const SRC = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "src");
const PRELOAD = join(SRC, "sdk-route-preload.cjs");
const PYDIR = join(SRC, "sdk-route-python");
const HAVE_PYTHON = spawnSync("python3", ["-c", "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"]).status === 0;
const preload = createRequire(import.meta.url)(PRELOAD) as {
  routeEnv(route: SdkRoute, env: Record<string, string | undefined>): Record<string, string>;
};

/** A stand-in agent CLI named `name` in `dir`: records argv and env. Its
 *  interpreter is this test's own Node by absolute path: several legs give
 *  the child a PATH of /usr/bin:/bin only, where a CI image may have no
 *  `node` (the shims themselves run the launcher's Node by absolute path). */
function standIn(dir: string, name: string): { bin: string; record: string } {
  mkdirSync(dir, { recursive: true });
  const record = join(dir, `${name}.json`);
  const bin = join(dir, name);
  writeFileSync(
    bin,
    `#!${process.execPath}\nconst fs=require("fs");const p=${JSON.stringify(record)};` +
      "const all=fs.existsSync(p)?JSON.parse(fs.readFileSync(p,'utf8')):[];" +
      "all.push({argv:process.argv.slice(2),env:process.env});fs.writeFileSync(p,JSON.stringify(all));\n",
    { mode: 0o755 },
  );
  return { bin, record };
}

interface Run { argv: string[]; env: Record<string, string> }
const runs = (record: string): Run[] => (existsSync(record) ? JSON.parse(readFileSync(record, "utf8")) as Run[] : []);

const CODEX_ROUTE = {
  provider: "mandu",
  toml: { OPENAI_API_KEY: '{name="mandu",env_key="OPENAI_API_KEY"}', CODEX_API_KEY: '{name="mandu",env_key="CODEX_API_KEY"}', "sign-in": '{name="mandu",requires_openai_auth=true}' },
};

/** A route as composeSdkRoute builds one; its launch values are those of
 *  its `env` (the launch's delta, nothing inherited) unless given. */
function route(shimDir: string, over: Partial<SdkRoute> = {}): SdkRoute {
  const r: Omit<SdkRoute, "launchRouting"> = {
    v: 1, target: "claude",
    env: { MANDU_SCOPE_ID: "sid", HTTPS_PROXY: "http://127.0.0.1:9", ANTHROPIC_BASE_URL: "http://127.0.0.1:8788" },
    path: process.env["PATH"] ?? "/usr/bin:/bin", pathPrefix: [shimDir], require: PRELOAD,
    pythonPath: PYDIR, node: process.execPath,
    anthropic: true, codex: null,
    ...over,
  };
  return { launchRouting: claudeRouteEnv(r.env), ...r };
}

/** The env a host gets from the launch for `r`, a route staged as the
 *  launch writes it (stage): the variables the launcher sets, never the
 *  route itself. */
function hostEnv(r: SdkRoute, extra: Record<string, string> = {}): Record<string, string | undefined> {
  return {
    PATH: `${r.pathPrefix[0]}:${process.env["PATH"]}`, HOME: process.env["HOME"],
    NODE_OPTIONS: `--require=${r.require}`, PYTHONPATH: r.pythonPath ?? PYDIR, ...r.env, ...extra,
  };
}

/** `<dir>/sdk-route/`'s preload copy: what the shims of a launch in `dir` name. */
const stagedPreload = (dir: string): string => sdkRouteFiles(join(dir, SDK_ROUTE_DIR)).preload;

// ── the PATH shims ──────────────────────────────────────────────────────────

test("PATH shims: a codex a shell command string names is routed (codex route) or refused (claude route); a shim with no route refuses", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-"));
  try {
    const shims = join(dir, "sdk-shims");
    writeSdkShims(shims, process.execPath, stagedPreload(dir));
    const bin = join(dir, "bin");
    const codex = standIn(bin, "codex");
    const host = (route0: SdkRoute, r = stageSdkRoute(dir, route0)) => spawnSync(process.execPath, ["-e", [
      'const { exec } = require("node:child_process");',
      // The host replaces the child's environment and names codex by name
      // only, with a PATH that holds no `node`: the shim must not need one.
      `exec("codex exec --experimental-json hi", { env: { PATH: ${JSON.stringify(bin)} } }, (e, out, err) => { process.stdout.write(String(e ? e.code : 0)); process.stderr.write(err); });`,
    ].join("\n")], { env: hostEnv(r), encoding: "utf8", timeout: 30_000 });

    const routed = host(route(shims, { target: "codex", anthropic: false, codex: CODEX_ROUTE, env: { MANDU_SCOPE_ID: "sid" } }));
    assert.equal(routed.stdout, "0", routed.stderr);
    const [g] = runs(codex.record) as [Run];
    assert.ok(g, "the real codex ran, behind the shim");
    assert.deepEqual(g.argv.slice(0, 2), ["-c", "model_provider=mandu"], `the shim spliced the provider: ${JSON.stringify(g.argv)}`);
    assert.equal(g.argv[g.argv.indexOf("exec") + 2], "model_provider=mandu", "at the exec level too");
    assert.equal(g.env["MANDU_SCOPE_ID"], "sid", "the routing env is back");

    rmSync(codex.record, { force: true });
    const refused = host(route(shims));
    assert.equal(refused.stdout, "126", "the shim refused the codex a claude launch does not route");
    assert.match(refused.stderr, /refusing to start .*codex: this launch does not route Codex/);
    assert.equal(runs(codex.record).length, 0, "the unrouted codex never ran");

    // The route file gone (a shim whose launch wrote none): refused, a
    // route in the environment notwithstanding (it is never read).
    stageSdkRoute(dir, route(shims, { target: "codex", anthropic: false, codex: CODEX_ROUTE }));
    rmSync(join(dir, SDK_ROUTE_DIR, "route.json"));
    const forged = JSON.stringify(route(shims, { target: "codex", anthropic: false, codex: CODEX_ROUTE }));
    const bare = spawnSync(join(shims, "codex"), ["exec", "hi"], { env: { PATH: `${shims}:${bin}`, [SDK_ROUTE_ENV]: forged }, encoding: "utf8" });
    assert.equal(bare.status, 126);
    assert.match(bare.stderr, /finds no route/);
    assert.equal(runs(codex.record).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("PATH shims: a claude found by name gets the routing in its --settings and the launch's base URL, over the host's own", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-"));
  try {
    const shims = join(dir, "sdk-shims");
    writeSdkShims(shims, process.execPath, stagedPreload(dir));
    const claude = standIn(join(dir, "bin"), "claude");
    const r = stageSdkRoute(dir, route(shims));
    const res = spawnSync("/bin/sh", ["-c", "claude -p hi"], {
      env: { ...hostEnv(r), PATH: `${shims}:${join(dir, "bin")}`, ANTHROPIC_BASE_URL: "https://api.anthropic.com" },
      encoding: "utf8", timeout: 30_000,
    });
    assert.equal(res.status, 0, res.stderr);
    const [g] = runs(claude.record) as [Run];
    assert.equal(g.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
    const at = g.argv.indexOf("--settings");
    assert.equal((JSON.parse(g.argv[at + 1]!) as { env: Record<string, string> }).env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── shapes the preload now knows ────────────────────────────────────────────

test("preload: `node cli.js` (Claude Code as a script), a renamed CLI on the SDKs' command line, and a CLI through another program", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-"));
  try {
    // A Claude Code npm package whose cli.js records how it was started.
    const pkg = join(dir, "node_modules", "@anthropic-ai", "claude-code");
    const cli = standIn(pkg, "cli.js");
    writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "@anthropic-ai/claude-code" }));
    const renamed = standIn(join(dir, "bin"), "my-agent");
    const docker = standIn(join(dir, "bin"), "docker");
    const SDK = ["--output-format", "stream-json", "--verbose", "--input-format", "stream-json"];
    const r = stageSdkRoute(dir, route(join(dir, "no-shims")));
    const host = [
      'const { spawn, execFileSync } = require("node:child_process");',
      'const own = { PATH: process.env.PATH, ANTHROPIC_BASE_URL: "https://api.anthropic.com" };',
      `execFileSync(process.execPath, ["--no-warnings", ${JSON.stringify(cli.bin)}, ...${JSON.stringify(SDK)}], { env: own });`,
      `execFileSync(${JSON.stringify(renamed.bin)}, ${JSON.stringify(SDK)}, { env: own });`,
      `try { spawn(${JSON.stringify(docker.bin)}, ["exec", "-i", "ctr", "claude", ...${JSON.stringify(SDK)}]); console.log("SPAWNED"); } catch (e) { console.log("REFUSED " + e.code); }`,
    ].join("\n");
    const res = spawnSync(process.execPath, ["-e", host], { env: hostEnv(r), encoding: "utf8", timeout: 30_000 });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout.trim(), "REFUSED MANDU_ROUTE_REFUSED", "the CLI started through docker is refused");
    assert.equal(runs(docker.record).length, 0, "docker never ran");
    for (const rec of [cli.record, renamed.record]) {
      const [g] = runs(rec) as [Run];
      assert.ok(g, rec);
      assert.equal(g.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "the launch's proxy over the host's own base URL");
      const at = g.argv.indexOf("--settings");
      assert.ok(at >= 0, `the routing rides --settings: ${JSON.stringify(g.argv)}`);
      assert.equal((JSON.parse(g.argv[at + 1]!) as { env: Record<string, string> }).env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788");
      assert.ok(g.argv.includes("--input-format"), "the SDK's own arguments stay");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── the Python hook ─────────────────────────────────────────────────────────

const pyTest = HAVE_PYTHON ? test : test.skip;

pyTest("Python hook: an `env` override of ANTHROPIC_BASE_URL is undone, asyncio children are routed, `codex app-server` and an unrouted codex refuse", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-"));
  try {
    const shims = join(dir, "sdk-shims");
    writeSdkShims(shims, process.execPath, stagedPreload(dir));
    const claude = standIn(join(dir, "bin"), "claude");
    const codex = standIn(join(dir, "bin"), "codex");
    const host = join(dir, "host.py");
    writeFileSync(host, [
      "import asyncio, os, subprocess, sys",
      "claude, codex, bindir = sys.argv[1], sys.argv[2], sys.argv[3]",
      "SDK = ['--output-format', 'stream-json', '--verbose', '--input-format', 'stream-json']",
      // The Python Claude Agent SDK: os.environ merged with the `env` option.
      "subprocess.run([claude] + SDK, env={**os.environ, 'ANTHROPIC_BASE_URL': 'https://api.anthropic.com'}, check=True)",
      // anyio / asyncio start through Popen too.
      "async def go():",
      "    p = await asyncio.create_subprocess_exec(claude, '-p', 'hi', env={'PATH': os.environ['PATH']})",
      "    await p.wait()",
      "asyncio.run(go())",
      "for argv in ([codex, 'app-server', '--listen', 'stdio://'], [codex, 'exec', 'hi']):",
      "    try:",
      "        subprocess.Popen(argv); print('SPAWNED')",
      "    except PermissionError as e:",
      "        print('REFUSED', type(e).__name__, str(e)[:200].replace(chr(10), ' '))",
      // A shell string naming codex: the shim refuses it under this claude route.
      "r = subprocess.run('codex exec hi', shell=True, env={'PATH': bindir + ':/usr/bin:/bin'}, stderr=subprocess.DEVNULL)",
      "print('SHELL', r.returncode)",
      // A plain child: its environment only.
      "out = subprocess.run(['/usr/bin/env'], env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True).stdout",
      "print('PLAIN', 'MANDU_SCOPE_ID=sid' in out.splitlines())",
    ].join("\n"));
    const r = stageSdkRoute(dir, route(shims, { target: "claude" }));
    const res = spawnSync("python3", [host, claude.bin, codex.bin, join(dir, "bin")], { env: hostEnv(r), encoding: "utf8", timeout: 60_000 });
    assert.equal(res.status, 0, res.stderr);
    const lines = res.stdout.trim().split("\n");
    assert.match(lines[0]!, /^REFUSED ManduRouteRefused .*does not route Codex/, "a codex under a claude launch, even app-server");
    assert.match(lines[1]!, /^REFUSED ManduRouteRefused .*does not route Codex/);
    assert.deepEqual(lines.slice(2), ["SHELL 126", "PLAIN True"]);
    assert.equal(runs(codex.record).length, 0, "no codex ran");
    const [sdk, asyncChild] = runs(claude.record) as [Run, Run];
    for (const g of [sdk, asyncChild]) {
      assert.equal(g.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "the launch's proxy, over the SDK's env option");
      assert.equal(g.env["MANDU_SCOPE_ID"], "sid");
      assert.ok(g.env["PATH"]!.startsWith(`${shims}:`), "the shims lead PATH");
      assert.equal(g.env["PYTHONPATH"]!.split(":")[0], r.pythonPath, "the hook rides on");
      assert.match(g.env["NODE_OPTIONS"] ?? "", /sdk-route-preload\.cjs/);
      const at = g.argv.indexOf("--settings");
      assert.ok(at >= 0, `the routing rides --settings: ${JSON.stringify(g.argv)}`);
    }
    assert.ok(sdk.argv.includes("--input-format"), "the SDK's own arguments stay");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

pyTest("Python hook: under a codex route, `codex exec` gets the provider splice and the Python Codex SDK's `app-server` refuses with its reason", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-"));
  try {
    const codex = standIn(join(dir, "bin"), "codex");
    const host = join(dir, "host.py");
    writeFileSync(host, [
      "import subprocess, sys",
      "codex = sys.argv[1]",
      "subprocess.run([codex, 'exec', '--experimental-json', 'hi'], env={'PATH': '/usr/bin:/bin', 'OPENAI_API_KEY': 'k'}, check=True)",
      "try:",
      "    subprocess.Popen([codex, '--config', 'x=1', 'app-server', '--listen', 'stdio://']); print('SPAWNED')",
      "except PermissionError as e:",
      "    print('REFUSED', str(e).replace(chr(10), ' '))",
    ].join("\n"));
    const r = stageSdkRoute(dir, route(join(dir, "no-shims"), { target: "codex", anthropic: false, codex: CODEX_ROUTE, env: { MANDU_SCOPE_ID: "sid" } }));
    const res = spawnSync("python3", [host, codex.bin], { env: hostEnv(r), encoding: "utf8", timeout: 60_000 });
    assert.equal(res.status, 0, res.stderr);
    assert.match(res.stdout, /REFUSED .*Python Codex SDK\) takes its threads' provider/);
    const got = runs(codex.record);
    assert.equal(got.length, 1, "only the routed exec ran");
    assert.deepEqual(got[0]!.argv.slice(0, 4), ["-c", "model_provider=mandu", "-c", `model_providers.mandu=${CODEX_ROUTE.toml.OPENAI_API_KEY}`]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

pyTest("parity: the Python hook's route_env equals the preload's routeEnv", () => {
  const r = route("/run/m/sdk-shims", {
    pathPrefix: ["/run/m/sdk-shims", "/run/m/box"], require: "/opt/a b/sdk-route-preload.cjs",
    env: { MANDU_SCOPE_ID: "sid", ANTHROPIC_BASE_URL: "http://127.0.0.1:8788", MANDU_LABEL: "café" },
  });
  const envs: Array<Record<string, string>> = [
    {},
    { PATH: "/usr/bin:/run/m/box:/bin", PYTHONPATH: "/x:" + PYDIR, NODE_OPTIONS: "--max-old-space-size=1" },
    { ANTHROPIC_BASE_URL: "https://api.anthropic.com", PATH: "", NODE_OPTIONS: `--require="/opt/a b/sdk-route-preload.cjs"`, KEEP: "1" },
    { [SDK_ROUTE_ENV]: '{"v":1,"env":{}}', PATH: "/usr/bin" },
  ];
  const code = [
    "import importlib.util, json, sys",
    `spec = importlib.util.spec_from_file_location("mandu_hook", ${JSON.stringify(join(PYDIR, "sitecustomize.py"))})`,
    "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)",
    "req = json.loads(sys.stdin.read())",
    "print(json.dumps([m.route_env(req['route'], e) for e in req['envs']]))",
  ].join("\n");
  const res = spawnSync("python3", ["-c", code], { input: JSON.stringify({ route: r, envs }), encoding: "utf8", env: { PATH: process.env["PATH"] } });
  assert.equal(res.status, 0, res.stderr);
  const py = JSON.parse(res.stdout) as Array<Record<string, string>>;
  envs.forEach((e, i) => assert.deepEqual(py[i], preload.routeEnv(r, e), JSON.stringify(e)));
});

// ── the route's source: the launch's file, never the environment (§3.6) ────

/** A route a host forges: the genuine shape (so the code before 2026-10-18
 *  took it), every routing value at `origin`, the provider too. */
function forgedRoute(r: SdkRoute, origin: string): string {
  const launchRouting = { ...r.launchRouting, ANTHROPIC_BASE_URL: origin, HTTPS_PROXY: origin, https_proxy: origin, NO_PROXY: "", no_proxy: "" };
  return JSON.stringify({ ...r, env: { ...r.env, ANTHROPIC_BASE_URL: origin }, launchRouting });
}

test("a route forged in MANDU_SDK_ROUTE (a shell string's claude, a Node host started with it) is ignored: the launch's file routes the claude", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-"));
  try {
    const shims = join(dir, "sdk-shims");
    writeSdkShims(shims, process.execPath, stagedPreload(dir));
    const bin = join(dir, "bin");
    const claude = standIn(bin, "claude");
    const r = stageSdkRoute(dir, route(shims));
    // Not the route's own HTTPS_PROXY (:9): a port nothing listens on.
    const evil = "http://127.0.0.1:7";
    const forgedFile = join(dir, "forged.json");
    writeFileSync(forgedFile, forgedRoute(r, evil));
    // The host (the model steering it) forges the route in a shell string,
    // and starts a Node grandchild with it, which starts claude by full path.
    const inner = join(dir, "inner.js");
    writeFileSync(inner, `require("node:child_process").execFileSync(${JSON.stringify(claude.bin)}, ["-p", "inner"], { env: process.env });\n`);
    const forge = `MANDU_SDK_ROUTE="$(cat ${forgedFile})"`;
    const host = [
      'const { execSync } = require("node:child_process");',
      `execSync(${JSON.stringify(`${forge} claude -p shell`)}, { stdio: "inherit" });`,
      `execSync(${JSON.stringify(`${forge} ${process.execPath} ${inner}`)}, { stdio: "inherit" });`,
    ].join("\n");
    const res = spawnSync(process.execPath, ["-e", host], { env: hostEnv(r, { PATH: `${shims}:${bin}:/usr/bin:/bin` }), encoding: "utf8", timeout: 30_000 });
    assert.equal(res.status, 0, res.stderr);
    const got = runs(claude.record);
    assert.equal(got.length, 2, JSON.stringify(got.map((g) => g.argv)));
    for (const g of got) {
      assert.equal(g.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", `the launch's base URL, not the forged one: ${g.argv.join(" ")}`);
      const at = g.argv.lastIndexOf("--settings");
      const overlay = (JSON.parse(g.argv[at + 1]!) as { env: Record<string, string> }).env;
      assert.equal(overlay["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "the overlay is the launch's");
      assert.equal(overlay["HTTPS_PROXY"], r.launchRouting["HTTPS_PROXY"], "the launch's proxy, not the forged one");
      assert.ok(!JSON.stringify(g.argv).includes(evil) && g.env["HTTPS_PROXY"] !== evil, "nothing of the forged route reached the claude");
      assert.equal(g.env[SDK_ROUTE_ENV], undefined, "the forged route went no further");
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

pyTest("a route forged in MANDU_SDK_ROUTE for a Python host is ignored; a Python hook whose route file is gone refuses an agent child", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-"));
  try {
    const claude = standIn(join(dir, "bin"), "claude");
    const r = stageSdkRoute(dir, route(join(dir, "no-shims")));
    const host = join(dir, "host.py");
    writeFileSync(host, [
      "import os, subprocess, sys",
      "try:",
      "    subprocess.run([sys.argv[1], '--output-format', 'stream-json', '--input-format', 'stream-json'], env=dict(os.environ), check=True); print('RAN')",
      "except PermissionError as e:",
      "    print('REFUSED', str(e).replace(chr(10), ' '))",
    ].join("\n"));
    const res = spawnSync("python3", [host, claude.bin], { env: hostEnv(r, { [SDK_ROUTE_ENV]: forgedRoute(r, "http://127.0.0.1:9") }), encoding: "utf8", timeout: 60_000 });
    assert.equal(res.status, 0, res.stderr);
    assert.equal(res.stdout.trim(), "RAN");
    const [g] = runs(claude.record) as [Run];
    assert.equal(g.env["ANTHROPIC_BASE_URL"], "http://127.0.0.1:8788", "the launch's base URL, not the forged one");
    assert.equal(g.env[SDK_ROUTE_ENV], undefined);

    // The route file gone: the hook refuses the agent child.
    rmSync(join(dir, SDK_ROUTE_DIR, "route.json"));
    const gone = spawnSync("python3", [host, claude.bin], { env: hostEnv(r, { [SDK_ROUTE_ENV]: JSON.stringify(r) }), encoding: "utf8", timeout: 60_000 });
    assert.equal(gone.status, 0, gone.stderr);
    assert.match(gone.stdout, /^REFUSED .*route file is missing or unreadable/);
    assert.equal(runs(claude.record).length, 1, "the claude did not start again");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a Node host whose route file is gone refuses its agent children, a route in MANDU_SDK_ROUTE notwithstanding; other children start", () => {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-"));
  try {
    const claude = standIn(join(dir, "bin"), "claude");
    const r = stageSdkRoute(dir, route(join(dir, "no-shims")));
    rmSync(join(dir, SDK_ROUTE_DIR, "route.json"));
    const host = [
      'const { execFileSync } = require("node:child_process");',
      `try { execFileSync(${JSON.stringify(claude.bin)}, ["-p", "x"]); console.log("RAN"); } catch (e) { console.log("REFUSED " + e.code); }`,
      'console.log(execFileSync("/bin/echo", ["plain"], { encoding: "utf8" }).trim());',
    ].join("\n");
    const res = spawnSync(process.execPath, ["-e", host], { env: hostEnv(r, { [SDK_ROUTE_ENV]: JSON.stringify(r) }), encoding: "utf8", timeout: 30_000 });
    assert.equal(res.status, 0, res.stderr);
    assert.deepEqual(res.stdout.trim().split("\n"), ["REFUSED MANDU_ROUTE_REFUSED", "plain"]);
    assert.equal(runs(claude.record).length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── through the launcher ────────────────────────────────────────────────────

async function withLauncher(fn: (dir: string, env: (extra?: Record<string, string>) => Record<string, string | undefined>) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-sdk-gaps-e2e-"));
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

const LAUNCH = ["--no-scope", "--no-reply-filter"];

pyTest("mandu --target claude -- python3 host.py: the claude the Python host starts with its own ANTHROPIC_BASE_URL is routed anyway", async () => {
  await withLauncher(async (dir, env) => {
    const claude = standIn(join(dir, "bin"), "claude");
    const host = join(dir, "host.py");
    writeFileSync(host, [
      "import os, subprocess, sys",
      `subprocess.run([${JSON.stringify(claude.bin)}, '--output-format', 'stream-json', '--input-format', 'stream-json'],`,
      "               env={**os.environ, 'ANTHROPIC_BASE_URL': 'https://api.anthropic.com'}, check=True)",
    ].join("\n"));
    const code = await main(["--target", "claude", ...LAUNCH, "--no-mcp", "--", "python3", host], env());
    assert.equal(code, 0);
    const [g] = runs(claude.record) as [Run];
    assert.ok(g, "the stand-in claude ran");
    assert.match(g.env["ANTHROPIC_BASE_URL"] ?? "", /^http:\/\/127\.0\.0\.1:\d+$/, "the launch's proxy, over the host's vendor URL");
    const at = g.argv.indexOf("--settings");
    assert.equal((JSON.parse(g.argv[at + 1]!) as { env: Record<string, string> }).env["ANTHROPIC_BASE_URL"], g.env["ANTHROPIC_BASE_URL"]);
    assert.equal(g.env["MANDU_ARBITER_HUMAN_SOCK"], undefined, "never the human-plane socket");
  });
});

pyTest("mandu --target codex -- python3 host.py: the Python Codex SDK's `codex app-server` refuses to start (it would run unrouted)", async () => {
  await withLauncher(async (dir, env) => {
    const codex = standIn(join(dir, "bin"), "codex");
    const host = join(dir, "host.py");
    writeFileSync(host, `import subprocess\nsubprocess.Popen([${JSON.stringify(codex.bin)}, 'app-server', '--listen', 'stdio://']).wait()\n`);
    const code = await main(["--target", "codex", ...LAUNCH, "--", "python3", host], env({ OPENAI_API_KEY: "sk-test-only" }));
    assert.notEqual(code, 0, "the host's start raised");
    assert.equal(runs(codex.record).length, 0, "the unrouted app-server never ran");
  });
});

test("mandu --target codex -- node host.mjs: a codex the host names in a shell command string is routed by the PATH shim", async () => {
  await withLauncher(async (dir, env) => {
    const bin = join(dir, "bin");
    const codex = standIn(bin, "codex");
    const host = join(dir, "host.mjs");
    writeFileSync(host, [
      'import { execSync } from "node:child_process";',
      `execSync("codex exec --experimental-json hi", { env: { PATH: ${JSON.stringify(bin)} + ":" + process.env.PATH, OPENAI_API_KEY: "sk-host" }, stdio: "inherit" });`,
    ].join("\n"));
    const code = await main(["--target", "codex", ...LAUNCH, "--", "node", host], env({ OPENAI_API_KEY: "sk-test-only" }));
    assert.equal(code, 0);
    const [g] = runs(codex.record) as [Run];
    assert.ok(g, "the stand-in codex ran");
    const execAt = g.argv.indexOf("exec");
    assert.equal(g.argv[execAt + 2], "model_provider=mandu", `the shim spliced the launch's provider: ${JSON.stringify(g.argv)}`);
    assert.match(g.argv[execAt + 4]!, /^model_providers\.mandu=\{name="mandu",base_url="http:\/\/127\.0\.0\.1:\d+\/v1"/);
  });
});

test("mandu --target codex -- node host.mjs: a proxy the host hands its codex (HTTPS_PROXY, HTTP_PROXY, ALL_PROXY, NO_PROXY) gives way to the launch's", async () => {
  await withLauncher(async (dir, env) => {
    const bin = join(dir, "bin");
    const codex = standIn(bin, "codex");
    const host = join(dir, "host.mjs");
    const own = { HTTPS_PROXY: "http://127.0.0.1:9", HTTP_PROXY: "http://127.0.0.1:9", ALL_PROXY: "socks5://127.0.0.1:9", all_proxy: "socks5://127.0.0.1:9", NO_PROXY: "*" };
    writeFileSync(host, [
      'import { spawnSync } from "node:child_process";',
      `spawnSync(${JSON.stringify(codex.bin)}, ["exec", "--experimental-json", "hi"], { env: { ...process.env, ...${JSON.stringify(own)} }, stdio: "inherit" });`,
    ].join("\n"));
    const code = await main(["--target", "codex", ...LAUNCH, "--no-net-proxy", "--", "node", host], env({ OPENAI_API_KEY: "sk-test-only" }));
    assert.equal(code, 0);
    const [g] = runs(codex.record) as [Run];
    assert.ok(g, "the stand-in codex ran");
    assert.ok(g.argv.includes("model_provider=mandu"), "spliced");
    for (const k of Object.keys(own)) assert.equal(g.env[k], undefined, `${k}: the launch sets none, so the host's is removed`);
  });
});

test("mandu --target codex -- bun app.js: refused before anything starts (Bun loads neither SDK hook)", async () => {
  await withLauncher(async (dir, env) => {
    const errs: string[] = [];
    const orig = console.error;
    console.error = (...a: unknown[]) => { errs.push(a.map(String).join(" ")); };
    let code: number;
    try {
      code = await main(["--target", "codex", ...LAUNCH, "--", "bun", join(dir, "app.js")], env({ OPENAI_API_KEY: "sk-test-only" }));
    } catch (e) {
      errs.push(String(e)); code = 1;
    } finally {
      console.error = orig;
    }
    assert.notEqual(code, 0);
    assert.match(errs.join("\n"), /refusing to launch: 'bun' loads neither of Mandu's SDK hooks/);
  });
});
