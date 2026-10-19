/**
 * agent-config-delivery.test — the config-routed targets' chokepoint wiring,
 * end to end through the REAL `main()`: one launch per target must
 *   1. write the per-run agent config into the scope run dir,
 *   2. deliver its path to the AGENT process via the target's own env var
 *      (OPENCLAW_CONFIG_PATH / OPENCODE_CONFIG),
 *   3. point the config's provider at the model-context proxy endpoint with
 *      the session header riding along,
 *   4. mount the U-LLM inspect channel in the target's own spelling (plugin
 *      block for OpenClaw, mcp section for OpenCode),
 *   5. deep-merge a user config UNDER the override (their keys survive),
 *   6. NOT leak ANTHROPIC_BASE_URL into the agent env (openclaw's
 *      plugin-mounted quarantine child inherits it — a proxy-pointing value
 *      there would poison the U-LLM channel),
 *   7. keep the user's own OpenClaw anthropic model entries (a model outside
 *      OpenClaw's catalog needs one to run at all), with every per-model
 *      endpoint field stripped so no model can route around the proxy.
 *
 * Real components: arbiter daemon (subprocess), parse → services → env-compose
 * → spawn through the real main(). Mock: the agent (a node script that reports
 * its env + the config file it was pointed at). The context proxy is skipped
 * (MANDU_NO_CONTEXT_PROXY=1, pinned port) — the fake agent never calls the
 * model; the proxy's own wiring is the golden-path test's job.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { spawn, type ChildProcess } from "node:child_process";
import { closeSync, mkdtempSync, mkdirSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { stateAxes } from "../axes.js";
import { stopGroup } from "../lib/tmp-dir.js";
import { sourceArbiterArgs, waitForPaths } from "../lib/arbiter-ready.js";

stateAxes("off"); // this suite states its axes (protection-modes.md §4); the wiring it proves is axis-independent

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..", "..");
const ARBITER_DIR = join(REPO_ROOT, "arbiter");

let tmp: string;
let workspace: string;
let arbiter: ChildProcess;
let passed = 0;

before(async () => {
  // A short prefix: the arbiter's human socket lands at <tmp>/mandu/human/<id>.sock
  // (107-byte sun_path; a suite's TMPDIR is longer than /tmp, test-organization.md §8.5).
  tmp = realpathSync(mkdtempSync(join(tmpdir(), "mdu-acd-")));
  workspace = join(tmp, "workspace");
  mkdirSync(workspace, { recursive: true });

  const logFd = openSync(join(tmp, "arbiter.log"), "a");
  arbiter = spawn(process.execPath, sourceArbiterArgs(join(tmp, "arbiter.sock")), {
    cwd: ARBITER_DIR,
    env: { ...process.env, MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"),
      MANDU_HOME: join(tmp, "mandu-home"),
      MANDU_RUNTIME_DIR: join(tmp, "mandu") },
    stdio: ["ignore", logFd, logFd], detached: true,
  });
  closeSync(logFd);
  await waitForPaths(join(tmp, "arbiter.sock"), { what: "the arbiter", child: arbiter, logPath: join(tmp, "arbiter.log") });
});

after(async () => {
  // Stop the arbiter (its whole group) and wait for it, so nothing writes into
  // tmp after it is removed; on a failure, its log goes to stderr first. The
  // dir is removed either way (test-organization.md §8.5).
  await stopGroup(arbiter);
  if (!tmp) return;
  if (passed !== 3) {
    try {
      const log = readFileSync(join(tmp, "arbiter.log"), "utf8").split("\n").slice(-40).join("\n");
      console.error(`agent-config-delivery: the arbiter's log (last 40 lines):\n${log}`);
    } catch { /* no log */ }
  }
  rmSync(tmp, { recursive: true, force: true });
});

/** The fake agent: report the delivery env var, the config it points at, and
 *  whether a base-URL env leaked in. */
function mintFakeAgent(envVar: string): string {
  const path = join(tmp, `fake-agent-${envVar}.cjs`);
  writeFileSync(path, `
    const fs = require("node:fs");
    const p = process.env[${JSON.stringify(envVar)}];
    fs.writeFileSync(process.argv[2], JSON.stringify({
      configPath: p ?? null,
      config: p ? JSON.parse(fs.readFileSync(p, "utf8")) : null,
      anthropicBaseUrl: process.env.ANTHROPIC_BASE_URL ?? null,
    }));
  `);
  return path;
}

/** Env for main(): hermetic, everything scoped into tmp, all optional rungs off
 *  (this test is about the agent-config delivery seam alone). */
function launchEnv(): Record<string, string | undefined> {
  return {
    HOME: join(tmp, "home"), PATH: process.env["PATH"], PWD: workspace,
    MANDU_HOME: PRIVATE_MANDU_HOME,
    XDG_RUNTIME_DIR: tmp,
    MANDU_ARBITER_SOCK: join(tmp, "arbiter.sock"),
    MANDU_NO_CONTEXT_PROXY: "1",
    MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0",
    MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
  };
}

/** writeAgentConfig reads the USER config via process.env (the same env the
 *  real CLI hands it) — pin it into tmp for the run so the developer's real
 *  ~/.openclaw / ~/.config/opencode never leaks into the test. */
async function withUserConfigEnv(
  pins: Record<string, string>, run: () => Promise<void>,
): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(pins)) { saved[k] = process.env[k]; process.env[k] = v; }
  try { await run(); }
  finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
}

test("openclaw: config written + delivered via OPENCLAW_CONFIG_PATH; user config merged; plugin mounted; no base-URL env", async () => {
  const userCfg = join(tmp, "user-openclaw.json");
  writeFileSync(userCfg, JSON.stringify({
    agents: { defaults: { model: { primary: "anthropic/claude-opus-4-6" } } },
  }));
  const outFile = join(tmp, "openclaw-report.json");
  const agent = mintFakeAgent("OPENCLAW_CONFIG_PATH");

  await withUserConfigEnv({ OPENCLAW_CONFIG_PATH: userCfg }, async () => {
    const code = await main(
      ["--target", "openclaw", "--no-scope", "--", "node", agent, outFile],
      launchEnv(),
    );
    assert.equal(code, 0);
  });

  const got = JSON.parse(readFileSync(outFile, "utf8"));
  assert.ok(got.configPath, "OPENCLAW_CONFIG_PATH reached the agent");
  assert.ok(got.configPath.startsWith(join(tmp, "mandu")), "config lives in the scope run dir");
  // Routing: the built-in provider now points at the proxy endpoint, session id riding.
  const prov = got.config.models.providers.anthropic;
  assert.equal(prov.baseUrl, "http://127.0.0.1:8788");
  assert.equal(prov.api, "anthropic-messages");
  assert.ok(prov.headers["x-mandu-session-id"], "session header present");
  // The user's own config survived UNDER the override.
  assert.equal(got.config.agents.defaults.model.primary, "anthropic/claude-opus-4-6");
  // U-LLM channel: the in-process plugin, lifted past the tools profile.
  assert.ok(String(got.config.plugins.load.paths[0]).endsWith("openclaw-inspect-plugin"));
  assert.equal(got.config.plugins.entries["mandu-inspect"].config.arbiterSock, join(tmp, "arbiter.sock"));
  assert.deepEqual(got.config.tools, { alsoAllow: ["inspect_symbol", "declassify_symbol"] });
  // The one env var that must NOT be there (the plugin quarantine inherits this env).
  assert.equal(got.anthropicBaseUrl, null);
  passed++;
});

test("openclaw: the user's own anthropic model entries survive, and none keeps an endpoint of its own", async () => {
  // OpenClaw 2026.7.1 runs a model outside its catalog (here claude-sonnet-4-5)
  // only when the user lists it with limits; an override that wrote models: []
  // over the list failed every turn "requires a positive maxTokens value"
  // (os-test-matrix.md §10.14.1). A per-model baseUrl wins over the
  // provider's, so it must not survive into the run config.
  const userCfg = join(tmp, "user-openclaw-models.json");
  writeFileSync(userCfg, JSON.stringify({
    agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-5" } } },
    models: { providers: { anthropic: { models: [
      { id: "claude-sonnet-4-5", name: "Claude Sonnet 4.5", maxTokens: 64000, contextWindow: 200000,
        baseUrl: "https://elsewhere.example", api: "openai-completions", headers: { "x-mandu-session-id": "forged" } },
    ] } } },
  }));
  const outFile = join(tmp, "openclaw-models-report.json");
  const agent = mintFakeAgent("OPENCLAW_CONFIG_PATH");
  const stderr: string[] = [];
  const origWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
    stderr.push(String(chunk));
    return (origWrite as (...a: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stderr.write;
  try {
    await withUserConfigEnv({ OPENCLAW_CONFIG_PATH: userCfg }, async () => {
      const code = await main(
        ["--target", "openclaw", "--no-scope", "--", "node", agent, outFile],
        launchEnv(),
      );
      assert.equal(code, 0);
    });
  } finally {
    process.stderr.write = origWrite;
  }

  const prov = JSON.parse(readFileSync(outFile, "utf8")).config.models.providers.anthropic;
  assert.equal(prov.baseUrl, "http://127.0.0.1:8788");
  assert.equal(prov.api, "anthropic-messages");
  assert.deepEqual(prov.models, [
    { id: "claude-sonnet-4-5", name: "Claude Sonnet 4.5", maxTokens: 64000, contextWindow: 200000 },
  ]);
  assert.notEqual(prov.headers["x-mandu-session-id"], "forged");
  // Shown in the default compact display (a WARNING is an attention note), not
  // only in launch.log: the user's own endpoint setting was overridden.
  const said = stderr.join("");
  assert.match(said, /WARNING: ignoring claude-sonnet-4-5\.baseUrl, claude-sonnet-4-5\.api, claude-sonnet-4-5\.headers/);
  passed++;
});

test("opencode: config written + delivered via OPENCODE_CONFIG; built-in provider override; mcp section mounted", async () => {
  const outFile = join(tmp, "opencode-report.json");
  const agent = mintFakeAgent("OPENCODE_CONFIG");

  await withUserConfigEnv({ OPENCODE_CONFIG: join(tmp, "no-user-opencode.json") }, async () => {
    const code = await main(
      ["--target", "opencode", "--no-scope", "--", "node", agent, outFile],
      launchEnv(),
    );
    assert.equal(code, 0);
  });

  const got = JSON.parse(readFileSync(outFile, "utf8"));
  assert.ok(got.configPath, "OPENCODE_CONFIG reached the agent");
  const opts = got.config.provider.anthropic.options;
  assert.equal(opts.baseURL, "http://127.0.0.1:8788/v1");
  assert.ok(opts.headers["x-mandu-session-id"], "session header present");
  // No model forced — the user's own selection keeps working.
  assert.equal(got.config.model, undefined);
  // U-LLM channel: the inspect-mcp server in OpenCode's own config spelling.
  const srv = got.config.mcp["mandu-inspect"];
  assert.equal(srv.type, "local");
  assert.equal(srv.environment.MANDU_ARBITER_SOCK, join(tmp, "arbiter.sock"));
  assert.equal(got.anthropicBaseUrl, null);
  passed++;
});
