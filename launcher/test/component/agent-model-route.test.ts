/**
 * agent-model-route.test — E2E: `mandu openclaw …` / `mandu opencode …`
 * through main(), with stand-in binaries NAMED `openclaw` / `opencode` that
 * record that they ran and what routing they were handed. Pins the fix for
 * the non-Anthropic model bypass (src/agent-model-route.ts): the routing
 * override points only the agent's anthropic provider at the proxy, so a
 * model from any other provider (OpenClaw's own default is openai/gpt-5.5 on
 * 2026.6+) went straight to that provider with tool results unmasked
 * (probe-verified 2026-09-27 on OpenClaw 2026.7.1 and OpenCode 1.18.13).
 *   - a model from a provider Mandu does not route, in the config or on
 *     argv, is REFUSED: the agent never starts and the stand-in upstream
 *     sees nothing;
 *   - an anthropic model launches, with the runtime fences in place
 *     (OpenClaw's model allowlist, OpenCode's enabled_providers delivered in
 *     OPENCODE_CONFIG_CONTENT, which outranks a project config);
 *   - an OpenAI-family model (openai/…, a declared OpenAI-compatible
 *     provider) launches ROUTED (2026-09-28): the run config points that
 *     provider at the proxy's /_mandu/openai/<id> prefix and the fences admit
 *     it; OpenCode signed in to OpenAI with a ChatGPT account is refused;
 *   - OpenClaw's `tools.exec.host: "node"` is dropped from the run config.
 *
 * PROJECT INVARIANT: the model traffic of a routed agent goes through the
 * context proxy, or the launch does not happen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { createServer, type Server } from "node:net";
import { createServer as createHttpServer } from "node:http";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

// Axes: stated per launch (MANDU_MODE: "off": confidentiality off, so the
// stand-in socket needs no secret discovery); routing is axis-independent.

interface Rig { dir: string; sock: string; upstream: string; hits: () => number }

async function withRig(fn: (r: Rig) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "mandu-model-route-"));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  // A counting stand-in upstream: a refused launch must never reach it.
  let n = 0;
  const up = createHttpServer((req, res) => { n++; req.resume(); res.writeHead(500); res.end(); });
  up.listen(0, "127.0.0.1");
  await once(up, "listening");
  const upstream = `http://127.0.0.1:${(up.address() as AddressInfo).port}`;
  try { await fn({ dir, sock, upstream, hits: () => n }); } finally {
    srv.close(); up.close(); rmSync(dir, { recursive: true, force: true });
  }
}

/** A stand-in agent binary named `name` that records its argv, the config
 *  file it was pointed at, and OPENCODE_CONFIG_CONTENT. `opencode` answers
 *  the launch's version probe (run before the model check) as the tested
 *  release: one whose version cannot be read is refused
 *  (agent-versions.ts opencodeLaunchRefusal). */
function standIn(dir: string, name: "openclaw" | "opencode", envVar: string): { bin: string; report: string } {
  const bin = join(dir, name);
  const report = join(dir, `${name}-report.json`);
  writeFileSync(bin, `#!/usr/bin/env node
${name === "opencode" ? 'if (process.argv[2] === "--version") { console.log("1.18.13"); process.exit(0); }\n' : ""}const fs = require("fs"); const p = process.env[${JSON.stringify(envVar)}];
fs.writeFileSync(${JSON.stringify(report)}, JSON.stringify({ argv: process.argv.slice(2),
  config: p ? JSON.parse(fs.readFileSync(p, "utf8")) : null,
  content: process.env.OPENCODE_CONFIG_CONTENT ?? null }));
`, { mode: 0o755 });
  return { bin, report };
}

const env = (r: Rig, extra: Record<string, string> = {}) => ({
  HOME: r.dir, PWD: r.dir, MANDU_ARBITER_SOCK: r.sock, PATH: process.env["PATH"], XDG_RUNTIME_DIR: r.dir,
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_UPSTREAM: r.upstream,
  MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
  ...extra,
});

/** The launcher reads the agent's own config via process.env (as the real
 *  CLI does): pin it for the run. */
async function withProcessEnv(pins: Record<string, string>, run: () => Promise<void>): Promise<void> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(pins)) { saved[k] = process.env[k]; process.env[k] = v; }
  try { await run(); } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

async function expectRefused(run: () => Promise<number>, re: RegExp): Promise<void> {
  let err: unknown; let code: number | undefined;
  try { code = await run(); } catch (e) { err = e; }
  assert.ok(err !== undefined, `refused (got exit ${String(code)})`);
  assert.match(String(err), re);
}

test("openclaw: an unrouted model in the config, on --model, or none at all is REFUSED; nothing starts", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "openclaw", "OPENCLAW_CONFIG_PATH");
    const cfg = join(r.dir, "openclaw.json");
    const launch = () => main(["--target", "openclaw", "--no-scope", "--", bin, "agent", "--local", "-m", "hi"], env(r));
    const launchModel = (m: string) => main(["--target", "openclaw", "--no-scope", "--", bin, "agent", "--local", "--model", m, "-m", "hi"], env(r));

    writeFileSync(cfg, JSON.stringify({ agents: { defaults: { model: { primary: "deepseek/deepseek-chat" } } } }));
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, () =>
      expectRefused(launch, /refusing to launch openclaw with model deepseek\/deepseek-chat \(agents\.defaults\.model\.primary\): Mandu routes an OpenAI-compatible provider only when models\.providers\.deepseek names its baseUrl and api/));

    writeFileSync(cfg, JSON.stringify({ agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6", fallbacks: ["google/gemini-3.1-pro"] } } } }));
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, () =>
      expectRefused(launch, /google\/gemini-3\.1-pro \(agents\.defaults\.model\.fallbacks\[0\]\)/));

    writeFileSync(cfg, JSON.stringify({ agents: { defaults: { model: { primary: "anthropic/claude-sonnet-4-6" } } } }));
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, () =>
      expectRefused(() => launchModel("xai/grok-5"), /xai\/grok-5 \(--model\)/));

    await withProcessEnv({ OPENCLAW_CONFIG_PATH: join(r.dir, "absent.json") }, () =>
      expectRefused(launch, /refusing to launch openclaw with no model configured/));

    // JSON5, as OpenClaw writes it: read, and its unrouted model refused by name.
    writeFileSync(cfg, "// hand-edited\n{ agents: { defaults: { model: { primary: 'google/gemini-3.1-pro', }, }, }, }\n");
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, () =>
      expectRefused(launch, /google\/gemini-3\.1-pro \(agents\.defaults\.model\.primary\)/));

    writeFileSync(cfg, "{ // not even JSON5\n agents: {");
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, () => expectRefused(launch, /could not read/));

    // A split config: the included file is read as OpenClaw reads it, so its
    // unrouted model is refused by name, and an include OpenClaw would refuse
    // (a missing file, one outside the config directory) is refused too.
    writeFileSync(join(r.dir, "agents.json5"), "{ defaults: { model: 'google/gemini-3.1-pro' } }");
    writeFileSync(cfg, JSON.stringify({ agents: { $include: "./agents.json5" } }));
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, () =>
      expectRefused(launch, /google\/gemini-3\.1-pro \(agents\.defaults\.model\)/));
    writeFileSync(cfg, JSON.stringify({ agents: { $include: "./missing.json5" } }));
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, () =>
      expectRefused(launch, /could not read .*\$include "\.\/missing\.json5": the file does not exist/));
    writeFileSync(cfg, JSON.stringify({ agents: { $include: "../outside.json5" } }));
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, () =>
      expectRefused(launch, /\$include "\.\.\/outside\.json5": it is outside the config directory/));

    assert.equal(existsSync(report), false, "the stand-in openclaw never ran");
    assert.equal(r.hits(), 0, "nothing reached the upstream");
  });
});

test("openclaw: an anthropic model launches, and the run config fences /model to the anthropic provider", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "openclaw", "OPENCLAW_CONFIG_PATH");
    const cfg = join(r.dir, "openclaw.json");
    writeFileSync(cfg, JSON.stringify({ agents: { defaults: {
      model: { primary: "anthropic/claude-sonnet-4-6" },
      models: { "anthropic/claude-sonnet-4-6": { alias: "sonnet" }, "google/gemini-3.1-pro": { alias: "gem" } },
    } } }));
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, async () => {
      const code = await main(["--target", "openclaw", "--no-scope", "--", bin, "agent", "--local", "--model", "sonnet", "-m", "hi"], env(r));
      assert.equal(code, 0);
    });
    const got = JSON.parse(readFileSync(report, "utf8"));
    assert.equal(got.config.models.providers.anthropic.api, "anthropic-messages");
    assert.deepEqual(got.config.agents.defaults.models, { "anthropic/*": {}, "anthropic/claude-sonnet-4-6": { alias: "sonnet" } },
      "the allowlist admits the anthropic provider only; the user's google entry is gone");
  });
});

test("openclaw: a split config ($include) with anthropic models launches, and the run config carries it resolved", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "openclaw", "OPENCLAW_CONFIG_PATH");
    const cfg = join(r.dir, "openclaw.json");
    mkdirSync(join(r.dir, "parts", "sub"), { recursive: true });
    writeFileSync(join(r.dir, "parts", "a.json5"),
      "{ defaults: { model: { primary: 'anthropic/claude-sonnet-4-6' } }, list: [{ id: 'ops', $include: './sub/ops.json5' }] }");
    writeFileSync(join(r.dir, "parts", "sub", "ops.json5"), "{ model: 'anthropic/claude-opus-4-8' }");
    writeFileSync(cfg, "{ agents: { $include: ['./parts/a.json5'], defaults: { model: { fallbacks: ['anthropic/claude-haiku-4-5'] } } } }");
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, async () => {
      const code = await main(["--target", "openclaw", "--no-scope", "--", bin, "agent", "--local", "-m", "hi"], env(r));
      assert.equal(code, 0);
    });
    const got = JSON.parse(readFileSync(report, "utf8"));
    assert.ok(!JSON.stringify(got.config).includes("$include"), "no $include is left in the run config");
    assert.deepEqual(got.config.agents.defaults.model, { primary: "anthropic/claude-sonnet-4-6", fallbacks: ["anthropic/claude-haiku-4-5"] });
    assert.deepEqual(got.config.agents.list, [{ id: "ops", model: "anthropic/claude-opus-4-8" }]);
    assert.equal(got.config.models.providers.anthropic.api, "anthropic-messages", "the routing override still applies");
    assert.equal(r.hits(), 0);
  });
});

test("opencode: an unrouted model on -m or in the config is REFUSED; nothing starts", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "opencode", "OPENCODE_CONFIG");
    const cfg = join(r.dir, "opencode.json");
    writeFileSync(cfg, JSON.stringify({}));
    await withProcessEnv({ OPENCODE_CONFIG: cfg }, () =>
      expectRefused(() => main(["--target", "opencode", "--no-scope", "--", bin, "run", "-m", "google/gemini-3", "hi"], env(r)),
        /refusing to launch opencode with model google\/gemini-3 \(--model\)/));
    // OpenAI through a ChatGPT sign-in: that login re-points requests itself.
    mkdirSync(join(r.dir, ".local", "share", "opencode"), { recursive: true });
    writeFileSync(join(r.dir, ".local", "share", "opencode", "auth.json"), JSON.stringify({ openai: { type: "oauth", refresh: "r", access: "a", expires: 0 } }));
    await withProcessEnv({ OPENCODE_CONFIG: cfg, HOME: r.dir, XDG_DATA_HOME: join(r.dir, ".local", "share") }, () =>
      expectRefused(() => main(["--target", "opencode", "--no-scope", "--", bin, "run", "-m", "openai/gpt-5", "hi"], env(r)),
        /openai\/gpt-5 \(--model\): OpenCode is signed in to OpenAI with a ChatGPT account/));
    writeFileSync(cfg, JSON.stringify({ agent: { plan: { model: "openrouter/anthropic/claude-sonnet-4.6" } } }));
    await withProcessEnv({ OPENCODE_CONFIG: cfg }, () =>
      expectRefused(() => main(["--target", "opencode", "--no-scope", "--", bin, "run", "hi"], env(r)),
        /openrouter\/anthropic\/claude-sonnet-4\.6 \(agent\.plan\.model in /));
    assert.equal(existsSync(report), false, "the stand-in opencode never ran");
    assert.equal(r.hits(), 0, "nothing reached the upstream");
  });
});

test("opencode: no model configured launches, fenced to the anthropic provider in OPENCODE_CONFIG_CONTENT (merged over the user's own)", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "opencode", "OPENCODE_CONFIG");
    await withProcessEnv({
      OPENCODE_CONFIG: join(r.dir, "absent.json"),
      OPENCODE_CONFIG_CONTENT: JSON.stringify({ theme: "mine", enabled_providers: ["openai"], provider: { anthropic: { options: { baseURL: "https://elsewhere.example/v1" } } } }),
    }, async () => {
      const code = await main(["--target", "opencode", "--no-scope", "--", bin, "run", "hi"], env(r));
      assert.equal(code, 0);
    });
    const got = JSON.parse(readFileSync(report, "utf8"));
    const content = JSON.parse(got.content);
    assert.deepEqual(content.enabled_providers, ["anthropic"]);
    assert.equal(content.provider.anthropic.options.baseURL, "http://127.0.0.1:8788/v1", "the user's own re-point is overridden");
    assert.ok(content.provider.anthropic.options.headers["x-mandu-session-id"]);
    assert.equal(content.theme, "mine", "the user's other inline settings survive");
    assert.deepEqual(got.config.enabled_providers, ["anthropic"], "the config file carries the fence too");
  });
});

test("openclaw: openai/… and a declared OpenAI-compatible provider launch ROUTED through the proxy; exec host node is dropped", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "openclaw", "OPENCLAW_CONFIG_PATH");
    const cfg = join(r.dir, "openclaw.json");
    writeFileSync(cfg, JSON.stringify({
      agents: { defaults: { model: { primary: "openai/gpt-5.5", fallbacks: ["deepseek/deepseek-chat"] }, models: { "openai/gpt-5.5": { alias: "g" }, "google/x": {} } }, list: [{ id: "ops", tools: { exec: { host: "node" } } }] },
      models: { providers: { deepseek: { baseUrl: "https://api.deepseek.com/v1", api: "openai-completions", apiKey: "DEEPSEEK_KEY_REF", models: [{ id: "deepseek-chat", baseUrl: "https://elsewhere.example/v1" }] } } },
      tools: { exec: { host: "node", ask: "off" } },
    }));
    await withProcessEnv({ OPENCLAW_CONFIG_PATH: cfg }, async () => {
      const code = await main(["--target", "openclaw", "--no-scope", "--", bin, "agent", "--local", "-m", "hi"], env(r));
      assert.equal(code, 0);
    });
    const got = JSON.parse(readFileSync(report, "utf8"));
    const p = got.config.models.providers;
    assert.equal(p.openai.baseUrl, "http://127.0.0.1:8788/_mandu/openai/openai");
    assert.equal(p.openai.api, "openai-responses");
    assert.equal(p.deepseek.baseUrl, "http://127.0.0.1:8788/_mandu/openai/deepseek");
    assert.equal(p.deepseek.api, "openai-completions");
    assert.equal(p.deepseek.apiKey, "DEEPSEEK_KEY_REF", "the user's credential setting survives");
    assert.deepEqual(p.deepseek.models, [{ id: "deepseek-chat" }], "a model's own baseUrl is dropped");
    assert.ok(p.openai.headers["x-mandu-session-id"]);
    assert.deepEqual(got.config.agents.defaults.models, { "anthropic/*": {}, "openai/*": {}, "deepseek/*": {}, "openai/gpt-5.5": { alias: "g" } });
    assert.equal(got.config.tools.exec.host, undefined, "the global exec host node is dropped");
    assert.equal(got.config.tools.exec.ask, "off", "the rest of tools.exec is kept");
    assert.equal(got.config.agents.list[0].tools.exec.host, undefined, "and the per-agent one");
    assert.equal(r.hits(), 0);
  });
});

test("opencode: openai/… and a declared openai-compatible provider launch ROUTED; the fence admits them", async () => {
  await withRig(async (r) => {
    const { bin, report } = standIn(r.dir, "opencode", "OPENCODE_CONFIG");
    const cfg = join(r.dir, "opencode.json");
    writeFileSync(cfg, JSON.stringify({ model: "openai/gpt-5", small_model: "lm/qwen3", provider: { lm: { npm: "@ai-sdk/openai-compatible", options: { baseURL: "http://127.0.0.1:1234/v1" } } } }));
    await withProcessEnv({ OPENCODE_CONFIG: cfg, XDG_DATA_HOME: join(r.dir, "no-auth") }, async () => {
      const code = await main(["--target", "opencode", "--no-scope", "--", bin, "run", "hi"], env(r));
      assert.equal(code, 0);
    });
    const got = JSON.parse(readFileSync(report, "utf8"));
    const content = JSON.parse(got.content);
    assert.deepEqual(content.enabled_providers, ["anthropic", "openai", "lm"]);
    assert.equal(content.provider.openai.options.baseURL, "http://127.0.0.1:8788/_mandu/openai/openai");
    assert.equal(content.provider.lm.options.baseURL, "http://127.0.0.1:8788/_mandu/openai/lm");
    assert.equal(got.config.provider.lm.npm, "@ai-sdk/openai-compatible", "the user's provider settings survive in the file");
    assert.equal(got.config.provider.lm.options.baseURL, "http://127.0.0.1:8788/_mandu/openai/lm");
  });
});
