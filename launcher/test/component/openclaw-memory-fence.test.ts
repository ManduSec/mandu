/**
 * openclaw-memory-fence.test — E2E: `mandu openclaw …` through main(), with a
 * stand-in binary NAMED `openclaw` that answers `--version` like the real one
 * and records the run config it was handed. Pins the memory-search fix
 * (services/agent-config.ts fenceOpenclawMemorySearch): OpenClaw's memory
 * search sends the memory files' text to its embedding provider (OpenAI by
 * default) directly, around Mandu (probe-verified 2026-09-27 on 2026.3.12,
 * 6.35, 7.1, 8.2 and 9.6: the memory text reached a stand-in /v1/embeddings).
 * The run config must switch the embeddings off in the spelling the probed
 * release accepts, or unload the memory plugin where the release is unknown.
 * Also pins the workspace (fenceOpenclawWorkspace): under `chat` the run
 * config names the directory the agent runs in; the Gateway keeps the user's.
 * The same under the real secret-twins wrap: test/kernel/openclaw-workspace-twin.test.ts.
 *
 * PROJECT INVARIANT: text a routed agent sends to a model-like service goes
 * through Mandu, or is not sent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import "../lib/private-home.js"; // the Mandu home and agent trust files go to temp, not the real HOME (test-organization.md §8.4)
import { PRIVATE_MANDU_HOME } from "../lib/private-home.js";
import { createServer, type Server } from "node:net";
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { main } from "../lib/launch-in-dir.js"; // the launch is for the env's PWD (launch-cwd.ts)
import { answerUnavailable } from "../lib/unanswered-arbiter.js";

// Axes: stated per launch (MANDU_MODE: "off": confidentiality off, so the
// stand-in socket needs no secret discovery); the fence is axis-independent.

async function withRig(fn: (dir: string, sock: string) => Promise<void>): Promise<void> {
  // realpath: the launch resolves its directory, and macOS /tmp is a link.
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "mandu-oc-memory-")));
  const sock = join(dir, "arbiter.sock");
  const srv: Server = createServer(answerUnavailable());
  srv.listen(sock);
  await once(srv, "listening");
  try { await fn(dir, sock); } finally { srv.close(); rmSync(dir, { recursive: true, force: true }); }
}

/** A stand-in `openclaw` printing `version` (or failing --version when null). */
function standIn(dir: string, version: string | null): { bin: string; report: string } {
  const bin = join(dir, "openclaw");
  const report = join(dir, "openclaw-report.json");
  writeFileSync(bin, `#!/usr/bin/env node
const fs = require("fs");
if (process.argv[2] === "--version") { ${version === null ? "process.exit(1);" : `console.log(${JSON.stringify(`OpenClaw ${version} (abc1234)`)}); process.exit(0);`} }
const p = process.env.OPENCLAW_CONFIG_PATH;
fs.writeFileSync(${JSON.stringify(report)}, JSON.stringify({ config: p ? JSON.parse(fs.readFileSync(p, "utf8")) : null, cwd: process.cwd(), argv: process.argv.slice(2) }));
`, { mode: 0o755 });
  return { bin, report };
}

const env = (dir: string, sock: string) => ({
  HOME: dir, PWD: dir, MANDU_ARBITER_SOCK: sock, PATH: process.env["PATH"], XDG_RUNTIME_DIR: dir,
  MANDU_NO_CONTEXT_PROXY: "1", MANDU_HOME: PRIVATE_MANDU_HOME, MANDU_MODE: "off", MANDU_UPSTREAM: "http://127.0.0.1:9",
  MANDU_NET_PROXY: "0", MANDU_EXEC_WRAP: "0", MANDU_REPLY_FILTER: "0", MANDU_NO_KERNEL: "1", MANDU_FS_SYNC: "0",
});

async function launchWith(version: string | null, userCfg: string, files: Record<string, string> = {}): Promise<Record<string, unknown>> {
  let got: Record<string, unknown> = {};
  await withRig(async (dir, sock) => {
    const { bin, report } = standIn(dir, version);
    const cfg = join(dir, "openclaw.json");
    writeFileSync(cfg, userCfg);
    for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
    const saved = process.env["OPENCLAW_CONFIG_PATH"];
    process.env["OPENCLAW_CONFIG_PATH"] = cfg;
    try {
      const code = await main(["--target", "openclaw", "--no-scope", "--", bin, "agent", "--local", "-m", "hi"], env(dir, sock));
      assert.equal(code, 0);
    } finally {
      if (saved === undefined) delete process.env["OPENCLAW_CONFIG_PATH"]; else process.env["OPENCLAW_CONFIG_PATH"] = saved;
    }
    got = (JSON.parse(readFileSync(report, "utf8")) as { config: Record<string, unknown> }).config;
  });
  return got;
}

// A hand-edited JSON5 config naming OpenAI embeddings, as OpenClaw's docs write it.
const USER = `// my OpenClaw
{
  agents: { defaults: { model: { primary: 'anthropic/claude-sonnet-4-6' }, }, },
  memory: { search: { provider: 'openai', model: 'text-embedding-3-small', }, },
}`;
const LEGACY_USER = `{ agents: { defaults: { model: 'anthropic/claude-sonnet-4-6', memorySearch: { provider: 'openai' } } } }`;

test("openclaw 2026.9.6: the run config turns memory-search embeddings off (memory.search), from a JSON5 user config", async () => {
  const cfg = await launchWith("2026.9.6", USER) as { memory: { search: Record<string, unknown> }; agents: { defaults: Record<string, unknown> }; plugins?: { slots?: unknown } };
  assert.equal(cfg.memory.search["provider"], "none");
  assert.equal(cfg.memory.search["fallback"], "none");
  assert.equal(cfg.memory.search["model"], "text-embedding-3-small", "the user's other settings ride through");
  assert.equal(cfg.agents.defaults["memorySearch"], undefined);
  assert.equal(cfg.plugins?.slots, undefined, "the memory tools stay (keyword search)");
});

test("openclaw 2026.9.6: an embeddings setting in an $include file is fenced too, and the run config has no $include", async () => {
  const cfg = await launchWith("2026.9.6",
    "{ agents: { defaults: { model: 'anthropic/claude-sonnet-4-6' } }, memory: { $include: './memory.json5' } }",
    { "memory.json5": "{ search: { provider: 'openai', model: 'text-embedding-3-small' } }" },
  ) as { memory: { search: Record<string, unknown> } };
  assert.ok(!JSON.stringify(cfg).includes("$include"));
  assert.deepEqual(cfg.memory.search, { provider: "none", fallback: "none", model: "text-embedding-3-small" });
});

test("openclaw 2026.7.1: the legacy spelling (agents.defaults.memorySearch), never memory.search", async () => {
  const cfg = await launchWith("2026.7.1", LEGACY_USER) as { memory?: unknown; agents: { defaults: { memorySearch: Record<string, unknown> } } };
  assert.equal(cfg.memory, undefined);
  assert.equal(cfg.agents.defaults.memorySearch["provider"], "none");
  assert.equal(cfg.agents.defaults.memorySearch["fallback"], "none");
});

test("openclaw with no readable version or 2026.3.12: the memory plugin is unloaded instead", async () => {
  for (const v of [null, "2026.3.12"]) {
    const cfg = await launchWith(v, LEGACY_USER) as { plugins: { slots: { memory: string } } };
    assert.equal(cfg.plugins.slots.memory, "none", `version ${String(v)}`);
  }
});

// ── Code Mode off (services/agent-config.ts fenceOpenclawCodeMode;
// supported-agents.md §2.1). Code Mode's JavaScript calls the tools inside
// OpenClaw, where no wire gate reads them; 2026.9.x reads an absent
// `tools.codeMode` as "auto" (on for models flagged preferred). ──

const CODE_MODE_USER = `{
  agents: {
    defaults: { model: { primary: 'anthropic/claude-opus-5' }, models: { 'anthropic/claude-opus-5': { codeMode: true } } },
    list: [{ id: 'main', tools: { codeMode: { enabled: 'auto', executor: 'node' } } }],
  },
  tools: { profile: 'coding', codeMode: true },
}`;

test("openclaw 2026.9.9: the run config turns Code Mode off at every level the user turned it on, and globally", async () => {
  const cfg = await launchWith("2026.9.9", CODE_MODE_USER) as {
    tools: Record<string, unknown>;
    agents: { defaults: { models: Record<string, Record<string, unknown>> }; list: Array<{ tools: Record<string, unknown> }> };
  };
  assert.equal(cfg.tools["codeMode"], false);
  assert.equal(cfg.tools["profile"], "coding", "the user's other tool settings ride through");
  assert.equal(cfg.agents.defaults.models["anthropic/claude-opus-5"]!["codeMode"], false);
  assert.equal(cfg.agents.list[0]!.tools["codeMode"], false);
});

test("openclaw 2026.9.9 with no Code Mode setting: the run config writes tools.codeMode false (an absent one is \"auto\" there)", async () => {
  const cfg = await launchWith("2026.9.9", USER) as { tools: Record<string, unknown> };
  assert.equal(cfg.tools["codeMode"], false);
});

test("openclaw 2026.3.12 or an unreadable version: no tools.codeMode is written (2026.3.12 rejects the key)", async () => {
  for (const v of [null, "2026.3.12"]) {
    const cfg = await launchWith(v, LEGACY_USER) as { tools?: Record<string, unknown> };
    assert.equal(cfg.tools?.["codeMode"], undefined, `version ${String(v)}`);
  }
});

// ── The workspace pin (services/agent-config.ts fenceOpenclawWorkspace;
// supported-agents.md §5.5 item 5). OpenClaw's workspace defaulted to
// ~/.openclaw/workspace, outside the project; under `chat` it is the directory
// the agent runs in, and OpenClaw writes none of its starter files there. ──

async function launchShape(shape: string[], userCfg: string): Promise<{ config: Record<string, unknown>; cwd: string; dir: string; argv: string[] }> {
  let got!: { config: Record<string, unknown>; cwd: string; dir: string; argv: string[] };
  await withRig(async (dir, sock) => {
    const { bin, report } = standIn(dir, "2026.6.35");
    const cfg = join(dir, "openclaw.json");
    writeFileSync(cfg, userCfg);
    const saved = process.env["OPENCLAW_CONFIG_PATH"];
    process.env["OPENCLAW_CONFIG_PATH"] = cfg;
    try {
      assert.equal(await main(["--target", "openclaw", "--no-scope", "--", bin, ...shape], env(dir, sock)), 0);
    } finally {
      if (saved === undefined) delete process.env["OPENCLAW_CONFIG_PATH"]; else process.env["OPENCLAW_CONFIG_PATH"] = saved;
    }
    const r = JSON.parse(readFileSync(report, "utf8")) as { config: Record<string, unknown>; cwd: string; argv: string[] };
    got = { ...r, dir };
  });
  return got;
}

const USER_WS = `{ agents: { defaults: { model: 'anthropic/claude-sonnet-4-6', workspace: '~/.openclaw/workspace' } } }`;

test("openclaw chat: the run config's workspace is the directory the agent runs in (the launch directory), starter files off", async () => {
  const r = await launchShape(["chat"], USER_WS);
  const defaults = (r.config["agents"] as { defaults: Record<string, unknown> }).defaults;
  assert.equal(defaults["workspace"], r.cwd, "OpenClaw works where the agent was started");
  assert.equal(r.cwd, r.dir, "under `off`/`secrets` that is the launch directory itself");
  assert.equal(defaults["skipBootstrap"], true);
  assert.equal(defaults["model"], "anthropic/claude-sonnet-4-6", "the user's other defaults ride through");
});

test("bare `mandu openclaw` runs `openclaw chat`: the agent gets `chat` and the workspace pin (openclaw-argv.ts openclawDefaultArgv)", async () => {
  const r = await launchShape([], USER_WS);
  assert.deepEqual(r.argv, ["chat"], "the agent is started as `openclaw chat`, never onboarding or Crestodian");
  const defaults = (r.config["agents"] as { defaults: Record<string, unknown> }).defaults;
  assert.equal(defaults["workspace"], r.cwd, "and runs as a confined, locally-run shape");
  assert.equal(defaults["skipBootstrap"], true);
});

test("openclaw gateway: the Gateway keeps the user's own workspace", async () => {
  const r = await launchShape(["gateway"], USER_WS);
  const defaults = (r.config["agents"] as { defaults: Record<string, unknown> }).defaults;
  assert.equal(defaults["workspace"], "~/.openclaw/workspace");
  assert.equal(defaults["skipBootstrap"], undefined);
});
