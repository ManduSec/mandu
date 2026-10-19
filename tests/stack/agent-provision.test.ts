/**
 * agent-provision.test.ts — unit tests for the PURE per-agent provisioning
 * logic (tests/lib/agent-provision.ts).
 *
 * Mandu (tests/). Design: docs/design/testing/agent-e2e-harness.md §3.
 *
 * WHY THESE LIVE IN tests/stack/ (the FREE tier) AND NOT WITH THE LIVE DRILLS:
 * provision() and extractReply() do no I/O, so they run on any machine with no
 * agent installed, no network, and no arbiter — the same discipline as the Rust
 * crates' privilege-free decision modules. That means the facts most likely to
 * rot (a config key, a mandatory flag, an output envelope shape) are pinned by
 * a test that runs on EVERY push, not only on the dev box that happens to have
 * both agents.
 *
 * The captured fixtures below are REAL observed output, not hand-written
 * guesses — see the design doc §2.4 for how they were captured.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  openclawProvisioner, opencodeProvisioner, opencode2Provisioner, gooseProvisioner, pluckOpenclawText, parseGooseJson,
  gooseExtensionSpec, GOOSE_UPLOADS_OFF_ENV, binarySkipReason, resolveOpencode2,
  buildOpenclawConfig, buildOpencodeConfig, buildOpencode2Config, OPENCODE_PROVIDER_ID,
  DUMMY_ANTHROPIC_KEY, PROVISIONERS, ullmCliUsable,
  realTierApiKey, realTierSkipReason, withUpstreamApiKey,
  type ProvisionInput,
} from "../lib/agent-provision.js";

const INPUT: ProvisionInput = {
  agentHome: "/tmp/mdu-test/home",
  workspace: "/tmp/mdu-test/ws",
  proxyUrl: "http://127.0.0.1:45678",
  sessionId: "openclaw-e2e-stored-ipi-1234567890",
  batchId: "20260805-1200-abcd",
  model: "test-model-id",
  prompt: "say hello",
  timeoutMs: 90_000,
};

// ── Cross-agent invariants ───────────────────────────────────────────────────

test("every provisioner routes the agent at the proxy and nowhere else", () => {
  for (const p of Object.values(PROVISIONERS)) {
    const got = p.provision(INPUT);
    const blob = JSON.stringify({ env: got.env, files: got.files, argv: got.argv });
    assert.ok(blob.includes(INPUT.proxyUrl), `${p.id}: proxy URL absent from the provisioning`);
    // The single most important negative: nothing may point at the real API, or
    // a "passing" run could be talking to Anthropic directly and bypassing the
    // chokepoint entirely.
    assert.ok(!blob.includes("api.anthropic.com"), `${p.id}: routes at the REAL API`);
  }
});

test("every provisioner confines the agent's state to the throwaway home", () => {
  for (const p of Object.values(PROVISIONERS)) {
    const got = p.provision(INPUT);
    assert.equal(got.env["HOME"], INPUT.agentHome, `${p.id}: HOME not redirected`);
    for (const f of got.files) {
      assert.ok(
        f.path.startsWith(INPUT.agentHome) || f.path.startsWith(INPUT.workspace),
        `${p.id}: writes ${f.path} outside the throwaway dirs`,
      );
    }
  }
});

test("every provisioner carries the session id so the proxy can correlate the run (or says it cannot, and the proxy keys it)", () => {
  for (const p of Object.values(PROVISIONERS)) {
    if (p.sessionHeader === false) continue; // Goose: the runner keys the proxy by sessionKey
    const got = p.provision(INPUT);
    const blob = JSON.stringify({ argv: got.argv, files: got.files, env: got.env });
    assert.ok(blob.includes(INPUT.sessionId), `${p.id}: session id never reaches the agent`);
  }
});

test("the dummy key is sk-ant- shaped", () => {
  // NOT cosmetic: OpenClaw's pi-ai layer branches on isOAuthToken(apiKey) and,
  // on that branch, swaps to authToken + Claude Code identity headers + an
  // injected "You are Claude Code…" system block — silently changing the very
  // model context the suites assert on.
  assert.match(DUMMY_ANTHROPIC_KEY, /^sk-ant-/);
});

test("provisioner metadata matches the trust spec it will activate", () => {
  assert.equal(openclawProvisioner.inboundSpec, "openclaw-agent");
  // NOT "openclaw": that id is the LIFTED reference ruleset, which trusts
  // `read` wholesale and would forward a poisoned file's bytes raw.
  assert.notEqual(openclawProvisioner.inboundSpec as string, "openclaw");
  assert.equal(opencodeProvisioner.inboundSpec, "opencode");
  assert.equal(openclawProvisioner.sessionClass, "openclaw-e2e");
  assert.equal(opencodeProvisioner.sessionClass, "opencode-e2e");
});

// ── OpenClaw ─────────────────────────────────────────────────────────────────

test("openclaw: --local is present (without it the run is nondeterministic)", () => {
  // Without --local the CLI tries the gateway daemon FIRST and only falls back
  // to embedded — so whether a run is embedded depends on ambient daemon state.
  assert.ok(openclawProvisioner.provision(INPUT).argv.includes("--local"));
});

test("openclaw: config sets baseUrl, header, and a host-runnable exec posture", () => {
  const cfg = JSON.parse(buildOpenclawConfig(INPUT));
  const anthropic = cfg.models.providers.anthropic;
  assert.equal(anthropic.baseUrl, INPUT.proxyUrl);
  assert.equal(anthropic.api, "anthropic-messages");
  assert.equal(anthropic.headers["x-mandu-session-id"], INPUT.sessionId);
  // merge, not replace — otherwise the built-in model catalog disappears and
  // the configured model id fails to resolve before any request is made.
  assert.equal(cfg.models.mode, "merge");
  // Defaults are host:"sandbox" + security:"deny", under which the shell tool
  // never runs on the host and every exec scenario silently degrades to "the
  // model declined" — a green suite that tested nothing.
  assert.equal(cfg.tools.exec.host, "gateway");
  assert.equal(cfg.tools.exec.security, "full");
  assert.equal(cfg.agents.defaults.workspace, INPUT.workspace);
});

test("openclaw: mounts the U-LLM channel as a PLUGIN, not MCP", () => {
  // OpenClaw has no MCP client at all — but the CAPABILITY the caller asks for
  // (the U-LLM inspect channel) is now mounted as an in-process plugin tool
  // (interceptors/openclaw-inspect-plugin; design doc §8). `inspectMount`
  // records the mount, and `unsupported` stays empty because nothing the caller
  // asked for is missing. Reporting "mcp" here would make the runner refuse a
  // scenario this agent can actually run.
  assert.equal(openclawProvisioner.inspectMount, "plugin");
  assert.equal(opencodeProvisioner.inspectMount, "mcp");

  const withMcp = openclawProvisioner.provision({
    ...INPUT,
    mcp: {
      name: "mandu-inspect",
      command: ["node", "server.js"],
      env: { MANDU_ARBITER_SOCK: "/tmp/a.sock", MANDU_SCOPE_ID: "sess-1" },
    },
  });
  assert.deepEqual(withMcp.unsupported, []);

  const cfg = JSON.parse(withMcp.files[0]!.content);
  // The plugin is loaded by PATH and enabled explicitly.
  assert.ok(cfg.plugins.load.paths[0].endsWith("interceptors/openclaw-inspect-plugin"));
  const entry = cfg.plugins.entries["mandu-inspect"];
  assert.equal(entry.enabled, true);
  assert.equal(entry.config.arbiterSock, "/tmp/a.sock");
  assert.equal(entry.config.scopeId, "sess-1");

  // THE NON-OBVIOUS ONE (probe-verified 2026-08-06): `tools.profile` is an
  // ALLOWLIST applied to the FINAL tool list, so a plugin tool outside the
  // profile is loaded and then filtered out before the model ever sees it —
  // the plugin logs "registered" and tools[] does not contain it. `alsoAllow`
  // is OpenClaw's additive escape hatch and is what makes the mount real.
  assert.deepEqual(
    cfg.tools.alsoAllow,
    ["inspect_symbol", "declassify_symbol"],
    "without tools.alsoAllow the profile allowlist silently drops the plugin tools (both of them)",
  );

  // No channel requested → no plugin block, and the profile is left alone.
  const bare = JSON.parse(openclawProvisioner.provision(INPUT).files[0]!.content);
  assert.equal(bare.plugins, undefined);
  assert.equal(bare.tools.alsoAllow, undefined);
  assert.deepEqual(openclawProvisioner.provision(INPUT).unsupported, []);
});

test("openclaw: extractReply plucks text from the REAL captured envelope", () => {
  // Captured from openclaw 2026.3.12 `agent --local --json` (design doc §2.4).
  const captured = JSON.stringify({
    payloads: [{ text: "437. MDU_LIVE_DONE", mediaUrl: null }],
    meta: {
      durationMs: 260,
      agentMeta: { sessionKey: "agent:main:main" },
      usage: { input: 10, output: 5, total: 15 },
      aborted: false,
    },
  });
  const got = openclawProvisioner.extractReply(captured);
  assert.equal(got.text, "437. MDU_LIVE_DONE");
  assert.equal(got.extracted, true);
});

test("openclaw: extractReply never descends into meta", () => {
  // meta carries telemetry; a blind walk would happily return some unrelated
  // string as "the reply". The descend list is an allow-list for this reason.
  const doc = JSON.stringify({ meta: { text: "NOT-THE-REPLY", usage: {} } });
  assert.equal(pluckOpenclawText(JSON.parse(doc)), undefined);
});

test("openclaw: an unknown envelope REPORTS the fallback instead of faking success", () => {
  // The regression this encodes: the first implementation returned raw stdout
  // silently, the utility oracle matched its regex against the raw envelope
  // (which contains the reply), and a completely broken parser went green.
  const got = openclawProvisioner.extractReply('{"totally":"unexpected"}');
  assert.equal(got.extracted, false);
  assert.equal(got.text, '{"totally":"unexpected"}');
});

test("openclaw: non-JSON stdout degrades to raw, flagged", () => {
  const got = openclawProvisioner.extractReply("boom: a crash trace");
  assert.equal(got.extracted, false);
  assert.equal(got.text, "boom: a crash trace");
});

// ── OpenCode ─────────────────────────────────────────────────────────────────

test("opencode: config names the ANTHROPIC sdk package (the wire we already parse)", () => {
  const cfg = JSON.parse(buildOpencodeConfig(INPUT));
  const provider = cfg.provider[OPENCODE_PROVIDER_ID];
  // @ai-sdk/anthropic POSTs /v1/messages in genuine Anthropic Messages, so the
  // existing anthropic-proxy works unchanged. @ai-sdk/openai-compatible would
  // emit Chat Completions — a wire we do NOT parse yet.
  assert.equal(provider.npm, "@ai-sdk/anthropic");
  assert.equal(provider.options.baseURL, `${INPUT.proxyUrl}/v1`);
  assert.equal(provider.options.headers["x-mandu-session-id"], INPUT.sessionId);
  // The provider id is deliberately NOT "anthropic": a custom id keeps the
  // built-in catalog and credential discovery out of the run, so a misconfigured
  // harness fails loudly instead of silently reaching the real API.
  assert.notEqual(OPENCODE_PROVIDER_ID, "anthropic");
  assert.equal(cfg.model, `${OPENCODE_PROVIDER_ID}/${INPUT.model}`);
  // The model the argv selects must be one the config declares, or resolution
  // fails before any request.
  assert.ok(Object.keys(provider.models).includes(INPUT.model));
});

test("opencode: env pins hermeticity and auto-approval", () => {
  const env = opencodeProvisioner.provision(INPUT).env;
  // Without this every run fetches the models.dev catalog over the network.
  assert.equal(env["OPENCODE_DISABLE_MODELS_FETCH"], "1");
  assert.equal(JSON.parse(env["OPENCODE_PERMISSION"]!)["*"], "allow");
  // All four XDG roots redirected, or auth.json/state lands in the real home.
  for (const k of ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"]) {
    assert.ok(env[k]?.startsWith(INPUT.agentHome), `${k} not confined`);
  }
});

test("opencode: mcp is registered with a timeout above the 5s default", () => {
  const cfg = JSON.parse(
    buildOpencodeConfig({
      ...INPUT,
      mcp: { name: "mandu-inspect", command: ["node", "server.js"] },
    }),
  );
  const server = cfg.mcp["mandu-inspect"];
  assert.equal(server.type, "local");
  assert.deepEqual(server.command, ["node", "server.js"]);
  // A cold inspect_symbol start can blow through opencode's 5000ms default, and
  // a dropped MCP server surfaces as a confusing "tool not found".
  assert.ok(server.timeout > 5000);
  assert.equal(opencodeProvisioner.provision(INPUT).unsupported.length, 0);
});

test("opencode: extractReply concatenates text parts from REAL captured NDJSON", () => {
  // Captured from opencode 1.18.13 `run --format json` (design doc §2.4).
  const captured = [
    '{"type":"step_start","timestamp":1785922509026,"sessionID":"ses_02eb","part":{"type":"step-start"}}',
    '{"type":"text","timestamp":1785922509026,"sessionID":"ses_02eb","part":{"type":"text","text":"437."}}',
    '{"type":"text","timestamp":1785922509027,"sessionID":"ses_02eb","part":{"type":"text","text":" MDU_LIVE_DONE"}}',
    '{"type":"step_finish","timestamp":1785922509028,"sessionID":"ses_02eb","part":{"type":"step-finish"}}',
  ].join("\n");
  const got = opencodeProvisioner.extractReply(captured);
  assert.equal(got.text, "437. MDU_LIVE_DONE");
  assert.equal(got.extracted, true);
});

test("opencode: extractReply survives interleaved non-JSON noise", () => {
  // A stray warning line must not lose the whole reply.
  const stdout = [
    "warning: something the runtime printed",
    '{"type":"text","part":{"type":"text","text":"hello"}}',
    "",
  ].join("\n");
  const got = opencodeProvisioner.extractReply(stdout);
  assert.equal(got.text, "hello");
  assert.equal(got.extracted, true);
});

test("opencode: no text parts REPORTS the fallback", () => {
  const got = opencodeProvisioner.extractReply(
    '{"type":"step_start","part":{"type":"step-start"}}',
  );
  assert.equal(got.extracted, false);
});

// ── OpenCode 2 ───────────────────────────────────────────────────────────────

test("opencode2: `run --standalone` (never the shared background service), the proxy and the throwaway home as 1.x, no OPENCODE_PERMISSION", () => {
  const got = opencode2Provisioner.provision(INPUT);
  assert.equal(got.binary, "opencode2");
  assert.deepEqual(got.argv.slice(0, 2), ["run", "--standalone"]);
  assert.ok(got.argv.includes("--auto") && got.argv.includes(`${OPENCODE_PROVIDER_ID}/${INPUT.model}`) && got.argv.at(-1) === INPUT.prompt);
  const blob = JSON.stringify({ env: got.env, files: got.files, argv: got.argv });
  assert.ok(blob.includes(INPUT.proxyUrl) && !blob.includes("api.anthropic.com"));
  assert.equal(got.env["OPENCODE_TEST_HOME"], INPUT.agentHome, "2.x looks for ~/.claude and ~/.agents under OPENCODE_TEST_HOME");
  assert.equal(got.env["HOME"], INPUT.agentHome);
  assert.equal(got.env["OPENCODE_PERMISSION"], undefined, "2.x has no OPENCODE_PERMISSION: --auto approves");
  for (const f of got.files) assert.ok(f.path.startsWith(INPUT.agentHome), f.path);
  assert.equal(opencode2Provisioner.id, "opencode");
  assert.equal(opencode2Provisioner.inboundSpec, "opencode", "one inbound spec covers both generations (opencode-inbound.ts)");
  assert.equal(opencode2Provisioner.execTool, "shell");
  assert.equal(opencode2Provisioner.sessionClass, "opencode-e2e");
});

test("opencode2: the inspect server in 2.x's spelling (mcp.servers, codemode off), `execute` denied, the V1 routing kept", () => {
  const cfg = JSON.parse(buildOpencode2Config({ ...INPUT, mcp: { name: "mandu-inspect", command: ["node", "server.js"], env: { A: "1" } } }));
  const server = cfg.mcp.servers["mandu-inspect"];
  assert.equal(server.type, "local");
  assert.deepEqual(server.command, ["node", "server.js"]);
  assert.deepEqual(server.environment, { A: "1" });
  // a 2.x MCP server defaults to code mode: its tools only inside `execute`
  assert.equal(server.codemode, false);
  assert.ok(server.timeout.startup > 5000 && server.timeout.catalog > 5000);
  assert.equal(cfg.mcp["mandu-inspect"], undefined, "not the V1 spelling (code mode)");
  assert.deepEqual(cfg.permissions, [{ action: "execute", resource: "*", effect: "deny" }]);
  assert.equal(cfg.provider[OPENCODE_PROVIDER_ID].options.baseURL, `${INPUT.proxyUrl}/v1`);
  assert.equal(cfg.model, `${OPENCODE_PROVIDER_ID}/${INPUT.model}`);
  assert.equal(JSON.parse(buildOpencode2Config(INPUT)).mcp, undefined, "no channel asked: no mcp key");
});

test("opencode2: the binary is MANDU_OPENCODE_V2_BIN or `opencode2` on PATH, and only a 2.x; else the skip names how to get it", () => {
  const v = (out: string | null) => () => out;
  assert.deepEqual(resolveOpencode2({}, v("opencode v2.0.23\n")), { binary: "opencode2", prefixArgs: [], source: "path" });
  assert.equal(resolveOpencode2({}, v("1.18.13\n")), undefined, "a 1.x named opencode2 is not OpenCode 2");
  assert.equal(resolveOpencode2({}, v(null)), undefined);
  assert.equal(resolveOpencode2({ MANDU_OPENCODE_V2_BIN: "/nonexistent/opencode2" }, v("opencode v2.0.23")), undefined);
  const dir = mkdtempSync(join(tmpdir(), "mdu-oc2-bin-"));
  try {
    const bin = join(dir, "opencode");
    writeFileSync(bin, "");
    assert.deepEqual(resolveOpencode2({ MANDU_OPENCODE_V2_BIN: bin }, v("opencode v2.0.23")), { binary: bin, prefixArgs: [], source: "env" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const missing = { ...opencode2Provisioner, resolveBinary: () => undefined };
  assert.match(String(binarySkipReason(missing)), /OpenCode 2 .*MANDU_OPENCODE_V2_BIN.*opencode2/);
});

// ── Goose ────────────────────────────────────────────────────────────────────

test("goose: env routing alone (GOOSE_PROVIDER + ANTHROPIC_HOST at the proxy), a throwaway GOOSE_PATH_ROOT, the keyring off, the subagent provider pinned", () => {
  const got = gooseProvisioner.provision(INPUT);
  assert.equal(got.binary, "goose");
  assert.equal(got.env["GOOSE_PROVIDER"], "anthropic");
  assert.equal(got.env["ANTHROPIC_HOST"], INPUT.proxyUrl);
  assert.equal(got.env["ANTHROPIC_API_KEY"], DUMMY_ANTHROPIC_KEY);
  assert.equal(got.env["GOOSE_MODEL"], INPUT.model);
  assert.equal(got.env["GOOSE_PATH_ROOT"], join(INPUT.agentHome, "goose"));
  assert.equal(got.env["GOOSE_DISABLE_KEYRING"], "1");
  assert.equal(got.env["GOOSE_SUBAGENT_PROVIDER"], "anthropic");
  assert.equal(got.env["GOOSE_MODE"], "auto");
  assert.deepEqual(got.files, [], "no config file: env routing outranks config.yaml");
  assert.deepEqual(got.argv, ["run", "--no-session", "--output-format", "json", "-t", INPUT.prompt]);
  assert.equal(gooseProvisioner.sessionHeader, false, "Goose sends no custom header: the proxy keys the run");
  assert.equal(gooseProvisioner.inboundSpec, "goose");
  assert.equal(gooseProvisioner.execTool, "shell");
  assert.equal(gooseProvisioner.readTool, "shell", "Goose has no read tool");
});

test("goose: the upload switches are applied LAST, so the user's env cannot turn an upload back on", () => {
  const got = gooseProvisioner.provision({
    ...INPUT,
    extraEnv: {
      GOOSE_TELEMETRY_OFF: "0", LANGFUSE_PUBLIC_KEY: "pk", LANGFUSE_SECRET_KEY: "sk", OTEL_SDK_DISABLED: "false",
      SECURITY_PROMPT_CLASSIFIER_ENABLED: "true", HTTPS_PROXY: "http://127.0.0.1:1",
    },
  });
  for (const [k, v] of Object.entries(GOOSE_UPLOADS_OFF_ENV)) assert.equal(got.env[k], v, k);
  assert.equal(got.env["HTTPS_PROXY"], "http://127.0.0.1:1", "a posture knob still reaches the agent");
  assert.deepEqual(Object.keys(GOOSE_UPLOADS_OFF_ENV).sort(), [
    "GOOSE_TELEMETRY_OFF", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "OTEL_SDK_DISABLED",
    "SECURITY_COMMAND_CLASSIFIER_ENABLED", "SECURITY_PROMPT_CLASSIFIER_ENABLED",
  ]);
  // both Langfuse keys EMPTY: Goose reads the first of each pair, and empty = unset
  assert.equal(GOOSE_UPLOADS_OFF_ENV["LANGFUSE_PUBLIC_KEY"], "");
});

test("goose: the U-LLM mounts as --with-extension '<name>:K=v … cmd args' (the explicit name gives <name>__<tool>)", () => {
  const mcp = { name: "mandu-inspect", command: ["/x/tsx", "/x/server-main.ts"], env: { MANDU_ARBITER_SOCK: "/run/a.sock", PATH: "/usr/bin:/bin" } };
  const got = gooseProvisioner.provision({ ...INPUT, mcp });
  const i = got.argv.indexOf("--with-extension");
  assert.ok(i > 0 && i < got.argv.indexOf("-t"), "before the prompt");
  assert.equal(got.argv[i + 1], "mandu-inspect:MANDU_ARBITER_SOCK=/run/a.sock PATH=/usr/bin:/bin /x/tsx /x/server-main.ts");
  assert.equal(gooseExtensionSpec(mcp), got.argv[i + 1]);
  assert.throws(() => gooseExtensionSpec({ ...mcp, env: { X: "has space" } }), /whitespace/);
  assert.deepEqual(got.unsupported, []);
});

/** The `goose run --no-session --output-format json` stdout of 1.53.0
 *  (captured 2026-10-05; banner, then one JSON document; trimmed). */
const GOOSE_JSON_STDOUT = [
  "",
  "    __( O)>  ● new session · anthropic claude-sonnet-4-5",
  "   \\____)    20261005_1 · /tmp/w",
  "     L L     goose is ready",
  "{",
  '  "messages": [',
  '    {"id": null, "role": "user", "created": 1, "content": [{"type": "text", "text": "read notes.txt"}], "metadata": {"userVisible": true, "agentVisible": true}},',
  '    {"id": "msg_u", "role": "assistant", "created": 1, "content": [{"type": "toolRequest", "id": "toolu_1", "toolCall": {"status": "success", "value": {"name": "shell", "arguments": {"command": "cat notes.txt"}}}}], "metadata": {}},',
  '    {"id": "msg_r", "role": "user", "created": 1, "content": [{"type": "toolResponse", "id": "toolu_1", "toolResult": {"status": "success", "value": {"content": [{"type": "text", "text": "planted file"}], "isError": false}}}], "metadata": {}},',
  '    {"id": "msg_t", "role": "assistant", "created": 1, "content": [{"type": "text", "text": "The file says: planted file"}], "metadata": {}}',
  "  ],",
  '  "metadata": {"total_tokens": 22, "status": "completed"}',
  "}",
  "",
].join("\n");

test("goose: extractReply reads the last assistant text out of the CAPTURED json document (the banner before it is not JSON)", () => {
  assert.deepEqual(gooseProvisioner.extractReply(GOOSE_JSON_STDOUT), { text: "The file says: planted file", extracted: true });
  assert.ok(parseGooseJson(GOOSE_JSON_STDOUT));
  // no JSON, a broken document, or no assistant text: reported, never faked
  for (const bad of ["goose is ready\nplain text", "{\n  \"messages\": [", "{\n\"messages\": [{\"role\": \"assistant\", \"content\": [{\"type\": \"toolRequest\"}]}]\n}"]) {
    assert.equal(gooseProvisioner.extractReply(bad).extracted, false, bad);
  }
});

// ── ullmCliUsable: the credential-aware U-LLM CLI probe ──────────────────────
// A version-only probe made the inspect scenarios RUN in the credential-less CI
// container and fail on the dead quarantine (first in-container
// agent-mock-openclaw-opencode run, 2026-08-06). These pin the decision logic
// with injected deps — no CLI, no HOME, no network.

test("ullmCliUsable: no runnable claude CLI → unusable regardless of credentials", () => {
  assert.equal(
    ullmCliUsable({ probe: () => false, env: { ANTHROPIC_API_KEY: "k" }, home: "/nonexistent" }),
    false,
  );
});

test("ullmCliUsable: runnable CLI but NO credentials (the CI container) → unusable", () => {
  assert.equal(ullmCliUsable({ probe: () => true, env: {}, home: "/nonexistent-mdu-home" }), false);
});

// The cli-mode U-LLM child deletes ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN
// (inspect-mcp ullm-client.ts buildChildEnv): a key with no login is a CLI
// that cannot authenticate, so the scenario must skip, not run and fail (the
// nightly's API lane holds keys only, continuous-integration.md §9.8).
test("ullmCliUsable: runnable CLI + ANTHROPIC_API_KEY but no login → unusable (cli mode strips the key)", () => {
  assert.equal(
    ullmCliUsable({ probe: () => true, env: { ANTHROPIC_API_KEY: "sk-ant-api03-k" }, home: "/nonexistent" }),
    false,
  );
});

test("ullmCliUsable: runnable CLI + MANDU_ULLM_API_KEY but no login → unusable", () => {
  assert.equal(
    ullmCliUsable({ probe: () => true, env: { MANDU_ULLM_API_KEY: "k" }, home: "/nonexistent" }),
    false,
  );
});

test("ullmCliUsable: runnable CLI + the OAuth store on disk → usable", () => {
  const home = mkdtempSync(join(tmpdir(), "mdu-ullm-probe-"));
  try {
    mkdirSync(join(home, ".claude"), { recursive: true });
    writeFileSync(join(home, ".claude", ".credentials.json"), "{}");
    assert.equal(ullmCliUsable({ probe: () => true, env: {}, home }), true);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// ── the real upstream tier's credential (integration.openclaw-headless, opencode-headless) ──
// Only an Anthropic API key serves the real tier; without one it SKIPs with
// the reason, and the fake tier never needs one.

const KEY = "sk-ant-api03-" + "k".repeat(40);
const OAUTH = "sk-ant-oat01-" + "o".repeat(40);

test("realTierApiKey: an sk-ant-api key from MANDU_E2E_ANTHROPIC_API_KEY or ANTHROPIC_API_KEY, never an OAuth token or the dummy", () => {
  assert.equal(realTierApiKey({ MANDU_E2E_ANTHROPIC_API_KEY: KEY }), KEY);
  assert.equal(realTierApiKey({ ANTHROPIC_API_KEY: KEY }), KEY);
  assert.equal(realTierApiKey({ MANDU_E2E_ANTHROPIC_API_KEY: OAUTH, ANTHROPIC_API_KEY: KEY }), KEY);
  assert.equal(realTierApiKey({ ANTHROPIC_API_KEY: OAUTH }), null);
  assert.equal(realTierApiKey({ ANTHROPIC_API_KEY: DUMMY_ANTHROPIC_KEY }), null);
  const usr = "sk-ant-usr01-" + "u".repeat(90); // the Console's newer key form (2026-10-05)
  assert.equal(realTierApiKey({ ANTHROPIC_API_KEY: usr }), usr);
  assert.equal(realTierApiKey({}), null);
});

test("realTierSkipReason: the real tier without a key skips with the reason; the fake tier never does", () => {
  const why = realTierSkipReason("real", {});
  assert.ok(typeof why === "string");
  assert.match(why as string, /needs an Anthropic API key/);
  assert.match(why as string, /subscription token/);
  assert.notEqual(realTierSkipReason("real", { ANTHROPIC_API_KEY: OAUTH }), false, "the nightly's OAuth token is not a key it can use");
  assert.equal(realTierSkipReason("real", { ANTHROPIC_API_KEY: KEY }), false);
  assert.equal(realTierSkipReason("fake", {}), false);
});

test("withUpstreamApiKey: the agent's dummy key (and any Authorization) is replaced on the hop, the rest passes unchanged", async () => {
  let seen: { headers: Record<string, string | string[] | undefined>; body: string } | undefined;
  const inner = async (a: { headers: Record<string, string | string[] | undefined>; body: string }) => { seen = a; return "ok"; };
  const f = withUpstreamApiKey(inner, KEY);
  assert.equal(await f({ headers: { "X-Api-Key": DUMMY_ANTHROPIC_KEY, authorization: "Bearer x", "anthropic-version": "2023-06-01" }, body: "B" }), "ok");
  assert.deepEqual(seen, { headers: { "anthropic-version": "2023-06-01", "x-api-key": KEY }, body: "B" });
});
